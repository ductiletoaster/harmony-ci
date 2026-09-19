#!/usr/bin/env python3
"""Turn an osv-scanner JSON report into a verdict that distinguishes
"no vulnerabilities" from "no packages examined" -- and from "no vulnerabilities
as of whenever this database was built".

osv-scanner cannot make the first distinction on its own. Its default JSON
report is byte-identical (`{"results": []}`) whether it scanned a clean lockfile
or scanned nothing at all, and `--allow-no-lockfiles` collapses the difference
further by printing "No package sources found / No issues found" and exiting 0.
A gate built on either of those reports coverage it does not have.

So the gate asserts coverage explicitly: scan with --all-packages (which does
record every scanned source, vulnerable or not), then require that at least one
source and at least one package were actually examined. Zero coverage is a
failure with a diagnostic, never a pass.

The second distinction is about the DATABASE rather than the scan. An offline
baked database cannot see an advisory published after the image was built, and
a scan against it still exits 0 -- so every green means "no advisories as of
whenever that image was built", which nothing in the output distinguishes from
"no advisories". Observed: the same uv.lock passed this gate on a baked database
while a github-hosted job querying osv.dev failed it on two advisories, one
critical, published the day before. So the age is measured, reported on every
run, and past a threshold it fails: an old database must not be able to present
as a clean bill of health.

Stdlib only, and no network: this runs on an egress-free runner.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

# osv-scanner exit codes we understand. Anything else is a tool failure we must
# not paper over.
EXIT_OK = 0
EXIT_VULNS = 1
EXIT_NO_SOURCES = 128

# Where the baked database records its own build time, if the image bakes one.
# RFC3339 (or a bare YYYY-MM-DD). This is the authoritative signal and the
# contract a runner image implements; everything below is the fallback for an
# image that does not yet write it.
MARKER_NAME = "BAKED_AT"

# How far ahead of this runner's clock a build time may sit and still be
# believed. NTP bounds real clock skew to seconds, so a day is generous cover
# for every honest disagreement between a runner and the host that built the
# image. Past it, the marker is describing a date that has not happened, and a
# vintage that cannot have happened is not a vintage: see Database.is_future().
FUTURE_TOLERANCE = timedelta(hours=24)


class Coverage:
    """What a scan actually examined, independent of what it found."""

    def __init__(self, sources: list[dict]) -> None:
        self.sources = sources

    @property
    def source_count(self) -> int:
        return len(self.sources)

    @property
    def package_count(self) -> int:
        return sum(s["packages"] for s in self.sources)

    @property
    def vuln_count(self) -> int:
        return sum(s["vulns"] for s in self.sources)

    @property
    def is_empty(self) -> bool:
        # Zero packages is zero coverage even when a source file was found --
        # an empty requirements.txt proves nothing about the dependency graph.
        return self.source_count == 0 or self.package_count == 0


class Database:
    """When the offline vulnerability database was built, and how we know.

    `source` is "marker" (the image told us), "mtime" (we inferred it from the
    downloaded database files) or "none" (we could not tell). The distinction
    is reported rather than hidden, because an inferred date is weaker evidence
    than a declared one and a reader should be able to see which they have.

    `zip_count`, `oldest_zip` and `newest_zip` describe the baked `all.zip`
    files regardless of which source dated the database, so a divergent image
    can be reported even when a marker supersedes them.
    """

    def __init__(
        self,
        built: datetime | None,
        source: str,
        where: str = "",
        zip_count: int = 0,
        oldest_zip: datetime | None = None,
        newest_zip: datetime | None = None,
    ) -> None:
        self.built = built
        self.source = source
        self.where = where
        self.zip_count = zip_count
        self.oldest_zip = oldest_zip
        self.newest_zip = newest_zip

    def is_future(self, now: datetime | None = None) -> bool:
        """Is this build time too far ahead to be a vintage at all?

        A marker reading 2099-01-01 is not a very fresh database; it is a
        broken marker. Clamping its age to 0 -- which this used to do -- made it
        report "built 2099-01-01, 0 days old", pass, and keep passing forever,
        with no threshold that could ever catch it. So past FUTURE_TOLERANCE the
        age is UNKNOWN instead, which the gate already treats as stale and which
        allow-stale-db can still override deliberately.
        """
        if self.built is None:
            return False
        now = now or datetime.now(timezone.utc)
        return self.built - now > FUTURE_TOLERANCE

    @property
    def is_unknown(self) -> bool:
        # A bogus future date folds in HERE rather than at each call site, so a
        # later edit that adds a caller cannot quietly reintroduce the
        # "2099 = 0 days old = fresh" pass. Callers that need to tell the two
        # apart -- to say WHICH kind of unknown this is -- ask is_future().
        return self.built is None or self.is_future()

    @property
    def built_date(self) -> str:
        return self.built.date().isoformat() if self.built else "unknown"

    def age_days(self, now: datetime | None = None) -> int | None:
        if self.built is None:
            return None
        now = now or datetime.now(timezone.utc)
        if self.built - now > FUTURE_TOLERANCE:
            # Not a measurable vintage. None, not a clamped 0: see is_future().
            return None
        # Within the tolerance, clamp at 0. A few hours of disagreement between
        # the runner's clock and the image build host's is ordinary, and failing
        # a build over that would be a worse bug than the one this gate fixes.
        return max(0, (now - self.built).days)


def _parse_marker(text: str) -> datetime | None:
    """RFC3339, or a bare YYYY-MM-DD, into an aware UTC datetime."""
    text = text.strip()
    if not text:
        return None
    # `fromisoformat` only learned to accept a trailing "Z" in 3.11, and this
    # runs on whatever Python the runner image happens to ship.
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        stamp = datetime.fromisoformat(text)
    except ValueError:
        return None
    # A bare date parses naive; treat it as UTC rather than as local time, so
    # the answer does not depend on the runner's timezone.
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.astimezone(timezone.utc)


def read_database(db_dir: Path | None) -> Database:
    """Date the offline database, preferring what the image declares.

    1. `<db_dir>/BAKED_AT` -- authoritative, and the contract a runner image
       should implement, since it survives anything that rewrites file mtimes.
    2. Otherwise the OLDEST `all.zip` mtime under `db_dir`. The image seeds one
       zip PER ECOSYSTEM (PyPI/npm/Go/Cargo), and Docker layer caching is
       exactly the mechanism that lets them diverge -- one re-seeded ecosystem
       and three stale ones is a normal outcome of a partial rebuild. A gate
       needs the LOWER bound on freshness: dating by the newest zip would let
       one fresh ecosystem vouch for the others while they rot.
    3. Otherwise unknown -- which the verdict treats as stale, not as fine.

    The zips are counted and spanned either way, so a divergent image is
    visible in the summary even when a marker supersedes them for dating.
    """
    if db_dir is None:
        return Database(None, "none", "")

    oldest: float | None = None
    newest: float | None = None
    zip_count = 0
    try:
        for zipped in db_dir.rglob("all.zip"):
            try:
                mtime = zipped.stat().st_mtime
            except OSError:
                continue
            zip_count += 1
            if oldest is None or mtime < oldest:
                oldest = mtime
            if newest is None or mtime > newest:
                newest = mtime
    except OSError:
        oldest = newest = None
        zip_count = 0

    def _at(stamp: float | None) -> datetime | None:
        return datetime.fromtimestamp(stamp, timezone.utc) if stamp is not None else None

    spread = {"zip_count": zip_count, "oldest_zip": _at(oldest), "newest_zip": _at(newest)}

    marker = db_dir / MARKER_NAME
    try:
        if marker.is_file():
            built = _parse_marker(marker.read_text(encoding="utf-8"))
            if built is not None:
                return Database(built, "marker", str(marker), **spread)
    except OSError:
        pass

    if oldest is None:
        return Database(None, "none", str(db_dir), **spread)
    return Database(_at(oldest), "mtime", str(db_dir), **spread)


def load_coverage(results_paths: list[Path]) -> Coverage:
    """Read one or more osv-scanner --format json --all-packages reports.

    Several reports because `--lockfile` and a positional directory cannot share
    one invocation (osv-scanner 2.3.1 exits 127 with "could not determine
    extractor suitable to this file"), so the action runs the directory walk and
    any explicit lockfiles separately and merges the coverage here.

    A missing file is not an error: osv-scanner writes no --output file at all
    when it finds no package sources, and that case is exactly what this gate
    exists to catch.
    """
    results: list[dict] = []
    for path in results_paths:
        if path is None or not path.exists():
            continue
        try:
            data = json.loads(path.read_text() or "{}")
        except json.JSONDecodeError as exc:
            raise SystemExit(f"::error::could not parse osv-scanner JSON report: {exc}")
        results.extend(data.get("results") or [])

    sources: list[dict] = []
    seen: set[str] = set()
    for result in results:
        # The walk and an explicit --lockfile can name the same file; count it once.
        path_key = result.get("source", {}).get("path", "?")
        if path_key in seen:
            continue
        seen.add(path_key)
        packages = result.get("packages") or []
        findings = []
        for pkg in packages:
            for vuln in pkg.get("vulnerabilities") or []:
                findings.append(
                    {
                        "id": vuln.get("id", "?"),
                        "name": pkg.get("package", {}).get("name", "?"),
                        "version": pkg.get("package", {}).get("version", "?"),
                    }
                )
        sources.append(
            {
                "path": result.get("source", {}).get("path", "?"),
                "type": result.get("source", {}).get("type", "?"),
                "packages": len(packages),
                "vulns": len(findings),
                "findings": findings,
            }
        )
    return Coverage(sources)


def relative(path: str) -> str:
    try:
        return str(Path(path).relative_to(Path.cwd()))
    except ValueError:
        return path


def render_database(db: Database, max_db_age: int) -> list[str]:
    """The database's vintage, on EVERY run.

    This line is half the fix. Without it a green says "no advisories" when what
    it means is "no advisories as of some date the reader cannot see, and has no
    way to ask about".
    """
    # A FUTURE build date is its own diagnosis, not a missing one. Reporting it
    # as merely "unknown" would send a reader looking for an absent marker when
    # what they have is a marker that says something impossible.
    if db.is_future():
        return [
            "> [!CAUTION]",
            f"> **Database build date is in the future** — `{db.where}` reports"
            f" it was built **{db.built_date}** (source: `{db.source}`), more"
            " than 24h ahead of this runner's clock. That date has not happened,"
            " so it is not a vintage: this run's database age counts as"
            " **unknown**, not as 0 days old. Fix the"
            f" `{MARKER_NAME}` marker, or the file times on the image.",
            "",
        ] + _spread_lines(db)

    if db.is_unknown:
        where = f" at `{db.where}`" if db.where else ""
        return [
            "> [!CAUTION]",
            f"> **Database age unknown** — no `{MARKER_NAME}` marker and no"
            f" `all.zip` found{where}, so this run cannot say how much of the"
            " CVE feed it saw.",
            "",
        ]

    age = db.age_days()
    note = f"OSV database built **{db.built_date}** — **{age}** day{'s' if age != 1 else ''} old (source: `{db.source}`)."
    if max_db_age and age is not None and age > max_db_age:
        return [
            "> [!CAUTION]",
            f"> {note} That is past `max-db-age: {max_db_age}`, so advisories"
            " published since were **not** considered.",
            "",
        ] + _spread_lines(db)
    return [note, ""] + _spread_lines(db)


def _spread_lines(db: Database) -> list[str]:
    """How many ecosystem databases were found, and whether they agree.

    One `all.zip` per seeded ecosystem, and a layer-cached image rebuild can
    refresh some and not others. The gate dates itself by the OLDEST, but a
    reader needs to see the divergence to know WHICH ecosystem to re-seed --
    otherwise a rotting npm database looks like a uniformly old image.
    """
    if not db.zip_count or db.oldest_zip is None or db.newest_zip is None:
        return []
    plural = "s" if db.zip_count != 1 else ""
    oldest = db.oldest_zip.date().isoformat()
    newest = db.newest_zip.date().isoformat()
    if oldest == newest:
        return [
            f"Found **{db.zip_count}** ecosystem database{plural}, all dated"
            f" {oldest}.",
            "",
        ]
    # Stated, not shouted. A day of spread is ordinary -- ecosystems download
    # minutes apart and can straddle midnight UTC -- so a callout here would cry
    # wolf on every run. The CAUTION above is what fires when the spread has
    # actually pushed the oldest past the threshold; this line is how a reader
    # sees WHICH ecosystem to re-seed instead of rebuilding the whole image.
    return [
        f"Found **{db.zip_count}** ecosystem database{plural}, spanning"
        f" **{oldest}** to **{newest}** — dated from the oldest, so a re-seeded"
        " ecosystem cannot vouch for one that a layer-cached rebuild left"
        " behind.",
        "",
    ]


def render(
    cov: Coverage,
    probe_hits: int | None,
    include_git_ignored: bool,
    db: Database,
    max_db_age: int,
) -> str:
    """Markdown for the job summary.

    Coverage is reported on EVERY run, not only on failure. A gate that only
    speaks up when it finds something teaches readers that silence means
    "clean", which is the assumption this whole action is correcting.
    """
    out: list[str] = ["### osv-scanner coverage", ""]
    out += render_database(db, max_db_age)

    if cov.is_empty:
        out += [
            "> [!CAUTION]",
            "> **Nothing was scanned.** Zero packages were examined, so this run"
            " proves nothing about dependency CVEs.",
            "",
        ]
        if probe_hits:
            out += [
                f"A probe with `--no-ignore` found **{probe_hits}** lockfile"
                f"{'s' if probe_hits != 1 else ''} that `.gitignore` excluded from"
                " the scan. Set `include-git-ignored: true` on this action.",
                "",
            ]
        elif not include_git_ignored:
            out += [
                "`include-git-ignored` is **false** and no lockfile was found"
                " either way — the repo genuinely appears to have no dependency"
                " manifest.",
                "",
            ]
        else:
            out += [
                "Gitignored files were included and still nothing matched, so the"
                " repo appears to have no lockfile osv-scanner recognises. If that"
                " is expected, set `allow-empty: true` to record the decision"
                " explicitly.",
                "",
            ]
        return "\n".join(out)

    out += [
        f"Examined **{cov.package_count}** package"
        f"{'s' if cov.package_count != 1 else ''} across **{cov.source_count}**"
        f" source{'s' if cov.source_count != 1 else ''}.",
        "",
        "| Source | Type | Packages | Vulnerabilities |",
        "|---|---|---:|---:|",
    ]
    for s in sorted(cov.sources, key=lambda s: s["path"]):
        out.append(
            f"| `{relative(s['path'])}` | {s['type']} | {s['packages']} | {s['vulns']} |"
        )
    out.append("")

    if cov.vuln_count:
        out += [f"#### {cov.vuln_count} known vulnerabilities", ""]
        for s in sorted(cov.sources, key=lambda s: s["path"]):
            for f in s["findings"]:
                out.append(
                    f"- `{f['name']}` {f['version']} — "
                    f"[{f['id']}](https://osv.dev/{f['id']}) "
                    f"({relative(s['path'])})"
                )
        out.append("")
    return "\n".join(out)


def decide(
    cov: Coverage,
    scanner_exit: int,
    allow_empty: bool,
    db: Database | None = None,
    max_db_age: int = 0,
    allow_stale_db: bool = False,
) -> tuple[int, str]:
    """Map coverage + scanner exit + database vintage onto this gate's verdict.

    Order is load-bearing:

      tool error -> real vulnerabilities -> stale database -> empty coverage

    Vulnerabilities outrank staleness because a finding from an OLD database is
    still a finding, and its message is the more actionable one. Staleness
    outranks emptiness for the same reason, and because `allow-empty` must never
    end up excusing a stale database -- the two escape hatches say different
    things and neither may stand in for the other.
    """
    if scanner_exit not in (EXIT_OK, EXIT_VULNS, EXIT_NO_SOURCES):
        return scanner_exit, (
            f"::error::osv-scanner failed with exit {scanner_exit} "
            "(a tool error, not a scan result)"
        )

    if cov.vuln_count:
        return 1, (
            f"::error::{cov.vuln_count} known vulnerabilities across "
            f"{cov.package_count} packages"
        )

    # max_db_age of 0 disables the FRESHNESS CHECK ENTIRELY -- the unknown and
    # future-dated cases included, not just the over-the-threshold one. That is
    # deliberate and documented: "0 means off" is the only reading a caller can
    # predict, and "off except when we cannot measure it" would fail a gate
    # someone had explicitly turned off. The age is still measured and still
    # printed wherever it can be -- opting out of the gate is not opting out of
    # knowing. A selftest case pins this so it cannot drift back.
    #
    # A downgraded staleness does NOT return here: it is carried forward, so
    # allow-stale-db cannot end up excusing an empty scan on its way past. The
    # selftest asserts that directly, having caught exactly that bug once.
    stale_note = ""
    if db is not None and max_db_age:
        age = db.age_days()
        stale = db.is_unknown or (age is not None and age > max_db_age)
        if stale and allow_stale_db:
            if db.is_future():
                stale_note = (
                    f"::warning::the OSV database reports a build date in the "
                    f"future ({db.built_date}), so its real age is unknown. "
                    "Continuing because allow-stale-db is set — this run's CVE "
                    "coverage has no known cutoff date."
                )
            elif db.is_unknown:
                stale_note = (
                    "::warning::the OSV database's age could not be determined. "
                    "Continuing because allow-stale-db is set — this run's CVE "
                    "coverage has no known cutoff date."
                )
            else:
                stale_note = (
                    f"::warning::the OSV database is {age} days old (built "
                    f"{db.built_date}). Continuing because allow-stale-db is set "
                    "— advisories published since then were NOT considered."
                )
        elif db.is_future():
            return 1, (
                f"::error::the OSV database reports a build date in the FUTURE "
                f"({db.built_date}, source: {db.source} at {db.where}), more "
                "than 24h ahead of this runner's clock, so its age cannot be "
                "measured. A date that has not happened is not a vintage: "
                "treating it as 0 days old would let a hand-edited or "
                "badly-stamped marker pass this gate forever, no matter what "
                "max-db-age said. An age this gate cannot measure is treated as "
                "stale. Fix the marker or the image's file times, or set "
                "allow-stale-db: true to state explicitly that freshness is not "
                "guaranteed here."
            )
        elif db.is_unknown:
            where = f" under {db.where}" if db.where else ""
            return 1, (
                f"::error::the OSV database's age could not be determined (no "
                f"{MARKER_NAME} marker and no all.zip{where}), so this gate "
                "cannot say how much of the CVE feed it examined. An age it "
                "cannot measure is treated as stale: 'no advisories' and 'no "
                "advisories as of an unknown date' are not the same result. "
                "Point this at a real database, or set allow-stale-db: true to "
                "state explicitly that freshness is not guaranteed here."
            )
        elif stale:
            return 1, (
                f"::error::the OSV database is {age} days old (built "
                f"{db.built_date}, max-db-age: {max_db_age}), so this gate could "
                "not see any advisory published since. A green from this "
                "database is indistinguishable from an unscanned one. Rebuild "
                "the runner image, raise max-db-age, or set allow-stale-db: true "
                "to state explicitly that freshness is not guaranteed here."
            )

    # A carried staleness warning rides along with whatever verdict follows; it
    # never replaces one.
    lead = f"{stale_note}\n" if stale_note else ""

    if cov.is_empty:
        if allow_empty:
            return 0, lead + (
                "::warning::osv-scanner examined 0 packages. Passing because "
                "allow-empty is set — this run provides NO dependency-CVE coverage."
            )
        return 1, lead + (
            "::error::osv-scanner examined 0 packages, so this gate verified "
            "nothing. A dependency-CVE gate that scans no packages must fail: "
            "'no vulnerabilities' and 'no packages examined' are not the same "
            "result. Fix the coverage, or set allow-empty: true to state "
            "explicitly that this repo has no dependencies to scan."
        )

    clean = (
        f"osv-scanner: no known vulnerabilities in {cov.package_count} packages "
        f"across {cov.source_count} sources"
    )
    # The date is part of the claim, not a footnote: "clean" without it is the
    # sentence this whole change exists to stop anyone writing.
    if db is not None and not db.is_unknown:
        return 0, lead + f"{clean}, against a database built {db.built_date}."
    return 0, lead + f"{clean}."


def _source(packages: int, vulns: int) -> dict:
    return {
        "path": "uv.lock",
        "type": "lockfile",
        "packages": packages,
        "vulns": vulns,
        "findings": [],
    }


def _db(days_old: int | None) -> Database:
    if days_old is None:
        return Database(None, "none", "/opt/osv-scanner-db")
    built = datetime.now(timezone.utc) - timedelta(days=days_old)
    return Database(built, "mtime", "/opt/osv-scanner-db")


def _db_ahead(hours: float) -> Database:
    """A database whose recorded build time is `hours` in the FUTURE."""
    built = datetime.now(timezone.utc) + timedelta(hours=hours)
    return Database(built, "marker", "/opt/osv-scanner-db/BAKED_AT")


def selftest_verdict() -> int:
    """Prove the verdict logic still distinguishes empty from clean, and a
    stale database from a fresh one.

    This is the check that keeps the fix from silently rotting: if someone later
    makes an empty scan or an old database pass, these cases fail and the gate
    fails with them.
    """
    fresh, stale, unknown = _db(1), _db(47), _db(None)
    skewed, ahead = _db_ahead(12), _db_ahead(48)
    far_future = Database(
        datetime(2099, 1, 1, tzinfo=timezone.utc), "marker", "/opt/osv-scanner-db/BAKED_AT"
    )
    empty = Coverage([])
    zero_packages = Coverage([_source(0, 0)])
    clean = Coverage([_source(1, 0)])
    vulnerable = Coverage([_source(1, 1)])

    # name, coverage, scanner exit, allow-empty, database, max-db-age,
    # allow-stale-db, expected exit
    cases = [
        ("nothing scanned, no file at all", empty, EXIT_NO_SOURCES, False, fresh, 30, False, 1),
        ("nothing scanned, allow-empty", empty, EXIT_NO_SOURCES, True, fresh, 30, False, 0),
        ("source found but zero packages", zero_packages, EXIT_OK, False, fresh, 30, False, 1),
        ("one clean package", clean, EXIT_OK, False, fresh, 30, False, 0),
        ("one vulnerable package", vulnerable, EXIT_VULNS, False, fresh, 30, False, 1),
        ("allow-empty must NOT mask real vulnerabilities", vulnerable, EXIT_VULNS, True, fresh, 30, False, 1),
        ("tool error is surfaced, not swallowed", empty, 127, True, fresh, 30, False, 127),
        # The database, which is what a clean scan's green actually rests on.
        ("stale database fails an otherwise clean scan", clean, EXIT_OK, False, stale, 30, False, 1),
        ("stale database passes with allow-stale-db", clean, EXIT_OK, False, stale, 30, True, 0),
        ("max-db-age 0 disables the threshold", clean, EXIT_OK, False, stale, 0, False, 0),
        ("unknown database age is treated as stale", clean, EXIT_OK, False, unknown, 30, False, 1),
        ("unknown database age passes with allow-stale-db", clean, EXIT_OK, False, unknown, 30, True, 0),
        # max-db-age 0 means OFF, including for an age nobody can measure. The
        # input's docs say so in as many words; this case is what keeps the two
        # from drifting apart again, and it is deliberate rather than an
        # oversight -- "off except sometimes" is not a setting anyone can predict.
        ("max-db-age 0 disables the check for an UNKNOWN age too (deliberate)", clean, EXIT_OK, False, unknown, 0, False, 0),
        # A build date in the future is a broken marker, not a very fresh
        # database. Clamping its age to 0 made a 2099 marker pass forever.
        ("12h in the future is clock skew: still fresh, still passes", clean, EXIT_OK, False, skewed, 30, False, 0),
        ("48h in the future is not a vintage: unknown, so stale", clean, EXIT_OK, False, ahead, 30, False, 1),
        ("a 2099 marker FAILS rather than reporting 0 days old", clean, EXIT_OK, False, far_future, 30, False, 1),
        ("a future-dated database passes with allow-stale-db", clean, EXIT_OK, False, far_future, 30, True, 0),
        ("max-db-age 0 disables the check for a future date too", clean, EXIT_OK, False, far_future, 0, False, 0),
        ("allow-empty must NOT excuse a future-dated database", empty, EXIT_NO_SOURCES, True, far_future, 30, False, 1),
        # The two escape hatches say different things; neither may cover for the
        # other, and neither may cover for a real finding.
        ("allow-stale-db must NOT mask real vulnerabilities", vulnerable, EXIT_VULNS, False, stale, 30, True, 1),
        ("allow-empty must NOT excuse a stale database", empty, EXIT_NO_SOURCES, True, stale, 30, False, 1),
        ("allow-stale-db must NOT excuse an empty scan", empty, EXIT_NO_SOURCES, False, stale, 30, True, 1),
    ]

    failures = 0
    for name, cov, rc, allow_empty, db, max_age, allow_stale, want in cases:
        got, _ = decide(cov, rc, allow_empty, db, max_age, allow_stale)
        status = "ok  " if got == want else "FAIL"
        if got != want:
            failures += 1
        print(f"  {status} {name}: want exit {want}, got {got}")
    return failures


def selftest_dating() -> int:
    """Prove the dating contract against real files on disk.

    House rule: prove the stat means what you think with a fixture rather than
    assuming it. Every branch of read_database() is exercised here, including
    the one that matters most -- that an unreadable marker falls back to the
    mtime rather than collapsing to "unknown" and failing the gate.
    """
    checks: list[tuple[str, object, object]] = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        db = read_database(root)
        checks.append(("empty directory reports unknown", db.source, "none"))
        checks.append(("unknown has no build date", db.is_unknown, True))

        eco = root / "osv-scanner" / "PyPI"
        eco.mkdir(parents=True)
        zipped = eco / "all.zip"
        zipped.write_bytes(b"")
        old = datetime.now(timezone.utc) - timedelta(days=12)
        os.utime(zipped, (old.timestamp(), old.timestamp()))

        db = read_database(root)
        checks.append(("all.zip mtime is used when nothing else is", db.source, "mtime"))
        checks.append(("mtime age is measured, not guessed", db.age_days(), 12))
        checks.append(("a single zip is counted", db.zip_count, 1))

        # A SECOND ecosystem, freshly seeded. This is the layer-cache case: one
        # ecosystem re-downloaded, the rest left as they were. The gate must
        # date the database by the OLD one -- dating by the new one would let a
        # re-seeded PyPI vouch for an npm database nobody refreshed.
        eco2 = root / "osv-scanner" / "npm"
        eco2.mkdir(parents=True)
        fresh_zip = eco2 / "all.zip"
        fresh_zip.write_bytes(b"")
        recent = datetime.now(timezone.utc) - timedelta(days=2)
        os.utime(fresh_zip, (recent.timestamp(), recent.timestamp()))

        db = read_database(root)
        checks.append(("two zips are both counted", db.zip_count, 2))
        checks.append(("a divergent image is dated by its OLDEST zip", db.age_days(), 12))
        checks.append(("the spread is reported, not just the verdict", db.newest_zip.date(), recent.date()))

        fresh_zip.unlink()
        eco2.rmdir()

        marker = root / MARKER_NAME
        marker.write_text("2020-01-01T00:00:00Z", encoding="utf-8")
        db = read_database(root)
        checks.append(("a marker outranks the mtime", db.source, "marker"))
        checks.append(("the marker's date is read, not the file's", db.built_date, "2020-01-01"))

        marker.write_text("2020-01-02", encoding="utf-8")
        db = read_database(root)
        checks.append(("a bare YYYY-MM-DD marker parses", db.built_date, "2020-01-02"))

        marker.write_text("not a date at all", encoding="utf-8")
        db = read_database(root)
        checks.append(("an unparseable marker falls back to mtime", db.source, "mtime"))

        checks.append(("no directory at all reports unknown", read_database(None).source, "none"))

        # A marker the image stamped from the future. Within a day it is clock
        # skew and gets clamped; past that it is not a vintage at all, and the
        # UNKNOWN answer is what stops it passing forever.
        skew = Database(datetime.now(timezone.utc) + timedelta(hours=12), "marker")
        checks.append(("12h ahead is skew: clamped to 0", skew.age_days(), 0))
        checks.append(("12h ahead is not treated as unknown", skew.is_unknown, False))

        ahead = Database(datetime.now(timezone.utc) + timedelta(hours=48), "marker")
        checks.append(("48h ahead has no measurable age", ahead.age_days(), None))
        checks.append(("48h ahead reads as unknown, not fresh", ahead.is_unknown, True))
        checks.append(("48h ahead is distinguishable from a missing marker", ahead.is_future(), True))

        far = Database(datetime(2099, 1, 1, tzinfo=timezone.utc), "marker")
        checks.append(("a 2099 marker has no age, rather than 0", far.age_days(), None))
        checks.append(("a 2099 marker still reports its bogus date", far.built_date, "2099-01-01"))
        checks.append(("a missing marker is NOT reported as future-dated", Database(None, "none").is_future(), False))

    failures = 0
    for name, got, want in checks:
        status = "ok  " if got == want else "FAIL"
        if got != want:
            failures += 1
        print(f"  {status} {name}: want {want!r}, got {got!r}")
    return failures


def selftest() -> int:
    failures = selftest_verdict() + selftest_dating()
    if failures:
        print(f"::error::osv_coverage selftest: {failures} case(s) failed")
        return 1
    print("osv_coverage selftest: all cases passed")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results", type=Path, action="append", default=[])
    ap.add_argument("--scanner-exit", type=int, default=0)
    ap.add_argument("--allow-empty", action="store_true")
    ap.add_argument("--include-git-ignored", action="store_true")
    ap.add_argument(
        "--db-dir",
        type=Path,
        default=None,
        help="offline database cache directory, dated per read_database()",
    )
    ap.add_argument(
        "--max-db-age",
        type=int,
        default=0,
        help="days; past this the database is stale and the gate fails. 0 = off",
    )
    ap.add_argument("--allow-stale-db", action="store_true")
    ap.add_argument(
        "--probe-hits",
        type=int,
        default=None,
        help="lockfiles a --no-ignore probe found after an empty scan",
    )
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    cov = load_coverage(args.results)
    db = read_database(args.db_dir)
    summary = render(cov, args.probe_hits, args.include_git_ignored, db, args.max_db_age)

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(summary + "\n")
    print(summary)

    code, message = decide(
        cov,
        args.scanner_exit,
        args.allow_empty,
        db,
        args.max_db_age,
        args.allow_stale_db,
    )
    print(message)
    return code


if __name__ == "__main__":
    sys.exit(main())
