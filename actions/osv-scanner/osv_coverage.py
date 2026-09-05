#!/usr/bin/env python3
"""Turn an osv-scanner JSON report into a verdict that distinguishes
"no vulnerabilities" from "no packages examined".

osv-scanner cannot make that distinction on its own. Its default JSON report is
byte-identical (`{"results": []}`) whether it scanned a clean lockfile or
scanned nothing at all, and `--allow-no-lockfiles` collapses the difference
further by printing "No package sources found / No issues found" and exiting 0.
A gate built on either of those reports coverage it does not have.

So the gate asserts coverage explicitly: scan with --all-packages (which does
record every scanned source, vulnerable or not), then require that at least one
source and at least one package were actually examined. Zero coverage is a
failure with a diagnostic, never a pass.

Stdlib only, and no network: this runs on an egress-free runner.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# osv-scanner exit codes we understand. Anything else is a tool failure we must
# not paper over.
EXIT_OK = 0
EXIT_VULNS = 1
EXIT_NO_SOURCES = 128


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


def render(cov: Coverage, probe_hits: int | None, include_git_ignored: bool) -> str:
    """Markdown for the job summary.

    Coverage is reported on EVERY run, not only on failure. A gate that only
    speaks up when it finds something teaches readers that silence means
    "clean", which is the assumption this whole action is correcting.
    """
    out: list[str] = ["### osv-scanner coverage", ""]

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


def decide(cov: Coverage, scanner_exit: int, allow_empty: bool) -> tuple[int, str]:
    """Map coverage + scanner exit onto this gate's verdict."""
    if scanner_exit not in (EXIT_OK, EXIT_VULNS, EXIT_NO_SOURCES):
        return scanner_exit, (
            f"::error::osv-scanner failed with exit {scanner_exit} "
            "(a tool error, not a scan result)"
        )

    if cov.is_empty:
        if allow_empty:
            return 0, (
                "::warning::osv-scanner examined 0 packages. Passing because "
                "allow-empty is set — this run provides NO dependency-CVE coverage."
            )
        return 1, (
            "::error::osv-scanner examined 0 packages, so this gate verified "
            "nothing. A dependency-CVE gate that scans no packages must fail: "
            "'no vulnerabilities' and 'no packages examined' are not the same "
            "result. Fix the coverage, or set allow-empty: true to state "
            "explicitly that this repo has no dependencies to scan."
        )

    if cov.vuln_count:
        return 1, (
            f"::error::{cov.vuln_count} known vulnerabilities across "
            f"{cov.package_count} packages"
        )

    return 0, (
        f"osv-scanner: no known vulnerabilities in {cov.package_count} packages "
        f"across {cov.source_count} sources."
    )


def selftest() -> int:
    """Prove the verdict logic still distinguishes empty from clean.

    This is the check that keeps the fix from silently rotting: if someone later
    makes an empty scan pass, these cases fail and the gate fails with them.
    """
    cases = [
        ("nothing scanned, no file at all", Coverage([]), EXIT_NO_SOURCES, False, 1),
        ("nothing scanned, allow-empty", Coverage([]), EXIT_NO_SOURCES, True, 0),
        (
            "source found but zero packages",
            Coverage([{"path": "r.txt", "type": "lockfile", "packages": 0, "vulns": 0, "findings": []}]),
            EXIT_OK,
            False,
            1,
        ),
        (
            "one clean package",
            Coverage([{"path": "uv.lock", "type": "lockfile", "packages": 1, "vulns": 0, "findings": []}]),
            EXIT_OK,
            False,
            0,
        ),
        (
            "one vulnerable package",
            Coverage([{"path": "uv.lock", "type": "lockfile", "packages": 1, "vulns": 1, "findings": []}]),
            EXIT_VULNS,
            False,
            1,
        ),
        (
            "allow-empty must NOT mask real vulnerabilities",
            Coverage([{"path": "uv.lock", "type": "lockfile", "packages": 1, "vulns": 1, "findings": []}]),
            EXIT_VULNS,
            True,
            1,
        ),
        ("tool error is surfaced, not swallowed", Coverage([]), 127, True, 127),
    ]

    failures = 0
    for name, cov, rc, allow_empty, want in cases:
        got, _ = decide(cov, rc, allow_empty)
        status = "ok  " if got == want else "FAIL"
        if got != want:
            failures += 1
        print(f"  {status} {name}: want exit {want}, got {got}")

    if failures:
        print(f"::error::osv_coverage selftest: {failures} case(s) failed")
        return 1
    print(f"osv_coverage selftest: {len(cases)} cases passed")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results", type=Path, action="append", default=[])
    ap.add_argument("--scanner-exit", type=int, default=0)
    ap.add_argument("--allow-empty", action="store_true")
    ap.add_argument("--include-git-ignored", action="store_true")
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
    summary = render(cov, args.probe_hits, args.include_git_ignored)

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(summary + "\n")
    print(summary)

    code, message = decide(cov, args.scanner_exit, args.allow_empty)
    print(message)
    return code


if __name__ == "__main__":
    sys.exit(main())
