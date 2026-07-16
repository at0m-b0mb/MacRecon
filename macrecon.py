#!/usr/bin/env python3
"""MacRecon — macOS information gatherer for security assessment.

    python3 macrecon.py                  # GUI, redaction on
    python3 macrecon.py --no-redact      # GUI, show real identifiers
    python3 macrecon.py --demo           # GUI, synthetic data (any OS)
    python3 macrecon.py --cli            # terminal report
    python3 macrecon.py --cli -o out.html

MacRecon is read-only: it observes this Mac and changes nothing. Only run it
against machines you own or are explicitly authorised to assess.
"""

from __future__ import annotations

import argparse
import platform
import sys


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="macrecon",
        description="Read-only macOS reconnaissance: system, hardware, users, "
                    "network, software, persistence and a graded security "
                    "audit.",
        epilog="Only scan machines you own or are authorised to assess.",
    )
    p.add_argument("--cli", action="store_true",
                   help="print the report to the terminal instead of opening "
                        "the GUI")
    p.add_argument("--demo", action="store_true",
                   help="use the bundled synthetic dataset instead of reading "
                        "this machine (works on any OS)")
    p.add_argument("--no-redact", action="store_true",
                   help="show real identifiers (serial, UUID, MACs, IPs, "
                        "usernames, SSIDs) instead of masking them")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="write the report to FILE; format is chosen from the "
                        "extension (.html, .json, .txt)")
    p.add_argument("--version", action="store_true", help="print version")
    return p


def _run_cli(redact: bool, output: str | None) -> int:
    from macrecon.collectors import ALL_COLLECTORS
    from macrecon.redact import Redactor
    from macrecon.report import to_html, to_json, to_text

    cats = []
    for collector in ALL_COLLECTORS:
        print(f"  collecting {collector.name}…", file=sys.stderr)
        try:
            cats.append(collector.collect())
        except Exception as exc:
            print(f"    ! {collector.name} failed: {exc}", file=sys.stderr)

    cats = Redactor(redact).apply(cats)

    if output:
        if output.endswith(".json"):
            data = to_json(cats, redact)
        elif output.endswith(".html"):
            data = to_html(cats, redact)
        else:
            data = to_text(cats, redact)
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(data)
        print(f"\nReport written to {output}", file=sys.stderr)
        if not redact:
            print("  ! UNREDACTED — this file identifies this Mac. "
                  "Store it encrypted.", file=sys.stderr)
    else:
        print(to_text(cats, redact))
    return 0


def main() -> int:
    args = _parser().parse_args()

    if args.version:
        import macrecon

        print(f"MacRecon {macrecon.__version__} by {macrecon.__author__}")
        return 0

    from macrecon.collectors.base import IS_MACOS, set_demo_mode

    set_demo_mode(args.demo)

    if not IS_MACOS and not args.demo:
        print(
            f"MacRecon reads macOS; this is {platform.system()}.\n"
            "Falling back to the bundled synthetic dataset so you can explore "
            "the interface. Use --demo to silence this.\n",
            file=sys.stderr,
        )

    redact = not args.no_redact

    if args.cli:
        return _run_cli(redact, args.output)

    try:
        from PyQt6.QtWidgets import QApplication
    except ImportError:
        print(
            "PyQt6 is not installed, so the GUI can't start.\n"
            "  pip install -r requirements.txt\n"
            "Or run the terminal report instead:\n"
            "  python3 macrecon.py --cli",
            file=sys.stderr,
        )
        return 1

    from macrecon.gui.main_window import MainWindow
    from macrecon.gui.theme import stylesheet

    app = QApplication(sys.argv)
    app.setApplicationName("MacRecon")
    app.setStyleSheet(stylesheet())
    win = MainWindow(redact=redact)
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
