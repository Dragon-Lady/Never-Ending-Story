from __future__ import annotations

import argparse
from pathlib import Path

from .scanner import render_markdown, scan_path


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="never-ending-story",
        description="Local announce-only Fire Door trust-surface scanner.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Path to scan")
    parser.add_argument(
        "--out",
        help="Optional Markdown report path. Parent directory must already exist.",
    )
    args = parser.parse_args()

    report = scan_path(args.path)
    markdown = render_markdown(report)

    if args.out:
        Path(args.out).write_text(markdown, encoding="utf-8")
    else:
        print(markdown)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
