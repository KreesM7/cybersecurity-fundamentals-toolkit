"""Launch the authenticated PyQt6 desktop."""

import sys


def main() -> int:
    if sys.argv[1:2] == ["secdesk"]:
        from toolkit.secdesk.cli import main as secdesk_main

        return secdesk_main(sys.argv[2:])
    if sys.argv[1:2] == ["lowrea"]:
        from toolkit.lowrea.cli import main as lowrea_main

        return lowrea_main(sys.argv[2:])
    from frontend.app import main as desktop_main

    return desktop_main()


if __name__ == "__main__":
    raise SystemExit(main())
