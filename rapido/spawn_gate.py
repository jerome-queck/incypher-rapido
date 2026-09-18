"""Hold a supervised child before exec until its parent explicitly releases it."""

from __future__ import annotations

import os
import sys


def main(argv: list[str] | None = None) -> int:
    selected = sys.argv[1:] if argv is None else argv
    if len(selected) < 3 or selected[1] != "--":
        return 125
    try:
        gate_fd = int(selected[0])
    except ValueError:
        return 125
    command = selected[2:]
    try:
        released = os.read(gate_fd, 1)
    except OSError:
        return 125
    finally:
        try:
            os.close(gate_fd)
        except OSError:
            pass
    if released != b"1":
        return 125
    try:
        os.execvpe(command[0], command, os.environ)
    except OSError:
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
