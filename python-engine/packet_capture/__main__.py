"""Module entry point so ``py -m packet_capture`` works.

Delegates to :mod:`packet_capture.cli` for argument parsing and dispatch.
"""

from __future__ import annotations

import sys

from packet_capture.cli import main

if __name__ == "__main__":
    sys.exit(main())
