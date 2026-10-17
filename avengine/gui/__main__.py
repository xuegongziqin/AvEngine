"""python -m avengine.gui —— GUI 入口。"""

from __future__ import annotations

import sys

from .app import launch

if __name__ == "__main__":
    sys.exit(launch(sys.argv[1:]))
