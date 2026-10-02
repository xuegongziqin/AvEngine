"""Nuitka/PyInstaller 打包入口：等价于 `python -m avengine`。"""

from __future__ import annotations

import sys

from avengine.cli import main

if __name__ == "__main__":
    sys.exit(main())
