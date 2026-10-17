"""
avengine.gui - Tkinter 图形界面

设计取向：
  * 每个标签页对应一个子系统（概览/扫描/监控/AI/Sysmon/ClamAV/特权服务/设置/日志），
    用户不用记命令行；
  * 页面只做 UI，所有系统操作在 `ops.py`（无 Tk 依赖，可单测）；
  * 耗时操作一律走主窗口的后台任务运行器，界面不会卡死；
  * 需要管理员的功能在非管理员下自动置灰并说明原因。

入口：
    python -m avengine.gui        （或 avengine.exe gui）
"""

from __future__ import annotations

from .app import AvEngineGUI, launch

__all__ = ["AvEngineGUI", "launch"]
