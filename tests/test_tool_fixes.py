r"""
针对一批真实报错的回归测试（Win7 现场反馈）。

每个用例都对应一个曾经发生过的具体故障，断言"不再出现那种错误特征"：

  * list_handles      信息类用了 62（应为 64）→ needed 是垃圾值 → 一路扩容 →「句柄表过大」
  * list_wmi_subscriptions  IID_IWbemLocator 写错 → CoCreateInstance 0x80004002
  * get_* 日志类      EvtQuery 标志误用 0x2000 → 每次「错误 87」
  * enumerate_registry_tree  正斜杠子路径 → 「键不存在（错误 2）」
  * get_recent_files  卷参数带冒号 → \\.\C:: → 「打开卷失败（错误 2）」
  * query_events process/network/fileio  只报「通道未找到」，没有可用的回退
  * list_scheduled_tasks  schtasks 失败被静默吞掉 → 返回 0 条
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import pathlib

import pytest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "tests"))

from avengine import core_bridge  # noqa: E402
from test_ai_tools_ext import MY_PID, _run  # noqa: E402

pytestmark = pytest.mark.skipif(
    not core_bridge.is_available(), reason="avengine_core.dll 未构建（先运行 cpp/build.bat）"
)


def _text(ev):
    return ev["detail"]


SYSTEM_FILE = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "cmd.exe")


def _json_or_error(text):
    if text.startswith("ERROR"):
        return None
    return json.loads(text)


# ------------------------------------------------------------ 句柄表（过滤契约）


def test_list_handles_requires_a_filter(tmp_path):
    """整表不返回：没有过滤条件时必须拒绝，并说明可用条件。"""
    _, ev = _run(tmp_path, "list_handles", {"pid": MY_PID})
    text = _text(ev)
    assert text.startswith("ERROR"), text
    assert "过滤条件" in text
    for key in ("type", "name", "handle"):
        assert key in text
    # 不能再出现"句柄表过大"这种信息类用错导致的失败
    assert "句柄表过大" not in text


def test_list_handles_bad_handle_value(tmp_path):
    _, ev = _run(tmp_path, "list_handles", {"pid": MY_PID, "handle": "不是数字"})
    text = _text(ev)
    assert text.startswith("ERROR") and "handle" in text


def test_list_handles_with_filter_is_actionable(tmp_path):
    """带过滤条件时：要么给出结果（管理员），要么明确说明需要管理员，不能报"过大"。"""
    _, ev = _run(tmp_path, "list_handles", {"pid": MY_PID, "type": "File"})
    text = _text(ev)
    assert "句柄表过大" not in text
    data = _json_or_error(text)
    if data is None:
        assert "管理员" in text, text
    else:
        assert "handles" in data and "type_counts" in data and "diagnostics" in data


def test_list_handles_diagnostics_and_budget_args(tmp_path):
    """
    抗卡顿改造的契约：接受 budget_ms / name_limit；有结果时必须带 diagnostics，
    这样"卡在哪一层"可以直接从输出看出来（表抖动 churn_bytes、复制次数 dup_attempted、
    名字解析超时 name_timeouts、停止原因 stopped_reason）。
    """
    _, ev = _run(tmp_path, "list_handles",
                 {"pid": MY_PID, "type": "any", "budget_ms": 1000, "name_limit": 10})
    text = _text(ev)
    data = _json_or_error(text)
    if data is None:
        # 非管理员只能拿到权限错误（系统句柄表在 Win7+ 必须管理员才能读）
        assert "管理员" in text, text
        return
    diag = data.get("diagnostics")
    assert isinstance(diag, dict), text
    for key in ("budget_ms", "elapsed_ms", "snapshot_attempts", "table_entries",
                "churn_bytes", "dup_attempted", "dup_failed", "type_rescue_attempts",
                "name_attempts", "name_timeouts", "name_worker_total_timeouts",
                "target_alive_at_end", "pid_reuse_detected", "stopped_reason"):
        assert key in diag, f"diagnostics 缺字段 {key}"
    assert diag["budget_ms"] == 1000
    assert diag["elapsed_ms"] <= 30000
    # 概览模式：不做逐句柄复制，复制次数应该是"类型数"量级而不是句柄数量级
    assert diag["dup_attempted"] <= max(32, diag["table_entries"])


def test_list_handles_reports_target_identity(tmp_path):
    """第 4 层：结果里要带目标身份（创建时间/路径/存活），并标出是否为半成品。"""
    _, ev = _run(tmp_path, "list_handles", {"pid": MY_PID, "type": "any"})
    data = _json_or_error(_text(ev))
    if data is None:
        pytest.skip("受限环境读不到系统句柄表（需要管理员）")
    target = data.get("target")
    assert isinstance(target, dict), data
    for key in ("pid", "name", "created", "alive", "pid_reused"):
        assert key in target, f"target 缺字段 {key}"
    assert target["pid"] == MY_PID
    assert target["pid_reused"] is False
    assert "partial" in data


def test_list_handles_overview_does_not_resolve_names(tmp_path):
    """第 3 层：默认不做名字解析——概览模式下 name_attempts 必须是 0。"""
    _, ev = _run(tmp_path, "list_handles", {"pid": MY_PID, "type": "any"})
    data = _json_or_error(_text(ev))
    if data is None:
        pytest.skip("受限环境读不到系统句柄表（需要管理员）")
    diag = data["diagnostics"]
    assert diag["name_attempts"] == 0
    assert diag["name_worker_total_timeouts"] == 0


def test_list_handles_missing_pid_fails_fast(tmp_path):
    """
    PID 不存在（看门狗把宿主换掉后的典型情况）必须在做任何昂贵操作之前就报清楚。
    这条不需要管理员，因此在本机也能验证。
    """
    _, ev = _run(tmp_path, "list_handles", {"pid": 999999, "type": "File"})
    text = _text(ev)
    assert text.startswith("ERROR"), text
    assert "进程不存在" in text, text
    assert "句柄表" not in text or "无效" in text


# ------------------------------------------------------------------------ WMI


def test_wmi_subscriptions_not_interface_error(tmp_path):
    """IID 写错时是 0x80004002（E_NOINTERFACE）；修好后要么有数据，要么是权限问题。"""
    _, ev = _run(tmp_path, "list_wmi_subscriptions", {})
    text = _text(ev)
    assert "0x80004002" not in text and "80004002" not in text
    data = _json_or_error(text)
    if data is None:
        # 允许"需要管理员"这类真实限制，但必须是 WMI 之后阶段的错误
        assert ("ConnectServer" in text or "查询" in text or "权限" in text or "WMI" in text), text
    else:
        for key in ("filters", "consumers", "bindings"):
            assert key in data


# ------------------------------------------------- EvtQuery 标志（错误 87 回归）


@pytest.mark.parametrize("tool,args", [
    ("get_script_block_log", {"hours": 24, "limit": 2}),
    ("get_security_log", {"hours": 24, "limit": 2}),
    ("get_etw", {"channel": "System", "hours": 24, "limit": 2}),
    ("get_amsi_events", {"limit": 2}),
])
def test_event_log_tools_not_error_87(tmp_path, tool, args):
    """
    EvtQuery 的 flags 曾经写成 0x2000（非法值）→ 每次都返回错误 87。
    正确值是 EvtQueryReverseDirection = 0x200。
    """
    _, ev = _run(tmp_path, tool, args)
    text = _text(ev)
    assert "错误 87" not in text, f"{tool} 又出现错误 87: {text[:200]}"


def test_get_etw_renders_time_stamp(tmp_path):
    """
    事件 XML 的属性是单引号（SystemTime='...'），只认双引号会导致 time= 为空。
    """
    _, ev = _run(tmp_path, "get_etw", {"channel": "System", "hours": 24, "limit": 2})
    data = _json_or_error(_text(ev))
    if data is None or not data.get("events"):
        pytest.skip("本机 System 通道没有可用事件")
    assert "time=" in data["events"][0]
    # 形如 time=2026-10-04T13:04:37.5514069Z
    assert data["events"][0].split("time=", 1)[1][:4].isdigit(), data["events"][0][:160]


# --------------------------------------------------------- 注册表分隔符与卷参数


def test_registry_tree_forward_slashes(tmp_path):
    """HKLM/SOFTWARE/Microsoft 这种正斜杠写法以前报"键不存在（错误 2）"。"""
    _, ev = _run(tmp_path, "enumerate_registry_tree",
                 {"key": "HKLM/SOFTWARE/Microsoft", "depth": 1, "values": True, "limit": 10})
    text = _text(ev)
    assert "错误 2" not in text and "键不存在" not in text
    data = json.loads(text)
    assert data["count"] >= 1, text


@pytest.mark.parametrize("volumes", ["C", "C:", "C:\\", "\\\\.\\C:"])
def test_recent_files_volume_forms(tmp_path, volumes):
    r"""卷参数的各种写法都应被规范化；拼成 \\.\C:: 会报错误 2。"""
    _, ev = _run(tmp_path, "get_recent_files", {"hours": 1, "volumes": volumes, "limit": 3})
    text = _text(ev)
    assert "错误 2" not in text, f"volumes={volumes!r} 又出现错误 2: {text[:200]}"
    assert "卷设备路径无效" not in text


def test_recent_files_rejects_garbage_volume(tmp_path):
    _, ev = _run(tmp_path, "get_recent_files", {"hours": 1, "volumes": "C:\\Windows", "limit": 3})
    text = _text(ev)
    assert text.startswith("ERROR") and "盘符" in text, text


# ------------------------------------------------------------------ 事件源回退


@pytest.mark.parametrize("source", ["process", "network", "fileio"])
def test_event_sources_report_fallback_chain(tmp_path, source):
    """
    Win7 没有 Kernel-* 通道。要么拿到数据（已回退到 Sysmon/Security），
    要么错误里必须列出尝试过的候选通道，不能只说一句"通道未找到"。
    """
    _, ev = _run(tmp_path, "grep_events", {"source": source, "hours": 24, "limit": 3})
    text = _text(ev)
    if text.startswith("ERROR"):
        assert "候选通道" in text or "回退" in text, text
        assert "Sysmon" in text, text          # 至少提到 Sysmon 这个回退目标
    else:
        assert "回退到" in text or "（无匹配事件）" in text


# ------------------------------------------------------------------ 计划任务


def test_scheduled_tasks_never_silently_empty(tmp_path):
    """schtasks 失败/超时/挂起时都必须报错或说明来源，不能静默返回 0 条。"""
    _, ev = _run(tmp_path, "list_scheduled_tasks", {"limit": 5})
    text = _text(ev)
    data = _json_or_error(text)
    if data is None:
        # 明确的失败（schtasks 报错、超时，或任务库读不到）都可以，静默空列表不行
        assert any(k in text for k in ("schtasks", "任务库", "超时")), text
    else:
        assert data.get("returned", 0) > 0 or "note" in data or data.get("source") == "tasks_dir", data


def test_verify_signature_never_claims_unsigned_for_system_file(tmp_path):
    """
    回归守卫：系统目录文件大量使用 catalog 签名，而 catalog 校验在部分环境（Win7、
    catalog 库不可读）下不可用 —— 此时 WinVerifyTrust 返回 TRUST_E_NOSIGNATURE。
    早期实现直接判"无签名"，导致 build_static_report 把 C:\\Windows\\System32\\cmd.exe
    标成 suspicious（AI 实测报过这个误报）。

    现在 signed 只允许 true / null（未知），为 null 时必须带说明。
    """
    _, ev = _run(tmp_path, "verify_signature", {"path": SYSTEM_FILE})
    text = _text(ev)
    assert not text.startswith("ERROR"), text
    data = json.loads(text)
    assert data["signed"] is not False, text
    if data["signed"] is None:
        assert data.get("note"), "判不了就必须说明原因"
        assert "catalog" in data["status"] or "catalog" in data["note"]


def test_list_scheduled_tasks_retries_without_nh():
    """
    回归守卫：部分系统（实测 Win7 中文版）对 `schtasks /query /fo CSV /nh` 会报
    "/NH 开关不能与 LIST 格式同时使用"，计划任务枚举因此完全失效。
    工具必须在不带 /NH 的 CSV 形式重试一次，而不是直接放弃。
    """
    source = (PROJECT_ROOT / "cpp" / "src" / "ai" / "ai_tools.cpp").read_text(
        encoding="utf-8", errors="replace")
    assert "schtasks /query /fo CSV /nh" in source
    assert 'schtasks /query /fo CSV"' in source, "必须有去掉 /NH 的重试"
    assert "不接受 /NH" in source
    assert "skip_header" in source


def test_list_firewall_rules_timeout_is_generous():
    """
    netsh 在规则多的机器上很慢（Win7 实测超过 120 秒），默认超时必须放宽到 300 秒、
    上限 15 分钟，并在超时时给出可操作建议。
    """
    source = (PROJECT_ROOT / "cpp" / "src" / "ai" / "ai_tools_net.cpp").read_text(
        encoding="utf-8", errors="replace")
    assert 'parse_int_arg(args, "timeout_ms", 300000)' in source
    assert "900000" in source
    assert "profile=domain|private|public" in source


def test_service_child_process_has_no_console():
    """
    回归守卫：SYSTEM 子进程必须用 DETACHED_PROCESS（完全无控制台）。

    打包版 avengine.exe 用 Nuitka 的 --windows-console-mode=attach，子进程启动时会尝试
    AttachConsole/新建控制台，一旦成功就把 stdout 重新指向 CONOUT$，绕过服务重定向到
    日志文件的句柄 —— 表现就是子进程输出跑到别处、半行文本混进用户命令行（实测见过）。
    """
    source = (PROJECT_ROOT / "service" / "AvEnginePrivSvc.cpp").read_text(encoding="utf-8")
    assert "DETACHED_PROCESS" in source
    assert "CREATE_UNICODE_ENVIRONMENT | DETACHED_PROCESS" in source
