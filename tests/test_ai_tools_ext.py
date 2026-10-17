"""
AI 扩展工具（todolist.txt 36 项）验收测试。

用本地 mock SSE 服务当模型：每条用例让 mock 模型调用一个工具、然后回答 END，
从而验证「工具已注册、可执行、返回合法 JSON / 明确 ERROR、处置类支持 dry-run、审计有记录」。

环境受限时（如 Security 日志/USN/WMI 需要管理员），工具应返回明确的 ERROR 文本而不是崩溃，
这类用例两种结果都接受。
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import sys

import pytest

from avengine import core_bridge

pytestmark = pytest.mark.skipif(
    not core_bridge.is_available(), reason="avengine_core.dll 未构建（先运行 cpp/build.bat）"
)

sys.path.insert(0, os.path.dirname(__file__))
from test_ai_stream import MockServer, _chunk  # noqa: E402

MY_PID = os.getpid()
MY_TID = ctypes.windll.kernel32.GetCurrentThreadId()


def _round(tool: str, args: dict):
    return [
        _chunk({"tool_calls": [{"index": 0, "id": "call_1",
                                "function": {"name": tool, "arguments": json.dumps(args)}}]}),
    ]


def _base_payload(tmp_path):
    payload = {
        "base_url": "", "api_key": "", "model": "mock", "timeout": 10, "max_rounds": 2,
        "rules_path": str(tmp_path / "rules"),
        "quarantine_dir": str(tmp_path / "quarantine"),
        "log_file": str(tmp_path / "avengine.log"),
        "dump_dir": str(tmp_path / "dumps"),
        "project_root": str(tmp_path),
        "audit_log_file": str(tmp_path / "audit.log"),
        "clam_host": "", "clam_port": 0,
    }
    os.makedirs(str(tmp_path / "rules" / "yara"), exist_ok=True)
    return payload


def _run(tmp_path, tool, args):
    """让 mock 模型调用一次工具并回答。

    返回 (最终结果, {"detail": 完整工具输出文本})。
    完整输出取自 mock 收到的第二轮请求里的 role=tool 消息——
    事件流里的 detail 只是首行 200 字符预览，不能用于断言完整 JSON。
    """
    payload = _base_payload(tmp_path)
    events = []
    with MockServer([_round(tool, args), [_chunk({"content": "好。\nEND"})]]) as server:
        payload["base_url"] = server.base_url
        result = core_bridge.ai_ask_stream(payload, "测试工具", events.append)
        requests = list(server.requests)

    full = None
    if len(requests) >= 2:
        for m in requests[1].get("messages", []):
            if m.get("role") == "tool":
                full = m.get("content")
                break
    if full is None:
        detail = [e for e in events if e["kind"] == "tool_result"]
        full = detail[0]["detail"] if detail else ""
    return result, {"detail": full}


def _json_or_error(detail_text):
    """工具结果要么是 JSON，要么是明确的 ERROR 文本（受限环境下可接受）。"""
    if detail_text.startswith("ERROR"):
        return None
    return json.loads(detail_text)


# ---------------------------------------------------------------- 一、进程/内存

def test_get_process_tree(tmp_path):
    _, ev = _run(tmp_path, "get_process_tree", {"pid": MY_PID, "depth": 2})
    data = json.loads(ev["detail"])
    assert data["root"] == MY_PID and data["count"] >= 1
    assert data["tree"][0]["pid"] == MY_PID


def test_get_parent_chain(tmp_path):
    _, ev = _run(tmp_path, "get_parent_chain", {"pid": MY_PID})
    data = json.loads(ev["detail"])
    assert data["chain"][0]["pid"] == MY_PID and data["depth"] >= 1


def _json_or_none(text):
    """工具结果要么是 JSON，要么是 ERROR 文本（沙箱/权限受限时可接受），返回 (data, is_error)。"""
    if text.startswith("ERROR"):
        return None, True
    return json.loads(text), False


def test_get_process_commandline(tmp_path):
    _, ev = _run(tmp_path, "get_process_commandline", {"pid": MY_PID})
    data, is_err = _json_or_none(ev["detail"])
    if is_err:
        pytest.skip("受限环境读不到 PEB（需要完整 OpenProcess 权限）: " + ev["detail"][:80])
    assert data["exe"]
    # 沙箱受限令牌可能读不到命令行（正常机器上可读）
    if data["commandline"]:
        assert isinstance(data["commandline"], str)
    assert data["peb_layout"] in ("verified", "unverified")


def test_get_process_env(tmp_path):
    _, ev = _run(tmp_path, "get_process_env", {"pid": MY_PID, "limit": 20})
    data, is_err = _json_or_none(ev["detail"])
    if is_err:
        pytest.skip("受限环境读不到环境块: " + ev["detail"][:80])
    assert data["count"] >= 1


def test_list_threads(tmp_path):
    _, ev = _run(tmp_path, "list_threads", {"pid": MY_PID, "limit": 10})
    data = json.loads(ev["detail"])
    assert data["count"] >= 1
    assert data["threads"][0]["tid"]


def test_get_thread_start_address(tmp_path):
    _, ev = _run(tmp_path, "get_thread_start_address", {"tid": MY_TID})
    data, is_err = _json_or_none(ev["detail"])
    if is_err:
        pytest.skip("受限环境读不到线程起始地址: " + ev["detail"][:80])
    assert data["tid"] == MY_TID and data.get("pid") == MY_PID


def test_list_handles(tmp_path):
    # 句柄表按契约必须带过滤条件（type/name/handle 之一）
    _, ev = _run(tmp_path, "list_handles", {"pid": MY_PID, "type": "File", "limit": 40})
    data, is_err = _json_or_none(ev["detail"])
    if is_err:
        pytest.skip("受限环境无法枚举句柄表（SystemExtendedHandleInformation 需要管理员）: "
                    + ev["detail"][:80])
    assert data["total_handles"] >= 1 and "type_counts" in data


def test_scan_memory_regions_own_process(tmp_path):
    _, ev = _run(tmp_path, "scan_memory_regions",
                 {"pid": MY_PID, "max_mb": 4, "max_regions": 8, "yara": False})
    data = json.loads(ev["detail"])
    assert "regions_total" in data and "skipped" in data


def test_verify_signature_system_file(tmp_path):
    _, ev = _run(tmp_path, "verify_signature", {"path": r"C:\Windows\System32\cmd.exe"})
    data = json.loads(ev["detail"])
    assert "signed" in data and data["status"]
    # cmd.exe 是 catalog 签名（无内嵌签名）；受限环境里 catalog 校验也不可用，
    # 会返回 TRUST_E_NOSIGNATURE（-2146762496）。正常机器上应为 signed=true。
    if not data["signed"]:
        assert data["result_code"] == -2146762496, "未签名时应给出明确结果码"
    else:
        assert data["signer"] or data["status"] == "有效签名"


def test_suspend_resume_process(tmp_path):
    # 对自身测试进程挂起会卡死测试，改用 spawn 的子进程验证
    import subprocess
    proc = subprocess.Popen(["cmd", "/c", "ping", "-n", "30", "127.0.0.1"],
                            creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        _, ev = _run(tmp_path, "suspend_process", {"pid": proc.pid})
        d1, err1 = _json_or_none(ev["detail"])
        _, ev = _run(tmp_path, "resume_process", {"pid": proc.pid})
        d2, err2 = _json_or_none(ev["detail"])
        if err1 or err2:
            pytest.skip("受限环境无法挂起/恢复进程（PROCESS_SUSPEND_RESUME 被拒）")
        assert d1["suspended"] is True
        assert d2.get("resumed") is True or "resumed" in ev["detail"]
    finally:
        proc.kill()


def test_kill_process_tree(tmp_path):
    import subprocess
    proc = subprocess.Popen(["cmd", "/c", "ping", "-n", "30", "127.0.0.1"],
                            creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        _, ev = _run(tmp_path, "kill_process_tree", {"pid": proc.pid})
        data = json.loads(ev["detail"])
        assert data["killed"] and proc.pid not in _alive_pids()
    finally:
        proc.kill()


def _alive_pids():
    import subprocess
    out = subprocess.run(["tasklist", "/fo", "csv", "/nh"], capture_output=True, text=True)
    pids = set()
    for line in out.stdout.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) > 1 and parts[1].isdigit():
            pids.add(int(parts[1]))
    return pids


# ---------------------------------------------------------------- 二、文件取证

def test_list_files(tmp_path):
    (tmp_path / "a.txt").write_text("hello", encoding="utf-8")
    _, ev = _run(tmp_path, "list_files", {"dir": str(tmp_path), "filter": "*.txt"})
    data = json.loads(ev["detail"])
    assert any(f["path"].endswith("a.txt") for f in data["files"])


def test_get_file_metadata(tmp_path):
    f = tmp_path / "meta.txt"
    f.write_text("hello world" * 100, encoding="utf-8")
    _, ev = _run(tmp_path, "get_file_metadata", {"path": str(f)})
    data = json.loads(ev["detail"])
    assert data["size"] == 1100 and data["magic"] and "entropy" in data


def test_get_ads(tmp_path):
    f = tmp_path / "noads.txt"
    f.write_text("plain", encoding="utf-8")
    _, ev = _run(tmp_path, "get_ads", {"path": str(f)})
    data = json.loads(ev["detail"])
    assert data["zone"]["exists"] is False


def test_get_recent_files(tmp_path):
    _, ev = _run(tmp_path, "get_recent_files", {"hours": 24, "limit": 5})
    assert ev["detail"].startswith("ERROR") or json.loads(ev["detail"])["count"] >= 0


# ---------------------------------------------------------------- 三、注册表/持久化

def test_enumerate_registry_tree(tmp_path):
    _, ev = _run(tmp_path, "enumerate_registry_tree",
                 {"key": "HKCU/Software", "depth": 1, "limit": 10})
    data = json.loads(ev["detail"])
    assert data["count"] >= 1


def test_check_persistence(tmp_path):
    _, ev = _run(tmp_path, "check_persistence", {})
    data = json.loads(ev["detail"])
    assert data["count"] >= 1 and isinstance(data["findings"], list)


def test_list_wmi_subscriptions(tmp_path):
    _, ev = _run(tmp_path, "list_wmi_subscriptions", {})
    assert ev["detail"].startswith("ERROR") or json.loads(ev["detail"])["count"] >= 0


def test_list_startup_folders(tmp_path):
    _, ev = _run(tmp_path, "list_startup_folders", {})
    data = json.loads(ev["detail"])
    assert data["folders"]


def test_list_drivers_loaded(tmp_path):
    _, ev = _run(tmp_path, "list_drivers_loaded", {"limit": 10})
    data, is_err = _json_or_none(ev["detail"])
    if is_err:
        pytest.skip("枚举驱动需要管理员（沙箱内被拒）: " + ev["detail"][:80])
    assert data["count"] >= 1


def test_delete_registry_value_dry_run(tmp_path):
    _, ev = _run(tmp_path, "delete_registry_value",
                 {"key": "HKCU/Software/AvEngineTest", "value_name": "x", "dry_run": True})
    data = json.loads(ev["detail"])
    assert data["dry_run"] is True


# ---------------------------------------------------------------- 四、网络

def test_get_dns_cache(tmp_path):
    _, ev = _run(tmp_path, "get_dns_cache", {"limit": 20})
    assert ev["detail"].startswith("ERROR") or json.loads(ev["detail"])["count"] >= 0


def test_list_udp_endpoints(tmp_path):
    _, ev = _run(tmp_path, "list_udp_endpoints", {"limit": 20})
    data = json.loads(ev["detail"])
    assert data["count"] >= 1


def test_list_listeners(tmp_path):
    _, ev = _run(tmp_path, "list_listeners", {"limit": 20})
    data = json.loads(ev["detail"])
    assert data["count"] >= 1


def test_resolve_ip_domains(tmp_path):
    _, ev = _run(tmp_path, "resolve_ip_domains", {"ip": "127.0.0.1"})
    data = json.loads(ev["detail"])
    assert data["ip"] == "127.0.0.1"


def test_get_route_table(tmp_path):
    _, ev = _run(tmp_path, "get_route_table", {"limit": 10})
    data = json.loads(ev["detail"])
    assert data["count"] >= 1


def test_get_arp_cache(tmp_path):
    _, ev = _run(tmp_path, "get_arp_cache", {"limit": 10})
    assert ev["detail"].startswith("ERROR") or json.loads(ev["detail"])["count"] >= 0


def test_list_firewall_rules(tmp_path):
    _, ev = _run(tmp_path, "list_firewall_rules", {"profile": "all", "limit": 5})
    data, is_err = _json_or_none(ev["detail"])
    if is_err:
        pytest.skip("受限环境无法执行 netsh 防火墙查询: " + ev["detail"][:80])
    assert data.get("rules_text") or ev["detail"].startswith("ERROR")


def test_get_proxy_config(tmp_path):
    _, ev = _run(tmp_path, "get_proxy_config", {})
    data = json.loads(ev["detail"])
    assert "winhttp" in data and "wininet" in data


def test_block_ip_dry_run(tmp_path):
    _, ev = _run(tmp_path, "block_ip", {"ip": "203.0.113.77", "dry_run": True})
    data = json.loads(ev["detail"])
    assert data["dry_run"] is True and "netsh" in data.get("command", "")


def test_block_domain_dry_run(tmp_path):
    _, ev = _run(tmp_path, "block_domain", {"domain": "localhost", "dry_run": True})
    data = json.loads(ev["detail"])
    assert data["dry_run"] is True


# ---------------------------------------------------------------- 五、日志/脚本

def test_get_script_block_log(tmp_path):
    _, ev = _run(tmp_path, "get_script_block_log", {"hours": 24, "limit": 5})
    assert ev["detail"].startswith("ERROR") or json.loads(ev["detail"])["count"] >= 0


def test_get_powershell_transcript(tmp_path):
    _, ev = _run(tmp_path, "get_powershell_transcript", {"limit": 5})
    assert ev["detail"].startswith("ERROR") or json.loads(ev["detail"])["count"] >= 0


def test_decode_script_base64_utf16(tmp_path):
    encoded = base64.b64encode("net user\n".encode("utf-16-le")).decode("ascii")
    _, ev = _run(tmp_path, "decode_script", {"text": encoded, "encodings": "auto"})
    data = json.loads(ev["detail"])
    assert "net user" in data["decoded"]


def test_decode_script_hex(tmp_path):
    _, ev = _run(tmp_path, "decode_script", {"text": "net user".encode("ascii").hex(),
                                             "encodings": "hex"})
    data = json.loads(ev["detail"])
    assert "net user" in data["decoded"]


def test_subscribe_tail_unsubscribe(tmp_path):
    result, ev = _run(tmp_path, "subscribe_events", {"source": "system"})
    data = json.loads(ev["detail"])
    assert data.get("active") is True
    # 订阅是全局单槽位：单独验证 poll / unsubscribe
    payload = _base_payload(tmp_path)
    events = []
    with MockServer([_round("tail_events", {"max": 5}),
                     [_chunk({"content": "好。\nEND"})]]) as server:
        payload["base_url"] = server.base_url
        core_bridge.ai_ask_stream(payload, "x", events.append)
    tail = [e for e in events if e["kind"] == "tool_result"]
    assert tail and (tail[0]["detail"].startswith("ERROR") or "count" in tail[0]["detail"])
    # 收尾：停掉订阅，避免影响其他用例
    with MockServer([_round("unsubscribe_events", {}),
                     [_chunk({"content": "好。\nEND"})]]) as server:
        payload["base_url"] = server.base_url
        core_bridge.ai_ask_stream(payload, "x", [])
    assert core_bridge  # no-op，避免 lint


def test_get_etw_system_channel(tmp_path):
    _, ev = _run(tmp_path, "get_etw", {"channel": "System", "hours": 24, "limit": 5})
    assert ev["detail"].startswith("ERROR") or json.loads(ev["detail"])["count"] >= 0


def test_get_amsi_events(tmp_path):
    _, ev = _run(tmp_path, "get_amsi_events", {"limit": 5})
    assert ev["detail"].startswith("ERROR") or json.loads(ev["detail"])["count"] >= 0


def test_get_security_log(tmp_path):
    _, ev = _run(tmp_path, "get_security_log", {"hours": 24, "limit": 5})
    assert ev["detail"].startswith("ERROR") or json.loads(ev["detail"])["count"] >= 0


# ---------------------------------------------------------------- 六/七、处置与情报

def test_reputation_lookup_private_ip(tmp_path):
    _, ev = _run(tmp_path, "reputation_lookup", {"value": "10.0.0.5"})
    data = json.loads(ev["detail"])
    assert data["type"] == "ip"
    assert data["local"]["verdict"]


def test_reputation_lookup_suspicious_tld(tmp_path):
    _, ev = _run(tmp_path, "reputation_lookup", {"value": "evil.click.example.tk"})
    data = json.loads(ev["detail"])
    assert data["type"] == "domain"
    assert data["local"]["reasons"]


def test_build_static_report(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_text("report me " * 50, encoding="utf-8")
    _, ev = _run(tmp_path, "build_static_report", {"path": str(f)})
    data = json.loads(ev["detail"])
    assert data["sha256"] and data["verdict"] in ("clean", "suspicious", "infected")


def test_write_yara_rule_and_scan_with_rule(tmp_path):
    # 写规则到临时规则库
    _, ev = _run(tmp_path, "write_yara_rule",
                 {"name": "TestAiExtMarker", "strings": ["TEST_AI_EXT_MARKER_12345"]})
    data = json.loads(ev["detail"])
    assert data["compiled"] is True and data["path"]

    # 用该规则扫描含标记的样本
    sample = tmp_path / "with_marker.txt"
    sample.write_text("TEST_AI_EXT_MARKER_12345 in file", encoding="utf-8")
    _, ev = _run(tmp_path, "scan_with_rule", {"rule": "TestAiExtMarker", "target": str(sample)})
    matches = json.loads(ev["detail"])
    assert matches["count"] >= 1
    assert any("TestAiExtMarker" in m["rules"] for m in matches["matches"])


def test_save_compare_baseline(tmp_path):
    _, ev = _run(tmp_path, "save_baseline", {"kind": "process"})
    data = json.loads(ev["detail"])
    assert data["saved_to"]
    _, ev = _run(tmp_path, "compare_baseline", {"kind": "process"})
    data = json.loads(ev["detail"])
    assert "added" in data and "removed" in data


def test_set_safety_and_list_tools(tmp_path):
    _, ev = _run(tmp_path, "set_safety", {"dry_run": True})
    assert json.loads(ev["detail"])["dry_run"] is True
    _, ev = _run(tmp_path, "list_tools", {"category": "处置"})
    data = json.loads(ev["detail"])
    assert data["count"] >= 5
    assert any(not t["readonly"] for t in data["tools"])


def test_mutating_actions_are_audited(tmp_path):
    payload = _base_payload(tmp_path)
    events = []
    with MockServer([_round("block_ip", {"ip": "203.0.113.78", "dry_run": True}),
                     [_chunk({"content": "好。\nEND"})]]) as server:
        payload["base_url"] = server.base_url
        core_bridge.ai_ask_stream(payload, "x", events.append)
    audit_file = tmp_path / "audit.log"
    assert audit_file.is_file(), "处置类动作（含 dry-run）应写入审计日志"
    line = audit_file.read_text(encoding="utf-8")
    assert "block_ip" in line and "hash=" in line and "prev=" in line
