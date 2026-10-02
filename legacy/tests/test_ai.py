"""ai 子包单元测试（纯函数与会话循环，不发网络请求）。"""

from __future__ import annotations

from pathlib import Path

import pytest

from avengine.ai.client import AIReply, ToolCall, parse_text_calls, split_end_tag
from avengine.ai.config import AIConfig, load_ai_config
from avengine.ai.prompts import build_batch_message, build_detection_message
from avengine.ai.service import AIService
from avengine.ai.session import AISession
from avengine.ai.tools import ToolContext, coerce_args, execute, schemas_for_api, TOOLS
from avengine.paths import AI_CONFIG_EXAMPLE_FILE


# -------------------- 文本兜底与 END 协议 --------------------

def test_parse_text_calls_key_value():
    text = "先看这个进程\nCALL get_process_info pid=1234\n然后结论"
    calls, stripped = parse_text_calls(text)
    assert len(calls) == 1
    assert calls[0].name == "get_process_info"
    assert calls[0].arguments == {"pid": "1234"}
    assert "CALL" not in stripped
    assert stripped == "先看这个进程\n然后结论"


def test_parse_text_calls_json_form():
    calls, stripped = parse_text_calls('CALL file_hash {"path": "C:/tmp/a.txt", "algos": "md5"}')
    assert len(calls) == 1
    assert calls[0].arguments == {"path": "C:/tmp/a.txt", "algos": "md5"}
    assert stripped == ""


def test_parse_text_calls_none():
    calls, stripped = parse_text_calls("普通文本，没有调用")
    assert calls == []
    assert stripped == "普通文本，没有调用"


def test_split_end_tag_with_end():
    assert split_end_tag("分析完毕\n风险低\nEND") == ("分析完毕\n风险低", True)
    assert split_end_tag("结束 END") == ("结束", True)  # 同行结论保留
    assert split_end_tag("分析完成，威胁已隔离 END") == ("分析完成，威胁已隔离", True)


def test_split_end_tag_without_end():
    body, has_end = split_end_tag("普通结论")
    assert body == "普通结论" and has_end is False
    assert split_end_tag("") == ("", False)


def test_split_end_tag_long_line_not_tag():
    # 结尾行超过 20 字符时不算 END 标记
    last = "这是一行超过二十个字符长度的结尾说明END"
    assert len(last) > 20
    _, has_end = split_end_tag("结论\n" + last)
    assert has_end is False


# -------------------- 工具参数与执行 --------------------

def _spec():
    from avengine.ai.tools import ToolSpec

    return ToolSpec(
        name="demo", category="情报", description="demo",
        properties={"pid": {"type": "integer"}, "force": {"type": "boolean"}, "path": {"type": "string"}},
        func=lambda a, c: "ok", required=["pid"],
    )


def test_coerce_args_types():
    args = coerce_args(_spec(), {"pid": "42", "force": "false", "path": 7, "extra": "x"})
    assert args == {"pid": 42, "force": False, "path": "7"}


def test_coerce_args_missing_required():
    with pytest.raises(ValueError):
        coerce_args(_spec(), {"force": "true"})


def test_execute_unknown_tool():
    ctx = ToolContext(engine_config={}, ai_config=AIConfig())
    out = execute("no_such_tool", {}, ctx)
    assert out.startswith("ERROR:")


def test_execute_bad_argument_type():
    ctx = ToolContext(engine_config={}, ai_config=AIConfig())
    out = execute("get_process_info", {"pid": "abc"}, ctx)
    assert out.startswith("ERROR:")


def test_schemas_for_api_shape():
    schemas = schemas_for_api()
    assert len(schemas) == len(TOOLS) >= 20
    for schema in schemas:
        fn = schema["function"]
        assert fn["name"] and fn["description"]
        assert fn["parameters"]["type"] == "object"


def test_tools_cover_seven_categories():
    categories = {spec.category for spec in TOOLS.values()}
    assert categories == {"进程", "文件", "网络", "系统", "事件", "处置", "情报"}
    assert "dump_memory" in TOOLS and "grep_events" in TOOLS


# -------------------- config.ini --------------------

def test_load_ai_config_defaults(tmp_path: Path):
    cfg = load_ai_config(tmp_path / "nope.ini")
    assert cfg.enabled is False
    assert cfg.active is False
    assert cfg.interval == 300
    assert cfg.source_enabled("sysmon") is True


def test_load_ai_config_values(tmp_path: Path):
    ini = tmp_path / "config.ini"
    ini.write_text(
        "[ai]\n"
        "enabled = true\n"
        "base_url = https://api.openai.com/v1\n"
        "api_key = sk-ab%cd\n"
        "model = gpt-4o-mini\n"
        "interval = 600\n"
        "max_rounds = 5\n"
        "[sources]\n"
        "fileio = false\n"
        "dns = false\n",
        encoding="utf-8",
    )
    cfg = load_ai_config(ini)
    assert cfg.active is True
    assert cfg.interval == 600
    assert cfg.max_rounds == 5
    assert cfg.api_key == "sk-ab%cd"  # 禁用插值，% 原样保留
    assert cfg.source_enabled("fileio") is False
    assert "dns" not in cfg.batch_sources()
    assert "sysmon" in cfg.batch_sources()


def test_example_config_parses():
    cfg = load_ai_config(AI_CONFIG_EXAMPLE_FILE)
    assert AI_CONFIG_EXAMPLE_FILE.is_file()
    assert cfg.exists and cfg.enabled is False
    assert cfg.interval == 300


# -------------------- 消息构建 --------------------

def test_build_batch_message_contains_contract():
    cfg = AIConfig()
    msg = build_batch_message(
        cfg, "12:00:01 进程创建 bad.exe", {"sysmon": 1, "process": 1},
        truncated=2, errors=["通道 X 未启用"], minutes=5,
    )
    assert "END" in msg
    assert "sysmon=1" in msg
    assert "截断" in msg
    assert "通道 X 未启用" in msg


def test_build_detection_message():
    msg = build_detection_message({"path": "C:/bad.exe", "engine": "yara", "match": "rule_X"})
    assert "C:/bad.exe" in msg
    assert "rule_X" in msg
    assert "END" in msg


# -------------------- 会话循环（伪造客户端，无网络） --------------------

class _FakeClient:
    def __init__(self, replies):
        self._replies = list(replies)
        self.request_count = 0

    def chat(self, messages, tools_schema=None):
        self.request_count += 1
        return self._replies.pop(0)


def _session(replies, max_rounds: int = 12):
    cfg = AIConfig(enabled=True, base_url="http://x", model="m", max_rounds=max_rounds)
    ctx = ToolContext(engine_config={}, ai_config=cfg)
    return AISession(cfg, ctx, client=_FakeClient(replies)), cfg


def test_session_text_call_then_end():
    session, _ = _session(
        [
            AIReply(content="CALL no_such_tool pid=1"),
            AIReply(content="调查完成，无威胁\nEND"),
        ]
    )
    result = session.run("批次内容")
    assert result.ended_by == "end_tag"
    assert result.final_text == "调查完成，无威胁"
    assert result.tool_calls == 1
    assert result.rounds == 2


def test_session_function_call_roundtrip():
    session, _ = _session(
        [
            AIReply(
                content="",
                tool_calls=[ToolCall(id="c1", name="no_such_tool", arguments={"pid": "1"})],
            ),
            AIReply(content="OK END"),
        ]
    )
    result = session.run("批次")
    assert result.ended_by == "end_tag"
    assert result.final_text == "OK"
    assert result.tool_calls == 1
    assert result.rounds == 2


def test_session_empty_reply_nudge():
    session, _ = _session([AIReply(content=""), AIReply(content="最终结论 END")])
    result = session.run("批次")
    assert result.ended_by == "end_tag"
    assert result.final_text == "最终结论"
    assert result.rounds == 2


def test_session_max_rounds_cap():
    session, _ = _session([AIReply(content="CALL no_such_tool a=1")], max_rounds=1)
    result = session.run("批次")
    assert result.ended_by == "max_rounds"
    assert result.rounds == 1


def test_session_client_error():
    class _Boom:
        def chat(self, messages, tools_schema=None):
            from avengine.ai.client import AIError

            raise AIError("HTTP 500")

    cfg = AIConfig(enabled=True, base_url="http://x", model="m")
    ctx = ToolContext(engine_config={}, ai_config=cfg)
    result = AISession(cfg, ctx, client=_Boom()).run("批次")
    assert result.ended_by == "error"
    assert "HTTP 500" in result.error
    assert result.final_text  # 失败信息回填


# -------------------- 服务可用性提示 --------------------

def test_service_availability_hints():
    svc = AIService.__new__(AIService)  # 跳过重构造（避免读引擎配置）
    svc.config = AIConfig(path=AI_CONFIG_EXAMPLE_FILE, enabled=False)
    assert svc.available is False
    assert "禁用" in svc.availability_hint()

    svc.config = AIConfig(path=AI_CONFIG_EXAMPLE_FILE, enabled=True, base_url="", model="")
    assert "配置不完整" in svc.availability_hint()
