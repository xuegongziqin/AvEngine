"""
AI 流式事件端到端测试。

用一个本地 mock SSE 服务（OpenAI 兼容的 /v1/chat/completions）替代真实模型，
验证：
  1) C++ 侧的 SSE 解析能把 reasoning_content / content / tool_calls 增量拆出来；
  2) 事件按顺序同步回调到 Python（thinking → content → tool_call → tool_result → final → done）；
  3) 服务端忽略 stream、直接返回整体 JSON 时能回退（并把正文补成一次 content 事件）。

不需要外网、不需要真实 API Key。
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from avengine import core_bridge

pytestmark = pytest.mark.skipif(
    not core_bridge.is_available(), reason="avengine_core.dll 未构建（先运行 cpp/build.bat）"
)


# ---------------------------------------------------------------- mock 服务

def _chunk(delta):
    return {"choices": [{"index": 0, "delta": delta}]}


class _MockHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            request = json.loads(raw.decode("utf-8"))
        except ValueError:
            request = {}
        self.server.requests.append(request)

        script = self.server.script.pop(0) if self.server.script else []
        if self.server.as_json:
            # 模拟「服务端忽略 stream，直接返回整体 JSON」
            body = json.dumps({
                "choices": [{"index": 0, "message": {"role": "assistant", "content": script}}]
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        for item in script:
            self.wfile.write(("data: " + json.dumps(item, ensure_ascii=False) + "\n\n").encode("utf-8"))
            self.wfile.flush()
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    def do_GET(self):  # noqa: N802 - /models 连通测试
        body = json.dumps({"data": [{"id": "mock"}]}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # 静音
        pass


class MockServer:
    def __init__(self, scripts, as_json=False):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _MockHandler)
        self.httpd.daemon_threads = True
        self.httpd.script = list(scripts)
        self.httpd.requests = []
        self.httpd.as_json = as_json
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    @property
    def base_url(self):
        host, port = self.httpd.server_address[:2]
        return "http://{}:{}/v1".format(host, port)

    @property
    def requests(self):
        return self.httpd.requests


def _payload(base_url):
    return {
        "base_url": base_url,
        "api_key": "",
        "model": "mock-model",
        "timeout": 10,
        "max_rounds": 3,
    }


# ---------------------------------------------------------------- 用例

def test_ask_stream_emits_thinking_content_and_final():
    scripts = [[
        _chunk({"reasoning_content": "先看"}),
        _chunk({"reasoning_content": "事件。"}),
        _chunk({"content": "结论："}),
        _chunk({"content": "未发现异常。\nEND"}),
    ]]
    events = []

    with MockServer(scripts) as server:
        result = core_bridge.ai_ask_stream(_payload(server.base_url), "有什么异常吗？", events.append)
        request = server.requests[0]

    kinds = [e["kind"] for e in events]
    # 顺序：会话信息 → 会话开始 → 轮次 → 思考 → 正文 → 轮次结束 → 结论 → 结束
    assert kinds[0] == "session_info"
    assert "session_start" in kinds and "round_start" in kinds
    assert kinds.index("thinking") < kinds.index("content") < kinds.index("round_end")
    assert kinds[-1] == "done" and "final" in kinds

    thinking = "".join(e["text"] for e in events if e["kind"] == "thinking")
    content = "".join(e["text"] for e in events if e["kind"] == "content")
    assert thinking == "先看事件。"
    # 注意：**不能**断言"每个分片一个事件"。ai_session.cpp 会把连续的小 delta
    # 合并后再回调（320 字节 / 40ms / 遇换行才发），否则 Python 侧每个 chunk 都要抢
    # 一次 GIL，实测 3000 chunk 时 GUI 主线程被卡十几秒。这里断言的是流式链路
    # 确实产出了正文事件、且内容完整无损。
    assert [e for e in events if e["kind"] == "content"], events
    assert content == "结论：未发现异常。\nEND"

    final = [e for e in events if e["kind"] == "final"][0]
    assert final["text"] == "结论：未发现异常。"     # END 标记被去掉
    assert result["ended_by"] == "end_tag"
    assert result["final_text"] == "结论：未发现异常。"
    assert result["ok"] is True

    # 请求侧确实是流式请求，且带上了工具
    assert request.get("stream") is True
    assert request.get("tools")


def test_ask_stream_reports_tool_calls_and_results():
    round1 = [
        _chunk({"reasoning_content": "先看看网络连接。"}),
        _chunk({"tool_calls": [{"index": 0, "id": "call_1",
                                "function": {"name": "network_stats", "arguments": "{"}}]}),
        _chunk({"tool_calls": [{"index": 0, "function": {"arguments": "}"}}]}),
    ]
    round2 = [_chunk({"content": "网络正常。\nEND"})]
    events = []

    with MockServer([round1, round2]) as server:
        result = core_bridge.ai_ask_stream(_payload(server.base_url), "网络正常吗？", events.append)

    calls = [e for e in events if e["kind"] == "tool_call"]
    results = [e for e in events if e["kind"] == "tool_result"]
    assert [c["name"] for c in calls] == ["network_stats"]
    assert calls[0]["args"] == {}                     # 分片参数被拼回合法 JSON
    assert results and results[0]["name"] == "network_stats"
    assert results[0]["ok"] is True
    assert result["tool_calls"] == 1
    assert result["rounds"] == 2
    assert result["final_text"] == "网络正常。"


def test_ask_stream_falls_back_when_server_ignores_stream():
    """服务端返回整体 JSON（不是 SSE）时，要能回退，并把正文补成一次 content 事件。"""
    events = []

    with MockServer(["整体响应，不是 SSE。"], as_json=True) as server:
        result = core_bridge.ai_ask_stream(_payload(server.base_url), "随便问问", events.append)

    content = [e for e in events if e["kind"] == "content"]
    assert [c["text"] for c in content] == ["整体响应，不是 SSE。"]
    assert result["final_text"] == "整体响应，不是 SSE。"
    assert result["ok"] is True


def test_supports_ai_stream_flag():
    assert core_bridge.supports_ai_stream() in (True, False)
    if core_bridge.supports_ai_stream():
        assert callable(core_bridge.ai_ask_stream)
        assert callable(core_bridge.ai_run_batch_stream)
        assert callable(core_bridge.ai_analyze_detection_stream)


def test_long_chinese_tool_result_does_not_break_json_dump():
    """
    回归：工具结果按「字节」截断到 200 时会劈开汉字，nlohmann 默认 dump() 会抛
    type_error.316（invalid UTF-8 byte at index 200），于是整个会话结果都拿不回来
    （用户实际遇到：会话跑到最后一步才崩，屏幕上还缺了最后一条工具结果和结束行）。

    这里用 get_engine_status 把「隔离目录」设成超长中文（该字段在结果首行里），
    并用 0/1/2 个 ASCII 前缀位移截断点 —— 三种位移里至少有一种会正好切在汉字中间。
    """
    run = "中文路径测试" * 40          # 480 字节，远大于 200
    round1 = [_chunk({"content": "先看下引擎状态。"}),
              _chunk({"tool_calls": [{"index": 0, "id": "call_1",
                                      "function": {"name": "get_engine_status", "arguments": "{}"}}]})]
    round2 = [_chunk({"content": "看完了。\nEND"})]

    for pad in ("", "a", "ab"):
        events = []
        with MockServer([round1, round2]) as server:
            payload = _payload(server.base_url)
            payload["rules_path"] = str(server.base_url) + "/no-such-rules"
            payload["quarantine_dir"] = pad + run
            payload["clam_host"] = ""
            payload["clam_port"] = 0
            result = core_bridge.ai_ask_stream(payload, "引擎状态怎么样？", events.append)

        assert result["ok"] is True, "会话结果应完整返回（补丁前这里会抛 type_error.316）"
        details = [e["detail"] for e in events if e["kind"] == "tool_result"]
        assert details, "工具结果事件不应丢失"
        assert "\ufffd" not in details[0], "截断后的文本不应含替换字符（说明按字符边界截断）"
        # 结果里的 trace 同样要能安全序列化
        assert any(t.get("kind") == "tool_result" for t in result["trace"])
