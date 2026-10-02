"""C++ AI 内核端到端测试：用本地 mock OpenAI 服务验证会话/工具/END 全链路。"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from avengine import core_bridge

pytestmark = pytest.mark.skipif(
    not core_bridge.is_available(),
    reason="avengine_core.dll 未构建（先运行 cpp/build.bat）",
)

TOOL_RESP = {
    "choices": [
        {
            "message": {
                "content": "",
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "get_engine_status", "arguments": "{}"},
                    }
                ],
            }
        }
    ]
}
END_RESP = {"choices": [{"message": {"content": "分析完成，未发现威胁\nEND"}}]}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # 静默
        pass

    def _send(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send({"data": []})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        count = getattr(self.server, "post_count", 0)
        self.server.post_count = count + 1
        self._send(TOOL_RESP if count == 0 else END_RESP)


@pytest.fixture
def mock_openai():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    server.post_count = 0
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:{}/v1".format(server.server_port)
    finally:
        server.shutdown()
        server.server_close()


def _payload(base_url, tmp_path):
    return {
        "base_url": base_url,
        "api_key": "",
        "model": "test-model",
        "timeout": 10,
        "max_rounds": 5,
        "interval": 300,
        "max_events_per_batch": 10,
        "max_event_chars": 200,
        "max_tool_result_chars": 4000,
        "scan_analysis": True,
        "batch_sources": [],
        "rules_path": "",
        "quarantine_dir": str(tmp_path / "q"),
        "clam_host": "",
        "clam_port": 0,
        "clam_timeout": 5,
        "log_file": str(tmp_path / "none.log"),
        "dump_dir": str(tmp_path / "dumps"),
        "project_root": str(tmp_path),
    }


def test_ai_ask_toolcall_then_end(mock_openai, tmp_path):
    result = core_bridge.ai_ask(_payload(mock_openai, tmp_path), "当前有可疑外联吗？")
    assert result["ended_by"] == "end_tag"
    assert result["tool_calls"] == 1
    assert result["ok"] is True
    assert "分析完成" in result["final_text"]
    assert any(t["kind"] == "tool_call" and t["name"] == "get_engine_status" for t in result["trace"])


def test_ai_run_batch_end(mock_openai, tmp_path):
    result = core_bridge.ai_run_batch(_payload(mock_openai, tmp_path), 5)
    assert result["ended_by"] == "end_tag"
    assert result["kind"] == "batch"
    assert result["rounds"] >= 1


def test_ai_analyze_detection(mock_openai, tmp_path):
    detection = {"path": "C:/tmp/bad.exe", "engine": "yara", "match": "rule_X", "total": 1}
    result = core_bridge.ai_analyze_detection(_payload(mock_openai, tmp_path), detection)
    assert result["ended_by"] == "end_tag"
    assert result["kind"] == "detection"


def test_ai_test_connection(mock_openai, tmp_path):
    result = core_bridge.ai_test(_payload(mock_openai, tmp_path))
    assert result["ok"] is True


def test_ai_text_fallback_call(tmp_path):
    # 文本兜底：模型不支持 function calling，用 CALL 行
    class _TextHandler(_Handler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            count = getattr(self.server, "post_count", 0)
            self.server.post_count = count + 1
            if count == 0:
                self._send({"choices": [{"message": {"content": "CALL get_engine_status"}}]})
            else:
                self._send({"choices": [{"message": {"content": "结论：正常 END"}}]})

    server = HTTPServer(("127.0.0.1", 0), _TextHandler)
    server.post_count = 0
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = "http://127.0.0.1:{}/v1".format(server.server_port)
        result = core_bridge.ai_ask(_payload(base, tmp_path), "测试文本兜底")
        assert result["ended_by"] == "end_tag"
        assert result["tool_calls"] == 1
        assert "正常" in result["final_text"]
    finally:
        server.shutdown()
        server.server_close()
