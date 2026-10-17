"""utils 模块单元测试。"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from avengine.utils import (
    SafeStreamHandler,
    compute_file_hash,
    get_platform_info,
    is_admin,
    make_console_tolerant,
    quarantine_file,
    setup_logging,
)


def _record(msg: str = "中文日志…") -> logging.LogRecord:
    return logging.LogRecord("t", logging.INFO, __file__, 1, msg, None, None)


def test_safe_stream_handler_survives_broken_stream():
    """
    控制台写入失败时不能把 traceback 甩给用户。

    真实场景：控制台代码页被别的程序改过、输出被重定向、或某个字符在当前代码页里
    编不出来 —— logging 默认会 print 一段 "--- Logging error ---" + traceback，
    对命令行工具来说纯属噪音。这个 handler 必须把它吞掉。
    """

    class BoomStream:
        encoding = "cp936"

        def write(self, _text):
            raise UnicodeEncodeError("gbk", "x", 0, 1, "boom")

        def flush(self):
            pass

    handler = SafeStreamHandler(BoomStream())
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.emit(_record())         # 不得抛出
    handler.handleError(_record())  # 也不得打印任何东西


def test_safe_stream_handler_replaces_unencodable_characters():
    """可写但编码受限的流：应把编不出来的字符替换掉写出去，而不是放弃整条日志。"""

    class AsciiOnlyStream:
        encoding = "ascii"

        def __init__(self):
            self.written = []

        def write(self, text):
            if any(ord(c) > 127 for c in text):
                text.encode("ascii")   # 模拟严格编码的流 → 抛 UnicodeEncodeError
            self.written.append(text)

        def flush(self):
            pass

    stream = AsciiOnlyStream()
    handler = SafeStreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.emit(_record("中文"))
    assert stream.written, "至少要写出点东西（降级为替换后的文本）"
    assert all(ord(c) < 128 for c in "".join(stream.written)), stream.written


def test_make_console_tolerant_sets_errors_replace():
    """标准流要设成 errors='replace'，避免 UnicodeEncodeError 变成 traceback。"""
    import io
    import sys

    original = sys.__stdout__
    sys.__stdout__ = io.TextIOWrapper(io.BytesIO(), encoding="ascii", errors="strict")
    try:
        make_console_tolerant()
        assert sys.__stdout__.errors == "replace"
    finally:
        sys.__stdout__ = original


def test_setup_logging_uses_safe_handler(tmp_path: Path):
    """setup_logging 必须挂上 SafeStreamHandler（而不是裸的 StreamHandler）。"""
    setup_logging(log_level=logging.INFO, log_file=tmp_path / "x.log")
    handlers = logging.getLogger().handlers
    assert any(isinstance(h, SafeStreamHandler) for h in handlers), handlers
    assert any(isinstance(h, logging.FileHandler) for h in handlers), handlers


def test_compute_file_hash_matches_hashlib(tmp_path: Path):
    path = tmp_path / "data.bin"
    payload = b"antierx" * 1000
    path.write_bytes(payload)

    assert compute_file_hash(str(path)) == hashlib.sha256(payload).hexdigest()
    assert compute_file_hash(str(path), "md5") == hashlib.md5(payload).hexdigest()


def test_compute_file_hash_invalid_inputs(tmp_path: Path):
    assert compute_file_hash(str(tmp_path / "missing.txt")) is None
    assert compute_file_hash(str(tmp_path)) is None

    real = tmp_path / "f.txt"
    real.write_text("x", encoding="utf-8")
    assert compute_file_hash(str(real), "not-an-algorithm") is None


def test_quarantine_file_moves_and_renames(tmp_path: Path):
    src = tmp_path / "evil.exe"
    src.write_bytes(b"MZ")
    q_dir = tmp_path / "q"

    dest = quarantine_file(str(src), str(q_dir))
    assert dest is not None
    assert not src.exists()
    assert Path(dest).is_file()
    assert Path(dest).parent == q_dir

    # 重名文件需要产生不同目标名
    src2 = tmp_path / "evil.exe"
    src2.write_bytes(b"MZ")
    dest2 = quarantine_file(str(src2), str(q_dir))
    assert dest2 != dest


def test_quarantine_file_missing_source(tmp_path: Path):
    assert quarantine_file(str(tmp_path / "nope.txt"), str(tmp_path / "q")) is None


def test_setup_logging_writes_file(tmp_path: Path):
    log_file = tmp_path / "logs" / "test.log"
    setup_logging(log_level=logging.DEBUG, log_file=log_file)
    logging.info("hello log")

    for handler in logging.getLogger().handlers:
        handler.flush()

    assert log_file.is_file()
    assert "hello log" in log_file.read_text(encoding="utf-8")

    # 还原，避免影响后续用例的输出
    for handler in logging.getLogger().handlers[:]:
        logging.getLogger().removeHandler(handler)
        handler.close()


def test_is_admin_returns_bool():
    assert isinstance(is_admin(), bool)


def test_get_platform_info():
    info = get_platform_info()
    assert info["system"]
    assert "." in info["python_version"]
