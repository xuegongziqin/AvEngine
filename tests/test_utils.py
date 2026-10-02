"""utils 模块单元测试。"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from avengine.utils import (
    compute_file_hash,
    get_platform_info,
    is_admin,
    quarantine_file,
    setup_logging,
)


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
