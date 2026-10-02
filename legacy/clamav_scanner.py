"""
clamav_scanner.py - ClamAV 扫描引擎封装
通过 pyclamd 与 clamd 守护进程通信，提供文件、目录、数据流扫描与病毒库管理。
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, Optional, Union

import pyclamd

logger = logging.getLogger(__name__)


class ClamavScanner:
    """ClamAV 扫描器，负责与 clamd 通信并执行扫描。"""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 3310,
        timeout: int = 30,
        auto_reload: bool = False,
    ):
        """
        初始化 ClamAV 扫描器并尝试连接。

        Args:
            host: clamd 地址。
            port: clamd 端口。
            timeout: 连接超时（秒）。
            auto_reload: 连接成功后是否立即重载病毒库。
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self._cd: Optional[pyclamd.ClamdNetworkSocket] = None

        try:
            cd = pyclamd.ClamdNetworkSocket(host=host, port=port, timeout=timeout)
            cd.ping()
            self._cd = cd
            logger.info("已连接 ClamAV 守护进程 (%s:%d)", host, port)
            if auto_reload:
                self.reload()
        except (ConnectionRefusedError, pyclamd.ConnectionError, OSError) as e:
            logger.error("无法连接 ClamAV 守护进程 (%s:%d): %s", host, port, e)
        except Exception as e:
            logger.error("初始化 ClamAV 扫描器出错: %s", e)

    @property
    def is_available(self) -> bool:
        """连接是否正常可用。"""
        return self._cd is not None

    def _mark_unavailable(self) -> None:
        """连接失效时把扫描器标记为不可用。"""
        self._cd = None

    def scan_file(self, filepath: Union[str, Path]) -> Optional[str]:
        """
        扫描单个文件。

        Returns:
            发现病毒时返回病毒名，否则返回 None。
        """
        if not self.is_available:
            logger.warning("ClamAV 不可用，跳过扫描: %s", filepath)
            return None
        if not Path(filepath).is_file():
            logger.debug("路径不是文件，跳过: %s", filepath)
            return None

        try:
            result = self._cd.scan_file(str(filepath))
            if result and str(filepath) in result:
                status, virus_name = result[str(filepath)]
                if status == "FOUND":
                    logger.info("ClamAV 发现病毒: %s -> %s", filepath, virus_name)
                    return virus_name
            return None
        except (pyclamd.ConnectionError, OSError) as e:
            logger.error("扫描文件时连接失败: %s", e)
            self._mark_unavailable()
            return None
        except Exception as e:
            logger.error("扫描文件 %s 出错: %s", filepath, e)
            return None

    def scan_directory(
        self, directory: Union[str, Path], recursive: bool = True
    ) -> Dict[str, str]:
        """
        扫描目录中的所有文件。

        Returns:
            {受感染文件路径: 病毒名}。
        """
        infected: Dict[str, str] = {}
        if not self.is_available:
            logger.warning("ClamAV 不可用，无法扫描目录: %s", directory)
            return infected

        base = Path(directory)
        if not base.is_dir():
            logger.error("路径不是目录: %s", directory)
            return infected

        files = [p for p in (base.rglob("*") if recursive else base.iterdir()) if p.is_file()]
        if not files:
            logger.info("目录 %s 为空，无文件可扫描", directory)
            return infected

        for path in files:
            virus_name = self.scan_file(path)
            if virus_name:
                infected[str(path)] = virus_name
        return infected

    def scan_stream(self, data: bytes) -> Optional[str]:
        """扫描内存中的数据流，返回病毒名或 None。"""
        if not self.is_available:
            logger.warning("ClamAV 不可用，无法扫描数据流")
            return None
        try:
            result = self._cd.scan_stream(data)
            if result and result.get("stream"):
                status, virus = result["stream"]
                if status == "FOUND":
                    return virus
            return None
        except (pyclamd.ConnectionError, OSError) as e:
            logger.error("扫描数据流时连接失败: %s", e)
            self._mark_unavailable()
            return None
        except Exception as e:
            logger.error("扫描数据流出错: %s", e)
            return None

    def get_version(self) -> Optional[str]:
        """获取 ClamAV 引擎版本。"""
        if not self.is_available:
            return None
        try:
            return self._cd.version()
        except Exception as e:
            logger.error("获取引擎版本失败: %s", e)
            return None

    def get_database_info(self) -> Optional[Dict[str, str]]:
        """获取病毒库信息（version + stats）。"""
        if not self.is_available:
            return None
        try:
            return {"version": self._cd.version(), "stats": self._cd.stats()}
        except Exception as e:
            logger.error("获取病毒库信息失败: %s", e)
            return None

    def reload(self) -> bool:
        """通知 clamd 重载病毒库。"""
        if not self.is_available:
            logger.warning("ClamAV 不可用，无法重载病毒库")
            return False
        try:
            result = self._cd.reload()
            if result == "RELOADING":
                logger.info("病毒库重载指令已发送")
                return True
            logger.warning("病毒库重载返回异常: %s", result)
            return False
        except Exception as e:
            logger.error("重载病毒库失败: %s", e)
            return False

    def close(self) -> None:
        """断开连接，调用后扫描器不可用。"""
        self._cd = None

    def __enter__(self) -> "ClamavScanner":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.close()
        return False

    def __repr__(self) -> str:
        status = "可用" if self.is_available else "不可用"
        return f"<ClamavScanner {self.host}:{self.port} ({status})>"
