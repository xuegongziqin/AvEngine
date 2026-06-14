"""
clamav_scanner.py - ClamAV 扫描引擎封装
通过 pyclamd 与 ClamAV 守护进程（clamd）通信，提供文件、目录扫描，
以及病毒库管理等功能。
"""

import os
import logging
from typing import Optional, Dict, List, Union

import pyclamd

logger = logging.getLogger(__name__)


class ClamavScanner:
    """ClamAV 扫描器，负责与 clamd 守护进程通信并执行扫描任务。"""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 3310,
        timeout: int = 30,
        auto_reload: bool = False,
    ):
        """
        初始化 ClamAV 扫描器。

        Args:
            host: clamd 服务地址
            port: clamd 服务端口
            timeout: 连接超时时间（秒）
            auto_reload: 是否在连接后自动重载病毒库（需谨慎使用）
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self._cd: Optional[pyclamd.ClamdNetworkSocket] = None

        # 尝试建立连接
        try:
            self._cd = pyclamd.ClamdNetworkSocket(
                host=self.host, port=self.port, timeout=self.timeout
            )
            self._cd.ping()
            logger.info("成功连接到 ClamAV 守护进程 (%s:%d)", self.host, self.port)
            if auto_reload:
                self.reload()
        except (ConnectionRefusedError, pyclamd.ConnectionError, OSError) as e:
            logger.error("无法连接到 ClamAV 守护进程: %s", e)
            self._cd = None
        except Exception as e:
            logger.error("初始化 ClamAV 扫描器时发生未知错误: %s", e)
            self._cd = None

    @property
    def is_available(self) -> bool:
        """返回扫描器是否处于可用状态（连接正常）。"""
        return self._cd is not None

    def scan_file(self, filepath: str) -> Optional[str]:
        """
        扫描单个文件。

        Args:
            filepath: 要扫描的文件路径

        Returns:
            如果发现病毒，返回病毒名称；否则返回 None（无病毒或扫描失败）。
        """
        if not self.is_available:
            logger.warning("ClamAV 扫描器不可用，跳过扫描: %s", filepath)
            return None

        if not os.path.isfile(filepath):
            logger.debug("跳过扫描，路径不是文件: %s", filepath)
            return None

        try:
            result = self._cd.scan_file(filepath)
            # scan_file 返回: {文件路径: ('FOUND', '病毒名')} 或 None
            if result and filepath in result:
                status, virus_name = result[filepath]
                if status == "FOUND":
                    logger.info("ClamAV 发现病毒: %s -> %s", filepath, virus_name)
                    return virus_name
            return None
        except (pyclamd.ConnectionError, OSError) as e:
            logger.error("扫描文件时连接失败: %s", e)
            self._cd = None  # 标记为不可用
            return None
        except Exception as e:
            logger.error("扫描文件 %s 时出错: %s", filepath, e)
            return None

    def scan_directory(self, directory: str, recursive: bool = True) -> Dict[str, str]:
        """
        扫描目录中的所有文件。

        Args:
            directory: 要扫描的目录路径
            recursive: 是否递归扫描子目录

        Returns:
            字典，键为发现病毒的文件路径，值为病毒名称。
        """
        infected_files: Dict[str, str] = {}
        if not self.is_available:
            logger.warning("ClamAV 扫描器不可用，无法扫描目录: %s", directory)
            return infected_files

        if not os.path.isdir(directory):
            logger.error("路径不是目录: %s", directory)
            return infected_files

        # 收集所有文件路径
        all_files = []
        if recursive:
            for dirpath, _, filenames in os.walk(directory):
                for f in filenames:
                    all_files.append(os.path.join(dirpath, f))
        else:
            all_files = [
                os.path.join(directory, f)
                for f in os.listdir(directory)
                if os.path.isfile(os.path.join(directory, f))
            ]

        if not all_files:
            logger.info("目录 %s 为空，无文件可扫描", directory)
            return infected_files

        # 逐个文件扫描（兼容所有 pyclamd 版本）
        for filepath in all_files:
            virus_name = self.scan_file(filepath)
            if virus_name:
                infected_files[filepath] = virus_name

        return infected_files

    def scan_stream(self, data: bytes) -> Optional[str]:
        """
        扫描内存中的数据流（二进制内容）。

        Args:
            data: 要扫描的字节数据

        Returns:
            如果发现病毒，返回病毒名称；否则返回 None。
        """
        if not self.is_available:
            logger.warning("ClamAV 扫描器不可用，无法扫描数据流")
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
            self._cd = None
            return None
        except Exception as e:
            logger.error("扫描数据流时出错: %s", e)
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
        """
        获取病毒库详细信息。

        Returns:
            包含 'version', 'signatures', 'daily', 'main' 等键的字典，
            或 None（连接失败时）。
        """
        if not self.is_available:
            return None
        try:
            # pyclamd 的 stats() 返回类似：
            # {'POOLS': 1, 'STATE': 'VALID', 'THREADS': 'live 1/ idle 0/ max 10', 'QUEUE': 0, 'MEMSTATS': ...}
            # 对于病毒库版本，通常用 reload 或直接调用 clamd 的 VERSION 命令
            # 这里返回 stats 信息，同时也可以组合 version()
            stats = self._cd.stats()
            version = self._cd.version()
            return {
                "version": version,
                "stats": stats,
            }
        except Exception as e:
            logger.error("获取病毒库信息失败: %s", e)
            return None

    def reload(self) -> bool:
        """
        通知 clamd 重载病毒库（类似 freshclam 更新后执行）。

        Returns:
            成功返回 True，否则返回 False。
        """
        if not self.is_available:
            logger.warning("ClamAV 不可用，无法重载病毒库")
            return False
        try:
            result = self._cd.reload()
            if result == "RELOADING":
                logger.info("病毒库重载指令已发送")
                return True
            else:
                logger.warning("病毒库重载返回异常: %s", result)
                return False
        except Exception as e:
            logger.error("重载病毒库失败: %s", e)
            return False

    def close(self) -> None:
        """
        释放资源（关闭网络连接）。
        调用后扫描器不再可用。
        """
        if self._cd:
            try:
                # pyclamd 没有显式的 close，但可以删除引用
                del self._cd
                self._cd = None
                logger.info("已关闭与 ClamAV 的连接")
            except Exception as e:
                logger.debug("关闭连接时忽略错误: %s", e)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False  # 不抑制异常

    def __repr__(self) -> str:
        status = "可用" if self.is_available else "不可用"
        return f"<ClamavScanner {self.host}:{self.port} ({status})>"


# 简单的命令行测试（直接运行该模块时）
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    # 示例：扫描当前目录下的一个测试文件（需提前安装并启动 clamd）
    scanner = ClamavScanner()
    if scanner.is_available:
        version = scanner.get_version()
        print(f"ClamAV 版本: {version}")
        db_info = scanner.get_database_info()
        print(f"病毒库信息: {db_info}")

        # 扫描一个安全测试文件
        test_file = "eicar.com"
        if os.path.exists(test_file):
            result = scanner.scan_file(test_file)
            if result:
                print(f"检测到病毒: {result}")
            else:
                print("未发现威胁")
        else:
            print(f"测试文件 {test_file} 不存在，跳过扫描")
    else:
        print("扫描器不可用，请确保 clamd 服务正在运行")