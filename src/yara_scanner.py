"""
yara_scanner.py - YARA 规则扫描引擎
提供基于 YARA 规则的恶意代码模式匹配功能。
支持从文件/目录加载规则，对文件、目录、内存数据进行扫描。
"""

import os
import logging
from typing import Dict, List, Optional, Union

import yara

logger = logging.getLogger(__name__)


class YaraScanner:
    """YARA 扫描器，管理规则编译与扫描操作。"""

    def __init__(
        self,
        rules_path: Optional[str] = None,
        compiled_rules: Optional[yara.Rules] = None,
        max_file_size: Optional[int] = None,
    ):
        """
        初始化 YARA 扫描器。

        Args:
            rules_path: 包含 .yar/.yara 规则文件的目录路径。
            compiled_rules: 已编译的 yara.Rules 对象（若提供则忽略 rules_path）。
            max_file_size: 扫描文件的最大字节数，超过此大小的文件将被跳过。
                           None 表示不限制。
        """
        self.rules_path = rules_path
        self._rules: Optional[yara.Rules] = compiled_rules
        self.max_file_size = max_file_size
        self._rules_files_count = 0

        if self._rules is None and rules_path:
            self._compile_rules(rules_path)

    # ---------- 规则加载 ----------
    def _compile_rules(self, rules_path: str) -> None:
        """
        从指定目录递归加载 YARA 规则并编译。

        Args:
            rules_path: 规则目录路径。
        """
        if not os.path.isdir(rules_path):
            logger.error("规则目录不存在: %s", rules_path)
            self._rules = None
            self._rules_files_count = 0
            return

        rule_files: Dict[str, str] = {}
        for root, _, filenames in os.walk(rules_path):
            for fname in filenames:
                if fname.endswith(('.yar', '.yara')):
                    full_path = os.path.join(root, fname)
                    # 使用相对路径作为命名空间，避免冲突
                    namespace = os.path.relpath(full_path, rules_path)
                    rule_files[namespace] = full_path

        if not rule_files:
            logger.warning("在 %s 中未找到任何 YARA 规则文件", rules_path)
            self._rules = None
            self._rules_files_count = 0
            return

        try:
            self._rules = yara.compile(filepaths=rule_files)
            self._rules_files_count = len(rule_files)          # 记录成功编译的文件数量
            logger.info(
                "成功编译 %d 个规则文件",
                self._rules_files_count
            )
        except yara.Error as e:
            logger.error("编译 YARA 规则时出错: %s", e)
            self._rules = None
            self._rules_files_count = 0

    def reload_rules(self, rules_path: Optional[str] = None) -> bool:
        """
        重新加载并编译规则（用于热更新）。

        Args:
            rules_path: 新规则目录（若为 None 则使用初始化时的目录）。

        Returns:
            成功返回 True，否则返回 False。
        """
        target_path = rules_path or self.rules_path
        if not target_path:
            logger.error("未提供规则路径，无法重新加载")
            return False
        self._compile_rules(target_path)
        return self._rules is not None

    @property
    def is_available(self) -> bool:
        """返回扫描器是否可用（规则是否成功加载）。"""
        return self._rules is not None

    def _rules_count(self) -> int:
        """返回已加载的规则数量（内部使用）。"""
        if not self._rules:
            return 0
        # yara.Rules 对象没有直接的数量属性，通过匹配空字符串获取数量估计
        try:
            # 使用空的 matches 来获取规则列表
            # 这是 hack，但比较安全
            return len(self._rules.match(data=b""))
        except Exception:
            return 0

    @property
    def rules_count(self) -> int:
        """返回成功编译的规则文件数量（非规则条数）。"""
        return self._rules_files_count

    def scan_file(self, filepath: str) -> List[str]:
        if not self._rules:
            logger.warning("YARA 规则未加载，无法扫描文件: %s", filepath)
            return []
        if not os.path.isfile(filepath):
            logger.debug("路径不是文件，跳过: %s", filepath)
            return []
        if self.max_file_size is not None:
            try:
                size = os.path.getsize(filepath)
                if size > self.max_file_size:
                    logger.debug("文件 %s 过大 (%d 字节)，跳过", filepath, size)
                    return []
            except OSError:
                pass

        try:
            # 尝试直接使用文件路径扫描
            matches = self._rules.match(filepath)
            rule_names = [match.rule for match in matches]
            if rule_names:
                logger.info("YARA 扫描 %s 命中 %d 条规则: %s", filepath, len(rule_names), rule_names)
            return rule_names
        except yara.Error as e:
            # 如果因为路径问题失败（如中文路径），尝试读取文件内容再扫描
            logger.debug("YARA 文件路径扫描失败 (%s)，尝试读取文件内容: %s", e, filepath)
            try:
                with open(filepath, 'rb') as f:
                    data = f.read()
                matches = self._rules.match(data=data)
                rule_names = [match.rule for match in matches]
                if rule_names:
                    logger.info("YARA 扫描 %s (内存模式) 命中 %d 条规则: %s", filepath, len(rule_names), rule_names)
                return rule_names
            except Exception as read_err:
                logger.error("YARA 扫描文件 %s 时出错: %s", filepath, read_err)
                return []
        except Exception as e:
            logger.error("扫描文件 %s 时发生未知错误: %s", filepath, e)
            return []

    def scan_directory(
        self, directory: str, recursive: bool = True
    ) -> Dict[str, List[str]]:
        """
        扫描目录中的所有文件。

        Args:
            directory: 目标目录路径。
            recursive: 是否递归扫描子目录。

        Returns:
            字典，键为命中文件路径，值为匹配的规则名称列表。
        """
        results: Dict[str, List[str]] = {}
        if not self._rules:
            logger.warning("YARA 规则未加载，无法扫描目录: %s", directory)
            return results

        if not os.path.isdir(directory):
            logger.error("路径不是目录: %s", directory)
            return results

        try:
            if recursive:
                for root, _, filenames in os.walk(directory):
                    for fname in filenames:
                        full_path = os.path.join(root, fname)
                        rules_hit = self.scan_file(full_path)
                        if rules_hit:
                            results[full_path] = rules_hit
            else:
                for fname in os.listdir(directory):
                    full_path = os.path.join(directory, fname)
                    if os.path.isfile(full_path):
                        rules_hit = self.scan_file(full_path)
                        if rules_hit:
                            results[full_path] = rules_hit
        except PermissionError as e:
            logger.error("扫描目录 %s 时权限不足: %s", directory, e)
        except Exception as e:
            logger.error("扫描目录 %s 时发生错误: %s", directory, e)

        return results

    def scan_data(self, data: bytes) -> List[str]:
        """
        扫描内存/缓冲区数据。

        Args:
            data: 要扫描的字节串。

        Returns:
            匹配的规则名称列表。
        """
        if not self._rules:
            logger.warning("YARA 规则未加载，无法扫描数据")
            return []
        if not isinstance(data, bytes):
            logger.error("scan_data 需要 bytes 类型数据")
            return []
        try:
            matches = self._rules.match(data=data)
            rule_names = [match.rule for match in matches]
            if rule_names:
                logger.info("内存扫描命中 %d 条规则", len(rule_names))
            return rule_names
        except yara.Error as e:
            logger.error("YARA 扫描数据时出错: %s", e)
            return []
        except Exception as e:
            logger.error("扫描数据时发生未知错误: %s", e)
            return []

    def scan_string(self, text: str, encoding: str = "utf-8") -> List[str]:
        """
        扫描文本字符串（内部编码为字节后再扫描）。

        Args:
            text: 待扫描的字符串。
            encoding: 字符串编码方式。

        Returns:
            匹配的规则名称列表。
        """
        try:
            data = text.encode(encoding)
            return self.scan_data(data)
        except UnicodeEncodeError as e:
            logger.error("字符串编码失败: %s", e)
            return []

    # ---------- 上下文管理器 ----------
    def close(self) -> None:
        """释放资源（目前无资源需要显式释放）。"""
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def __repr__(self) -> str:
        status = "已加载" if self.is_available else "未加载"
        return f"<YaraScanner rules_count={self.rules_count} ({status})>"


# ---------- 模块演示 ----------
def _demo():
    """快速功能演示（需要预先创建测试规则文件）。"""
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    # 创建一个临时规则文件
    test_rule = """
    rule TestRule : malware
    {
        strings:
            $a = "TEST_MALWARE_STRING"
            $b = { 4D 5A 90 00 } // MZ header
        condition:
            any of them
    }
    """
    rules_dir = "./temp_yara_rules"
    os.makedirs(rules_dir, exist_ok=True)
    with open(os.path.join(rules_dir, "test.yar"), "w") as f:
        f.write(test_rule)

    # 初始化扫描器
    scanner = YaraScanner(rules_path=rules_dir, max_file_size=10 * 1024 * 1024)  # 10 MB 限制
    print(scanner)

    if scanner.is_available:
        # 扫描自身文件（不应该命中 TestRule）
        print("扫描自身:", scanner.scan_file(__file__))

        # 扫描包含特征字符串的数据
        data = b"This is a test of TEST_MALWARE_STRING inside memory"
        print("内存扫描命中:", scanner.scan_data(data))

        # 扫描一个目录（当前目录）
        print("当前目录扫描结果:", len(scanner.scan_directory(".", recursive=False)))

    else:
        print("规则加载失败，演示终止")

    # 清理临时规则
    import shutil
    shutil.rmtree(rules_dir, ignore_errors=True)


if __name__ == "__main__":
    _demo() 