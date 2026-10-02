"""
yara_scanner.py - YARA 规则扫描引擎
从目录递归加载 .yar/.yara 规则并编译，支持对文件、目录、内存数据进行扫描。
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional, Union

import yara

logger = logging.getLogger(__name__)

RULE_SUFFIXES = (".yar", ".yara")


class YaraScanner:
    """YARA 扫描器，负责规则编译与扫描。"""

    def __init__(
        self,
        rules_path: Optional[Union[str, Path]] = None,
        compiled_rules: Optional[yara.Rules] = None,
        max_file_size: Optional[int] = None,
    ):
        """
        初始化 YARA 扫描器。

        Args:
            rules_path: 包含 .yar/.yara 规则文件的目录。
            compiled_rules: 已编译的 yara.Rules，提供后忽略 rules_path。
            max_file_size: 超过该字节数的文件跳过扫描，None 表示不限制。
        """
        self.rules_path = str(rules_path) if rules_path else None
        self._rules: Optional[yara.Rules] = compiled_rules
        self.max_file_size = max_file_size
        self._rules_files_count = 0
        self.skipped_files: List[str] = []

        if self._rules is None and self.rules_path:
            self._compile_rules(self.rules_path)

    # ---------- 规则加载 ----------

    @staticmethod
    def _failing_file(error: yara.Error, filepaths: Dict[str, str]) -> Optional[str]:
        """从 yara 编译错误中定位出错的规则文件路径。"""
        message = str(error)
        for path in filepaths.values():
            if str(path) in message:
                return str(path)
        return None

    def _compile_rules(self, rules_path: str) -> None:
        """
        递归收集规则文件并编译。

        单个规则文件语法/特性不兼容时会跳过该文件并继续，
        避免一条坏规则导致整个规则库不可用。
        """
        base = Path(rules_path)
        if not base.is_dir():
            logger.error("规则目录不存在: %s", rules_path)
            self._rules = None
            self._rules_files_count = 0
            self.skipped_files = []
            return

        filepaths: Dict[str, str] = {}
        for path in sorted(base.rglob("*")):
            if path.suffix in RULE_SUFFIXES and path.is_file():
                # 用相对路径作命名空间，避免不同目录下规则名冲突
                filepaths[str(path.relative_to(base))] = str(path)

        if not filepaths:
            logger.warning("在 %s 中未找到任何 YARA 规则文件", rules_path)
            self._rules = None
            self._rules_files_count = 0
            self.skipped_files = []
            return

        skipped: List[str] = []
        while True:
            try:
                self._rules = yara.compile(filepaths=filepaths)
                break
            except yara.Error as e:
                bad_file = self._failing_file(e, filepaths)
                if bad_file is None:
                    logger.error("编译 YARA 规则失败: %s", e)
                    self._rules = None
                    self._rules_files_count = 0
                    self.skipped_files = skipped
                    return
                logger.warning("跳过无法编译的规则文件 %s: %s", bad_file, e)
                skipped.append(bad_file)
                filepaths = {k: v for k, v in filepaths.items() if v != bad_file}
                if not filepaths:
                    logger.error("规则目录 %s 中没有任何可编译的规则", rules_path)
                    self._rules = None
                    self._rules_files_count = 0
                    self.skipped_files = skipped
                    return

        self.skipped_files = skipped
        self._rules_files_count = len(filepaths)
        logger.info(
            "成功编译 %d 个规则文件%s",
            self._rules_files_count,
            f" (跳过 {len(skipped)} 个)" if skipped else "",
        )

    def reload_rules(self, rules_path: Optional[Union[str, Path]] = None) -> bool:
        """重新编译规则（热更新）。返回是否成功。"""
        target = str(rules_path) if rules_path else self.rules_path
        if not target:
            logger.error("未提供规则路径，无法重新加载")
            return False
        self.rules_path = target
        self._compile_rules(target)
        return self.is_available

    @property
    def is_available(self) -> bool:
        """规则是否成功加载。"""
        return self._rules is not None

    @property
    def rules_count(self) -> int:
        """已成功编译的规则文件数量。"""
        return self._rules_files_count

    @property
    def skipped_count(self) -> int:
        """因语法或特性不兼容而被跳过的规则文件数量。"""
        return len(self.skipped_files)

    # ---------- 扫描 ----------

    def scan_file(self, filepath: Union[str, Path]) -> List[str]:
        """扫描单个文件，返回命中的规则名列表。"""
        if not self._rules:
            logger.warning("YARA 规则未加载，无法扫描: %s", filepath)
            return []

        path = Path(filepath)
        if not path.is_file():
            logger.debug("路径不是文件，跳过: %s", filepath)
            return []

        if self.max_file_size is not None:
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
            if size > self.max_file_size:
                logger.debug("文件 %s 过大 (%d 字节)，跳过", filepath, size)
                return []

        try:
            matches = self._rules.match(filepath=str(path))
        except yara.Error as e:
            # 常见于非 ASCII 路径，回退为按内容匹配
            logger.debug("按路径匹配失败 (%s)，改用内容匹配: %s", e, filepath)
            return self.scan_data(self._read_bytes(path), context=str(filepath))
        except Exception as e:
            logger.error("扫描文件 %s 出错: %s", filepath, e)
            return []

        rule_names = [m.rule for m in matches]
        if rule_names:
            logger.info("YARA 扫描 %s 命中 %d 条规则: %s", filepath, len(rule_names), rule_names)
        return rule_names

    @staticmethod
    def _read_bytes(path: Path) -> bytes:
        try:
            return path.read_bytes()
        except OSError as e:
            logger.error("读取文件 %s 失败: %s", path, e)
            return b""

    def scan_directory(
        self, directory: Union[str, Path], recursive: bool = True
    ) -> Dict[str, List[str]]:
        """
        扫描目录中的文件。

        Returns:
            {文件路径: [命中的规则名]}，仅包含命中的文件。
        """
        results: Dict[str, List[str]] = {}
        if not self._rules:
            logger.warning("YARA 规则未加载，无法扫描目录: %s", directory)
            return results

        base = Path(directory)
        if not base.is_dir():
            logger.error("路径不是目录: %s", directory)
            return results

        try:
            files = base.rglob("*") if recursive else base.iterdir()
            for item in files:
                if not item.is_file():
                    continue
                hits = self.scan_file(item)
                if hits:
                    results[str(item)] = hits
        except PermissionError as e:
            logger.error("扫描目录 %s 权限不足: %s", directory, e)
        except OSError as e:
            logger.error("扫描目录 %s 出错: %s", directory, e)

        return results

    def scan_data(self, data: bytes, context: str = "") -> List[str]:
        """扫描内存/缓冲区数据，返回命中的规则名列表。"""
        if not self._rules:
            logger.warning("YARA 规则未加载，无法扫描数据")
            return []
        if not isinstance(data, bytes):
            logger.error("scan_data 需要 bytes 类型数据")
            return []

        try:
            matches = self._rules.match(data=data)
        except yara.Error as e:
            logger.error("YARA 扫描数据出错: %s", e)
            return []
        except Exception as e:
            logger.error("扫描数据时发生未知错误: %s", e)
            return []

        rule_names = [m.rule for m in matches]
        if rule_names:
            target = context or "内存数据"
            logger.info("YARA 扫描 %s 命中 %d 条规则: %s", target, len(rule_names), rule_names)
        return rule_names

    def scan_string(self, text: str, encoding: str = "utf-8") -> List[str]:
        """扫描文本字符串（编码为字节后匹配）。"""
        try:
            return self.scan_data(text.encode(encoding))
        except UnicodeEncodeError as e:
            logger.error("字符串编码失败: %s", e)
            return []

    # ---------- 上下文管理器 ----------

    def __enter__(self) -> "YaraScanner":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self._rules = None
        return False

    def __repr__(self) -> str:
        status = "已加载" if self.is_available else "未加载"
        return f"<YaraScanner rules_count={self.rules_count} ({status})>"
