"""
gui/tab_ai.py - AI 分析页

三种用法：
  * 自由提问（`ai_ask_stream`）：边生成边显示思考 / 工具调用 / 正文
  * 批次事件分析（`ai_run_batch_stream`）：按时间窗分析采集到的事件
  * 常驻后台分析（`ai_start_background` + `ai_poll`）：内核线程按 interval 自动分析

流式回调是在**工作线程**里触发的，绝不能直接写控件：
事件先进 `queue.Queue`，由 Tk 的 after 循环取出渲染。
"""

from __future__ import annotations

import json
import queue
import time
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any, Dict, List, Optional

from .. import core_bridge
from ..aiconfig import build_ai_payload, load_ai_config
from . import theme
from .ops import OpResult
from .widgets import Card, OutputPane, StatusPill, ToolTip

DRAIN_MS = 120
BG_POLL_MS = 3000

#: 单次刷新最多写多少字符：防止一个事件 flush 掉几十 KB 把 tick 预算打穿
MAX_FLUSH_CHARS = 8192


class AiTab(ttk.Frame):
    """AI 会话界面。"""

    def __init__(self, master, app):
        super().__init__(master, padding=10)
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)
        self._events: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self._running = False
        self._bg_polling = False
        # 流式文本缓冲（见 _push_stream）。用**列表**累积：字符串 += 在
        # 上万个 chunk 时是 O(n^2)，实测会让主线程卡十几秒。
        self._pending_parts: List[str] = []
        self._pending_tag: Optional[str] = None

        head = Card(self, "AI 状态")
        head.grid(row=0, column=0, sticky="ew")
        self.pill = StatusPill(head, "AI: 未知", "unknown")
        self.pill.pack(anchor="w")
        self.hint = ttk.Label(head, text="", style="Hint.TLabel", wraplength=940, justify="left")
        self.hint.pack(anchor="w", pady=(4, 0))

        buttons = ttk.Frame(head)
        buttons.pack(anchor="w", pady=(8, 0))
        ttk.Button(buttons, text="测试连通", command=self.test_connection).pack(side="left", padx=(0, 6))
        ttk.Button(buttons, text="批次分析", command=self.run_batch).pack(side="left", padx=(0, 6))
        self.background_button = ttk.Button(buttons, text="启动常驻分析", command=self.toggle_background)
        self.background_button.pack(side="left", padx=(0, 6))
        ttk.Button(buttons, text="打开设置", command=lambda: self._goto("设置")).pack(side="left")
        ToolTip(buttons.winfo_children()[-1], "在「设置」页填写 base_url / model / api_key 并启用 AI")

        # ---------- 提问 ----------
        ask = Card(self, "提问")
        ask.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        ask.columnconfigure(0, weight=1)
        self.question = tk.Text(ask, height=3, wrap="word", font=theme.ui_font())
        self.question.grid(row=0, column=0, sticky="ew")
        self.question.bind("<Control-Return>", lambda _e: self.ask())
        row = ttk.Frame(ask)
        row.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        self.ask_button = ttk.Button(row, text="提问（Ctrl+Enter）", command=self.ask)
        self.ask_button.pack(side="left")
        self.minutes = tk.StringVar(value="0")
        ttk.Label(row, text="批次窗口(分钟):").pack(side="left", padx=(12, 4))
        ttk.Entry(row, textvariable=self.minutes, width=6).pack(side="left")
        ttk.Label(row, text="0 = 使用 config.ini 的 interval", style="Hint.TLabel").pack(
            side="left", padx=(6, 0))

        # ---------- 输出 ----------
        output = Card(self, "会话输出")
        output.grid(row=2, column=0, sticky="nsew", pady=(6, 0))
        self.pane = OutputPane(output, height=18)
        self.pane.pack(fill="both", expand=True)

        self.after(DRAIN_MS, self._drain_events)

    # ---------------- 钩子 ----------------

    def append_output(self, text: str) -> None:
        self.pane.append(text)

    def on_config_reloaded(self) -> None:
        self._refresh_hint()

    def on_status(self, status: Dict[str, Any]) -> None:
        self._refresh_hint(status)

    def on_close(self) -> None:
        self._bg_polling = False

    # ---------------- 状态 ----------------

    def _refresh_hint(self, status: Optional[Dict[str, Any]] = None) -> None:
        cfg = load_ai_config()
        if not cfg.exists:
            text = "未配置：请到「设置」页填写（或从 config.ini.example 复制一份 config.ini）"
            level = "warn"
        elif not cfg.enabled:
            text = "已禁用（config.ini [ai] enabled=false）"
            level = "warn"
        elif not cfg.configured:
            text = "配置不完整：缺少 base_url 或 model"
            level = "warn"
        else:
            text = "已启用：{} @ {}（超时 {}s，最多 {} 轮，批次源 {}）".format(
                cfg.model, cfg.base_url, cfg.timeout, cfg.max_rounds,
                ", ".join(cfg.batch_sources()) or "无")
            level = "ok"
        self.pill.set("AI: {}".format(text.split("：")[0] if "：" in text else text), level)
        self.hint.configure(text=text + "\n流式显示依赖 avengine_core.dll 的流式接口；"
                                    "旧内核会自动退化为一次性输出。")

    def _goto(self, title: str) -> None:
        page = self.app.tabs.get(title)
        if page is not None:
            self.app.notebook.select(page)

    # ---------------- 动作 ----------------

    def _payload(self) -> Dict[str, Any]:
        return build_ai_payload(self.app.config_data or {}, load_ai_config())

    def _set_running(self, running: bool) -> None:
        self._running = running
        state = ["disabled"] if running else ["!disabled"]
        self.ask_button.state(state)

    def test_connection(self) -> None:
        payload = self._payload()

        def work() -> OpResult:
            if not core_bridge.is_available():
                return OpResult(False, "C++ 内核未加载: {}".format(core_bridge.load_error()))
            try:
                res = core_bridge.ai_test(payload)
            except core_bridge.CoreError as exc:
                return OpResult(False, "调用失败: {}".format(exc))
            ok = bool(res.get("ok"))
            return OpResult(ok, "连通性: {}".format(res.get("detail") or res.get("error") or "未知"),
                            json.dumps(res, ensure_ascii=False, indent=2), res)

        self.app.run_task("正在测试 AI 连通性…", work,
                          lambda result: self.app.show_result("AI 连通性", result, self.pane))

    def ask(self) -> None:
        question = self.question.get("1.0", "end").strip()
        if not question:
            messagebox.showinfo("AI", "请输入问题")
            return
        self._start_session(question=question)

    def ask_about_detection(self, path: str) -> None:
        """供监控/扫描页调用：预填一个针对具体检出的问题并立即提问。"""
        self.question.delete("1.0", "end")
        self.question.insert("1.0", "文件 {} 被检出，请分析其风险并给出处置建议。".format(path))
        self._start_session(question=self.question.get("1.0", "end").strip())

    def run_batch(self) -> None:
        try:
            minutes = max(0, int(self.minutes.get() or 0))
        except ValueError:
            messagebox.showwarning("AI", "批次窗口分钟数必须是整数")
            return
        self._start_session(minutes=minutes)

    def _start_session(self, question: Optional[str] = None, minutes: int = 0) -> None:
        if self._running:
            self.app.set_status("AI 会话进行中…")
            return
        if not core_bridge.is_available():
            messagebox.showerror("AI", "C++ 内核未加载: {}".format(core_bridge.load_error()))
            return
        cfg = load_ai_config()
        if not cfg.active:
            messagebox.showinfo("AI", "AI 未启用或配置不完整：请到「设置」页填写 base_url / model / api_key。")
            return

        payload = self._payload()
        self.pane.clear()
        self._set_running(True)
        mode = "ask" if question else "batch"
        self.pane.append("[AI] {}".format("自由提问" if question else "批次事件分析（{} 分钟）".format(minutes or "默认")),
                         "info")
        if question:
            self.pane.append("提问: {}".format(question), "dim")

        def on_event(event: Dict[str, Any]) -> None:
            # 工作线程：只入队，绝不碰控件
            self._events.put(event)

        def work() -> OpResult:
            try:
                if question:
                    res = core_bridge.ai_ask_stream(payload, question, on_event=on_event)
                else:
                    res = core_bridge.ai_run_batch_stream(payload, minutes, on_event=on_event)
            except core_bridge.CoreError as exc:
                return OpResult(False, "AI 调用失败: {}".format(exc), "", {"error": str(exc)})
            ok = bool(res.get("ok"))
            summary = "会话结束: {} | {} 轮 | {} 次工具调用".format(
                res.get("ended_by"), res.get("rounds"), res.get("tool_calls"))
            return OpResult(ok, summary, res.get("final_text") or "", {"result": res, "mode": mode})

        def done(result: OpResult) -> None:
            self._set_running(False)
            self._drain_all()   # 把剩余事件渲染完再收尾（此时不必再考虑响应性）
            self._flush_stream()
            res = result.data.get("result") or {}
            final_text = (res.get("final_text") or "").strip()
            if final_text:
                self.pane.append("── AI 结论 ──", "info")
                self.pane.append(final_text, "ok")
            self.pane.append("──── {}".format(result.message), "dim")
            if not result.ok:
                self.pane.append(result.message, "error")

        self.app.run_task("AI 会话进行中…", work, done)

    # ---------------- 常驻后台分析 ----------------

    def toggle_background(self) -> None:
        if core_bridge.ai_background_running():
            def stop() -> OpResult:
                core_bridge.ai_stop_background()
                return OpResult(True, "已停止常驻分析")

            def stopped(result: OpResult) -> None:
                self._bg_polling = False
                self.background_button.configure(text="启动常驻分析")
                self.pane.append(result.message, "dim")
                self._refresh_hint()

            self.app.run_task("正在停止常驻分析…", stop, stopped)
            return

        if not load_ai_config().active:
            messagebox.showinfo("AI", "AI 未启用或配置不完整：请到「设置」页填写。")
            return
        payload = self._payload()

        def start() -> OpResult:
            try:
                core_bridge.ai_start_background(payload)
            except core_bridge.CoreError as exc:
                return OpResult(False, "启动常驻分析失败: {}".format(exc))
            return OpResult(True, "常驻分析已启动（按 config.ini 的 interval 周期执行）")

        def started(result: OpResult) -> None:
            self.pane.append(result.message, "ok" if result.ok else "error")
            if not result.ok:
                messagebox.showwarning("AI", result.message)
                return
            self.background_button.configure(text="停止常驻分析")
            self._bg_polling = True
            self.after(BG_POLL_MS, self._poll_background)

        self.app.run_task("正在启动常驻分析…", start, started)

    def _poll_background(self) -> None:
        if not self._bg_polling:
            return
        try:
            if not core_bridge.ai_background_running():
                self._bg_polling = False
                self.background_button.configure(text="启动常驻分析")
                self.pane.append("常驻分析已结束。", "dim")
                return
            for event in core_bridge.ai_poll(50) or []:
                self._render_event(event)
        except Exception as exc:  # noqa: BLE001
            self.pane.append("常驻分析轮询失败: {}".format(exc), "error")
        self.after(BG_POLL_MS, self._poll_background)

    # ---------------- 事件渲染 ----------------

    def _push_stream(self, tag: str, text: str) -> None:
        """
        流式文本累积渲染。

        模型的 content / thinking 是**一大段话被拆成很多小 chunk** 推过来的，
        早期实现把每个 chunk 当作一行 append，结果界面上"一个词一行"（用户实测截图）。

        性能注意：这里用**列表 + join**，绝不能用 `self._pending_text += chunk`。
        后者在同一个段落被拆成上万个 chunk 时是 O(n²) 的内存复制 —— 实测一次 AI
        会话里主线程因此卡了 13.9 秒（界面完全没响应）。
        """
        if not text:
            return
        if self._pending_tag is not None and self._pending_tag != tag:
            self._flush_stream()
        self._pending_tag = tag
        self._pending_parts.append(text)
        if "\n" not in text:
            return          # 没有换行：继续累积，不做任何控件操作
        buf = "".join(self._pending_parts)
        self._pending_parts.clear()
        while "\n" in buf:
            line, buf = buf.split("\n", 1)
            self.pane.write(line + "\n", tag)
        if buf:
            self._pending_parts.append(buf)   # 末段留到下次

    def _flush_stream(self, limit: int = 0) -> None:
        """
        把缓冲里剩下的半行写出去（段落结束/会话结束时调用）。

        `limit > 0` 时最多写 limit 个字符，剩下的留到下次 —— 这样**单条事件**的渲染
        成本也有上限。为什么需要：向 Tk Text 插入的成本随控件内容量增长（长会话实测
        单次 insert 到 0.25s），一次事件 flush 掉几十 KB 就会突破 tick 预算、界面卡顿。
        """
        if self._pending_parts:
            buf = "".join(self._pending_parts)
            self._pending_parts.clear()
            if limit and len(buf) > limit:
                self.pane.write(buf[:limit], self._pending_tag)
                self._pending_parts.append(buf[limit:])
                return
            self.pane.write(buf, self._pending_tag)
        if self._pending_tag is not None and not self._pending_parts:
            self.pane.write("\n", self._pending_tag)
            self._pending_tag = None

    def _drain_now(self, budget_ms: int = 25, max_events: int = 4000) -> bool:
        """
        渲染队列里的事件，**限制每个 tick 的工作量**。

        返回 True 表示还有积压（调用方应立刻再排一次 tick）。
        为什么必须有上限：DLL 在阻塞型工具执行期间仍会推事件，一秒几千条；
        早期实现一次 tick 把整个队列渲染完，实测主线程被卡住 3.3 秒，
        用户看到的就是"AI 一跑工具 GUI 就卡死"。

        预算**每条事件都检查**：早期为了"省开销"每 128 条才查一次，结果单次 drain
        仍能跑到 1.47 秒（一次事件可能 flush 很大的缓冲）。monotonic 每次几十纳秒，
        与渲染一条事件相比可以忽略。
        """
        deadline = time.monotonic() + budget_ms / 1000.0
        done = 0
        while done < max_events:
            try:
                event = self._events.get_nowait()
            except queue.Empty:
                return False
            self._render_event(event)
            done += 1
            if time.monotonic() > deadline:
                return not self._events.empty()
        return not self._events.empty()

    def _drain_events(self) -> None:
        more = self._drain_now()
        # 有积压就立刻再来一次（0ms），否则回到常规节奏。
        # 无论队列多长，单个 tick 都只花 ~25ms，界面保持可响应。
        self.after(0 if more else DRAIN_MS, self._drain_events)

    def _drain_all(self) -> None:
        """会话结束时把剩余事件全部渲染完（此时不必再考虑响应性）。"""
        while self._drain_now(budget_ms=2000, max_events=200000):
            pass

    def _render_event(self, event: Dict[str, Any]) -> None:
        """在主线程渲染一条流式事件。"""
        kind = event.get("kind")
        # 非流式文本事件之前，先把上一段正文落地（限制单次写入量：见 _flush_stream）
        if kind not in ("content", "thinking"):
            self._flush_stream(limit=MAX_FLUSH_CHARS)
        if kind == "session_info":
            mode = {"ask": "自由提问", "batch": "批次事件分析",
                    "detection": "检出分析"}.get(event.get("mode"), event.get("mode") or "")
            self.pane.append("[会话] {}".format(mode), "info")
        elif kind == "session_start":
            self.pane.append("模型: {} | 最大轮数: {}".format(
                event.get("model"), event.get("max_rounds")), "dim")
        elif kind == "round_start":
            self.pane.append("── 第 {} 轮 ──".format(event.get("round")), "dim")
        elif kind == "thinking":
            self._push_stream("dim", event.get("text", ""))
        elif kind == "content":
            self._push_stream("ok", event.get("text", ""))
        elif kind == "tool_call":
            try:
                detail = json.dumps(event.get("args"), ensure_ascii=False)
            except (TypeError, ValueError):
                detail = str(event.get("args"))
            if len(detail) > 300:
                detail = detail[:300] + "…"
            self.pane.append("[AI →] {} {}".format(event.get("name"), detail), "tool")
        elif kind == "tool_result":
            detail = str(event.get("detail", ""))
            if len(detail) > 400:
                detail = detail[:400] + "…"
            took = event.get("ms")
            self.pane.append("[AI ←] {}: {} {}".format(
                event.get("name"), detail, "{}ms".format(took) if isinstance(took, int) else ""),
                "tool" if event.get("ok", True) else "error")
        elif kind == "note":
            self.pane.append("[提示] {}".format(event.get("text", "")), "dim")
        elif kind == "error":
            self.pane.append("[错误] {}".format(event.get("message", "")), "error")
        elif kind == "final":
            text = (event.get("text") or "").strip()
            if text:
                self.pane.append("── 结论 ──", "info")
                self.pane.append(text, "ok")
        elif kind == "done":
            self.pane.append("（会话结束：{} 轮 / {} 次工具调用）".format(
                event.get("rounds"), event.get("tool_calls")), "dim")
