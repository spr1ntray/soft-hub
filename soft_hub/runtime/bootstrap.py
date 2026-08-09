from __future__ import annotations

import asyncio
import importlib
import inspect
import json
import os
import signal
import sys
import threading
import traceback
from pathlib import Path
from typing import Any

CORE_ROOT = Path(__file__).resolve().parents[2]
_core_path = str(CORE_ROOT)
sys.path.insert(0, _core_path)
try:
    from soft_hub.sdk import CancelledError, decode_context  # noqa: E402
finally:
    # The packaged core lives beside its own dependencies. Keeping that directory
    # ahead of plugin site-packages would silently override versions installed in
    # the plugin's .venv. The SDK is loaded now, so remove only our temporary path.
    sys.path.remove(_core_path)

_protocol_stdout = sys.stdout
_write_lock = threading.Lock()
_sequence = 0
_cancelled = threading.Event()


class _SanitizingBinaryStream:
    """Minimal bytes writer that cannot bypass runtime-secret sanitization."""

    def __init__(self, stream: Any, sanitize: Any, encoding: str):
        self._stream = stream
        self._sanitize = sanitize
        self._encoding = encoding

    def write(self, value: bytes | bytearray | memoryview) -> int:
        raw = bytes(value)
        text = raw.decode(self._encoding, errors="replace")
        safe = self._sanitize(text).encode(self._encoding, errors="replace")
        self._stream.write(safe)
        return len(raw)

    def flush(self) -> None:
        self._stream.flush()

    def fileno(self) -> int:
        return int(self._stream.fileno())

    def isatty(self) -> bool:
        return bool(self._stream.isatty())

    def writable(self) -> bool:
        return True

    @property
    def closed(self) -> bool:
        return bool(self._stream.closed)


class _SanitizingTextStream:
    """File-like stderr facade that masks protected values before host I/O."""

    def __init__(self, stream: Any, sanitize: Any):
        self._stream = stream
        self._sanitize = sanitize
        self._encoding = str(getattr(stream, "encoding", None) or "utf-8")
        raw_buffer = getattr(stream, "buffer", None)
        self._buffer = (
            _SanitizingBinaryStream(raw_buffer, sanitize, self._encoding)
            if raw_buffer is not None
            else None
        )

    def write(self, value: str) -> int:
        text = str(value)
        self._stream.write(self._sanitize(text))
        return len(text)

    def writelines(self, values: Any) -> None:
        for value in values:
            self.write(value)

    def flush(self) -> None:
        self._stream.flush()

    def fileno(self) -> int:
        return int(self._stream.fileno())

    def isatty(self) -> bool:
        return bool(self._stream.isatty())

    def writable(self) -> bool:
        return True

    @property
    def encoding(self) -> str:
        return self._encoding

    @property
    def errors(self) -> str:
        return str(getattr(self._stream, "errors", None) or "replace")

    @property
    def closed(self) -> bool:
        return bool(self._stream.closed)

    @property
    def buffer(self) -> _SanitizingBinaryStream:
        if self._buffer is None:
            raise AttributeError("stderr has no binary buffer")
        return self._buffer


def emit(event: dict[str, Any]) -> None:
    global _sequence
    with _write_lock:
        _sequence += 1
        frame = {"protocol": "soft-hub-jsonl/1", "seq": _sequence, **event}
        _protocol_stdout.write(json.dumps(frame, ensure_ascii=False, separators=(",", ":")) + "\n")
        _protocol_stdout.flush()


def request_cancel(_signum: int, _frame: Any) -> None:
    if not _cancelled.is_set():
        _cancelled.set()
        emit(
            {
                "type": "warning",
                "level": "warning",
                "message": "Получен запрос на безопасную остановку",
                "data": {},
            }
        )


def main() -> int:
    if len(sys.argv) != 3:
        emit({"type": "failed", "level": "error", "message": "Некорректный bootstrap", "data": {}})
        return 2
    plugin_root = Path(sys.argv[1]).resolve()
    entrypoint = sys.argv[2]
    if not plugin_root.is_dir():
        emit({"type": "failed", "level": "error", "message": "Каталог плагина не найден", "data": {}})
        return 2

    signal.signal(signal.SIGTERM, request_cancel)
    if hasattr(signal, "SIGINT"):
        signal.signal(signal.SIGINT, request_cancel)

    frame = sys.stdin.buffer.readline(8 * 1024 * 1024 + 1)
    if not frame or len(frame) > 8 * 1024 * 1024:
        emit({"type": "failed", "level": "error", "message": "Контекст запуска отсутствует или слишком велик", "data": {}})
        return 2
    try:
        context = decode_context(frame.decode("utf-8"), emit, _cancelled)
        # Keep the protocol on the original stdout, but prevent accidental
        # print/logging (including stderr.buffer writes) from racing the host's
        # in-memory protect_secret control frame with an unredacted value.
        sys.stderr = _SanitizingTextStream(sys.stderr, context.sanitize_text)
        sys.path.insert(0, str(plugin_root))
        module_name, function_name = entrypoint.split(":", 1)
        module = importlib.import_module(module_name)
        function = getattr(module, function_name)
        if not callable(function):
            raise TypeError("Entry point не является callable")
        emit(
            {
                "type": "started",
                "level": "info",
                "message": "Плагин принял задачу",
                "data": {"action_id": context.action_id},
            }
        )
        # Accidental print() must not corrupt the JSONL protocol.
        sys.stdout = sys.stderr
        result = function(context)
        if inspect.isawaitable(result):
            result = asyncio.run(result)
        sys.stdout = _protocol_stdout
        context.check_cancelled()
        summary = context.sanitize_value(result if isinstance(result, dict) else {})
        emit(
            {
                "type": "completed",
                "level": "success",
                "message": "Задача завершена",
                "data": {"summary": summary},
            }
        )
        return 0
    except CancelledError:
        sys.stdout = _protocol_stdout
        emit({"type": "cancelled", "level": "warning", "message": "Задача остановлена", "data": {}})
        return 130
    except BaseException as error:
        sys.stdout = _protocol_stdout
        safe_message = (
            context.sanitize_text(f"{type(error).__name__}: {error}")
            if "context" in locals()
            else f"{type(error).__name__}: {error}"
        )
        emit(
            {
                "type": "failed",
                "level": "error",
                "message": safe_message,
                "data": {},
            }
        )
        trace = traceback.format_exc()
        if "context" in locals():
            trace = context.sanitize_text(trace)
        print(trace, file=sys.stderr, end="")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
