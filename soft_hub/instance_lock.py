from __future__ import annotations

import os
from pathlib import Path
from typing import BinaryIO


class InstanceLockError(RuntimeError):
    pass


class DataDirectoryLock:
    """Cross-process exclusive lock held for the lifetime of one Hub application."""

    def __init__(self, data_dir: Path):
        self.path = data_dir / ".soft-hub.lock"
        self._handle: BinaryIO | None = None
        self._acquire()

    def _acquire(self) -> None:
        handle = self.path.open("a+b")
        try:
            os.set_inheritable(handle.fileno(), False)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
            if os.name == "nt":
                import msvcrt

                handle.seek(0, os.SEEK_END)
                if handle.tell() == 0:
                    handle.write(b"\0")
                    handle.flush()
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError) as error:
            handle.close()
            raise InstanceLockError(
                "Этот data directory уже открыт другим процессом Soft Hub"
            ) from error
        self._handle = handle

    def release(self) -> None:
        handle = self._handle
        if handle is None:
            return
        self._handle = None
        try:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()

    def __enter__(self) -> "DataDirectoryLock":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.release()
