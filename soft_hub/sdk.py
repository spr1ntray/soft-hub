from __future__ import annotations

import json
import math
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Callable, Iterator, Mapping


ACCOUNT_STATE_STATUSES = frozenset(
    {
        "running",
        "succeeded",
        "partial",
        "failed",
        "skipped",
        "blocked",
        "needs_attention",
        "cancelled",
    }
)
_ACCOUNT_STAGE_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


class HubAccount(Mapping[str, Any]):
    """Secret-bearing account view with an intentionally redacted repr."""

    def __init__(self, values: dict[str, Any]):
        self._values = values

    def __getitem__(self, key: str) -> Any:
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __repr__(self) -> str:
        return (
            f"HubAccount(id={self._values.get('id')!r}, "
            f"label={self._values.get('label')!r}, secrets=<redacted>)"
        )

    @property
    def id(self) -> str:
        return str(self._values["id"])

    @property
    def label(self) -> str:
        return str(self._values["label"])

    @property
    def evm_address(self) -> str:
        return str(self._values.get("evm_address", ""))

    @property
    def referrer_account_id(self) -> str | None:
        """Return the Hub account that invited this account, never a referral code."""
        value = self._values.get("referrer_account_id")
        return str(value) if isinstance(value, str) and value else None

    @property
    def referral_depth(self) -> int:
        """Topological depth captured by the host when the run was admitted."""
        value = self._values.get("referral_depth", 0)
        return int(value) if isinstance(value, int) and not isinstance(value, bool) else 0

    def secret(self, kind: str) -> str:
        value = self._values.get(kind)
        if not isinstance(value, str) or not value:
            raise KeyError(f"Секрет {kind!r} не был выдан этому плагину")
        return value


class HubSettings(Mapping[str, str]):
    """Exact-grant global settings view with an intentionally redacted repr."""

    def __init__(self, values: dict[str, Any]):
        self._values = {
            str(key): str(value)
            for key, value in values.items()
            if isinstance(key, str) and isinstance(value, str) and value
        }

    def __getitem__(self, key: str) -> str:
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __repr__(self) -> str:
        return "HubSettings(secrets=<redacted>)"

    def secret(self, kind: str) -> str:
        value = self._values.get(kind)
        if not value:
            raise KeyError(f"Настройка {kind!r} не была выдана этому плагину")
        return value


class HubReferrals:
    """Exact direct-parent view for selected targets in one immutable run."""

    def __init__(self, raw: dict[str, Any] | None = None):
        payload = raw if isinstance(raw, dict) else {}
        parents = payload.get("parents", [])
        links = payload.get("links", [])
        self.mode = str(payload.get("mode", "none"))
        self.revision = str(payload.get("revision", ""))
        self._parents = {
            str(parent["id"]): HubAccount(dict(parent))
            for parent in parents
            if isinstance(parent, dict) and isinstance(parent.get("id"), str)
        }
        self._links: dict[str, tuple[str | None, int]] = {}
        for link in links:
            if not isinstance(link, dict) or not isinstance(
                link.get("child_account_id"), str
            ):
                continue
            parent_id = link.get("parent_account_id")
            self._links[str(link["child_account_id"])] = (
                str(parent_id) if isinstance(parent_id, str) and parent_id else None,
                max(0, int(link.get("depth", 0))),
            )

    @property
    def parents(self) -> tuple[HubAccount, ...]:
        return tuple(self._parents.values())

    @property
    def links(self) -> tuple[dict[str, Any], ...]:
        return tuple(
            {
                "child_account_id": child_id,
                "parent_account_id": parent_id,
                "depth": depth,
            }
            for child_id, (parent_id, depth) in self._links.items()
        )

    def parent_for(self, child_account_id: str) -> HubAccount | None:
        if child_account_id not in self._links:
            raise KeyError("Аккаунт не входит в referral plan этого запуска")
        parent_id = self._links[child_account_id][0]
        if parent_id is None:
            return None
        parent = self._parents.get(parent_id)
        if parent is None:
            raise KeyError("Direct parent отсутствует в exact referral grant")
        return parent

    def depth_for(self, child_account_id: str) -> int:
        if child_account_id not in self._links:
            return 0
        return self._links[child_account_id][1]

    def __repr__(self) -> str:
        return (
            f"HubReferrals(mode={self.mode!r}, links={len(self._links)}, "
            "parent_secrets=<redacted>)"
        )


@dataclass(slots=True)
class HubContext:
    run_id: str
    plugin_id: str
    plugin_version: str
    action_id: str
    options: dict[str, Any]
    accounts: tuple[HubAccount, ...]
    plugin_root: str
    scratch_dir: str
    _emit_raw: Callable[[dict[str, Any]], None]
    _cancelled: threading.Event
    settings: HubSettings = field(default_factory=lambda: HubSettings({}))
    account_concurrency: int = 1
    referral_mode: str = "none"
    referrals: HubReferrals = field(default_factory=HubReferrals)
    _protected_secrets: list[str] = field(default_factory=list, init=False, repr=False)
    _protected_lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def check_cancelled(self) -> None:
        if self.cancelled:
            raise CancelledError("Run отменён пользователем")

    @property
    def referral_levels(self) -> tuple[tuple[HubAccount, ...], ...]:
        """Selected accounts grouped parent-first for project-resolved referrals.

        Hub passes only topology. A plugin obtains its own project-specific code
        while processing a parent and may use it for children in the next level.
        Codes must never be sent back to Hub events, results, logs, or summaries.
        """
        if not self.accounts:
            return ()
        levels: dict[int, list[HubAccount]] = {}
        for account in self.accounts:
            levels.setdefault(self.referrals.depth_for(account.id), []).append(account)
        return tuple(tuple(levels[depth]) for depth in sorted(levels))

    def protect_secret(self, value: str) -> str:
        """Register a runtime-issued project secret before it can reach Hub output."""
        if not isinstance(value, str) or not 4 <= len(value) <= 4096:
            raise ValueError("Runtime secret должен быть строкой длиной 4..4096 символов")
        registered = False
        with self._protected_lock:
            if value not in self._protected_secrets:
                self._protected_secrets.append(value)
                self._protected_secrets.sort(key=len, reverse=True)
                registered = True
        # This control frame is consumed in-memory by the host and is never
        # persisted as a run event. Register before any plugin log/result/print.
        if registered:
            self._emit_raw(
                {
                    "type": "protect_secret",
                    "level": "debug",
                    "message": "",
                    "data": {"value": value},
                    "timestamp": _now(),
                }
            )
        return value

    def sanitize_text(self, value: Any) -> str:
        clean = str(value)
        with self._protected_lock:
            secrets = tuple(self._protected_secrets)
        for secret in secrets:
            clean = clean.replace(secret, "[REDACTED_RUNTIME_SECRET]")
        return clean

    def _sanitize_value(self, value: Any, depth: int = 0) -> Any:
        if depth > 8:
            return "[TRUNCATED]"
        if isinstance(value, str):
            return self.sanitize_text(value)
        if isinstance(value, dict):
            return {
                self.sanitize_text(key): self._sanitize_value(item, depth + 1)
                for key, item in list(value.items())[:200]
            }
        if isinstance(value, (list, tuple)):
            return [self._sanitize_value(item, depth + 1) for item in value[:500]]
        return value

    def sanitize_value(self, value: Any) -> Any:
        """Remove runtime-protected values from a structured plugin payload."""
        return self._sanitize_value(value)

    def map_accounts(
        self,
        worker: Callable[[HubAccount], Any],
        *,
        accounts: tuple[HubAccount, ...] | list[HubAccount] | None = None,
    ) -> tuple[Any, ...]:
        """Run one bounded worker per account and preserve input ordering.

        Expected per-account failures should be handled inside ``worker`` so one
        bad profile does not cancel unrelated profiles. Unhandled exceptions are
        re-raised after already-running workers have returned; queued work is
        cancelled where possible. Every worker must use finite network timeouts
        and call ``check_cancelled`` between external side effects.
        """
        selected = tuple(self.accounts if accounts is None else accounts)
        if not selected:
            return ()
        self.check_cancelled()
        workers = max(1, min(int(self.account_concurrency), len(selected)))
        if workers == 1:
            return tuple(worker(account) for account in selected)

        results: list[Any] = [None] * len(selected)
        first_error: BaseException | None = None
        with ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix=f"hub-account-{self.run_id[:8]}",
        ) as executor:
            futures = {
                executor.submit(worker, account): index
                for index, account in enumerate(selected)
            }
            for future in as_completed(futures):
                index = futures[future]
                try:
                    results[index] = future.result()
                except BaseException as error:  # preserve plugin exception type
                    if first_error is None:
                        first_error = error
                        for pending in futures:
                            if pending is not future:
                                pending.cancel()
        if first_error is not None:
            raise first_error
        self.check_cancelled()
        return tuple(results)

    def emit(
        self,
        event_type: str,
        *,
        level: str = "info",
        message: str = "",
        account_id: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        self._emit_raw(
            {
                "type": event_type,
                "level": level,
                "message": self.sanitize_text(message),
                "account_id": account_id,
                "data": self._sanitize_value(data or {}),
                "timestamp": _now(),
            }
        )

    def log(
        self,
        message: str,
        *,
        level: str = "info",
        account_id: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        self.emit("log", level=level, message=message, account_id=account_id, data=data)

    def progress(
        self,
        value: float,
        *,
        message: str = "",
        account_id: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or not 0 <= float(value) <= 1
        ):
            raise ValueError("progress должен быть конечным числом от 0 до 1")
        payload = {**(data or {}), "value": float(value)}
        self.emit("progress", message=message, account_id=account_id, data=payload)

    def result(
        self,
        title: str,
        *,
        kind: str = "summary",
        status: str = "succeeded",
        account_id: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        self.emit(
            "result",
            message=title,
            account_id=account_id,
            data={"kind": kind, "status": status, "payload": data or {}},
        )

    def account_state(
        self,
        account_id: str,
        *,
        status: str,
        stage: str,
        progress: float | None = None,
        message: str = "",
        data: dict[str, Any] | None = None,
    ) -> None:
        """Publish the authoritative lifecycle state for one selected account.

        Account terminal state must be reported through this event. Ordinary
        logs/results remain useful evidence, but the Hub never guesses a
        terminal account status from their wording or ordering.
        """
        if not isinstance(account_id, str) or not account_id:
            raise ValueError("account_id должен быть непустой строкой")
        if status not in ACCOUNT_STATE_STATUSES:
            raise ValueError(f"Неизвестный account status: {status!r}")
        if not isinstance(stage, str) or not _ACCOUNT_STAGE_RE.fullmatch(stage):
            raise ValueError(
                "stage должен быть коротким machine-readable идентификатором"
            )
        payload: dict[str, Any] = {
            "status": status,
            "stage": stage,
            "payload": dict(data or {}),
        }
        if progress is not None:
            if (
                isinstance(progress, bool)
                or not isinstance(progress, (int, float))
                or not math.isfinite(float(progress))
                or not 0 <= float(progress) <= 1
            ):
                raise ValueError("progress должен быть конечным числом от 0 до 1")
            payload["progress"] = float(progress)
        self.emit(
            "account_state",
            message=message,
            account_id=account_id,
            data=payload,
        )


class CancelledError(RuntimeError):
    pass


def decode_context(payload: str, emit: Callable[[dict[str, Any]], None], cancelled: threading.Event) -> HubContext:
    raw = json.loads(payload)
    raw_concurrency = raw.get("account_concurrency", 1)
    if (
        not isinstance(raw_concurrency, int)
        or isinstance(raw_concurrency, bool)
        or not 1 <= raw_concurrency <= 20
    ):
        raise ValueError("account_concurrency должен быть integer 1..20")
    return HubContext(
        run_id=str(raw["run_id"]),
        plugin_id=str(raw["plugin_id"]),
        plugin_version=str(raw["plugin_version"]),
        action_id=str(raw["action_id"]),
        options=dict(raw.get("options", {})),
        accounts=tuple(HubAccount(dict(account)) for account in raw.get("accounts", [])),
        plugin_root=str(raw["plugin_root"]),
        scratch_dir=str(raw["scratch_dir"]),
        _emit_raw=emit,
        _cancelled=cancelled,
        settings=HubSettings(dict(raw.get("settings", {}))),
        account_concurrency=raw_concurrency,
        referral_mode=str(raw.get("referral_mode", "none")),
        referrals=HubReferrals(dict(raw.get("referrals", {}))),
    )
