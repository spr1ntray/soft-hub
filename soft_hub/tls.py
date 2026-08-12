from __future__ import annotations

import socket
import ssl
from pathlib import Path
from typing import Any

import certifi


def ca_bundle_path() -> Path:
    """Return the CA bundle shipped with the managed runtime.

    Python still loads the native trust store first.  The bundled Mozilla roots
    make public GitHub TLS independent from an incomplete or stale Windows root
    store without removing locally managed enterprise roots.
    """

    candidate = Path(certifi.where()).resolve()
    if not candidate.is_file():
        raise RuntimeError("Встроенный набор TLS-сертификатов отсутствует или повреждён")
    return candidate


def public_https_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.load_verify_locations(cafile=str(ca_bundle_path()))
    return context


def github_connection_error(error: BaseException) -> str:
    """Map connection failures to useful messages without leaking internals."""

    reason: Any = getattr(error, "reason", error)
    if isinstance(reason, ssl.SSLCertVerificationError) or (
        isinstance(reason, ssl.SSLError) and "certificate" in str(reason).casefold()
    ):
        return (
            "Не удалось проверить TLS-сертификат GitHub. "
            "Проверьте дату и время на компьютере и обновите Hub"
        )
    if isinstance(reason, (socket.timeout, TimeoutError)):
        return "GitHub не ответил вовремя. Проверьте интернет, VPN или firewall"
    if isinstance(reason, socket.gaierror):
        return "Компьютер не смог найти GitHub в сети. Проверьте интернет, DNS или VPN"
    lowered = str(reason).casefold()
    if "407" in lowered and "proxy" in lowered:
        return "Прокси-сервер просит авторизацию. Проверьте настройки сети"
    return "GitHub недоступен из этой сети. Проверьте интернет, VPN или firewall"
