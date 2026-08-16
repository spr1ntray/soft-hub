from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import uuid
from dataclasses import dataclass
from typing import Any, Iterable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .database import Database, utc_now

_PRIVATE_KEY_RE = re.compile(r"^(?:0[xX])?[0-9a-fA-F]{64}$")
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_HOST_RE = re.compile(r"^[A-Za-z0-9._:-]+$")
_VERIFIER = b"soft-hub-vault-v1"
_KDF = {"name": "scrypt", "n": 32768, "r": 8, "p": 1, "length": 32}
_MAX_PASSWORD_BYTES = 4096
# Kept as compatibility aliases for older API clients.  Export authorization is
# the freshly verified master password; the old typed phrase added friction but
# no additional identity proof.
PLAINTEXT_EXPORT_ACKNOWLEDGEMENT = "EXPORT PLAINTEXT SECRETS"
EXPORT_ACKNOWLEDGEMENT = PLAINTEXT_EXPORT_ACKNOWLEDGEMENT
_CAPSOLVER_SECRET_NAME = "capsolver_api_key"
_ADSPOWER_API_SECRET_NAME = "adspower_api_key"
_EMAIL_PASSWORD_FLAG_BACKFILL_SETTING = "vault_email_password_flag_backfilled_v1"
_REFERRAL_TOPOLOGY_MIGRATION_SETTING = "vault_referral_topology_only_v1"
_GLOBAL_SECRET_PERMISSIONS = {
    "capsolver_api_key": _CAPSOLVER_SECRET_NAME,
    "adspower_api_key": _ADSPOWER_API_SECRET_NAME,
}
_ACCOUNT_RESOURCE_PERMISSIONS = {
    "private_key": "evm_private_key",
    "proxy": "proxy",
    "email": "email",
    "email_password": "email_password",
    "twitter": "twitter",
    "adspower_profile": "adspower_profile",
}
_SETTING_RESOURCE_PERMISSIONS = {
    "capsolver": "capsolver_api_key",
    "adspower_api": "adspower_api_key",
}


class VaultError(ValueError):
    pass


class ReferralRevisionConflict(VaultError):
    pass


@dataclass(frozen=True, slots=True)
class ImportRecord:
    private_key: str
    proxy: str
    email: str
    email_password: str = ""
    twitter: str | None = None
    label: str = ""
    tags: tuple[str, ...] = ()
    adspower_profile: str | None = None


def _derive_key(password: str, salt: bytes, config: dict[str, Any]) -> bytes:
    if not isinstance(password, str) or len(password.encode("utf-8")) > _MAX_PASSWORD_BYTES:
        raise VaultError("Мастер-пароль превышает допустимый размер")
    if not isinstance(salt, bytes) or len(salt) != 16:
        raise VaultError("Vault не прошёл проверку целостности")
    if (
        not isinstance(config, dict)
        or set(config) != set(_KDF)
        or any(type(config.get(key)) is not type(value) for key, value in _KDF.items())
        or config != _KDF
    ):
        raise VaultError("Vault содержит неподдерживаемые параметры KDF")
    kdf = Scrypt(
        salt=salt,
        length=int(config["length"]),
        n=int(config["n"]),
        r=int(config["r"]),
        p=int(config["p"]),
    )
    return kdf.derive(password.encode("utf-8"))


def _password_error(password: str) -> str | None:
    if not isinstance(password, str) or len(password.encode("utf-8")) > _MAX_PASSWORD_BYTES:
        return "Мастер-пароль превышает допустимый размер"
    if len(password) < 14:
        return "Мастер-пароль должен содержать минимум 14 символов"
    if len(set(password)) < 6:
        return "Мастер-пароль слишком однообразный"
    return None


def normalize_private_key(value: str) -> str:
    clean = value.strip()
    if not _PRIVATE_KEY_RE.fullmatch(clean):
        raise VaultError("Некорректный EVM private key: ожидаются 64 hex-символа")
    return "0x" + clean.removeprefix("0x").removeprefix("0X").lower()


def parse_proxy(value: str) -> tuple[str, str]:
    clean = value.strip()
    if clean.startswith("http://"):
        clean = clean[7:]
    elif clean.startswith("https://"):
        raise VaultError("Поддерживаются только HTTP-прокси")
    if "@" in clean:
        credentials, endpoint = clean.rsplit("@", 1)
        if ":" not in credentials or ":" not in endpoint:
            raise VaultError("Прокси должен иметь формат host:port:user:password")
        user, password = credentials.split(":", 1)
        host, port_text = endpoint.rsplit(":", 1)
    else:
        parts = clean.split(":", 3)
        if len(parts) != 4:
            raise VaultError("Прокси должен иметь формат host:port:user:password")
        host, port_text, user, password = parts
    if not host or not _HOST_RE.fullmatch(host) or not user or not password:
        raise VaultError("Прокси содержит недопустимые или пустые поля")
    try:
        port = int(port_text)
    except ValueError as error:
        raise VaultError("Порт прокси должен быть числом") from error
    if not 1 <= port <= 65535:
        raise VaultError("Порт прокси вне диапазона 1..65535")
    canonical = f"{host.lower()}:{port}:{user}:{password}"
    return canonical, f"{host}:{port}"


def _mask_email(email: str) -> str:
    local, domain = email.split("@", 1)
    visible = local[:1]
    return f"{visible}{'•' * max(3, min(8, len(local) - 1))}@{domain}"


def _normalize_optional_secret(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise VaultError(f"{field} должен быть строкой")
    clean = value.strip()
    if len(clean) > 4096 or any(ord(character) < 32 for character in clean):
        raise VaultError(f"{field} содержит недопустимые данные")
    return clean


def _normalize_api_key(value: str | None, field: str) -> str:
    clean = _normalize_optional_secret(value, field)
    if clean is None or len(clean) < 4:
        raise VaultError(f"{field} должен содержать минимум 4 символа")
    return clean


def _normalize_adspower_profile(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise VaultError(f"{field} должен быть строкой")
    if value == "":
        return ""
    if (
        value != value.strip()
        or len(value) > 256
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise VaultError(
            f"{field} должен быть непустой строкой до 256 символов без пробелов по краям и control-символов"
        )
    return value


def _referrer_account_id(payload: dict[str, Any]) -> str:
    referrer_account_id = payload.get("referrer_account_id", "")
    if referrer_account_id is None:
        referrer_account_id = ""
    if not isinstance(referrer_account_id, str) or len(referrer_account_id) > 128:
        raise VaultError("Реферальная запись аккаунта не прошла проверку целостности")
    return referrer_account_id


def _validate_referral_graph(parents: dict[str, str]) -> dict[str, int]:
    for account_id, parent_id in parents.items():
        if not parent_id:
            continue
        if parent_id not in parents:
            raise VaultError(f"Аккаунт {account_id!r}: реферер больше не существует")
        if parent_id == account_id:
            raise VaultError("Аккаунт не может быть собственным реферером")
    # Iterative traversal keeps the documented 10k-account topology limit safe:
    # a valid long chain must not depend on Python's much smaller recursion limit.
    depths: dict[str, int] = {}
    for start in parents:
        if start in depths:
            continue
        path: list[str] = []
        positions: set[str] = set()
        current = start
        while current and current not in depths:
            if current in positions:
                raise VaultError("Реферальная цепь содержит цикл")
            positions.add(current)
            path.append(current)
            current = parents[current]
        current_depth = depths[current] if current else -1
        while path:
            current_depth += 1
            depths[path.pop()] = current_depth
    return depths


def _referral_revision(parents: dict[str, str]) -> str:
    canonical = json.dumps(
        sorted((account_id, parent_id or None) for account_id, parent_id in parents.items()),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _address_from_key(private_key: str) -> str:
    try:
        from eth_account import Account

        return str(Account.from_key(private_key).address)
    except ImportError:
        # The fallback remains stable, but pyproject installs eth-account so production
        # always displays the real public EVM address.
        digest = hashlib.sha256(bytes.fromhex(private_key[2:])).hexdigest()
        return "unresolved:" + digest[:32]
    except Exception as error:
        raise VaultError("EVM private key не принят криптографической библиотекой") from error


class Vault:
    def __init__(self, database: Database):
        self.database = database
        self._key: bytearray | None = None

    @property
    def exists(self) -> bool:
        return self.database.one("SELECT singleton FROM vault_meta WHERE singleton = 1") is not None

    @property
    def unlocked(self) -> bool:
        return self._key is not None

    def create(self, password: str) -> None:
        if self.exists:
            raise VaultError("Vault уже создан")
        error = _password_error(password)
        if error:
            raise VaultError(error)
        salt = os.urandom(16)
        key = _derive_key(password, salt, _KDF)
        nonce = os.urandom(12)
        verifier = AESGCM(key).encrypt(nonce, _VERIFIER, b"vault-meta-v1")
        now = utc_now()
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT INTO vault_meta(singleton, salt, nonce, verifier, kdf_json, created_at, updated_at) "
                "VALUES (1, ?, ?, ?, ?, ?, ?)",
                (salt, nonce, verifier, json.dumps(_KDF), now, now),
            )
        self._key = bytearray(key)

    def unlock(self, password: str) -> None:
        row = self.database.one("SELECT * FROM vault_meta WHERE singleton = 1")
        if not row:
            raise VaultError("Vault ещё не создан")
        try:
            config = json.loads(row["kdf_json"])
            key = _derive_key(password, row["salt"], config)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise VaultError("Vault не прошёл проверку целостности") from error
        try:
            plain = AESGCM(key).decrypt(row["nonce"], row["verifier"], b"vault-meta-v1")
        except InvalidTag as error:
            raise VaultError("Неверный мастер-пароль") from error
        if plain != _VERIFIER:
            raise VaultError("Vault не прошёл проверку целостности")
        self.lock()
        self._backfill_email_password_configured(key)
        self._migrate_referral_topology_only(key)
        self._key = bytearray(key)

    def _backfill_email_password_configured(self, key: bytes) -> None:
        """Repair the 0.5 -> 0.6 metadata flag without rewriting ciphertext.

        Legacy payloads could already contain an email password before the public
        configured flag existed. Keep the scan and every metadata update in one
        write transaction, so an authentication failure cannot leave a partial
        backfill behind. Rows already marked configured are never decrypted here.
        """
        with self.database.transaction() as connection:
            marker = connection.execute(
                "SELECT value_json FROM settings WHERE key=?",
                (_EMAIL_PASSWORD_FLAG_BACKFILL_SETTING,),
            ).fetchone()
            if marker is not None:
                try:
                    completed = json.loads(marker["value_json"])
                except (TypeError, json.JSONDecodeError):
                    completed = False
                if completed is True:
                    return
            rows = connection.execute(
                "SELECT a.id,s.nonce,s.ciphertext FROM accounts a "
                "LEFT JOIN account_secrets s ON s.account_id=a.id "
                "WHERE a.email_password_configured=0 ORDER BY a.id"
            ).fetchall()
            for row in rows:
                if row["nonce"] is None or row["ciphertext"] is None:
                    raise VaultError(
                        "Legacy account metadata не прошла проверку целостности"
                    )
                payload = self._decrypt_account_payload(
                    key, row["id"], row["nonce"], row["ciphertext"]
                )
                email_password = payload.get("email_password", "")
                if email_password is None:
                    email_password = ""
                if not isinstance(email_password, str):
                    raise VaultError(
                        "Legacy account metadata не прошла проверку целостности"
                    )
                connection.execute(
                    "UPDATE accounts SET email_password_configured=? WHERE id=?",
                    (int(bool(email_password)), row["id"]),
                )
            connection.execute(
                "INSERT INTO settings(key,value_json,updated_at) VALUES (?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,"
                "updated_at=excluded.updated_at",
                (
                    _EMAIL_PASSWORD_FLAG_BACKFILL_SETTING,
                    json.dumps(True),
                    utc_now(),
                ),
            )

    def _migrate_referral_topology_only(self, key: bytes) -> None:
        """Remove every legacy referral code after a successful unlock.

        The migration is deliberately all-or-nothing: Hub keeps only the
        encrypted child -> parent topology. Project-specific software obtains
        current codes from the project at runtime and never stores them here.
        """
        with self.database.transaction() as connection:
            marker = connection.execute(
                "SELECT value_json FROM settings WHERE key=?",
                (_REFERRAL_TOPOLOGY_MIGRATION_SETTING,),
            ).fetchone()
            if marker is not None:
                try:
                    if json.loads(marker["value_json"]) is True:
                        return
                except (TypeError, json.JSONDecodeError):
                    pass
            rows = connection.execute(
                "SELECT a.id,s.nonce,s.ciphertext FROM accounts a "
                "LEFT JOIN account_secrets s ON s.account_id=a.id ORDER BY a.id"
            ).fetchall()
            payloads: dict[str, dict[str, Any]] = {}
            parents: dict[str, str] = {}
            for row in rows:
                if row["nonce"] is None or row["ciphertext"] is None:
                    raise VaultError("Реферальная topology не прошла проверку целостности")
                account_id = str(row["id"])
                payload = self._decrypt_account_payload(
                    key, account_id, row["nonce"], row["ciphertext"]
                )
                parent_id = _referrer_account_id(payload)
                # An old external-code relation has no parent and becomes a root.
                payload.pop("referral_code", None)
                payload.pop("external_referrer_code", None)
                payload["referrer_account_id"] = parent_id
                payloads[account_id] = payload
                parents[account_id] = parent_id
            _validate_referral_graph(parents)
            now = utc_now()
            for account_id, payload in payloads.items():
                nonce, ciphertext = self._encrypt_account_payload(key, account_id, payload)
                connection.execute(
                    "UPDATE account_secrets SET nonce=?,ciphertext=?,updated_at=? "
                    "WHERE account_id=?",
                    (nonce, ciphertext, now, account_id),
                )
            connection.execute(
                "INSERT INTO settings(key,value_json,updated_at) VALUES (?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,"
                "updated_at=excluded.updated_at",
                (
                    _REFERRAL_TOPOLOGY_MIGRATION_SETTING,
                    json.dumps(True),
                    now,
                ),
            )

    def verify_password(self, password: str) -> bool:
        """Verify a repeated master password without changing lock state or live key."""
        row = self.database.one("SELECT * FROM vault_meta WHERE singleton = 1")
        if not row:
            raise VaultError("Vault ещё не создан")
        try:
            config = json.loads(row["kdf_json"])
            candidate = bytearray(_derive_key(password, row["salt"], config))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise VaultError("Vault не прошёл проверку целостности") from error
        try:
            try:
                plain = AESGCM(bytes(candidate)).decrypt(
                    row["nonce"], row["verifier"], b"vault-meta-v1"
                )
            except InvalidTag:
                return False
            return plain == _VERIFIER
        finally:
            for index in range(len(candidate)):
                candidate[index] = 0

    def lock(self) -> None:
        if self._key is not None:
            for index in range(len(self._key)):
                self._key[index] = 0
        self._key = None

    def _require_key(self) -> bytes:
        if self._key is None:
            raise VaultError("Vault заблокирован")
        return bytes(self._key)

    def import_records(self, records: Iterable[ImportRecord | dict[str, Any]]) -> dict[str, int]:
        key = self._require_key()
        normalized: list[dict[str, Any]] = []
        seen_keys: set[str] = set()
        seen_proxies: set[str] = set()
        seen_emails: set[str] = set()

        for index, raw in enumerate(records, start=1):
            record = raw if isinstance(raw, ImportRecord) else ImportRecord(**raw)
            private_key = normalize_private_key(record.private_key)
            proxy, proxy_label = parse_proxy(record.proxy)
            email = record.email.strip().lower()
            if not _EMAIL_RE.fullmatch(email):
                raise VaultError(f"Строка {index}: некорректный email")
            email_password = _normalize_optional_secret(
                record.email_password, f"Строка {index}: email_password"
            )
            twitter = _normalize_optional_secret(record.twitter, f"Строка {index}: twitter")
            adspower_profile = _normalize_adspower_profile(
                record.adspower_profile,
                f"Строка {index}: adspower_profile",
            )
            key_fingerprint = hashlib.sha256(bytes.fromhex(private_key[2:])).hexdigest()
            proxy_fingerprint = hashlib.sha256(proxy.encode()).hexdigest()
            email_fingerprint = hashlib.sha256(email.encode()).hexdigest()
            if key_fingerprint in seen_keys:
                raise VaultError(f"Строка {index}: private key повторяется в импорте")
            if proxy_fingerprint in seen_proxies:
                raise VaultError(f"Строка {index}: proxy повторяется в импорте")
            if email_fingerprint in seen_emails:
                raise VaultError(f"Строка {index}: email повторяется в импорте")
            seen_keys.add(key_fingerprint)
            seen_proxies.add(proxy_fingerprint)
            seen_emails.add(email_fingerprint)
            normalized.append(
                {
                    "private_key": private_key,
                    "proxy": proxy,
                    "proxy_label": proxy_label,
                    "email": email,
                    "email_password": email_password or "",
                    "twitter": twitter,
                    "adspower_profile": adspower_profile,
                    "label": record.label.strip() or f"Account {index:02d}",
                    "tags": sorted({str(tag).strip() for tag in record.tags if str(tag).strip()}),
                    "key_fingerprint": key_fingerprint,
                    "proxy_fingerprint": proxy_fingerprint,
                    "email_fingerprint": email_fingerprint,
                    "evm_address": _address_from_key(private_key),
                }
            )

        if not normalized:
            raise VaultError("Нет записей для импорта")

        inserted = 0
        updated = 0
        now = utc_now()
        with self.database.transaction() as connection:
            for item in normalized:
                existing = connection.execute(
                    "SELECT a.id,s.nonce,s.ciphertext FROM accounts a "
                    "LEFT JOIN account_secrets s ON s.account_id=a.id "
                    "WHERE a.key_fingerprint = ?",
                    (item["key_fingerprint"],),
                ).fetchone()
                account_id = existing["id"] if existing else str(uuid.uuid4())
                twitter = item["twitter"]
                adspower_profile = item["adspower_profile"]
                previous: dict[str, Any] | None = None
                if existing:
                    if existing["nonce"] is None or existing["ciphertext"] is None:
                        raise VaultError("У аккаунта отсутствует зашифрованная запись")
                    previous = self._decrypt_account_payload(
                        key,
                        account_id,
                        existing["nonce"],
                        existing["ciphertext"],
                    )
                if existing and twitter is None:
                    assert previous is not None
                    twitter = str(previous.get("twitter") or "")
                elif twitter is None:
                    twitter = ""
                if existing and adspower_profile is None:
                    assert previous is not None
                    adspower_profile = str(previous.get("adspower_profile") or "")
                elif adspower_profile is None:
                    adspower_profile = ""
                if previous is not None:
                    referrer_account_id = _referrer_account_id(previous)
                else:
                    referrer_account_id = ""
                conflict = connection.execute(
                    "SELECT id FROM accounts WHERE (proxy_fingerprint = ? OR email_fingerprint = ?) AND id != ?",
                    (item["proxy_fingerprint"], item["email_fingerprint"], account_id),
                ).fetchone()
                if conflict:
                    raise VaultError("Proxy или email уже привязан к другому кошельку")
                if existing:
                    connection.execute(
                        "UPDATE accounts SET label=?, evm_address=?, proxy_label=?, proxy_fingerprint=?, "
                        "email_label=?, email_fingerprint=?, twitter_configured=?, "
                        "adspower_configured=?, email_password_configured=?, tags_json=?, "
                        "status='ready', updated_at=? WHERE id=?",
                        (
                            item["label"],
                            item["evm_address"],
                            item["proxy_label"],
                            item["proxy_fingerprint"],
                            _mask_email(item["email"]),
                            item["email_fingerprint"],
                            int(bool(twitter)),
                            int(bool(adspower_profile)),
                            int(bool(item["email_password"])),
                            json.dumps(item["tags"], ensure_ascii=False),
                            now,
                            account_id,
                        ),
                    )
                    updated += 1
                else:
                    connection.execute(
                        "INSERT INTO accounts(id,label,evm_address,key_fingerprint,proxy_label,proxy_fingerprint,"
                        "email_label,email_fingerprint,twitter_configured,adspower_configured,"
                        "email_password_configured,tags_json,"
                        "status,created_at,updated_at) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'ready',?,?)",
                        (
                            account_id,
                            item["label"],
                            item["evm_address"],
                            item["key_fingerprint"],
                            item["proxy_label"],
                            item["proxy_fingerprint"],
                            _mask_email(item["email"]),
                            item["email_fingerprint"],
                            int(bool(twitter)),
                            int(bool(adspower_profile)),
                            int(bool(item["email_password"])),
                            json.dumps(item["tags"], ensure_ascii=False),
                            now,
                            now,
                        ),
                    )
                    inserted += 1
                payload = json.dumps(
                    {
                        "evm_private_key": item["private_key"],
                        "proxy": item["proxy"],
                        "email": item["email"],
                        "email_password": item["email_password"],
                        "twitter": twitter,
                        "adspower_profile": adspower_profile,
                        "referrer_account_id": referrer_account_id,
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode()
                nonce = os.urandom(12)
                ciphertext = AESGCM(key).encrypt(
                    nonce, payload, f"account:{account_id}:v1".encode()
                )
                connection.execute(
                    "INSERT INTO account_secrets(account_id,nonce,ciphertext,updated_at) VALUES (?,?,?,?) "
                    "ON CONFLICT(account_id) DO UPDATE SET nonce=excluded.nonce,ciphertext=excluded.ciphertext,"
                    "updated_at=excluded.updated_at",
                    (account_id, nonce, ciphertext, now),
                )
        return {"inserted": inserted, "updated": updated, "total": len(normalized)}

    def list_accounts(self) -> list[dict[str, Any]]:
        # Account labels, public addresses, proxy endpoints, masked e-mails and
        # resource flags are still private user metadata.  They must follow the
        # same lock boundary as ciphertext-backed secrets instead of becoming a
        # password-free catalogue through the renderer API.
        key = self._require_key()
        rows = self.database.all(
            "SELECT a.id,a.label,a.evm_address,a.proxy_label,a.email_label,"
            "a.twitter_configured,a.adspower_configured,a.email_password_configured,"
            "a.tags_json,a.status,a.created_at,a.updated_at,s.nonce,s.ciphertext "
            "FROM accounts a JOIN account_secrets s ON s.account_id=a.id "
            "ORDER BY a.created_at, a.label"
        )
        labels = {str(row["id"]): str(row["label"]) for row in rows}
        parents: dict[str, str] = {}
        for row in rows:
            account_id = str(row["id"])
            payload = self._decrypt_account_payload(
                key, account_id, row.pop("nonce"), row.pop("ciphertext")
            )
            parents[account_id] = _referrer_account_id(payload)
        depths = _validate_referral_graph(parents)
        child_counts: dict[str, int] = {}
        for parent_id in parents.values():
            if parent_id:
                child_counts[parent_id] = child_counts.get(parent_id, 0) + 1
        for row in rows:
            account_id = str(row["id"])
            parent_id = parents[account_id]
            row["tags"] = json.loads(row.pop("tags_json"))
            row["twitter_configured"] = bool(row["twitter_configured"])
            row["adspower_configured"] = bool(row["adspower_configured"])
            row["email_password_configured"] = bool(
                row["email_password_configured"]
            )
            row["referrer_account_id"] = parent_id or None
            row["referrer_label"] = labels.get(parent_id) if parent_id else None
            row["referral_children_count"] = child_counts.get(account_id, 0)
            row["referral_depth"] = depths[account_id]
            row["referral_is_root"] = not bool(parent_id)
        return rows

    @staticmethod
    def referral_topology(accounts: list[dict[str, Any]]) -> dict[str, Any]:
        parents = {
            str(account["id"]): str(account.get("referrer_account_id") or "")
            for account in accounts
        }
        depths = _validate_referral_graph(parents)
        relationships = [
            {
                "child_account_id": account_id,
                "parent_account_id": parent_id or None,
            }
            for account_id, parent_id in parents.items()
        ]
        return {
            "revision": _referral_revision(parents),
            "relationships": relationships,
            "roots": sum(not parent_id for parent_id in parents.values()),
            "links": sum(bool(parent_id) for parent_id in parents.values()),
            "max_depth": max(depths.values(), default=0),
        }

    def update_referral_topology(
        self, expected_revision: Any, relationships: Any
    ) -> dict[str, Any]:
        """Atomically replace the complete encrypted child -> parent forest."""
        key = self._require_key()
        if (
            not isinstance(expected_revision, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_revision)
        ):
            raise VaultError("expected_revision имеет некорректный формат")
        if not isinstance(relationships, list) or len(relationships) > 10_000:
            raise VaultError("relationships должен быть списком до 10000 связей")
        parents: dict[str, str] = {}
        for index, raw in enumerate(relationships, start=1):
            scope = f"relationships[{index}]"
            if not isinstance(raw, dict) or set(raw) != {
                "child_account_id",
                "parent_account_id",
            }:
                raise VaultError(
                    f"{scope} должен содержать только child_account_id и parent_account_id"
                )
            child_id = raw["child_account_id"]
            parent_id = raw["parent_account_id"]
            if not isinstance(child_id, str):
                raise VaultError(f"{scope}.child_account_id должен быть UUID")
            try:
                if str(uuid.UUID(child_id)) != child_id:
                    raise ValueError
            except (ValueError, AttributeError) as error:
                raise VaultError(f"{scope}.child_account_id должен быть canonical UUID") from error
            if child_id in parents:
                raise VaultError("relationships содержит повторяющийся child_account_id")
            if parent_id is None:
                parents[child_id] = ""
            elif isinstance(parent_id, str):
                try:
                    if str(uuid.UUID(parent_id)) != parent_id:
                        raise ValueError
                except (ValueError, AttributeError) as error:
                    raise VaultError(
                        f"{scope}.parent_account_id должен быть canonical UUID или null"
                    ) from error
                parents[child_id] = parent_id
            else:
                raise VaultError(f"{scope}.parent_account_id должен быть UUID или null")

        now = utc_now()
        with self.database.transaction() as connection:
            rows = connection.execute(
                "SELECT a.id,s.nonce,s.ciphertext FROM accounts a "
                "LEFT JOIN account_secrets s ON s.account_id=a.id ORDER BY a.id"
            ).fetchall()
            current_payloads: dict[str, dict[str, Any]] = {}
            current_parents: dict[str, str] = {}
            for row in rows:
                if row["nonce"] is None or row["ciphertext"] is None:
                    raise VaultError("У одного из аккаунтов отсутствует зашифрованная запись")
                account_id = str(row["id"])
                payload = self._decrypt_account_payload(
                    key, account_id, row["nonce"], row["ciphertext"]
                )
                current_payloads[account_id] = payload
                current_parents[account_id] = _referrer_account_id(payload)
            _validate_referral_graph(current_parents)
            if not hmac.compare_digest(
                _referral_revision(current_parents), expected_revision
            ):
                raise ReferralRevisionConflict(
                    "Реферальная сеть изменилась в другом окне; обновите схему"
                )
            if set(parents) != set(current_payloads):
                missing = set(current_payloads) - set(parents)
                unknown = set(parents) - set(current_payloads)
                if missing:
                    raise VaultError("Полная схема должна содержать каждый аккаунт ровно один раз")
                raise VaultError(f"Аккаунт {sorted(unknown)[0]!r} не найден")
            depths = _validate_referral_graph(parents)
            for account_id, payload in current_payloads.items():
                payload.pop("referral_code", None)
                payload.pop("external_referrer_code", None)
                payload["referrer_account_id"] = parents[account_id]
                nonce, ciphertext = self._encrypt_account_payload(key, account_id, payload)
                connection.execute(
                    "UPDATE account_secrets SET nonce=?,ciphertext=?,updated_at=? "
                    "WHERE account_id=?",
                    (nonce, ciphertext, now, account_id),
                )
                connection.execute(
                    "UPDATE accounts SET updated_at=? WHERE id=?", (now, account_id)
                )
        return {
            "revision": _referral_revision(parents),
            "relationships": [
                {
                    "child_account_id": account_id,
                    "parent_account_id": parent_id or None,
                }
                for account_id, parent_id in parents.items()
            ],
            "roots": sum(not parent_id for parent_id in parents.values()),
            "links": sum(bool(parent_id) for parent_id in parents.values()),
            "max_depth": max(depths.values(), default=0),
        }

    @property
    def capsolver_configured(self) -> bool:
        return self.database.one(
            "SELECT 1 AS configured FROM vault_secrets WHERE name=?",
            (_CAPSOLVER_SECRET_NAME,),
        ) is not None

    def capsolver_status(self) -> dict[str, bool]:
        return {"configured": self.capsolver_configured}

    @property
    def adspower_api_configured(self) -> bool:
        return self.database.one(
            "SELECT 1 AS configured FROM vault_secrets WHERE name=?",
            (_ADSPOWER_API_SECRET_NAME,),
        ) is not None

    def adspower_api_status(self) -> dict[str, bool]:
        return {"configured": self.adspower_api_configured}

    def set_capsolver_api_key(self, value: str) -> None:
        key = self._require_key()
        clean = _normalize_api_key(value, "Capsolver API key")
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(
            nonce,
            clean.encode("utf-8"),
            self._vault_secret_aad(_CAPSOLVER_SECRET_NAME),
        )
        self.database.execute(
            "INSERT INTO vault_secrets(name,nonce,ciphertext,updated_at) VALUES (?,?,?,?) "
            "ON CONFLICT(name) DO UPDATE SET nonce=excluded.nonce,"
            "ciphertext=excluded.ciphertext,updated_at=excluded.updated_at",
            (_CAPSOLVER_SECRET_NAME, nonce, ciphertext, utc_now()),
        )

    def clear_capsolver_api_key(self) -> bool:
        self._require_key()
        return bool(
            self.database.execute(
                "DELETE FROM vault_secrets WHERE name=?", (_CAPSOLVER_SECRET_NAME,)
            )
        )

    def set_adspower_api_key(self, value: str) -> None:
        key = self._require_key()
        clean = _normalize_api_key(value, "AdsPower API key")
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(
            nonce,
            clean.encode("utf-8"),
            self._vault_secret_aad(_ADSPOWER_API_SECRET_NAME),
        )
        self.database.execute(
            "INSERT INTO vault_secrets(name,nonce,ciphertext,updated_at) VALUES (?,?,?,?) "
            "ON CONFLICT(name) DO UPDATE SET nonce=excluded.nonce,"
            "ciphertext=excluded.ciphertext,updated_at=excluded.updated_at",
            (_ADSPOWER_API_SECRET_NAME, nonce, ciphertext, utc_now()),
        )

    def clear_adspower_api_key(self) -> bool:
        self._require_key()
        return bool(
            self.database.execute(
                "DELETE FROM vault_secrets WHERE name=?", (_ADSPOWER_API_SECRET_NAME,)
            )
        )

    def export_rows(
        self, password: str, acknowledgement: str | None = None
    ) -> list[dict[str, Any]]:
        key = self._require_key()
        if not self.verify_password(password):
            raise VaultError("Неверный мастер-пароль")
        rows = self.database.all(
            "SELECT a.id,a.label,a.tags_json,s.nonce,s.ciphertext "
            "FROM accounts a JOIN account_secrets s ON s.account_id=a.id "
            "ORDER BY a.created_at,a.label"
        )
        exported: list[dict[str, Any]] = []
        for row in rows:
            secrets = self._decrypt_account_payload(
                key, row["id"], row["nonce"], row["ciphertext"]
            )
            exported.append(
                {
                    "label": row["label"],
                    "private_key": str(secrets.get("evm_private_key") or ""),
                    "proxy": str(secrets.get("proxy") or ""),
                    "email": str(secrets.get("email") or ""),
                    "email_password": str(secrets.get("email_password") or ""),
                    "twitter": str(secrets.get("twitter") or ""),
                    "adspower_profile": str(secrets.get("adspower_profile") or ""),
                    "tags": json.loads(row["tags_json"]),
                }
            )
        return exported

    def delete_account(self, account_id: str) -> bool:
        key = self._require_key()
        # Serialize the lease check with both run admission and the delete itself.
        # Otherwise a concurrent start could acquire a lease between two separate
        # database calls and ON DELETE CASCADE would immediately erase that lease.
        with self.database.transaction() as connection:
            if not connection.execute(
                "SELECT 1 FROM accounts WHERE id=?", (account_id,)
            ).fetchone():
                return False
            if connection.execute(
                "SELECT 1 FROM account_leases WHERE account_id=? LIMIT 1", (account_id,)
            ).fetchone():
                raise VaultError("Нельзя удалить аккаунт, пока он занят write-задачей")
            if connection.execute(
                "SELECT 1 FROM run_account_pins WHERE account_id=? LIMIT 1", (account_id,)
            ).fetchone():
                raise VaultError("Нельзя удалить аккаунт, пока он используется запуском")
            rows = connection.execute(
                "SELECT a.id,s.nonce,s.ciphertext FROM accounts a "
                "JOIN account_secrets s ON s.account_id=a.id WHERE a.id!=?",
                (account_id,),
            ).fetchall()
            expected_children = connection.execute(
                "SELECT COUNT(*) AS count FROM accounts WHERE id!=?", (account_id,)
            ).fetchone()["count"]
            if len(rows) != expected_children:
                raise VaultError("У одного из аккаунтов отсутствует зашифрованная запись")
            now = utc_now()
            for row in rows:
                child_id = str(row["id"])
                payload = self._decrypt_account_payload(
                    key, child_id, row["nonce"], row["ciphertext"]
                )
                parent_id = _referrer_account_id(payload)
                if parent_id != account_id:
                    continue
                payload["referrer_account_id"] = ""
                payload.pop("referral_code", None)
                payload.pop("external_referrer_code", None)
                nonce, ciphertext = self._encrypt_account_payload(
                    key, child_id, payload
                )
                connection.execute(
                    "UPDATE account_secrets SET nonce=?,ciphertext=?,updated_at=? "
                    "WHERE account_id=?",
                    (nonce, ciphertext, now, child_id),
                )
                connection.execute(
                    "UPDATE accounts SET updated_at=? WHERE id=?", (now, child_id)
                )
            return bool(
                connection.execute(
                    "DELETE FROM accounts WHERE id=?", (account_id,)
                ).rowcount
            )

    @staticmethod
    def _runner_permissions(secret_permissions: Iterable[str]) -> set[str]:
        allowed = set(secret_permissions)
        supported = {
            "evm_private_key",
            "proxy",
            "email",
            "email_password",
            "twitter",
            "adspower_profile",
            "capsolver_api_key",
            "adspower_api_key",
        }
        unknown = allowed - supported
        if unknown:
            raise VaultError("Плагин запросил неизвестный тип секрета")
        return allowed

    @staticmethod
    def _runner_resources(
        resources: Iterable[str], supported: dict[str, str], scope: str
    ) -> set[str]:
        if isinstance(resources, (str, bytes)):
            raise VaultError(f"{scope} должен быть списком ресурсов")
        normalized = set(resources)
        if any(not isinstance(resource, str) for resource in normalized):
            raise VaultError(f"{scope} содержит неизвестный ресурс")
        unknown = normalized - set(supported)
        if unknown:
            raise VaultError(f"{scope} содержит неизвестный ресурс: {sorted(unknown)[0]}")
        return normalized

    def _account_payload_snapshot(
        self, key: bytes
    ) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, str]]]:
        rows = self.database.all(
            "SELECT a.id,a.label,a.evm_address,s.nonce,s.ciphertext FROM accounts a "
            "JOIN account_secrets s ON s.account_id=a.id"
        )
        payloads: dict[str, dict[str, Any]] = {}
        public: dict[str, dict[str, str]] = {}
        for row in rows:
            account_id = str(row["id"])
            payload = self._decrypt_account_payload(
                key, account_id, row["nonce"], row["ciphertext"]
            )
            _referrer_account_id(payload)
            payloads[account_id] = payload
            public[account_id] = {
                "id": account_id,
                "label": str(row["label"]),
                "evm_address": str(row["evm_address"]),
            }
        return payloads, public

    def referral_plan(
        self, account_ids: list[str], *, parent_required: bool
    ) -> dict[str, Any]:
        """Capture direct-parent dependencies without exposing any project code."""
        key = self._require_key()
        payloads, public = self._account_payload_snapshot(key)
        parents = {
            account_id: _referrer_account_id(payload)
            for account_id, payload in payloads.items()
        }
        _validate_referral_graph(parents)
        selected = list(dict.fromkeys(account_ids))
        selected_set = set(selected)
        for account_id in selected:
            if account_id not in public:
                raise VaultError(f"Аккаунт {account_id!r}: не найден")
            if parent_required and not parents[account_id]:
                raise VaultError(
                    f"Аккаунт «{public[account_id]['label']}»: не назначен реферер"
                )
        target_depths: dict[str, int] = {}
        for start in selected:
            if start in target_depths:
                continue
            path: list[str] = []
            current = start
            while current in selected_set and current not in target_depths:
                path.append(current)
                current = parents[current]
            current_depth = target_depths.get(current, -1)
            while path:
                current_depth += 1
                target_depths[path.pop()] = current_depth
        links = [
            {
                "child_account_id": account_id,
                "parent_account_id": parents[account_id] or None,
                "depth": target_depths[account_id],
            }
            for account_id in selected
        ]
        parent_ids = list(
            dict.fromkeys(
                parents[account_id]
                for account_id in selected
                if parents[account_id]
            )
        )
        return {
            "mode": "project_runtime",
            "revision": _referral_revision(parents),
            "links": links,
            "parent_ids": parent_ids,
        }

    def validate_runner_access(
        self,
        account_ids: list[str],
        secret_permissions: Iterable[str],
        account_resources: Iterable[str] = (),
        setting_resources: Iterable[str] = (),
    ) -> None:
        """Fail admission before run creation for exact declared resources."""
        allowed = self._runner_permissions(secret_permissions)
        required_accounts = self._runner_resources(
            account_resources, _ACCOUNT_RESOURCE_PERMISSIONS, "action.resources.account"
        )
        required_settings = self._runner_resources(
            setting_resources, _SETTING_RESOURCE_PERMISSIONS, "action.resources.settings"
        )
        required_permissions = {
            _ACCOUNT_RESOURCE_PERMISSIONS[resource] for resource in required_accounts
        } | {
            _SETTING_RESOURCE_PERMISSIONS[resource] for resource in required_settings
        }
        if not required_permissions.issubset(allowed):
            raise VaultError("Обязательный ресурс не разрешён action.permissions.secrets")
        # Even an action with an empty secret grant receives the account label,
        # id and EVM address.  Selecting an account is therefore protected by
        # the Vault lock in its own right, not only when a secret permission is
        # present.
        key = self._require_key() if account_ids or allowed else None
        account_permissions = allowed - set(_GLOBAL_SECRET_PERMISSIONS)
        for account_id in account_ids:
            if account_permissions:
                row = self.database.one(
                    "SELECT a.id,a.label,a.twitter_configured,a.adspower_configured,"
                    "a.email_password_configured "
                    "FROM accounts a "
                    "JOIN account_secrets s ON s.account_id=a.id WHERE a.id=?",
                    (account_id,),
                )
            else:
                row = self.database.one(
                    "SELECT id,label,twitter_configured,adspower_configured,"
                    "email_password_configured "
                    "FROM accounts WHERE id=?",
                    (account_id,),
                )
            if not row:
                raise VaultError(f"Аккаунт {account_id!r}: не найден")
            for resource, configured_column in (
                ("email_password", "email_password_configured"),
                ("twitter", "twitter_configured"),
                ("adspower_profile", "adspower_configured"),
            ):
                if resource in required_accounts and not bool(row[configured_column]):
                    raise VaultError(
                        f"Аккаунт «{row['label']}»: не настроен ресурс {resource}"
                    )
        for resource in required_settings:
            secret_name = _GLOBAL_SECRET_PERMISSIONS[
                _SETTING_RESOURCE_PERMISSIONS[resource]
            ]
            if self.database.one(
                "SELECT 1 AS configured FROM vault_secrets WHERE name=?", (secret_name,)
            ) is None:
                raise VaultError(f"Глобальная настройка: не настроен ресурс {resource}")

    def bundles_for_runner(
        self,
        account_ids: list[str],
        secret_permissions: Iterable[str],
        required_account_resources: Iterable[str] = (),
    ) -> list[dict[str, Any]]:
        allowed = self._runner_permissions(secret_permissions)
        required = self._runner_resources(
            required_account_resources,
            _ACCOUNT_RESOURCE_PERMISSIONS,
            "action.resources.account",
        )
        if not {
            _ACCOUNT_RESOURCE_PERMISSIONS[resource] for resource in required
        }.issubset(allowed):
            raise VaultError("Обязательный ресурс не разрешён action.permissions.secrets")
        key = self._require_key() if account_ids or allowed else None
        account_permissions = allowed - set(_GLOBAL_SECRET_PERMISSIONS)
        capsolver = (
            self._decrypt_vault_secret(key, _CAPSOLVER_SECRET_NAME)
            if key is not None and "capsolver_api_key" in allowed
            else None
        )
        bundles: list[dict[str, Any]] = []
        for account_id in account_ids:
            if not account_permissions:
                row = self.database.one(
                    "SELECT id,label,evm_address FROM accounts WHERE id=?", (account_id,)
                )
            else:
                row = self.database.one(
                    "SELECT a.id,a.label,a.evm_address,s.nonce,s.ciphertext "
                    "FROM accounts a JOIN account_secrets s ON s.account_id=a.id WHERE a.id=?",
                    (account_id,),
                )
            if not row:
                raise VaultError("Один из выбранных аккаунтов не найден")
            bundle: dict[str, Any] = {
                "id": row["id"],
                "label": row["label"],
                "evm_address": row["evm_address"],
            }
            if account_permissions:
                assert key is not None
                try:
                    secrets = self._decrypt_account_payload(
                        key, account_id, row["nonce"], row["ciphertext"]
                    )
                except VaultError as error:
                    if required:
                        names = ", ".join(sorted(required))
                        raise VaultError(
                            f"Аккаунт «{row['label']}»: ресурсы {names} не прошли проверку целостности"
                        ) from error
                    raise
                _referrer_account_id(secrets)
                for permission in account_permissions:
                    if secrets.get(permission):
                        bundle[permission] = secrets[permission]
                for resource in required:
                    permission = _ACCOUNT_RESOURCE_PERMISSIONS[resource]
                    value = secrets.get(permission)
                    if not isinstance(value, str) or not value:
                        raise VaultError(
                            f"Аккаунт «{row['label']}»: не настроен ресурс {resource}"
                        )
            if capsolver:
                bundle["capsolver_api_key"] = capsolver
            bundles.append(bundle)
        return bundles

    def settings_for_runner(
        self,
        secret_permissions: Iterable[str],
        required_settings: Iterable[str] = (),
    ) -> dict[str, str]:
        allowed = self._runner_permissions(secret_permissions)
        required = self._runner_resources(
            required_settings,
            _SETTING_RESOURCE_PERMISSIONS,
            "action.resources.settings",
        )
        if not {
            _SETTING_RESOURCE_PERMISSIONS[resource] for resource in required
        }.issubset(allowed):
            raise VaultError("Обязательный ресурс не разрешён action.permissions.secrets")
        granted = {
            resource: permission
            for resource, permission in _SETTING_RESOURCE_PERMISSIONS.items()
            if permission in allowed
        }
        key = self._require_key() if granted else None
        settings: dict[str, str] = {}
        for resource, permission in granted.items():
            assert key is not None
            try:
                value = self._decrypt_vault_secret(
                    key, _GLOBAL_SECRET_PERMISSIONS[permission]
                )
            except VaultError as error:
                raise VaultError(
                    f"Глобальная настройка: ресурс {resource} не прошёл проверку целостности"
                ) from error
            if value:
                settings[resource] = value
            elif resource in required:
                raise VaultError(f"Глобальная настройка: не настроен ресурс {resource}")
        return settings

    @staticmethod
    def _vault_secret_aad(name: str) -> bytes:
        return f"vault-secret:{name}:v1".encode()

    @staticmethod
    def _encrypt_account_payload(
        key: bytes, account_id: str, payload: dict[str, Any]
    ) -> tuple[bytes, bytes]:
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(
            nonce,
            json.dumps(
                payload, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8"),
            f"account:{account_id}:v1".encode(),
        )
        return nonce, ciphertext

    @staticmethod
    def _decrypt_account_payload(
        key: bytes, account_id: str, nonce: bytes, ciphertext: bytes
    ) -> dict[str, Any]:
        try:
            payload = AESGCM(key).decrypt(
                nonce, ciphertext, f"account:{account_id}:v1".encode()
            )
            decoded = json.loads(payload)
        except (InvalidTag, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise VaultError("Запись аккаунта не прошла проверку целостности") from error
        if not isinstance(decoded, dict):
            raise VaultError("Запись аккаунта не прошла проверку целостности")
        return decoded

    def _decrypt_vault_secret(self, key: bytes, name: str) -> str | None:
        row = self.database.one(
            "SELECT nonce,ciphertext FROM vault_secrets WHERE name=?", (name,)
        )
        if not row:
            return None
        try:
            value = AESGCM(key).decrypt(
                row["nonce"], row["ciphertext"], self._vault_secret_aad(name)
            )
            return value.decode("utf-8")
        except (InvalidTag, UnicodeDecodeError) as error:
            raise VaultError("Глобальный секрет Vault не прошёл проверку целостности") from error
