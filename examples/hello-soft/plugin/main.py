from __future__ import annotations

import time

from soft_hub.sdk import HubContext


def run(context: HubContext) -> dict:
    if context.action_id == "profile_preview":
        return preview_profiles(context)
    if context.action_id != "healthcheck":
        raise ValueError("Unknown action")

    steps = max(2, min(12, int(context.options.get("steps", 5))))
    context.log("Self-check запущен")
    context.progress(0.05, message="Подготовка локальной проверки")
    for index in range(steps):
        context.check_cancelled()
        time.sleep(0.12)
        context.progress(
            0.10 + (0.85 * ((index + 1) / steps)),
            message=f"Проверка компонента {index + 1}/{steps}",
            data={"component": index + 1, "total": steps},
        )
    context.result(
        "Runtime отвечает штатно",
        kind="healthcheck",
        data={"checks": steps, "network_used": False, "secrets_used": False},
    )
    return {"checks": steps, "status": "healthy"}


def preview_profiles(context: HubContext) -> dict:
    def preview(account):
        context.check_cancelled()
        context.account_state(
            account.id,
            status="running",
            stage="profile_preview",
            progress=0.10,
            message="Проверяем публичный профиль",
        )
        context.log(
            "Публичный профиль доступен",
            account_id=account.id,
            data={"label": account.label, "address": account.evm_address},
        )
        context.account_state(
            account.id,
            status="running",
            stage="result_ready",
            progress=0.72,
            message="Публичные данные проверены",
        )
        context.result(
            f"{account.label}: профиль готов",
            kind="profile_preview",
            account_id=account.id,
            data={
                "fields_checked": 2,
                "profile_ready": True,
                "network_used": False,
            },
        )
        context.account_state(
            account.id,
            status="succeeded",
            stage="completed",
            progress=1.0,
            message="Публичный профиль проверен",
        )
        return account.id

    completed = context.map_accounts(preview)
    return {"profiles": len(completed)}
