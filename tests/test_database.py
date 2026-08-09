from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from soft_hub import database as database_module
from soft_hub.config import HubPaths
from soft_hub.database import Database


class DatabaseMigrationTests(unittest.TestCase):
    def test_failed_migration_rolls_back_schema_and_version_then_retries(self) -> None:
        with tempfile.TemporaryDirectory(prefix="soft-hub-migration-test-") as temporary:
            root = Path(temporary)
            paths = HubPaths.create(root / "data")
            migrations = root / "migrations"
            migrations.mkdir()
            migration = migrations / "001_atomic.sql"
            migration.write_text(
                "CREATE TABLE migration_probe(value TEXT NOT NULL);\n"
                "INSERT INTO migration_probe(value) VALUES ('partial');\n"
                "THIS IS NOT VALID SQL;\n",
                encoding="utf-8",
            )

            with mock.patch.object(database_module, "MIGRATIONS_DIR", migrations):
                with self.assertRaises(sqlite3.OperationalError):
                    Database(paths)

                connection = sqlite3.connect(paths.database)
                try:
                    table = connection.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='migration_probe'"
                    ).fetchone()
                    versions = connection.execute(
                        "SELECT version FROM schema_migrations"
                    ).fetchall()
                finally:
                    connection.close()
                self.assertIsNone(table)
                self.assertEqual(versions, [])

                migration.write_text(
                    "CREATE TABLE migration_probe(value TEXT NOT NULL);\n"
                    "INSERT INTO migration_probe(value) VALUES ('complete');\n",
                    encoding="utf-8",
                )
                database = Database(paths)
                self.assertEqual(
                    database.one("SELECT value FROM migration_probe"),
                    {"value": "complete"},
                )
                self.assertEqual(
                    database.all("SELECT version FROM schema_migrations"),
                    [{"version": 1}],
                )

    def test_result_statistics_migration_snapshots_public_address_and_adds_indexes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="soft-hub-result-statistics-") as temporary:
            paths = HubPaths.create(Path(temporary) / "data")
            connection = sqlite3.connect(paths.database)
            try:
                for migration in sorted(
                    database_module.MIGRATIONS_DIR.glob("[0-9][0-9][0-9]_*.sql")
                ):
                    version = int(migration.name.split("_", 1)[0])
                    if version >= 11:
                        break
                    connection.executescript(migration.read_text(encoding="utf-8"))
                    connection.execute(
                        "INSERT INTO schema_migrations(version,applied_at) VALUES (?,?)",
                        (version, "2026-08-09T00:00:00+00:00"),
                    )
                now = "2026-08-09T00:00:00+00:00"
                connection.execute(
                    "INSERT INTO accounts(id,label,evm_address,key_fingerprint,proxy_label,"
                    "proxy_fingerprint,email_label,email_fingerprint,tags_json,status,"
                    "created_at,updated_at) VALUES "
                    "('account-1','Historical Account','0x1234','key-fingerprint','proxy',"
                    "'proxy-fingerprint','mail','email-fingerprint','[]','ready',?,?)",
                    (now, now),
                )
                connection.execute(
                    "INSERT INTO modules(id,name,version,description,active_path,manifest_json,"
                    "enabled,trust_status,health,installed_at,updated_at) VALUES "
                    "('migration.report','Migration Report','1.0.0','','/tmp/report','{}',1,"
                    "'local_unsigned','ready',?,?)",
                    (now, now),
                )
                connection.execute(
                    "INSERT INTO runs(id,module_id,module_version,action_id,status,progress,"
                    "account_count,requested_at) VALUES "
                    "('run-1','migration.report','1.0.0','run','succeeded',1,1,?)",
                    (now,),
                )
                connection.execute(
                    "INSERT INTO run_account_states(run_id,account_id,account_label,status,"
                    "stage,progress,last_message,updated_at) VALUES "
                    "('run-1','account-1','Historical Account','succeeded','completed',1,'',?)",
                    (now,),
                )
                connection.commit()
            finally:
                connection.close()

            database = Database(paths)
            self.assertEqual(
                database.one(
                    "SELECT output_schema_json FROM runs WHERE id='run-1'"
                ),
                {"output_schema_json": "{}"},
            )
            self.assertEqual(
                database.one(
                    "SELECT account_address FROM run_account_states "
                    "WHERE run_id='run-1' AND account_id='account-1'"
                ),
                {"account_address": "0x1234"},
            )
            self.assertEqual(
                database.one(
                    "SELECT COUNT(*) AS count FROM schema_migrations WHERE version=11"
                ),
                {"count": 1},
            )
            self.assertIn(
                "output_schema_json",
                {row["name"] for row in database.all("PRAGMA table_info(runs)")},
            )
            self.assertIn(
                "account_address",
                {
                    row["name"]
                    for row in database.all("PRAGMA table_info(run_account_states)")
                },
            )
            result_indexes = {
                row["name"] for row in database.all("PRAGMA index_list(results)")
            }
            self.assertTrue(
                {
                    "idx_results_run_kind_account",
                    "idx_results_module_created_id",
                }.issubset(result_indexes)
            )
            run_indexes = {
                row["name"] for row in database.all("PRAGMA index_list(runs)")
            }
            self.assertIn("idx_runs_module_action_requested", run_indexes)

    def test_legacy_account_summary_projection_is_allowlisted_and_unambiguous(self) -> None:
        with tempfile.TemporaryDirectory(prefix="soft-hub-legacy-projection-") as temporary:
            paths = HubPaths.create(Path(temporary) / "data")
            connection = sqlite3.connect(paths.database)
            try:
                for migration in sorted(
                    database_module.MIGRATIONS_DIR.glob("[0-9][0-9][0-9]_*.sql")
                ):
                    version = int(migration.name.split("_", 1)[0])
                    if version >= 7:
                        break
                    connection.executescript(migration.read_text(encoding="utf-8"))
                    connection.execute(
                        "INSERT INTO schema_migrations(version,applied_at) VALUES (?,?)",
                        (version, "2026-08-08T00:00:00+00:00"),
                    )

                connection.executemany(
                    "INSERT INTO modules(id,name,version,description,active_path,"
                    "manifest_json,enabled,trust_status,health,installed_at,updated_at) "
                    "VALUES (?,?,?,'',?,'{}',1,'local_unsigned','ready',?,?)",
                    (
                        (
                            "io.sprintray.sekai-testnet",
                            "Sekai Testnet",
                            "1.0.0",
                            "/tmp/sekai",
                            "2026-08-08T00:00:00+00:00",
                            "2026-08-08T00:00:00+00:00",
                        ),
                        (
                            "third.party.summary",
                            "Third Party",
                            "1.0.0",
                            "/tmp/third-party",
                            "2026-08-08T00:00:00+00:00",
                            "2026-08-08T00:00:00+00:00",
                        ),
                    ),
                )
                runs = (
                    ("allowed-unique", "io.sprintray.sekai-testnet", "run_cycle"),
                    ("third-party", "third.party.summary", "run"),
                    ("allowed-duplicate", "io.sprintray.sekai-testnet", "run_cycle"),
                    ("allowed-historical", "io.sprintray.sekai-testnet", "run_cycle"),
                )
                connection.executemany(
                    "INSERT INTO runs(id,module_id,module_version,action_id,status,progress,"
                    "account_count,requested_at,started_at,finished_at) "
                    "VALUES (?,?,? ,?,'succeeded',1,1,?,?,?)",
                    (
                        (
                            run_id,
                            module_id,
                            "1.0.0",
                            action_id,
                            "2026-08-08T00:00:00+00:00",
                            "2026-08-08T00:00:01+00:00",
                            "2026-08-08T00:00:02+00:00",
                        )
                        for run_id, module_id, action_id in runs
                    ),
                )
                connection.executemany(
                    "INSERT INTO run_account_states(run_id,account_id,account_label,status,"
                    "stage,progress,last_message,updated_at) VALUES (?,?,?,'unknown',?,0,'',?)",
                    (
                        (
                            run_id,
                            f"{run_id}-account",
                            f"{run_id} account",
                            "historical" if run_id == "allowed-historical" else "unreported",
                            "2026-08-08T00:00:02+00:00",
                        )
                        for run_id, _, _ in runs
                    ),
                )
                results = [
                    ("result-allowed", "allowed-unique", "io.sprintray.sekai-testnet"),
                    ("result-third", "third-party", "third.party.summary"),
                    ("result-duplicate-a", "allowed-duplicate", "io.sprintray.sekai-testnet"),
                    ("result-duplicate-b", "allowed-duplicate", "io.sprintray.sekai-testnet"),
                    ("result-historical", "allowed-historical", "io.sprintray.sekai-testnet"),
                ]
                connection.executemany(
                    "INSERT INTO results(id,run_id,module_id,account_id,kind,status,title,"
                    "data_json,created_at) VALUES (?,?,?,?,"
                    "'account_summary','succeeded','Done','{}',?)",
                    (
                        (
                            result_id,
                            run_id,
                            module_id,
                            f"{run_id}-account",
                            "2026-08-08T00:00:01+00:00",
                        )
                        for result_id, run_id, module_id in results
                    ),
                )
                connection.commit()
            finally:
                connection.close()

            database = Database(paths)
            states = {
                row["run_id"]: row
                for row in database.all(
                    "SELECT run_id,status,stage,progress FROM run_account_states"
                )
            }

            self.assertEqual(
                states["allowed-unique"],
                {
                    "run_id": "allowed-unique",
                    "status": "succeeded",
                    "stage": "completed",
                    "progress": 1.0,
                },
            )
            self.assertEqual(states["third-party"]["status"], "unknown")
            self.assertEqual(states["third-party"]["stage"], "unreported")
            self.assertEqual(states["allowed-duplicate"]["status"], "unknown")
            self.assertEqual(states["allowed-duplicate"]["stage"], "unreported")
            self.assertEqual(states["allowed-historical"]["status"], "unknown")
            self.assertEqual(states["allowed-historical"]["stage"], "historical")
            self.assertEqual(
                database.one(
                    "SELECT COUNT(*) AS count FROM schema_migrations WHERE version=7"
                ),
                {"count": 1},
            )


if __name__ == "__main__":
    unittest.main()
