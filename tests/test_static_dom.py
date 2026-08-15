from __future__ import annotations

import re
import subprocess
import unittest
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse


PROJECT_ROOT = Path(__file__).resolve().parents[1]
STATIC_ROOT = PROJECT_ROOT / "soft_hub" / "static"


def _relative_luminance(color: str) -> float:
    channels = [int(color[index : index + 2], 16) / 255 for index in (1, 3, 5)]
    linear = [
        channel / 12.92
        if channel <= 0.04045
        else ((channel + 0.055) / 1.055) ** 2.4
        for channel in channels
    ]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast(first: str, second: str) -> float:
    first_luminance = _relative_luminance(first)
    second_luminance = _relative_luminance(second)
    light = max(first_luminance, second_luminance)
    dark = min(first_luminance, second_luminance)
    return (light + 0.05) / (dark + 0.05)


class DOMInventory(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elements: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.elements.append((tag, dict(attrs)))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    @property
    def ids(self) -> list[str]:
        return [attrs["id"] for _, attrs in self.elements if attrs.get("id")]

    def find(self, tag: str | None = None, **attributes: str) -> list[dict[str, str | None]]:
        return [
            attrs
            for element_tag, attrs in self.elements
            if (tag is None or element_tag == tag)
            and all(attrs.get(key) == value for key, value in attributes.items())
        ]


class StaticDOMTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.html_path = STATIC_ROOT / "index.html"
        cls.js_path = STATIC_ROOT / "app.js"
        cls.css_path = STATIC_ROOT / "style.css"
        cls.html = cls.html_path.read_text(encoding="utf-8")
        cls.javascript = cls.js_path.read_text(encoding="utf-8")
        cls.css = cls.css_path.read_text(encoding="utf-8")
        cls.dom = DOMInventory()
        cls.dom.feed(cls.html)
        cls.id_set = set(cls.dom.ids)

    def test_ids_are_unique_and_accessibility_references_resolve(self) -> None:
        duplicates = sorted(identifier for identifier, count in Counter(self.dom.ids).items() if count > 1)
        self.assertEqual(duplicates, [])

        references: list[tuple[str, str]] = []
        for _, attrs in self.dom.elements:
            for attribute in ("for", "aria-labelledby", "aria-describedby", "aria-controls"):
                if attrs.get(attribute):
                    references.extend((attribute, target) for target in str(attrs[attribute]).split())
        unresolved = sorted({f"{attribute}={target}" for attribute, target in references if target not in self.id_set})
        self.assertEqual(unresolved, [])

        fragment_targets: list[str] = []
        for _, attrs in self.dom.elements:
            href = attrs.get("href")
            if href and href.startswith("#") and len(href) > 1:
                fragment_targets.append(href[1:])
        self.assertEqual(
            sorted(target for target in fragment_targets if target not in self.id_set),
            [],
        )

    def test_navigation_page_metadata_and_view_sections_stay_in_sync(self) -> None:
        nav_views = {
            str(attrs["data-view"])
            for attrs in self.dom.find("button")
            if attrs.get("data-view")
        }
        trigger_views = {
            str(attrs["data-view-trigger"])
            for _, attrs in self.dom.elements
            if attrs.get("data-view-trigger")
        }
        section_views = {
            identifier.removeprefix("view-")
            for identifier in self.id_set
            if identifier.startswith("view-")
        }
        page_meta_match = re.search(r"const pageMeta\s*=\s*\{(.*?)\n\};", self.javascript, re.DOTALL)
        self.assertIsNotNone(page_meta_match)
        page_meta_views = set(re.findall(r"^\s*([a-z][a-z0-9_-]*):\s*\[", page_meta_match.group(1), re.MULTILINE))
        self.assertEqual(nav_views, section_views)
        self.assertEqual(page_meta_views, section_views)
        self.assertLessEqual(trigger_views, section_views)

        visible_views = self.dom.find("section", **{"class": "view is-visible"})
        active_navigation = self.dom.find("button", **{"class": "nav-item is-active"})
        self.assertEqual(len(visible_views), 1)
        self.assertEqual(len(active_navigation), 1)
        self.assertEqual(
            visible_views[0]["id"],
            "view-" + str(active_navigation[0]["data-view"]),
        )
        self.assertEqual(active_navigation[0].get("aria-current"), "page")
        self.assertIn("item.toggleAttribute('aria-current', active)", self.javascript)

    def test_every_static_id_used_by_javascript_exists(self) -> None:
        referenced_ids = set(
            re.findall(r"\$\$?\(\s*['\"]#([A-Za-z][A-Za-z0-9_-]*)", self.javascript)
        )
        self.assertGreater(len(referenced_ids), 40, "Selector extraction should cover the UI surface")
        self.assertEqual(sorted(referenced_ids - self.id_set), [])

        html_nav_counts = {
            str(attrs["data-nav-count"])
            for _, attrs in self.dom.elements
            if attrs.get("data-nav-count")
        }
        js_nav_counts = set(re.findall(r'data-nav-count="([a-z]+)"', self.javascript))
        self.assertEqual(js_nav_counts, html_nav_counts)

    def test_csp_compatible_markup_has_only_local_external_assets(self) -> None:
        inline_scripts = [attrs for attrs in self.dom.find("script") if not attrs.get("src")]
        self.assertEqual(inline_scripts, [])
        self.assertNotIn("<style", self.html.lower())

        forbidden_attributes: list[str] = []
        for tag, attrs in self.dom.elements:
            for name in attrs:
                if name == "style" or name.lower().startswith("on"):
                    forbidden_attributes.append(f"{tag}[{name}]")
        self.assertEqual(forbidden_attributes, [])

        local_assets: list[str] = []
        for tag, attrs in self.dom.elements:
            reference = attrs.get("src") or (
                attrs.get("href") if tag == "link" else None
            )
            if not reference:
                continue
            parsed = urlparse(reference)
            self.assertEqual(parsed.scheme, "", reference)
            self.assertEqual(parsed.netloc, "", reference)
            self.assertNotIn("..", Path(parsed.path).parts)
            local_assets.append(parsed.path.lstrip("/"))
        self.assertEqual(set(local_assets), {"app.js", "style.css", "brand-icon.png"})
        for asset in local_assets:
            self.assertTrue((STATIC_ROOT / asset).is_file())

        self.assertNotRegex(self.css, r"(?i)@import\s|url\(\s*['\"]?https?://")
        self.assertNotRegex(self.javascript, r"\beval\s*\(|\bnew\s+Function\s*\(|document\.write\s*\(")
        self.assertNotRegex(
            self.javascript,
            r"\.style(?:\.|\[)|setAttribute\(\s*['\"]style['\"]",
            "Strict style-src blocks JavaScript-created inline style attributes",
        )

    def test_dialogs_controls_and_sensitive_inputs_keep_required_invariants(self) -> None:
        dialogs = self.dom.find(role="dialog")
        self.assertEqual(
            {dialog.get("id") for dialog in dialogs},
            {
                "vault-modal",
                "import-modal",
                "export-modal",
                "quick-run-modal",
                "batch-run-modal",
                "destructive-modal",
                "referral-modal",
                "run-modal",
            },
        )
        for dialog in dialogs:
            self.assertEqual(dialog.get("aria-modal"), "true")
            self.assertIn("hidden", dialog)
            self.assertIn(str(dialog.get("aria-labelledby")), self.id_set)

        run_drawers = self.dom.find("aside", id="run-drawer")
        self.assertEqual(len(run_drawers), 1)
        self.assertIn("hidden", run_drawers[0])
        self.assertIsNone(run_drawers[0].get("role"))
        self.assertIsNone(run_drawers[0].get("aria-modal"))
        self.assertIn(str(run_drawers[0].get("aria-labelledby")), self.id_set)

        buttons_without_type = [attrs.get("id") or attrs.get("class") or "<button>" for attrs in self.dom.find("button") if not attrs.get("type")]
        self.assertEqual(buttons_without_type, [])

        by_id: dict[str, dict[str, str | None]] = {
            str(attrs["id"]): attrs
            for _, attrs in self.dom.elements
            if attrs.get("id")
        }
        self.assertEqual(by_id["vault-password"].get("type"), "password")
        self.assertEqual(by_id["vault-password"].get("minlength"), "14")
        self.assertEqual(by_id["vault-confirm"].get("type"), "password")
        self.assertEqual(by_id["import-keys"].get("autocomplete"), "off")
        self.assertEqual(by_id["import-proxies"].get("autocomplete"), "off")
        self.assertEqual(by_id["import-emails"].get("autocomplete"), "off")
        self.assertEqual(by_id["import-twitters"].get("autocomplete"), "off")
        self.assertEqual(by_id["import-table"].get("autocomplete"), "off")
        self.assertEqual(by_id["export-password"].get("type"), "password")
        self.assertEqual(by_id["export-password"].get("minlength"), "14")
        self.assertEqual(len(self.dom.find("select", id="export-format")), 1)
        export_formats = {
            str(option["value"])
            for option in self.dom.find("option")
            if option.get("value") in {"xlsx", "csv"}
        }
        self.assertEqual(export_formats, {"xlsx", "csv"})
        xlsx_options = self.dom.find("option", value="xlsx")
        self.assertEqual(len(xlsx_options), 1)
        self.assertIn("selected", xlsx_options[0])
        self.assertIn('formatInput.value === \'csv\'', self.javascript)
        self.assertIn("XLSX для Excel — советуем", self.html)
        self.assertIn("CSV без защиты — только для импорта", self.html)
        self.assertEqual(by_id["capsolver-key"].get("type"), "password")
        self.assertEqual(by_id["capsolver-key"].get("autocomplete"), "off")
        self.assertEqual(
            by_id["plugin-file-input"].get("accept"),
            ".softhub.zip,.softhub,.zip",
        )
        self.assertIn("Выберите ZIP-пакет Soft Hub", self.javascript)
        self.assertEqual(by_id["toast-region"].get("aria-live"), "polite")

        scripts = self.dom.find("script")
        self.assertEqual(len(scripts), 1)
        self.assertEqual(scripts[0].get("src"), "app.js")
        self.assertIn("defer", scripts[0])
        html_nodes = self.dom.find("html")
        self.assertEqual(html_nodes[0].get("lang"), "ru")

    def test_startup_requires_password_before_the_workspace_is_revealed(self) -> None:
        body = self.dom.find("body")
        self.assertEqual(len(body), 1)
        self.assertIn("vault-entry-required", str(body[0].get("class", "")).split())

        loader = self.dom.find("div", id="vault-entry-loader")
        self.assertEqual(len(loader), 1)
        self.assertEqual(loader[0].get("role"), "status")
        self.assertEqual(loader[0].get("aria-live"), "polite")

        vault_modal = self.dom.find("section", id="vault-modal")
        self.assertEqual(len(vault_modal), 1)
        self.assertEqual(vault_modal[0].get("aria-describedby"), "vault-modal-description")
        self.assertEqual(vault_modal[0].get("data-startup-required"), "false")
        self.assertEqual(len(self.dom.find("button", id="vault-modal-close")), 1)

        self.assertIn("startupVaultGate: true", self.javascript)
        self.assertIn("function setStartupVaultGate(required)", self.javascript)
        self.assertIn("if (state.startupVaultGate && !$('#vault-modal').hidden)", self.javascript)
        self.assertIn("openVaultModal({ startupRequired: true });", self.javascript)
        self.assertIn("setStartupVaultGate(false);", self.javascript)
        self.assertNotIn("window.setTimeout(openVaultModal, 500)", self.javascript)

        self.assertIn("body.vault-entry-required .shell", self.css)
        self.assertIn("body.vault-entry-required .quick-dock", self.css)
        self.assertIn('#vault-modal[data-startup-required="true"] > .modal-close', self.css)
        self.assertIn("visibility: hidden", self.css)

    def test_product_ui_exposes_the_requested_install_and_visual_controls(self) -> None:
        by_id: dict[str, dict[str, str | None]] = {
            str(attrs["id"]): attrs
            for _, attrs in self.dom.elements
            if attrs.get("id")
        }
        self.assertEqual(by_id["github-install-form"].get("class"), "github-install-form")
        self.assertEqual(by_id["github-url"].get("type"), "url")
        self.assertEqual(by_id["theme-button"].get("class"), "theme-switch")
        self.assertEqual(by_id["theme-button"].get("role"), "switch")
        self.assertEqual(by_id["theme-button"].get("aria-checked"), "false")
        self.assertNotIn("theme-curtain", self.id_set)
        self.assertNotIn("theme-curtain", self.css)
        self.assertNotIn("themeTimers", self.javascript)
        self.assertTrue(self.dom.find("nav", **{"class": "quick-dock"}))
        quick_actions = {
            str(attrs["data-quick-action"])
            for attrs in self.dom.find("button")
            if attrs.get("data-quick-action")
        }
        self.assertEqual(quick_actions, {"batch", "live", "attention"})
        self.assertFalse(
            [attrs for _, attrs in self.dom.elements if attrs.get("data-dock-view")],
            "Dock must expose actions instead of duplicating sidebar navigation",
        )
        self.assertEqual(by_id["patch-feed-form"].get("class"), "patch-feed-form")
        self.assertEqual(by_id["patch-feed-status"].get("role"), "status")
        self.assertEqual(len(self.dom.find("svg", **{"class": "patch-radar-orbit"})), 1)
        self.assertEqual(len(self.dom.find("g", **{"class": "patch-radar-sweep"})), 1)
        self.assertEqual(len(self.dom.find("circle", **{"class": "patch-radar-blip"})), 5)
        self.assertEqual(by_id["accounts-file-input"].get("type"), "file")
        self.assertEqual(by_id["accounts-file-button"].get("type"), "button")
        self.assertIsNone(by_id["drop-zone"].get("role"))
        self.assertIsNone(by_id["drop-zone"].get("tabindex"))
        self.assertIn("by sprintray with love", self.html)
        for hook in ("specular-button", "border-glow", "animated-list", "blur-text"):
            self.assertIn(hook, self.html)
            self.assertIn(f".{hook}", self.css)

    def test_update_badges_and_catalog_searches_keep_their_alignment_contract(self) -> None:
        by_catalog = {
            str(attrs["data-catalog-search"]): attrs
            for attrs in self.dom.find("input")
            if attrs.get("data-catalog-search")
        }
        self.assertEqual(set(by_catalog), {"nft", "testnet"})
        for section, attrs in by_catalog.items():
            self.assertEqual(attrs.get("type"), "search")
            self.assertEqual(attrs.get("autocomplete"), "off")
            self.assertEqual(attrs.get("spellcheck"), "false")
            self.assertEqual(attrs.get("name"), f"{section}-software-search")
            self.assertTrue(str(attrs.get("placeholder", "")).endswith("…"))

        state_rule = re.search(
            r"\.setting-update-state\s*\{(?P<body>.*?)\n\}",
            self.css,
            re.DOTALL,
        )
        search_rule = re.search(
            r"\.catalog-search\s*\{(?P<body>.*?)\n\}",
            self.css,
            re.DOTALL,
        )
        nav_badge_rule = re.search(
            r"\.nav-item > i:not\(:empty\)\s*\{(?P<body>.*?)\n\}",
            self.css,
            re.DOTALL,
        )
        self.assertIsNotNone(state_rule)
        self.assertIsNotNone(search_rule)
        self.assertIsNotNone(nav_badge_rule)
        for declaration in (
            "display: inline-flex",
            "align-items: center",
            "justify-content: center",
            "justify-self: end",
            "line-height: 1",
        ):
            self.assertIn(declaration, state_rule.group("body"))
        for declaration in (
            "min-height: 44px",
            "grid-template-columns: 18px minmax(0, 1fr)",
            "align-items: center",
            "max-width: 310px",
        ):
            self.assertIn(declaration, search_rule.group("body"))
        for declaration in (
            "display: inline-flex",
            "min-height: 20px",
            "align-items: center",
            "line-height: 1",
        ):
            self.assertIn(declaration, nav_badge_rule.group("body"))
        self.assertIn(
            '.nav-item[data-view="settings"][data-update-available="true"]::after { display: block; }',
            self.css,
        )
        self.assertIn(".catalog-search:has(input:focus-visible)", self.css)
        self.assertIn(".patch-feed-card-head {", self.css)
        self.assertIn("grid-template-columns: minmax(0, 1fr) auto", self.css)
        discovery_rule = re.search(
            r"\.discovery-state\s*\{(?P<body>.*?)\n\}",
            self.css,
            re.DOTALL,
        )
        self.assertIsNotNone(discovery_rule)
        for declaration in (
            "display: inline-flex",
            "min-height: 24px",
            "align-items: center",
            "line-height: 1",
        ):
            self.assertIn(declaration, discovery_rule.group("body"))

    def test_local_patch_picker_accepts_zip_names_and_leaves_content_validation_to_core(self) -> None:
        helper_source = self.javascript[
            self.javascript.index("function isLocalPluginArchiveName("):
            self.javascript.index("async function installFile(")
        ]
        script = "\n".join(
            (
                helper_source,
                "const accepted = ['patch.softhub.zip', 'PATCH.SOFTHUB.ZIP', 'patch.softhub (1).zip', 'download.zip', 'patch.softhub'];",
                "const rejected = ['patch', 'patch.tar.gz', 'patch.softhub.zip.exe'];",
                "if (accepted.some((name) => !isLocalPluginArchiveName(name))) throw new Error('zip package rejected');",
                "if (rejected.some((name) => isLocalPluginArchiveName(name))) throw new Error('unsupported file accepted');",
            )
        )
        completed = subprocess.run(
            ["node", "--input-type=module", "-e", script],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_patch_radar_rotates_only_the_sweep_and_fades_random_static_blips(self) -> None:
        orbit_rule = re.search(
            r"\.patch-radar-orbit\s*\{(?P<body>.*?)\n\}",
            self.css,
            re.DOTALL,
        )
        sweep_rule = re.search(
            r"\.patch-radar-sweep\s*\{(?P<body>.*?)\n\}",
            self.css,
            re.DOTALL,
        )
        self.assertIsNotNone(orbit_rule)
        self.assertIsNotNone(sweep_rule)
        self.assertNotIn("animation:", orbit_rule.group("body"))
        self.assertIn("animation: radar-sweep 5.6s linear infinite", sweep_rule.group("body"))
        self.assertIn("@keyframes radar-sweep", self.css)
        self.assertIn("@keyframes radar-blip", self.css)
        self.assertIn(".patch-radar-blip.is-visible", self.css)
        self.assertNotIn("@keyframes radar-orbit", self.css)

        radar_motion = self.javascript[
            self.javascript.index("function stopPatchRadarMotion("):
            self.javascript.index("function updateNavigationState(")
        ]
        for contract in (
            "Math.random() * Math.PI * 2",
            "Math.sqrt(",
            "blip.setAttribute('cx'",
            "blip.setAttribute('cy'",
            "blip.setAttribute('r'",
            "blip.classList.add('is-visible')",
            "document.visibilityState === 'visible'",
            "window.matchMedia('(prefers-reduced-motion: reduce)').matches",
        ):
            self.assertIn(contract, radar_motion)
        self.assertIn(
            "blip.addEventListener('animationend', () => blip.classList.remove('is-visible'))",
            self.javascript,
        )
        self.assertIn(
            "window.matchMedia('(prefers-reduced-motion: reduce)').addEventListener('change', syncPatchRadarMotion)",
            self.javascript,
        )

    def test_patch_radar_only_offers_core_verified_new_or_newer_packages(self) -> None:
        patch_renderer = self.javascript[
            self.javascript.index("function renderPatchFeed("):
            self.javascript.index("async function scanPatchFeed(")
        ]
        self.assertIn("const versionState = patch.version_state || 'unavailable'", patch_renderer)
        self.assertIn("versionState === 'installed'", patch_renderer)
        self.assertIn("versionState === 'update_available'", patch_renderer)
        self.assertIn("versionState === 'newer_installed'", patch_renderer)
        self.assertIn("patch.installable === true", patch_renderer)
        self.assertNotIn("patch.status === 'ready' ? `<button", patch_renderer)
        self.assertIn(
            "state.patchFeed.filter((patch) => patch.installable === true)",
            self.javascript,
        )
        installer = self.javascript[
            self.javascript.index("async function installPatchAsset("):
            self.javascript.index("function renderAll(")
        ]
        self.assertIn("await scanPatchFeed({ silent: true })", installer)

    def test_results_are_grouped_by_software_without_a_fixed_ok_badge(self) -> None:
        renderer = self.javascript[
            self.javascript.index("function groupResultsByModule("):
            self.javascript.index("function renderPatchFeed(")
        ]
        for contract in (
            "const groups = new Map()",
            "groups.get(moduleId).push(result)",
            "<details class=\"result-software-group border-glow\"",
            'data-result-module="${escapeHtml(moduleId)}"',
            "items.map((result)",
            "resultStatusLabel(result.status)",
            "state.resultModuleExpansion.set(group.dataset.resultModule, group.open)",
        ):
            self.assertIn(contract, renderer)
        self.assertNotIn('<span class="result-icon">OK</span>', renderer)
        self.assertNotIn('class="result-card', renderer)
        self.assertIn(".result-software-group {", self.css)
        self.assertIn(".result-group-body {", self.css)
        self.assertIn(".result-entry {", self.css)
        self.assertIn("Все результаты по софтам", self.html)

    def test_parsing_reports_have_a_filterable_wallet_table_and_safe_csv_export(self) -> None:
        by_id = {
            str(attrs["id"]): attrs
            for _, attrs in self.dom.elements
            if attrs.get("id")
        }
        for control_id in (
            "result-report-workbench",
            "result-report-select",
            "result-report-search",
            "result-report-status",
            "result-report-export",
            "result-report-summary",
            "result-report-table-head",
            "result-report-table-body",
        ):
            self.assertIn(control_id, by_id)
        self.assertEqual(by_id["result-report-search"].get("type"), "search")
        self.assertIn("/api/results/overview", self.javascript)
        self.assertIn("/api/results/report?run_id=", self.javascript)
        self.assertIn("function renderSelectedResultReport", self.javascript)
        self.assertIn("function filteredResultReportRows", self.javascript)
        self.assertIn("function exportSelectedResultReport", self.javascript)
        self.assertIn("if (formulaGuard && /^[=+\\-@\\t\\r\\n]/.test(text))", self.javascript)
        self.assertIn("{ formulaGuard: !['integer', 'number', 'decimal_string'].includes(column.type) }", self.javascript)
        self.assertIn("state.selectedResultReport?.truncated === true", self.javascript)
        self.assertIn("Hub не будет скачивать неполный CSV", self.javascript)
        self.assertIn("resultReportsRefreshPending", self.javascript)
        self.assertIn("resultReportDataSignature(nextData)", self.javascript)
        self.assertIn("reportsChanged || !state.resultReportsLoaded", self.javascript)
        self.assertIn("ACTIVE_RUN_STATUSES.has(selectedReport.run_status)", self.javascript)
        self.assertIn("показана сохранённая версия", self.javascript)
        self.assertIn("resetResultReportPresentation()", self.javascript)
        self.assertIn("resultReportOutput(report).columns", self.javascript)
        self.assertIn("slice(0, 12)", self.javascript)
        self.assertIn(".result-report-workbench {", self.css)
        self.assertIn(".result-report-table th {", self.css)
        self.assertIn("position: sticky", self.css)
        self.assertIn("@media (max-width: 1200px)", self.css)

    def test_parsing_report_helpers_preserve_precision_and_formula_safety(self) -> None:
        value_source = self.javascript[
            self.javascript.index("function resultReportValue("):
            self.javascript.index("function resultReportRowMatchesStatus(")
        ]
        csv_source = self.javascript[
            self.javascript.index("function csvSafeCell("):
            self.javascript.index("function exportSelectedResultReport(")
        ]
        aggregate_source = self.javascript[
            self.javascript.index("function resultReportAggregateMetrics("):
            self.javascript.index("function renderSelectedResultReport(")
        ]
        signature_source = self.javascript[
            self.javascript.index("function resultReportDataSignature("):
            self.javascript.index("function resultReportOutput(")
        ]
        script = "\n".join(
            (
                "const RESULT_REPORT_NUMBER_FORMATTER = new Intl.NumberFormat('ru-RU', {maximumSignificantDigits:12});",
                "const RESULT_REPORT_INTEGER_FORMATTER = new Intl.NumberFormat('ru-RU', {maximumFractionDigits:0});",
                value_source,
                csv_source,
                "const state = {selectedResultReport:{aggregates:{points:{aggregate:'sum',value:'18014398509481982',count:2}}}};",
                "function resultReportColumns() { return [{key:'points',title:'Очки',type:'integer',aggregate:'sum'}]; }",
                aggregate_source,
                signature_source,
                "const exact = resultReportValue({type:'integer'}, '18014398509481982').replace(/[^0-9-]/g, '');",
                "if (exact !== '18014398509481982') throw new Error('unsafe integer lost precision');",
                "if (resultReportValue({type:'number'}, 1e-10) === '0') throw new Error('tiny value rounded to zero');",
                "if (resultReportValue({type:'decimal_string'}, '0.000000000000000001') !== '0.000000000000000001') throw new Error('decimal string changed');",
                "if (csvSafeCell('-1.25', {formulaGuard:false}) !== '\"-1.25\"') throw new Error('numeric CSV was rewritten');",
                "if (!csvSafeCell('=WEBSERVICE(1)').includes(\"'=WEBSERVICE(1)\")) throw new Error('formula guard missing');",
                "const multilineFormula = csvSafeCell('\\n=WEBSERVICE(1)');",
                "if (multilineFormula.charCodeAt(1) !== 39 || multilineFormula.charCodeAt(2) !== 10) throw new Error('multiline formula guard missing');",
                "const metric = resultReportAggregateMetrics({columns:[{key:'points',title:'Очки',type:'integer',aggregate:'sum'}]})[0];",
                "if (!metric || metric.value.replace(/[^0-9-]/g, '') !== '18014398509481982' || !metric.note.includes('2 знач.')) throw new Error('aggregate object rendered incorrectly');",
                "const first = resultReportDataSignature({stats:{results:1},runs:[{id:'r',status:'running'}]});",
                "const second = resultReportDataSignature({stats:{results:2},runs:[{id:'r',status:'running'}]});",
                "if (first === second) throw new Error('result mutation did not invalidate report cache');",
            )
        )
        completed = subprocess.run(
            ["node", "--input-type=module", "-e", script],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_svg_icon_sprite_and_theme_switch_contract(self) -> None:
        symbols = {
            str(attrs["id"]): attrs
            for attrs in self.dom.find("symbol")
            if attrs.get("id")
        }
        self.assertGreaterEqual(len(symbols), 20)
        for icon_id in (
            "icon-sun",
            "icon-moon",
            "icon-batch",
            "icon-activity",
            "icon-alert",
            "icon-trash",
            "icon-stop",
            "icon-force",
            "icon-close",
            "icon-search",
        ):
            self.assertIn(icon_id, symbols)
            self.assertEqual(symbols[icon_id].get("viewbox"), "0 0 24 24")

        static_icon_references = {
            str(attrs["href"]).removeprefix("#")
            for attrs in self.dom.find("use")
            if str(attrs.get("href") or "").startswith("#")
        }
        self.assertGreaterEqual(len(static_icon_references), 8)
        self.assertEqual(sorted(static_icon_references - set(symbols)), [])
        self.assertIn('<use href="#icon-sun"></use>', self.html)
        self.assertIn('<use href="#icon-moon"></use>', self.html)
        self.assertEqual(len(self.dom.find("span", **{"class": "theme-switch-thumb"})), 1)
        self.assertNotRegex(self.html, r">\s*(?:SUN|MOON)\s*<")
        self.assertIn("button.setAttribute('aria-checked', String(dark))", self.javascript)
        self.assertNotIn("button.setAttribute('aria-pressed', String(dark))", self.javascript)

        switch_rule = re.search(r"\.theme-switch\s*\{(?P<body>.*?)\n\}", self.css, re.DOTALL)
        track_rule = re.search(r"\.theme-switch-track\s*\{(?P<body>.*?)\n\}", self.css, re.DOTALL)
        thumb_rule = re.search(r"\.theme-switch-thumb\s*\{(?P<body>.*?)\n\}", self.css, re.DOTALL)
        dark_thumb_rule = re.search(
            r':root\[data-theme="dark"\]\s+\.theme-switch-thumb\s*\{(?P<body>.*?)\n\}',
            self.css,
            re.DOTALL,
        )
        self.assertIsNotNone(switch_rule)
        self.assertIsNotNone(track_rule)
        self.assertIsNotNone(thumb_rule)
        self.assertIsNotNone(dark_thumb_rule)
        for declaration in (
            "display: inline-grid",
            "flex: 0 0 70px",
            "width: 70px",
            "height: 40px",
            "place-items: center",
            "padding: 4px",
        ):
            self.assertIn(declaration, switch_rule.group("body"))
        self.assertIn("grid-template-columns: 1fr 1fr", track_rule.group("body"))
        self.assertIn("line-height: 0", track_rule.group("body"))
        self.assertIn("width: 50%", thumb_rule.group("body"))
        self.assertIn("transform: translateX(100%)", dark_thumb_rule.group("body"))
        self.assertNotIn("translateX(32px)", self.css)

    def test_activity_is_a_non_modal_operations_panel_with_semantic_table(self) -> None:
        by_id: dict[str, dict[str, str | None]] = {
            str(attrs["id"]): attrs
            for _, attrs in self.dom.elements
            if attrs.get("id")
        }
        self.assertFalse(self.dom.find("button", **{"data-view": "activity"}))
        self.assertNotIn("view-activity", self.id_set)
        self.assertNotIn("activity: ['RUN JOURNAL'", self.javascript)
        self.assertNotIn("showView('activity')", self.javascript)

        panel = self.dom.find("aside", id="activity-panel")
        self.assertEqual(len(panel), 1)
        self.assertIn("hidden", panel[0])
        self.assertEqual(panel[0].get("tabindex"), "-1")
        self.assertIsNone(panel[0].get("role"))
        self.assertIsNone(panel[0].get("aria-modal"))
        self.assertEqual(panel[0].get("aria-labelledby"), "activity-panel-title")
        self.assertEqual(panel[0].get("aria-describedby"), "activity-panel-summary")

        panel_controls = [
            attrs
            for _, attrs in self.dom.elements
            if attrs.get("aria-controls") == "activity-panel"
        ]
        self.assertGreaterEqual(len(panel_controls), 4)
        self.assertTrue(all(attrs.get("aria-expanded") == "false" for attrs in panel_controls))
        self.assertEqual(by_id["activity-panel-summary"].get("role"), "status")
        self.assertEqual(by_id["activity-panel-summary"].get("aria-live"), "polite")

        self.assertEqual(len(self.dom.find("table", id="activity-table")), 1)
        self.assertEqual(len(self.dom.find("tbody", id="activity-table-body")), 1)
        activity_table_markup = self.html[
            self.html.index('<table id="activity-table"'):
            self.html.index("</table>", self.html.index('<table id="activity-table"'))
        ]
        self.assertEqual(activity_table_markup.count('scope="col"'), 7)
        for label in ("Софт", "Аккаунт", "Текущий этап", "Прогресс", "Состояние", "Давность"):
            self.assertIn(label, self.html)

        filters = {
            str(attrs["data-activity-filter"]): attrs
            for attrs in self.dom.find("button")
            if attrs.get("data-activity-filter")
        }
        self.assertEqual(set(filters), {"active", "attention"})
        self.assertEqual(filters["active"].get("aria-pressed"), "true")
        self.assertEqual(filters["attention"].get("aria-pressed"), "false")
        self.assertIn("hidden", by_id["activity-panel-empty"])
        self.assertIn("hidden", by_id["activity-panel-loading"])
        self.assertEqual(by_id["activity-panel-loading"].get("role"), "status")
        self.assertIn("hidden", by_id["activity-panel-unavailable"])

        for contract in (
            "function activityProjectionMatches(row, filter)",
            "function activityResolutionKind(row, runRows = [row])",
            "function accountFreeActivityRows(filter)",
            "function activityRows(filter = state.activityFilter)",
            "function activityGroups(rows)",
            "function activityTableMarkup(rows)",
            "function loadActivityAccounts(",
            'rowspan="${group.length}"',
            'data-open-run="${escapeHtml(row.run_id)}"',
            'data-activity-control="details:${escapeHtml(activityControlKey)}"',
            'data-request-run-stop="${escapeHtml(row.run_id)}"',
            'data-review-run="${escapeHtml(row.run_id)}"',
            "function renderActivityPanel()",
            "function openActivityPanel(",
            "function toggleActivityPanel(",
            "function closeActivityPanel(",
            "function openRunStopFlow(runId)",
            "ACTIVE_RUN_STATUSES",
            "ATTENTION_RUN_STATUSES",
            "ACTIVE_ACCOUNT_STATUSES",
            "ATTENTION_ACCOUNT_STATUSES",
            "MAX_ACTIVITY_ROWS = 40",
        ):
            self.assertIn(contract, self.javascript)
        self.assertIn("api('/api/run-accounts?scope=active&limit=500')", self.javascript)
        self.assertIn("api('/api/run-accounts?scope=attention&limit=500')", self.javascript)
        self.assertIn("activePayload.truncated === true", self.javascript)
        self.assertIn("attentionPayload.truncated === true", self.javascript)
        self.assertNotIn("data-open-run-row", self.javascript)
        self.assertIn("tableBody.contains(document.activeElement)", self.javascript)
        self.assertIn("exactReplacement || runFallback || $('#activity-panel-close')", self.javascript)
        self.assertIn("function setTextIfChanged(target, value)", self.javascript)
        self.assertIn("setTextIfChanged($('#dock-presence-copy'), presenceCopy)", self.javascript)
        self.assertIn("setTextIfChanged($('#activity-panel-summary'), activitySummary)", self.javascript)
        self.assertIn("const attentionCount = Number(state.data.stats.attention_runs || 0)", self.javascript)
        self.assertIn("stats.attention_runs || ''", self.javascript)
        for field in ("row.account_label", "row.stage", "row.progress", "row.updated_at"):
            self.assertIn(field, self.javascript)
        projection_matcher = self.javascript[
            self.javascript.index("function activityProjectionMatches("):
            self.javascript.index("function accountFreeActivityRows(")
        ]
        self.assertNotIn("last_message", projection_matcher)
        self.assertNotIn("result", projection_matcher)
        self.assertIn("ACTIVE_RUN_STATUSES.has(row.run_status)", projection_matcher)
        self.assertIn("ATTENTION_RUN_STATUSES.has(row.run_status)", projection_matcher)
        self.assertIn("!['historical', 'reconciled'].includes(row.stage)", projection_matcher)
        self.assertIn("await openRunDrawer(runId)", self.javascript)
        stop_entry = self.javascript[
            self.javascript.index("async function openRunStopFlow("):
            self.javascript.index("function renderResults(")
        ]
        self.assertNotIn("/stop", stop_entry)
        self.assertNotIn("/force-stop", stop_entry)
        for stage_id in (
            "preflight", "fill", "partially_completed", "action_failed",
            "external_state_unknown", "preflight_failed", "external_reconciliation",
            "adapter_error", "write_gate", "write_blocked", "account_preflight",
            "reconciliation", "needs_reconciliation", "profile_validation",
            "validated", "registration", "invalid_profile",
        ):
            self.assertRegex(self.javascript, rf"\n\s+{stage_id}: '[^']+'")
        self.assertIn("return raw ? 'Выполняет шаг' : 'Текущий этап';", self.javascript)
        self.assertIn("else if (!$('#activity-panel').hidden) closeActivityPanel()", self.javascript)
        self.assertIn("origin?.isConnected", self.javascript)
        self.assertIn("fullyOpen && state.activityFilter === resolvedFilter", self.javascript)
        self.assertIn("toggleActivityPanel(button.dataset.activityOpen, button)", self.javascript)
        self.assertNotIn("$('[data-quick-action=\"live\"]').disabled", self.javascript)

        activity_renderer = self.javascript[
            self.javascript.index("function activityTableMarkup("):
            self.javascript.index("function loadActivityAccounts(")
        ]
        self.assertIn('aria-controls="run-drawer"', activity_renderer)
        self.assertIn('aria-label="Открыть подробный журнал запуска:', activity_renderer)
        self.assertIn('title="Открыть подробный журнал"', activity_renderer)
        self.assertIn("${iconMarkup('search')}</button>", activity_renderer)
        self.assertNotIn("${iconMarkup('history')}</button>", activity_renderer)
        self.assertIn("«Скрыть» уберёт ошибку из уведомлений", self.html)
        self.assertIn("сохранит журнал и результаты в истории", self.html)
        self.assertIn("function reviewRunAttention(runId, button)", self.javascript)
        self.assertIn("function applyAttentionResolution(resolvedRun)", self.javascript)
        self.assertIn("state.activityAccountsGeneration += 1", self.javascript)
        self.assertIn("target.dataset.reviewRun", self.javascript)
        self.assertNotIn("target.dataset.reconcileRun", self.javascript)
        self.assertNotIn("data-reconcile-run", self.javascript)
        self.assertNotIn("/reconcile", self.javascript)

        self.assertIn(".activity-panel {", self.css)
        self.assertIn(".activity-table {", self.css)
        self.assertIn("overscroll-behavior: contain", self.css)
        self.assertIn("env(safe-area-inset-bottom)", self.css)
        self.assertIn("@keyframes activity-panel-in", self.css)
        self.assertIn("@keyframes activity-loading", self.css)

    def test_mixed_account_attention_can_be_hidden_without_reconciliation(self) -> None:
        resolution_source = self.javascript[
            self.javascript.index("function activityProjectionMatches("):
            self.javascript.index("function accountFreeActivityRows(")
        ]
        script = "\n".join(
            (
                "const ACTIVE_RUN_STATUSES = new Set(['queued','starting','running','cancelling']);",
                "const ATTENTION_RUN_STATUSES = new Set(['failed']);",
                "const ATTENTION_ACCOUNT_STATUSES = new Set(['partial','failed','blocked','needs_attention']);",
                resolution_source,
                "const mixed = [",
                "  {run_status:'failed',status:'failed',stage:'action_failed'},",
                "  {run_status:'failed',status:'needs_attention',stage:'external_state_unknown'},",
                "];",
                "const mixedKinds = mixed.map((row) => activityResolutionKind(row, mixed));",
                "if (mixedKinds.some((kind) => kind !== 'review')) throw new Error(JSON.stringify(mixedKinds));",
                "const known = [{run_status:'succeeded',status:'failed',stage:'action_failed'}];",
                "if (activityResolutionKind(known[0], known) !== 'review') throw new Error('known failure must be reviewable');",
            )
        )
        completed = subprocess.run(
            ["node", "--input-type=module", "-e", script],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        renderer = self.javascript[
            self.javascript.index("function activityTableMarkup("):
            self.javascript.index("function loadActivityAccounts(")
        ]
        self.assertIn(
            "group.filter((candidate) => candidate.run_id === row.run_id)",
            renderer,
        )
        self.assertIn("@media (prefers-reduced-motion: reduce)", self.css)

    def test_activity_and_live_run_layers_are_mutually_exclusive_and_close_on_navigation(self) -> None:
        show_view = self.javascript[
            self.javascript.index("function showView("):
            self.javascript.index("function updateVaultState(")
        ]
        close_activity = "closeActivityPanel({ restoreFocus: false, immediate: true })"
        close_drawer = "closeRunDrawer({ restoreFocus: false, immediate: true })"
        self.assertIn(close_activity, show_view)
        self.assertIn(close_drawer, show_view)
        self.assertLess(show_view.index(close_activity), show_view.index("const commit = () =>"))
        self.assertLess(show_view.index(close_drawer), show_view.index("const commit = () =>"))
        self.assertLess(show_view.index(close_drawer), show_view.index("document.startViewTransition(commit)"))

        open_activity = self.javascript[
            self.javascript.index("function openActivityPanel("):
            self.javascript.index("function closeActivityPanel(")
        ]
        self.assertIn(close_drawer, open_activity)
        self.assertLess(open_activity.index(close_drawer), open_activity.index("panel.hidden = false"))

        open_drawer = self.javascript[
            self.javascript.index("async function openRunDrawer("):
            self.javascript.index("function closeRunDrawer(")
        ]
        self.assertIn(close_activity, open_drawer)
        self.assertLess(open_drawer.index(close_activity), open_drawer.index("drawer.hidden = false"))

        close_drawer_source = self.javascript[
            self.javascript.index("function closeRunDrawer("):
            self.javascript.index("function dismissRunDrawer(")
        ]
        self.assertIn(
            "function closeRunDrawer({ restoreFocus = true, immediate = false } = {})",
            close_drawer_source,
        )
        self.assertIn("window.clearTimeout(state.drawerCloseTimer)", close_drawer_source)
        self.assertIn("state.drawerRequestGeneration += 1", close_drawer_source)
        self.assertIn("if (drawer.hidden || immediate ||", close_drawer_source)
        self.assertLess(
            close_drawer_source.index("state.drawerRequestGeneration += 1"),
            close_drawer_source.index("window.setTimeout(finish, 210)"),
        )

        by_id: dict[str, dict[str, str | None]] = {
            str(attrs["id"]): attrs
            for _, attrs in self.dom.elements
            if attrs.get("id")
        }
        drawer_close = by_id["drawer-close"]
        self.assertIn("drawer-close", str(drawer_close.get("class")))
        self.assertEqual(drawer_close.get("aria-label"), "Закрыть журнал запуска")
        self.assertEqual(drawer_close.get("title"), "Закрыть")
        drawer_markup = self.html[
            self.html.index('<aside id="run-drawer"'):
            self.html.index("</aside>", self.html.index('<aside id="run-drawer"'))
        ]
        self.assertIn('<use href="#icon-close"></use>', drawer_markup)

        drawer_rule = re.search(r"\.drawer\s*\{(?P<body>.*?)\n\}", self.css, re.DOTALL)
        drawer_controls_rule = re.search(
            r"\.drawer button,\s*\n\.drawer-close\s*\{(?P<body>.*?)\n\}",
            self.css,
            re.DOTALL,
        )
        self.assertIsNotNone(drawer_rule)
        self.assertIsNotNone(drawer_controls_rule)
        self.assertIn("-webkit-app-region: no-drag", drawer_rule.group("body"))
        self.assertIn("-webkit-app-region: no-drag", drawer_controls_rule.group("body"))

        busy_source = self.javascript[
            self.javascript.index("function setBusy("):
            self.javascript.index("const focusIdentityAttributes")
        ]
        dismiss_source = self.javascript[
            self.javascript.index("function dismissRunDrawer("):
            self.javascript.index("async function updateDrawer(")
        ]
        self.assertIn("button.closest('.modal')", busy_source)
        self.assertNotIn("button.closest('.modal, .drawer')", busy_source)
        self.assertEqual(dismiss_source.count("closeRunDrawer()"), 1)
        self.assertNotIn("dataset.busy", dismiss_source)
        self.assertNotIn("дождитесь результата", dismiss_source)
        self.assertIn("$('#drawer-close').addEventListener('click', dismissRunDrawer)", self.javascript)
        self.assertIn("async function toggleRunDrawer(runId)", self.javascript)
        self.assertIn("void toggleRunDrawer(target.dataset.openRun)", self.javascript)
        self.assertIn("!runDrawer.contains(event.target)", self.javascript)
        self.assertIn("closeRunDrawer({ restoreFocus: false })", self.javascript)
        self.assertIn("pointer-events: none", re.search(r"\.dock-tooltip\s*\{(?P<body>.*?)\n\}", self.css, re.DOTALL).group("body"))

    def test_activity_and_drawer_toggle_state_machines_execute(self) -> None:
        resolve_source = self.javascript[
            self.javascript.index("function resolveActivityFilter("):
            self.javascript.index("function openActivityPanel(")
        ]
        toggle_activity_source = self.javascript[
            self.javascript.index("function toggleActivityPanel("):
            self.javascript.index("function closeActivityPanel(")
        ]
        toggle_drawer_source = self.javascript[
            self.javascript.index("async function toggleRunDrawer("):
            self.javascript.index("function closeRunDrawer(")
        ]
        script = "\n".join(
            (
                "const panel = {hidden:true,classList:{closing:false,contains(name){return name === 'is-closing' && this.closing;}}};",
                "const drawer = {hidden:true,classList:{closing:false,contains(name){return name === 'is-closing' && this.closing;}}};",
                "const state = {activityFilter:'active',activityAccountsLoaded:false,data:{stats:{attention_runs:0}},selectedRunId:null};",
                "const document = {activeElement:null};",
                "const $ = (selector) => selector === '#activity-panel' ? panel : drawer;",
                "const activityRows = () => [];",
                "let activityOpened = []; let activityClosed = 0; let drawerOpened = []; let drawerClosed = 0;",
                "function openActivityPanel(filter){activityOpened.push(filter);state.activityFilter=filter;panel.hidden=false;panel.classList.closing=false;}",
                "function closeActivityPanel(){activityClosed += 1;panel.hidden=true;}",
                "async function openRunDrawer(runId){drawerOpened.push(runId);state.selectedRunId=runId;drawer.hidden=false;drawer.classList.closing=false;}",
                "function closeRunDrawer(){drawerClosed += 1;state.selectedRunId=null;drawer.hidden=true;}",
                resolve_source,
                toggle_activity_source,
                toggle_drawer_source,
                "toggleActivityPanel('active');",
                "if (activityOpened.join(',') !== 'active' || activityClosed) throw new Error('closed activity must open');",
                "toggleActivityPanel('active');",
                "if (activityClosed !== 1 || !panel.hidden) throw new Error('same activity key must close');",
                "panel.hidden=false;state.activityFilter='active';toggleActivityPanel('attention');",
                "if (activityOpened.at(-1) !== 'attention' || activityClosed !== 1) throw new Error('different activity key must switch');",
                "panel.classList.closing=true;toggleActivityPanel('attention');",
                "if (activityOpened.at(-1) !== 'attention' || panel.classList.closing) throw new Error('closing activity must reopen');",
                "state.selectedRunId='run-a';drawer.hidden=false;await toggleRunDrawer('run-a');",
                "if (drawerClosed !== 1 || !drawer.hidden) throw new Error('same drawer key must close');",
                "await toggleRunDrawer('run-b');",
                "if (drawerOpened.at(-1) !== 'run-b' || state.selectedRunId !== 'run-b') throw new Error('different drawer key must open');",
            )
        )
        completed = subprocess.run(
            ["node", "--input-type=module", "-e", script],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_ambient_background_motion_is_compositor_only_and_respects_reduced_motion(self) -> None:
        ambient_rule = re.search(r"\.ambient-scene\s*\{(?P<body>.*?)\n\}", self.css, re.DOTALL)
        blue_orb_rule = re.search(r"\.ambient-orb--blue\s*\{(?P<body>.*?)\n\}", self.css, re.DOTALL)
        coral_orb_rule = re.search(r"\.ambient-orb--coral\s*\{(?P<body>.*?)\n\}", self.css, re.DOTALL)
        reduced_motion = re.search(
            r"@media \(prefers-reduced-motion: reduce\)\s*\{(?P<body>.*)\n\}",
            self.css,
            re.DOTALL,
        )
        self.assertIsNotNone(ambient_rule)
        self.assertIsNotNone(blue_orb_rule)
        self.assertIsNotNone(coral_orb_rule)
        self.assertIsNotNone(reduced_motion)
        for declaration in ("position: fixed", "pointer-events: none", "overflow: hidden"):
            self.assertIn(declaration, ambient_rule.group("body"))
        self.assertIn("animation: ambient-orb-blue 18s", blue_orb_rule.group("body"))
        self.assertIn("animation: ambient-orb-coral 22s", coral_orb_rule.group("body"))
        for keyframes in (
            "@keyframes ambient-orb-blue",
            "@keyframes ambient-orb-coral",
            "@keyframes ambient-orbit-spin",
            "@keyframes ambient-orbit-spin-reverse",
            "@keyframes ambient-flow-drift",
            "@keyframes ambient-flow-pulse",
        ):
            self.assertIn(keyframes, self.css)
        self.assertEqual(len(self.dom.find("div", **{"class": "ambient-scene"})), 1)
        self.assertEqual(len(self.dom.find("span", **{"class": "ambient-orb ambient-orb--blue"})), 1)
        self.assertEqual(len(self.dom.find("span", **{"class": "ambient-orb ambient-orb--coral"})), 1)
        self.assertEqual(len(self.dom.find("span", **{"class": "ambient-flow"})), 1)
        self.assertIn(".ambient-flow i { animation: none !important; }", reduced_motion.group("body"))

    def test_dock_tooltips_and_run_options_are_designed_as_accessible_workbenches(self) -> None:
        by_id: dict[str, dict[str, str | None]] = {
            str(attrs["id"]): attrs
            for _, attrs in self.dom.elements
            if attrs.get("id")
        }
        for action in ("batch", "live", "attention"):
            buttons = self.dom.find("button", **{"data-quick-action": action})
            self.assertEqual(len(buttons), 1)
            tooltip_id = f"dock-tooltip-{action}"
            self.assertEqual(buttons[0].get("aria-describedby"), tooltip_id)
            self.assertEqual(by_id[tooltip_id].get("role"), "tooltip")
            self.assertEqual(by_id[tooltip_id].get("class"), "dock-tooltip")
        self.assertIn(".dock-tooltip {", self.css)
        self.assertIn("transform-origin: bottom center", self.css)
        self.assertNotIn(".quick-dock > button .hub-icon { width: 20px; height: 20px; transform:", self.css)

        self.assertIn("run-workbench", str(by_id["run-form"].get("class")))
        self.assertEqual(by_id["run-options-block"].get("aria-labelledby"), "run-options-title")
        self.assertEqual(by_id["run-launch-summary"].get("aria-live"), "polite")
        for contract in (
            "function optionUi(field)",
            "function optionEntries(action)",
            "function optionFieldMarkup(key, field, required)",
            "function renderRunOptions(action)",
            "ui.group",
            "firstUi.order",
            "secondUi.order",
            "ui.advanced",
            "ui.enum_labels",
            "option-toggle-control",
            "option-group",
        ):
            self.assertIn(contract, self.javascript)
        for css_hook in (
            ".run-config-section {",
            ".run-config-head {",
            ".option-group {",
            ".option-grid {",
            ".option-toggle {",
            ".run-launch-footer {",
        ):
            self.assertIn(css_hook, self.css)

    def test_batch_selection_preflight_and_parallel_submit_contract(self) -> None:
        by_id: dict[str, dict[str, str | None]] = {
            str(attrs["id"]): attrs
            for _, attrs in self.dom.elements
            if attrs.get("id")
        }
        self.assertEqual(by_id["software-batch-bar"].get("aria-live"), "polite")
        self.assertEqual(by_id["batch-select-ready"].get("type"), "button")
        self.assertEqual(by_id["batch-clear"].get("type"), "button")
        self.assertIn("hidden", by_id["batch-clear"])
        self.assertEqual(by_id["batch-open-button"].get("type"), "button")
        self.assertIn("disabled", by_id["batch-open-button"])

        self.assertEqual(by_id["batch-run-modal"].get("role"), "dialog")
        self.assertEqual(by_id["batch-run-modal"].get("aria-modal"), "true")
        self.assertIn("hidden", by_id["batch-run-modal"])
        self.assertEqual(by_id["batch-run-form"].get("novalidate"), None)
        self.assertEqual(by_id["batch-account-policy"].get("id"), "batch-account-policy")
        self.assertEqual(by_id["batch-risk-checkbox"].get("type"), "checkbox")
        self.assertEqual(by_id["batch-run-error"].get("role"), "alert")
        self.assertEqual(by_id["batch-run-submit"].get("type"), "submit")

        self.assertIn("batchModuleIds: new Set()", self.javascript)
        self.assertIn('data-batch-module="${escapeHtml(module.id)}"', self.javascript)
        self.assertIn("function openBatchRunModal()", self.javascript)
        self.assertIn("function updateBatchPreflight()", self.javascript)
        self.assertIn("function handleBatchRunSubmit(event)", self.javascript)
        self.assertIn("if (action.risk === 'mainnet_write')", self.javascript)
        self.assertIn("window.crypto.randomUUID()", self.javascript)
        self.assertIn("jsonPost('/api/runs/batch'", self.javascript)
        self.assertIn("$('#batch-run-form').addEventListener('submit', handleBatchRunSubmit)", self.javascript)
        self.assertIn("function actionSecretPermissions(module, action)", self.javascript)
        self.assertIn("Object.prototype.hasOwnProperty.call(action, 'permissions')", self.javascript)
        self.assertNotIn("manifest.permissions.secrets.length", self.javascript)
        self.assertIn("external_write: 'Внешняя запись'", self.javascript)
        self.assertIn("if (action?.risk === 'external_write') return 'Изменит данные во внешнем сервисе';", self.javascript)
        self.assertIn("action.risk === 'external_write' ? '<em>Изменит данные во внешнем сервисе</em>' : ''", self.javascript)
        self.assertIn("? ' — Внешняя запись' : ''", self.javascript)

        open_run = self.javascript[
            self.javascript.index("function openRunModal("):
            self.javascript.index("function updateRunAccountSelection(")
        ]
        batch_issue = self.javascript[
            self.javascript.index("function batchActionIssue("):
            self.javascript.index("function batchDefaultOptions(")
        ]
        batch_open = self.javascript[
            self.javascript.index("function openBatchRunModal("):
            self.javascript.index("async function handleBatchRunSubmit(")
        ]
        batch_submit = self.javascript[
            self.javascript.index("async function handleBatchRunSubmit("):
            self.javascript.index("function openQuickRun(")
        ]
        for source in (open_run, batch_issue, batch_open):
            self.assertIn("actionSecretPermissions(", source)
        self.assertNotIn("external_write", batch_issue)
        self.assertIn(
            "if (compositionChanged) state.batchIdempotencyKey = null",
            batch_open,
        )
        catch_body = batch_submit[batch_submit.index("} catch (failure) {"):]
        self.assertNotIn("state.batchIdempotencyKey = null", catch_body)
        self.assertIn("state.batchIdempotencyKey = null", batch_submit[:batch_submit.index("} catch (failure) {")])

    def test_destructive_module_delete_and_force_stop_contract(self) -> None:
        by_id: dict[str, dict[str, str | None]] = {
            str(attrs["id"]): attrs
            for _, attrs in self.dom.elements
            if attrs.get("id")
        }
        self.assertEqual(by_id["destructive-modal"].get("role"), "dialog")
        self.assertEqual(by_id["destructive-modal"].get("aria-modal"), "true")
        self.assertIn("hidden", by_id["destructive-modal"])
        self.assertEqual(by_id["destructive-phrase"].get("autocomplete"), "off")
        self.assertEqual(by_id["destructive-phrase"].get("spellcheck"), "false")
        self.assertEqual(by_id["destructive-error"].get("role"), "alert")
        self.assertEqual(by_id["destructive-cancel"].get("type"), "button")
        self.assertEqual(by_id["destructive-submit"].get("type"), "submit")

        self.assertEqual(by_id["drawer-stop-note"].get("role"), "status")
        self.assertIn("hidden", by_id["drawer-stop-note"])
        self.assertEqual(by_id["drawer-resolution-note"].get("role"), "status")
        self.assertIn("hidden", by_id["drawer-resolution-note"])
        self.assertEqual(by_id["drawer-review"].get("type"), "button")
        self.assertIn("hidden", by_id["drawer-review"])
        self.assertEqual(by_id["drawer-stop"].get("type"), "button")
        self.assertEqual(by_id["drawer-force-stop"].get("type"), "button")
        self.assertIn("button--danger", str(by_id["drawer-force-stop"].get("class")))

        self.assertIn("function requestDestructiveConfirmation(", self.javascript)
        self.assertIn("if (request.phrase && value !== request.phrase)", self.javascript)
        self.assertNotRegex(self.javascript, r"window\.(?:confirm|prompt)\s*\(")
        self.assertIn("function deleteModule(moduleId, button)", self.javascript)
        self.assertIn('data-delete-module="${escapeHtml(module.id)}"', self.javascript)
        self.assertIn("iconMarkup('trash')", self.javascript)
        self.assertIn("method: 'DELETE'", self.javascript)
        self.assertIn("if (target.dataset.deleteModule) deleteModule(", self.javascript)

        self.assertIn("function forceStopSelectedRun()", self.javascript)
        self.assertIn("phrase: 'FORCE STOP'", self.javascript)
        self.assertIn("/force-stop`, { acknowledgement: 'FORCE STOP' }", self.javascript)
        self.assertIn("$('#drawer-force-stop').addEventListener('click', forceStopSelectedRun)", self.javascript)
        self.assertNotIn("phrase: 'RECONCILED'", self.javascript)
        self.assertNotIn("acknowledgement: 'RECONCILED'", self.javascript)
        self.assertIn("function reviewSelectedRunFailure()", self.javascript)
        self.assertIn("/review`, {}", self.javascript)
        self.assertIn("$('#drawer-review').addEventListener('click', reviewSelectedRunFailure)", self.javascript)
        self.assertIn("Hub сразу завершит весь процесс", self.javascript)
        self.assertIn("аккаунты сразу освободятся", self.javascript)

    def test_software_card_has_only_power_and_delete_secondary_controls(self) -> None:
        renderer = self.javascript[
            self.javascript.index("function renderSoftware()"):
            self.javascript.index("function updateBatchControls()")
        ]

        self.assertEqual(renderer.count('class="card-action-tooltip" role="tooltip"'), 2)
        self.assertEqual(renderer.count('aria-describedby="${controlId}-'), 2)
        self.assertIn("Выключить софт", renderer)
        self.assertIn("Включить софт", renderer)
        self.assertIn("Удалим код и окружение, а запуски и результаты оставим", renderer)
        self.assertNotIn("rollback", renderer.casefold())
        self.assertNotIn("can_rollback", self.javascript)
        self.assertNotIn("data-rollback-module", self.javascript)
        self.assertNotIn("function rollbackModule(", self.javascript)
        self.assertNotIn("/rollback", self.javascript)

        self.assertIn(".card-action-control:hover .card-action-tooltip", self.css)
        self.assertIn(".card-action-control:focus-within .card-action-tooltip", self.css)
        self.assertIn('.software-actions[data-tooltips-dismissed="true"] .card-action-tooltip', self.css)
        self.assertIn("softwareActions.dataset.tooltipsDismissed = 'true'", self.javascript)
        self.assertIn("delete softwareActions.dataset.tooltipsDismissed", self.javascript)

    def test_nft_and_testnet_workspaces_are_scoped_views_over_shared_data(self) -> None:
        navigation = {
            str(attrs["data-view"]): attrs
            for attrs in self.dom.find("button")
            if attrs.get("data-view")
        }
        self.assertEqual(navigation["nft"].get("aria-label"), "NFT")
        self.assertEqual(navigation["testnets"].get("aria-label"), "Тестнеты")

        for view, section in (("nft", "nft"), ("testnets", "testnet")):
            workspace = self.dom.find(
                "section",
                id=f"view-{view}",
                **{"data-catalog-workspace": section},
            )
            self.assertEqual(len(workspace), 1)
            self.assertEqual(
                len(self.dom.find("div", **{"data-catalog-software-grid": section})),
                1,
            )
            self.assertEqual(
                len(self.dom.find("div", **{"data-catalog-runs": section})),
                1,
            )
            self.assertEqual(
                len(self.dom.find("div", **{"data-catalog-results": section})),
                1,
            )
            self.assertEqual(
                len(self.dom.find("div", **{"data-catalog-reports": section})),
                1,
            )

        for contract in (
            "manifest.catalog?.sections || manifest.catalog_sections",
            "module?.catalog_sections",
            "record?.catalog_sections",
            "function renderCatalogWorkspace(section)",
            "function beginCatalogBatchSelection(section)",
            "function openCatalogBatch(section)",
            "function setResultCatalogFilter(section = 'all')",
            "state.data.runs || []",
            "state.data.results || []",
            "state.resultReports.filter",
            "data-batch-scope=\"${escapeHtml(scope)}\"",
        ):
            self.assertIn(contract, self.javascript)

        self.assertIn("showCatalogChips: true", self.javascript)
        self.assertIn("kind === 'locked'", self.javascript)
        self.assertIn("data-catalog-open-patches", self.javascript)
        self.assertIn(".catalog-hero {", self.css)
        self.assertIn(".catalog-workspace[data-catalog-workspace=\"testnet\"]", self.css)
        self.assertIn(".catalog-section-chip[data-catalog-section=\"nft\"]", self.css)
        self.assertIn("overflow-x: auto", self.css)
        self.assertIn("NFT: от WL до результата", self.html)
        self.assertIn("Тестнеты: запуск и контроль", self.html)
        for art_class in (
            "catalog-hero-art catalog-hero-art--nft catalog-art--certificate",
            "catalog-hero-art catalog-hero-art--testnet catalog-art--sandbox",
        ):
            art = self.dom.find("svg", **{"class": art_class})
            self.assertEqual(len(art), 1)
            self.assertEqual(art[0].get("aria-hidden"), "true")
            self.assertEqual(art[0].get("focusable"), "false")
        self.assertEqual(len(self.dom.find("div", **{"class": "catalog-route"})), 0)
        for removed_step in (
            "<strong>Заполнить</strong>",
            "<strong>Заминтить</strong>",
            "<strong>Подготовить</strong>",
            "<strong>Проследить</strong>",
        ):
            self.assertNotIn(removed_step, self.html)
        for visual_contract in (
            "catalog-art-token-card",
            "catalog-art-chain",
            "DIGITAL ASSET",
            "catalog-art-sandbox-frame",
            "catalog-art-block--active",
            ">TESTNET<",
        ):
            self.assertIn(visual_contract, self.html)
        hero_css = self.css[self.css.index(".catalog-hero {"):self.css.index(".catalog-hero::before {")]
        self.assertIn("min-height: 0", hero_css)
        self.assertIn("grid-template-columns: minmax(0, 1fr) 190px", hero_css)
        self.assertNotIn("min-height: 350px", self.css)
        self.assertIn("@media (max-width: 1240px)", self.css)
        self.assertNotIn(".catalog-route", self.css)
        self.assertIn("catalog-art--certificate", self.html)
        self.assertIn("catalog-art--sandbox", self.html)
        self.assertNotIn(".catalog-hero-art--nft i", self.css)
        self.assertNotIn("NFT-софты сюда не попадут", self.html)
        self.assertNotIn("ничего из тестнетов", self.html)

    def test_hub_has_no_bundled_software_catalog(self) -> None:
        by_id = {str(attrs["id"]) for _, attrs in self.dom.elements if attrs.get("id")}
        self.assertNotIn("discovery-grid", by_id)
        self.assertNotIn("bundled-count-label", by_id)
        self.assertNotIn("data-install-bundled", self.javascript)
        self.assertNotIn("/api/modules/install/bundled", self.javascript)
        self.assertNotIn("function renderDiscovery(", self.javascript)
        self.assertNotIn("function installBundled(", self.javascript)
        self.assertIn("plugin-file-input", by_id)
        self.assertIn("github-install-form", by_id)
        self.assertIn("patch-feed-grid", by_id)

    def test_run_drawer_prioritizes_account_lifecycle_over_collapsed_technical_log(self) -> None:
        by_id: dict[str, dict[str, str | None]] = {
            str(attrs["id"]): attrs
            for _, attrs in self.dom.elements
            if attrs.get("id")
        }
        details = self.dom.find("details", id="drawer-technical-log")
        self.assertEqual(len(details), 1)
        self.assertNotIn("open", details[0], "Raw technical log must be closed by default")
        self.assertEqual(by_id["drawer-account-table-wrap"].get("tabindex"), "0")
        self.assertEqual(by_id["drawer-account-empty"].get("role"), "status")
        self.assertEqual(by_id["drawer-account-summary"].get("aria-live"), "polite")
        self.assertEqual(by_id["drawer-events"].get("role"), "log")
        self.assertEqual(by_id["drawer-events"].get("aria-live"), "off")
        self.assertIn("hidden", by_id["drawer-events"])

        drawer_markup = self.html[
            self.html.index('<aside id="run-drawer"'):
            self.html.index("</aside>", self.html.index('<aside id="run-drawer"'))
        ]
        self.assertLess(drawer_markup.index('id="drawer-account-table"'), drawer_markup.index('id="drawer-technical-log"'))
        self.assertEqual(drawer_markup.count('scope="col"'), 4)
        for label in ("Аккаунт", "Текущий этап", "Прогресс", "Состояние"):
            self.assertIn(label, drawer_markup)
        self.assertIn('<summary aria-controls="drawer-technical-log-body">', drawer_markup)
        self.assertIn("Технических событий пока нет.", drawer_markup)

        table_renderer = self.javascript[
            self.javascript.index("function drawerAccountTableMarkup("):
            self.javascript.index("function renderDrawerAccounts(")
        ]
        for contract in (
            "activityStageLabel(account.stage)",
            "account.last_message",
            "account.progress",
            "account.status",
            "accountStatusNames[account.status]",
            'scope="row"',
        ):
            self.assertIn(contract, table_renderer)
        self.assertNotIn("events", table_renderer)

        drawer_update = self.javascript[
            self.javascript.index("async function updateDrawer("):
            self.javascript.index("async function stopSelectedRun(")
        ]
        fetch_group = drawer_update[
            drawer_update.index("await Promise.all(["):
            drawer_update.index("if (state.selectedRunId !== runId")
        ]
        self.assertEqual(fetch_group.count("api(`/api/runs/"), 3)
        self.assertIn("/accounts`)", fetch_group)
        self.assertIn("const [run, eventsPayload, accountsPayload]", drawer_update)
        self.assertLess(
            drawer_update.index("if (state.selectedRunId !== runId"),
            drawer_update.index("renderDrawerAccounts(run, accountRows)"),
        )
        self.assertIn(
            "const accountRows = Array.isArray(accountsPayload.accounts) ? accountsPayload.accounts : []",
            drawer_update,
        )
        self.assertIn("const resolutionKind = runResolutionKind(run, accountRows)", drawer_update)
        self.assertIn("Number(run.account_count || 0) === 0", self.javascript)
        self.assertIn("Этот запуск не использует аккаунты", self.javascript)
        self.assertIn("$('#drawer-technical-log').open = false", self.javascript)
        self.assertIn("$('#drawer-technical-log').addEventListener('toggle', syncDrawerLogLiveRegion)", self.javascript)
        self.assertIn('<use href="#icon-search"></use></svg>Общий лог софта', drawer_markup)
        self.assertEqual(by_id["drawer-download-log"].get("type"), "button")
        self.assertEqual(by_id["drawer-download-log"].get("aria-describedby"), "drawer-log-export-note")
        self.assertIn("Весь запуск · UTF-8 · приватники, пароли и другие секреты скрыты", drawer_markup)
        self.assertIn('<use href="#icon-download"></use></svg>Скачать полный лог', drawer_markup)
        self.assertIn("`Весь запуск · ${logAccountCount}", self.javascript)
        self.assertIn("'Весь запуск без аккаунтов · секреты скрыты'", self.javascript)
        self.assertIn("/log`", self.javascript)
        self.assertIn("'X-Soft-Hub-Token': apiToken", self.javascript)
        self.assertIn("URL.revokeObjectURL(url)", self.javascript)
        self.assertIn("if (target.textContent !== value) target.textContent = value", self.javascript)
        self.assertIn("if (state.drawerAccountSignature !== signature)", self.javascript)
        self.assertIn("window.clearTimeout(state.drawerCloseTimer)", self.javascript)
        self.assertIn("if (state.selectedRunId === runId && !drawer.hidden", self.javascript)

        for selector in (
            ".drawer-account-section {",
            ".drawer-account-table-wrap {",
            ".drawer-account-table {",
            ".drawer-technical-log {",
            ".drawer-technical-log summary:focus-visible",
            ".drawer-log-export {",
        ):
            self.assertIn(selector, self.css)
        self.assertIn("overscroll-behavior: contain", self.css)
        self.assertIn("height: 100dvh", self.css)

    def test_background_refresh_does_not_replay_list_entrances(self) -> None:
        self.assertIn("(!state.motionPass && !force)", self.javascript)
        self.assertIn("state.motionPass = false", self.javascript)
        self.assertNotIn('<tr class="animated-item', self.javascript)
        self.assertIn("while (state.refreshPending)", self.javascript)
        self.assertNotIn("if (state.refreshing) return", self.javascript)
        self.assertIn("MAX_DRAWER_EVENT_LINES = 2_000", self.javascript)
        self.assertIn("if (state.drawerUpdating)", self.javascript)
        self.assertIn("if (!file || state.fileInstallBusy) return", self.javascript)

    def test_vault_lock_purges_renderer_projections_and_invalidates_inflight_reads(self) -> None:
        self.assertIn("function purgeProtectedClientState()", self.javascript)
        self.assertIn("state.protectedDataEpoch += 1", self.javascript)
        self.assertIn("purgeProtectedClientState();", self.javascript)
        self.assertIn("protectedDataEpoch !== state.protectedDataEpoch", self.javascript)
        for selector in (
            "#accounts-table",
            "#results-list",
            "#overview-runs",
            "#run-account-list",
            "#activity-table-body",
            "#drawer-account-table-body",
            "#drawer-events",
        ):
            self.assertIn(selector, self.javascript)
        self.assertIn("$('#toast-region').replaceChildren()", self.javascript)
        self.assertIn("$('#accounts-locked').hidden = !locked", self.javascript)

    def test_v06_resources_adspower_and_presentation_contract(self) -> None:
        by_id: dict[str, dict[str, str | None]] = {
            str(attrs["id"]): attrs
            for _, attrs in self.dom.elements
            if attrs.get("id")
        }
        for input_id in ("adspower-key", "import-adspower-profiles"):
            self.assertIn(input_id, by_id)
            self.assertEqual(by_id[input_id].get("autocomplete"), "off")
        self.assertEqual(by_id["adspower-key"].get("type"), "password")
        self.assertIn("private_key · proxy · email · twitter · adspower_profile", self.html)
        self.assertIn("ожидаются ровно 5 колонок", self.javascript)
        self.assertIn("private_key,proxy,email,twitter,adspower_profile", self.javascript)
        self.assertIn("adspower_profiles: lines($('#import-adspower-profiles').value)", self.javascript)
        self.assertIn("account.adspower_configured", self.javascript)
        self.assertIn("vault.adspower_api_configured", self.javascript)
        self.assertIn("/api/settings/adspower", self.javascript)

    def test_adspower_status_badge_keeps_both_states_inside_its_pill(self) -> None:
        status = self.dom.find("span", id="adspower-status")
        self.assertEqual(len(status), 1)
        self.assertIn("capability-status", str(status[0].get("class", "")).split())
        self.assertEqual(status[0].get("role"), "status")
        self.assertEqual(status[0].get("aria-live"), "polite")
        self.assertEqual(status[0].get("data-state"), "loading")
        status_rule = re.search(r"(?m)^\.capability-status\s*\{([^}]*)\}", self.css, re.DOTALL)
        self.assertIsNotNone(status_rule)
        self.assertIn("inline-size: max-content", status_rule.group(1))
        self.assertIn("min-inline-size: 112px", status_rule.group(1))
        self.assertIn("min-block-size: 28px", status_rule.group(1))
        self.assertIn('.capability-status[data-state="ready"]', self.css)
        self.assertIn('.capability-status[data-state="warning"]', self.css)
        self.assertIn('"mark copy status"', self.css)
        self.assertIn('". status"', self.css)
        self.assertNotIn("min-width: min(390px, 38vw)", self.css)
        self.assertNotIn("padding-right: 116px", self.css)

    def test_settings_offer_explicit_accessible_core_update_flow(self) -> None:
        by_id: dict[str, dict[str, str | None]] = {
            str(attrs["id"]): attrs
            for _, attrs in self.dom.elements
            if attrs.get("id")
        }
        for element_id in (
            "core-update-card",
            "settings-app-version",
            "core-update-live",
            "core-update-state",
            "core-update-progress",
            "core-update-progress-bar",
            "core-update-notes",
            "core-update-notes-list",
            "core-update-primary",
            "core-update-secondary",
            "core-update-guide",
            "settings-update-platform",
            "nav-core-update",
        ):
            self.assertIn(element_id, by_id)
        self.assertEqual(by_id["core-update-live"].get("role"), "status")
        self.assertEqual(by_id["core-update-live"].get("aria-live"), "polite")
        self.assertEqual(by_id["core-update-live"].get("aria-atomic"), "true")
        self.assertEqual(by_id["core-update-card"].get("aria-busy"), "false")
        self.assertEqual(by_id["core-update-progress-bar"].get("max"), "100")
        self.assertEqual(by_id["core-update-primary"].get("aria-describedby"), "core-update-copy")
        self.assertIn("Проверить обновления", self.html)
        self.assertIn("Скачивание и установка начнутся только после вашего разрешения", self.html)
        self.assertIn("function renderCoreUpdateGuide()", self.javascript)
        self.assertIn("function initializeCoreUpdater()", self.javascript)
        self.assertIn("const CORE_UPDATE_CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000", self.javascript)
        self.assertIn("function recheckCoreUpdateIfDue()", self.javascript)
        self.assertIn("state.coreUpdateCheckTimer = window.setInterval", self.javascript)
        self.assertIn("Date.now() - checkedAt >= CORE_UPDATE_CHECK_INTERVAL_MS", self.javascript)
        self.assertIn("function announceCoreUpdateIfReady()", self.javascript)
        self.assertIn(
            "if (state.coreUpdate.phase !== 'installing') await refresh();",
            self.javascript,
        )
        self.assertIn("Оно ждёт вас в Настройках", self.javascript)
        self.assertIn('settingsNav.dataset.updateAvailable', self.javascript)
        self.assertIn("window.softHubDesktop", self.javascript)
        self.assertIn("onStateChanged", self.javascript)
        self.assertIn("await requestDestructiveConfirmation", self.javascript)
        self.assertIn("openActivityPanel('active'", self.javascript)
        self.assertIn("state.data.app.platform", self.javascript)
        self.assertIn("перетащите Soft Hub в Applications", self.javascript)
        self.assertIn("Запустите новый EXE поверх текущей установки", self.javascript)
        self.assertIn(".setting-card--update {", self.css)
        self.assertIn(".core-update-progress progress {", self.css)
        self.assertIn('@media (prefers-reduced-motion: reduce)', self.css)

        initializer = self.javascript[
            self.javascript.index("async function initializeCoreUpdater("):
            self.javascript.index("function renderDock(")
        ]
        self.assertIn("await checkCoreUpdate()", initializer)
        self.assertNotIn("updater.download", initializer)
        self.assertNotIn("updater.install", initializer)

        notes_renderer = self.javascript[
            self.javascript.index("function renderCoreUpdateNotes("):
            self.javascript.index("function configureCoreUpdateButton(")
        ]
        self.assertIn("item.textContent = note", notes_renderer)
        self.assertNotIn("innerHTML", notes_renderer)

    def test_core_update_state_normalization_preserves_optimistic_phases(self) -> None:
        state_source = self.javascript[
            self.javascript.index("function normalizeCoreUpdatePhase("):
            self.javascript.index("function applyCoreUpdatePayload(")
        ]
        script = "\n".join(
            (
                state_source,
                "for (const phase of ['checking','downloading','installing']) {",
                "  if (normalizeCoreUpdatePayload({}, phase).phase !== phase) throw new Error('lost fallback '+phase);",
                "}",
                "const current = normalizeCoreUpdatePayload({status:'up_to_date',currentVersion:'v0.6.12'});",
                "if (current.phase !== 'current' || current.currentVersion !== '0.6.12') throw new Error('bad current state');",
                "const ready = normalizeCoreUpdatePayload({phase:'downloaded',availableVersion:'v0.6.13',releaseNotes:'## Новое\\n- Быстрый старт\\n<script>текст</script>'});",
                "if (ready.phase !== 'ready' || ready.availableVersion !== '0.6.13') throw new Error('bad ready state');",
                "if (ready.releaseNotes.length !== 3 || ready.releaseNotes.some((note) => /[<>]/.test(note))) throw new Error('notes are not plain text');",
                "const progress = normalizeCoreUpdatePayload({status:'downloading',percent:42.4,transferred:10,total:20});",
                "if (progress.phase !== 'downloading' || progress.percent !== 42.4 || progress.total !== 20) throw new Error('bad progress');",
                "const failure = normalizeCoreUpdatePayload({status:'error',message:'network request failed'});",
                "if (failure.phase !== 'error' || failure.errorKind !== 'offline') throw new Error('bad error state');",
                "if (failure.message !== 'network request failed') throw new Error('safe updater message was lost');",
                "const sanitized = normalizeCoreUpdatePayload({status:'error',message:'  failed\\nagain\\u202eevil  '});",
                "if (sanitized.message !== 'failed again evil') throw new Error('updater message was not sanitized');",
                "const retry = normalizeCoreUpdatePayload({status:'downloaded',installIssue:'  Vault  не ответил\\nповторите  '});",
                "if (retry.installIssue !== 'Vault не ответил повторите') throw new Error('bad install issue');",
            )
        )
        completed = subprocess.run(
            ["node", "--input-type=module", "-e", script],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_adspower_is_discoverable_and_referrals_use_a_topology_only_editor(self) -> None:
        by_id: dict[str, dict[str, str | None]] = {
            str(attrs["id"]): attrs
            for _, attrs in self.dom.elements
            if attrs.get("id")
        }
        self.assertEqual(by_id["adspower-key"].get("type"), "password")
        self.assertEqual(by_id["adspower-key"].get("autocomplete"), "off")
        self.assertEqual(by_id["adspower-key"].get("minlength"), "4")
        self.assertEqual(by_id["capsolver-key"].get("minlength"), "4")
        self.assertIn("API-ключ один на весь Hub", self.html)
        self.assertIn("data-open-account-connections", self.html)
        self.assertEqual(by_id["referral-modal"].get("aria-modal"), "true")
        self.assertEqual(by_id["referral-chain-preview"].get("aria-live"), "polite")
        self.assertIn("referral-graph", by_id)
        self.assertIn("referral-inspector", by_id)
        self.assertIn("referral-parent-select", by_id)
        for control_id in (
            "referral-map-controls",
            "referral-zoom-out",
            "referral-zoom-level",
            "referral-zoom-in",
            "referral-fit-all",
            "referral-fit",
            "referral-minimap-shell",
            "referral-minimap",
        ):
            self.assertIn(control_id, by_id)
        self.assertEqual(by_id["referral-chain-preview"].get("tabindex"), "0")
        self.assertEqual(by_id["referral-minimap"].get("tabindex"), "0")
        self.assertIn("function referralTopologySnapshot", self.javascript)
        self.assertIn("function referralGraphLayout", self.javascript)
        self.assertIn("function referralGraphMarkup", self.javascript)
        self.assertIn("function renderReferralInspector", self.javascript)
        self.assertIn("state.referralDraft = new Map", self.javascript)
        self.assertIn("function referralDescendants", self.javascript)
        self.assertIn("function referralZoomAroundPoint", self.javascript)
        self.assertIn("function fitReferralGraph", self.javascript)
        self.assertIn("function handleReferralPointerMove", self.javascript)
        self.assertIn("function handleReferralWheel", self.javascript)
        self.assertIn("function referralMinimapMarkup", self.javascript)
        self.assertIn("function handleReferralMinimapPointer", self.javascript)
        self.assertIn("setPointerCapture?.(event.pointerId)", self.javascript)
        self.assertIn("window.requestAnimationFrame(applyReferralViewNow)", self.javascript)
        self.assertIn("{ passive: false }", self.javascript)
        self.assertIn("Цепочка замыкается в круг", self.javascript)
        self.assertIn("child_account_id: account.id", self.javascript)
        self.assertIn("parent_account_id: parentByChild.get(account.id) || null", self.javascript)
        self.assertIn("expected_revision: state.referralRevision", self.javascript)
        self.assertIn("/api/accounts/referral-topology", self.javascript)
        self.assertIn("На карте должен быть каждый аккаунт — без дублей", self.javascript)
        self.assertIn("function referralAccountIssue(account, action)", self.javascript)
        self.assertNotIn("/api/accounts/referrals", self.javascript)
        self.assertNotIn("referral_code_configured", self.javascript)
        self.assertNotIn("effective_referrer_code_configured", self.javascript)
        self.assertNotIn("own_code", self.javascript)
        self.assertNotIn("external_referrer", self.javascript)
        for selector in (
            ".account-capability-grid {",
            ".modal--referrals {",
            ".referral-chain-preview {",
            ".referral-workspace {",
            ".referral-graph-node {",
            ".referral-inspector {",
        ):
            self.assertIn(selector, self.css)
        graph_block = re.search(r"\.referral-graph\s*\{(.*?)\}", self.css, re.DOTALL)
        surface_block = re.search(r"\.referral-graph-surface\s*\{(.*?)\}", self.css, re.DOTALL)
        self.assertIsNotNone(graph_block)
        self.assertIsNotNone(surface_block)
        for declaration in ("position: absolute", "inset: 0", "height: 100%"):
            self.assertIn(declaration, graph_block.group(1))
        self.assertIn("height: 100%", surface_block.group(1))
        search_renderer = self.javascript[
            self.javascript.index("function applyReferralSearch("):
            self.javascript.index("function applyReferralPattern(")
        ]
        self.assertIn("{ focusNode: false }", search_renderer)
        self.assertNotIn(".referral-row {", self.css)
        self.assertNotIn("function syncReferralEditorState", self.javascript)

        self.assertGreaterEqual(
            self.javascript.count("if (event.currentTarget.value === '') return;"),
            2,
            "Single and batch concurrency inputs must allow a temporary blank while editing",
        )

        self.assertIn("function actionResources(action)", self.javascript)
        self.assertIn("function runResourceIssue(action, accountIds)", self.javascript)
        self.assertIn("missingSettingResources(action)", self.javascript)
        self.assertIn("missingAccountResources(account, action)", self.javascript)
        self.assertIn("input[name=\"run-account\"]:not(:disabled)", self.javascript)
        batch_preflight = self.javascript[
            self.javascript.index("function batchActionIssue("):
            self.javascript.index("function batchDefaultOptions(")
        ]
        self.assertIn("missingSettingResources(action)", batch_preflight)
        self.assertIn("missingAccountResources(account, action)", batch_preflight)
        self.assertIn("Для «${account.label}»", batch_preflight)

        self.assertIn("function modulePresentation(module)", self.javascript)
        self.assertIn("modulePresentation(module)?.display_name", self.javascript)
        self.assertIn("modulePresentation(module)?.description", self.javascript)
        self.assertIn("/presentation/${kind}", self.javascript)
        self.assertIn("'X-Soft-Hub-Token': apiToken", self.javascript)
        self.assertIn("URL.createObjectURL(blob)", self.javascript)
        self.assertIn("function revokePresentationAssets()", self.javascript)
        self.assertIn("URL.revokeObjectURL(url)", self.javascript)
        self.assertIn(".software-card-cover {", self.css)
        self.assertIn(".presentation-icon-shell {", self.css)

        drawer_markup = self.html[
            self.html.index('id="run-drawer"'):
            self.html.index('</aside>', self.html.index('id="run-drawer"'))
        ]
        self.assertIn('<use href="#icon-search"></use></svg>Общий лог софта', drawer_markup)
        self.assertIn('<use href="#icon-download"></use></svg>Скачать полный лог', drawer_markup)

    def test_referral_graph_layout_builds_roots_branches_and_rejects_cycles(self) -> None:
        graph_source = self.javascript[
            self.javascript.index("function referralTopologySnapshot("):
            self.javascript.index("function referralGraphMarkup(")
        ]
        script = "\n".join(
            (
                "const accounts = ['A','B','C','D'].map((id) => ({id,label:id,evm_address:'0x'+id}));",
                "const state = {data:{accounts},referralDraft:new Map([['A',''],['B','A'],['C','A'],['D','B']])};",
                "function accountById(id) { return state.data.accounts.find((account) => account.id === id); }",
                graph_source,
                "const snapshot = referralTopologySnapshot();",
                "if (snapshot.roots !== 1 || snapshot.links !== 3 || snapshot.maxDepth !== 2) throw new Error('bad topology stats');",
                "if (snapshot.depths.get('A') !== 0 || snapshot.depths.get('D') !== 2) throw new Error('bad depth');",
                "const layout = referralGraphLayout(snapshot);",
                "if (!(layout.positions.get('A').y < layout.positions.get('B').y && layout.positions.get('B').y < layout.positions.get('D').y)) throw new Error('levels are not top-down');",
                "if (layout.positions.get('B').x === layout.positions.get('C').x) throw new Error('siblings overlap');",
                "state.referralDraft.set('A','D');",
                "let cycleRejected = false;",
                "try { referralTopologySnapshot(); } catch (error) { cycleRejected = /круг/.test(error.message); }",
                "if (!cycleRejected) throw new Error('cycle was accepted');",
            )
        )
        completed = subprocess.run(
            ["node", "--input-type=module", "-e", script],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_referral_view_math_preserves_cursor_anchor_and_fits_wide_forests(self) -> None:
        math_source = self.javascript[
            self.javascript.index("function clampReferralZoom("):
            self.javascript.index("function referralViewportSize(")
        ]
        script = "\n".join(
            (
                "const REFERRAL_ZOOM_MIN = 0.35;",
                "const REFERRAL_ZOOM_ABSOLUTE_MIN = 0.0001;",
                "const REFERRAL_ZOOM_MAX = 1.8;",
                math_source,
                "const before = {x:-210,y:-95,zoom:0.8};",
                "const point = {x:320,y:180};",
                "const after = referralZoomAroundPoint(before,1.25,point);",
                "const gxBefore = (point.x-before.x)/before.zoom;",
                "const gyBefore = (point.y-before.y)/before.zoom;",
                "const gxAfter = (point.x-after.x)/after.zoom;",
                "const gyAfter = (point.y-after.y)/after.zoom;",
                "if (Math.abs(gxBefore-gxAfter)>1e-8 || Math.abs(gyBefore-gyAfter)>1e-8) throw new Error('cursor anchor moved');",
                "const manual = referralZoomAroundPoint({x:10,y:20,zoom:0.5},0.06,point);",
                "if (manual.zoom !== REFERRAL_ZOOM_MIN) throw new Error('manual zoom escaped readable floor');",
                "const fitFloor = 0.06;",
                "const tinyBefore = {x:10,y:20,zoom:0.08};",
                "const tinyAfter = referralZoomAroundPoint(tinyBefore,0.01,point,fitFloor);",
                "if (tinyAfter.zoom !== fitFloor) throw new Error('wide-forest fit floor was ignored');",
                "const fit = referralFitTransform({x:0,y:0,width:100000,height:1200},{width:900,height:500});",
                "if (!(fit.zoom < REFERRAL_ZOOM_MIN)) throw new Error('wide forest cannot fit');",
                "if (100000*fit.zoom > 900.001) throw new Error('fit exceeds viewport');",
                "if (clampReferralZoom(99) !== REFERRAL_ZOOM_MAX) throw new Error('max zoom clamp failed');",
            )
        )
        completed = subprocess.run(
            ["node", "--input-type=module", "-e", script],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_referral_map_double_click_cannot_select_the_account_tree(self) -> None:
        preview_block = re.search(r"\.referral-chain-preview\s*\{(.*?)\}", self.css, re.DOTALL)
        self.assertIsNotNone(preview_block)
        self.assertIn("-webkit-user-select: none", preview_block.group(1))
        self.assertIn("user-select: none", preview_block.group(1))

        handler = self.javascript[
            self.javascript.index("function handleReferralDoubleClick("):
            self.javascript.index("function handleReferralMapKeydown(")
        ]
        self.assertIn("event.preventDefault()", handler)
        self.assertIn("window.getSelection()?.removeAllRanges()", handler)
        self.assertIn("#referral-map-controls, #referral-minimap-shell", handler)
        self.assertNotIn("stopPropagation", handler)
        self.assertIn(
            "$('#referral-chain-preview').addEventListener('dblclick', handleReferralDoubleClick)",
            self.javascript,
        )

    def test_scroll_surfaces_use_themed_accessible_scrollbars(self) -> None:
        light_match = re.search(r":root\s*\{(.*?)\n\}", self.css, re.DOTALL)
        dark_match = re.search(r':root\[data-theme="dark"\]\s*\{(.*?)\n\}', self.css, re.DOTALL)
        self.assertIsNotNone(light_match)
        self.assertIsNotNone(dark_match)
        for palette in (light_match.group(1), dark_match.group(1)):
            for token in (
                "scrollbar-track",
                "scrollbar-thumb",
                "scrollbar-thumb-hover",
                "scrollbar-thumb-active",
            ):
                self.assertIn(f"--{token}:", palette)

        firefox_rule = re.search(r":where\(\*\)\s*\{(?P<body>.*?)\n\}", self.css, re.DOTALL)
        webkit_rule = re.search(
            r":where\(\*\)::-webkit-scrollbar\s*\{(?P<body>.*?)\n\}",
            self.css,
            re.DOTALL,
        )
        thumb_rule = re.search(
            r":where\(\*\)::-webkit-scrollbar-thumb\s*\{(?P<body>.*?)\n\}",
            self.css,
            re.DOTALL,
        )
        track_rule = re.search(
            r":where\(\*\)::-webkit-scrollbar-track\s*\{(?P<body>.*?)\n\}",
            self.css,
            re.DOTALL,
        )
        self.assertIsNotNone(firefox_rule)
        self.assertIsNotNone(webkit_rule)
        self.assertIsNotNone(thumb_rule)
        self.assertIsNotNone(track_rule)
        self.assertIn("scrollbar-width: thin", firefox_rule.group("body"))
        self.assertIn(
            "scrollbar-color: var(--scrollbar-thumb) var(--scrollbar-track)",
            firefox_rule.group("body"),
        )
        for declaration in ("width: 12px", "height: 12px"):
            self.assertIn(declaration, webkit_rule.group("body"))
        for declaration in (
            "min-width: 44px",
            "min-height: 44px",
            "border-radius: 999px",
            "background-color: var(--scrollbar-thumb)",
            "background-clip: padding-box",
        ):
            self.assertIn(declaration, thumb_rule.group("body"))
        self.assertIn("background-color: var(--scrollbar-track)", track_rule.group("body"))
        self.assertIn("::-webkit-scrollbar-thumb:hover", self.css)
        self.assertIn("background-color: var(--scrollbar-thumb-hover)", self.css)
        self.assertIn("::-webkit-scrollbar-thumb:active", self.css)
        self.assertIn("background-color: var(--scrollbar-thumb-active)", self.css)
        self.assertIn(":where(*)::-webkit-scrollbar-corner", self.css)

        html_rule = re.search(r"html\s*\{(?P<body>.*?)\n\}", self.css, re.DOTALL)
        gutter_rule = re.search(
            r":where\(\s*\.modal,(?P<selectors>.*?)\)\s*\{(?P<body>.*?)\n\}",
            self.css,
            re.DOTALL,
        )
        self.assertIsNotNone(html_rule)
        self.assertIsNotNone(gutter_rule)
        self.assertIn("scrollbar-gutter: stable", html_rule.group("body"))
        self.assertIn("scrollbar-gutter: stable", gutter_rule.group("body"))
        for selector in (
            ".referral-inspector",
            ".batch-run-list",
            ".account-selector",
            ".drawer",
            ".drawer-account-table-wrap",
            ".event-console",
            ".activity-table-wrap",
            ".result-report-table-scroll",
        ):
            self.assertIn(selector, gutter_rule.group("selectors"))

        more_contrast = self.css[
            self.css.index("@media (prefers-contrast: more)"):
            self.css.index("@media (forced-colors: active)")
        ]
        forced_colors = self.css[
            self.css.index("@media (forced-colors: active)"):
            self.css.index("@media (prefers-reduced-motion: reduce)")
        ]
        reduced_motion = self.css[self.css.index("@media (prefers-reduced-motion: reduce)"):]
        self.assertIn("--scrollbar-thumb: var(--ink)", more_contrast)
        self.assertIn("scrollbar-color: ButtonText Canvas", forced_colors)
        self.assertIn("background-color: ButtonText", forced_colors)
        self.assertIn(":where(*)::-webkit-scrollbar-thumb { transition: none; }", reduced_motion)

    def test_semantic_palette_and_focus_ring_keep_readable_contrast(self) -> None:
        light_match = re.search(r":root\s*\{(.*?)\n\}", self.css, re.DOTALL)
        dark_match = re.search(r':root\[data-theme="dark"\]\s*\{(.*?)\n\}', self.css, re.DOTALL)
        self.assertIsNotNone(light_match)
        self.assertIsNotNone(dark_match)

        def variables(block: str) -> dict[str, str]:
            return dict(re.findall(r"--([a-z-]+):\s*(#[0-9a-fA-F]{6});", block))

        for palette in (variables(light_match.group(1)), variables(dark_match.group(1))):
            self.assertGreaterEqual(
                _contrast("#fffaf2", palette["acid-deep"]),
                4.5,
                "primary button text on --acid-deep",
            )
            for foreground in ("muted", "faint", "amber"):
                for background in ("canvas", "paper", "paper-strong"):
                    self.assertGreaterEqual(
                        _contrast(palette[foreground], palette[background]),
                        4.5,
                        f"--{foreground} on --{background}",
                    )
            for foreground in ("olive", "butter"):
                self.assertGreaterEqual(
                    _contrast(palette["paper"], palette[foreground]),
                    4.5,
                    f"--{foreground} on --paper",
                )
            for background in ("canvas", "paper", "paper-strong"):
                self.assertGreaterEqual(
                    _contrast(palette["focus-ring"], palette[background]),
                    3.0,
                    f"--focus-ring on --{background}",
                )


if __name__ == "__main__":
    unittest.main()
