const tokenParams = new URLSearchParams(window.location.hash.slice(1));
const apiToken = tokenParams.get('token') || window.sessionStorage.getItem('soft-hub-token') || '';
if (apiToken) window.sessionStorage.setItem('soft-hub-token', apiToken);
window.history.replaceState(null, '', window.location.pathname);

const CORE_UPDATE_CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000;

const state = {
  data: null,
  view: 'overview',
  activityFilter: 'active',
  activityFocusOrigin: null,
  activityPanelTimer: null,
  activityAccountRows: [],
  activityAccountsTruncated: { active: false, attention: false },
  activityAccountsLoaded: false,
  activityAccountsLoading: false,
  activityAccountsError: '',
  activityAccountsPromise: null,
  activityAccountsGeneration: 0,
  selectedModuleId: null,
  batchModuleIds: new Set(),
  batchActionIds: new Map(),
  batchIdempotencyKey: null,
  lastRunActionId: null,
  selectedRunId: null,
  selectedRunSnapshot: null,
  drawerAccountSignature: '',
  eventAfter: 0,
  eventLogHydrated: false,
  drawerUpdating: false,
  drawerRefreshQueued: false,
  drawerRequestGeneration: 0,
  drawerCloseTimer: null,
  refreshing: false,
  refreshPending: false,
  refreshSpinPending: false,
  refreshPromise: null,
  startupVaultGate: true,
  pendingAfterUnlock: null,
  resumeRunAfterImport: null,
  pollHandle: null,
  motionPass: true,
  patchFeed: [],
  patchFeedLoaded: false,
  patchFeedLoading: false,
  fileInstallBusy: false,
  focusOrigin: null,
  focusOriginIdentity: null,
  destructiveRequest: null,
  presentationUrls: new Map(),
  presentationLoads: new Map(),
  presentationFailures: new Map(),
  resultModuleExpansion: new Map(),
  resultReports: [],
  resultReportsLoaded: false,
  resultReportsLoading: false,
  resultReportsRefreshPending: false,
  resultReportsError: '',
  resultReportsRequestGeneration: 0,
  resultReportBootstrapSignature: '',
  selectedResultReportId: '',
  selectedResultReport: null,
  resultReportLoading: false,
  resultReportRequestGeneration: 0,
  resultReportFilterTimer: null,
  resultCatalogFilter: 'all',
  catalogBatchScope: 'all',
  patchRadarTimer: null,
  coreUpdate: {
    phase: 'idle',
    bridgeAvailable: null,
    currentVersion: '',
    availableVersion: '',
    percent: 0,
    transferred: 0,
    total: 0,
    releaseNotes: [],
    checkedAt: '',
    errorKind: '',
    message: '',
    installIssue: '',
  },
  coreUpdateAutoCheckStarted: false,
  coreUpdateCheckTimer: null,
  coreUpdateUnsubscribe: null,
  coreUpdateNotifiedVersion: '',
  protectedDataEpoch: 0,
  referralRevision: '',
  referralDraft: new Map(),
  referralSelectedAccountId: null,
  referralDirty: false,
  referralView: { x: 0, y: 0, zoom: 1 },
  referralViewFrame: null,
  referralPointers: new Map(),
  referralGesture: null,
  referralSuppressClickUntil: 0,
};

const pageMeta = {
  overview: ['ГЛАВНОЕ', 'Обзор'],
  software: ['МОИ СОФТЫ', 'Софты'],
  accounts: ['АККАУНТЫ', 'Аккаунты'],
  results: ['ИТОГИ', 'Результаты'],
  nft: ['NFT · WL / MINT / MARKET', 'NFT'],
  testnets: ['TESTNET · RUN / TRACK / PARSE', 'Тестнеты'],
  patches: ['ПАТЧИ', 'Патчи'],
  settings: ['НАСТРОЙКИ', 'Настройки'],
};

const catalogSectionMeta = {
  nft: {
    label: 'NFT',
    plural: 'NFT-софтов',
    emptyTitle: 'NFT-софтов пока нет',
    emptyCopy: 'Установите патч, отмеченный разделом NFT, — карточка сразу появится здесь.',
    searchEmptyCopy: 'По вашему запросу ничего не нашлось. Можно сбросить поиск и посмотреть весь раздел.',
  },
  testnet: {
    label: 'TESTNET',
    plural: 'тестнет-софтов',
    emptyTitle: 'Тестнет-софтов пока нет',
    emptyCopy: 'Установите патч для тестовой сети — Hub сам положит его в этот раздел.',
    searchEmptyCopy: 'По вашему запросу ничего не нашлось. Сбросьте поиск, чтобы вернуть все тестнеты.',
  },
};

function catalogSectionForView(view) {
  if (view === 'nft') return 'nft';
  if (view === 'testnets') return 'testnet';
  return '';
}

const MAX_DRAWER_EVENT_LINES = 2_000;
const MAX_ACTIVITY_ROWS = 40;
const REFERRAL_ZOOM_MIN = 0.35;
const REFERRAL_ZOOM_ABSOLUTE_MIN = 0.0001;
const REFERRAL_ZOOM_MAX = 1.8;
const REFERRAL_ZOOM_STEP = 1.2;
const REFERRAL_MINIMAP_WIDTH = 180;
const REFERRAL_MINIMAP_HEIGHT = 112;
const ACTIVE_RUN_STATUSES = new Set(['queued', 'starting', 'running', 'cancelling']);
const ATTENTION_RUN_STATUSES = new Set(['failed']);
const ACTIVE_ACCOUNT_STATUSES = new Set(['queued', 'running']);
const ATTENTION_ACCOUNT_STATUSES = new Set(['partial', 'failed', 'blocked', 'needs_attention']);

const statusNames = {
  queued: 'В очереди',
  starting: 'Запускается',
  running: 'Работает',
  cancelling: 'Останавливается',
  succeeded: 'Завершено',
  failed: 'Ошибка',
  cancelled: 'Остановлено',
  needs_attention: 'Внешний итог неясен',
  reconciled: 'Закрыто',
  reviewed: 'Просмотрено',
};

const accountStatusNames = {
  queued: 'В очереди',
  running: 'Работает',
  succeeded: 'Завершено',
  partial: 'Частично',
  failed: 'Ошибка',
  skipped: 'Пропущено',
  blocked: 'Заблокировано',
  needs_attention: 'Внешний итог неясен',
  cancelled: 'Остановлено',
  unknown: 'Не определено',
};

const riskNames = {
  none: 'БЕЗ РИСКА ДЛЯ СРЕДСТВ',
  testnet: 'TESTNET',
  mainnet: 'MAINNET',
};

const actionRiskNames = {
  read: 'Чтение',
  testnet_write: 'Testnet-запись',
  mainnet_write: 'Mainnet-запись',
  external_write: 'Внешняя запись',
};

const accountResourceNames = {
  private_key: 'EVM-ключ',
  proxy: 'HTTP-прокси',
  email: 'Почта',
  email_password: 'Пароль почты',
  twitter: 'Twitter',
  adspower_profile: 'AdsPower-профиль',
};

const settingResourceNames = {
  capsolver: 'Capsolver API',
  adspower_api: 'AdsPower API',
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

function setTextIfChanged(target, value) {
  const nextValue = String(value);
  if (target.textContent !== nextValue) target.textContent = nextValue;
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function shortAddress(value) {
  const text = String(value || '—');
  return text.length > 20 ? `${text.slice(0, 8)}…${text.slice(-6)}` : text;
}

function lines(value) {
  return String(value || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function parseDelimitedRow(line, delimiter) {
  const cells = [];
  let cell = '';
  let quoted = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (character === '"') {
      if (quoted && line[index + 1] === '"') {
        cell += '"';
        index += 1;
      } else {
        quoted = !quoted;
      }
    } else if (character === delimiter && !quoted) {
      cells.push(cell.trim());
      cell = '';
    } else {
      cell += character;
    }
  }
  if (quoted) throw new Error('В таблице есть незакрытая кавычка');
  cells.push(cell.trim());
  return cells;
}

function parseAccountTable(value) {
  const rows = String(value || '').replace(/^\uFEFF/, '').split(/\r?\n/).filter((line) => line.trim());
  if (!rows.length) return [];
  const sample = rows[0];
  const delimiter = sample.includes('\t') ? '\t' : sample.includes(';') ? ';' : ',';
  const parsed = rows.map((line, index) => {
    const cells = parseDelimitedRow(line, delimiter);
    if (cells.length !== 5) throw new Error(`Строка ${index + 1}: ожидаются ровно 5 колонок`);
    return cells;
  });
  const header = parsed[0].map((cell) => cell.toLowerCase().replaceAll(' ', '_'));
  if (header.join(',') === 'private_key,proxy,email,twitter,adspower_profile') parsed.shift();
  return parsed.map(([privateKey, proxy, email, twitter, adspowerProfile], index) => {
    if (!privateKey || !proxy || !email) throw new Error(`Строка ${index + 1}: первые три колонки обязательны`);
    return {
      private_key: privateKey,
      proxy,
      email,
      twitter,
      adspower_profile: adspowerProfile,
    };
  });
}

function relativeTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  const delta = Math.max(0, Date.now() - date.getTime());
  const seconds = Math.floor(delta / 1000);
  if (seconds < 10) return 'только что';
  if (seconds < 60) return `${seconds} сек назад`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} мин назад`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} ч назад`;
  return date.toLocaleDateString('ru-RU', { day: '2-digit', month: 'short' });
}

function clockTime(value) {
  if (!value) return '—';
  return new Date(value).toLocaleTimeString('ru-RU', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function fullDateTime(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return new Intl.DateTimeFormat('ru-RU', {
    day: '2-digit',
    month: 'long',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date);
}

function countWord(value, one, few, many) {
  const count = Math.abs(Number(value || 0));
  const lastTwo = count % 100;
  if (lastTwo >= 11 && lastTwo <= 14) return many;
  const last = count % 10;
  if (last === 1) return one;
  if (last >= 2 && last <= 4) return few;
  return many;
}

function initials(name, manifest = {}) {
  const supplied = manifest.ui?.monogram;
  if (supplied) return String(supplied).slice(0, 3).toUpperCase();
  return String(name || 'SH')
    .split(/\s+/)
    .map((part) => part[0])
    .join('')
    .slice(0, 2)
    .toUpperCase();
}

function accentClass(module) {
  const seed = `${module?.id || ''}:${module?.manifest?.ui?.accent || ''}`;
  const hash = Array.from(seed).reduce((sum, char) => sum + char.charCodeAt(0), 0);
  return `accent-${hash % 6}`;
}

function normalizeCatalogSections(value) {
  const source = Array.isArray(value) ? value : typeof value === 'string' ? [value] : [];
  return Array.from(new Set(source.map((entry) => {
    const normalized = String(entry || '').trim().toLowerCase();
    if (normalized === 'testnets') return 'testnet';
    return normalized;
  }).filter((entry) => ['general', 'nft', 'testnet'].includes(entry))));
}

function fallbackManifestCatalogSections(manifest = {}) {
  const declared = normalizeCatalogSections(manifest.catalog?.sections || manifest.catalog_sections);
  if (declared.length) return declared;
  const actions = Array.isArray(manifest.actions) ? manifest.actions : [];
  if (
    manifest.permissions?.financial_risk === 'testnet'
    || actions.some((action) => action?.risk === 'testnet_write')
  ) return ['testnet'];
  return ['general'];
}

function moduleCatalogSections(module) {
  const projected = normalizeCatalogSections(module?.catalog_sections);
  return projected.length ? projected : fallbackManifestCatalogSections(module?.manifest || {});
}

function moduleBelongsToCatalog(module, section) {
  return moduleCatalogSections(module).includes(section);
}

function recordCatalogSections(record) {
  const projected = normalizeCatalogSections(record?.catalog_sections);
  if (projected.length) return projected;
  const manifest = record?.run_manifest || record?.manifest;
  if (manifest && typeof manifest === 'object') return fallbackManifestCatalogSections(manifest);
  const module = state.data?.modules?.find((candidate) => candidate.id === record?.module_id);
  return module ? moduleCatalogSections(module) : ['general'];
}

function recordBelongsToCatalog(record, section) {
  return recordCatalogSections(record).includes(section);
}

function catalogModules(section) {
  return (state.data?.modules || []).filter((module) => moduleBelongsToCatalog(module, section));
}

function catalogSectionChips(module) {
  const sections = moduleCatalogSections(module);
  return sections.map((section) => {
    const label = section === 'nft' ? 'NFT' : section === 'testnet' ? 'TESTNET' : 'ОБЩЕЕ';
    return `<span class="catalog-section-chip" data-catalog-section="${escapeHtml(section)}">${label}</span>`;
  }).join('');
}

function modulePresentation(module) {
  const presentation = module?.manifest?.presentation;
  if (!presentation || typeof presentation !== 'object') return null;
  if (!presentation.assets || typeof presentation.assets !== 'object') return null;
  return presentation;
}

function moduleDisplayName(module) {
  return modulePresentation(module)?.display_name || module?.name || 'Без названия';
}

function moduleDisplayDescription(module) {
  return modulePresentation(module)?.description || module?.description || '';
}

function presentationAssetKey(module, kind) {
  const presentation = modulePresentation(module);
  const asset = presentation?.assets?.[kind];
  return presentation && typeof asset === 'string'
    ? `${module.id}:${module.version}:${kind}:${asset}`
    : '';
}

function presentationAssetUrl(module, kind) {
  const key = presentationAssetKey(module, kind);
  return key ? state.presentationUrls.get(key) || '' : '';
}

function iconMarkup(name, className = 'hub-icon') {
  return `<svg class="${escapeHtml(className)}" aria-hidden="true"><use href="#icon-${escapeHtml(name)}"></use></svg>`;
}

function moduleIconMarkup(module) {
  const accent = accentClass(module);
  const presentation = modulePresentation(module);
  if (presentation) {
    const url = presentationAssetUrl(module, 'icon');
    return `<span class="module-icon-shell presentation-icon-shell ${accent} ${url ? 'has-presentation-asset' : ''}" aria-hidden="true">
      <img data-presentation-icon="${escapeHtml(module.id)}" alt="" width="48" height="48" decoding="async" ${url ? `src="${escapeHtml(url)}"` : 'hidden'} />
      <span class="presentation-asset-placeholder" ${url ? 'hidden' : ''}>${escapeHtml(initials(moduleDisplayName(module), module.manifest))}</span>
    </span>`;
  }
  const index = Number(accent.slice(-1)) || 0;
  return `<span class="module-icon-shell ${accent}" aria-hidden="true">${iconMarkup(`module-${index}`)}</span>`;
}

function moduleCoverMarkup(module) {
  if (!modulePresentation(module)) return '';
  const url = presentationAssetUrl(module, 'image');
  return `<div class="software-card-cover ${url ? 'has-presentation-asset' : ''}" aria-hidden="true">
    <img data-presentation-image="${escapeHtml(module.id)}" alt="" width="1600" height="900" loading="lazy" decoding="async" ${url ? `src="${escapeHtml(url)}"` : 'hidden'} />
    <span class="presentation-cover-placeholder">${escapeHtml(initials(moduleDisplayName(module), module.manifest))}</span>
  </div>`;
}

function applyPresentationAsset(moduleId, kind, url) {
  $$(`[data-presentation-${kind}]`).forEach((image) => {
    if (image.dataset[`presentation${kind[0].toUpperCase()}${kind.slice(1)}`] !== moduleId) return;
    image.src = url;
    image.hidden = false;
    const shell = image.parentElement;
    shell?.classList.add('has-presentation-asset');
    $('.presentation-asset-placeholder', shell)?.toggleAttribute('hidden', true);
  });
}

async function loadPresentationAsset(module, kind) {
  const key = presentationAssetKey(module, kind);
  if (!key || state.presentationUrls.has(key) || state.presentationLoads.has(key)) return;
  const failedAt = state.presentationFailures.get(key) || 0;
  if (Date.now() - failedAt < 30_000) return;
  const promise = fetch(
    `/api/modules/${encodeURIComponent(module.id)}/presentation/${kind}`,
    { headers: { 'X-Soft-Hub-Token': apiToken }, cache: 'no-store' },
  )
    .then(async (response) => {
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const contentType = response.headers.get('Content-Type') || '';
      if (!contentType.startsWith('image/')) throw new Error('Некорректный тип presentation asset');
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const current = state.data?.modules.find((item) => item.id === module.id);
      if (!current || presentationAssetKey(current, kind) !== key) {
        URL.revokeObjectURL(url);
        return;
      }
      state.presentationUrls.set(key, url);
      state.presentationFailures.delete(key);
      applyPresentationAsset(module.id, kind, url);
    })
    .catch(() => state.presentationFailures.set(key, Date.now()))
    .finally(() => state.presentationLoads.delete(key));
  state.presentationLoads.set(key, promise);
  await promise;
}

function syncPresentationAssets() {
  const validKeys = new Set();
  (state.data?.modules || []).forEach((module) => {
    for (const kind of ['icon', 'image']) {
      const key = presentationAssetKey(module, kind);
      if (!key) continue;
      validKeys.add(key);
      if (kind === 'icon' || ['software', 'nft', 'testnets'].includes(state.view) || state.presentationUrls.has(key)) {
        void loadPresentationAsset(module, kind);
      }
    }
  });
  for (const [key, url] of state.presentationUrls) {
    if (validKeys.has(key)) continue;
    URL.revokeObjectURL(url);
    state.presentationUrls.delete(key);
  }
  for (const key of state.presentationFailures.keys()) {
    if (!validKeys.has(key)) state.presentationFailures.delete(key);
  }
}

function revokePresentationAssets() {
  for (const url of state.presentationUrls.values()) URL.revokeObjectURL(url);
  state.presentationUrls.clear();
}

async function api(path, options = {}) {
  if (!apiToken) throw new Error('Не получилось открыть локальную сессию. Перезапустите Soft Hub.');
  const headers = new Headers(options.headers || {});
  headers.set('X-Soft-Hub-Token', apiToken);
  if (options.body && !(options.body instanceof Blob) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  const response = await fetch(path, { ...options, headers });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload.error || `HTTP ${response.status}`);
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return payload;
}

function jsonPost(path, body = {}) {
  return api(path, { method: 'POST', body: JSON.stringify(body) });
}

function toast(message, type = 'success', timeout = 3800) {
  const item = document.createElement('div');
  item.className = 'toast';
  item.dataset.type = type;
  const dot = document.createElement('i');
  const copy = document.createElement('span');
  const close = document.createElement('button');
  copy.textContent = message;
  close.type = 'button';
  close.textContent = '×';
  close.setAttribute('aria-label', 'Закрыть уведомление');
  const dismiss = () => {
    if (!item.isConnected || item.classList.contains('is-closing')) return;
    item.classList.add('is-closing');
    window.setTimeout(() => item.remove(), 180);
  };
  close.addEventListener('click', dismiss);
  item.append(dot, copy, close);
  $('#toast-region').append(item);
  window.setTimeout(dismiss, timeout);
}

function setBusy(button, busy, label = 'Подождите…') {
  if (!button) return;
  // A modal mutation stays blocking, while a drawer operation may safely
  // continue after the user closes its visual details panel.
  const layer = button.closest('.modal');
  if (busy) {
    button.dataset.previousHtml = button.innerHTML;
    button.dataset.previousDisabled = String(button.disabled);
    button.textContent = label;
    button.disabled = true;
  } else {
    if (button.dataset.previousHtml) button.innerHTML = button.dataset.previousHtml;
    button.disabled = button.dataset.previousDisabled === 'true';
    delete button.dataset.previousHtml;
    delete button.dataset.previousDisabled;
  }
  if (layer) {
    layer.dataset.busy = busy ? 'true' : 'false';
    $('.modal-close', layer)?.toggleAttribute('disabled', busy);
  }
}

const focusIdentityAttributes = [
  'data-open-run',
  'data-run-module',
  'data-prepare-module',
  'data-toggle-module',
  'data-delete-module',
  'data-batch-module',
  'data-delete-account',
  'data-install-patch',
  'data-open-patch-repository',
  'data-quick-action',
  'data-open-catalog-report',
];

function focusIdentity(element) {
  if (!(element instanceof HTMLElement)) return null;
  if (element.id) return { id: element.id };
  for (const attribute of focusIdentityAttributes) {
    const value = element.getAttribute(attribute);
    if (value !== null) return { attribute, value };
  }
  return null;
}

function findFocusIdentity(identity) {
  if (!identity) return null;
  if (identity.id) return document.getElementById(identity.id);
  const visibleView = $('.view.is-visible');
  const roots = visibleView ? [visibleView, document] : [document];
  for (const root of roots) {
    const match = $$(`[${identity.attribute}]`, root).find((element) => element.getAttribute(identity.attribute) === identity.value);
    if (match) return match;
  }
  return null;
}

function rememberFocusOrigin() {
  const active = document.activeElement;
  if (!(active instanceof HTMLElement) || active === document.body) return;
  state.focusOrigin = active;
  state.focusOriginIdentity = focusIdentity(active);
}

function restoreFocusOrigin() {
  const target = state.focusOrigin?.isConnected
    ? state.focusOrigin
    : findFocusIdentity(state.focusOriginIdentity);
  if (target) target.focus({ preventScroll: true });
  state.focusOrigin = null;
  state.focusOriginIdentity = null;
}

function decorateAnimatedList(root, force = false) {
  if (!root || (!state.motionPass && !force)) return;
  Array.from(root.children).forEach((item, index) => {
    item.classList.add('animated-item', `list-step-${Math.min(index, 9)}`);
  });
}

function replayBlurText(element) {
  if (!element || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  element.classList.remove('is-animating');
  // Reading layout restarts the authored entrance when the command state changes.
  void element.offsetWidth;
  element.classList.add('is-animating');
}

function stopPatchRadarMotion() {
  if (state.patchRadarTimer !== null) window.clearTimeout(state.patchRadarTimer);
  state.patchRadarTimer = null;
  $$('.patch-radar-blip.is-visible').forEach((blip) => blip.classList.remove('is-visible'));
}

function patchRadarCanAnimate() {
  const radar = $('.patch-radar-orbit');
  return Boolean(
    radar
    && state.view === 'patches'
    && document.visibilityState === 'visible'
    && !window.matchMedia('(prefers-reduced-motion: reduce)').matches
    && radar.getClientRects().length,
  );
}

function schedulePatchRadarBlip(delay = 180) {
  if (!patchRadarCanAnimate() || state.patchRadarTimer !== null) return;
  state.patchRadarTimer = window.setTimeout(() => {
    state.patchRadarTimer = null;
    if (!patchRadarCanAnimate()) {
      stopPatchRadarMotion();
      return;
    }
    const available = $$('.patch-radar-blip').filter((blip) => !blip.classList.contains('is-visible'));
    if (available.length) {
      const blip = available[Math.floor(Math.random() * available.length)];
      const angle = Math.random() * Math.PI * 2;
      const innerRadius = 9;
      const outerRadius = 39;
      const radius = Math.sqrt(
        innerRadius ** 2 + Math.random() * (outerRadius ** 2 - innerRadius ** 2),
      );
      blip.setAttribute('cx', (50 + Math.cos(angle) * radius).toFixed(2));
      blip.setAttribute('cy', (50 + Math.sin(angle) * radius).toFixed(2));
      blip.setAttribute('r', (1.8 + Math.random() * 1.1).toFixed(2));
      // Force the authored SVG animation to restart without creating inline styles.
      void blip.getBoundingClientRect();
      blip.classList.add('is-visible');
    }
    schedulePatchRadarBlip(460 + Math.random() * 980);
  }, delay);
}

function syncPatchRadarMotion() {
  if (!patchRadarCanAnimate()) {
    stopPatchRadarMotion();
    return;
  }
  schedulePatchRadarBlip();
}

function prefersReducedMotion() {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

function updateNavigationState(name = state.view) {
  const navigation = $('.navigation');
  if (!navigation) return;
  navigation.dataset.activeView = name;
  const active = $(`.nav-item[data-view="${name}"]`, navigation);
  if (!active) return;
  const line = $('#nav-line');
  if (line && line.parentElement !== active) active.append(line);
}

function showView(name) {
  if (!pageMeta[name]) return;
  const changed = state.view !== name;
  if (changed) {
    if (!$('#activity-panel').hidden) closeActivityPanel({ restoreFocus: false, immediate: true });
    if (!$('#run-drawer').hidden || state.selectedRunId) {
      closeRunDrawer({ restoreFocus: false, immediate: true });
    }
  }
  const commit = () => {
    state.view = name;
    $$('.view').forEach((view) => {
      const visible = view.id === `view-${name}`;
      view.classList.toggle('is-visible', visible);
      view.classList.remove('is-entering');
      if (visible && changed && !document.startViewTransition) {
        view.classList.add('is-entering');
        window.setTimeout(() => view.classList.remove('is-entering'), 320);
      }
    });
    $$('.nav-item').forEach((item) => {
      const active = item.dataset.view === name;
      item.classList.toggle('is-active', active);
      item.toggleAttribute('aria-current', active);
      if (active) item.setAttribute('aria-current', 'page');
    });
    $('#page-kicker').textContent = pageMeta[name][0];
    $('#page-title').textContent = pageMeta[name][1];
    document.title = `${pageMeta[name][1]} · Soft Hub`;
    updateNavigationState(name);
    window.scrollTo({ top: 0, behavior: 'auto' });
    if (changed) window.requestAnimationFrame(() => $('#page-title').focus({ preventScroll: true }));
    if (name === 'accounts') renderAccounts();
    if (name === 'software') syncPresentationAssets();
    if (catalogSectionForView(name)) {
      renderCatalogWorkspaces();
      syncPresentationAssets();
      if (state.data?.vault?.unlocked) void loadResultReports({ force: false });
    }
    if (name === 'results') {
      renderResults();
      renderResultReportWorkbench();
      void loadResultReports({ force: changed && state.resultReportsLoaded });
    }
    if (name === 'patches' && state.data?.patch_feed?.owner && !state.patchFeedLoaded) {
      void scanPatchFeed({ silent: true });
    }
    syncPatchRadarMotion();
  };
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (changed && document.startViewTransition && !reduced) document.startViewTransition(commit);
  else commit();
}

function updateVaultState() {
  if (!state.data) return;
  const vault = state.data.vault;
  const accountCount = state.data.accounts.length;
  const quick = $('#vault-quick');
  const title = $('#vault-quick-title');
  const detail = $('#vault-quick-detail');
  if (vault.unlocked) {
    quick.dataset.state = accountCount ? 'unlocked' : 'unlocked-empty';
    title.textContent = 'Vault открыт';
    detail.textContent = accountCount
      ? `${accountCount} ${countWord(accountCount, 'аккаунт готов', 'аккаунта готовы', 'аккаунтов готовы')} к запуску`
      : 'Аккаунтов пока нет — добавьте первый';
    $('#vault-chip').textContent = accountCount ? `Открыт · ${accountCount}` : 'Открыт · пусто';
    $('#vault-chip').dataset.state = accountCount ? 'ready' : 'warning';
    $('#vault-lock-button').disabled = false;
  } else if (vault.exists) {
    quick.dataset.state = 'locked';
    title.textContent = 'Vault закрыт';
    detail.textContent = 'Нажмите, чтобы открыть';
    $('#vault-chip').textContent = 'Заблокирован';
    $('#vault-chip').dataset.state = 'warning';
    $('#vault-lock-button').disabled = true;
  } else {
    quick.dataset.state = 'locked';
    title.textContent = 'Vault не создан';
    detail.textContent = 'Настройте хранилище';
    $('#vault-chip').textContent = 'Не настроен';
    $('#vault-chip').dataset.state = 'warning';
    $('#vault-lock-button').disabled = true;
  }
  $('#settings-vault-copy').textContent = vault.unlocked
    ? accountCount
      ? `Vault открыт. Аккаунтов: ${accountCount}. Ключ шифрования хранится только в памяти и исчезнет после блокировки Hub.`
      : 'Vault открыт, но аккаунтов пока нет. Добавьте их — один аккаунт на одну строку.'
    : vault.exists
      ? 'Vault закрыт: аккаунты и ключи сейчас недоступны.'
      : 'Создайте мастер-пароль перед импортом аккаунтов.';
  $('#settings-vault-action').textContent = vault.unlocked ? 'Заблокировать' : vault.exists ? 'Разблокировать' : 'Создать';
  $('#export-accounts-button').disabled = !vault.unlocked || state.data.accounts.length === 0;
  $('#capsolver-key').disabled = !vault.unlocked;
  $('#capsolver-save').disabled = !vault.unlocked;
  $('#capsolver-clear').disabled = !vault.unlocked || !vault.capsolver_configured;
  $('#capsolver-status').textContent = !vault.unlocked && vault.exists
    ? 'ЗАКРЫТО'
    : vault.capsolver_configured ? 'СОХРАНЁН' : 'НЕ ДОБАВЛЕН';
  $('#capsolver-status').dataset.state = vault.unlocked && vault.capsolver_configured ? 'ready' : 'warning';
  $('#adspower-key').disabled = !vault.unlocked;
  $('#adspower-save').disabled = !vault.unlocked;
  $('#adspower-clear').disabled = !vault.unlocked || !vault.adspower_api_configured;
  $('#adspower-status').textContent = !vault.unlocked && vault.exists
    ? 'ЗАКРЫТО'
    : vault.adspower_api_configured ? 'СОХРАНЁН' : 'НЕ ДОБАВЛЕН';
  $('#adspower-status').dataset.state = vault.unlocked && vault.adspower_api_configured ? 'ready' : 'warning';
  const referralStatus = $('#referral-network-status');
  const referralButton = $('#referral-open-button');
  const relationshipCount = state.data.accounts.filter((account) => Boolean(account.referrer_account_id)).length;
  referralStatus.textContent = !vault.unlocked && vault.exists
    ? 'ЗАКРЫТО'
    : relationshipCount
      ? `${relationshipCount} ${countWord(relationshipCount, 'связь', 'связи', 'связей')}`
      : 'Нет связей';
  referralStatus.dataset.state = vault.unlocked && relationshipCount ? 'ready' : 'warning';
  referralButton.textContent = relationshipCount ? 'Изменить цепочку' : 'Настроить цепочку';
  renderDock();
}

function coreUpdaterBridge() {
  try {
    const desktop = window.softHubDesktop;
    const updater = desktop?.updater || desktop?.updates;
    return updater && typeof updater === 'object' ? updater : null;
  } catch {
    return null;
  }
}

function normalizeCoreUpdatePhase(value) {
  const phase = String(value || 'idle').trim().toLowerCase().replaceAll('_', '-');
  const aliases = {
    'checking-for-update': 'checking',
    'update-not-available': 'current',
    'not-available': 'current',
    'up-to-date': 'current',
    latest: 'current',
    'update-available': 'available',
    'download-progress': 'downloading',
    downloaded: 'ready',
    'update-downloaded': 'ready',
    cancelled: 'available',
    canceled: 'available',
    disabled: 'unsupported',
    unavailable: 'unsupported',
  };
  const normalized = aliases[phase] || phase;
  return new Set([
    'idle', 'checking', 'current', 'available', 'downloading',
    'ready', 'installing', 'error', 'unsupported',
  ]).has(normalized) ? normalized : 'idle';
}

function normalizeCoreUpdateVersion(value) {
  const version = String(value || '').trim().replace(/^v(?=\d)/i, '');
  return /^[0-9A-Za-z.+-]{1,64}$/.test(version) ? version : '';
}

function collectCoreUpdateNoteText(value, output = [], depth = 0) {
  if (value === null || value === undefined || depth > 3) return output;
  if (Array.isArray(value)) {
    value.forEach((item) => collectCoreUpdateNoteText(item, output, depth + 1));
    return output;
  }
  if (typeof value === 'object') {
    for (const key of ['note', 'body', 'notes', 'releaseNotes', 'release_notes']) {
      if (value[key] !== undefined) collectCoreUpdateNoteText(value[key], output, depth + 1);
    }
    return output;
  }
  output.push(String(value));
  return output;
}

function normalizeCoreUpdateNotes(value) {
  const notes = [];
  for (const source of collectCoreUpdateNoteText(value)) {
    const plain = source
      .replace(/<[^>]*>/g, ' ')
      .replace(/!\[[^\]]*\]\([^)]*\)/g, ' ')
      .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1');
    for (const line of plain.split(/\r?\n|•/)) {
      const cleaned = line
        .replace(/^\s{0,3}#{1,6}\s*/, '')
        .replace(/^\s*(?:[-*+] |\d+[.)]\s*)/, '')
        .replace(/\s+/g, ' ')
        .trim();
      if (!cleaned || notes.includes(cleaned)) continue;
      notes.push(cleaned.length > 220 ? `${cleaned.slice(0, 217).trimEnd()}…` : cleaned);
      if (notes.length === 4) return notes;
    }
  }
  return notes;
}

function coreUpdateErrorKind(value) {
  const message = String(value?.message || value || '').toLowerCase();
  if (/checksum|sha(?:256|512)|signature|integrity|immutable|verif|подпис|провер|защищ.*измен/.test(message)) return 'verification';
  if (/offline|network|internet|github|econn|enotfound|timed?\s*out|http|fetch|request/.test(message)) return 'offline';
  return 'generic';
}

function normalizeCoreUpdatePayload(payload, fallbackPhase = '') {
  const envelope = payload && typeof payload === 'object' ? payload : {};
  const nestedState = envelope.state && typeof envelope.state === 'object' ? envelope.state : null;
  const source = nestedState ? { ...envelope, ...nestedState } : envelope;
  const info = source.updateInfo && typeof source.updateInfo === 'object'
    ? source.updateInfo
    : source.update_info && typeof source.update_info === 'object' ? source.update_info : {};
  const progress = source.progress && typeof source.progress === 'object' ? source.progress : {};
  const rawPhase = source.phase
    || source.status
    || source.event
    || source.type
    || (typeof source.state === 'string' ? source.state : '')
    || fallbackPhase
    || 'idle';
  const next = {
    phase: normalizeCoreUpdatePhase(rawPhase),
  };
  if (source.supported === false) next.phase = 'unsupported';

  const currentVersion = normalizeCoreUpdateVersion(
    source.currentVersion ?? source.current_version ?? source.installedVersion ?? source.installed_version,
  );
  if (currentVersion) next.currentVersion = currentVersion;

  const versionCandidate = source.availableVersion
    ?? source.available_version
    ?? source.latestVersion
    ?? source.latest_version
    ?? info.version
    ?? (['available', 'downloading', 'ready', 'installing'].includes(next.phase) ? source.version : '');
  const availableVersion = normalizeCoreUpdateVersion(versionCandidate);
  if (availableVersion) next.availableVersion = availableVersion;

  const percent = Number(source.percent ?? source.downloadPercent ?? source.download_percent ?? progress.percent);
  if (Number.isFinite(percent)) next.percent = Math.max(0, Math.min(100, percent));
  const transferred = Number(source.transferred ?? source.transferredBytes ?? source.transferred_bytes ?? progress.transferred);
  if (Number.isFinite(transferred)) next.transferred = Math.max(0, transferred);
  const total = Number(source.total ?? source.totalBytes ?? source.total_bytes ?? progress.total);
  if (Number.isFinite(total)) next.total = Math.max(0, total);

  const noteSource = source.releaseNotes ?? source.release_notes ?? info.releaseNotes ?? info.release_notes;
  if (noteSource !== undefined) next.releaseNotes = normalizeCoreUpdateNotes(noteSource);
  const checkedAt = source.checkedAt ?? source.checked_at;
  if (checkedAt && !Number.isNaN(new Date(checkedAt).getTime())) next.checkedAt = new Date(checkedAt).toISOString();
  const installIssue = source.installIssue ?? source.install_issue ?? source.issue;
  if (typeof installIssue === 'string') {
    next.installIssue = installIssue
      .replace(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, ' ')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 280);
  }
  const error = source.error ?? source.message;
  if (next.phase === 'error' || error) next.errorKind = coreUpdateErrorKind(error);
  if (typeof source.message === 'string') {
    next.message = source.message
      .replace(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, ' ')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 280);
  }
  return next;
}

function applyCoreUpdatePayload(payload, fallbackPhase = '') {
  const next = normalizeCoreUpdatePayload(payload, fallbackPhase);
  state.coreUpdate = { ...state.coreUpdate, ...next };
  if (next.phase === 'current') {
    state.coreUpdate.availableVersion = '';
    state.coreUpdate.releaseNotes = [];
    state.coreUpdate.percent = 0;
    state.coreUpdate.transferred = 0;
    state.coreUpdate.total = 0;
  }
  if (['current', 'available'].includes(next.phase) && !next.checkedAt) {
    state.coreUpdate.checkedAt = new Date().toISOString();
  }
  renderCoreUpdateGuide();
  announceCoreUpdateIfReady();
}

function announceCoreUpdateIfReady() {
  const version = state.coreUpdate.availableVersion;
  if (
    state.startupVaultGate
    || state.coreUpdate.phase !== 'available'
    || !version
    || state.coreUpdateNotifiedVersion === version
  ) return;
  state.coreUpdateNotifiedVersion = version;
  toast(`Вышло обновление Soft Hub v${version}. Оно ждёт вас в Настройках.`, 'success', 7600);
}

function formatCoreUpdateBytes(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes) || bytes <= 0) return '';
  const units = ['Б', 'КБ', 'МБ', 'ГБ'];
  let amount = bytes;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit += 1;
  }
  return `${new Intl.NumberFormat('ru-RU', { maximumFractionDigits: amount < 10 && unit > 0 ? 1 : 0 }).format(amount)} ${units[unit]}`;
}

function coreUpdateCheckedLabel(value) {
  const date = new Date(value || '');
  if (Number.isNaN(date.getTime())) return '';
  return new Intl.DateTimeFormat('ru-RU', { hour: '2-digit', minute: '2-digit' }).format(date);
}

function coreUpdatePresentation(phase, update) {
  const currentVersion = update.currentVersion || state.data?.app?.version || '';
  const availableVersion = update.availableVersion || '';
  const currentLabel = currentVersion ? `v${currentVersion}` : 'текущая версия';
  const targetLabel = availableVersion ? `v${availableVersion}` : 'новая версия';
  const checkedAt = coreUpdateCheckedLabel(update.checkedAt);
  const activeCount = Number(state.data?.stats?.active_runs || 0);
  const platform = state.data?.app?.platform;
  const readyCopy = update.installIssue || (platform === 'darwin'
    ? 'Hub закроется и откроет проверенный DMG. Перетащите Soft Hub в Applications и подтвердите замену — ваши данные останутся на месте.'
    : platform === 'win32'
      ? 'Hub закроется и запустит проверенный установщик. Завершите установку — ваши данные останутся на месте.'
      : 'Hub закроется и откроет проверенный установщик. Аккаунты, ключи, софты, история и результаты останутся на месте.');
  const installingCopy = platform === 'darwin'
    ? 'Закрываем Hub и открываем проверенный DMG…'
    : platform === 'win32'
      ? 'Закрываем Hub и запускаем проверенный установщик…'
      : 'Закрываем Hub и запускаем проверенное обновление…';
  const effectivePhase = phase === 'ready' && activeCount > 0 ? 'blocked' : phase;
  const presentations = {
    idle: {
      stateLabel: 'ГОТОВ К ПРОВЕРКЕ',
      title: 'Проверим, есть ли новая версия',
      copy: 'Hub сам посмотрит официальный GitHub. Скачивание и установка начнутся только после вашего разрешения.',
      primary: ['check', 'Проверить обновления', 'ink'],
    },
    checking: {
      stateLabel: 'ИЩЕМ ВЕРСИЮ',
      title: 'Ищем новую версию…',
      copy: `Сейчас стоит ${currentLabel}. Hub только проверяет GitHub — ничего не скачивает и не устанавливает.`,
      primary: ['checking', 'Проверяем…', 'quiet', true],
      busy: true,
    },
    current: {
      stateLabel: 'ВСЁ АКТУАЛЬНО',
      title: 'У вас свежая версия',
      copy: `${currentLabel}${checkedAt ? ` · проверено в ${checkedAt}` : ''}. Можно спокойно продолжать работу.`,
      primary: ['check', 'Проверить ещё раз', 'quiet'],
    },
    available: {
      stateLabel: 'ЕСТЬ ОБНОВЛЕНИЕ',
      title: `Вышла версия ${targetLabel}`,
      copy: 'Скачаем её с официального GitHub, проверим и установим только после вашего подтверждения.',
      primary: ['download', `Скачать ${targetLabel}`, 'ink'],
    },
    downloading: {
      stateLabel: 'СКАЧИВАЕМ',
      title: `Скачиваем ${targetLabel}…`,
      copy: 'Можно продолжать пользоваться Hub. Перед установкой мы отдельно спросим разрешение.',
      primary: ['cancel', 'Отменить загрузку', 'quiet'],
      busy: true,
    },
    ready: {
      stateLabel: update.installIssue ? 'НУЖНО ПОВТОРИТЬ' : 'ГОТОВО',
      title: update.installIssue ? 'Обновление пока не запустилось' : `${targetLabel} готова к установке`,
      copy: readyCopy,
      primary: ['install', 'Установить обновление', 'ink'],
    },
    blocked: {
      stateLabel: 'ЕСТЬ АКТИВНЫЕ ЗАПУСКИ',
      title: `Сейчас ${activeCount} ${countWord(activeCount, 'запуск работает', 'запуска работают', 'запусков работают')}`,
      copy: 'Дайте им закончить — после этого Hub можно будет безопасно обновить.',
      primary: ['activity', 'Посмотреть запуски', 'ink'],
    },
    installing: {
      stateLabel: 'ОБНОВЛЯЕМ',
      title: `Готовим ${targetLabel}…`,
      copy: installingCopy,
      primary: ['installing', 'Обновляем…', 'quiet', true],
      busy: true,
    },
    error: {
      stateLabel: 'НЕ ПОЛУЧИЛОСЬ',
      title: update.errorKind === 'verification' ? 'Файл не прошёл проверку' : 'Обновление остановлено',
      copy: update.message || (update.errorKind === 'verification'
        ? 'Мы остановили установку. Текущая версия и ваши данные не изменились.'
        : update.errorKind === 'offline'
          ? 'Проверьте интернет и попробуйте ещё раз. Hub продолжит работать как обычно.'
          : 'Hub не смог закончить обновление. Текущая версия и ваши данные остались на месте.'),
      primary: [availableVersion ? 'download' : 'check', availableVersion ? 'Скачать ещё раз' : 'Попробовать снова', 'ink'],
      secondary: ['guide', 'Открыть инструкцию'],
    },
    unsupported: {
      stateLabel: 'РУЧНОЙ РЕЖИМ',
      title: 'Встроенное обновление здесь недоступно',
      copy: 'Если это тестовая сборка, так и задумано. Для этой версии можно воспользоваться обычным установщиком.',
      primary: ['guide', 'Открыть инструкцию', 'quiet'],
    },
  };
  return { phase: effectivePhase, ...presentations[effectivePhase] };
}

function renderCoreUpdateNotes(visible) {
  const details = $('#core-update-notes');
  const list = $('#core-update-notes-list');
  const notes = state.coreUpdate.releaseNotes || [];
  const signature = notes.join('\n');
  if (list.dataset.signature !== signature) {
    list.replaceChildren(...notes.map((note) => {
      const item = document.createElement('li');
      item.textContent = note;
      return item;
    }));
    list.dataset.signature = signature;
  }
  details.hidden = !visible || notes.length === 0;
  if (details.hidden) details.open = false;
}

function configureCoreUpdateButton(button, config, secondary = false) {
  if (!config) {
    button.hidden = true;
    button.disabled = false;
    delete button.dataset.coreUpdateAction;
    return;
  }
  const [action, label, tone = 'quiet', disabled = false] = config;
  button.hidden = false;
  button.disabled = disabled;
  button.dataset.coreUpdateAction = action;
  button.textContent = label;
  button.className = `button button--${tone}${!secondary && tone === 'ink' ? ' specular-button' : ''}`;
}

function renderCoreUpdateGuide() {
  if (!state.data?.app) return;
  const update = state.coreUpdate;
  update.currentVersion = update.currentVersion || state.data.app.version;
  const requestedPhase = update.bridgeAvailable === false ? 'unsupported' : update.phase;
  const presentation = coreUpdatePresentation(requestedPhase, update);
  const card = $('#core-update-card');
  card.dataset.state = presentation.phase;
  card.setAttribute('aria-busy', String(Boolean(presentation.busy)));
  setTextIfChanged($('#settings-app-version'), `v${update.currentVersion || state.data.app.version}`);
  setTextIfChanged($('#core-update-state'), presentation.stateLabel);
  $('#core-update-state').dataset.state = presentation.phase;
  setTextIfChanged($('#core-update-title'), presentation.title);
  setTextIfChanged($('#core-update-copy'), presentation.copy);
  configureCoreUpdateButton($('#core-update-primary'), presentation.primary);
  configureCoreUpdateButton($('#core-update-secondary'), presentation.secondary, true);

  const showProgress = presentation.phase === 'downloading';
  const progressWrap = $('#core-update-progress');
  const progressBar = $('#core-update-progress-bar');
  const percent = Math.round(Math.max(0, Math.min(100, Number(update.percent || 0))));
  const transferred = formatCoreUpdateBytes(update.transferred);
  const total = formatCoreUpdateBytes(update.total);
  const progressCopy = transferred && total ? `${percent}% · ${transferred} из ${total}` : `${percent}%`;
  progressWrap.hidden = !showProgress;
  progressBar.value = percent;
  progressBar.textContent = `${percent}%`;
  progressBar.setAttribute('aria-label', `Загрузка обновления: ${percent}%`);
  setTextIfChanged($('#core-update-progress-copy'), progressCopy);
  renderCoreUpdateNotes(['available', 'downloading', 'ready', 'blocked'].includes(presentation.phase));
  const updateVisible = ['available', 'downloading', 'ready', 'blocked'].includes(presentation.phase);
  const settingsNav = $('.nav-item[data-view="settings"]');
  const updateBadge = $('#nav-core-update');
  settingsNav.dataset.updateAvailable = String(updateVisible);
  settingsNav.setAttribute('aria-label', updateVisible && update.availableVersion
    ? `Настройки — доступно обновление v${update.availableVersion}`
    : 'Настройки');
  updateBadge.textContent = updateVisible ? 'NEW' : '';

  const platform = state.data.app.platform;
  $('#settings-update-platform').textContent = platform === 'darwin'
    ? 'Откройте новый DMG, перетащите Soft Hub в Applications и подтвердите замену.'
    : platform === 'win32'
      ? 'Запустите новый EXE поверх текущей установки. Другую папку выбирать не нужно.'
      : 'Откройте установщик для своей системы и замените текущую версию приложения.';
}

function setCoreUpdateFailure(error) {
  applyCoreUpdatePayload({
    phase: 'error',
    error: error instanceof Error ? error.message : String(error || ''),
  });
}

function openCoreUpdateGuide() {
  const guide = $('#core-update-guide');
  guide.open = true;
  $('summary', guide)?.focus({ preventScroll: true });
  guide.scrollIntoView({ block: 'nearest', behavior: 'auto' });
}

function openRunsBlockingCoreUpdate(origin) {
  openActivityPanel('active', origin || $('#core-update-primary'));
}

async function checkCoreUpdate() {
  const updater = coreUpdaterBridge();
  if (!updater || typeof updater.check !== 'function') {
    state.coreUpdate.bridgeAvailable = false;
    applyCoreUpdatePayload({ phase: 'unsupported' });
    return;
  }
  state.coreUpdate.bridgeAvailable = true;
  applyCoreUpdatePayload({}, 'checking');
  try {
    const payload = await updater.check();
    if (payload && typeof payload === 'object') applyCoreUpdatePayload(payload);
  } catch (error) {
    setCoreUpdateFailure(error);
  }
}

async function downloadCoreUpdate() {
  const updater = coreUpdaterBridge();
  if (!updater || typeof updater.download !== 'function') {
    state.coreUpdate.bridgeAvailable = false;
    applyCoreUpdatePayload({ phase: 'unsupported' });
    return;
  }
  applyCoreUpdatePayload({}, 'downloading');
  try {
    const payload = await updater.download();
    if (payload && typeof payload === 'object') applyCoreUpdatePayload(payload);
  } catch (error) {
    setCoreUpdateFailure(error);
  }
}

async function cancelCoreUpdateDownload() {
  const updater = coreUpdaterBridge();
  const cancel = updater?.cancel || updater?.cancelDownload;
  if (typeof cancel !== 'function') {
    setCoreUpdateFailure(new Error('Загрузка не поддерживает отмену'));
    return;
  }
  try {
    const payload = await cancel.call(updater);
    applyCoreUpdatePayload(payload && typeof payload === 'object' ? payload : {}, 'available');
  } catch (error) {
    setCoreUpdateFailure(error);
  }
}

async function installCoreUpdate(origin) {
  const activeCount = Number(state.data?.stats?.active_runs || 0);
  if (activeCount > 0) {
    openRunsBlockingCoreUpdate(origin);
    return;
  }
  const version = state.coreUpdate.availableVersion;
  const platform = state.data?.app?.platform;
  const installMessage = platform === 'darwin'
    ? 'Hub закроется и откроет проверенный DMG. Перетащите Soft Hub в Applications и подтвердите замену. Аккаунты, ключи, софты, история и результаты останутся на месте.'
    : platform === 'win32'
      ? 'Hub закроется и запустит проверенный установщик. Завершите установку в открывшемся окне — ваши данные останутся на месте.'
      : 'Hub закроется и откроет проверенный установщик. Ваши данные останутся на месте.';
  const confirmed = await requestDestructiveConfirmation({
    title: `Установить Soft Hub${version ? ` v${version}` : ''}?`,
    message: installMessage,
    confirmLabel: platform === 'darwin' ? 'Закрыть Hub и открыть DMG' : 'Запустить установщик',
    tone: 'update',
  });
  if (!confirmed) return;
  await refresh();
  if (Number(state.data?.stats?.active_runs || 0) > 0) {
    openRunsBlockingCoreUpdate(origin);
    return;
  }
  const updater = coreUpdaterBridge();
  if (!updater || typeof updater.install !== 'function') {
    state.coreUpdate.bridgeAvailable = false;
    applyCoreUpdatePayload({ phase: 'unsupported' });
    return;
  }
  applyCoreUpdatePayload({}, 'installing');
  try {
    const payload = await updater.install();
    if (payload && typeof payload === 'object') applyCoreUpdatePayload(payload);
    // A recoverable refusal can lock Vault in the main process. Refresh now so
    // protected renderer state is purged and the unlock gate is immediately
    // consistent with the core instead of waiting for background polling.
    if (state.coreUpdate.phase !== 'installing') await refresh();
  } catch (error) {
    setCoreUpdateFailure(error);
    await refresh();
  }
}

function handleCoreUpdateAction(event) {
  const button = event.currentTarget;
  const action = button.dataset.coreUpdateAction;
  if (action === 'check') void checkCoreUpdate();
  else if (action === 'download') void downloadCoreUpdate();
  else if (action === 'cancel') void cancelCoreUpdateDownload();
  else if (action === 'install') void installCoreUpdate(button);
  else if (action === 'activity') openRunsBlockingCoreUpdate(button);
  else if (action === 'guide') openCoreUpdateGuide();
}

function subscribeToCoreUpdateState(updater) {
  const subscribe = updater?.onStateChanged || updater?.onStateChange;
  if (typeof subscribe !== 'function') return;
  const listener = (...values) => {
    let payload = null;
    for (let index = values.length - 1; index >= 0; index -= 1) {
      if (values[index] && typeof values[index] === 'object') {
        payload = values[index];
        break;
      }
    }
    if (payload) applyCoreUpdatePayload(payload);
  };
  const unsubscribe = subscribe.call(updater, listener);
  if (typeof unsubscribe === 'function') state.coreUpdateUnsubscribe = unsubscribe;
}

async function initializeCoreUpdater() {
  if (state.coreUpdateAutoCheckStarted) return;
  state.coreUpdateAutoCheckStarted = true;
  const updater = coreUpdaterBridge();
  if (!updater || typeof updater.check !== 'function') {
    state.coreUpdate.bridgeAvailable = false;
    applyCoreUpdatePayload({ phase: 'unsupported' });
    return;
  }
  state.coreUpdate.bridgeAvailable = true;
  subscribeToCoreUpdateState(updater);
  try {
    if (typeof updater.getState === 'function') {
      const payload = await updater.getState();
      if (payload && typeof payload === 'object') applyCoreUpdatePayload(payload);
    }
  } catch (error) {
    setCoreUpdateFailure(error);
  }
  if (!['available', 'downloading', 'ready', 'installing'].includes(state.coreUpdate.phase)) {
    await checkCoreUpdate();
  }
  if (state.coreUpdateCheckTimer === null) {
    state.coreUpdateCheckTimer = window.setInterval(() => {
      if (document.visibilityState !== 'visible') return;
      if (['checking', 'downloading', 'ready', 'installing'].includes(state.coreUpdate.phase)) return;
      void checkCoreUpdate();
    }, CORE_UPDATE_CHECK_INTERVAL_MS);
  }
}

function recheckCoreUpdateIfDue() {
  if (state.coreUpdate.bridgeAvailable !== true) return;
  if (['checking', 'downloading', 'ready', 'installing'].includes(state.coreUpdate.phase)) return;
  const checkedAt = new Date(state.coreUpdate.checkedAt || '').getTime();
  if (!Number.isFinite(checkedAt) || Date.now() - checkedAt >= CORE_UPDATE_CHECK_INTERVAL_MS) {
    void checkCoreUpdate();
  }
}

function renderDock() {
  if (!state.data) return;
  const activeCount = Number(state.data.stats.active_runs || 0);
  const attentionCount = Number(state.data.stats.attention_runs || 0);
  const presence = $('.dock-presence');
  presence.dataset.state = attentionCount ? 'attention' : activeCount ? 'active' : 'idle';
  const presenceCopy = attentionCount
    ? `${attentionCount} ${countWord(attentionCount, 'ошибка', 'ошибки', 'ошибок')}`
    : activeCount
      ? `${activeCount} ${countWord(activeCount, 'задача', 'задачи', 'задач')} ${activeCount === 1 ? 'работает' : 'работают'}`
      : 'Очередь свободна';
  setTextIfChanged($('#dock-presence-copy'), presenceCopy);
  presence.setAttribute('aria-label', `Открыть запуски: ${presenceCopy}`);
  $('#dock-run-count').textContent = state.batchModuleIds.size || '';
  $('#dock-live-count').textContent = activeCount || '';
  $('#dock-attention-count').textContent = attentionCount || '';
}

function renderMetrics() {
  const { stats } = state.data;
  const locked = state.data.vault.exists && !state.data.vault.unlocked;
  $('#metric-modules').textContent = stats.modules;
  $('#metric-accounts').textContent = locked ? '—' : stats.accounts;
  $('#metric-active').textContent = stats.active_runs;
  $('#metric-results').textContent = locked ? '—' : stats.results;
  $('[data-nav-count="modules"]').textContent = stats.modules || '';
  $('[data-nav-count="accounts"]').textContent = locked ? '' : stats.accounts || '';
  $('[data-nav-count="attention"]').textContent = stats.attention_runs || '';
  $('[data-nav-count="nft"]').textContent = catalogModules('nft').length || '';
  $('[data-nav-count="testnets"]').textContent = catalogModules('testnet').length || '';
  const patchCount = state.patchFeed.filter((patch) => patch.installable === true).length;
  $('[data-nav-count="patches"]').textContent = patchCount || '';
  $('#live-pill-text').textContent = stats.active_runs
    ? `${stats.active_runs} ${stats.active_runs === 1 ? 'задача работает' : 'задачи работают'}`
    : 'Система готова';
  const commandTitle = $('#command-title');
  const nextCommandTitle = stats.active_runs
    ? 'Софты уже работают.'
    : stats.modules
      ? 'Все софты под рукой.'
      : 'Добавьте первый софт.';
  if (commandTitle.textContent !== nextCommandTitle) {
    commandTitle.textContent = nextCommandTitle;
    replayBlurText(commandTitle);
  }
  $('#command-detail').textContent = 'Приватники и пароли остаются на этом компьютере. Каждый софт работает отдельно.';
  const onboarding = [
    { id: 'vault', done: state.data.vault.unlocked, action: 'vault', label: state.data.vault.exists ? 'Разблокировать Vault' : 'Создать Vault' },
    { id: 'accounts', done: !locked && stats.accounts > 0, action: 'import', label: 'Импортировать аккаунты' },
    { id: 'modules', done: stats.modules > 0, action: 'patch', label: 'Установить первый патч' },
    { id: 'run', done: state.data.runs.length > 0, action: 'run', label: 'Запустить первый софт' },
  ];
  const next = onboarding.find((step) => !step.done);
  $('#overview-onboarding').hidden = !next;
  $('#view-overview').dataset.mode = next ? 'onboarding' : 'operational';
  onboarding.forEach((step) => {
    const item = $(`[data-onboarding-step="${step.id}"]`);
    item.classList.toggle('is-done', step.done);
    item.classList.toggle('is-current', next?.id === step.id);
  });
  if (next) {
    $('#onboarding-action').dataset.onboardingAction = next.action;
    $('#onboarding-action').textContent = next.label;
  }
}

function emptyRunMarkup() {
  if (state.data?.vault.exists && !state.data.vault.unlocked) {
    return '<div class="empty-state"><span class="empty-glyph">••</span><h3>История скрыта, пока Vault закрыт</h3><p>Разблокируйте Vault, чтобы увидеть аккаунты и прошлые запуски.</p></div>';
  }
  return '<div class="empty-state"><span class="empty-glyph">04</span><h3>Запусков пока нет</h3><p>После первого запуска здесь появятся прогресс и результат.</p></div>';
}

function runRow(run, className = 'run-row') {
  const progress = Math.round(Number(run.progress || 0) * 100);
  const concurrency = Math.max(1, Number(run.account_concurrency || 1));
  return `
    <button class="${className}" type="button" data-open-run="${escapeHtml(run.id)}">
      <span class="run-status-dot" data-status="${escapeHtml(run.status)}"></span>
      <span class="run-primary"><strong>${escapeHtml(run.module_name)}</strong><small>${escapeHtml(activityActionName(run))} · ${escapeHtml(shortAddress(run.id))}</small></span>
      <span class="run-secondary"><strong>${escapeHtml(run.account_count)} акк.</strong><small>${concurrency > 1 ? `${concurrency} потоков · ` : ''}${escapeHtml(relativeTime(run.requested_at))}</small></span>
      <span class="mini-progress"><progress max="100" value="${progress}">${progress}%</progress><small>${progress}%</small></span>
      <span class="status-label" data-status="${escapeHtml(run.status)}">${escapeHtml(statusNames[run.status] || run.status)}</span>
    </button>`;
}

function renderOverviewRuns() {
  const root = $('#overview-runs');
  const runs = state.data.runs.slice(0, 5);
  root.innerHTML = runs.length ? runs.map((run) => runRow(run)).join('') : emptyRunMarkup();
  decorateAnimatedList(root);
}

function renderOverviewModules() {
  const modules = state.data.modules;
  const root = $('#overview-modules');
  root.innerHTML = modules.length
    ? modules.slice(0, 5).map((module) => `
      <div class="fleet-item ${accentClass(module)}">
        ${moduleIconMarkup(module)}
        <span><strong>${escapeHtml(moduleDisplayName(module))}</strong><small>v${escapeHtml(module.version)}</small></span>
        <span class="health-word" data-health="${escapeHtml(module.health)}">${module.health === 'ready' ? 'ГОТОВ' : 'НАСТРОИТЬ'}</span>
      </div>`).join('')
    : '<div class="empty-state"><p>Установленных софтов пока нет.</p></div>';
  decorateAnimatedList(root);
  const ready = modules.filter((module) => module.enabled && module.health === 'ready').length;
  $('#fleet-score').textContent = modules.length ? `${Math.round((ready / modules.length) * 100)}%` : '—';
}

function renderSoftware() {
  return renderSoftwareLibrary();
}

function softwareCardMarkup(module, moduleIndex, { scope = 'all', showCatalogChips = false } = {}) {
  const manifest = module.manifest;
  const risk = manifest.permissions.financial_risk;
  const actionCount = manifest.actions.length;
  const batchReady = module.enabled && module.health === 'ready';
  const selected = state.batchModuleIds.has(module.id);
  const activeCount = state.data.runs.filter((run) => run.module_id === module.id && ACTIVE_RUN_STATUSES.has(run.status)).length;
  const safeScope = String(scope).replace(/[^a-z0-9_-]/gi, '-') || 'all';
  const controlId = `${safeScope}-software-control-${moduleIndex}`;
  const toggleTitle = module.enabled ? 'Выключить софт' : 'Включить софт';
  const toggleDetail = module.enabled ? 'Новые запуски станут недоступны. Текущие продолжат работу' : 'Софт снова появится среди доступных для запуска';
  return `
    <article class="software-card border-glow ${accentClass(module)} ${selected ? 'is-selected' : ''}" data-software-id="${escapeHtml(module.id)}">
      ${moduleCoverMarkup(module)}
      <div class="software-card-head">
        <div class="software-card-identity">${moduleIconMarkup(module)}</div>
        <div class="software-card-controls">
          <span class="module-version">v${escapeHtml(module.version)}</span>
          <label class="card-select" title="${batchReady ? 'Добавить в пачку' : 'Сначала включите и подготовьте софт'}">
            <input type="checkbox" data-batch-module="${escapeHtml(module.id)}" data-batch-scope="${escapeHtml(scope)}" aria-label="Выбрать ${escapeHtml(moduleDisplayName(module))} для пакетного запуска" ${selected ? 'checked' : ''} ${batchReady ? '' : 'disabled'} />
            <span>${iconMarkup('check')}</span>
          </label>
        </div>
      </div>
      <h3>${escapeHtml(moduleDisplayName(module))}</h3>
      <p>${escapeHtml(moduleDisplayDescription(module))}</p>
      <div class="software-meta">
        ${showCatalogChips ? catalogSectionChips(module) : ''}
        <span class="risk-chip" data-risk="${escapeHtml(risk)}">${escapeHtml(riskNames[risk] || risk)}</span>
        <span class="risk-chip">${actionCount} ${countWord(actionCount, 'ДЕЙСТВИЕ', 'ДЕЙСТВИЯ', 'ДЕЙСТВИЙ')}</span>
        ${activeCount ? `<span class="status-chip" data-state="ready">${activeCount} ${activeCount === 1 ? 'РАБОТАЕТ' : 'В РАБОТЕ'}</span>` : ''}
        <span class="status-chip" data-state="${module.health === 'ready' ? 'ready' : 'warning'}">${module.health === 'ready' ? 'ГОТОВ' : 'НУЖНА НАСТРОЙКА'}</span>
      </div>
      <div class="software-actions">
        ${module.health === 'ready'
          ? `<button class="button button--ink specular-button" type="button" data-run-module="${escapeHtml(module.id)}" ${module.enabled ? '' : 'disabled'}>${iconMarkup('play')} ${module.enabled ? 'Запустить' : 'Выключен'}</button>`
          : `<button class="button button--acid specular-button" type="button" data-prepare-module="${escapeHtml(module.id)}">${iconMarkup('patch')} Подготовить</button>`}
        <span class="card-action-control">
          <button class="mini-button" type="button" data-toggle-module="${escapeHtml(module.id)}" aria-label="${toggleTitle}: ${escapeHtml(moduleDisplayName(module))}" aria-describedby="${controlId}-toggle-tip">${iconMarkup('power')}</button>
          <span id="${controlId}-toggle-tip" class="card-action-tooltip" role="tooltip"><strong>${toggleTitle}</strong><span>${toggleDetail}</span></span>
        </span>
        <span class="card-action-control card-action-control--end">
          <button class="mini-button mini-button--danger" type="button" data-delete-module="${escapeHtml(module.id)}" aria-label="Удалить софт: ${escapeHtml(moduleDisplayName(module))}" aria-describedby="${controlId}-delete-tip">${iconMarkup('trash')}</button>
          <span id="${controlId}-delete-tip" class="card-action-tooltip" role="tooltip"><strong>Удалить софт</strong><span>Удалим код и окружение, а запуски и результаты оставим</span></span>
        </span>
      </div>
    </article>`;
}

function renderSoftwareLibrary() {
  const root = $('#software-grid');
  const modules = state.data.modules;
  const installedIds = new Set(modules.map((module) => module.id));
  for (const moduleId of state.batchModuleIds) {
    if (!installedIds.has(moduleId)) state.batchModuleIds.delete(moduleId);
  }
  if (!modules.length) {
    root.innerHTML = `
      <div class="empty-state panel"><span class="empty-glyph">02</span><h3>Софтов пока нет</h3>
      <p>Установите готовый пакет с компьютера или GitHub.</p>
      <button class="button button--acid specular-button" type="button" data-install-trigger>Установить первый пакет</button></div>`;
    bindInstallTriggers(root);
    updateBatchControls();
    return;
  }
  root.innerHTML = modules.map((module, moduleIndex) => softwareCardMarkup(
    module,
    moduleIndex,
    { scope: 'all', showCatalogChips: true },
  )).join('');
  decorateAnimatedList(root);
  updateBatchControls();
}

function updateBatchControls() {
  const count = state.batchModuleIds.size;
  const bar = $('#software-batch-bar');
  if (!bar) return;
  bar.dataset.hasSelection = String(count > 0);
  $('#batch-selection-title').textContent = count
    ? `Выбрано: ${count}`
    : 'Пакетный запуск';
  $('#batch-selection-copy').textContent = count
    ? 'Проверьте действия — и запустим выбранные софты параллельно.'
    : 'Отметьте софты галочками, чтобы запустить их одной пачкой.';
  $('#batch-clear').hidden = count === 0;
  $('#batch-open-button').disabled = count === 0;
  $('#batch-open-button span').textContent = count ? `Запустить ${count}` : 'Запустить выбранные';
  const dockCount = $('#dock-run-count');
  if (dockCount) dockCount.textContent = count || '';
  const dockBatch = $('[data-quick-action="batch"]');
  if (dockBatch) dockBatch.setAttribute('aria-label', count ? `Проверить и запустить выбранные софты: ${count}` : 'Выбрать софты для пакетного запуска');
}

function catalogSelectedModules(section) {
  return catalogModules(section).filter((module) => state.batchModuleIds.has(module.id));
}

function syncBatchSelectionSurface() {
  $$('input[data-batch-module]').forEach((checkbox) => {
    const selected = state.batchModuleIds.has(checkbox.dataset.batchModule);
    checkbox.checked = selected;
    checkbox.closest('.software-card')?.classList.toggle('is-selected', selected);
  });
  updateBatchControls();
  updateCatalogBatchControls();
  renderDock();
}

function beginCatalogBatchSelection(section) {
  if (state.catalogBatchScope === section) return;
  state.catalogBatchScope = section;
  state.batchIdempotencyKey = null;
  state.batchModuleIds.clear();
  state.batchActionIds.clear();
}

function updateCatalogBatchControls() {
  if (!state.data) return;
  for (const section of Object.keys(catalogSectionMeta)) {
    const count = catalogSelectedModules(section).length;
    const bar = $(`[data-catalog-batch-bar="${section}"]`);
    if (!bar) continue;
    bar.dataset.hasSelection = String(count > 0);
    $(`[data-catalog-batch-title="${section}"]`).textContent = count
      ? `Выбрано: ${count}`
      : section === 'nft' ? 'Пакетный запуск NFT' : 'Пакетный запуск тестнетов';
    $(`[data-catalog-batch-copy="${section}"]`).textContent = count
      ? `В пачке только ${catalogSectionMeta[section].plural}. Проверьте действия перед стартом.`
      : section === 'nft'
        ? 'Отметьте нужные карточки — запустим только NFT-софты.'
        : 'Отметьте нужные карточки — запустим выбранные тестнет-софты.';
    const clear = $(`[data-catalog-clear-selection="${section}"]`);
    const open = $(`[data-catalog-open-batch="${section}"]`);
    clear.hidden = count === 0;
    open.disabled = count === 0;
    $('span', open).textContent = count ? `Запустить ${count}` : 'Запустить выбранные';
  }
}

function catalogEmptyMarkup(section, { query = '', kind = 'software' } = {}) {
  const meta = catalogSectionMeta[section];
  if (kind === 'locked') {
    return '<div class="catalog-inline-empty"><span aria-hidden="true">••</span><div><strong>Результаты скрыты, пока Vault закрыт</strong><small>Разблокируйте Vault — история этого раздела появится на месте.</small></div></div>';
  }
  if (kind === 'runs') {
    return '<div class="catalog-inline-empty"><span aria-hidden="true">00</span><div><strong>Запусков пока нет</strong><small>После первого старта здесь появится живой прогресс.</small></div></div>';
  }
  if (kind === 'results') {
    return '<div class="catalog-inline-empty"><span aria-hidden="true">00</span><div><strong>Итогов пока нет</strong><small>Они появятся после первого завершённого запуска.</small></div></div>';
  }
  if (kind === 'reports') {
    return '<div class="catalog-inline-empty"><span aria-hidden="true">00</span><div><strong>Отчётов пока нет</strong><small>Софт с режимом парсинга соберёт здесь таблицу по кошелькам.</small></div></div>';
  }
  if (query) {
    return `<div class="empty-state panel catalog-software-empty"><span class="empty-glyph">⌕</span><h3>Здесь пока пусто</h3><p>${escapeHtml(meta.searchEmptyCopy)}</p><button class="button button--quiet" type="button" data-catalog-clear-search="${escapeHtml(section)}">Сбросить поиск</button></div>`;
  }
  return `<div class="empty-state panel catalog-software-empty"><span class="empty-glyph">${section === 'nft' ? 'NFT' : 'TN'}</span><h3>${escapeHtml(meta.emptyTitle)}</h3><p>${escapeHtml(meta.emptyCopy)}</p><button class="button button--acid specular-button" type="button" data-catalog-open-patches>Перейти к патчам</button></div>`;
}

function catalogResultRow(result) {
  const tone = resultTone(result.status);
  const icon = tone === 'success' ? 'check' : tone === 'attention' ? 'alert' : 'history';
  const tag = result.run_id ? 'button' : 'div';
  const action = result.run_id ? ` type="button" data-open-run="${escapeHtml(result.run_id)}"` : '';
  return `<${tag} class="catalog-result-row" data-tone="${tone}"${action}>
    <span class="catalog-result-icon" aria-hidden="true">${iconMarkup(icon)}</span>
    <span><strong>${escapeHtml(result.title || 'Результат')}</strong><small>${escapeHtml(result.account_label || 'Общий итог')} · ${escapeHtml(resultStatusLabel(result.status))}</small></span>
    <time datetime="${escapeHtml(result.created_at || '')}">${escapeHtml(relativeTime(result.created_at))}</time>
  </${tag}>`;
}

function catalogReportRow(report, section) {
  const active = ACTIVE_RUN_STATUSES.has(report.run_status);
  const status = active ? 'ИДЁТ СЕЙЧАС' : report.run_status === 'succeeded' ? 'ГОТОВ' : 'ЕСТЬ ИТОГ';
  return `<button class="catalog-report-row" type="button" data-open-catalog-report="${escapeHtml(report.run_id)}" data-report-section="${escapeHtml(section)}">
    <span class="catalog-report-mark" aria-hidden="true">${iconMarkup('search')}</span>
    <span><strong>${escapeHtml(resultReportName(report))}</strong><small>${escapeHtml(resultReportActionName(report))} · ${escapeHtml(fullDateTime(report.finished_at || report.requested_at) || 'время не указано')}</small></span>
    <em data-state="${active ? 'active' : 'ready'}">${status}</em>
  </button>`;
}

function renderCatalogWorkspace(section) {
  const root = $(`[data-catalog-workspace="${section}"]`);
  if (!root || !state.data) return;
  const allModules = catalogModules(section);
  const search = $(`[data-catalog-search="${section}"]`);
  const query = String(search?.value || '').trim().toLowerCase();
  const modules = allModules.filter((module) => !query || [
    moduleDisplayName(module),
    moduleDisplayDescription(module),
    ...(module.manifest?.actions || []).flatMap((action) => [action.name, action.description]),
  ].some((value) => String(value || '').toLowerCase().includes(query)));
  const runs = (state.data.runs || []).filter((run) => recordBelongsToCatalog(run, section));
  const orderedRuns = [
    ...runs.filter((run) => ACTIVE_RUN_STATUSES.has(run.status)),
    ...runs.filter((run) => !ACTIVE_RUN_STATUSES.has(run.status)),
  ].slice(0, 5);
  const locked = state.data.vault.exists && !state.data.vault.unlocked;
  const results = locked ? [] : (state.data.results || []).filter((result) => recordBelongsToCatalog(result, section)).slice(0, 5);
  const reports = locked ? [] : state.resultReports.filter((report) => recordBelongsToCatalog(report, section)).slice(0, 4);
  const ready = allModules.filter((module) => module.enabled && module.health === 'ready').length;
  const active = runs.filter((run) => ACTIVE_RUN_STATUSES.has(run.status)).length;
  const metrics = [
    { label: section === 'nft' ? 'NFT-софты' : 'Тестнеты', value: allModules.length, note: 'в этом разделе' },
    { label: 'Готовы', value: ready, note: 'можно запускать' },
    { label: 'Сейчас работают', value: active, note: active ? 'видно в нижней панели' : 'очередь свободна' },
    { label: 'Свежие итоги', value: locked ? '—' : results.length, note: locked ? 'Vault закрыт' : 'в быстрой ленте' },
  ];
  $('[data-catalog-metrics]', root).innerHTML = metrics.map((metric) => `<article><small>${escapeHtml(metric.label)}</small><strong>${escapeHtml(metric.value)}</strong><span>${escapeHtml(metric.note)}</span></article>`).join('');
  const softwareRoot = $('[data-catalog-software-grid]', root);
  softwareRoot.innerHTML = modules.length
    ? modules.map((module, index) => softwareCardMarkup(module, index, { scope: section })).join('')
    : catalogEmptyMarkup(section, { query });
  const runsRoot = $('[data-catalog-runs]', root);
  runsRoot.innerHTML = locked
    ? catalogEmptyMarkup(section, { kind: 'locked' })
    : orderedRuns.length ? orderedRuns.map((run) => runRow(run)).join('') : catalogEmptyMarkup(section, { kind: 'runs' });
  const resultsRoot = $('[data-catalog-results]', root);
  resultsRoot.innerHTML = locked
    ? catalogEmptyMarkup(section, { kind: 'locked' })
    : results.length ? results.map(catalogResultRow).join('') : catalogEmptyMarkup(section, { kind: 'results' });
  const reportsRoot = $('[data-catalog-reports]', root);
  reportsRoot.innerHTML = locked
    ? catalogEmptyMarkup(section, { kind: 'locked' })
    : state.resultReportsLoading && !state.resultReportsLoaded
      ? '<div class="catalog-inline-empty" data-loading="true"><span aria-hidden="true">••</span><div><strong>Собираем отчёты…</strong><small>Это займёт пару секунд.</small></div></div>'
      : reports.length ? reports.map((report) => catalogReportRow(report, section)).join('') : catalogEmptyMarkup(section, { kind: 'reports' });
  decorateAnimatedList(softwareRoot);
  decorateAnimatedList(runsRoot);
}

function renderCatalogWorkspaces() {
  if (!state.data) return;
  renderCatalogWorkspace('nft');
  renderCatalogWorkspace('testnet');
  updateCatalogBatchControls();
}

function selectCatalogReady(section) {
  beginCatalogBatchSelection(section);
  for (const module of catalogModules(section)) {
    if (module.enabled && module.health === 'ready') state.batchModuleIds.add(module.id);
  }
  syncBatchSelectionSurface();
}

function clearCatalogSelection(section) {
  for (const module of catalogModules(section)) state.batchModuleIds.delete(module.id);
  state.batchIdempotencyKey = null;
  state.batchActionIds.clear();
  syncBatchSelectionSurface();
}

function openCatalogBatch(section) {
  const selected = new Set(catalogSelectedModules(section).map((module) => module.id));
  for (const moduleId of state.batchModuleIds) {
    if (!selected.has(moduleId)) state.batchModuleIds.delete(moduleId);
  }
  state.catalogBatchScope = section;
  updateBatchControls();
  updateCatalogBatchControls();
  openBatchRunModal();
}

function setResultCatalogFilter(section = 'all') {
  state.resultCatalogFilter = catalogSectionMeta[section] ? section : 'all';
  const banner = $('#result-catalog-filter');
  if (!banner) return;
  banner.hidden = state.resultCatalogFilter === 'all';
  if (!banner.hidden) $('#result-catalog-filter-copy').textContent = `Показаны только результаты: ${catalogSectionMeta[state.resultCatalogFilter].label}`;
}

async function openCatalogReport(runId, section) {
  if (!runId) return;
  setResultCatalogFilter(section);
  state.selectedResultReportId = runId;
  showView('results');
  await loadSelectedResultReport(runId);
}

function accountReferrerLabel(account) {
  if (account?.referrer_account_id) return account.referrer_label || 'Аккаунт в Hub';
  return '—';
}

function renderAccounts() {
  if (!state.data) return;
  const locked = state.data.vault.exists && !state.data.vault.unlocked;
  const query = ($('#account-search').value || '').trim().toLowerCase();
  const accounts = state.data.accounts.filter((account) =>
    [account.label, account.evm_address, account.proxy_label, account.email_label, account.referrer_label]
      .some((value) => String(value || '').toLowerCase().includes(query)),
  );
  const tbody = $('#accounts-table');
  tbody.innerHTML = accounts.length ? accounts.map((account, index) => `
    <tr>
      <td><span class="profile-cell"><i class="profile-seed">${String(index + 1).padStart(2, '0')}</i>${escapeHtml(account.label)}</span></td>
      <td class="mono-cell" title="${escapeHtml(account.evm_address)}">${escapeHtml(shortAddress(account.evm_address))}</td>
      <td class="mono-cell">${escapeHtml(account.proxy_label)}</td>
      <td>${escapeHtml(account.email_label)}</td>
      <td><span class="credential-state" data-configured="${account.twitter_configured ? 'true' : 'false'}">${account.twitter_configured ? 'Настроен' : '—'}</span></td>
      <td><span class="credential-state" data-configured="${account.adspower_configured ? 'true' : 'false'}">${account.adspower_configured ? 'Привязан' : '—'}</span></td>
      <td><span class="credential-state" data-configured="${account.referrer_account_id ? 'true' : 'false'}">${escapeHtml(accountReferrerLabel(account))}</span></td>
      <td><button class="row-menu" type="button" data-delete-account="${escapeHtml(account.id)}" title="Удалить аккаунт" aria-label="Удалить аккаунт ${escapeHtml(account.label)}">×</button></td>
    </tr>`).join('') : state.data.accounts.length
      ? '<tr class="table-search-empty"><td colspan="8"><strong>Ничего не найдено</strong><span>Попробуйте другой label, адрес или почту.</span><button class="text-button" type="button" data-clear-account-search>Сбросить поиск</button></td></tr>'
      : '';
  decorateAnimatedList(tbody);
  $('#account-count-label').textContent = locked ? 'Vault закрыт' : `${accounts.length} ${countWord(accounts.length, 'аккаунт', 'аккаунта', 'аккаунтов')}`;
  const empty = state.data.accounts.length === 0;
  $('#accounts-locked').hidden = !locked;
  $('#accounts-empty').hidden = locked || !empty;
  $('.data-table-wrap').hidden = locked || empty;
}

function referralProfileMark(account, index) {
  const label = String(account.label || '').trim();
  const mark = label.split(/\s+/).map((part) => part[0]).join('').slice(0, 2).toUpperCase();
  return mark || String(index + 1).padStart(2, '0');
}

function referralTopologyRevision() {
  return String(
    state.data?.referral_topology?.revision
    || state.data?.referral_topology_revision
    || state.data?.vault?.referral_topology_revision
    || '',
  );
}

function accountById(accountId) {
  return state.data?.accounts.find((account) => account.id === accountId);
}

function referralTopologySnapshot({ validate = true } = {}) {
  const accounts = state.data?.accounts || [];
  const parentByChild = new Map(accounts.map((account) => [
    account.id,
    String(state.referralDraft.get(account.id) || ''),
  ]));
  if (state.referralDraft.size !== accounts.length || accounts.some((account) => !state.referralDraft.has(account.id))) {
    throw new Error('На карте должен быть каждый аккаунт — без дублей');
  }

  const childrenByParent = new Map(accounts.map((account) => [account.id, []]));
  parentByChild.forEach((parentId, childId) => {
    if (!parentId) return;
    if (!childrenByParent.has(parentId)) throw new Error('На карте указан аккаунт, который уже удалён');
    if (parentId === childId) throw new Error('Аккаунт не может пригласить сам себя');
    childrenByParent.get(parentId).push(childId);
  });

  const depths = new Map();
  if (validate) {
    accounts.forEach((account) => {
      if (depths.has(account.id)) return;
      const path = [];
      const positions = new Map();
      let current = account.id;
      while (current && !depths.has(current)) {
        if (positions.has(current)) {
          const cycleStart = positions.get(current);
          const cycle = [...path.slice(cycleStart), current]
            .map((id) => accountById(id)?.label || id)
            .join(' → ');
          throw new Error(`Цепочка замыкается в круг: ${cycle}`);
        }
        positions.set(current, path.length);
        path.push(current);
        current = parentByChild.get(current) || '';
      }
      let depth = current ? depths.get(current) : -1;
      while (path.length) {
        depth += 1;
        depths.set(path.pop(), depth);
      }
    });
  }

  const relationships = accounts.map((account) => ({
    child_account_id: account.id,
    parent_account_id: parentByChild.get(account.id) || null,
  }));
  return {
    relationships,
    parentByChild,
    childrenByParent,
    depths,
    roots: relationships.filter((item) => !item.parent_account_id).length,
    links: relationships.filter((item) => Boolean(item.parent_account_id)).length,
    maxDepth: Math.max(0, ...depths.values()),
  };
}

function referralDescendants(accountId, childrenByParent) {
  const descendants = new Set();
  const queue = [...(childrenByParent.get(accountId) || [])];
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    const next = queue[cursor];
    if (descendants.has(next)) continue;
    descendants.add(next);
    queue.push(...(childrenByParent.get(next) || []));
  }
  return descendants;
}

function referralPath(accountId, snapshot) {
  const path = [];
  const visited = new Set();
  let current = accountId;
  while (current && !visited.has(current)) {
    visited.add(current);
    path.unshift(current);
    current = snapshot.parentByChild.get(current) || '';
  }
  return path;
}

function referralGraphLayout(snapshot) {
  const accounts = state.data?.accounts || [];
  const accountOrder = new Map(accounts.map((account, index) => [account.id, index]));
  const roots = accounts
    .filter((account) => !snapshot.parentByChild.get(account.id))
    .map((account) => account.id);
  const positions = new Map();
  const nodeWidth = 176;
  const nodeHeight = 70;
  const horizontalStep = 218;
  const verticalStep = 132;
  const paddingX = 48;
  const paddingTop = 42;
  let leafCursor = 0;

  for (const rootId of roots) {
    const postOrder = [];
    const stack = [[rootId, false]];
    while (stack.length) {
      const [accountId, visited] = stack.pop();
      if (visited) {
        postOrder.push(accountId);
        continue;
      }
      stack.push([accountId, true]);
      const children = [...(snapshot.childrenByParent.get(accountId) || [])]
        .sort((first, second) => accountOrder.get(second) - accountOrder.get(first));
      children.forEach((childId) => stack.push([childId, false]));
    }
    for (const accountId of postOrder) {
      const children = snapshot.childrenByParent.get(accountId) || [];
      const x = children.length
        ? children.reduce((sum, childId) => sum + positions.get(childId).x, 0) / children.length
        : paddingX + leafCursor++ * horizontalStep;
      positions.set(accountId, {
        x,
        y: paddingTop + (snapshot.depths.get(accountId) || 0) * verticalStep,
      });
    }
    leafCursor += 0.55;
  }

  const width = Math.max(
    760,
    ...[...positions.values()].map((position) => position.x + nodeWidth + paddingX),
  );
  const height = Math.max(390, paddingTop * 2 + nodeHeight + snapshot.maxDepth * verticalStep);
  return { positions, width, height, nodeWidth, nodeHeight };
}

function referralGraphMarkup(snapshot) {
  const accounts = state.data?.accounts || [];
  const layout = referralGraphLayout(snapshot);
  const paths = snapshot.relationships
    .filter((relationship) => relationship.parent_account_id)
    .map((relationship) => {
      const parent = layout.positions.get(relationship.parent_account_id);
      const child = layout.positions.get(relationship.child_account_id);
      if (!parent || !child) return '';
      const startX = parent.x + layout.nodeWidth / 2;
      const startY = parent.y + layout.nodeHeight;
      const endX = child.x + layout.nodeWidth / 2;
      const endY = child.y;
      const middleY = startY + (endY - startY) / 2;
      const tone = (snapshot.depths.get(relationship.child_account_id) || 0) % 6;
      return `<path data-tone="${tone}" d="M ${startX} ${startY} C ${startX} ${middleY}, ${endX} ${middleY}, ${endX} ${endY}" />`;
    }).join('');
  const nodes = accounts.map((account, index) => {
    const position = layout.positions.get(account.id) || { x: 0, y: 0 };
    const depth = snapshot.depths.get(account.id) || 0;
    const children = snapshot.childrenByParent.get(account.id)?.length || 0;
    const parent = accountById(snapshot.parentByChild.get(account.id));
    const selected = account.id === state.referralSelectedAccountId;
    const search = `${account.label} ${account.evm_address} ${parent?.label || ''}`.toLowerCase();
    return `<foreignObject class="referral-node-slot" x="${position.x}" y="${position.y}" width="${layout.nodeWidth}" height="${layout.nodeHeight}">
      <button class="referral-graph-node ${selected ? 'is-selected' : ''}" type="button" data-referral-node="${escapeHtml(account.id)}" data-referral-search="${escapeHtml(search)}" data-referral-x="${position.x}" data-referral-y="${position.y}" data-depth="${depth}" data-tone="${depth % 6}" aria-pressed="${selected}">
        <i>${escapeHtml(referralProfileMark(account, index))}</i>
        <span><small>${depth ? `УРОВЕНЬ ${String(depth).padStart(2, '0')}` : 'КОРЕНЬ'}</small><strong>${escapeHtml(account.label)}</strong><code>${escapeHtml(shortAddress(account.evm_address))}</code></span>
        ${children ? `<b title="Прямые рефералы">${children}</b>` : '<b aria-hidden="true">·</b>'}
      </button>
    </foreignObject>`;
  }).join('');
  const transform = `translate(${state.referralView.x} ${state.referralView.y}) scale(${state.referralView.zoom})`;
  return `<svg class="referral-graph-surface" width="100%" height="100%" data-graph-width="${layout.width}" data-graph-height="${layout.height}" aria-label="Реферальное дерево"><g id="referral-graph-viewport" class="referral-graph-viewport" transform="${transform}"><g class="referral-graph-links" aria-hidden="true">${paths}</g>${nodes}</g></svg>`;
}

function clampReferralZoom(value, minimum = REFERRAL_ZOOM_MIN) {
  return Math.min(REFERRAL_ZOOM_MAX, Math.max(minimum, Number(value) || 1));
}

function referralZoomAroundPoint(view, nextZoom, point, minimumZoom = REFERRAL_ZOOM_MIN) {
  const zoom = clampReferralZoom(nextZoom, minimumZoom);
  const previousZoom = clampReferralZoom(view.zoom, minimumZoom);
  const graphX = (point.x - view.x) / previousZoom;
  const graphY = (point.y - view.y) / previousZoom;
  return {
    x: point.x - graphX * zoom,
    y: point.y - graphY * zoom,
    zoom,
  };
}

function referralFitTransform(bounds, viewport, { padding = 48, maxZoom = 1 } = {}) {
  const availableWidth = Math.max(1, viewport.width - padding * 2);
  const availableHeight = Math.max(1, viewport.height - padding * 2);
  const width = Math.max(1, bounds.width);
  const height = Math.max(1, bounds.height);
  const zoom = clampReferralZoom(
    Math.min(maxZoom, availableWidth / width, availableHeight / height),
    REFERRAL_ZOOM_ABSOLUTE_MIN,
  );
  return {
    x: (viewport.width - width * zoom) / 2 - (bounds.x || 0) * zoom,
    y: (viewport.height - height * zoom) / 2 - (bounds.y || 0) * zoom,
    zoom,
  };
}

function referralViewportSize() {
  const preview = $('#referral-chain-preview');
  return {
    width: Math.max(1, preview?.clientWidth || 760),
    height: Math.max(1, preview?.clientHeight || 390),
  };
}

function referralGraphSize() {
  const surface = $('.referral-graph-surface', $('#referral-graph'));
  return {
    width: Math.max(1, Number(surface?.dataset.graphWidth) || 760),
    height: Math.max(1, Number(surface?.dataset.graphHeight) || 390),
  };
}

function referralInteractiveZoomMin() {
  const fit = referralFitTransform(
    { x: 0, y: 0, ...referralGraphSize() },
    referralViewportSize(),
    { padding: 44, maxZoom: 1 },
  );
  return Math.min(REFERRAL_ZOOM_MIN, fit.zoom);
}

function constrainReferralView(view, minimumZoom = referralInteractiveZoomMin()) {
  const viewport = referralViewportSize();
  const graph = referralGraphSize();
  const zoom = clampReferralZoom(view.zoom, minimumZoom);
  const width = graph.width * zoom;
  const height = graph.height * zoom;
  const edge = 64;
  let x = Number.isFinite(view.x) ? view.x : 0;
  let y = Number.isFinite(view.y) ? view.y : 0;
  if (width <= viewport.width - edge * 2) x = (viewport.width - width) / 2;
  else x = Math.min(edge, Math.max(viewport.width - edge - width, x));
  if (height <= viewport.height - edge * 2) y = (viewport.height - height) / 2;
  else y = Math.min(edge, Math.max(viewport.height - edge - height, y));
  return { x, y, zoom };
}

function updateReferralMinimapViewport() {
  const minimap = $('#referral-minimap');
  const viewportRect = $('.referral-minimap-viewport', minimap);
  if (!minimap || !viewportRect) return;
  const graph = referralGraphSize();
  const viewport = referralViewportSize();
  const zoom = state.referralView.zoom;
  const left = Math.max(0, Math.min(graph.width, -state.referralView.x / zoom));
  const top = Math.max(0, Math.min(graph.height, -state.referralView.y / zoom));
  const right = Math.max(left, Math.min(graph.width, (viewport.width - state.referralView.x) / zoom));
  const bottom = Math.max(top, Math.min(graph.height, (viewport.height - state.referralView.y) / zoom));
  const scale = Number(minimap.dataset.mapScale) || 1;
  const offsetX = Number(minimap.dataset.mapOffsetX) || 0;
  const offsetY = Number(minimap.dataset.mapOffsetY) || 0;
  viewportRect.setAttribute('x', String(offsetX + left * scale));
  viewportRect.setAttribute('y', String(offsetY + top * scale));
  viewportRect.setAttribute('width', String(Math.max(3, (right - left) * scale)));
  viewportRect.setAttribute('height', String(Math.max(3, (bottom - top) * scale)));
}

function applyReferralViewNow() {
  state.referralViewFrame = null;
  const transform = $('.referral-graph-viewport', $('#referral-graph'));
  if (transform) {
    const { x, y, zoom } = state.referralView;
    transform.setAttribute('transform', `translate(${x} ${y}) scale(${zoom})`);
  }
  const level = $('#referral-zoom-level');
  if (level) {
    const percent = state.referralView.zoom * 100;
    level.textContent = `${percent < 1 ? percent.toFixed(2) : Math.round(percent)}%`;
  }
  updateReferralMinimapViewport();
}

function scheduleReferralViewApply() {
  if (state.referralViewFrame !== null) return;
  state.referralViewFrame = window.requestAnimationFrame(applyReferralViewNow);
}

function setReferralView(nextView, { immediate = false, minimumZoom } = {}) {
  state.referralView = constrainReferralView(nextView, minimumZoom);
  if (immediate) {
    if (state.referralViewFrame !== null) window.cancelAnimationFrame(state.referralViewFrame);
    applyReferralViewNow();
  } else {
    scheduleReferralViewApply();
  }
}

function referralMinimapMarkup(snapshot) {
  const layout = referralGraphLayout(snapshot);
  const padding = 8;
  const scale = Math.min(
    (REFERRAL_MINIMAP_WIDTH - padding * 2) / layout.width,
    (REFERRAL_MINIMAP_HEIGHT - padding * 2) / layout.height,
  );
  const offsetX = (REFERRAL_MINIMAP_WIDTH - layout.width * scale) / 2;
  const offsetY = (REFERRAL_MINIMAP_HEIGHT - layout.height * scale) / 2;
  const links = snapshot.relationships
    .filter((relationship) => relationship.parent_account_id)
    .map((relationship) => {
      const parent = layout.positions.get(relationship.parent_account_id);
      const child = layout.positions.get(relationship.child_account_id);
      if (!parent || !child) return '';
      return `<line x1="${offsetX + (parent.x + layout.nodeWidth / 2) * scale}" y1="${offsetY + (parent.y + layout.nodeHeight / 2) * scale}" x2="${offsetX + (child.x + layout.nodeWidth / 2) * scale}" y2="${offsetY + (child.y + layout.nodeHeight / 2) * scale}" />`;
    }).join('');
  const nodes = (state.data?.accounts || []).map((account) => {
    const position = layout.positions.get(account.id);
    if (!position) return '';
    const root = !snapshot.parentByChild.get(account.id);
    return `<circle cx="${offsetX + (position.x + layout.nodeWidth / 2) * scale}" cy="${offsetY + (position.y + layout.nodeHeight / 2) * scale}" r="${root ? 2.8 : 2}" data-root="${root}" />`;
  }).join('');
  return {
    markup: `<g class="referral-minimap-links" aria-hidden="true">${links}</g><g class="referral-minimap-nodes" aria-hidden="true">${nodes}</g><rect id="referral-minimap-viewport" class="referral-minimap-viewport" x="0" y="0" width="1" height="1" rx="3" aria-hidden="true" />`,
    scale,
    offsetX,
    offsetY,
  };
}

function renderReferralMinimap(snapshot) {
  const minimap = $('#referral-minimap');
  if (!minimap) return;
  const map = referralMinimapMarkup(snapshot);
  minimap.innerHTML = map.markup;
  minimap.dataset.mapScale = String(map.scale);
  minimap.dataset.mapOffsetX = String(map.offsetX);
  minimap.dataset.mapOffsetY = String(map.offsetY);
  updateReferralMinimapViewport();
}

function fitReferralGraph(mode = 'all') {
  const viewport = referralViewportSize();
  const graph = referralGraphSize();
  let bounds = { x: 0, y: 0, width: graph.width, height: graph.height };
  let maxZoom = 1;
  if (mode === 'roots') {
    const roots = $$('.referral-graph-node[data-depth="0"]', $('#referral-graph'));
    const points = roots.map((node) => ({
      x: Number(node.dataset.referralX) || 0,
      y: Number(node.dataset.referralY) || 0,
    }));
    if (points.length) {
      const minimumX = Math.min(...points.map((point) => point.x));
      const maximumX = Math.max(...points.map((point) => point.x));
      const minimumY = Math.min(...points.map((point) => point.y));
      bounds = { x: minimumX, y: minimumY, width: maximumX - minimumX + 176, height: 70 };
    }
  }
  setReferralView(
    referralFitTransform(bounds, viewport, { padding: mode === 'roots' ? 64 : 44, maxZoom }),
    { minimumZoom: REFERRAL_ZOOM_ABSOLUTE_MIN },
  );
}

function centerReferralGraphPoint(point) {
  const viewport = referralViewportSize();
  const zoom = state.referralView.zoom;
  setReferralView({
    x: viewport.width / 2 - point.x * zoom,
    y: viewport.height / 2 - point.y * zoom,
    zoom,
  });
}

function centerReferralNode(accountId, { focusNode = true } = {}) {
  const node = $(`[data-referral-node="${CSS.escape(accountId)}"]`, $('#referral-graph'));
  if (!node) return;
  centerReferralGraphPoint({
    x: (Number(node.dataset.referralX) || 0) + 88,
    y: (Number(node.dataset.referralY) || 0) + 35,
  });
  if (focusNode) node.focus({ preventScroll: true });
}

function changeReferralZoom(multiplier) {
  const viewport = referralViewportSize();
  setReferralView(referralZoomAroundPoint(
    state.referralView,
    state.referralView.zoom * multiplier,
    { x: viewport.width / 2, y: viewport.height / 2 },
    referralInteractiveZoomMin(),
  ));
}

function referralLocalPoint(event, element) {
  const bounds = element.getBoundingClientRect();
  return { x: event.clientX - bounds.left, y: event.clientY - bounds.top };
}

function beginReferralGesture() {
  const points = [...state.referralPointers.values()];
  if (!points.length) {
    state.referralGesture = null;
    return;
  }
  if (points.length > 1) {
    const first = points[0];
    const second = points[1];
    const center = { x: (first.x + second.x) / 2, y: (first.y + second.y) / 2 };
    state.referralGesture = {
      mode: 'pinch',
      center,
      distance: Math.max(1, Math.hypot(second.x - first.x, second.y - first.y)),
      view: { ...state.referralView },
      graphPoint: {
        x: (center.x - state.referralView.x) / state.referralView.zoom,
        y: (center.y - state.referralView.y) / state.referralView.zoom,
      },
      moved: true,
    };
    state.referralSuppressClickUntil = Date.now() + 320;
    return;
  }
  state.referralGesture = {
    mode: 'pan',
    point: { x: points[0].x, y: points[0].y },
    view: { ...state.referralView },
    moved: false,
    tapAccountId: points[0].accountId || '',
  };
}

function handleReferralPointerDown(event) {
  const preview = $('#referral-chain-preview');
  if ((event.pointerType === 'mouse' && event.button !== 0) || event.target.closest('#referral-map-controls, #referral-minimap-shell')) return;
  const point = referralLocalPoint(event, preview);
  state.referralPointers.set(event.pointerId, {
    ...point,
    accountId: event.target.closest('[data-referral-node]')?.dataset.referralNode || '',
  });
  preview.setPointerCapture?.(event.pointerId);
  beginReferralGesture();
}

function handleReferralPointerMove(event) {
  const preview = $('#referral-chain-preview');
  if (!state.referralPointers.has(event.pointerId) || !state.referralGesture) return;
  const previous = state.referralPointers.get(event.pointerId);
  const point = referralLocalPoint(event, preview);
  state.referralPointers.set(event.pointerId, { ...previous, ...point });
  const gesture = state.referralGesture;
  if (gesture.mode === 'pinch') {
    const points = [...state.referralPointers.values()];
    if (points.length < 2) return;
    const first = points[0];
    const second = points[1];
    const center = { x: (first.x + second.x) / 2, y: (first.y + second.y) / 2 };
    const distance = Math.max(1, Math.hypot(second.x - first.x, second.y - first.y));
    const zoom = clampReferralZoom(
      gesture.view.zoom * distance / gesture.distance,
      referralInteractiveZoomMin(),
    );
    setReferralView({
      x: center.x - gesture.graphPoint.x * zoom,
      y: center.y - gesture.graphPoint.y * zoom,
      zoom,
    });
  } else {
    const deltaX = point.x - gesture.point.x;
    const deltaY = point.y - gesture.point.y;
    if (!gesture.moved && Math.hypot(deltaX, deltaY) < 5) return;
    gesture.moved = true;
    preview.classList.add('is-dragging');
    state.referralSuppressClickUntil = Date.now() + 320;
    setReferralView({
      x: gesture.view.x + deltaX,
      y: gesture.view.y + deltaY,
      zoom: gesture.view.zoom,
    });
  }
  event.preventDefault();
}

function handleReferralPointerEnd(event) {
  const preview = $('#referral-chain-preview');
  if (!state.referralPointers.has(event.pointerId)) return;
  const gesture = state.referralGesture;
  state.referralPointers.delete(event.pointerId);
  if (preview.hasPointerCapture?.(event.pointerId)) preview.releasePointerCapture(event.pointerId);
  preview.classList.remove('is-dragging');
  if (!gesture?.moved && gesture?.tapAccountId && state.referralPointers.size === 0 && Date.now() >= state.referralSuppressClickUntil) {
    selectReferralNode(gesture.tapAccountId);
  }
  beginReferralGesture();
}

function handleReferralWheel(event) {
  const preview = $('#referral-chain-preview');
  if (event.target.closest('#referral-map-controls, #referral-minimap-shell')) return;
  const point = referralLocalPoint(event, preview);
  const rawDelta = event.deltaMode === 1 ? event.deltaY * 16 : event.deltaY;
  const delta = Math.max(-180, Math.min(180, rawDelta));
  const multiplier = Math.exp(-delta * 0.0014);
  setReferralView(referralZoomAroundPoint(
    state.referralView,
    state.referralView.zoom * multiplier,
    point,
    referralInteractiveZoomMin(),
  ));
  event.preventDefault();
}

function handleReferralDoubleClick(event) {
  if (event.target.closest('#referral-map-controls, #referral-minimap-shell')) return;
  event.preventDefault();
  window.getSelection()?.removeAllRanges();
}

function handleReferralMapKeydown(event) {
  if (event.target !== event.currentTarget) return;
  const movement = event.shiftKey ? 120 : 48;
  const next = { ...state.referralView };
  if (event.key === 'ArrowLeft') next.x += movement;
  else if (event.key === 'ArrowRight') next.x -= movement;
  else if (event.key === 'ArrowUp') next.y += movement;
  else if (event.key === 'ArrowDown') next.y -= movement;
  else if (event.key === '+' || event.key === '=') changeReferralZoom(REFERRAL_ZOOM_STEP);
  else if (event.key === '-') changeReferralZoom(1 / REFERRAL_ZOOM_STEP);
  else if (event.key === '0' || event.key === 'Home') fitReferralGraph('all');
  else return;
  if (event.key.startsWith('Arrow')) setReferralView(next);
  event.preventDefault();
}

function minimapGraphPoint(event) {
  const minimap = $('#referral-minimap');
  const point = referralLocalPoint(event, minimap);
  const bounds = minimap.getBoundingClientRect();
  const svgX = point.x * REFERRAL_MINIMAP_WIDTH / Math.max(1, bounds.width);
  const svgY = point.y * REFERRAL_MINIMAP_HEIGHT / Math.max(1, bounds.height);
  const scale = Number(minimap.dataset.mapScale) || 1;
  return {
    x: (svgX - (Number(minimap.dataset.mapOffsetX) || 0)) / scale,
    y: (svgY - (Number(minimap.dataset.mapOffsetY) || 0)) / scale,
  };
}

function handleReferralMinimapPointer(event) {
  const minimap = $('#referral-minimap');
  if (event.type === 'pointerdown') {
    if (event.pointerType === 'mouse' && event.button !== 0) return;
    minimap.setPointerCapture?.(event.pointerId);
  } else if (!minimap.hasPointerCapture?.(event.pointerId)) {
    return;
  }
  centerReferralGraphPoint(minimapGraphPoint(event));
  event.preventDefault();
  event.stopPropagation();
}

function handleReferralMinimapPointerEnd(event) {
  const minimap = $('#referral-minimap');
  if (minimap.hasPointerCapture?.(event.pointerId)) minimap.releasePointerCapture(event.pointerId);
  event.stopPropagation();
}

function resetReferralNavigation({ clearTransform = false } = {}) {
  if (state.referralViewFrame !== null) window.cancelAnimationFrame(state.referralViewFrame);
  state.referralViewFrame = null;
  state.referralView = { x: 0, y: 0, zoom: 1 };
  state.referralPointers.clear();
  state.referralGesture = null;
  state.referralSuppressClickUntil = 0;
  $('#referral-chain-preview')?.classList.remove('is-dragging');
  if (clearTransform) $('.referral-graph-viewport', $('#referral-graph'))?.removeAttribute('transform');
  const level = $('#referral-zoom-level');
  if (level) level.textContent = '100%';
}

function selectReferralNode(accountId, { focus = false } = {}) {
  if (!accountById(accountId)) return;
  state.referralSelectedAccountId = accountId;
  $$('.referral-graph-node', $('#referral-graph')).forEach((node) => {
    const selected = node.dataset.referralNode === accountId;
    node.classList.toggle('is-selected', selected);
    node.setAttribute('aria-pressed', String(selected));
  });
  renderReferralInspector(referralTopologySnapshot());
  if (focus) {
    centerReferralNode(accountId);
  }
}

function renderReferralInspector(snapshot) {
  const accounts = state.data?.accounts || [];
  let account = accountById(state.referralSelectedAccountId);
  if (!account && accounts.length) {
    account = accounts.find((candidate) => !snapshot.parentByChild.get(candidate.id)) || accounts[0];
    state.referralSelectedAccountId = account.id;
  }
  const empty = $('#referral-inspector-empty');
  const content = $('#referral-inspector-content');
  if (!account) {
    empty.hidden = false;
    content.hidden = true;
    return;
  }
  empty.hidden = true;
  content.hidden = false;
  const accountIndex = accounts.findIndex((candidate) => candidate.id === account.id);
  const depth = snapshot.depths.get(account.id) || 0;
  const parentId = snapshot.parentByChild.get(account.id) || '';
  const descendants = referralDescendants(account.id, snapshot.childrenByParent);
  $('#referral-inspector-mark').textContent = referralProfileMark(account, accountIndex);
  $('#referral-inspector-level').textContent = depth ? `УРОВЕНЬ ${String(depth).padStart(2, '0')}` : 'КОРНЕВОЙ АККАУНТ';
  $('#referral-inspector-label').textContent = account.label;
  $('#referral-inspector-address').textContent = shortAddress(account.evm_address);
  $('#referral-inspector-path').innerHTML = referralPath(account.id, snapshot).map((pathId, index, path) => {
    const item = accountById(pathId);
    return `<button type="button" data-referral-focus="${escapeHtml(pathId)}" ${pathId === account.id ? 'aria-current="true"' : ''}>${escapeHtml(item?.label || pathId)}</button>${index < path.length - 1 ? '<i>›</i>' : ''}`;
  }).join('');

  const select = $('#referral-parent-select');
  select.innerHTML = [
    '<option value="">Никто · это корень</option>',
    ...accounts
      .filter((candidate) => candidate.id !== account.id)
      .map((candidate) => {
        const disabled = descendants.has(candidate.id);
        const candidateDepth = snapshot.depths.get(candidate.id) || 0;
        return `<option value="${escapeHtml(candidate.id)}" ${disabled ? 'disabled' : ''}>${disabled ? 'Нельзя выбрать · ' : ''}${escapeHtml(candidate.label)} · ${candidateDepth ? `уровень ${candidateDepth}` : 'корень'}</option>`;
      }),
  ].join('');
  select.value = parentId;
  $('#referral-parent-help').textContent = parentId
    ? `${accountById(parentId)?.label || 'Выбранный аккаунт'} пригласил ${account.label}. Код для проекта софт подставит сам.`
    : 'Это корень отдельной ветки.';
  $('#referral-make-root').disabled = !parentId;
  const children = snapshot.childrenByParent.get(account.id) || [];
  $('#referral-inspector-children').innerHTML = children.length
    ? children.map((childId) => `<button type="button" data-referral-focus="${escapeHtml(childId)}">${escapeHtml(accountById(childId)?.label || childId)}<span>→</span></button>`).join('')
    : '<small>Пока никого.</small>';
}

function renderReferralEditor() {
  const accounts = state.data?.accounts || [];
  resetReferralNavigation();
  state.referralRevision = referralTopologyRevision();
  state.referralDraft = new Map(accounts.map((account) => [
    account.id,
    String(account.referrer_account_id || ''),
  ]));
  state.referralDirty = false;
  state.referralSelectedAccountId = accounts.find((account) => !account.referrer_account_id)?.id || accounts[0]?.id || null;
  $('#referral-search').value = '';
  $('#referral-error').hidden = true;
  updateReferralPreview(false);
}

function applyReferralSearch({ focusFirst = false } = {}) {
  const query = $('#referral-search').value.trim().toLowerCase();
  const nodes = $$('.referral-graph-node', $('#referral-graph'));
  const matches = nodes.filter((node) => !query || node.dataset.referralSearch.includes(query));
  nodes.forEach((node) => {
    const match = !query || node.dataset.referralSearch.includes(query);
    node.classList.toggle('is-search-match', Boolean(query) && match);
    node.classList.toggle('is-search-dimmed', Boolean(query) && !match);
  });
  const copy = query ? `${matches.length} из ${nodes.length}` : `${nodes.length} ${countWord(nodes.length, 'аккаунт', 'аккаунта', 'аккаунтов')}`;
  $('#referral-search-count').textContent = copy;
  $('#referral-editor-count').textContent = copy;
  if (query && matches.length && focusFirst) {
    selectReferralNode(matches[0].dataset.referralNode);
    centerReferralNode(matches[0].dataset.referralNode, { focusNode: false });
  }
}

function applyReferralPattern(pattern) {
  const accounts = state.data?.accounts || [];
  accounts.forEach((account, index) => {
    if (pattern === 'linear') state.referralDraft.set(account.id, index ? accounts[index - 1].id : '');
    else if (pattern === 'leader') state.referralDraft.set(account.id, index ? accounts[0].id : '');
    else state.referralDraft.set(account.id, '');
  });
  state.referralSelectedAccountId = accounts[0]?.id || null;
  state.referralDirty = true;
  updateReferralPreview(true, { resetGraph: true });
}

function setReferralParent(parentId) {
  const accountId = state.referralSelectedAccountId;
  if (!accountId || !state.referralDraft.has(accountId)) return;
  const previous = state.referralDraft.get(accountId) || '';
  state.referralDraft.set(accountId, parentId || '');
  try {
    referralTopologySnapshot();
    state.referralDirty = true;
    updateReferralPreview(true);
  } catch (failure) {
    state.referralDraft.set(accountId, previous);
    $('#referral-error').textContent = failure.message;
    $('#referral-error').hidden = false;
    renderReferralInspector(referralTopologySnapshot());
    toast(failure.message, 'error', 5200);
  }
}

function updateReferralPreview(dirty = state.referralDirty, { resetGraph = false } = {}) {
  const preview = $('#referral-chain-preview');
  const copy = $('#referral-overview-copy');
  try {
    const snapshot = referralTopologySnapshot();
    preview.dataset.state = snapshot.links ? 'ready' : 'empty';
    $('#referral-graph').innerHTML = referralGraphMarkup(snapshot);
    renderReferralMinimap(snapshot);
    if (resetGraph) fitReferralGraph('all');
    else setReferralView(state.referralView, { immediate: true });
    $('#referral-root-count').textContent = snapshot.roots;
    $('#referral-link-count').textContent = snapshot.links;
    $('#referral-depth-count').textContent = snapshot.maxDepth + 1;
    copy.textContent = dirty ? 'Есть изменения — сохраните карту' : 'Схема сохранена';
    $('#referral-error').hidden = true;
    renderReferralInspector(snapshot);
    applyReferralSearch();
  } catch (error) {
    preview.dataset.state = 'error';
    $('#referral-graph').innerHTML = `<span class="referral-chain-empty">${escapeHtml(error.message)}</span>`;
    copy.textContent = 'В цепочке получился круг. Исправьте связь.';
  }
}

function openReferralModal() {
  requireUnlocked(() => {
    if (!state.data.accounts.length) {
      toast('Сначала добавьте хотя бы один аккаунт.', 'info');
      openImportModal();
      return;
    }
    renderReferralEditor();
    openModal('referral-modal');
    window.requestAnimationFrame(() => fitReferralGraph('all'));
  });
}

function handleReferralEditorInput(event) {
  if (event.target.id === 'referral-search') applyReferralSearch({ focusFirst: true });
}

function handleReferralEditorClick(event) {
  if (Date.now() < state.referralSuppressClickUntil && event.target.closest('[data-referral-node]')) {
    event.preventDefault();
    return;
  }
  const button = event.target.closest('[data-referral-pattern]');
  if (button) {
    applyReferralPattern(button.dataset.referralPattern);
    return;
  }
  const node = event.target.closest('[data-referral-node], [data-referral-focus]');
  if (node) {
    selectReferralNode(node.dataset.referralNode || node.dataset.referralFocus, { focus: Boolean(node.dataset.referralFocus) });
    return;
  }
  if (event.target.closest('#referral-fit')) {
    fitReferralGraph('roots');
    return;
  }
  if (event.target.closest('#referral-fit-all')) {
    fitReferralGraph('all');
    return;
  }
  if (event.target.closest('#referral-zoom-in')) {
    changeReferralZoom(REFERRAL_ZOOM_STEP);
    return;
  }
  if (event.target.closest('#referral-zoom-out')) {
    changeReferralZoom(1 / REFERRAL_ZOOM_STEP);
    return;
  }
  if (event.target.closest('#referral-make-root')) setReferralParent('');
}

async function saveReferralNetwork(event) {
  event.preventDefault();
  const error = $('#referral-error');
  error.hidden = true;
  let snapshot;
  try {
    snapshot = referralTopologySnapshot();
  } catch (failure) {
    error.textContent = failure.message;
    error.hidden = false;
    $('#referral-chain-preview').focus?.();
    return;
  }
  const button = $('#referral-save');
  const modal = $('#referral-modal');
  modal.dataset.busy = 'true';
  setBusy(button, true, 'Сохраняем карту…');
  try {
    const result = await jsonPost('/api/accounts/referral-topology', {
      expected_revision: state.referralRevision,
      relationships: snapshot.relationships,
    });
    state.referralRevision = result.revision || state.referralRevision;
    state.referralDirty = false;
    closeModals(true, true);
    await refresh();
    toast('Реферальная карта сохранена', 'success');
  } catch (failure) {
    if (failure.status === 409) {
      await refresh();
      renderReferralEditor();
      error.textContent = 'Карта изменилась в другом окне. Мы загрузили свежую версию — повторите свои изменения.';
    } else {
      error.textContent = failure.message;
    }
    error.hidden = false;
  } finally {
    delete modal.dataset.busy;
    setBusy(button, false);
  }
}

function activityRuns(filter = state.activityFilter) {
  if (!state.data) return [];
  const statuses = filter === 'attention' ? ATTENTION_RUN_STATUSES : ACTIVE_RUN_STATUSES;
  return state.data.runs.filter((run) => statuses.has(run.status));
}

function activityModuleForRun(run) {
  return state.data?.modules.find((module) => module.id === run.module_id) || {
    id: run.module_id,
    name: run.module_name,
    manifest: { ui: {} },
  };
}

function activityActionName(run) {
  const module = state.data?.modules.find((item) => item.id === run.module_id);
  return module?.manifest?.actions?.find((action) => action.id === run.action_id)?.name || run.action_id;
}

function activityRunStage(run) {
  const actionName = activityActionName(run);
  const stages = {
    queued: ['Ждёт место в очереди', actionName],
    starting: ['Запускает софт', actionName],
    running: [actionName, 'Работает'],
    cancelling: ['Останавливается', actionName],
    failed: ['Запуск завершился с ошибкой', actionName],
    needs_attention: ['Запуск завершился с ошибкой', actionName],
  };
  return stages[run.status] || [statusNames[run.status] || run.status, actionName];
}

function activityProjectionMatches(row, filter) {
  if (filter === 'active') return ACTIVE_RUN_STATUSES.has(row.run_status);
  if (['reconciled', 'reviewed'].includes(row.run_status)) return false;
  return ATTENTION_RUN_STATUSES.has(row.run_status)
    || ATTENTION_ACCOUNT_STATUSES.has(row.status)
    || (row.status === 'unknown' && !['historical', 'reconciled'].includes(row.stage));
}

function activityResolutionKind(row, runRows = [row]) {
  if (!activityProjectionMatches(row, 'attention')) return '';
  if (ACTIVE_RUN_STATUSES.has(row.run_status)) return '';
  if (['reconciled', 'reviewed'].includes(row.run_status)) return '';
  return runRows.length ? 'review' : '';
}

function accountFreeActivityRows(filter) {
  return activityRuns(filter)
    .filter((run) => Number(run.account_count || 0) === 0)
    .map((run) => {
      const [stage, detail] = activityRunStage(run);
      return {
        run_id: run.id,
        account_id: '',
        account_label: 'Без аккаунта',
        status: run.status,
        stage,
        progress: run.progress,
        last_message: detail,
        updated_at: run.started_at || run.requested_at,
        module_id: run.module_id,
        module_name: run.module_name,
        module_version: run.module_version,
        action_id: run.action_id,
        run_status: run.status,
        requested_at: run.requested_at,
        started_at: run.started_at,
        finished_at: run.finished_at,
        synthetic: true,
      };
    });
}

function activityRows(filter = state.activityFilter) {
  if (!state.activityAccountsLoaded) return [];
  return state.activityAccountRows
    .filter((row) => activityProjectionMatches(row, filter))
    .concat(accountFreeActivityRows(filter))
    .sort((first, second) => {
      const firstTime = new Date(first.updated_at || first.requested_at || 0).getTime() || 0;
      const secondTime = new Date(second.updated_at || second.requested_at || 0).getTime() || 0;
      return secondTime - firstTime;
    });
}

function activityStageLabel(value) {
  const raw = String(value || '').trim();
  const normalized = raw.toLowerCase();
  const stages = {
    queued: 'Ожидает запуска',
    starting: 'Подготовка',
    running: 'Выполнение',
    completed: 'Завершение',
    succeeded: 'Завершено',
    failed: 'Ошибка этапа',
    cancelled: 'Остановлено',
    historical: 'История',
    reconciled: 'История',
    hub_shutdown: 'Остановка Hub',
    preflight: 'Проверяет условия',
    fill: 'Заполняет данные',
    partially_completed: 'Завершено частично',
    action_failed: 'Ошибка действия',
    external_state_unknown: 'Внешний результат неясен',
    preflight_failed: 'Проверка не пройдена',
    external_reconciliation: 'Проверяет внешний результат',
    adapter_error: 'Ошибка адаптера',
    write_gate: 'Проверяет разрешение на запись',
    write_blocked: 'Запись заблокирована',
    account_preflight: 'Проверяет аккаунт',
    reconciliation: 'Проверяет результат',
    needs_reconciliation: 'Результат не определён',
    profile_validation: 'Проверяет аккаунт',
    validated: 'Аккаунт проверен',
    registration: 'Регистрирует аккаунт',
    invalid_profile: 'Аккаунт не прошёл проверку',
  };
  if (stages[normalized]) return stages[normalized];
  if (/[а-яё]/i.test(raw)) return raw;
  return raw ? 'Выполняет шаг' : 'Текущий этап';
}

function activityGroups(rows) {
  const groups = new Map();
  rows.forEach((row) => {
    const key = row.module_id || row.run_id;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(row);
  });
  return Array.from(groups.values());
}

function activityTableMarkup(rows) {
  return activityGroups(rows).map((group) => {
    const module = activityModuleForRun(group[0]);
    const renderedRunActions = new Set();
    const runCount = new Set(group.map((row) => row.run_id)).size;
    const profileCount = group.filter((row) => !row.synthetic).length;
    const concurrency = Math.max(...group.map((row) => Number(row.account_concurrency || 0)), 0);
    const concurrencyCopy = concurrency > 1 ? ` · ${concurrency} потоков` : '';
    const groupDetail = profileCount
      ? `${runCount} ${countWord(runCount, 'запуск', 'запуска', 'запусков')} · ${profileCount} ${countWord(profileCount, 'аккаунт', 'аккаунта', 'аккаунтов')}${concurrencyCopy}`
      : `${runCount} ${countWord(runCount, 'запуск', 'запуска', 'запусков')} · без аккаунтов`;
    return group.map((row, index) => {
      const progress = Math.max(0, Math.min(100, Math.round(Number(row.progress || 0) * 100)));
      const stage = activityStageLabel(row.stage);
      const stageDetail = row.last_message || activityActionName(row) || 'Подробностей пока нет';
      const updatedAt = row.updated_at || row.requested_at;
      const statusLabel = accountStatusNames[row.status] || statusNames[row.status] || row.status;
      const showRunAction = !renderedRunActions.has(row.run_id);
      const showStop = ACTIVE_RUN_STATUSES.has(row.run_status || row.status) && showRunAction;
      const resolutionKind = showRunAction
        ? activityResolutionKind(row, group.filter((candidate) => candidate.run_id === row.run_id))
        : '';
      const activityControlKey = `${row.run_id}:${row.account_id || 'public'}`;
      renderedRunActions.add(row.run_id);
      const resolutionControl = resolutionKind === 'review'
        ? `<button class="activity-resolution activity-resolution--review" type="button" data-review-run="${escapeHtml(row.run_id)}" data-activity-control="review:${escapeHtml(row.run_id)}" aria-label="Скрыть ошибку ${escapeHtml(row.module_name)} из текущих уведомлений">${iconMarkup('check')}<span>Скрыть</span></button>`
        : '';
      const moduleCell = index === 0 ? `
        <th class="activity-module-cell" scope="rowgroup" rowspan="${group.length}">
          ${moduleIconMarkup(module)}
          <span><strong>${escapeHtml(group[0].module_name)}</strong><small>${escapeHtml(groupDetail)}</small></span>
        </th>` : '';
      return `
        <tr class="activity-table-row" data-status="${escapeHtml(row.status)}">
          ${moduleCell}
          <td><span class="activity-cell-stack"><strong>${escapeHtml(row.account_label || 'Без аккаунта')}</strong><small>${row.synthetic ? 'Запуск без аккаунтов' : 'Аккаунт из Hub'}</small></span></td>
          <td><span class="activity-cell-stack activity-stage"><strong>${escapeHtml(stage)}</strong><small>${escapeHtml(stageDetail)}</small></span></td>
          <td><span class="activity-progress"><progress max="100" value="${progress}" aria-label="Прогресс ${escapeHtml(row.module_name)} для ${escapeHtml(row.account_label || 'операции')}: ${progress}%">${progress}%</progress><small>${progress}%</small></span></td>
          <td><span class="status-label" data-status="${escapeHtml(row.status)}">${escapeHtml(statusLabel)}</span></td>
          <td><time class="activity-age" datetime="${escapeHtml(updatedAt)}" title="${escapeHtml(fullDateTime(updatedAt))}">${escapeHtml(relativeTime(updatedAt))}</time></td>
          <td><span class="activity-row-actions"><button class="activity-open-run" type="button" data-open-run="${escapeHtml(row.run_id)}" data-activity-control="details:${escapeHtml(activityControlKey)}" aria-controls="run-drawer" aria-label="Открыть подробный журнал запуска: ${escapeHtml(row.module_name)}, ${escapeHtml(row.account_label || stage)}" title="Открыть подробный журнал">${iconMarkup('search')}</button>${showStop ? `<button class="activity-stop-run" type="button" data-request-run-stop="${escapeHtml(row.run_id)}" data-activity-control="stop:${escapeHtml(row.run_id)}" aria-label="Открыть безопасную остановку запуска ${escapeHtml(row.module_name)}">${iconMarkup('stop')}</button>` : ''}${resolutionControl}</span></td>
        </tr>`;
    }).join('');
  }).join('');
}

function loadActivityAccounts({ silent = false } = {}) {
  if (state.activityAccountsPromise) return state.activityAccountsPromise;
  const protectedDataEpoch = state.protectedDataEpoch;
  const requestGeneration = state.activityAccountsGeneration;
  state.activityAccountsLoading = true;
  state.activityAccountsError = '';
  if (!silent) renderActivityPanel();
  let promise;
  promise = Promise.all([
    api('/api/run-accounts?scope=active&limit=500'),
    api('/api/run-accounts?scope=attention&limit=500'),
  ])
    .then(([activePayload, attentionPayload]) => {
      if (
        protectedDataEpoch !== state.protectedDataEpoch
        || requestGeneration !== state.activityAccountsGeneration
        || !state.data?.vault?.unlocked
      ) return;
      if (!Array.isArray(activePayload.accounts) || !Array.isArray(attentionPayload.accounts)) {
        throw new Error('Ядро вернуло некорректный список операций');
      }
      const rows = new Map();
      [...activePayload.accounts, ...attentionPayload.accounts].forEach((row) => {
        rows.set(JSON.stringify([row.run_id, row.account_id]), row);
      });
      state.activityAccountRows = Array.from(rows.values());
      state.activityAccountsTruncated = {
        active: activePayload.truncated === true,
        attention: attentionPayload.truncated === true,
      };
      state.activityAccountsLoaded = true;
    })
    .catch((error) => {
      if (
        protectedDataEpoch !== state.protectedDataEpoch
        || requestGeneration !== state.activityAccountsGeneration
      ) return;
      state.activityAccountsError = error.message || 'Не удалось загрузить операции';
    })
    .finally(() => {
      state.activityAccountsLoading = false;
      if (state.activityAccountsPromise === promise) state.activityAccountsPromise = null;
      renderActivityPanel();
    });
  state.activityAccountsPromise = promise;
  return promise;
}

function renderActivityPanel() {
  const tableWrap = $('#activity-table-wrap');
  const empty = $('#activity-panel-empty');
  const loading = $('#activity-panel-loading');
  const unavailable = $('#activity-panel-unavailable');
  const panel = $('#activity-panel');
  const filter = state.activityFilter === 'attention' ? 'attention' : 'active';
  const activeCount = state.activityAccountsLoaded ? activityRows('active').length : activityRuns('active').length;
  const attentionCount = state.activityAccountsLoaded ? activityRows('attention').length : Number(state.data?.stats.attention_runs || 0);
  $('#activity-filter-active-count').textContent = `${activeCount}${state.activityAccountsTruncated.active ? '+' : ''}`;
  $('#activity-filter-attention-count').textContent = `${attentionCount}${state.activityAccountsTruncated.attention ? '+' : ''}`;
  panel.dataset.filter = filter;
  $('#activity-panel-title').textContent = filter === 'attention' ? 'Ошибки запусков' : 'Текущие запуски';
  $$('#activity-panel-filters button').forEach((button) => {
    const selected = button.dataset.activityFilter === filter;
    button.classList.toggle('is-active', selected);
    button.setAttribute('aria-pressed', String(selected));
  });

  if (!state.data) {
    tableWrap.hidden = true;
    empty.hidden = true;
    loading.hidden = true;
    unavailable.hidden = false;
    $('#activity-unavailable-copy').textContent = 'Hub не отвечает. Перезапустите приложение и попробуйте ещё раз.';
    setTextIfChanged($('#activity-panel-summary'), 'Данные ещё не загружены');
    panel.setAttribute('aria-busy', 'false');
    return;
  }

  if (state.activityAccountsLoading && !state.activityAccountsLoaded) {
    tableWrap.hidden = true;
    empty.hidden = true;
    loading.hidden = false;
    unavailable.hidden = true;
    setTextIfChanged($('#activity-panel-summary'), 'Собираем статусы аккаунтов…');
    panel.setAttribute('aria-busy', 'true');
    return;
  }

  if (!state.activityAccountsLoaded) {
    tableWrap.hidden = true;
    empty.hidden = true;
    loading.hidden = true;
    unavailable.hidden = false;
    $('#activity-unavailable-copy').textContent = state.activityAccountsError
      ? 'Не удалось загрузить статусы аккаунтов. Обновите данные и попробуйте ещё раз.'
      : 'Нажмите «Обновить», чтобы загрузить статусы аккаунтов.';
    setTextIfChanged($('#activity-panel-summary'), 'Статусы пока недоступны');
    panel.setAttribute('aria-busy', 'false');
    return;
  }

  const rows = activityRows(filter);
  const visibleRows = rows.slice(0, MAX_ACTIVITY_ROWS);
  const runCount = new Set(rows.map((row) => row.run_id)).size;
  const moduleCount = new Set(rows.map((row) => row.module_id)).size;
  unavailable.hidden = true;
  loading.hidden = true;
  tableWrap.hidden = visibleRows.length === 0;
  empty.hidden = visibleRows.length > 0;
  const truncationCopy = rows.length > visibleRows.length ? ` · показаны ${visibleRows.length}` : '';
  const sourceLimitCopy = state.activityAccountsTruncated[filter] ? ' · список ограничен' : '';
  const staleCopy = state.activityAccountsError ? ' · данные могут быть устаревшими' : '';
  const activitySummary = rows.length
    ? `${rows.length} ${countWord(rows.length, 'аккаунт', 'аккаунта', 'аккаунтов')} · ${runCount} ${countWord(runCount, 'запуск', 'запуска', 'запусков')} · ${moduleCount} ${countWord(moduleCount, 'софт', 'софта', 'софтов')}${truncationCopy}${sourceLimitCopy}${staleCopy}`
    : filter === 'attention' ? 'Ошибок нет' : 'Очередь свободна';
  setTextIfChanged($('#activity-panel-summary'), activitySummary);
  $('#activity-empty-title').textContent = filter === 'attention' ? 'Ошибок нет' : 'Очередь свободна';
  $('#activity-empty-copy').textContent = filter === 'attention'
    ? 'Все завершённые запуски в порядке.'
    : 'Сейчас ничего не запущено. Можно выбрать софты и отправить их одной пачкой.';
  const tableBody = $('#activity-table-body');
  const focusedControl = tableBody.contains(document.activeElement)
    ? document.activeElement.closest('[data-activity-control]')
    : null;
  const focusKey = focusedControl?.dataset.activityControl || '';
  const focusRunId = focusedControl?.dataset.openRun
    || focusedControl?.dataset.requestRunStop
    || focusedControl?.dataset.reviewRun
    || '';
  const tableMarkup = activityTableMarkup(visibleRows);
  if (tableBody.innerHTML !== tableMarkup) {
    tableBody.innerHTML = tableMarkup;
    if (focusKey) {
      const exactReplacement = $$('[data-activity-control]', tableBody)
        .find((control) => control.dataset.activityControl === focusKey);
      const runFallback = $$('[data-open-run]', tableBody)
        .find((control) => control.dataset.openRun === focusRunId);
      (exactReplacement || runFallback || $('#activity-panel-close')).focus({ preventScroll: true });
    }
  }
  panel.setAttribute('aria-busy', String(state.activityAccountsLoading));
}

function setActivityFilter(filter) {
  state.activityFilter = filter === 'attention' ? 'attention' : 'active';
  renderActivityPanel();
}

function resolveActivityFilter(filter = 'active') {
  if (filter !== 'auto') return filter === 'attention' ? 'attention' : 'active';
  const attentionCount = state.activityAccountsLoaded
    ? activityRows('attention').length
    : Number(state.data?.stats.attention_runs || 0);
  return attentionCount ? 'attention' : 'active';
}

function openActivityPanel(filter = 'active', origin = document.activeElement) {
  const panel = $('#activity-panel');
  if (!$('#run-drawer').hidden || state.selectedRunId) {
    closeRunDrawer({ restoreFocus: false, immediate: true });
  }
  const resolvedFilter = resolveActivityFilter(filter);
  if (panel.hidden && origin instanceof HTMLElement && !panel.contains(origin)) {
    state.activityFocusOrigin = origin;
  }
  if (state.activityPanelTimer) window.clearTimeout(state.activityPanelTimer);
  state.activityPanelTimer = null;
  panel.hidden = false;
  panel.classList.remove('is-closing');
  $$('[aria-controls="activity-panel"]').forEach((control) => control.setAttribute('aria-expanded', 'true'));
  setActivityFilter(resolvedFilter);
  void loadActivityAccounts({ silent: state.activityAccountsLoaded });
  window.requestAnimationFrame(() => $('#activity-panel-close').focus({ preventScroll: true }));
}

function toggleActivityPanel(filter = 'active', origin = document.activeElement) {
  const panel = $('#activity-panel');
  const resolvedFilter = resolveActivityFilter(filter);
  const fullyOpen = !panel.hidden && !panel.classList.contains('is-closing');
  if (fullyOpen && state.activityFilter === resolvedFilter) {
    closeActivityPanel();
    return;
  }
  openActivityPanel(resolvedFilter, origin);
}

function closeActivityPanel({ restoreFocus = true, immediate = false } = {}) {
  const panel = $('#activity-panel');
  if (panel.hidden) return;
  if (state.activityPanelTimer) window.clearTimeout(state.activityPanelTimer);
  $$('[aria-controls="activity-panel"]').forEach((control) => control.setAttribute('aria-expanded', 'false'));
  const finish = () => {
    panel.hidden = true;
    panel.classList.remove('is-closing');
    state.activityPanelTimer = null;
    const origin = state.activityFocusOrigin;
    state.activityFocusOrigin = null;
    if (restoreFocus && origin?.isConnected) origin.focus({ preventScroll: true });
  };
  if (immediate || window.matchMedia('(prefers-reduced-motion: reduce)').matches) finish();
  else {
    panel.classList.add('is-closing');
    state.activityPanelTimer = window.setTimeout(finish, 170);
  }
}

async function refreshActivityPanel() {
  const button = $('#activity-panel-refresh');
  setBusy(button, true, 'Обновляем…');
  $('#activity-panel').setAttribute('aria-busy', 'true');
  try {
    await refresh({ spin: true });
    await loadActivityAccounts();
  } finally {
    setBusy(button, false);
  }
}

async function openRunStopFlow(runId) {
  await openRunDrawer(runId);
  if (state.selectedRunId !== runId) return;
  const safeStop = $('#drawer-stop');
  const forceStop = $('#drawer-force-stop');
  const target = !safeStop.hidden ? safeStop : forceStop;
  target?.focus({ preventScroll: true });
}

const RESULT_REPORT_ATTENTION_STATUSES = new Set(['failed', 'blocked', 'needs_attention', 'unknown']);
const RESULT_REPORT_NUMBER_FORMATTER = new Intl.NumberFormat('ru-RU', { maximumSignificantDigits: 12 });
const RESULT_REPORT_INTEGER_FORMATTER = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 0 });

function resultReportDataSignature(data) {
  const runs = Array.isArray(data?.runs) ? data.runs : [];
  return JSON.stringify([
    Number(data?.stats?.results || 0),
    ...runs.map((run) => [run.id, run.status, run.finished_at || '']),
  ]);
}

function resultReportOutput(report) {
  const output = report?.output || report?.output_schema || {};
  return output && typeof output === 'object' ? output : {};
}

function resultReportColumns(report) {
  const columns = resultReportOutput(report).columns;
  return Array.isArray(columns) ? columns.slice(0, 12).filter((column) => (
    column
    && typeof column.key === 'string'
    && typeof column.title === 'string'
    && ['string', 'integer', 'number', 'decimal_string', 'boolean'].includes(column.type)
  )) : [];
}

function resultReportModule(report) {
  return state.data?.modules.find((module) => module.id === report?.module_id) || null;
}

function resultReportAction(report) {
  const module = resultReportModule(report);
  return module?.manifest?.actions?.find((action) => action.id === report?.action_id) || null;
}

function resultReportName(report) {
  const module = resultReportModule(report);
  return report?.module_name || (module ? moduleDisplayName(module) : report?.module_id) || 'Удалённый софт';
}

function resultReportActionName(report) {
  return report?.action_name || resultReportAction(report)?.name || report?.action_id || 'Парсинг';
}

function normalizeResultReports(payload) {
  const source = Array.isArray(payload?.reports)
    ? payload.reports
    : Array.isArray(payload?.overview)
      ? payload.overview
      : [];
  return source
    .filter((report) => report && typeof report.run_id === 'string' && resultReportOutput(report).mode === 'account_table')
    .sort((first, second) => String(second.finished_at || second.requested_at || '').localeCompare(String(first.finished_at || first.requested_at || '')));
}

function visibleResultReports() {
  if (state.resultCatalogFilter === 'all') return state.resultReports;
  return state.resultReports.filter((report) => recordBelongsToCatalog(report, state.resultCatalogFilter));
}

function resetResultReportPresentation() {
  $('#result-report-workbench').dataset.stale = 'false';
  $('#result-report-title').textContent = 'Отчёт парсинга';
  $('#result-report-copy').textContent = 'Выберите запуск — Hub соберёт показатели по всем аккаунтам в одну таблицу.';
  $('#result-report-table-title').textContent = 'Кошельки';
  $('#result-report-visible-count').textContent = '0 строк';
  $('#result-report-export').textContent = 'Скачать CSV';
  $('#result-report-export').title = 'Скачать строки текущего фильтра';
}

function setResultReportState(title, copy, mode = 'empty') {
  const stateBox = $('#result-report-state');
  resetResultReportPresentation();
  $('#result-report-workbench').setAttribute('aria-busy', String(mode === 'loading'));
  stateBox.dataset.state = mode;
  stateBox.hidden = false;
  $('#result-report-content').hidden = true;
  stateBox.innerHTML = `<span class="empty-glyph">${mode === 'loading' ? '••' : mode === 'error' ? '!' : '07'}</span><h3>${escapeHtml(title)}</h3><p>${escapeHtml(copy)}</p>`;
  $('#result-report-export').disabled = true;
}

function renderResultReportSelector() {
  const select = $('#result-report-select');
  if (!select) return;
  const reports = visibleResultReports();
  if (!reports.length) {
    select.innerHTML = '<option value="">Пока нет готовых отчётов</option>';
    select.value = '';
    select.disabled = true;
    return;
  }
  select.disabled = false;
  select.innerHTML = reports.map((report) => {
    const when = ACTIVE_RUN_STATUSES.has(report.run_status)
      ? 'работает сейчас'
      : fullDateTime(report.finished_at || report.requested_at) || 'время не указано';
    return `<option value="${escapeHtml(report.run_id)}">${escapeHtml(resultReportName(report))} · ${escapeHtml(resultReportActionName(report))} · ${escapeHtml(when)}</option>`;
  }).join('');
  const available = reports.some((report) => report.run_id === state.selectedResultReportId);
  if (!available) state.selectedResultReportId = reports[0].run_id;
  select.value = state.selectedResultReportId;
}

function renderResultReportWorkbench() {
  if (!$('#result-report-workbench') || !state.data) return;
  const locked = state.data.vault.exists && !state.data.vault.unlocked;
  renderResultReportSelector();
  if (locked) {
    setResultReportState('Статистика скрыта вместе с Vault', 'Разблокируйте Hub — после этого здесь появятся отчёты по кошелькам.');
    return;
  }
  if (state.resultReportsLoading && !state.resultReportsLoaded) {
    setResultReportState('Собираем отчёты', 'Проверяем готовые запуски и их статистику.', 'loading');
    return;
  }
  if (state.resultReportsError && !state.selectedResultReport) {
    setResultReportState('Не получилось загрузить статистику', state.resultReportsError, 'error');
    return;
  }
  if (!state.resultReportsLoaded) {
    setResultReportState('Собираем список отчётов', 'Это займёт пару секунд.', 'loading');
    return;
  }
  if (!visibleResultReports().length) {
    setResultReportState('Готовых таблиц пока нет', 'Запустите у софта действие «Парсинг». Чтобы Hub собрал таблицу, действие должно объявить output account_table и сохранить результат по каждому кошельку.');
    return;
  }
  if (!state.selectedResultReport) {
    setResultReportState('Открываем выбранный запуск', 'Собираем строки по всем кошелькам.', 'loading');
    return;
  }
  renderSelectedResultReport();
}

async function loadResultReports({ force = false } = {}) {
  if (!state.data || (state.data.vault.exists && !state.data.vault.unlocked)) {
    renderResultReportWorkbench();
    return;
  }
  if (state.resultReportsLoading) {
    if (force) state.resultReportsRefreshPending = true;
    return;
  }
  if (state.resultReportsLoaded && !force) return;
  const generation = ++state.resultReportsRequestGeneration;
  const protectedDataEpoch = state.protectedDataEpoch;
  const hadSelectedReport = Boolean(state.selectedResultReport);
  state.resultReportsLoading = true;
  state.resultReportsError = '';
  renderResultReportWorkbench();
  renderCatalogWorkspaces();
  try {
    const payload = await api('/api/results/overview?limit=500');
    if (generation !== state.resultReportsRequestGeneration || protectedDataEpoch !== state.protectedDataEpoch) return;
    state.resultReports = normalizeResultReports(payload);
    state.resultReportsLoaded = true;
    renderResultReportSelector();
    if (state.resultReports.length) await loadSelectedResultReport(state.selectedResultReportId, { force });
    else state.selectedResultReport = null;
  } catch (error) {
    if (generation !== state.resultReportsRequestGeneration || protectedDataEpoch !== state.protectedDataEpoch) return;
    state.resultReportsError = error.message;
    state.resultReportsLoaded = true;
    if (!hadSelectedReport) state.selectedResultReport = null;
  } finally {
    if (generation === state.resultReportsRequestGeneration) {
      state.resultReportsLoading = false;
      renderResultReportWorkbench();
      renderCatalogWorkspaces();
      const refreshAgain = state.resultReportsRefreshPending;
      state.resultReportsRefreshPending = false;
      if (refreshAgain) void loadResultReports({ force: true });
    }
  }
}

async function loadSelectedResultReport(runId, { force = false } = {}) {
  if (!runId || (state.selectedResultReport?.report?.run_id === runId && !force)) {
    renderResultReportWorkbench();
    return;
  }
  const generation = ++state.resultReportRequestGeneration;
  const protectedDataEpoch = state.protectedDataEpoch;
  const refreshingCurrent = state.selectedResultReport?.report?.run_id === runId;
  state.selectedResultReportId = runId;
  if (!refreshingCurrent) state.selectedResultReport = null;
  state.resultReportLoading = true;
  state.resultReportsError = '';
  renderResultReportSelector();
  renderResultReportWorkbench();
  try {
    const payload = await api(`/api/results/report?run_id=${encodeURIComponent(runId)}&limit=2000`);
    if (generation !== state.resultReportRequestGeneration || protectedDataEpoch !== state.protectedDataEpoch) return;
    state.selectedResultReport = payload;
  } catch (error) {
    if (generation !== state.resultReportRequestGeneration || protectedDataEpoch !== state.protectedDataEpoch) return;
    state.resultReportsError = error.message;
  } finally {
    if (generation === state.resultReportRequestGeneration) state.resultReportLoading = false;
    renderResultReportWorkbench();
  }
}

function selectedResultReportEnvelope() {
  const payload = state.selectedResultReport || {};
  return payload.report || state.resultReports.find((report) => report.run_id === state.selectedResultReportId) || {};
}

function resultReportRows() {
  return Array.isArray(state.selectedResultReport?.rows) ? state.selectedResultReport.rows : [];
}

function resultReportRowHasData(row) {
  return row?.has_result === true || Boolean(row?.result_id || row?.result_created_at || row?.created_at);
}

function resultReportRowData(row) {
  const data = row?.data || row?.result_data || {};
  return data && typeof data === 'object' && !Array.isArray(data) ? data : {};
}

function resultReportValue(column, value) {
  if (value === null || value === undefined || value === '') return '—';
  if (column.type === 'boolean') return value === true ? 'Да' : value === false ? 'Нет' : String(value);
  if (column.type === 'integer') {
    if (typeof value === 'string' && /^-?\d+$/.test(value)) {
      try {
        return RESULT_REPORT_INTEGER_FORMATTER.format(BigInt(value));
      } catch (_error) {
        return value;
      }
    }
    const numeric = Number(value);
    if (Number.isSafeInteger(numeric)) return RESULT_REPORT_INTEGER_FORMATTER.format(numeric);
  }
  if (column.type === 'number') {
    const numeric = Number(value);
    if (Number.isFinite(numeric)) {
      if (numeric !== 0 && Math.abs(numeric) < 1e-8) return numeric.toExponential(6);
      return RESULT_REPORT_NUMBER_FORMATTER.format(numeric);
    }
  }
  return String(value);
}

function resultReportRowMatchesStatus(row, filter) {
  const status = String(row?.status || 'unknown');
  if (filter === 'all') return true;
  if (filter === 'attention') return RESULT_REPORT_ATTENTION_STATUSES.has(status);
  if (filter === 'missing') return !resultReportRowHasData(row);
  return status === filter;
}

function filteredResultReportRows(columns = resultReportColumns(selectedResultReportEnvelope())) {
  const query = $('#result-report-search')?.value.trim().toLowerCase() || '';
  const status = $('#result-report-status')?.value || 'all';
  return resultReportRows().filter((row) => {
    if (!resultReportRowMatchesStatus(row, status)) return false;
    if (!query) return true;
    const data = resultReportRowData(row);
    return [
      row.account_label,
      row.account_address,
      row.title,
      ...columns.map((column) => resultReportValue(column, data[column.key])),
    ].filter(Boolean).some((value) => String(value).toLowerCase().includes(query));
  });
}

function scheduleResultReportFilterRender() {
  if (state.resultReportFilterTimer) window.clearTimeout(state.resultReportFilterTimer);
  state.resultReportFilterTimer = window.setTimeout(() => {
    state.resultReportFilterTimer = null;
    if (state.selectedResultReport) renderSelectedResultReport();
  }, 140);
}

function resultReportSystemMetrics(report, rows) {
  const counts = report?.counts && typeof report.counts === 'object' ? report.counts : {};
  const count = (status) => Number.isFinite(Number(counts[status]))
    ? Number(counts[status])
    : rows.filter((row) => row.status === status).length;
  const total = Number.isFinite(Number(report?.total)) ? Number(report.total) : rows.length;
  const succeeded = count('succeeded');
  const partial = count('partial');
  const attention = count('failed') + count('blocked') + count('needs_attention') + count('unknown');
  const fullResultCount = Number(state.selectedResultReport?.result_count);
  const missing = Number.isFinite(fullResultCount)
    ? Math.max(0, total - fullResultCount)
    : rows.filter((row) => !resultReportRowHasData(row)).length;
  return [
    { title: 'Кошельков в запуске', value: total, note: 'вся выбранная пачка', accent: 'tangerine' },
    { title: 'Успешно', value: succeeded, note: 'подтверждено lifecycle', accent: 'teal' },
    { title: 'Частично', value: partial, note: 'есть полезный результат', accent: 'butter' },
    {
      title: 'С ошибками',
      value: attention,
      note: missing
        ? `${ACTIVE_RUN_STATUSES.has(report?.run_status) ? 'ещё без результата' : 'без результата'}: ${missing}`
        : 'ошибок без результата нет',
      accent: 'olive',
    },
  ];
}

function resultReportAggregateMetrics(report) {
  const aggregates = state.selectedResultReport?.aggregates;
  if (!aggregates || typeof aggregates !== 'object') return [];
  return resultReportColumns(report).filter((column) => column.aggregate && Object.hasOwn(aggregates, column.key)).slice(0, 4).map((column, index) => {
    const aggregate = aggregates[column.key];
    const value = aggregate && typeof aggregate === 'object' ? aggregate.value : aggregate;
    const count = aggregate && typeof aggregate === 'object' ? Number(aggregate.count || 0) : 0;
    return {
      title: column.title,
      value: value === null || value === undefined ? '—' : resultReportValue(column, value),
      note: `${({ sum: 'сумма', avg: 'среднее', min: 'минимум', max: 'максимум' })[column.aggregate] || 'итог'}${count ? ` · ${count} знач.` : ''}`,
      accent: ['olive', 'butter', 'teal', 'rose'][index % 4],
    };
  });
}

function renderSelectedResultReport() {
  const report = selectedResultReportEnvelope();
  const columns = resultReportColumns(report);
  const rows = resultReportRows();
  const filtered = filteredResultReportRows(columns);
  const output = resultReportOutput(report);
  const total = Number.isFinite(Number(report.total)) ? Number(report.total) : rows.length;
  const truncated = state.selectedResultReport?.truncated === true;
  const active = ACTIVE_RUN_STATUSES.has(report.run_status);
  const stale = Boolean(state.resultReportsError);
  const runMoment = active
    ? 'идёт сейчас'
    : fullDateTime(report.finished_at || report.requested_at) || 'готовый запуск';
  $('#result-report-workbench').setAttribute('aria-busy', String(state.resultReportsLoading || state.resultReportLoading));
  $('#result-report-workbench').dataset.stale = String(stale);
  $('#result-report-state').hidden = true;
  $('#result-report-content').hidden = false;
  $('#result-report-export').disabled = !filtered.length || truncated;
  $('#result-report-export').textContent = truncated ? 'CSV: слишком много строк' : 'Скачать CSV';
  $('#result-report-export').title = truncated ? 'В запуске больше 2000 кошельков. Hub не скачивает неполную таблицу.' : 'Скачать строки текущего фильтра';
  $('#result-report-title').textContent = output.title || 'Отчёт парсинга';
  $('#result-report-copy').textContent = `${resultReportName(report)} · ${resultReportActionName(report)} · ${runMoment}${truncated ? ' · показана только часть строк' : ''}${stale ? ' · не удалось обновить, показана сохранённая версия' : ''}`;
  $('#result-report-table-title').textContent = `${resultReportName(report)} · ${resultReportActionName(report)}`;
  $('#result-report-visible-count').textContent = truncated
    ? `${filtered.length} найдено · загружено ${rows.length} из ${total}`
    : `${filtered.length} из ${total} ${countWord(total, 'строки', 'строк', 'строк')}`;
  const metrics = [...resultReportSystemMetrics(report, rows), ...resultReportAggregateMetrics(report)];
  $('#result-report-summary').innerHTML = metrics.map((metric) => `<article class="result-report-metric" data-accent="${escapeHtml(metric.accent)}"><small>${escapeHtml(metric.title)}</small><strong title="${escapeHtml(String(metric.value))}">${escapeHtml(String(metric.value))}</strong><em>${escapeHtml(metric.note)}</em></article>`).join('');
  $('#result-report-table-head').innerHTML = `<tr><th scope="col">Аккаунт</th><th scope="col">Кошелёк</th><th scope="col">Статус</th>${columns.map((column) => `<th scope="col">${escapeHtml(column.title)}</th>`).join('')}<th scope="col">Время</th></tr>`;
  $('#result-report-table-body').innerHTML = filtered.length ? filtered.map((row) => {
    const data = resultReportRowData(row);
    const status = String(row.status || 'unknown');
    const resultTime = row.result_created_at || row.created_at;
    return `<tr data-status="${escapeHtml(status)}"><td title="${escapeHtml(row.account_label || row.account_id || '')}">${escapeHtml(row.account_label || row.account_id || 'Без названия')}</td><td data-cell="address" title="${escapeHtml(row.account_address || '')}">${escapeHtml(row.account_address || '—')}</td><td><span class="result-report-status" data-status="${escapeHtml(status)}">${escapeHtml(resultStatusLabel(status))}</span></td>${columns.map((column) => {
      const value = resultReportValue(column, data[column.key]);
      const empty = value === '—';
      return `<td data-cell="${['integer', 'number', 'decimal_string'].includes(column.type) ? 'number' : 'value'}" data-empty="${empty}" title="${escapeHtml(value)}">${escapeHtml(value)}</td>`;
    }).join('')}<td title="${escapeHtml(fullDateTime(resultTime))}">${escapeHtml(relativeTime(resultTime))}</td></tr>`;
  }).join('') : `<tr class="result-report-empty-row"><td colspan="${columns.length + 4}">По этому фильтру ничего не нашлось. Сбросьте поиск или выберите другой статус.</td></tr>`;
}

function csvSafeCell(value, { formulaGuard = true } = {}) {
  let text = value === null || value === undefined ? '' : String(value);
  if (formulaGuard && /^[=+\-@\t\r\n]/.test(text)) text = `'${text}`;
  return `"${text.replaceAll('"', '""')}"`;
}

function resultReportRawExportValue(column, value) {
  if (value === null || value === undefined) return '';
  if (column.type === 'boolean') return value === true ? 'Да' : value === false ? 'Нет' : String(value);
  return String(value);
}

function exportSelectedResultReport() {
  const report = selectedResultReportEnvelope();
  const columns = resultReportColumns(report);
  const rows = filteredResultReportRows(columns);
  if (state.selectedResultReport?.truncated === true) {
    toast('В запуске больше 2000 строк. Hub не будет скачивать неполный CSV.', 'error', 6200);
    return;
  }
  if (!rows.length) {
    toast('В текущем фильтре нет строк для скачивания.', 'error');
    return;
  }
  const header = ['Аккаунт', 'Кошелёк', 'Статус', ...columns.map((column) => column.title), 'Время'];
  const lines = [header.map((value) => csvSafeCell(value)), ...rows.map((row) => {
    const data = resultReportRowData(row);
    return [
      csvSafeCell(row.account_label || row.account_id || ''),
      csvSafeCell(row.account_address || ''),
      csvSafeCell(resultStatusLabel(row.status)),
      ...columns.map((column) => csvSafeCell(
        resultReportRawExportValue(column, data[column.key]),
        { formulaGuard: !['integer', 'number', 'decimal_string'].includes(column.type) },
      )),
      csvSafeCell(fullDateTime(row.result_created_at || row.created_at)),
    ].join(',');
  })];
  const blob = new Blob([`\uFEFF${lines.join('\r\n')}\r\n`], { type: 'text/csv;charset=utf-8' });
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement('a');
  const safeName = `${resultReportName(report)}-${resultReportActionName(report)}`.toLowerCase().replace(/[^a-z0-9а-яё_-]+/gi, '-').replace(/^-|-$/g, '') || 'parsing';
  link.href = objectUrl;
  link.download = `soft-hub-${safeName}-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
  toast(`Скачали ${rows.length} ${countWord(rows.length, 'строку', 'строки', 'строк')}. Фильтр сохранён в CSV.`);
}

function groupResultsByModule(results) {
  const groups = new Map();
  for (const result of results) {
    const moduleId = String(result.module_id || 'unknown');
    if (!groups.has(moduleId)) groups.set(moduleId, []);
    groups.get(moduleId).push(result);
  }
  return Array.from(groups, ([moduleId, items]) => ({ moduleId, items }));
}

function resultStatusLabel(status) {
  return accountStatusNames[status] || statusNames[status] || 'Зафиксировано';
}

function resultTone(status) {
  if (status === 'succeeded') return 'success';
  if (['partial', 'failed', 'blocked', 'needs_attention'].includes(status)) return 'attention';
  return 'neutral';
}

function resultGroupSummary(items) {
  const succeeded = items.filter((item) => item.status === 'succeeded').length;
  const attention = items.filter((item) => resultTone(item.status) === 'attention').length;
  return [
    succeeded ? `<span data-tone="success">${succeeded} успешно</span>` : '',
    attention ? `<span data-tone="attention">${attention} ${countWord(attention, 'ошибка', 'ошибки', 'ошибок')}</span>` : '',
    `<span>${items.length} ${countWord(items.length, 'результат', 'результата', 'результатов')}</span>`,
  ].filter(Boolean).join('');
}

function renderResults() {
  if (!state.data) return;
  const allResults = Array.isArray(state.data.results) ? state.data.results : [];
  const results = state.resultCatalogFilter === 'all'
    ? allResults
    : allResults.filter((result) => recordBelongsToCatalog(result, state.resultCatalogFilter));
  const root = $('#results-list');
  const modules = new Map(state.data.modules.map((module) => [module.id, module]));
  const groups = groupResultsByModule(results);
  const locked = state.data.vault.exists && !state.data.vault.unlocked;
  setResultCatalogFilter(state.resultCatalogFilter);
  root.innerHTML = groups.length
    ? groups.map(({ moduleId, items }, index) => {
      const module = modules.get(moduleId) || {
        id: moduleId,
        name: items[0]?.module_name || 'Удалённый софт',
        version: '',
        manifest: {},
      };
      const expanded = state.resultModuleExpansion.has(moduleId)
        ? state.resultModuleExpansion.get(moduleId)
        : index === 0;
      return `
        <details class="result-software-group border-glow" data-result-module="${escapeHtml(moduleId)}" ${expanded ? 'open' : ''}>
          <summary>
            ${moduleIconMarkup(module)}
            <span class="result-group-heading"><small>СОФТ</small><strong>${escapeHtml(moduleDisplayName(module))}</strong><em>Последний результат ${escapeHtml(relativeTime(items[0]?.created_at))}</em></span>
            <span class="result-group-summary">${resultGroupSummary(items)}</span>
            <span class="result-group-chevron" aria-hidden="true"></span>
          </summary>
          <div class="result-group-body" role="list">
            ${items.map((result) => {
              const tone = resultTone(result.status);
              const icon = tone === 'success' ? 'check' : tone === 'attention' ? 'alert' : 'history';
              return `
                <article class="result-entry" data-status="${escapeHtml(result.status)}" data-tone="${tone}" role="listitem">
                  <span class="result-entry-icon" aria-hidden="true">${iconMarkup(icon)}</span>
                  <div class="result-entry-copy">
                    <h3>${escapeHtml(result.title)}</h3>
                    <p><span>${escapeHtml(result.account_label || 'Общий итог запуска')}</span><span>${escapeHtml(resultStatusLabel(result.status))}</span><span>${escapeHtml(relativeTime(result.created_at))}</span></p>
                  </div>
                </article>`;
            }).join('')}
          </div>
        </details>`;
    }).join('')
    : locked
      ? '<div class="empty-state panel"><span class="empty-glyph">••</span><h3>Результаты скрыты, пока Vault закрыт</h3><p>Разблокируйте его, чтобы увидеть итоги по аккаунтам.</p></div>'
      : '<div class="empty-state panel"><span class="empty-glyph">05</span><h3>Результатов пока нет</h3><p>После запуска здесь появятся группы софтов и итоги по каждому аккаунту.</p></div>';
  $$('[data-result-module]', root).forEach((group) => {
    group.addEventListener('toggle', () => {
      state.resultModuleExpansion.set(group.dataset.resultModule, group.open);
    });
  });
  decorateAnimatedList(root);
  syncPresentationAssets();
}

function renderPatchFeed({ animate = false } = {}) {
  const root = $('#patch-feed-grid');
  const status = $('#patch-feed-status');
  const patches = state.patchFeed;
  const owner = state.data?.patch_feed?.owner || $('#patch-feed-owner').value.trim();
  if (!state.patchFeedLoaded) {
    root.hidden = true;
    status.textContent = owner ? `@${owner} · ещё не проверяли` : 'Профиль не подключён';
    return;
  }
  root.hidden = false;
  if (!patches.length) {
    root.innerHTML = '<div class="patch-feed-empty"><strong>Патчей пока нет</strong><small>Нужен открытый репозиторий с .patch в конце и свежий релиз с одним файлом .softhub.zip.</small></div>';
    status.textContent = `@${owner} · 0 патчей`;
    return;
  }
  const ready = patches.filter((patch) => patch.status === 'ready').length;
  const available = patches.filter((patch) => patch.installable === true).length;
  status.textContent = `@${owner} · к установке ${available} · проверено ${ready} из ${patches.length}`;
  root.innerHTML = patches.map((patch) => {
    const versionState = patch.version_state || 'unavailable';
    const stateLabel = versionState === 'installed'
      ? 'УСТАНОВЛЕН'
      : versionState === 'removed_current'
        ? 'УДАЛЁН'
        : versionState === 'removed_update_available'
          ? 'МОЖНО ВЕРНУТЬ'
          : versionState === 'removed_newer_known'
            ? 'СТАРАЯ ВЕРСИЯ'
      : versionState === 'update_available'
        ? 'ЕСТЬ ОБНОВЛЕНИЕ'
        : versionState === 'newer_installed'
          ? 'УСТАНОВЛЕНА НОВЕЕ'
          : versionState === 'identity_conflict'
            ? 'КОНФЛИКТ'
            : versionState === 'version_unknown'
              ? 'НУЖНА ПРОВЕРКА'
              : patch.status === 'ready' ? 'ГОТОВ' : patch.status === 'missing_release' ? 'НЕТ РЕЛИЗА' : 'ПРОВЕРЬТЕ ФАЙЛЫ';
    const metadataReason = patch.reason === 'installable_asset_missing'
      ? 'В последнем релизе нет пакета .softhub'
      : patch.reason === 'multiple_installable_assets'
        ? 'В последнем релизе несколько пакетов .softhub — оставьте один'
        : patch.reason === 'latest_release_not_found'
          ? 'Последний релиз ещё не опубликован'
          : patch.reason === 'unsafe_or_incomplete_asset_metadata'
            ? 'Файл не прошёл проверку безопасности'
          : patch.status === 'ready' ? `Релиз ${patch.release_tag} готов` : 'Описание релиза нужно проверить';
    const reason = versionState === 'installed'
      ? `v${patch.installed_version} уже установлена`
      : versionState === 'removed_current'
        ? `v${patch.installed_version} удалена и не может быть установлена повторно`
        : versionState === 'removed_update_available'
          ? `После удаления доступна новая v${patch.candidate_version}`
          : versionState === 'removed_newer_known'
            ? `Hub уже знает более новую v${patch.installed_version}`
      : versionState === 'update_available'
        ? `Доступно обновление v${patch.installed_version} → v${patch.candidate_version}`
        : versionState === 'newer_installed'
          ? `Установлена более новая v${patch.installed_version}`
          : versionState === 'identity_conflict'
            ? 'Репозиторий и установленный софт не совпадают по ID'
            : versionState === 'version_unknown'
              ? 'Не получилось надёжно сравнить версии релиза и установленного софта'
              : metadataReason;
    const repositoryUrl = typeof patch.repository_url === 'string' ? patch.repository_url : '';
    const installLabel = ['update_available', 'removed_update_available'].includes(versionState) && patch.candidate_version
      ? `Обновить до v${patch.candidate_version}`
      : 'Установить';
    return `
      <article class="patch-feed-card">
        <div class="patch-feed-card-head"><span class="module-version">${escapeHtml(patch.candidate_version ? `v${patch.candidate_version}` : patch.release_tag || 'БЕЗ ТЕГА')}</span><span class="discovery-state" data-state="${escapeHtml(['update_available', 'removed_update_available'].includes(versionState) ? 'update' : versionState)}">${stateLabel}</span></div>
        <h3>${escapeHtml(patch.repository)}</h3>
        <p>${escapeHtml(patch.description || reason)}</p>
        <footer><small>${escapeHtml(reason)} · ${escapeHtml(relativeTime(patch.pushed_at))}</small><span class="patch-feed-actions">${repositoryUrl ? `<a class="button button--quiet" href="${escapeHtml(repositoryUrl)}" target="_blank" rel="noopener noreferrer" data-open-patch-repository="${escapeHtml(repositoryUrl)}">GitHub</a>` : ''}${patch.installable === true ? `<button class="button button--ink specular-button" type="button" data-install-patch="${escapeHtml(patch.asset_url)}">${escapeHtml(installLabel)}</button>` : ''}</span></footer>
      </article>`;
  }).join('');
  decorateAnimatedList(root, animate);
}

async function scanPatchFeed({ silent = false } = {}) {
  if (state.patchFeedLoading) return;
  const input = $('#patch-feed-owner');
  const owner = input.value.trim() || state.data?.patch_feed?.owner || '';
  if (!owner) {
    if (!silent) toast('Введите имя пользователя GitHub или ссылку на профиль.', 'error');
    return;
  }
  const button = $('#patch-feed-scan-button');
  state.patchFeedLoading = true;
  $('#patch-feed-status').textContent = 'Проверяем открытые репозитории…';
  setBusy(button, true, 'Проверяем…');
  try {
    const payload = await jsonPost('/api/patch-feed/scan', { owner });
    state.patchFeed = payload.patches;
    state.patchFeedLoaded = true;
    state.data.patch_feed.owner = payload.owner;
    input.value = payload.owner;
    renderPatchFeed({ animate: !silent });
    renderMetrics();
    if (!silent) toast(`Найдено патчей: ${payload.patches.length}`);
  } catch (error) {
    state.patchFeed = [];
    state.patchFeedLoaded = false;
    $('#patch-feed-grid').replaceChildren();
    $('#patch-feed-grid').hidden = true;
    renderMetrics();
    $('#patch-feed-status').textContent = error.message;
    if (!silent) toast(error.message, 'error', 7000);
  } finally {
    state.patchFeedLoading = false;
    setBusy(button, false);
  }
}

async function installPatchAsset(url, button) {
  setBusy(button, true, 'Устанавливаем…');
  try {
    const module = await jsonPost('/api/modules/install/github', { url });
    await refresh();
    await scanPatchFeed({ silent: true });
    toast(`${moduleDisplayName(module)} v${module.version} установлен из Patch Radar`, 'success', 6200);
    showView('software');
  } catch (error) {
    toast(error.message, 'error', 8000);
  } finally {
    setBusy(button, false);
  }
}

function renderAll() {
  renderMetrics();
  renderCoreUpdateGuide();
  updateVaultState();
  renderOverviewRuns();
  renderOverviewModules();
  renderSoftware();
  renderAccounts();
  renderActivityPanel();
  renderResults();
  renderResultReportWorkbench();
  renderCatalogWorkspaces();
  renderPatchFeed();
  syncPresentationAssets();
  const configuredOwner = state.data.patch_feed?.owner || '';
  if (configuredOwner && !$('#patch-feed-owner').value) $('#patch-feed-owner').value = configuredOwner;
  $('#app-version').textContent = `v${state.data.app.version}`;
  if (!state.focusOrigin?.isConnected && state.focusOriginIdentity) {
    state.focusOrigin = findFocusIdentity(state.focusOriginIdentity);
  }
}

function refresh(options = {}) {
  state.refreshPending = true;
  state.refreshSpinPending = state.refreshSpinPending || options.spin === true;
  if (state.refreshPromise) return state.refreshPromise;
  state.refreshing = true;
  const button = $('#refresh-button');
  const drain = async () => {
    while (state.refreshPending) {
      state.refreshPending = false;
      if (state.refreshSpinPending) button.classList.add('is-spinning');
      state.refreshSpinPending = false;
      const activeBeforeRender = document.activeElement;
      const activeIdentity = focusIdentity(activeBeforeRender);
      const protectedDataEpoch = state.protectedDataEpoch;
      try {
        const nextData = await api('/api/bootstrap');
        if (protectedDataEpoch !== state.protectedDataEpoch) continue;
        const transitionedToLocked = Boolean(
          state.data?.vault?.unlocked
          && nextData?.vault?.exists
          && !nextData.vault.unlocked
        );
        if (transitionedToLocked) purgeProtectedClientState();
        const reportSignature = resultReportDataSignature(nextData);
        const reportsChanged = reportSignature !== state.resultReportBootstrapSignature;
        state.resultReportBootstrapSignature = reportSignature;
        state.data = nextData;
        renderAll();
        if (
          (reportsChanged || !state.resultReportsLoaded)
          && ['results', 'nft', 'testnets'].includes(state.view)
          && nextData?.vault?.unlocked
        ) {
          void loadResultReports({ force: true });
        }
        if (
          activeBeforeRender instanceof HTMLElement
          && !activeBeforeRender.isConnected
          && !state.selectedRunId
          && !$('.modal:not([hidden])')
        ) {
          findFocusIdentity(activeIdentity)?.focus({ preventScroll: true });
        }
        if (state.selectedRunId) await updateDrawer();
      } catch (error) {
        toast(error.message, 'error', 6000);
        $('#command-title').textContent = 'Hub не отвечает.';
        $('#command-detail').textContent = 'Перезапустите Soft Hub и попробуйте ещё раз.';
      }
    }
  };
  let promise;
  promise = drain().finally(() => {
    state.refreshing = false;
    if (state.refreshPromise === promise) state.refreshPromise = null;
    button.classList.remove('is-spinning');
    if (state.refreshPending) return refresh();
    return undefined;
  });
  state.refreshPromise = promise;
  return promise;
}

function requestDestructiveConfirmation({ title, message, confirmLabel, phrase = '', tone = 'danger' }) {
  if (state.destructiveRequest) return Promise.resolve(false);
  return new Promise((resolve) => {
    state.destructiveRequest = { resolve, phrase };
    const modal = $('#destructive-modal');
    const submit = $('#destructive-submit');
    modal.dataset.tone = tone === 'update' ? 'update' : 'danger';
    $('#destructive-modal-title').textContent = title;
    $('#destructive-modal-copy').textContent = message;
    submit.textContent = confirmLabel;
    submit.classList.toggle('button--danger', tone !== 'update');
    submit.classList.toggle('button--ink', tone === 'update');
    $('#destructive-phrase-label').hidden = !phrase;
    $('#destructive-phrase').required = Boolean(phrase);
    $('#destructive-phrase').value = '';
    $('#destructive-phrase-copy').textContent = phrase ? `Для подтверждения введите: ${phrase}` : '';
    $('#destructive-error').hidden = true;
    openModal('destructive-modal');
  });
}

function settleDestructiveConfirmation(accepted) {
  const request = state.destructiveRequest;
  if (!request) return;
  state.destructiveRequest = null;
  closeModals(false);
  request.resolve(accepted);
}

function handleDestructiveSubmit(event) {
  event.preventDefault();
  const request = state.destructiveRequest;
  if (!request) return;
  const value = $('#destructive-phrase').value.trim();
  if (request.phrase && value !== request.phrase) {
    $('#destructive-error').textContent = `Введите фразу точно: ${request.phrase}`;
    $('#destructive-error').hidden = false;
    $('#destructive-phrase').focus();
    return;
  }
  settleDestructiveConfirmation(true);
}

function openModal(id) {
  if (!$('#activity-panel').hidden) closeActivityPanel({ restoreFocus: false, immediate: true });
  if (!$('#run-drawer').hidden || state.selectedRunId) closeRunDrawer({ restoreFocus: false, immediate: true });
  if (!$('.modal:not([hidden])') && $('#run-drawer').hidden) {
    rememberFocusOrigin();
  }
  closeModals(false, true);
  $('#modal-backdrop').hidden = false;
  $('#modal-backdrop').classList.remove('is-closing');
  const modal = $(`#${id}`);
  modal.classList.remove('is-closing');
  modal.hidden = false;
  document.body.classList.add('modal-open');
  window.setTimeout(() => $('input:not([type="file"]):not([hidden]):not([disabled]), textarea:not([hidden]):not([disabled]), button:not(.modal-close):not([disabled])', modal)?.focus(), 30);
}

function dismissModals() {
  if ($('.modal:not([hidden])')?.dataset.busy === 'true') {
    toast('Операция уже выполняется — дождитесь результата', 'error');
    return;
  }
  if (state.startupVaultGate && !$('#vault-modal').hidden) {
    $('#vault-password').focus();
    return;
  }
  if (state.destructiveRequest && !$('#destructive-modal').hidden) {
    settleDestructiveConfirmation(false);
    return;
  }
  state.pendingAfterUnlock = null;
  state.resumeRunAfterImport = null;
  state.focusOrigin = null;
  state.focusOriginIdentity = null;
  state.activityFocusOrigin = null;
  state.drawerAccountSignature = '';
  closeModals();
}

function clearSecretForms() {
  $('#vault-form').reset();
  $('#import-form').reset();
  $('#export-form').reset();
  $('#referral-form').reset();
  $('#vault-error').hidden = true;
  $('#import-error').hidden = true;
  $('#export-error').hidden = true;
  $('#referral-error').hidden = true;
  $('#capsolver-key').value = '';
  $('#adspower-key').value = '';
  $('#referral-graph').replaceChildren();
  $('#referral-minimap').replaceChildren();
  $('#referral-inspector-content').hidden = true;
  $('#referral-inspector-empty').hidden = false;
  $('#referral-search').value = '';
  state.referralRevision = '';
  state.referralDraft = new Map();
  state.referralSelectedAccountId = null;
  state.referralDirty = false;
  resetReferralNavigation();
  updateImportCount();
}

function purgeProtectedClientState() {
  // Locking is also a renderer cache boundary. In-flight responses captured
  // before the lock are invalidated by the epoch and may not repopulate DOM or
  // state after this point.
  state.protectedDataEpoch += 1;
  state.pendingAfterUnlock = null;
  state.resumeRunAfterImport = null;
  state.activityAccountRows = [];
  state.activityAccountsTruncated = { active: false, attention: false };
  state.activityAccountsLoaded = false;
  state.activityAccountsLoading = false;
  state.activityAccountsError = '';
  state.activityAccountsPromise = null;
  state.resultReports = [];
  state.resultReportsLoaded = false;
  state.resultReportsLoading = false;
  state.resultReportsRefreshPending = false;
  state.resultReportsError = '';
  state.resultReportsRequestGeneration += 1;
  state.selectedResultReportId = '';
  state.selectedResultReport = null;
  state.resultReportLoading = false;
  state.resultReportRequestGeneration += 1;
  if (state.resultReportFilterTimer) window.clearTimeout(state.resultReportFilterTimer);
  state.resultReportFilterTimer = null;
  closeActivityPanel({ restoreFocus: false, immediate: true });
  closeRunDrawer({ restoreFocus: false, immediate: true });
  if (state.destructiveRequest) settleDestructiveConfirmation(false);
  closeModals(true, true);
  $('#account-search').value = '';
  $('#result-report-search').value = '';
  $('#result-report-status').value = 'all';
  resetResultReportPresentation();
  for (const selector of (
    '#accounts-table,#results-list,#overview-runs,#run-account-list,'
    + '#run-requirements,#run-options,#activity-table-body,'
    + '#drawer-account-table-body,#drawer-events,#result-report-summary,'
    + '#result-report-table-head,#result-report-table-body'
  ).split(',')) {
    $(selector)?.replaceChildren();
  }
  $('#drawer-meta').replaceChildren();
  $('#drawer-account-summary').textContent = 'Vault закрыт';
  $('#drawer-log-export-note').textContent = 'Vault закрыт';
  $('#run-account-selection').textContent = '0 выбрано';
  $('#run-launch-summary').textContent = 'Разблокируйте Vault, чтобы выбрать аккаунты.';
  $('#run-error').textContent = '';
  $('#batch-run-error').textContent = '';
  $('#destructive-modal-title').textContent = '';
  $('#destructive-modal-copy').textContent = '';
  $('#toast-region').replaceChildren();
  if (state.data) {
    state.data = {
      ...state.data,
      vault: {
        ...state.data.vault,
        unlocked: false,
        capsolver_configured: null,
        adspower_api_configured: null,
      },
      stats: { ...state.data.stats, accounts: 0, results: 0 },
      accounts: [],
      runs: [],
      runs_truncated: false,
      results: [],
    };
    renderAll();
  }
}

function closeModals(clear = true, immediate = false) {
  const open = $$('.modal:not([hidden])');
  const closesReferral = open.some((modal) => modal.id === 'referral-modal');
  const finish = () => {
    open.forEach((modal) => {
      modal.hidden = true;
      modal.classList.remove('is-closing');
    });
    const layersClosed = !$('.modal:not([hidden])');
    if (layersClosed) {
      $('#modal-backdrop').hidden = true;
      $('#modal-backdrop').classList.remove('is-closing');
      document.body.classList.remove('modal-open');
      if (!immediate && $('#run-drawer').hidden) restoreFocusOrigin();
    }
    if (closesReferral) resetReferralNavigation({ clearTransform: true });
  };
  if (immediate || window.matchMedia('(prefers-reduced-motion: reduce)').matches) finish();
  else {
    open.forEach((modal) => modal.classList.add('is-closing'));
    if (!state.selectedRunId) $('#modal-backdrop').classList.add('is-closing');
    window.setTimeout(finish, 190);
  }
  if (clear) clearSecretForms();
}

function setStartupVaultGate(required) {
  state.startupVaultGate = Boolean(required);
  document.body.classList.toggle('vault-entry-required', state.startupVaultGate);
  $('#vault-modal').dataset.startupRequired = String(state.startupVaultGate);
  $('#vault-modal-close').hidden = state.startupVaultGate;
  if (!state.startupVaultGate) $('#vault-entry-loader').hidden = true;
  if (!state.startupVaultGate) announceCoreUpdateIfReady();
}

function openVaultModal({ startupRequired = false } = {}) {
  if (!state.data) return;
  if (startupRequired) setStartupVaultGate(true);
  const creating = !state.data.vault.exists;
  $('#vault-modal-kicker').textContent = creating ? 'ПЕРВЫЙ ЗАПУСК' : 'ЗАЩИЩЁННЫЙ ВХОД';
  $('#vault-modal-title').textContent = creating ? 'Придумайте пароль' : 'Введите пароль';
  $('#vault-modal-description').textContent = creating
    ? 'Он зашифрует аккаунты и настройки на этом компьютере. Восстановить забытый пароль не получится.'
    : 'Сначала откройте локальное хранилище — после этого появится сам Hub и ваши рабочие данные.';
  $('#vault-confirm-label').hidden = !creating;
  $('#vault-confirm').required = creating;
  $('#vault-password').autocomplete = creating ? 'new-password' : 'current-password';
  $('#vault-submit').textContent = creating ? 'Создать пароль и войти' : 'Открыть Hub';
  $('#vault-entry-loader').hidden = true;
  openModal('vault-modal');
}

async function handleVaultSubmit(event) {
  event.preventDefault();
  const password = $('#vault-password').value;
  const creating = !state.data.vault.exists;
  const error = $('#vault-error');
  error.hidden = true;
  if (creating && password !== $('#vault-confirm').value) {
    error.textContent = 'Пароли не совпадают';
    error.hidden = false;
    return;
  }
  const submit = $('#vault-submit');
  setBusy(submit, true);
  try {
    await jsonPost(creating ? '/api/vault/create' : '/api/vault/unlock', { password });
    $('#vault-password').value = '';
    $('#vault-confirm').value = '';
    setStartupVaultGate(false);
    closeModals();
    await refresh();
    const hasAccounts = state.data.accounts.length > 0;
    toast(creating
      ? 'Vault создан. Теперь добавьте аккаунты.'
      : hasAccounts ? 'Vault открыт, аккаунты готовы' : 'Vault открыт, но пока пуст — добавьте аккаунты.', 'success', 6000);
    const pending = state.pendingAfterUnlock;
    state.pendingAfterUnlock = null;
    if (pending) pending();
  } catch (failure) {
    error.textContent = failure.message;
    error.hidden = false;
  } finally {
    setBusy(submit, false);
  }
}

async function lockVault() {
  try {
    await jsonPost('/api/vault/lock');
    purgeProtectedClientState();
    await refresh();
    toast('Vault заблокирован');
  } catch (error) {
    toast(error.message, 'error');
  }
}

function requireUnlocked(callback) {
  if (state.data?.vault.unlocked) {
    callback();
    return;
  }
  state.pendingAfterUnlock = callback;
  openVaultModal();
}

function openImportModal() {
  requireUnlocked(() => openModal('import-modal'));
}

function updateImportCount() {
  const label = $('#import-line-count');
  if ($('#import-table').value.trim()) {
    try {
      const count = parseAccountTable($('#import-table').value).length;
      label.textContent = `${count} ${count === 1 ? 'строка' : 'строк'} в таблице`;
      label.classList.remove('has-mismatch');
    } catch (error) {
      label.textContent = error.message;
      label.classList.add('has-mismatch');
    }
    return;
  }
  const counts = [
    lines($('#import-keys').value).length,
    lines($('#import-proxies').value).length,
    lines($('#import-emails').value).length,
    lines($('#import-twitters').value).length,
    lines($('#import-adspower-profiles').value).length,
  ];
  const equal = counts.slice(0, 3).every((count) => count === counts[0])
    && counts.slice(3).every((count) => count === 0 || count === counts[0]);
  label.textContent = equal ? `${counts[0]} связок` : `${counts.join(' / ')} строк`;
  label.classList.toggle('has-mismatch', !equal);
}

async function handleImportSubmit(event) {
  event.preventDefault();
  const error = $('#import-error');
  error.hidden = true;
  const submit = $('#import-form button[type="submit"]');
  setBusy(submit, true, 'Шифруем…');
  let payload;
  try {
    const passwords = lines($('#import-email-passwords').value);
    const labels = lines($('#import-labels').value);
    if ($('#import-table').value.trim()) {
      const records = parseAccountTable($('#import-table').value);
      if (passwords.length && passwords.length !== records.length) throw new Error('Паролей от почт должно быть столько же, сколько строк в таблице');
      if (labels.length && labels.length !== records.length) throw new Error('Названий аккаунтов должно быть столько же, сколько строк в таблице');
      records.forEach((record, index) => {
        record.email_password = passwords[index] || '';
        record.label = labels[index] || '';
      });
      payload = { records };
    } else {
      payload = {
        private_keys: lines($('#import-keys').value),
        proxies: lines($('#import-proxies').value),
        emails: lines($('#import-emails').value),
        twitters: lines($('#import-twitters').value),
        adspower_profiles: lines($('#import-adspower-profiles').value),
        email_passwords: passwords,
        labels,
      };
    }
    const result = await jsonPost('/api/accounts/import', payload);
    Object.values(payload).forEach((value) => {
      if (!Array.isArray(value)) return;
      value.forEach((item) => {
        if (item && typeof item === 'object') Object.keys(item).forEach((key) => { item[key] = ''; });
      });
      value.fill('');
    });
    const resume = state.resumeRunAfterImport;
    state.resumeRunAfterImport = null;
    closeModals(true, Boolean(resume));
    await refresh();
    toast(`Импортировано: ${result.inserted}, обновлено: ${result.updated}`);
    if (resume) openRunModal(resume.moduleId, resume.actionId);
  } catch (failure) {
    error.textContent = failure.message;
    error.hidden = false;
  } finally {
    setBusy(submit, false);
  }
}

function openExportModal() {
  if (!state.data?.accounts.length) {
    toast('Нет аккаунтов для экспорта', 'error');
    return;
  }
  requireUnlocked(() => openModal('export-modal'));
}

async function handleExportSubmit(event) {
  event.preventDefault();
  const passwordInput = $('#export-password');
  const acknowledgementInput = $('#export-acknowledgement');
  const formatInput = $('#export-format');
  const error = $('#export-error');
  const submit = $('#export-submit');
  const format = formatInput.value === 'csv' ? 'csv' : 'xlsx';
  error.hidden = true;
  setBusy(submit, true, format === 'xlsx' ? 'Готовим XLSX…' : 'Готовим CSV…');
  try {
    const response = await fetch('/api/accounts/export', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Soft-Hub-Token': apiToken,
      },
      body: JSON.stringify({
        password: passwordInput.value,
        acknowledgement: acknowledgementInput.value,
        format,
      }),
    });
    passwordInput.value = '';
    acknowledgementInput.value = '';
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.error || `HTTP ${response.status}`);
    }
    const blob = await response.blob();
    const link = document.createElement('a');
    const objectUrl = URL.createObjectURL(blob);
    link.href = objectUrl;
    link.download = `soft-hub-accounts-${new Date().toISOString().slice(0, 10)}.${format}`;
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
    closeModals();
    toast(
      format === 'xlsx'
        ? 'XLSX скачан. В нём открытые секреты — храните файл в защищённом месте.'
        : 'CSV скачан. Не открывайте его в Excel или Sheets.',
      'success',
      6500,
    );
  } catch (failure) {
    passwordInput.value = '';
    error.textContent = failure.message;
    error.hidden = false;
  } finally {
    setBusy(submit, false);
  }
}

async function saveCapsolver(event) {
  event.preventDefault();
  const input = $('#capsolver-key');
  const button = $('#capsolver-save');
  const value = input.value.trim();
  if (value.length < 4) {
    toast('В API-ключе Capsolver должно быть хотя бы 4 символа.', 'error');
    return;
  }
  setBusy(button, true, 'Шифруем…');
  try {
    await jsonPost('/api/settings/capsolver', { action: 'save', api_key: value });
    input.value = '';
    await refresh();
    toast('API-ключ Capsolver сохранён в Vault');
  } catch (error) {
    input.value = '';
    toast(error.message, 'error', 6000);
  } finally {
    setBusy(button, false);
  }
}

async function clearCapsolver() {
  const confirmed = await requestDestructiveConfirmation({
    title: 'Удалить API-ключ Capsolver?',
    message: 'Ключ будет удалён из Vault. Софты с Capsolver не запустятся, пока вы не сохраните новый ключ.',
    confirmLabel: 'Удалить ключ',
  });
  if (!confirmed) return;
  const button = $('#capsolver-clear');
  setBusy(button, true, 'Удаляем…');
  try {
    await jsonPost('/api/settings/capsolver', { action: 'clear' });
    await refresh();
    toast('API-ключ Capsolver удалён');
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    setBusy(button, false);
    updateVaultState();
  }
}

async function saveAdsPower(event) {
  event.preventDefault();
  const input = $('#adspower-key');
  const button = $('#adspower-save');
  const value = input.value.trim();
  if (value.length < 4) {
    toast('В API-ключе AdsPower должно быть хотя бы 4 символа.', 'error');
    return;
  }
  setBusy(button, true, 'Шифруем…');
  try {
    await jsonPost('/api/settings/adspower', { action: 'save', api_key: value });
    input.value = '';
    await refresh();
    toast('API-ключ AdsPower сохранён в Vault');
  } catch (error) {
    input.value = '';
    toast(error.message, 'error', 6000);
  } finally {
    setBusy(button, false);
  }
}

async function clearAdsPower() {
  const confirmed = await requestDestructiveConfirmation({
    title: 'Удалить API-ключ AdsPower?',
    message: 'Ключ будет удалён из Vault. Софты с AdsPower не запустятся, пока вы не сохраните новый ключ.',
    confirmLabel: 'Удалить ключ',
  });
  if (!confirmed) return;
  const button = $('#adspower-clear');
  setBusy(button, true, 'Удаляем…');
  try {
    await jsonPost('/api/settings/adspower', { action: 'clear' });
    await refresh();
    toast('API-ключ AdsPower удалён');
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    setBusy(button, false);
    updateVaultState();
  }
}

function selectedRunModule() {
  return state.data.modules.find((module) => module.id === state.selectedModuleId);
}

function selectedAction() {
  const module = selectedRunModule();
  const selected = $('input[name="run-action"]:checked');
  return module?.manifest.actions.find((action) => action.id === selected?.value);
}

function actionSecretPermissions(module, action) {
  if (!action) return [];
  const referralSecrets = Array.isArray(action.referral?.permissions?.secrets)
    ? action.referral.permissions.secrets
    : [];
  if (Object.prototype.hasOwnProperty.call(action, 'permissions')) {
    const actionSecrets = Array.isArray(action.permissions?.secrets) ? action.permissions.secrets : [];
    return [...new Set([...actionSecrets, ...referralSecrets])];
  }
  const legacy = module?.manifest?.permissions?.secrets;
  return [...new Set([...(Array.isArray(legacy) ? legacy : []), ...referralSecrets])];
}

function actionResources(action) {
  if (!action || !Object.prototype.hasOwnProperty.call(action, 'resources')) {
    return { declared: false, account: [], settings: [] };
  }
  return {
    declared: true,
    account: Array.isArray(action.resources?.account) ? action.resources.account : [],
    settings: Array.isArray(action.resources?.settings) ? action.resources.settings : [],
  };
}

function accountHasResource(account, resource) {
  const checks = {
    private_key: Boolean(account?.evm_address),
    proxy: Boolean(account?.proxy_label),
    email: Boolean(account?.email_label),
    email_password: account?.email_password_configured === true,
    twitter: account?.twitter_configured === true,
    adspower_profile: account?.adspower_configured === true,
  };
  return checks[resource] === true;
}

function settingHasResource(resource) {
  const checks = {
    capsolver: state.data?.vault?.capsolver_configured === true,
    adspower_api: state.data?.vault?.adspower_api_configured === true,
  };
  return checks[resource] === true;
}

function missingAccountResources(account, action) {
  return actionResources(action).account.filter((resource) => !accountHasResource(account, resource));
}

function missingSettingResources(action) {
  return actionResources(action).settings.filter((resource) => !settingHasResource(resource));
}

function referralRequirements(action) {
  const referral = action?.referral;
  if (!referral || referral.mode !== 'project_runtime') {
    return { declared: false, parentRequired: false, account: [] };
  }
  return {
    declared: true,
    parentRequired: referral.parent_required === true,
    account: Array.isArray(referral.resources?.account) ? referral.resources.account : [],
  };
}

function referralAccountIssue(account, action) {
  const referral = referralRequirements(action);
  if (!referral.declared) return '';
  if (!account?.referrer_account_id) {
    return referral.parentRequired ? 'выберите, кто его пригласил' : '';
  }
  const parent = accountById(account.referrer_account_id);
  if (!parent) return 'аккаунт, который его пригласил, уже удалён';
  const missing = referral.account.filter((resource) => !accountHasResource(parent, resource));
  return missing.length
    ? `у аккаунта «${parent.label}» не хватает: ${resourceNames(missing, accountResourceNames)}`
    : '';
}

function resourceNames(resources, names) {
  return resources.map((resource) => names[resource] || resource).join(', ');
}

function runResourceIssue(action, accountIds) {
  const resources = actionResources(action);
  if (!resources.declared) return '';
  const missingSettings = missingSettingResources(action);
  if (missingSettings.length) {
    return `Сначала настройте: ${resourceNames(missingSettings, settingResourceNames)}.`;
  }
  if (action.account_mode === 'none') return '';
  if (!accountIds.length) return 'Выберите хотя бы один готовый аккаунт.';
  const selected = accountIds
    .map((accountId) => state.data.accounts.find((account) => account.id === accountId))
    .filter(Boolean);
  for (const account of selected) {
    const missing = missingAccountResources(account, action);
    if (missing.length) {
      return `Для «${account.label}» добавьте: ${resourceNames(missing, accountResourceNames)}.`;
    }
    const referralIssue = referralAccountIssue(account, action);
    if (referralIssue) return `Для «${account.label}» ${referralIssue}.`;
  }
  return '';
}

function renderRunRequirements(action) {
  const root = $('#run-requirements');
  const resources = actionResources(action);
  const referral = referralRequirements(action);
  const all = [
    ...resources.account.map((resource) => ({ scope: 'account', resource })),
    ...resources.settings.map((resource) => ({ scope: 'settings', resource })),
    ...(referral.declared ? [{ scope: 'referral', resource: 'topology' }] : []),
    ...referral.account.map((resource) => ({ scope: 'referral-parent', resource })),
  ];
  if ((!resources.declared && !referral.declared) || !all.length) {
    root.hidden = true;
    root.replaceChildren();
    return;
  }
  const selectedIds = $$('input[name="run-account"]:checked').map((input) => input.value);
  const selectedAccounts = selectedIds
    .map((accountId) => state.data.accounts.find((account) => account.id === accountId))
    .filter(Boolean);
  const accountScope = selectedAccounts.length ? selectedAccounts : state.data.accounts;
  const chips = all.map(({ scope, resource }) => {
    let ready;
    let label;
    if (scope === 'settings') {
      ready = settingHasResource(resource);
      label = settingResourceNames[resource] || resource;
    } else if (scope === 'account') {
      ready = accountScope.length > 0 && accountScope.every((account) => accountHasResource(account, resource));
      label = accountResourceNames[resource] || resource;
    } else if (scope === 'referral') {
      ready = accountScope.length > 0 && accountScope.every((account) => !referralAccountIssue(account, action));
      label = 'Связь с пригласившим';
    } else {
      ready = accountScope.length > 0 && accountScope.every((account) => {
        const parent = accountById(account.referrer_account_id);
        return (!referral.parentRequired && !parent) || (parent && accountHasResource(parent, resource));
      });
      label = `У пригласившего: ${accountResourceNames[resource] || resource}`;
    }
    return `<span class="resource-chip" data-state="${ready ? 'ready' : 'missing'}">${iconMarkup(ready ? 'check' : 'alert')} ${escapeHtml(label)}</span>`;
  }).join('');
  const missingSettings = missingSettingResources(action);
  const unavailableAccounts = action.account_mode === 'none'
    ? []
    : accountScope.filter((account) => missingAccountResources(account, action).length || referralAccountIssue(account, action));
  let warning = '';
  let actionButton = '';
  if (missingSettings.length) {
    warning = `Перед запуском добавьте ${resourceNames(missingSettings, settingResourceNames)}.`;
    actionButton = '<button class="text-button" type="button" data-resource-settings>Открыть настройки</button>';
  } else if (unavailableAccounts.length) {
    const topologyMissing = unavailableAccounts.some((account) => referralAccountIssue(account, action));
    warning = `${unavailableAccounts.length} ${countWord(unavailableAccounts.length, 'аккаунт недоступен', 'аккаунта недоступны', 'аккаунтов недоступны')}: ${topologyMissing ? 'не хватает связи с пригласившим или его данных' : 'не хватает обязательных данных'}.`;
    actionButton = topologyMissing
      ? '<button class="text-button" type="button" data-resource-referrals>Открыть карту</button>'
      : '<button class="text-button" type="button" data-resource-import>Дополнить аккаунты</button>';
  }
  root.innerHTML = `<div class="run-requirements-head"><span><strong>Перед запуском</strong><small>Проверим всё заранее</small></span>${warning ? '<i data-state="warning">НУЖНО ДОПОЛНИТЬ</i>' : '<i data-state="ready">ВСЁ ГОТОВО</i>'}</div><div class="resource-chip-list">${chips}</div>${warning ? `<div class="resource-warning" role="status"><span>${escapeHtml(warning)}</span>${actionButton}</div>` : ''}`;
  root.hidden = false;
  $('[data-resource-settings]', root)?.addEventListener('click', () => {
    closeModals(true, true);
    showView('settings');
    const target = $(missingSettings[0] === 'capsolver' ? '#capsolver-key' : '#adspower-key');
    window.requestAnimationFrame(() => target.focus({ preventScroll: true }));
  });
  $('[data-resource-import]', root)?.addEventListener('click', () => {
    const module = selectedRunModule();
    state.resumeRunAfterImport = module ? { moduleId: module.id, actionId: action.id } : null;
    closeModals(true, true);
    openImportModal();
  });
  $('[data-resource-referrals]', root)?.addEventListener('click', () => {
    closeModals(true, true);
    openReferralModal();
  });
}

function renderRunAccounts(action, selectedIds = []) {
  const root = $('#run-account-list');
  if (!state.data.accounts.length) {
    root.innerHTML = `<div class="run-account-empty" role="status">
      <span aria-hidden="true">＋</span><div><strong>В Vault пока нет аккаунтов</strong><small>Добавьте приватник, прокси, почту и, если нужно, ID AdsPower.</small></div>
      <button class="button button--ink" type="button" data-import-for-run>Добавить аккаунты</button>
    </div>`;
    return;
  }
  const selected = new Set(selectedIds);
  root.innerHTML = state.data.accounts.map((account) => {
    const missing = missingAccountResources(account, action);
    const referralIssue = referralAccountIssue(account, action);
    const unavailable = missing.length > 0 || Boolean(referralIssue);
    const detail = missing.length
      ? `Добавьте: ${resourceNames(missing, accountResourceNames)}`
      : referralIssue
        ? `Проверьте связь: ${referralIssue}`
      : shortAddress(account.evm_address);
    return `<label class="account-option ${unavailable ? 'is-unavailable' : ''}"><input type="checkbox" name="run-account" value="${escapeHtml(account.id)}" ${selected.has(account.id) ? 'checked' : ''} ${unavailable ? 'disabled' : ''} />
      <span><strong>${escapeHtml(account.label)}</strong><small>${escapeHtml(detail)}</small></span>${unavailable ? iconMarkup('alert') : ''}</label>`;
  }).join('');
  $$('input[name="run-account"]', root).forEach((input) => input.addEventListener('change', updateRunAccountSelection));
}

function actionRiskLabel(action) {
  return actionRiskNames[action?.risk] || 'Действие софта';
}

function actionReadyNote(action) {
  if (action?.risk === 'testnet_write') return 'Понадобится общее подтверждение testnet-запуска';
  if (action?.risk === 'external_write') return 'Изменит данные во внешнем сервисе';
  return 'Готово к запуску';
}

function openRunModal(moduleId, preferredActionId = '') {
  const module = state.data.modules.find((item) => item.id === moduleId);
  if (!module) return;
  const initialAction = module.manifest.actions.find((action) => action.id === preferredActionId)
    || module.manifest.actions.find((action) => actionSecretPermissions(module, action).length === 0)
    || module.manifest.actions[0];
  const needsVault = actionSecretPermissions(module, initialAction).length > 0;
  if (needsVault && !state.data.vault.unlocked) {
    state.pendingAfterUnlock = () => openRunModal(moduleId, preferredActionId);
    openVaultModal();
    return;
  }
  state.selectedModuleId = moduleId;
  state.lastRunActionId = null;
  $('#run-modal-title').textContent = `Запустить ${moduleDisplayName(module)}`;
  $('#run-modal-description').textContent = moduleDisplayDescription(module);
  $('#run-action-list').innerHTML = module.manifest.actions.map((action) => `
    <label class="action-option"><input type="radio" name="run-action" value="${escapeHtml(action.id)}" ${action.id === initialAction?.id ? 'checked' : ''} />
    <span><strong>${escapeHtml(action.name)}</strong><small>${escapeHtml(action.description)}</small><i data-risk="${escapeHtml(action.risk)}">${escapeHtml(actionRiskLabel(action))}</i>${action.risk === 'external_write' ? '<em>Изменит данные во внешнем сервисе</em>' : ''}</span></label>`).join('');
  $$('#run-action-list input').forEach((input) => input.addEventListener('change', () => updateRunForm({ applyAccountDefault: true })));
  $('#run-form').reset();
  const preferred = initialAction
    ? $$('#run-action-list input').find((input) => input.value === initialAction.id)
    : null;
  const first = $('#run-action-list input');
  if (preferred) preferred.checked = true;
  else if (first) first.checked = true;
  updateRunForm({ applyAccountDefault: true });
  openModal('run-modal');
}

function updateRunAccountSelection({ applyDefault = false } = {}) {
  const action = selectedAction();
  if (!action) return;
  const block = $('#run-accounts-block');
  const boxes = $$('input[name="run-account"]:not(:disabled)');
  if (applyDefault && action.account_mode === 'one_or_more' && !boxes.some((box) => box.checked)) {
    if (boxes.length === 1) boxes[0].checked = true;
  }
  const selected = boxes.filter((box) => box.checked).length;
  const count = $('#run-account-selection');
  const selectAll = $('#select-all-accounts');
  if (action.account_mode === 'none') {
    count.textContent = 'Не требуются';
    selectAll.hidden = true;
  } else if (!boxes.length) {
    count.textContent = 'Нет аккаунтов';
    selectAll.hidden = true;
  } else {
    count.textContent = `${selected} из ${boxes.length}`;
    selectAll.hidden = false;
    selectAll.textContent = selected === boxes.length ? 'Снять выбор' : 'Выбрать все';
  }
  if (action.account_mode === 'none' || !boxes.length || selected > 0) block.classList.remove('has-error');
  syncRunConcurrency(action);
  renderRunRequirements(action);
  const selectedIds = boxes.filter((box) => box.checked).map((box) => box.value);
  const issue = runResourceIssue(action, selectedIds);
  const submit = $('#run-submit');
  const blockedByEmptyVault = action.account_mode === 'one_or_more' && boxes.length === 0;
  submit.disabled = $('#run-modal').dataset.busy === 'true';
  submit.textContent = blockedByEmptyVault
    ? state.data.accounts.length ? 'Дополнить аккаунты' : 'Добавить аккаунты'
    : issue ? 'Что нужно добавить' : 'Запустить';
  const launchSummary = $('#run-launch-summary');
  if (issue) launchSummary.textContent = issue;
  else if (action.account_mode === 'none') launchSummary.textContent = `${action.name} · аккаунты не нужны`;
  else if (!selected) launchSummary.textContent = `${action.name} · выберите хотя бы один аккаунт`;
  else {
    const concurrency = Number($('#run-account-concurrency')?.value || 1);
    launchSummary.textContent = `${action.name} · ${selected} ${countWord(selected, 'аккаунт', 'аккаунта', 'аккаунтов')} · ${concurrency} ${countWord(concurrency, 'поток', 'потока', 'потоков')}`;
  }
}

function accountConcurrencyField(action) {
  const field = action?.options?.properties?.account_concurrency;
  return field?.type === 'integer' ? field : null;
}

function integerClamp(value, minimum, maximum, fallback = minimum) {
  const number = Number(value);
  const integer = Number.isFinite(number) ? Math.round(number) : fallback;
  return Math.max(minimum, Math.min(maximum, integer));
}

function syncRunConcurrency(action, { reset = false } = {}) {
  const block = $('#run-concurrency-block');
  const field = accountConcurrencyField(action);
  const selected = $$('input[name="run-account"]:checked').length;
  if (action?.account_mode === 'none' || !field) {
    block.hidden = true;
    return 1;
  }
  block.hidden = false;
  const declaredMaximum = integerClamp(field.maximum, 1, 20, 1);
  const effectiveMaximum = Math.max(1, Math.min(declaredMaximum, selected || 1));
  const safeDefault = integerClamp(field.default, 1, declaredMaximum, 1);
  const input = $('#run-account-concurrency');
  input.min = '1';
  input.max = String(effectiveMaximum);
  if (reset || !input.dataset.preferredValue) input.dataset.preferredValue = String(safeDefault);
  const preferredValue = integerClamp(input.dataset.preferredValue, 1, declaredMaximum, safeDefault);
  const nextValue = integerClamp(preferredValue, 1, effectiveMaximum, safeDefault);
  input.value = String(nextValue);
  const waves = selected ? Math.ceil(selected / nextValue) : 0;
  $('#run-concurrency-limit').textContent = `до ${effectiveMaximum}`;
  $('#run-concurrency-copy').textContent = field.description || 'Сколько аккаунтов софт запустит одновременно.';
  $('#run-concurrency-value').textContent = `${nextValue} ${countWord(nextValue, 'поток', 'потока', 'потоков')}`;
  $('#run-concurrency-waves').textContent = selected
    ? `${selected} ${countWord(selected, 'аккаунт', 'аккаунта', 'аккаунтов')} · ${waves} ${countWord(waves, 'волна', 'волны', 'волн')}`
    : 'Сначала выберите аккаунты';
  const presets = [...new Set([1, 3, 5, 10, safeDefault, effectiveMaximum])]
    .filter((value) => value <= effectiveMaximum)
    .sort((first, second) => first - second);
  $('#run-concurrency-presets').innerHTML = presets.map((value) => `<button type="button" data-run-concurrency-preset="${value}" class="${value === nextValue ? 'is-active' : ''}" aria-pressed="${value === nextValue}">${value}</button>`).join('');
  return nextValue;
}

function optionNumberStep(type, field) {
  const multiple = Number(field.multipleOf);
  if (Number.isFinite(multiple) && multiple > 0 && (type !== 'integer' || Number.isSafeInteger(multiple))) return String(multiple);
  return type === 'integer' ? '1' : 'any';
}

function optionDecimalPlaces(value) {
  const text = String(value).toLowerCase();
  if (text.includes('e')) {
    const [coefficient, exponentText] = text.split('e');
    const decimals = (coefficient.split('.')[1] || '').length;
    return Math.max(0, decimals - Number(exponentText));
  }
  return (text.split('.')[1] || '').length;
}

function optionCleanNumber(value, precision = 10) {
  return String(Number(Number(value).toFixed(precision)));
}

function optionSliderConfig(type, field) {
  const declaredMinimum = Number(field.minimum);
  const declaredMaximum = Number(field.maximum);
  if (!Number.isFinite(declaredMinimum) || !Number.isFinite(declaredMaximum) || declaredMaximum <= declaredMinimum) return null;
  const explicitMultiple = Number(field.multipleOf);
  const hasExplicitMultiple = Number.isFinite(explicitMultiple) && explicitMultiple > 0;
  let step = hasExplicitMultiple ? explicitMultiple : type === 'integer' ? 1 : 0;
  if (type === 'integer' && !Number.isSafeInteger(step)) return null;
  if (!step) {
    const roughStep = (declaredMaximum - declaredMinimum) / 100;
    const magnitude = 10 ** Math.floor(Math.log10(roughStep));
    const normalized = roughStep / magnitude;
    const niceStep = normalized <= 1 ? 1 : normalized <= 2 ? 2 : normalized <= 5 ? 5 : 10;
    step = niceStep * magnitude;
  }
  const precision = Math.min(10, Math.max(
    optionDecimalPlaces(declaredMinimum),
    optionDecimalPlaces(declaredMaximum),
    optionDecimalPlaces(step),
  ));
  const alignsToMultiple = hasExplicitMultiple || type === 'integer';
  const minimum = alignsToMultiple
    ? Math.ceil((declaredMinimum / step) - 1e-9) * step
    : declaredMinimum;
  const maximum = alignsToMultiple
    ? Math.floor((declaredMaximum / step) + 1e-9) * step
    : declaredMaximum;
  const tickCount = (maximum - minimum) / step;
  if (
    !Number.isFinite(minimum)
    || !Number.isFinite(maximum)
    || maximum <= minimum
    || !Number.isFinite(tickCount)
    || tickCount > 1000
    || (type === 'integer' && ![minimum, maximum, step].every(Number.isSafeInteger))
  ) return null;
  return {
    minimum: Number(optionCleanNumber(minimum, precision)),
    maximum: Number(optionCleanNumber(maximum, precision)),
    step: Number(optionCleanNumber(step, precision)),
    precision,
  };
}

function optionUi(field) {
  const value = field?.['x-ui'];
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function optionEntries(action) {
  const properties = action.options?.properties || {};
  return Object.entries(properties)
    .filter(([key, field]) => key !== 'account_concurrency' && !(
      action.risk === 'testnet_write'
      && key === 'acknowledge_testnet_transactions'
      && field.type === 'boolean'
    ))
    .sort(([firstKey, first], [secondKey, second]) => {
      const firstUi = optionUi(first);
      const secondUi = optionUi(second);
      const advancedOrder = Number(Boolean(firstUi.advanced)) - Number(Boolean(secondUi.advanced));
      if (advancedOrder) return advancedOrder;
      const order = Number(firstUi.order ?? 1000) - Number(secondUi.order ?? 1000);
      return order || firstKey.localeCompare(secondKey, 'ru');
    });
}

function optionValueLabel(value) {
  if (typeof value === 'boolean') return value ? 'Включено' : 'Выключено';
  return String(value);
}

function optionNumericInputMarkup(key, field, type, title, isRequired, unit, extraClass = '') {
  const placeholderBase = String(optionUi(field).placeholder || (field.default !== undefined ? `Например, ${field.default}` : '')).trim();
  const placeholder = placeholderBase && !placeholderBase.endsWith('…') ? `${placeholderBase}…` : placeholderBase;
  return `<span class="option-input-shell option-number-shell ${escapeHtml(extraClass)}"><input id="run-option-${escapeHtml(key)}" class="option-number-input" type="number" name="option-${escapeHtml(key)}" autocomplete="off" data-option-key="${escapeHtml(key)}" data-option-type="${escapeHtml(type)}" data-option-label="${escapeHtml(title)}" data-option-required="${isRequired}" data-option-multiple="${escapeHtml(field.multipleOf ?? '')}" value="${escapeHtml(field.default ?? '')}" placeholder="${escapeHtml(placeholder)}" step="${escapeHtml(optionNumberStep(type, field))}" inputmode="${type === 'integer' ? 'numeric' : 'decimal'}" min="${escapeHtml(field.minimum)}" max="${escapeHtml(field.maximum)}"/>${unit ? `<span>${escapeHtml(unit)}</span>` : ''}</span>`;
}

function optionSingleSliderMarkup(key, field, type, title, isRequired, unit) {
  const config = optionSliderConfig(type, field);
  if (!config) return optionNumericInputMarkup(key, field, type, title, isRequired, unit);
  const initialValue = field.default !== undefined ? Number(field.default) : config.minimum;
  const safeInitial = Math.max(config.minimum, Math.min(config.maximum, initialValue));
  const span = config.maximum - config.minimum;
  const progress = safeInitial - config.minimum;
  return `<div class="option-slider-control" data-option-slider-control>
    <div class="option-slider-readout"><span class="option-slider-limit">${escapeHtml(optionCleanNumber(config.minimum, config.precision))}</span>${optionNumericInputMarkup(key, field, type, title, isRequired, unit, 'option-slider-value')}<span class="option-slider-limit">${escapeHtml(optionCleanNumber(config.maximum, config.precision))}</span></div>
    <div class="option-slider-track"><progress data-option-slider-progress max="${escapeHtml(optionCleanNumber(span, config.precision))}" value="${escapeHtml(optionCleanNumber(progress, config.precision))}" aria-hidden="true"></progress><input type="range" data-option-slider aria-label="${escapeHtml(title)}" min="${escapeHtml(optionCleanNumber(config.minimum, config.precision))}" max="${escapeHtml(optionCleanNumber(config.maximum, config.precision))}" step="${escapeHtml(optionCleanNumber(config.step, config.precision))}" value="${escapeHtml(optionCleanNumber(safeInitial, config.precision))}"/></div>
  </div>`;
}

function optionRangePair(fields, startIndex) {
  const [, field] = fields[startIndex];
  const ui = optionUi(field);
  const descriptor = ui.range;
  if (ui.control !== 'dual_range' || !descriptor?.id) return null;
  const members = fields.filter(([, candidate]) => {
    const candidateUi = optionUi(candidate);
    return candidateUi.control === 'dual_range' && candidateUi.range?.id === descriptor.id;
  });
  if (members.length !== 2) return null;
  const lower = members.find(([, candidate]) => optionUi(candidate).range?.role === 'from');
  const upper = members.find(([, candidate]) => optionUi(candidate).range?.role === 'to');
  if (!lower || !upper) return null;
  return { lower, upper, group: descriptor.id };
}

function optionRangeFieldMarkup(pair, required) {
  const [[lowerKey, lowerField], [upperKey, upperField]] = [pair.lower, pair.upper];
  const lowerUi = optionUi(lowerField);
  const upperUi = optionUi(upperField);
  const type = lowerField.type || 'number';
  const title = String(lowerField.title || upperField.title || pair.group);
  const unit = String(lowerUi.unit || upperUi.unit || '').trim();
  const config = optionSliderConfig(type, lowerField);
  if (!config) return optionFieldMarkup(lowerKey, lowerField, required) + optionFieldMarkup(upperKey, upperField, required);
  const lowerRequired = required.has(lowerKey);
  const upperRequired = required.has(upperKey);
  const badge = lowerRequired || upperRequired ? '<i class="option-required">нужно</i>' : '<i class="option-optional">можно пропустить</i>';
  const lowerInitial = Math.max(config.minimum, Math.min(config.maximum, Number(lowerField.default ?? config.minimum)));
  const upperInitial = Math.max(lowerInitial, Math.min(config.maximum, Number(upperField.default ?? config.maximum)));
  const span = config.maximum - config.minimum;
  const descriptions = [...new Set([lowerField.description, upperField.description].map((value) => String(value || '').trim()).filter(Boolean))];
  descriptions.push(`Можно выбрать: ${optionCleanNumber(config.minimum, config.precision)}–${optionCleanNumber(config.maximum, config.precision)}${unit ? ` ${unit}` : ''}`);
  const help = descriptions.join(' · ');
  const lowerInput = optionNumericInputMarkup(lowerKey, lowerField, type, lowerField.title || lowerKey, lowerRequired, unit, 'option-range-value');
  const upperInput = optionNumericInputMarkup(upperKey, upperField, type, upperField.title || upperKey, upperRequired, unit, 'option-range-value');
  return `<fieldset class="option-field option-field--range option-field--wide" data-option-range-group="${escapeHtml(pair.group)}"><legend class="sr-only">${escapeHtml(title)}</legend>
    <span class="option-field-head"><strong>${escapeHtml(title)}</strong>${badge}</span>
    <div class="option-range-readouts"><label for="run-option-${escapeHtml(lowerKey)}"><span>ОТ</span>${lowerInput}</label><i aria-hidden="true"></i><label for="run-option-${escapeHtml(upperKey)}"><span>ДО</span>${upperInput}</label></div>
    <div class="option-range-track" data-option-range-track><progress class="option-range-progress option-range-progress--maximum" data-option-range-progress="maximum" max="${escapeHtml(optionCleanNumber(span, config.precision))}" value="${escapeHtml(optionCleanNumber(upperInitial - config.minimum, config.precision))}" aria-hidden="true"></progress><progress class="option-range-progress option-range-progress--minimum" data-option-range-progress="minimum" max="${escapeHtml(optionCleanNumber(span, config.precision))}" value="${escapeHtml(optionCleanNumber(lowerInitial - config.minimum, config.precision))}" aria-hidden="true"></progress><input type="range" data-option-range-slider="minimum" aria-label="${escapeHtml(`${title}, от`)}" min="${escapeHtml(optionCleanNumber(config.minimum, config.precision))}" max="${escapeHtml(optionCleanNumber(config.maximum, config.precision))}" step="${escapeHtml(optionCleanNumber(config.step, config.precision))}" value="${escapeHtml(optionCleanNumber(lowerInitial, config.precision))}"/><input type="range" data-option-range-slider="maximum" aria-label="${escapeHtml(`${title}, до`)}" min="${escapeHtml(optionCleanNumber(config.minimum, config.precision))}" max="${escapeHtml(optionCleanNumber(config.maximum, config.precision))}" step="${escapeHtml(optionCleanNumber(config.step, config.precision))}" value="${escapeHtml(optionCleanNumber(upperInitial, config.precision))}"/></div>
    <div class="option-range-limits" aria-hidden="true"><span>${escapeHtml(optionCleanNumber(config.minimum, config.precision))}</span><span>${escapeHtml(optionCleanNumber(config.maximum, config.precision))}</span></div>
    <small class="field-help">${escapeHtml(help)}</small>
  </fieldset>`;
}

function optionFieldMarkup(key, field, required) {
  const ui = optionUi(field);
  const type = field.type || 'string';
  const title = field.title || key;
  const isRequired = required.has(key);
  const badge = isRequired ? '<i class="option-required">нужно</i>' : '<i class="option-optional">можно пропустить</i>';
  const description = String(field.description || '').trim();
  const unit = String(ui.unit || '').trim();
  const helpParts = [];
  if (description) helpParts.push(description);
  if (['integer', 'number'].includes(type) && (field.minimum !== undefined || field.maximum !== undefined)) {
    const minimum = field.minimum !== undefined ? optionValueLabel(field.minimum) : 'без минимума';
    const maximum = field.maximum !== undefined ? optionValueLabel(field.maximum) : 'без максимума';
    helpParts.push(`Можно выбрать: ${minimum}–${maximum}${unit ? ` ${unit}` : ''}`);
  }
  if (type === 'string' && field.maxLength !== undefined) {
    const minimum = field.minLength !== undefined ? `${field.minLength}–` : 'до ';
    helpParts.push(`${minimum}${field.maxLength} символов`);
  }
  if (field.default !== undefined) helpParts.push(`Сейчас стоит: ${optionValueLabel(field.default)}${unit ? ` ${unit}` : ''}`);
  const help = helpParts.length ? helpParts.join(' · ') : 'Эта настройка действует только для текущего запуска.';

  if (type === 'boolean') {
    return `<label class="option-toggle"><input type="checkbox" data-option-key="${escapeHtml(key)}" data-option-type="boolean" data-option-label="${escapeHtml(title)}" ${field.default ? 'checked' : ''}/><span class="option-toggle-copy"><span><strong>${escapeHtml(title)}</strong>${badge}</span><small>${escapeHtml(help)}</small></span><span class="option-toggle-control" aria-hidden="true"><i></i></span></label>`;
  }

  if (Array.isArray(field.enum)) {
    const labels = ui.enum_labels && typeof ui.enum_labels === 'object' && !Array.isArray(ui.enum_labels) ? ui.enum_labels : {};
    return `<label class="option-field"><span class="option-field-head"><strong>${escapeHtml(title)}</strong>${badge}</span><select name="option-${escapeHtml(key)}" autocomplete="off" data-option-key="${escapeHtml(key)}" data-option-type="${escapeHtml(type)}" data-option-label="${escapeHtml(title)}" data-option-required="${isRequired}">${field.enum.map((value) => `<option value="${escapeHtml(value)}" ${value === field.default ? 'selected' : ''}>${escapeHtml(labels[value] || value)}</option>`).join('')}</select><small class="field-help">${escapeHtml(help)}</small></label>`;
  }

  const numeric = ['integer', 'number'].includes(type);
  const placeholderBase = String(ui.placeholder || (field.default !== undefined ? `Например, ${field.default}` : '')).trim();
  const placeholder = placeholderBase && !placeholderBase.endsWith('…') ? `${placeholderBase}…` : placeholderBase;
  const stringBounds = type === 'string'
    ? `${field.minLength !== undefined ? `minlength="${escapeHtml(field.minLength)}"` : ''} ${field.maxLength !== undefined ? `maxlength="${escapeHtml(field.maxLength)}"` : ''}`
    : '';
  const control = ui.control === 'textarea' && type === 'string'
    ? `<textarea name="option-${escapeHtml(key)}" autocomplete="off" data-option-key="${escapeHtml(key)}" data-option-type="string" data-option-label="${escapeHtml(title)}" data-option-required="${isRequired}" placeholder="${escapeHtml(placeholder)}" ${stringBounds}>${escapeHtml(field.default ?? '')}</textarea>`
    : numeric
      ? ui.control === 'input'
        ? optionNumericInputMarkup(key, field, type, title, isRequired, unit)
        : optionSingleSliderMarkup(key, field, type, title, isRequired, unit)
      : `<span class="option-input-shell"><input type="text" name="option-${escapeHtml(key)}" autocomplete="off" data-option-key="${escapeHtml(key)}" data-option-type="${escapeHtml(type)}" data-option-label="${escapeHtml(title)}" data-option-required="${isRequired}" value="${escapeHtml(field.default ?? '')}" placeholder="${escapeHtml(placeholder)}" ${stringBounds}/></span>`;
  return `<label class="option-field"><span class="option-field-head"><strong>${escapeHtml(title)}</strong>${badge}</span>${control}<small class="field-help">${escapeHtml(help)}</small></label>`;
}

function optionGroupFieldsMarkup(fields, required) {
  const consumed = new Set();
  const markup = [];
  fields.forEach(([key, field], index) => {
    if (consumed.has(key)) return;
    const pair = optionRangePair(fields, index);
    if (pair) {
      consumed.add(pair.lower[0]);
      consumed.add(pair.upper[0]);
      markup.push(optionRangeFieldMarkup(pair, required));
      return;
    }
    consumed.add(key);
    markup.push(optionFieldMarkup(key, field, required));
  });
  return markup.join('');
}

function optionSliderValue(value, slider) {
  const minimum = Number(slider.min);
  const maximum = Number(slider.max);
  const precision = Math.min(10, Math.max(optionDecimalPlaces(slider.step), optionDecimalPlaces(slider.min), optionDecimalPlaces(slider.max)));
  return optionCleanNumber(Math.max(minimum, Math.min(maximum, Number(value))), precision);
}

function syncOptionSingleProgress(slider) {
  const progress = $('[data-option-slider-progress]', slider.closest('[data-option-slider-control]'));
  progress.value = Math.max(0, Number(slider.value) - Number(slider.min));
}

function bindOptionSingleSliders(root) {
  $$('[data-option-slider]', root).forEach((slider) => {
    const control = slider.closest('[data-option-slider-control]');
    const input = $('[data-option-key]', control);
    const fromSlider = () => {
      input.value = optionSliderValue(slider.value, slider);
      input.removeAttribute('aria-invalid');
      syncOptionSingleProgress(slider);
    };
    const fromInput = ({ commit = false } = {}) => {
      if (!input.value.trim() || !Number.isFinite(Number(input.value))) return;
      slider.value = optionSliderValue(input.value, slider);
      if (commit) input.value = optionSliderValue(slider.value, slider);
      syncOptionSingleProgress(slider);
    };
    slider.addEventListener('input', fromSlider);
    input.addEventListener('input', () => fromInput());
    input.addEventListener('change', () => fromInput({ commit: true }));
    syncOptionSingleProgress(slider);
  });
}

function syncOptionRange(group, role, rawValue, { commitInput = true } = {}) {
  const slider = $(`[data-option-range-slider="${role}"]`, group);
  const otherRole = role === 'minimum' ? 'maximum' : 'minimum';
  const otherSlider = $(`[data-option-range-slider="${otherRole}"]`, group);
  const input = role === 'minimum'
    ? $$('[data-option-key]', group)[0]
    : $$('[data-option-key]', group)[1];
  let value = Number(optionSliderValue(rawValue, slider));
  const otherValue = Number(otherSlider.value);
  value = role === 'minimum' ? Math.min(value, otherValue) : Math.max(value, otherValue);
  slider.value = optionSliderValue(value, slider);
  const normalized = optionSliderValue(slider.value, slider);
  if (commitInput) input.value = normalized;
  input.removeAttribute('aria-invalid');
  $('[data-option-range-progress="minimum"]', group).value = Math.max(0, Number($('[data-option-range-slider="minimum"]', group).value) - Number(slider.min));
  $('[data-option-range-progress="maximum"]', group).value = Math.max(0, Number($('[data-option-range-slider="maximum"]', group).value) - Number(slider.min));
}

function bindOptionRangeSliders(root) {
  $$('[data-option-range-group]', root).forEach((group) => {
    const inputs = $$('[data-option-key]', group);
    ['minimum', 'maximum'].forEach((role, index) => {
      const slider = $(`[data-option-range-slider="${role}"]`, group);
      const input = inputs[index];
      slider.addEventListener('input', () => syncOptionRange(group, role, slider.value));
      slider.addEventListener('focus', () => slider.classList.add('is-active'));
      slider.addEventListener('blur', () => slider.classList.remove('is-active'));
      input.addEventListener('input', () => {
        if (input.value.trim() && Number.isFinite(Number(input.value))) syncOptionRange(group, role, input.value, { commitInput: false });
      });
      input.addEventListener('change', () => {
        if (input.value.trim() && Number.isFinite(Number(input.value))) syncOptionRange(group, role, input.value);
      });
    });
    $('[data-option-range-track]', group).addEventListener('pointerdown', (event) => {
      if (event.target.closest('input[type="range"]')) return;
      const track = event.currentTarget;
      const lower = $('[data-option-range-slider="minimum"]', group);
      const upper = $('[data-option-range-slider="maximum"]', group);
      const bounds = track.getBoundingClientRect();
      const ratio = Math.max(0, Math.min(1, (event.clientX - bounds.left) / Math.max(1, bounds.width)));
      const candidate = Number(lower.min) + ratio * (Number(lower.max) - Number(lower.min));
      const role = Math.abs(candidate - Number(lower.value)) <= Math.abs(candidate - Number(upper.value)) ? 'minimum' : 'maximum';
      syncOptionRange(group, role, candidate);
      $(`[data-option-range-slider="${role}"]`, group).focus({ preventScroll: true });
    });
  });
}

function bindOptionSliders(root) {
  bindOptionSingleSliders(root);
  bindOptionRangeSliders(root);
}

function renderRunOptions(action) {
  const entries = optionEntries(action);
  const block = $('#run-options-block');
  const root = $('#run-options');
  block.hidden = entries.length === 0;
  $('#run-options-count').textContent = `${entries.length} ${countWord(entries.length, 'параметр', 'параметра', 'параметров')}`;
  if (!entries.length) {
    root.innerHTML = '';
    return;
  }
  const required = new Set(Array.isArray(action.options?.required) ? action.options.required : []);
  const groups = new Map();
  entries.forEach(([key, field]) => {
    const ui = optionUi(field);
    const group = String(ui.group || (ui.advanced ? 'Дополнительно' : 'Основные настройки')).trim();
    if (!groups.has(group)) groups.set(group, { advanced: Boolean(ui.advanced), fields: [] });
    groups.get(group).fields.push([key, field]);
  });
  root.innerHTML = [...groups.entries()].map(([name, group]) => `<section class="option-group ${group.advanced ? 'option-group--advanced' : ''}"><header><span><strong>${escapeHtml(name)}</strong><small>${group.advanced ? 'Лучше не менять без причины' : 'Настройки для этого запуска'}</small></span><i>${String(group.fields.length).padStart(2, '0')}</i></header><div class="option-grid">${optionGroupFieldsMarkup(group.fields, required)}</div></section>`).join('');
  bindOptionSliders(root);
}

function updateRunForm({ applyAccountDefault = false } = {}) {
  const action = selectedAction();
  if (!action) return;
  const actionChanged = state.lastRunActionId !== action.id;
  const selectedIds = actionChanged
    ? []
    : $$('input[name="run-account"]:checked').map((box) => box.value);
  renderRunAccounts(action, selectedIds);
  state.lastRunActionId = action.id;
  $('#run-accounts-block').hidden = action.account_mode === 'none';
  $('#risk-confirmation').hidden = action.risk !== 'testnet_write';
  $('#mainnet-confirmation').hidden = action.risk !== 'mainnet_write';
  $('#risk-checkbox').checked = false;
  $('#risk-checkbox').removeAttribute('aria-invalid');
  const phrase = action.confirmation_phrase || '';
  $('#mainnet-phrase').value = '';
  $('#mainnet-phrase').placeholder = phrase;
  $('#mainnet-phrase').required = action.risk === 'mainnet_write';
  $('#mainnet-phrase').removeAttribute('aria-invalid');
  $('#mainnet-confirmation').firstChild.textContent = phrase ? `Введите: ${phrase}` : 'Фраза подтверждения';
  syncRunConcurrency(action, { reset: actionChanged });
  renderRunOptions(action);
  updateRunAccountSelection({ applyDefault: applyAccountDefault });
}

function collectOptions() {
  const options = {};
  $$('[data-option-key]', $('#run-options')).forEach((field) => field.removeAttribute('aria-invalid'));
  $$('[data-option-key]', $('#run-options')).forEach((field) => {
    const key = field.dataset.optionKey;
    const type = field.dataset.optionType;
    const label = field.dataset.optionLabel || key;
    if (type === 'boolean') options[key] = field.checked;
    else {
      const raw = field.value.trim();
      if (!raw) {
        if (field.dataset.optionRequired === 'true') {
          field.setAttribute('aria-invalid', 'true');
          field.focus();
          throw new Error(`Заполните поле «${label}»`);
        }
        return;
      }
      if (type === 'integer' || type === 'number') {
        const value = Number(raw);
        if (!Number.isFinite(value) || (type === 'integer' && !Number.isSafeInteger(value))) {
          field.setAttribute('aria-invalid', 'true');
          field.focus();
          throw new Error(`В поле «${label}» нужно указать ${type === 'integer' ? 'целое число' : 'число'}`);
        }
        const minimum = field.min === '' ? null : Number(field.min);
        const maximum = field.max === '' ? null : Number(field.max);
        if (minimum !== null && value < minimum) {
          field.setAttribute('aria-invalid', 'true');
          field.focus();
          throw new Error(`Минимум для «${label}» — ${field.min}`);
        }
        if (maximum !== null && value > maximum) {
          field.setAttribute('aria-invalid', 'true');
          field.focus();
          throw new Error(`Максимум для «${label}» — ${field.max}`);
        }
        const multiple = Number(field.dataset.optionMultiple);
        if (Number.isFinite(multiple) && multiple > 0) {
          const quotient = value / multiple;
          if (!Number.isFinite(quotient) || Math.abs(quotient - Math.round(quotient)) > 1e-9) {
            field.setAttribute('aria-invalid', 'true');
            field.focus();
            throw new Error(`Шаг для «${label}» — ${field.dataset.optionMultiple}`);
          }
        }
        options[key] = value;
      } else {
        if (field.minLength >= 0 && raw.length < field.minLength) {
          field.setAttribute('aria-invalid', 'true');
          field.focus();
          throw new Error(`Для «${label}» нужно хотя бы ${field.minLength} символов`);
        }
        if (field.maxLength >= 0 && raw.length > field.maxLength) {
          field.setAttribute('aria-invalid', 'true');
          field.focus();
          throw new Error(`Для «${label}» можно указать не больше ${field.maxLength} символов`);
        }
        options[key] = raw;
      }
    }
  });
  $$('[data-option-range-group]', $('#run-options')).forEach((group) => {
    const [fromField, toField] = $$('[data-option-key]', group);
    if (!fromField || !toField || !fromField.value.trim() || !toField.value.trim()) return;
    if (Number(fromField.value) > Number(toField.value)) {
      fromField.setAttribute('aria-invalid', 'true');
      toField.setAttribute('aria-invalid', 'true');
      fromField.focus();
      throw new Error(`В диапазоне «${fromField.dataset.optionLabel}» значение «От» не может быть больше «До»`);
    }
  });
  const action = selectedAction();
  if (accountConcurrencyField(action) && action.account_mode !== 'none') {
    options.account_concurrency = syncRunConcurrency(action);
  }
  return options;
}

async function handleRunSubmit(event) {
  event.preventDefault();
  if ($('#run-modal').dataset.busy === 'true') return;
  const module = selectedRunModule();
  const action = selectedAction();
  if (!module || !action) return;
  const error = $('#run-error');
  error.hidden = true;
  if (actionSecretPermissions(module, action).length && !state.data.vault.unlocked) {
    state.pendingAfterUnlock = () => openRunModal(module.id, action.id);
    openVaultModal();
    return;
  }
  const accountIds = action.account_mode === 'none'
    ? []
    : $$('input[name="run-account"]:checked').map((input) => input.value);
  if (action.account_mode === 'one_or_more' && !accountIds.length) {
    const enabledAccounts = $$('input[name="run-account"]:not(:disabled)');
    if (!state.data.accounts.length) {
      $('[data-import-for-run]')?.click();
      return;
    }
    const hasRunnableAccount = enabledAccounts.length > 0;
    error.textContent = hasRunnableAccount
      ? 'Выберите хотя бы один готовый аккаунт.'
      : 'Сейчас ни один аккаунт не готов. Добавьте недостающие данные.';
    error.hidden = false;
    $('#run-accounts-block').classList.add('has-error');
    if (!hasRunnableAccount) renderRunRequirements(action);
    const target = hasRunnableAccount
      ? enabledAccounts[0]
      : $('[data-resource-import]') || $('#run-requirements');
    target?.focus();
    target?.scrollIntoView({ block: 'nearest' });
    return;
  }
  const resourceIssue = runResourceIssue(action, accountIds);
  if (resourceIssue) {
    error.textContent = resourceIssue;
    error.hidden = false;
    renderRunRequirements(action);
    $('#run-requirements').focus?.({ preventScroll: true });
    return;
  }
  let acknowledgement = '';
  if (action.risk === 'testnet_write') {
    if (!$('#risk-checkbox').checked) {
      error.textContent = 'Подтвердите testnet-запуск';
      error.hidden = false;
      $('#risk-checkbox').setAttribute('aria-invalid', 'true');
      $('#risk-checkbox').focus();
      return;
    }
    $('#risk-checkbox').removeAttribute('aria-invalid');
    acknowledgement = 'TESTNET';
  } else if (action.risk === 'mainnet_write') {
    const confirmation = $('#mainnet-phrase');
    acknowledgement = confirmation.value.trim();
    if (acknowledgement !== action.confirmation_phrase) {
      error.textContent = `Введите фразу подтверждения точно: ${action.confirmation_phrase}`;
      error.hidden = false;
      confirmation.setAttribute('aria-invalid', 'true');
      confirmation.focus();
      return;
    }
    confirmation.removeAttribute('aria-invalid');
  } else if (action.confirmation_phrase) {
    acknowledgement = action.confirmation_phrase;
  }
  const submit = $('#run-submit');
  setBusy(submit, true, 'Добавляем в очередь…');
  try {
    const run = await jsonPost(`/api/modules/${encodeURIComponent(module.id)}/run`, {
      action_id: action.id,
      account_ids: accountIds,
      options: collectOptions(),
      acknowledgement,
    });
    closeModals();
    await refresh();
    toast(`${moduleDisplayName(module)}: запуск добавлен в очередь`);
    openRunDrawer(run.id);
  } catch (failure) {
    error.textContent = failure.message;
    error.hidden = false;
  } finally {
    setBusy(submit, false);
  }
}

function drawerAccountTableMarkup(accounts) {
  return accounts.map((account) => {
    const progress = Math.max(0, Math.min(100, Math.round(Number(account.progress || 0) * 100)));
    const stage = activityStageLabel(account.stage);
    const message = account.last_message || 'Софт пока не добавил сообщение.';
    const status = accountStatusNames[account.status] || account.status || 'Не определено';
    return `
      <tr data-status="${escapeHtml(account.status || 'unknown')}">
        <th scope="row"><strong>${escapeHtml(account.account_label || 'Аккаунт')}</strong></th>
        <td><span class="drawer-stage"><strong>${escapeHtml(stage)}</strong><small>${escapeHtml(message)}</small></span></td>
        <td><span class="drawer-account-progress"><progress max="100" value="${progress}" aria-label="Прогресс ${escapeHtml(account.account_label || 'аккаунта')}: ${progress}%">${progress}%</progress><small>${progress}%</small></span></td>
        <td><span class="status-label" data-status="${escapeHtml(account.status || 'unknown')}">${escapeHtml(status)}</span></td>
      </tr>`;
  }).join('');
}

function setDrawerText(selector, value) {
  const target = $(selector);
  if (target.textContent !== value) target.textContent = value;
}

function renderDrawerAccounts(run, accounts) {
  const rows = Array.isArray(accounts) ? accounts : [];
  const tableWrap = $('#drawer-account-table-wrap');
  const empty = $('#drawer-account-empty');
  const summary = $('#drawer-account-summary');
  const signature = JSON.stringify(rows.map((account) => [
    account.account_label,
    account.status,
    account.stage,
    account.progress,
    account.last_message,
  ]));
  if (state.drawerAccountSignature !== signature) {
    $('#drawer-account-table-body').innerHTML = drawerAccountTableMarkup(rows);
    state.drawerAccountSignature = signature;
  }
  tableWrap.hidden = rows.length === 0;
  empty.hidden = rows.length > 0;
  if (rows.length) {
    const active = rows.filter((account) => ACTIVE_ACCOUNT_STATUSES.has(account.status)).length;
    const recordedErrors = rows.filter((account) => ATTENTION_ACCOUNT_STATUSES.has(account.status)).length;
    const resolution = run.status === 'reconciled'
      ? 'запуск закрыт'
      : run.status === 'reviewed'
        ? 'ошибка просмотрена'
        : '';
    const attention = resolution ? 0 : recordedErrors;
    const summaryCopy = [
      `${rows.length} ${countWord(rows.length, 'аккаунт', 'аккаунта', 'аккаунтов')}`,
      active ? `${active} ${countWord(active, 'работает', 'работают', 'работают')}` : '',
      attention ? `${attention} ${countWord(attention, 'ошибка', 'ошибки', 'ошибок')}` : '',
      resolution && recordedErrors
        ? `${recordedErrors} ${countWord(recordedErrors, 'ошибка сохранена', 'ошибки сохранены', 'ошибок сохранено')} · ${resolution}`
        : '',
    ].filter(Boolean).join(' · ');
    if (summary.textContent !== summaryCopy) summary.textContent = summaryCopy;
    return;
  }
  const accountFree = Number(run.account_count || 0) === 0;
  setDrawerText('#drawer-account-summary', accountFree ? 'Без аккаунтов' : 'Ждём статусы');
  setDrawerText('#drawer-account-empty-title', accountFree ? 'Запуск без аккаунтов' : 'Статусы ещё не пришли');
  setDrawerText('#drawer-account-empty-copy', accountFree
    ? 'Этот запуск не использует аккаунты. Итоговый статус показан выше.'
    : 'Ждём первый статус от софта.');
}

function syncDrawerLogLiveRegion() {
  const enabled = $('#drawer-technical-log').open && state.eventLogHydrated;
  $('#drawer-events').setAttribute('aria-live', enabled ? 'polite' : 'off');
}

function runResolutionKind(run, accounts = []) {
  if (!run || ACTIVE_RUN_STATUSES.has(run.status)) return '';
  if (['reconciled', 'reviewed'].includes(run.status)) return '';
  const knownAccountIssue = accounts.some((account) => (
    ['partial', 'failed', 'blocked', 'needs_attention'].includes(account.status)
    || (account.status === 'unknown' && !['historical', 'reconciled'].includes(account.stage))
  ));
  return run.status === 'failed' || knownAccountIssue ? 'review' : '';
}

async function openRunDrawer(runId) {
  const drawer = $('#run-drawer');
  let activityOrigin = null;
  if (!$('#activity-panel').hidden) {
    activityOrigin = state.activityFocusOrigin?.isConnected ? state.activityFocusOrigin : null;
    closeActivityPanel({ restoreFocus: false, immediate: true });
  }
  if (state.drawerCloseTimer !== null) {
    window.clearTimeout(state.drawerCloseTimer);
    state.drawerCloseTimer = null;
  }
  if (state.selectedRunId === runId && !drawer.hidden && !drawer.classList.contains('is-closing')) {
    await updateDrawer();
    return;
  }
  if (!state.selectedRunId && !$('.modal:not([hidden])')) {
    if (activityOrigin) {
      state.focusOrigin = activityOrigin;
      state.focusOriginIdentity = focusIdentity(activityOrigin);
    } else {
      rememberFocusOrigin();
    }
  }
  state.selectedRunId = runId;
  state.drawerRequestGeneration += 1;
  state.eventAfter = 0;
  state.eventLogHydrated = false;
  state.drawerAccountSignature = '';
  $('#drawer-account-table-body').replaceChildren();
  $('#drawer-account-table-wrap').hidden = true;
  $('#drawer-account-empty').hidden = false;
  setDrawerText('#drawer-account-empty-title', 'Загружаем статусы…');
  setDrawerText('#drawer-account-empty-copy', 'Ждём первые статусы от софта.');
  setDrawerText('#drawer-account-summary', 'Загружаем…');
  $('#drawer-technical-log').open = false;
  $('#drawer-events').replaceChildren();
  $('#drawer-events').hidden = true;
  $('#drawer-events-empty').hidden = false;
  $('#drawer-event-count').textContent = '0 событий';
  $('#drawer-events').setAttribute('aria-live', 'off');
  drawer.classList.remove('is-closing');
  drawer.hidden = false;
  $('#drawer-close').focus({ preventScroll: true });
  await updateDrawer();
}

async function toggleRunDrawer(runId) {
  const drawer = $('#run-drawer');
  if (state.selectedRunId === runId && !drawer.hidden && !drawer.classList.contains('is-closing')) {
    closeRunDrawer();
    return;
  }
  await openRunDrawer(runId);
}

function closeRunDrawer({ restoreFocus = true, immediate = false } = {}) {
  const drawer = $('#run-drawer');
  if (drawer.hidden && !state.selectedRunId && state.drawerCloseTimer === null) return;
  if (state.drawerCloseTimer !== null) {
    window.clearTimeout(state.drawerCloseTimer);
    state.drawerCloseTimer = null;
  }
  state.selectedRunId = null;
  state.selectedRunSnapshot = null;
  state.drawerRequestGeneration += 1;
  state.eventAfter = 0;
  state.eventLogHydrated = false;
  state.drawerRefreshQueued = false;
  const finish = () => {
    state.drawerCloseTimer = null;
    if (state.selectedRunId) return;
    drawer.hidden = true;
    drawer.classList.remove('is-closing');
    if (restoreFocus && $$('.modal:not([hidden])').length === 0) restoreFocusOrigin();
    else {
      state.focusOrigin = null;
      state.focusOriginIdentity = null;
    }
  };
  drawer.classList.add('is-closing');
  if (drawer.hidden || immediate || window.matchMedia('(prefers-reduced-motion: reduce)').matches) finish();
  else state.drawerCloseTimer = window.setTimeout(finish, 210);
}

function dismissRunDrawer() {
  closeRunDrawer();
}

async function updateDrawer() {
  if (!state.selectedRunId) return;
  if (state.drawerUpdating) {
    state.drawerRefreshQueued = true;
    return;
  }
  state.drawerUpdating = true;
  state.drawerRefreshQueued = false;
  const runId = state.selectedRunId;
  const generation = state.drawerRequestGeneration;
  try {
    const [run, eventsPayload, accountsPayload] = await Promise.all([
      api(`/api/runs/${encodeURIComponent(runId)}`),
      api(`/api/runs/${encodeURIComponent(runId)}/events?after=${state.eventAfter}&limit=500`),
      api(`/api/runs/${encodeURIComponent(runId)}/accounts`),
    ]);
    if (state.selectedRunId !== runId || state.drawerRequestGeneration !== generation) return;
    state.selectedRunSnapshot = run;
    $('#drawer-title').textContent = run.module_name;
    $('#drawer-meta').innerHTML = `
      <span class="status-label" data-status="${escapeHtml(run.status)}">${escapeHtml(statusNames[run.status] || run.status)}</span>
      <span class="module-version">${escapeHtml(activityActionName(run))}</span>
      <span class="module-version">${escapeHtml(run.account_count)} ${countWord(Number(run.account_count || 0), 'аккаунт', 'аккаунта', 'аккаунтов')}</span>
      ${Number(run.account_count || 0) > 0 ? `<span class="module-version module-version--concurrency">${escapeHtml(run.account_concurrency || 1)} ${countWord(Number(run.account_concurrency || 1), 'поток', 'потока', 'потоков')}</span>` : ''}
      <span class="module-version">v${escapeHtml(run.module_version)}</span>`;
    const logAccountCount = Number(run.account_count || 0);
    setDrawerText(
      '#drawer-log-export-note',
      logAccountCount
        ? `Весь запуск · ${logAccountCount} ${countWord(logAccountCount, 'аккаунт', 'аккаунта', 'аккаунтов')} · секреты скрыты`
        : 'Весь запуск без аккаунтов · секреты скрыты',
    );
    $('#drawer-progress-bar').value = Math.round(Number(run.progress || 0) * 100);
    const accountRows = Array.isArray(accountsPayload.accounts) ? accountsPayload.accounts : [];
    renderDrawerAccounts(run, accountRows);
    const consoleRoot = $('#drawer-events');
    const fragment = document.createDocumentFragment();
    for (const event of eventsPayload.events) {
      const line = document.createElement('div');
      line.className = 'event-line';
      line.dataset.level = event.level;
      const time = document.createElement('time');
      const level = document.createElement('span');
      const message = document.createElement('p');
      time.textContent = clockTime(event.created_at);
      const eventScope = event.account_label || (event.account_id ? 'Аккаунт' : 'Софт');
      level.textContent = `${eventScope} · ${event.event_type}`;
      message.textContent = event.message || JSON.stringify(event.data || {});
      line.append(time, level, message);
      fragment.append(line);
      state.eventAfter = Math.max(state.eventAfter, Number(event.id));
    }
    consoleRoot.append(fragment);
    const excessLines = consoleRoot.children.length - MAX_DRAWER_EVENT_LINES;
    for (let index = 0; index < excessLines; index += 1) consoleRoot.firstElementChild?.remove();
    const eventCount = consoleRoot.children.length;
    consoleRoot.hidden = eventCount === 0;
    $('#drawer-events-empty').hidden = eventCount > 0;
    $('#drawer-event-count').textContent = `${eventCount} ${countWord(eventCount, 'событие', 'события', 'событий')}`;
    if (eventsPayload.events.length) consoleRoot.scrollTop = consoleRoot.scrollHeight;
    if (!state.eventLogHydrated) {
      state.eventLogHydrated = true;
      window.requestAnimationFrame(() => {
        if (state.selectedRunId === runId) syncDrawerLogLiveRegion();
      });
    }
    const active = ['queued', 'starting', 'running', 'cancelling'].includes(run.status);
    const safeStop = run.safe_stop === true;
    $('#drawer-stop').hidden = !active || !safeStop || run.status === 'cancelling';
    $('#drawer-stop').disabled = false;
    $('#drawer-force-stop').hidden = !active;
    $('#drawer-force-stop').disabled = false;
    $('#drawer-stop-note').hidden = !active || safeStop;
    $('#drawer-stop-note').textContent = safeStop
      ? ''
      : 'Мягкая остановка для этого софта не настроена. «Остановить принудительно» завершит процесс через систему и сохранит журнал запуска.';
    const resolutionKind = runResolutionKind(run, accountRows);
    const resolutionNote = $('#drawer-resolution-note');
    resolutionNote.hidden = !resolutionKind;
    resolutionNote.dataset.resolution = resolutionKind;
    resolutionNote.textContent = resolutionKind === 'review'
      ? 'Посмотрите общий лог, если нужны детали. «Скрыть уведомление» уберёт ошибку с панели, но оставит её в истории.'
      : '';
    $('#drawer-review').hidden = resolutionKind !== 'review';
  } catch (error) {
    if (state.selectedRunId === runId && state.drawerRequestGeneration === generation) {
      $('#drawer-account-table-wrap').hidden = true;
      $('#drawer-account-empty').hidden = false;
      setDrawerText('#drawer-account-empty-title', 'Не удалось обновить статусы');
      setDrawerText('#drawer-account-empty-copy', 'Hub не отвечает. Обновите данные и попробуйте ещё раз.');
      setDrawerText('#drawer-account-summary', 'Нет свежих данных');
      toast(error.message, 'error');
    }
  } finally {
    state.drawerUpdating = false;
    if (state.drawerRefreshQueued && state.selectedRunId) {
      state.drawerRefreshQueued = false;
      void updateDrawer();
    }
  }
}

async function stopSelectedRun() {
  if (!state.selectedRunId) return;
  const button = $('#drawer-stop');
  setBusy(button, true, 'Останавливаем…');
  try {
    await jsonPost(`/api/runs/${encodeURIComponent(state.selectedRunId)}/stop`);
    toast('Софт получил запрос на мягкую остановку.');
    await updateDrawer();
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    setBusy(button, false);
    await updateDrawer();
  }
}

function logDownloadFilename(response, runId) {
  const disposition = response.headers.get('Content-Disposition') || '';
  const utfName = disposition.match(/filename\*=UTF-8''([^;]+)/i)?.[1];
  const plainName = disposition.match(/filename="?([^";]+)"?/i)?.[1];
  let candidate = utfName ? decodeURIComponent(utfName) : plainName;
  if (!candidate) candidate = `soft-hub-run-${runId}.log`;
  return candidate.replace(/[\\/:*?"<>|]/g, '-').slice(0, 160);
}

async function downloadSelectedRunLog() {
  const runId = state.selectedRunId;
  if (!runId || !apiToken) return;
  const button = $('#drawer-download-log');
  const previousHtml = button.innerHTML;
  button.disabled = true;
  button.setAttribute('aria-busy', 'true');
  button.textContent = 'Готовим…';
  try {
    const response = await fetch(`/api/runs/${encodeURIComponent(runId)}/log`, {
      headers: { 'X-Soft-Hub-Token': apiToken },
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.error || `HTTP ${response.status}`);
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = logDownloadFilename(response, runId);
    link.hidden = true;
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
    toast('Лог скачан. Секреты из него убраны.', 'success');
  } catch (error) {
    toast(`Не удалось скачать лог: ${error.message}`, 'error', 6000);
  } finally {
    button.innerHTML = previousHtml;
    button.disabled = false;
    button.removeAttribute('aria-busy');
  }
}

async function forceStopSelectedRun() {
  if (!state.selectedRunId) return;
  const snapshot = state.selectedRunSnapshot;
  const confirmed = await requestDestructiveConfirmation({
    title: 'Остановить софт принудительно?',
    message: snapshot?.status === 'queued'
      ? 'Уберём задачу из очереди — процесс ещё не запущен.'
      : 'Hub сразу завершит весь процесс. Журнал останется в истории, а аккаунты сразу освободятся для следующего запуска.',
    confirmLabel: 'Остановить принудительно',
    phrase: 'FORCE STOP',
  });
  if (!confirmed || !state.selectedRunId) return;
  const button = $('#drawer-force-stop');
  setBusy(button, true, 'Завершаем…');
  try {
    await jsonPost(`/api/runs/${encodeURIComponent(state.selectedRunId)}/force-stop`, { acknowledgement: 'FORCE STOP' });
    toast('Процесс остановлен. Аккаунты освободятся сразу после завершения процесса.', 'success', 5600);
    await refresh();
  } catch (error) {
    toast(error.message, 'error', 7000);
  } finally {
    setBusy(button, false);
    await updateDrawer();
  }
}

async function applyAttentionResolution(resolvedRun) {
  if (!resolvedRun?.id) return;
  const runId = String(resolvedRun.id);
  const previousRun = state.data?.runs.find((run) => run.id === runId);
  state.activityAccountsGeneration += 1;
  state.activityAccountRows = state.activityAccountRows.filter((row) => row.run_id !== runId);
  if (previousRun) Object.assign(previousRun, resolvedRun);
  if (state.data?.stats) {
    state.data.stats.attention_runs = Math.max(0, Number(state.data.stats.attention_runs || 0) - 1);
  }
  renderActivityPanel();
  renderDock();
  const pendingProjection = state.activityAccountsPromise;
  if (pendingProjection) await pendingProjection;
  await refresh();
  if (state.activityAccountsLoaded) await loadActivityAccounts({ silent: true });
}

async function reviewRunAttention(runId, button) {
  if (!runId) return;
  setBusy(button, true, 'Скрываем уведомление…');
  try {
    const resolved = await jsonPost(`/api/runs/${encodeURIComponent(runId)}/review`, {});
    await applyAttentionResolution(resolved);
    toast('Уведомление скрыто. Ошибка осталась в журнале, софт можно запускать снова.', 'success', 6200);
  } catch (error) {
    toast(error.message, 'error', 6000);
  } finally {
    setBusy(button, false);
  }
}

function reviewSelectedRunFailure() {
  if (!state.selectedRunId) return Promise.resolve();
  return reviewRunAttention(state.selectedRunId, $('#drawer-review'));
}

function bindInstallTriggers(root = document) {
  $$('[data-install-trigger]', root).forEach((button) => {
    button.addEventListener('click', () => {
      showView('patches');
      window.setTimeout(() => $('.button', $('#drop-zone')).focus({ preventScroll: true }), 220);
    });
  });
}

function isLocalPluginArchiveName(value) {
  const filename = String(value || '').toLowerCase();
  return filename.endsWith('.zip') || filename.endsWith('.softhub');
}

async function installFile(file) {
  if (!file || state.fileInstallBusy) return;
  if (!isLocalPluginArchiveName(file.name)) {
    toast('Выберите ZIP-пакет Soft Hub или файл .softhub.', 'error', 6200);
    return;
  }
  const zone = $('#drop-zone');
  const button = $('.button', zone);
  state.fileInstallBusy = true;
  zone.dataset.busy = 'true';
  zone.setAttribute('aria-busy', 'true');
  $('#plugin-file-input').disabled = true;
  zone.classList.add('is-dragging');
  setBusy(button, true, 'Проверяем пакет…');
  try {
    const module = await api('/api/modules/install', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/zip',
        'X-Soft-Hub-Filename': encodeURIComponent(file.name),
      },
      body: file,
    });
    await refresh();
    showView('software');
    toast(`${moduleDisplayName(module)} v${module.version} установлен`);
  } catch (error) {
    toast(error.message, 'error', 7000);
  } finally {
    state.fileInstallBusy = false;
    delete zone.dataset.busy;
    zone.removeAttribute('aria-busy');
    $('#plugin-file-input').disabled = false;
    zone.classList.remove('is-dragging');
    setBusy(button, false);
    $('#plugin-file-input').value = '';
  }
}

async function installFromGitHub(event) {
  event.preventDefault();
  const input = $('#github-url');
  const button = $('#github-install-button');
  const url = input.value.trim();
  if (!url) return;
  setBusy(button, true, 'Скачиваем релиз…');
  try {
    const module = await jsonPost('/api/modules/install/github', { url });
    await refresh();
    showView('software');
    input.value = '';
    const source = module.github;
    const release = source ? ` из ${source.owner}/${source.repository} ${source.release}` : '';
    toast(`${moduleDisplayName(module)} v${module.version} установлен${release}`, 'success', 6200);
  } catch (error) {
    toast(error.message, 'error', 8000);
  } finally {
    setBusy(button, false);
  }
}

async function prepareModule(moduleId, button) {
  setBusy(button, true, 'Готовим софт…');
  try {
    await jsonPost(`/api/modules/${encodeURIComponent(moduleId)}/prepare`);
    await refresh();
    toast('Софт готов к запуску.');
  } catch (error) {
    toast(error.message, 'error', 7000);
  } finally {
    setBusy(button, false);
  }
}

async function toggleModule(moduleId) {
  const module = state.data.modules.find((item) => item.id === moduleId);
  if (!module) return;
  try {
    await jsonPost(`/api/modules/${encodeURIComponent(moduleId)}/enabled`, { enabled: !module.enabled });
    await refresh();
    toast(module.enabled ? 'Софт выключен' : 'Софт включён');
  } catch (error) {
    toast(error.message, 'error');
  }
}

async function deleteModule(moduleId, button) {
  const module = state.data.modules.find((item) => item.id === moduleId);
  if (!module) return;
  const active = state.data.runs.filter((run) => run.module_id === moduleId && ACTIVE_RUN_STATUSES.has(run.status));
  if (active.length) {
    toast(`Сначала остановите активные запуски ${moduleDisplayName(module)}: ${active.length}.`, 'error', 6200);
    openActivityPanel('active', button);
    return;
  }
  const confirmed = await requestDestructiveConfirmation({
    title: `Удалить ${moduleDisplayName(module)}?`,
    message: 'Удалим код, все версии и рабочее окружение. Запуски и результаты останутся в Hub.',
    confirmLabel: 'Удалить софт',
  });
  if (!confirmed) return;
  setBusy(button, true, 'Удаляем…');
  try {
    const result = await api(`/api/modules/${encodeURIComponent(moduleId)}`, { method: 'DELETE' });
    state.batchModuleIds.delete(moduleId);
    state.batchActionIds.delete(moduleId);
    state.batchIdempotencyKey = null;
    await refresh();
    toast(result.cleanup_pending
      ? 'Софт отключён. Остатки рабочего окружения удалятся при следующей очистке.'
      : `${moduleDisplayName(module)} удалён. История и результаты сохранены.`, 'success', 6000);
  } catch (error) {
    toast(error.message, 'error', 7000);
  } finally {
    setBusy(button, false);
  }
}

async function deleteAccount(accountId) {
  const account = state.data.accounts.find((item) => item.id === accountId);
  if (!account) return;
  const childCount = Number(account.referral_children_count || 0);
  const confirmed = await requestDestructiveConfirmation({
    title: `Удалить аккаунт ${account.label}?`,
    message: `Из Vault удалятся приватник, прокси, почта, Twitter и ID профиля AdsPower. История запусков останется.${childCount ? ` Его ${childCount} ${countWord(childCount, 'реферал станет', 'реферала станут', 'рефералов станут')} корневыми аккаунтами без пригласившего.` : ''}`,
    confirmLabel: 'Удалить аккаунт',
  });
  if (!confirmed) return;
  try {
    await api(`/api/accounts/${encodeURIComponent(accountId)}`, { method: 'DELETE' });
    await refresh();
    toast('Аккаунт удалён');
  } catch (error) {
    toast(error.message, 'error');
  }
}

function applyTheme(theme) {
  const value = theme === 'dark' ? 'dark' : 'light';
  document.documentElement.dataset.theme = value;
  window.localStorage.setItem('soft-hub-theme', value);
  const button = $('#theme-button');
  if (button) {
    const dark = value === 'dark';
    button.setAttribute('aria-checked', String(dark));
    button.setAttribute('aria-label', dark ? 'Включить светлую тему' : 'Включить тёмную тему');
  }
  const themeMeta = $('meta[name="theme-color"]');
  if (themeMeta) themeMeta.setAttribute('content', value === 'dark' ? '#1d1a17' : '#ede8de');
}

function setTheme(theme) {
  applyTheme(theme === 'dark' ? 'dark' : 'light');
}

function initializeTheme() {
  const saved = window.localStorage.getItem('soft-hub-theme');
  setTheme(saved || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));
}

function batchActionIssue(module, action, { ignoreVault = false } = {}) {
  if (!module.enabled || module.health !== 'ready') return 'Софт выключен или ещё не подготовлен';
  if (action.risk === 'mainnet_write') return 'Mainnet-действия запускаются только отдельно';
  if (action.account_mode === 'one_or_more' && !state.data.accounts.length) return 'В Vault нет аккаунтов';
  if (!ignoreVault && actionSecretPermissions(module, action).length && !state.data.vault.unlocked) return 'Сначала разблокируйте Vault';
  const resources = actionResources(action);
  if (resources.declared) {
    const missingSettings = missingSettingResources(action);
    if (missingSettings.length) {
      return `Настройте ${resourceNames(missingSettings, settingResourceNames)}`;
    }
    if (action.account_mode === 'one_or_more') {
      const policy = $('#batch-account-policy')?.value === 'first' ? 'first' : 'all';
      const accounts = policy === 'first' ? state.data.accounts.slice(0, 1) : state.data.accounts;
      for (const account of accounts) {
        const missing = missingAccountResources(account, action);
        if (missing.length) {
          return `Для «${account.label}» добавьте: ${resourceNames(missing, accountResourceNames)}`;
        }
        const referralIssue = referralAccountIssue(account, action);
        if (referralIssue) return `Для «${account.label}»: ${referralIssue}`;
      }
    }
  }
  const schema = action.options || {};
  const properties = schema.properties || {};
  const required = Array.isArray(schema.required) ? schema.required : [];
  for (const key of required) {
    const field = properties[key] || {};
    if (action.risk === 'testnet_write' && key === 'acknowledge_testnet_transactions' && field.type === 'boolean') continue;
    if (field.type === 'boolean') continue;
    if (Array.isArray(field.enum) && field.enum.length) continue;
    if (field.default === undefined || field.default === '') {
      return `Для «${field.title || key}» нужно выбрать значение вручную`;
    }
  }
  return '';
}

function batchDefaultOptions(action, { accountCount = 0, requestedConcurrency = 1 } = {}) {
  const options = {};
  const properties = action.options?.properties || {};
  for (const [key, field] of Object.entries(properties)) {
    if (action.risk === 'testnet_write' && key === 'acknowledge_testnet_transactions' && field.type === 'boolean') continue;
    if (field.default !== undefined && field.default !== '') options[key] = field.default;
    else if (Array.isArray(field.enum) && field.enum.length) options[key] = field.enum[0];
    else if (field.type === 'boolean') options[key] = false;
  }
  const concurrencyField = accountConcurrencyField(action);
  if (concurrencyField && action.account_mode !== 'none') {
    const maximum = Math.max(1, Math.min(Number(concurrencyField.maximum || 1), accountCount || 1));
    options.account_concurrency = integerClamp(requestedConcurrency, 1, maximum, Number(concurrencyField.default || 1));
  }
  return options;
}

function batchSelectedActionEntries() {
  return [...state.batchModuleIds].map((moduleId) => {
    const module = state.data?.modules.find((item) => item.id === moduleId);
    const action = module?.manifest.actions.find((item) => item.id === state.batchActionIds.get(moduleId));
    return [module, action];
  }).filter(([, action]) => Boolean(action));
}

function syncBatchConcurrency({ reset = false } = {}) {
  const block = $('#batch-concurrency-block');
  const policy = $('#batch-account-policy')?.value === 'first' ? 'first' : 'all';
  const accountCount = policy === 'first' ? Math.min(1, state.data?.accounts.length || 0) : state.data?.accounts.length || 0;
  const fields = batchSelectedActionEntries()
    .map(([, action]) => accountConcurrencyField(action))
    .filter(Boolean);
  if (!fields.length) {
    block.hidden = true;
    return 1;
  }
  block.hidden = false;
  const declaredMaximum = Math.max(...fields.map((field) => Number(field.maximum || 1)), 1);
  const effectiveMaximum = Math.max(1, Math.min(20, declaredMaximum, accountCount || 1));
  const defaults = fields.map((field) => Number(field.default || 1));
  const safeDefault = integerClamp(Math.max(...defaults, 1), 1, effectiveMaximum, 1);
  const input = $('#batch-account-concurrency');
  input.min = '1';
  input.max = String(effectiveMaximum);
  if (reset || !input.dataset.preferredValue) input.dataset.preferredValue = String(safeDefault);
  const preferredValue = integerClamp(input.dataset.preferredValue, 1, Math.min(20, declaredMaximum), safeDefault);
  input.value = String(integerClamp(preferredValue, 1, effectiveMaximum, safeDefault));
  const requested = Number(input.value);
  $('#batch-concurrency-copy').textContent = accountCount
    ? `Одновременно запустим до ${requested} ${countWord(requested, 'аккаунта', 'аккаунтов', 'аккаунтов')}. Лимит каждого софта всё равно соблюдается.`
    : 'Добавьте аккаунты, чтобы включить параллельную обработку';
  $$('[data-batch-concurrency-preset]').forEach((button) => {
    const value = Number(button.dataset.batchConcurrencyPreset);
    button.hidden = value > effectiveMaximum && value !== requested;
    button.classList.toggle('is-active', value === requested);
    button.setAttribute('aria-pressed', String(value === requested));
  });
  return requested;
}

function preferredBatchAction(module, { ignoreVault = false } = {}) {
  const compatible = module.manifest.actions.filter((action) => !batchActionIssue(module, action, { ignoreVault }));
  return compatible.find((action) => action.risk === 'read' && actionSecretPermissions(module, action).length === 0)
    || compatible.find((action) => actionSecretPermissions(module, action).length === 0)
    || compatible.find((action) => action.risk === 'read')
    || compatible[0]
    || null;
}

function renderBatchRunList() {
  const modules = state.data.modules.filter((module) => state.batchModuleIds.has(module.id));
  const root = $('#batch-run-list');
  const nextActions = new Map();
  root.innerHTML = modules.map((module) => {
    const previousId = state.batchActionIds.get(module.id);
    const previous = module.manifest.actions.find((action) => action.id === previousId && !batchActionIssue(module, action));
    const selected = previous || preferredBatchAction(module);
    if (selected) nextActions.set(module.id, selected.id);
    const options = module.manifest.actions.map((action) => {
      const issue = batchActionIssue(module, action);
      const suffix = issue
        ? ` — ${issue}`
        : action.risk === 'testnet_write'
          ? ' — TESTNET'
          : action.risk === 'external_write' ? ' — Внешняя запись' : '';
      return `<option value="${escapeHtml(action.id)}" ${selected?.id === action.id ? 'selected' : ''} ${issue ? 'disabled' : ''}>${escapeHtml(action.name)}${escapeHtml(suffix)}</option>`;
    }).join('');
    const issue = selected ? batchActionIssue(module, selected) : 'Нет действия, подходящего для пакетного запуска';
    return `<article class="batch-run-item ${issue ? 'is-blocked' : ''}" data-batch-row="${escapeHtml(module.id)}">
      ${moduleIconMarkup(module)}
      <span class="batch-run-copy"><strong>${escapeHtml(moduleDisplayName(module))}</strong><small>v${escapeHtml(module.version)} · ${escapeHtml(moduleDisplayDescription(module))}</small></span>
      <label class="batch-action-field"><span>ДЕЙСТВИЕ</span><select data-batch-action="${escapeHtml(module.id)}" aria-label="Действие для ${escapeHtml(moduleDisplayName(module))}" ${selected ? '' : 'disabled'}>${selected ? options : '<option>Нет совместимых действий</option>'}</select></label>
      <button class="mini-button batch-remove" type="button" data-batch-remove="${escapeHtml(module.id)}" aria-label="Убрать ${escapeHtml(moduleDisplayName(module))} из пачки" title="Убрать из пачки">×</button>
      <p class="batch-item-note" data-state="${issue ? 'blocked' : 'ready'}">${escapeHtml(issue || actionReadyNote(selected))}</p>
    </article>`;
  }).join('');
  state.batchActionIds = nextActions;
  $('#batch-module-count').textContent = `${modules.length} ${modules.length === 1 ? 'софт' : 'софта'}`;
  updateBatchPreflight();
}

function updateBatchPreflight() {
  let blocked = false;
  let hasTestnet = false;
  $$('[data-batch-row]').forEach((row) => {
    const module = state.data.modules.find((item) => item.id === row.dataset.batchRow);
    const select = $('[data-batch-action]', row);
    const action = module?.manifest.actions.find((item) => item.id === select?.value);
    if (module && action) state.batchActionIds.set(module.id, action.id);
    const issue = module && action ? batchActionIssue(module, action) : 'Нет совместимого действия';
    row.classList.toggle('is-blocked', Boolean(issue));
    const note = $('.batch-item-note', row);
    note.dataset.state = issue ? 'blocked' : 'ready';
    note.textContent = issue || actionReadyNote(action);
    blocked ||= Boolean(issue);
    hasTestnet ||= action?.risk === 'testnet_write';
  });
  $('#batch-testnet-confirmation').hidden = !hasTestnet;
  if (!hasTestnet) $('#batch-risk-checkbox').checked = false;
  syncBatchConcurrency();
  $('#batch-run-submit').disabled = blocked || state.batchModuleIds.size === 0;
  $('#batch-run-error').hidden = true;
}

function openBatchRunModal() {
  const selectedModules = state.data?.modules.filter((module) => state.batchModuleIds.has(module.id)) || [];
  if (!selectedModules.length) {
    showView('software');
    toast('Отметьте галочками софты, которые нужно запустить вместе.', 'error', 5200);
    return;
  }
  let compositionChanged = false;
  const selectedActions = selectedModules.map((module) => {
    const selectedId = state.batchActionIds.get(module.id);
    const selected = module.manifest.actions.find((action) => action.id === selectedId
      && !batchActionIssue(module, action, { ignoreVault: true }));
    const action = selected || preferredBatchAction(module, { ignoreVault: true });
    if (action && selectedId !== action.id) {
      compositionChanged = true;
      state.batchActionIds.set(module.id, action.id);
    } else if (!action && selectedId !== undefined) {
      compositionChanged = true;
      state.batchActionIds.delete(module.id);
    }
    return [module, action];
  });
  if (compositionChanged) state.batchIdempotencyKey = null;
  const needsVault = selectedActions.some(([module, action]) => actionSecretPermissions(module, action).length > 0);
  if (needsVault && !state.data.vault.unlocked) {
    state.pendingAfterUnlock = openBatchRunModal;
    openVaultModal();
    return;
  }
  $('#batch-account-concurrency').value = '5';
  renderBatchRunList();
  syncBatchConcurrency({ reset: true });
  openModal('batch-run-modal');
}

async function handleBatchRunSubmit(event) {
  event.preventDefault();
  const error = $('#batch-run-error');
  error.hidden = true;
  const policy = $('#batch-account-policy').value;
  const allAccountIds = state.data.accounts.map((account) => account.id);
  const requestedConcurrency = syncBatchConcurrency();
  const runs = [];
  for (const moduleId of state.batchModuleIds) {
    const module = state.data.modules.find((item) => item.id === moduleId);
    const action = module?.manifest.actions.find((item) => item.id === state.batchActionIds.get(moduleId));
    if (!module || !action) {
      error.textContent = 'В пачке есть софт без выбранного действия';
      error.hidden = false;
      return;
    }
    const issue = batchActionIssue(module, action);
    if (issue) {
      error.textContent = `${moduleDisplayName(module)}: ${issue}`;
      error.hidden = false;
      return;
    }
    if (action.risk === 'testnet_write' && !$('#batch-risk-checkbox').checked) {
      error.textContent = 'Подтвердите testnet-запуски в этой пачке';
      error.hidden = false;
      $('#batch-risk-checkbox').focus();
      return;
    }
    const accountIds = action.account_mode === 'none'
      ? []
      : policy === 'first' ? allAccountIds.slice(0, 1) : allAccountIds;
    runs.push({
      module_id: module.id,
      action_id: action.id,
      account_ids: accountIds,
      options: batchDefaultOptions(action, {
        accountCount: accountIds.length,
        requestedConcurrency,
      }),
      acknowledgement: action.risk === 'testnet_write' ? 'TESTNET' : '',
    });
  }
  const submit = $('#batch-run-submit');
  setBusy(submit, true, 'Проверяем пачку…');
  try {
    if (!state.batchIdempotencyKey) state.batchIdempotencyKey = window.crypto.randomUUID();
    const payload = await jsonPost('/api/runs/batch', {
      idempotency_key: state.batchIdempotencyKey,
      runs,
    });
    state.batchModuleIds.clear();
    state.batchActionIds.clear();
    state.batchIdempotencyKey = null;
    closeModals(true, true);
    await refresh();
    openActivityPanel('active', $('[data-quick-action="live"]'));
    const started = Array.isArray(payload.runs) ? payload.runs.length : runs.length;
    toast(
      payload.replayed
        ? `Эта пачка уже была принята: ${started} задач. Дубликаты не созданы.`
        : `Запустили ${started} задач. Они будут работать параллельно.`,
      'success',
      6200,
    );
  } catch (failure) {
    error.textContent = failure.message;
    error.hidden = false;
  } finally {
    setBusy(submit, false);
  }
}

function openQuickRun() {
  const modules = state.data?.modules.filter((module) => module.enabled && module.health === 'ready') || [];
  if (!modules.length) {
    toast('Пока нет готовых софтов. Сначала установите или подготовьте хотя бы один.', 'error', 5600);
    return;
  }
  $('#quick-run-list').innerHTML = modules.map((module) => `
    <button class="quick-run-item" type="button" data-quick-run-module="${escapeHtml(module.id)}">
      ${moduleIconMarkup(module)}
      <span><strong>${escapeHtml(moduleDisplayName(module))}</strong><small>${escapeHtml(moduleDisplayDescription(module))}</small></span>
      <i>${module.manifest.actions.length} ${countWord(module.manifest.actions.length, 'действие', 'действия', 'действий')}</i>
    </button>`).join('');
  openModal('quick-run-modal');
}

function openLiveRun(origin) {
  toggleActivityPanel('active', origin);
}

function openAttentionRun(origin) {
  toggleActivityPanel('attention', origin);
}

async function confirmVaultLock() {
  const confirmed = await requestDestructiveConfirmation({
    title: 'Заблокировать Vault?',
    message: 'Пока Vault закрыт, новые запуски с секретами недоступны. Уже работающие софты продолжат работу с выданными данными.',
    confirmLabel: 'Заблокировать',
  });
  if (confirmed) await lockVault();
}

function handleQuickAction(action, origin = document.activeElement) {
  if (action === 'run') openQuickRun();
  else if (action === 'batch') openBatchRunModal();
  else if (action === 'live') openLiveRun(origin);
  else if (action === 'attention') openAttentionRun(origin);
  else if (action === 'import') openImportModal();
  else if (action === 'patch') $('#plugin-file-input').click();
  else if (action === 'vault') {
    if (state.data?.vault.unlocked) {
      void confirmVaultLock();
    } else {
      openVaultModal();
    }
  }
}

function bindEvents() {
  $$('.nav-item').forEach((button) => button.addEventListener('click', () => {
    if (button.dataset.view === 'results') setResultCatalogFilter('all');
    showView(button.dataset.view);
  }));
  $$('[data-view-trigger]').forEach((button) => button.addEventListener('click', (event) => {
    event.preventDefault();
    showView(button.dataset.viewTrigger);
  }));
  bindInstallTriggers();
  $('#refresh-button').addEventListener('click', () => refresh({ spin: true }));
  $('#result-report-refresh').addEventListener('click', () => loadResultReports({ force: true }));
  $('#result-report-select').addEventListener('change', (event) => loadSelectedResultReport(event.currentTarget.value));
  $('#result-report-search').addEventListener('input', scheduleResultReportFilterRender);
  $('#result-report-status').addEventListener('change', () => {
    if (state.resultReportFilterTimer) window.clearTimeout(state.resultReportFilterTimer);
    state.resultReportFilterTimer = null;
    if (state.selectedResultReport) renderSelectedResultReport();
  });
  $('#result-report-export').addEventListener('click', exportSelectedResultReport);
  $('#result-catalog-filter-clear').addEventListener('click', () => {
    setResultCatalogFilter('all');
    state.selectedResultReport = null;
    renderResults();
    renderResultReportWorkbench();
    if (state.resultReports.length) void loadSelectedResultReport(state.selectedResultReportId);
  });
  $$('[data-catalog-search]').forEach((input) => input.addEventListener('input', () => renderCatalogWorkspace(input.dataset.catalogSearch)));
  $$('[data-catalog-refresh-reports]').forEach((button) => button.addEventListener('click', () => loadResultReports({ force: true })));
  $('#theme-button').addEventListener('click', () => setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));
  $$('.patch-radar-blip').forEach((blip) => {
    blip.addEventListener('animationend', () => blip.classList.remove('is-visible'));
  });
  window.matchMedia('(prefers-reduced-motion: reduce)').addEventListener('change', syncPatchRadarMotion);
  $('#onboarding-action').addEventListener('click', () => handleQuickAction($('#onboarding-action').dataset.onboardingAction));
  $('#github-install-form').addEventListener('submit', installFromGitHub);
  $('#patch-feed-form').addEventListener('submit', (event) => { event.preventDefault(); void scanPatchFeed(); });
  $$('[data-quick-action]').forEach((button) => button.addEventListener('click', () => handleQuickAction(button.dataset.quickAction, button)));
  $$('[data-activity-open]').forEach((button) => button.addEventListener('click', () => toggleActivityPanel(button.dataset.activityOpen, button)));
  $('#vault-quick').addEventListener('click', () => state.data?.vault.unlocked ? showView('settings') : openVaultModal());
  $('#settings-vault-action').addEventListener('click', () => state.data?.vault.unlocked ? lockVault() : openVaultModal());
  $('#core-update-primary').addEventListener('click', handleCoreUpdateAction);
  $('#core-update-secondary').addEventListener('click', handleCoreUpdateAction);
  $('#vault-lock-button').addEventListener('click', lockVault);
  $('#import-accounts-button').addEventListener('click', openImportModal);
  $('#export-accounts-button').addEventListener('click', openExportModal);
  $$('[data-import-trigger]').forEach((button) => button.addEventListener('click', openImportModal));
  $$('[data-modal-close]').forEach((button) => button.addEventListener('click', dismissModals));
  $('#modal-backdrop').addEventListener('click', () => {
    if ($('.modal:not([hidden])')) dismissModals();
    else if (state.selectedRunId) dismissRunDrawer();
  });
  $('#vault-form').addEventListener('submit', handleVaultSubmit);
  $('#import-form').addEventListener('submit', handleImportSubmit);
  $('#export-form').addEventListener('submit', handleExportSubmit);
  $('#capsolver-form').addEventListener('submit', saveCapsolver);
  $('#capsolver-clear').addEventListener('click', clearCapsolver);
  $('#adspower-form').addEventListener('submit', saveAdsPower);
  $('#adspower-clear').addEventListener('click', clearAdsPower);
  $('#referral-open-button').addEventListener('click', openReferralModal);
  $('#referral-form').addEventListener('submit', saveReferralNetwork);
  $('#referral-parent-select').addEventListener('change', (event) => setReferralParent(event.currentTarget.value));
  $('#referral-form').addEventListener('input', handleReferralEditorInput);
  $('#referral-form').addEventListener('click', handleReferralEditorClick);
  $('#referral-chain-preview').addEventListener('pointerdown', handleReferralPointerDown);
  $('#referral-chain-preview').addEventListener('pointermove', handleReferralPointerMove);
  $('#referral-chain-preview').addEventListener('pointerup', handleReferralPointerEnd);
  $('#referral-chain-preview').addEventListener('pointercancel', handleReferralPointerEnd);
  $('#referral-chain-preview').addEventListener('lostpointercapture', handleReferralPointerEnd);
  $('#referral-chain-preview').addEventListener('wheel', handleReferralWheel, { passive: false });
  $('#referral-chain-preview').addEventListener('dblclick', handleReferralDoubleClick);
  $('#referral-chain-preview').addEventListener('keydown', handleReferralMapKeydown);
  $('#referral-minimap').addEventListener('pointerdown', handleReferralMinimapPointer);
  $('#referral-minimap').addEventListener('pointermove', handleReferralMinimapPointer);
  $('#referral-minimap').addEventListener('pointerup', handleReferralMinimapPointerEnd);
  $('#referral-minimap').addEventListener('pointercancel', handleReferralMinimapPointerEnd);
  $('#referral-minimap').addEventListener('lostpointercapture', handleReferralMinimapPointerEnd);
  $('#referral-minimap').addEventListener('keydown', handleReferralMapKeydown);
  window.addEventListener('resize', () => {
    if (!$('#referral-modal').hidden) setReferralView(state.referralView);
  });
  $('[data-unlock-vault]').addEventListener('click', openVaultModal);
  $('[data-open-account-connections]').addEventListener('click', () => {
    showView('accounts');
    window.setTimeout(() => {
      const target = state.data?.vault.unlocked ? $('#adspower-key') : $('[data-unlock-vault]');
      target?.focus({ preventScroll: true });
    }, 240);
  });
  $('#run-form').addEventListener('submit', handleRunSubmit);
  $('#run-concurrency-block').addEventListener('click', (event) => {
    const step = event.target.closest('[data-run-concurrency-step]');
    const preset = event.target.closest('[data-run-concurrency-preset]');
    if (!step && !preset) return;
    const input = $('#run-account-concurrency');
    input.value = String(preset
      ? preset.dataset.runConcurrencyPreset
      : Number(input.value || 1) + Number(step.dataset.runConcurrencyStep));
    input.dataset.preferredValue = input.value;
    updateRunAccountSelection();
  });
  $('#run-account-concurrency').addEventListener('input', (event) => {
    if (event.currentTarget.value === '') return;
    event.currentTarget.dataset.preferredValue = event.currentTarget.value;
    updateRunAccountSelection();
  });
  $('#run-account-concurrency').addEventListener('change', () => updateRunAccountSelection());
  $('#risk-checkbox').addEventListener('change', (event) => {
    if (event.currentTarget.checked) event.currentTarget.removeAttribute('aria-invalid');
  });
  $('#mainnet-phrase').addEventListener('input', (event) => {
    event.currentTarget.removeAttribute('aria-invalid');
  });
  $('#batch-run-form').addEventListener('submit', handleBatchRunSubmit);
  $('#batch-account-policy').addEventListener('change', () => {
    state.batchIdempotencyKey = null;
    updateBatchPreflight();
  });
  $('#batch-concurrency-block').addEventListener('click', (event) => {
    const step = event.target.closest('[data-batch-concurrency-step]');
    const preset = event.target.closest('[data-batch-concurrency-preset]');
    if (!step && !preset) return;
    const input = $('#batch-account-concurrency');
    input.value = String(preset
      ? preset.dataset.batchConcurrencyPreset
      : Number(input.value || 1) + Number(step.dataset.batchConcurrencyStep));
    input.dataset.preferredValue = input.value;
    state.batchIdempotencyKey = null;
    syncBatchConcurrency();
  });
  $('#batch-account-concurrency').addEventListener('input', (event) => {
    if (event.currentTarget.value === '') return;
    event.currentTarget.dataset.preferredValue = event.currentTarget.value;
    state.batchIdempotencyKey = null;
    syncBatchConcurrency();
  });
  $('#batch-account-concurrency').addEventListener('change', () => syncBatchConcurrency());
  $('#batch-open-button').addEventListener('click', openBatchRunModal);
  $('#batch-select-ready').addEventListener('click', () => {
    state.catalogBatchScope = 'all';
    state.batchIdempotencyKey = null;
    state.data.modules.filter((module) => module.enabled && module.health === 'ready').forEach((module) => state.batchModuleIds.add(module.id));
    renderSoftware();
    renderCatalogWorkspaces();
  });
  $('#batch-clear').addEventListener('click', () => {
    state.batchIdempotencyKey = null;
    state.batchModuleIds.clear();
    state.batchActionIds.clear();
    renderSoftware();
    renderCatalogWorkspaces();
  });
  $('#destructive-form').addEventListener('submit', handleDestructiveSubmit);
  $('#destructive-cancel').addEventListener('click', () => settleDestructiveConfirmation(false));
  ['#import-table', '#import-keys', '#import-proxies', '#import-emails', '#import-twitters', '#import-adspower-profiles'].forEach((selector) => $(selector).addEventListener('input', updateImportCount));
  $('#accounts-file-button').addEventListener('click', () => $('#accounts-file-input').click());
  $('#accounts-file-input').addEventListener('change', async () => {
    const file = $('#accounts-file-input').files[0];
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) {
      toast('Таблица превышает лимит 5 MB', 'error');
      $('#accounts-file-input').value = '';
      return;
    }
    try {
      $('#import-table').value = await file.text();
      updateImportCount();
    } catch (error) {
      toast(`Не удалось прочитать таблицу: ${error.message}`, 'error');
    } finally {
      $('#accounts-file-input').value = '';
    }
  });
  $('#account-search').addEventListener('input', renderAccounts);
  $('#select-all-accounts').addEventListener('click', () => {
    const boxes = $$('input[name="run-account"]:not(:disabled)');
    const shouldCheck = boxes.some((box) => !box.checked);
    boxes.forEach((box) => { box.checked = shouldCheck; });
    updateRunAccountSelection();
  });
  const quickDock = $('.quick-dock');
  quickDock.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') quickDock.dataset.tooltipsDismissed = 'true';
  });
  quickDock.addEventListener('focusout', () => {
    window.setTimeout(() => {
      if (!quickDock.contains(document.activeElement)) delete quickDock.dataset.tooltipsDismissed;
    }, 0);
  });
  quickDock.addEventListener('pointerleave', () => {
    delete quickDock.dataset.tooltipsDismissed;
  });
  $('#drawer-close').addEventListener('click', dismissRunDrawer);
  $('#drawer-technical-log').addEventListener('toggle', syncDrawerLogLiveRegion);
  $('#drawer-download-log').addEventListener('click', downloadSelectedRunLog);
  $('#drawer-stop').addEventListener('click', stopSelectedRun);
  $('#drawer-force-stop').addEventListener('click', forceStopSelectedRun);
  $('#drawer-review').addEventListener('click', reviewSelectedRunFailure);
  $('#activity-panel-close').addEventListener('click', () => closeActivityPanel());
  $('#activity-panel-refresh').addEventListener('click', refreshActivityPanel);
  $$('#activity-panel-filters button').forEach((button) => button.addEventListener('click', () => setActivityFilter(button.dataset.activityFilter)));
  $('#drop-zone').addEventListener('click', (event) => {
    if (!state.fileInstallBusy && !event.target.closest('input')) $('#plugin-file-input').click();
  });
  $('#drop-zone').addEventListener('dragover', (event) => { event.preventDefault(); $('#drop-zone').classList.add('is-dragging'); });
  $('#drop-zone').addEventListener('dragleave', () => $('#drop-zone').classList.remove('is-dragging'));
  $('#drop-zone').addEventListener('drop', (event) => {
    event.preventDefault();
    $('#drop-zone').classList.remove('is-dragging');
    installFile(event.dataTransfer.files[0]);
  });
  $('#plugin-file-input').addEventListener('change', () => installFile($('#plugin-file-input').files[0]));
  document.addEventListener('change', (event) => {
    const checkbox = event.target.closest('input[data-batch-module]');
    if (checkbox) {
      const scope = checkbox.dataset.batchScope || 'all';
      if (scope !== 'all') beginCatalogBatchSelection(scope);
      else state.catalogBatchScope = 'all';
      state.batchIdempotencyKey = null;
      if (checkbox.checked) state.batchModuleIds.add(checkbox.dataset.batchModule);
      else state.batchModuleIds.delete(checkbox.dataset.batchModule);
      syncBatchSelectionSurface();
      return;
    }
    const action = event.target.closest('select[data-batch-action]');
    if (action) {
      state.batchIdempotencyKey = null;
      updateBatchPreflight();
    }
  });
  document.addEventListener('click', (event) => {
    const updateGuide = $('#core-update-guide');
    const updateNotes = $('#core-update-notes');
    if (
      updateGuide.open
      && !updateGuide.contains(event.target)
      && !event.target.closest('[data-core-update-action="guide"]')
    ) updateGuide.open = false;
    if (updateNotes.open && !updateNotes.contains(event.target)) updateNotes.open = false;
    const activityPanel = $('#activity-panel');
    if (
      !activityPanel.hidden
      && !activityPanel.contains(event.target)
      && !event.target.closest('[aria-controls="activity-panel"]')
    ) {
      closeActivityPanel({ restoreFocus: false });
    }
    const runDrawer = $('#run-drawer');
    if (
      !runDrawer.hidden
      && !runDrawer.contains(event.target)
      && !event.target.closest('[data-open-run]')
      && !event.target.closest('[data-request-run-stop], [data-review-run]')
    ) {
      closeRunDrawer({ restoreFocus: false });
    }
    const target = event.target.closest('button');
    if (!target) return;
    if (target.dataset.runModule) openRunModal(target.dataset.runModule);
    if (target.dataset.openRun) void toggleRunDrawer(target.dataset.openRun);
    if (target.dataset.openCatalogReport) void openCatalogReport(target.dataset.openCatalogReport, target.dataset.reportSection);
    if (target.dataset.catalogOpenResults) {
      const section = target.dataset.catalogOpenResults;
      setResultCatalogFilter(section);
      const firstReport = state.resultReports.find((report) => recordBelongsToCatalog(report, section));
      state.selectedResultReport = null;
      if (firstReport) state.selectedResultReportId = firstReport.run_id;
      showView('results');
      if (firstReport) void loadSelectedResultReport(firstReport.run_id);
    }
    if (target.dataset.catalogSelectReady) selectCatalogReady(target.dataset.catalogSelectReady);
    if (target.dataset.catalogClearSelection) clearCatalogSelection(target.dataset.catalogClearSelection);
    if (target.dataset.catalogOpenBatch) openCatalogBatch(target.dataset.catalogOpenBatch);
    if (target.hasAttribute('data-catalog-open-patches')) showView('patches');
    if (target.dataset.catalogClearSearch) {
      const input = $(`[data-catalog-search="${target.dataset.catalogClearSearch}"]`);
      if (input) {
        input.value = '';
        renderCatalogWorkspace(target.dataset.catalogClearSearch);
        input.focus();
      }
    }
    if (target.dataset.requestRunStop) openRunStopFlow(target.dataset.requestRunStop);
    if (target.dataset.reviewRun) reviewRunAttention(target.dataset.reviewRun, target);
    if (target.dataset.prepareModule) prepareModule(target.dataset.prepareModule, target);
    if (target.dataset.installPatch) installPatchAsset(target.dataset.installPatch, target);
    if (target.hasAttribute('data-import-for-run')) {
      const action = selectedAction();
      state.resumeRunAfterImport = {
        moduleId: state.selectedModuleId,
        actionId: action?.id || '',
      };
      closeModals(true, true);
      openImportModal();
    }
    if (target.dataset.quickRunModule) {
      closeModals();
      openRunModal(target.dataset.quickRunModule);
    }
    if (target.dataset.toggleModule) toggleModule(target.dataset.toggleModule);
    if (target.dataset.deleteModule) deleteModule(target.dataset.deleteModule, target);
    if (target.dataset.batchRemove) {
      state.batchIdempotencyKey = null;
      state.batchModuleIds.delete(target.dataset.batchRemove);
      state.batchActionIds.delete(target.dataset.batchRemove);
      if (state.batchModuleIds.size) renderBatchRunList();
      else {
        closeModals();
        renderSoftware();
      }
      updateBatchControls();
      syncBatchSelectionSurface();
      renderDock();
    }
    if (target.dataset.deleteAccount) deleteAccount(target.dataset.deleteAccount);
    if (target.hasAttribute('data-clear-account-search')) {
      $('#account-search').value = '';
      renderAccounts();
      $('#account-search').focus();
    }
  });
  document.addEventListener('keydown', (event) => {
    const layer = $('.modal:not([hidden])');
    if (event.key === 'Tab' && layer) {
      const focusable = $$('a[href], button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])', layer)
        .filter((element) => !element.hidden && !element.closest('[hidden]') && element.getAttribute('aria-hidden') !== 'true' && element.getClientRects().length > 0);
      if (!focusable.length) {
        event.preventDefault();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && (document.activeElement === first || !layer.contains(document.activeElement))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (document.activeElement === last || !layer.contains(document.activeElement))) {
        event.preventDefault();
        first.focus();
      }
      return;
    }
    if (event.key !== 'Escape') return;
    const softwareActions = event.target.closest?.('.software-actions');
    if (softwareActions) {
      softwareActions.dataset.tooltipsDismissed = 'true';
      return;
    }
    if ($('.modal:not([hidden])')) dismissModals();
    else if (state.selectedRunId) dismissRunDrawer();
    else if (!$('#activity-panel').hidden) closeActivityPanel();
  });
  document.addEventListener('pointerout', (event) => {
    const softwareActions = event.target.closest?.('.software-actions');
    if (softwareActions && !softwareActions.contains(event.relatedTarget)) {
      delete softwareActions.dataset.tooltipsDismissed;
    }
  });
  document.addEventListener('focusout', (event) => {
    const softwareActions = event.target.closest?.('.software-actions');
    if (softwareActions && !softwareActions.contains(event.relatedTarget)) {
      delete softwareActions.dataset.tooltipsDismissed;
    }
  });
  document.addEventListener('visibilitychange', () => {
    syncPatchRadarMotion();
    if (document.visibilityState === 'visible') {
      void refresh();
      recheckCoreUpdateIfDue();
    }
  });
  window.addEventListener('resize', () => updateNavigationState(), { passive: true });
  window.addEventListener('beforeunload', () => {
    stopPatchRadarMotion();
    revokePresentationAssets();
    if (typeof state.coreUpdateUnsubscribe === 'function') state.coreUpdateUnsubscribe();
    state.coreUpdateUnsubscribe = null;
    if (state.coreUpdateCheckTimer !== null) window.clearInterval(state.coreUpdateCheckTimer);
    state.coreUpdateCheckTimer = null;
  }, { once: true });
}

async function start() {
  document.body.classList.add('app-is-starting', 'vault-entry-required');
  initializeTheme();
  bindEvents();
  updateNavigationState();
  replayBlurText($('#command-title'));
  $('#overview-runs').innerHTML = '<div class="skeleton"></div><div class="skeleton"></div>';
  $('#overview-modules').innerHTML = '<div class="skeleton"></div><div class="skeleton"></div>';
  await refresh();
  syncPatchRadarMotion();
  state.motionPass = false;
  window.setTimeout(() => document.body.classList.remove('app-is-starting'), 720);
  if (!state.data) {
    $('#vault-entry-loader-title').textContent = 'Hub не отвечает';
    $('#vault-entry-loader-copy').textContent = 'Перезапустите приложение и попробуйте ещё раз.';
  } else if (!state.data.vault.unlocked) {
    openVaultModal({ startupRequired: true });
  } else {
    setStartupVaultGate(false);
  }
  void initializeCoreUpdater();
  if (state.data?.patch_feed?.owner) window.setTimeout(() => void scanPatchFeed({ silent: true }), 850);
  state.pollHandle = window.setInterval(async () => {
    if (document.visibilityState !== 'visible') return;
    const hasActive = state.data?.runs.some((run) => ['queued', 'starting', 'running', 'cancelling'].includes(run.status));
    const activityPanelOpen = !$('#activity-panel').hidden;
    if (hasActive || state.selectedRunId || activityPanelOpen || ['results', 'nft', 'testnets'].includes(state.view)) {
      await refresh();
    }
    const selectedReport = selectedResultReportEnvelope();
    if (
      ['results', 'nft', 'testnets'].includes(state.view)
      && state.data?.vault?.unlocked
      && !state.resultReportsLoading
      && ACTIVE_RUN_STATUSES.has(selectedReport.run_status)
    ) {
      await loadSelectedResultReport(selectedReport.run_id, { force: true });
    }
    if (activityPanelOpen) await loadActivityAccounts({ silent: true });
  }, 2500);
}

start();
