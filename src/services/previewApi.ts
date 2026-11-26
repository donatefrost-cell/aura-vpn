import { BRAND } from '../config/brand';
import { DEFAULT_SETTINGS } from '../config/defaultSettings';
import { detectInputKind, splitSubscriptionUrls } from '../utils/importHelpers';
import type {
  AppSettings,
  AutoSelectResult,
  BackgroundStyle,
  BootstrapState,
  ConfigStudioView,
  ConfigValidationResult,
  ConnectionHistoryEntry,
  ConnectionHistoryResponse,
  ConnectionInspectorSnapshot,
  ConnectionSnapshot,
  ConnectionTimelineEvent,
  CoreDiagnostics,
  CoreInventorySnapshot,
  CoreKind,
  CoreUpdateCheckResult,
  DiagnosticsReport,
  DnsInspectorReport,
  DnsLiveLookupResult,
  DnsRouteCheckResult,
  DnsServerTestResult,
  EmergencyRecoveryOutcome,
  ImportOutcome,
  ImportPreviewResult,
  IpMonitorState,
  IpProviderId,
  KillSwitchConfig,
  KillSwitchSnapshot,
  LogEntry,
  NetworkDoctorReport,
  PrivacyInventory,
  PrivacyPurgeReport,
  PrivacyPurgeScope,
  ProfileAnalysisReport,
  ProfileOverrides,
  ProtectionCenterSnapshot,
  ProxyProbeResult,
  RouteTestResult,
  RoutingConfig,
  RuCategoriesConfig,
  RulepackStatus,
  ServerProfile,
  ServerQualityMetrics,
  SmartImportOutcome,
  SpeedTestResult,
  SubscriptionImportOutcome,
  SubscriptionRefreshOutcome,
  SubscriptionSyncEntry,
  TunManagerSnapshot,
  UpdateCheckResult,
  VirtualAdapterConflict,
} from '../types/vpn';

function defaultRuCategories(): RuCategoriesConfig {
  return {
    banks: true,
    gov: true,
    marketplaces: true,
    search: true,
    social: true,
    mail: true,
    telecom: true,
    education: true,
    ruTlds: true,
    otherRu: true,
  };
}

function defaultPreviewRouting(): RoutingConfig {
  return {
    profile: 'ru_direct',
    bypassLan: true,
    bypassRuDomains: true,
    ruCategories: defaultRuCategories(),
    splitTunnelMode: 'all_vpn',
    splitApps: ['steam.exe'],
    customRules: [
      {
        id: 'rule-local-example',
        enabled: true,
        matchType: 'domain',
        pattern: 'domain:gosuslugi.ru',
        action: 'direct',
        note: 'Госуслуги напрямую без VPN',
      },
      {
        id: 'rule-ads-block',
        enabled: false,
        matchType: 'domain',
        pattern: 'domain:doubleclick.net',
        action: 'block',
        note: 'Пример блокировки домена',
      },
    ],
    rulepackUpdateUrl: null,
  };
}

export function defaultPreviewSettings(): AppSettings {
  return {
    autostart: false,
    startMinimized: false,
    minimizeToTray: true,
    theme: 'dark',
    accentPreset: 'indigo',
    customAccentHex: '#6366F1',
    dynamicColor: true,
    uiScale: 100,
    compactMode: false,
    animationsEnabled: true,
    sidebarExpanded: false,
    connectionMode: 'system_proxy',
    httpPort: 10809,
    socksPort: 10808,
    activeServerId: 'srv-nl-1',
    killSwitchEnabled: false,
    killSwitch: {
      mode: 'off',
      allowLan: true,
      blockIpv6Leaks: true,
      persistOnExit: false,
      reconnectAttempts: 3,
    },
    backgroundStyle: 'aura',
    configAdaptationMode: 'auto',
    autoReconnect: true,
    reconnectOnWake: true,
    connectTimeoutSecs: DEFAULT_SETTINGS.connectTimeoutSecs,
    autoConnectOnLaunch: false,
    systemNotifications: true,
    ipv6Enabled: false,
    dns: { ...DEFAULT_SETTINGS.dns },
    tun: DEFAULT_SETTINGS.tun ? { ...DEFAULT_SETTINGS.tun } : undefined,
    advanced: DEFAULT_SETTINGS.advanced ? { ...DEFAULT_SETTINGS.advanced } : undefined,
    preferredIpProvider: 'auto',
    autoCheckIpIntervalSecs: 0,
    autoUpdateRulepack: true,
    keepLocalSubOverrides: true,
    duplicatePolicy: 'merge',
    logLevel: 'warning',
    autoCheckUpdates: false,
    updateFeedUrl: null,
    updateChannel: 'stable',
    sendHwid: true,
    deviceHwid: 'aura-preview-hwid-89f1c20b4e3a7d10',
    historyEnabled: true,
    onboardingCompleted: true,
    routing: defaultPreviewRouting(),
  };
}

let previewState: BootstrapState | null = null;
let previewRulepack: RulepackStatus | null = null;
let previewHistory: ConnectionHistoryEntry[] | null = null;

function createPreviewRulepack(): RulepackStatus {
  return {
    version: '2026.11-ru1',
    updatedAt: '2026-11-24T12:00:00Z',
    source: 'builtin',
    totalDomains: 158,
    hasBackup: false,
    geositePresent: false,
    geoipPresent: false,
    categories: [
      {
        id: 'banks',
        title: 'Банки и платежи РФ',
        description: 'Сбер, Т-Банк, Альфа-Банк, ВТБ, Мир, ЮMoney, СБП',
        examples: ['sberbank.ru', 'tbank.ru', 'alfabank.ru', 'nspk.ru'],
        domainCount: 28,
      },
      {
        id: 'gov',
        title: 'Госуслуги и госструктуры',
        description: 'Госуслуги, ФНС, Мос.ру, ПФР/СФР, суды, ЕСИА',
        examples: ['gosuslugi.ru', 'nalog.gov.ru', 'mos.ru'],
        domainCount: 18,
      },
      {
        id: 'marketplaces',
        title: 'Маркетплейсы и доставка',
        description: 'Ozon, Wildberries, Яндекс Маркет, Авито, СДЭК, Почта России',
        examples: ['ozon.ru', 'wildberries.ru', 'avito.ru', 'pochta.ru'],
        domainCount: 22,
      },
      {
        id: 'search',
        title: 'Поиск, карты и сервисы Яндекса',
        description: 'Яндекс, Поиск, 2ГИС, Навигатор, Диск (кроме внешних CDN)',
        examples: ['yandex.ru', 'ya.ru', '2gis.ru'],
        domainCount: 14,
      },
      {
        id: 'social',
        title: 'Соцсети и медиа РФ',
        description: 'ВКонтакте, Одноклассники, RuTube, Кинопоиск, Дзен',
        examples: ['vk.com', 'ok.ru', 'rutube.ru', 'kinopoisk.ru'],
        domainCount: 16,
      },
      {
        id: 'mail',
        title: 'Российская почта и облака',
        description: 'Mail.ru, Яндекс Почта, Rambler, Облако Mail.ru',
        examples: ['mail.ru', 'rambler.ru', 'disk.yandex.ru'],
        domainCount: 12,
      },
      {
        id: 'telecom',
        title: 'Операторы связи и провайдеры',
        description: 'МТС, МегаФон, Билайн, Tele2, Ростелеком, Yota',
        examples: ['mts.ru', 'megafon.ru', 'beeline.ru', 'rt.ru'],
        domainCount: 14,
      },
      {
        id: 'education',
        title: 'Образование и дневники',
        description: 'Учи.ру, Дневник.ру, Фоксфорд, вузы и порталы обучения',
        examples: ['uchi.ru', 'dnevnik.ru', 'foxford.ru'],
        domainCount: 10,
      },
      {
        id: 'ru_tlds',
        title: 'Национальные домены (.ru / .рф / .su)',
        description: 'Все домены верхнего уровня .ru, .su, .xn--p1ai (.рф)',
        examples: ['*.ru', '*.рф', '*.su'],
        domainCount: 6,
      },
      {
        id: 'other_ru',
        title: 'Прочие локальные сервисы РФ',
        description: 'РЖД, Аэрофлот, Хабр, Лента, РБК, сервисы такси',
        examples: ['rzd.ru', 'habr.com', 'rbc.ru'],
        domainCount: 18,
      },
    ],
  };
}

export function getPreviewRulepack(): RulepackStatus {
  if (!previewRulepack) {
    previewRulepack = createPreviewRulepack();
  }
  return previewRulepack;
}

function defaultPreviewQuality(): Record<string, ServerQualityMetrics> {
  return {
    'srv-nl-1': {
      lastTcpMs: 38,
      lastHttpRttMs: 62,
      successCount: 14,
      failCount: 0,
      consecutiveFailures: 0,
      lastSuccessAt: '2026-11-24T17:10:00Z',
      lastErrorCode: null,
      qualityScore: 95,
      qualityLabel: 'Отлично',
    },
    'srv-de-2': {
      lastTcpMs: 49,
      lastHttpRttMs: 74,
      successCount: 8,
      failCount: 1,
      consecutiveFailures: 0,
      lastSuccessAt: '2026-11-24T15:30:00Z',
      lastErrorCode: null,
      qualityScore: 84,
      qualityLabel: 'Отлично',
    },
    'srv-fi-3': {
      lastTcpMs: 31,
      lastHttpRttMs: null,
      successCount: 5,
      failCount: 1,
      consecutiveFailures: 0,
      lastSuccessAt: '2026-11-24T14:20:00Z',
      lastErrorCode: null,
      qualityScore: 78,
      qualityLabel: 'Хорошо',
    },
    'srv-us-4': {
      lastTcpMs: 138,
      lastHttpRttMs: null,
      successCount: 3,
      failCount: 2,
      consecutiveFailures: 1,
      lastSuccessAt: null,
      lastErrorCode: 'SERVER_UNREACHABLE',
      qualityScore: 42,
      qualityLabel: 'Нестабильно',
    },
  };
}

function getPreviewHistory(): ConnectionHistoryEntry[] {
  if (!previewHistory) {
    const now = Date.now();
    previewHistory = [
      {
        id: 'hist-1',
        serverId: 'srv-nl-1',
        serverName: 'Amsterdam Reality 01',
        countryCode: 'NL',
        protocol: 'VLESS',
        mode: 'system_proxy',
        startedAt: new Date(now - 3_600_000 * 3).toISOString(),
        endedAt: new Date(now - 3_600_000 * 1.5).toISOString(),
        durationSecs: 5400,
        rxBytes: 428_500_000,
        txBytes: 51_200_000,
        endReason: 'manual',
        reconnectCount: 0,
      },
      {
        id: 'hist-2',
        serverId: 'srv-de-2',
        serverName: 'Frankfurt Turbo Hy2',
        countryCode: 'DE',
        protocol: 'HYSTERIA2',
        mode: 'tun',
        startedAt: new Date(now - 86_400_000 * 2).toISOString(),
        endedAt: new Date(now - 86_400_000 * 2 + 2400_000).toISOString(),
        durationSecs: 2400,
        rxBytes: 1_120_000_000,
        txBytes: 145_000_000,
        endReason: 'manual',
        reconnectCount: 1,
      },
    ];
  }
  return previewHistory;
}

export function getPreviewSeedState(): BootstrapState {
  if (!previewState) {
    const now = Math.floor(Date.now() / 1000);
    const settings = defaultPreviewSettings();

    const initial: BootstrapState = {
      profiles: [
        {
          id: 'srv-nl-1',
          name: 'Amsterdam Reality 01',
          protocol: 'vless',
          address: 'nl1.aura-demo.example',
          port: 443,
          countryCode: 'NL',
          subscriptionId: 'sub-demo',
          latencyMs: 38,
          createdAt: '2026-11-24T10:00:00Z',
          favorite: true,
          lastUsedAt: '2026-11-24T17:10:00Z',
          details: {
            kind: 'vless',
            data: {
              uuid: '11111111-1111-4111-8111-111111111111',
              encryption: 'none',
              flow: 'xtls-rprx-vision',
              network: 'tcp',
              security: 'reality',
              sni: 'www.cloudflare.com',
              fingerprint: 'chrome',
              publicKey: 'demo_public_key',
              shortId: '1a2b',
              spiderX: '/',
              allowInsecure: false,
            },
          },
        },
        {
          id: 'srv-de-2',
          name: 'Frankfurt Turbo Hy2',
          protocol: 'hysteria2',
          address: 'de2.aura-demo.example',
          port: 8443,
          countryCode: 'DE',
          subscriptionId: 'sub-demo',
          latencyMs: 49,
          createdAt: '2026-11-24T10:01:00Z',
          favorite: true,
          lastUsedAt: null,
          details: {
            kind: 'hysteria2',
            data: {
              password: 'demo-password',
              sni: 'de2.aura-demo.example',
              obfs: 'salamander',
              obfsPassword: 'demo',
              allowInsecure: false,
            },
          },
        },
        {
          id: 'srv-fi-3',
          name: 'Helsinki AWG Backup',
          protocol: 'amneziawg',
          address: 'fi1.aura-demo.example',
          port: 51820,
          countryCode: 'FI',
          subscriptionId: null,
          latencyMs: 31,
          createdAt: '2026-11-24T10:02:00Z',
          favorite: false,
          lastUsedAt: '2026-11-24T14:20:00Z',
          details: {
            kind: 'amneziawg',
            data: {
              secretKey: 'demo-priv',
              address: ['10.8.0.2/32'],
              publicKey: 'demo-pub',
              endpoint: 'fi1.aura-demo.example:51820',
              mtu: 1280,
              dns: ['1.1.1.1'],
              jc: '4',
              jmin: '40',
              jmax: '70',
              s1: '12',
              s2: '24',
            },
          },
        },
        {
          id: 'srv-us-4',
          name: 'New York Trojan WS',
          protocol: 'trojan',
          address: 'us1.aura-demo.example',
          port: 443,
          countryCode: 'US',
          subscriptionId: 'sub-demo',
          latencyMs: 138,
          createdAt: '2026-11-24T10:03:00Z',
          favorite: false,
          lastUsedAt: null,
          details: {
            kind: 'trojan',
            data: {
              password: 'demo-password',
              network: 'ws',
              security: 'tls',
              sni: 'us1.aura-demo.example',
              path: '/ws',
              allowInsecure: false,
            },
          },
        },
      ],
      subscriptions: [
        {
          id: 'sub-demo',
          title: 'AURA Premium Mix',
          url: 'https://panel.aura-demo.example/sub/secret-token-preview',
          updatedAt: '2026-11-24T10:00:00Z',
          serverCount: 3,
          updateIntervalHours: 12,
          enabled: true,
          autoUpdate: true,
          errorHistory: [],
          userInfo: {
            uploadBytes: 14_200_000_000,
            downloadBytes: 98_500_000_000,
            totalBytes: 268_435_456_000,
            expireTimestamp: now + 86400 * 18,
          },
        },
      ],
      settings,
      connection: {
        status: 'disconnected',
        mode: settings.connectionMode,
        activeServerId: 'srv-nl-1',
        connectedSince: null,
        latencyMs: 38,
        errorMessage: null,
        errorInfo: null,
        systemProxyEnabled: false,
        killSwitchEngaged: false,
        localHttpPort: settings.httpPort,
        localSocksPort: settings.socksPort,
        health: {
          state: 'stopped',
          consecutiveFailures: 0,
          reason: 'Ожидание подключения',
        },
        killSwitch: {
          mode: settings.killSwitch?.mode ?? 'off',
          status: 'inactive',
          enforcement: 'none',
          blockingActive: false,
          needsElevation: false,
          allowedExceptions: [],
        },
      },
      traffic: {
        rxBytesPerSec: 0,
        txBytesPerSec: 0,
        totalRxBytes: 0,
        totalTxBytes: 0,
      },
      diagnostics: {
        coreName: 'Xray-core (MPL-2.0)',
        coreVersion: 'Xray 26.11.9 (X25519) Windows/amd64',
        corePath: 'resources/core/xray.exe',
        coreAvailable: true,
        wintunAvailable: true,
        awgAvailable: true,
        isElevated: false,
        killSwitchEngaged: false,
        systemProxyActive: false,
        activeProxyEndpoint: null,
        configDir: '%APPDATA%\\app.auravpn.desktop',
        coreIntegrityOk: true,
        awgIntegrityOk: true,
        wintunIntegrityOk: true,
        integrityNote: 'Все компоненты ядра подтверждены SHA-256.',
      },
      serverQuality: defaultPreviewQuality(),
      needsKillSwitchElevation: false,
      killSwitch: {
        mode: settings.killSwitch?.mode ?? 'off',
        status: 'inactive',
        enforcement: 'none',
        blockingActive: false,
        needsElevation: false,
        allowedExceptions: [],
      },
      ipMonitor: {
        vpnIp: null,
        originalIp: {
          ip: '198.51.100.18',
          country: 'Russia',
          countryCode: 'RU',
          city: 'Moscow',
          isp: 'Preview ISP',
          checkedAt: new Date(now * 1000 - 300_000).toISOString(),
          source: 'preview',
          viaVpn: false,
          mode: 'system_proxy',
        },
        ipChanged: null,
        maskIp: true,
      },
    };

    if (typeof window !== 'undefined') {
      const urlParams = new URLSearchParams(window.location.search);
      if (urlParams.get('preview') === 'empty') {
        initial.profiles = [];
        initial.subscriptions = [];
        initial.settings.activeServerId = null;
        initial.settings.onboardingCompleted = false;
        initial.connection.activeServerId = null;
      } else if (urlParams.get('preview') === 'connected') {
        initial.connection = {
          status: 'connected',
          mode: initial.settings.connectionMode,
          activeServerId: 'srv-nl-1',
          connectedSince: now - 325,
          latencyMs: 38,
          errorMessage: null,
          errorInfo: null,
          systemProxyEnabled: initial.settings.connectionMode === 'system_proxy',
          killSwitchEngaged: false,
          localHttpPort: initial.settings.httpPort,
          localSocksPort: initial.settings.socksPort,
        };
        initial.traffic = {
          rxBytesPerSec: 4_850_000,
          txBytesPerSec: 680_000,
          totalRxBytes: 428_500_000,
          totalTxBytes: 51_200_000,
        };
      } else if (urlParams.get('preview') === 'error') {
        initial.connection = {
          status: 'error',
          mode: 'tun',
          activeServerId: 'srv-nl-1',
          connectedSince: null,
          latencyMs: null,
          errorMessage: 'Для работы TUN-режима требуются права администратора Windows.',
          errorInfo: {
            code: 'ADMIN_REQUIRED',
            category: 'permissions',
            title: 'Требуются права администратора',
            message: 'Для работы TUN-режима требуются права администратора Windows.',
            hint: 'Перезапустите AURA VPN от имени администратора или переключитесь в режим «Системный прокси».',
            action: 'relaunch_admin',
          },
          systemProxyEnabled: false,
          killSwitchEngaged: false,
          localHttpPort: null,
          localSocksPort: null,
        };
      }
      const qTheme = urlParams.get('theme');
      if (qTheme === 'light' || qTheme === 'dark' || qTheme === 'system') {
        initial.settings.theme = qTheme;
      }
      const qAccent = urlParams.get('accent');
      if (
        qAccent === 'windows' ||
        qAccent === 'indigo' ||
        qAccent === 'blue' ||
        qAccent === 'purple' ||
        qAccent === 'teal' ||
        qAccent === 'green' ||
        qAccent === 'custom'
      ) {
        initial.settings.accentPreset = qAccent;
      }
      const qHex = urlParams.get('hex');
      if (qHex && /^[0-9a-fA-F]{6}$/.test(qHex.replace(/^#/, ''))) {
        initial.settings.accentPreset = 'custom';
        initial.settings.customAccentHex = `#${qHex.replace(/^#/, '').toUpperCase()}`;
      }
      const qScale = Number(urlParams.get('scale'));
      if (Number.isFinite(qScale) && qScale >= 90 && qScale <= 120) {
        initial.settings.uiScale = qScale;
      }
      if (urlParams.get('compact') === '1') {
        initial.settings.compactMode = true;
      }
    }

    previewState = initial;
  }
  return previewState;
}

export const previewApi = {
  async getBootstrapState(): Promise<BootstrapState> {
    return getPreviewSeedState();
  },

  async previewImportText(raw: string): Promise<ImportPreviewResult> {
    const detected = detectInputKind(raw);
    const trimmed = raw.trim();
    if (!trimmed) {
      return { kind: 'empty', validCount: 0, duplicateCount: 0, skippedLines: 0, errors: [], servers: [] };
    }
    if (detected.kind === 'sub' || detected.kind === 'multi_sub') {
      const urls = splitSubscriptionUrls(trimmed);
      return {
        kind: 'subscription',
        validCount: urls.length > 0 ? urls.length : 1,
        duplicateCount: 0,
        skippedLines: 0,
        errors: [],
        servers: [],
      };
    }
    const lines = trimmed.split(/\r?\n/).filter((l) => l.trim().length > 0);
    return {
      kind: 'servers',
      validCount: Math.max(1, Math.min(lines.length, 5)),
      duplicateCount: 0,
      skippedLines: 0,
      errors: [],
      servers: [
        {
          name: 'Preview Node',
          protocol: detected.kind === 'awg_ini' ? 'AMNEZIAWG' : 'VLESS',
          address: 'preview.example.com',
          port: 443,
          countryCode: 'NL',
          isDuplicate: false,
        },
      ],
    };
  },

  async importFromText(raw: string, _applyAdaptations?: boolean): Promise<ImportOutcome> {
    const s = getPreviewSeedState();
    const srv: ServerProfile = {
      id: `srv-${Date.now()}`,
      name: raw.trim().slice(0, 24) || 'Импортированный узел (демо)',
      protocol: 'vless',
      address: 'demo-imported.example',
      port: 443,
      countryCode: 'DE',
      latencyMs: 52,
      createdAt: new Date().toISOString(),
      favorite: false,
      lastUsedAt: null,
      details: s.profiles[0]?.details ?? {
        kind: 'shadowsocks',
        data: { method: 'chacha20-ietf-poly1305', password: 'demo' },
      },
    };
    s.profiles.unshift(srv);
    return { result: { importedServers: [srv], skippedLines: 0, errors: [] }, state: { ...s } };
  },

  async importSubscription(url: string): Promise<SubscriptionImportOutcome> {
    const s = getPreviewSeedState();
    const sub = {
      id: `sub-${Date.now()}`,
      title: new URL(url).hostname,
      url,
      updatedAt: new Date().toISOString(),
      serverCount: 1,
      updateIntervalHours: 12,
      enabled: true,
      autoUpdate: true,
      errorHistory: [],
      userInfo: null,
    };
    s.subscriptions.push(sub);
    return { subscription: sub, state: { ...s } };
  },

  async smartImport(raw: string, _applyAdaptations?: boolean): Promise<SmartImportOutcome> {
    const trimmed = raw.trim();
    if (/^https?:\/\//i.test(trimmed)) {
      const out = await previewApi.importSubscription(trimmed);
      return {
        kind: 'subscription',
        importedCount: out.subscription.serverCount,
        skippedLines: 0,
        title: out.subscription.title,
        state: out.state,
      };
    }
    const out = await previewApi.importFromText(raw);
    return {
      kind: 'servers',
      importedCount: out.result.importedServers.length,
      skippedLines: out.result.skippedLines,
      state: out.state,
    };
  },

  async refreshSubscription(id: string): Promise<SubscriptionRefreshOutcome> {
    const s = getPreviewSeedState();
    const sub = s.subscriptions.find((x) => x.id === id);
    if (sub) sub.updatedAt = new Date().toISOString();
    const count = s.profiles.filter((p) => p.subscriptionId === id).length;
    return {
      diff: {
        subscriptionId: id,
        added: 0,
        removed: 0,
        updated: 0,
        unchanged: count,
        activeServerChanged: false,
        canRollback: true,
        warnings: [],
      },
      state: { ...s },
    };
  },

  async rollbackSubscription(_id: string): Promise<BootstrapState> {
    return { ...getPreviewSeedState() };
  },

  async deleteSubscription(id: string): Promise<BootstrapState> {
    const s = getPreviewSeedState();
    s.subscriptions = s.subscriptions.filter((x) => x.id !== id);
    s.profiles = s.profiles.filter((p) => p.subscriptionId !== id);
    return { ...s };
  },

  async renameSubscription(id: string, title: string): Promise<BootstrapState> {
    const s = getPreviewSeedState();
    const clean = title.trim();
    if (!clean) throw new Error('Название подписки не может быть пустым');
    s.subscriptions = s.subscriptions.map((x) => (x.id === id ? { ...x, title: clean } : x));
    return { ...s };
  },

  async toggleSubscriptionEnabled(id: string, enabled: boolean): Promise<BootstrapState> {
    const s = getPreviewSeedState();
    s.subscriptions = s.subscriptions.map((x) => (x.id === id ? { ...x, enabled } : x));
    return { ...s };
  },

  async updateSubscriptionConfig(
    id: string,
    autoUpdate: boolean,
    updateIntervalHours: number | null,
  ): Promise<BootstrapState> {
    const s = getPreviewSeedState();
    s.subscriptions = s.subscriptions.map((x) =>
      x.id === id ? { ...x, autoUpdate, updateIntervalHours } : x,
    );
    return { ...s };
  },

  async selectServer(id: string): Promise<BootstrapState> {
    const s = getPreviewSeedState();
    s.settings.activeServerId = id;
    s.connection.activeServerId = id;
    return { ...s };
  },

  async toggleFavoriteServer(id: string): Promise<BootstrapState> {
    const s = getPreviewSeedState();
    s.profiles = s.profiles.map((p) => (p.id === id ? { ...p, favorite: !p.favorite } : p));
    return { ...s };
  },

  async renameServer(id: string, name: string): Promise<BootstrapState> {
    const s = getPreviewSeedState();
    s.profiles = s.profiles.map((p) => (p.id === id ? { ...p, name } : p));
    return { ...s };
  },

  async deleteServer(id: string): Promise<BootstrapState> {
    const s = getPreviewSeedState();
    s.profiles = s.profiles.filter((p) => p.id !== id);
    if (s.settings.activeServerId === id) {
      s.settings.activeServerId = s.profiles[0]?.id ?? null;
      s.connection.activeServerId = s.settings.activeServerId;
    }
    return { ...s };
  },

  async pingServer(id: string): Promise<number | null> {
    const s = getPreviewSeedState();
    const val = Math.floor(28 + Math.random() * 65);
    s.profiles = s.profiles.map((p) => (p.id === id ? { ...p, latencyMs: val } : p));
    return val;
  },

  async pingAllServers(): Promise<ServerProfile[]> {
    const s = getPreviewSeedState();
    s.profiles = s.profiles.map((p) => ({
      ...p,
      latencyMs: Math.floor(25 + Math.random() * 140),
    }));
    return [...s.profiles];
  },

  async autoSelectFastestServer(): Promise<AutoSelectResult> {
    const s = getPreviewSeedState();
    const sorted = [...s.profiles].sort((a, b) => (a.latencyMs ?? 9999) - (b.latencyMs ?? 9999));
    const best = sorted[0];
    s.settings.activeServerId = best?.id ?? null;
    s.connection.activeServerId = best?.id ?? null;
    return {
      selectedServerId: best?.id ?? '',
      serverName: best?.name ?? 'Сервер',
      latencyMs: best?.latencyMs ?? 38,
      state: { ...s },
    };
  },

  async connect(serverId?: string | null): Promise<ConnectionSnapshot> {
    const s = getPreviewSeedState();
    const id = serverId ?? s.settings.activeServerId ?? null;
    if (id) {
      s.profiles = s.profiles.map((p) =>
        p.id === id ? { ...p, lastUsedAt: new Date().toISOString() } : p,
      );
    }
    s.connection = {
      status: 'connected',
      mode: s.settings.connectionMode,
      activeServerId: id,
      connectedSince: Math.floor(Date.now() / 1000),
      latencyMs: s.profiles.find((p) => p.id === id)?.latencyMs ?? 38,
      errorMessage: null,
      errorInfo: null,
      systemProxyEnabled: s.settings.connectionMode === 'system_proxy',
      killSwitchEngaged: false,
      localHttpPort: s.settings.httpPort,
      localSocksPort: s.settings.socksPort,
    };
    return { ...s.connection };
  },

  async disconnect(): Promise<ConnectionSnapshot> {
    const s = getPreviewSeedState();
    s.connection = {
      status: 'disconnected',
      mode: s.settings.connectionMode,
      activeServerId: s.settings.activeServerId ?? null,
      connectedSince: null,
      latencyMs: null,
      errorMessage: null,
      errorInfo: null,
      systemProxyEnabled: false,
      killSwitchEngaged: false,
      localHttpPort: null,
      localSocksPort: null,
    };
    return { ...s.connection };
  },

  async disengageKillSwitch(): Promise<ConnectionSnapshot> {
    const s = getPreviewSeedState();
    s.connection.killSwitchEngaged = false;
    s.needsKillSwitchElevation = false;
    return { ...s.connection };
  },

  async probeActiveConnection(): Promise<ProxyProbeResult> {
    const s = getPreviewSeedState();
    if (s.connection.status !== 'connected') {
      return {
        ok: false,
        rttMs: null,
        endpoint: 'https://cp.cloudflare.com/generate_204',
        message: 'Нет активного подключения (превью)',
      };
    }
    return {
      ok: true,
      rttMs: 64,
      endpoint: `127.0.0.1:${s.settings.httpPort}`,
      message: 'HTTPS 204 через локальный прокси',
    };
  },

  async updateSettings(newSettings: AppSettings): Promise<AppSettings> {
    const s = getPreviewSeedState();
    s.settings = newSettings;
    s.connection.mode = newSettings.connectionMode;
    return newSettings;
  },

  async getRulepackStatus(): Promise<RulepackStatus> {
    return { ...getPreviewRulepack() };
  },

  async updateRulepack(url?: string | null): Promise<RulepackStatus> {
    const rp = getPreviewRulepack();
    rp.updatedAt = new Date().toISOString();
    rp.source = url?.trim() ? url.trim() : 'preview-sync';
    rp.hasBackup = true;
    return { ...rp };
  },

  async rollbackRulepack(): Promise<RulepackStatus> {
    const rp = getPreviewRulepack();
    rp.hasBackup = false;
    rp.source = 'builtin';
    return { ...rp };
  },

  async testRoute(query: string, _process?: string | null): Promise<RouteTestResult> {
    const host = query
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, '')
      .split('/')[0]
      .split(':')[0];
    if (!host) {
      throw new Error('Введите домен, URL или IP-адрес для проверки маршрута');
    }
    const isRu =
      host.endsWith('.ru') ||
      host.endsWith('.su') ||
      host.endsWith('.xn--p1ai') ||
      ['vk.com', 'gosuslugi.ru', 'sberbank.ru'].some((d) => host === d || host.endsWith(`.${d}`));
    return {
      query,
      normalizedHost: host,
      action: isRu ? 'direct' : 'proxy',
      priorityLabel: isRu ? 'Приоритет 3 — РФ напрямую' : 'Приоритет 4 — Маршрут по умолчанию (VPN)',
      matchedRule: isRu ? 'category:ru-direct' : 'proxy (outbound)',
      matchedCategory: isRu ? 'Российские сервисы напрямую' : null,
      explanation: isRu
        ? 'Домен относится к российским сервисам и направляется напрямую.'
        : 'Трафик направляется через VPN-туннель.',
      requiresTunNote: false,
      isConfigAnalysis: true,
    };
  },

  async dnsLookupRoute(domain: string): Promise<DnsRouteCheckResult> {
    return { domain: domain.trim(), resolvedIps: ['203.0.113.242'], error: null };
  },

  async runNetworkDiagnostics(includeExternalIp: boolean): Promise<DiagnosticsReport> {
    const s = getPreviewSeedState();
    return {
      checkedAt: new Date().toISOString(),
      externalIp: includeExternalIp ? '198.51.100.42' : null,
      checks: [
        {
          id: 'integrity',
          label: 'Целостность компонентов',
          status: 'ok',
          value: 'SHA-256 OK',
          detail: `xray.exe, wireproxy-awg.exe и wintun.dll соответствуют манифесту v${BRAND.version}.`,
        },
        {
          id: 'ports',
          label: 'Локальные порты и шлюз',
          status: 'ok',
          value: `${s.settings.httpPort}/${s.settings.socksPort}`,
          detail: 'Порты HTTP и SOCKS5 готовы к работе.',
        },
        {
          id: 'dns',
          label: 'DNS-резолвинг',
          status: 'ok',
          value: '18 мс',
          detail: 'Системный DNS вернул 2 адреса для one.one.one.one.',
        },
        {
          id: 'tunnel',
          label: 'Доступность узла',
          status: s.connection.status === 'connected' ? 'ok' : 'warn',
          value: s.connection.status === 'connected' ? '64 мс' : 'Отключён',
          detail:
            s.connection.status === 'connected'
              ? 'Подтверждён выход через cloudflare HTTPS 204.'
              : 'Подключитесь к серверу для полной проверки туннеля.',
        },
        {
          id: 'external_ip',
          label: includeExternalIp ? 'Внешний IP (opt-in)' : 'Внешний IP (приватность)',
          status: 'ok',
          value: includeExternalIp ? '198.51.100.42' : 'Отключено',
          detail: includeExternalIp
            ? 'Демонстрационный IP-адрес (превью).'
            : 'Запросы к внешним сервисам IP не выполняются без явного согласия.',
        },
      ],
    };
  },

  async getConnectionHistory(): Promise<ConnectionHistoryResponse> {
    const entries = getPreviewHistory();
    return {
      entries: [...entries],
      aggregates: {
        todayRxBytes: entries[0]?.rxBytes ?? 0,
        todayTxBytes: entries[0]?.txBytes ?? 0,
        weekRxBytes: entries.reduce((acc, e) => acc + e.rxBytes, 0),
        weekTxBytes: entries.reduce((acc, e) => acc + e.txBytes, 0),
        monthRxBytes: entries.reduce((acc, e) => acc + e.rxBytes, 0),
        monthTxBytes: entries.reduce((acc, e) => acc + e.txBytes, 0),
        totalDurationSecs: entries.reduce((acc, e) => acc + e.durationSecs, 0),
        totalSessions: entries.length,
        totalReconnects: entries.reduce((acc, e) => acc + e.reconnectCount, 0),
      },
      serverQuality: getPreviewSeedState().serverQuality,
    };
  },

  async clearConnectionHistory(): Promise<ConnectionHistoryResponse> {
    previewHistory = [];
    return {
      entries: [],
      aggregates: {
        todayRxBytes: 0,
        todayTxBytes: 0,
        weekRxBytes: 0,
        weekTxBytes: 0,
        monthRxBytes: 0,
        monthTxBytes: 0,
        totalDurationSecs: 0,
        totalSessions: 0,
        totalReconnects: 0,
      },
      serverQuality: getPreviewSeedState().serverQuality,
    };
  },

  async exportDiagnosticsBundle(): Promise<string> {
    const s = getPreviewSeedState();
    return JSON.stringify(
      {
        exportedAt: new Date().toISOString(),
        appVersion: BRAND.version,
        diagnostics: s.diagnostics,
        connection: s.connection,
        settings: { ...s.settings, deviceHwid: '[REDACTED]' },
        logs: [],
      },
      null,
      2,
    );
  },

  async exportSettingsBackup(): Promise<string> {
    const { deviceHwid: _omit, ...rest } = getPreviewSeedState().settings;
    return JSON.stringify(rest, null, 2);
  },

  async importSettingsBackup(rawJson: string): Promise<AppSettings> {
    const parsed = JSON.parse(rawJson) as Partial<AppSettings>;
    const s = getPreviewSeedState();
    s.settings = {
      ...s.settings,
      ...parsed,
      dns: { ...s.settings.dns, ...(parsed.dns ?? {}) },
      routing: { ...s.settings.routing, ...(parsed.routing ?? {}) },
    };
    return s.settings;
  },

  async resetSettingsToDefault(): Promise<BootstrapState> {
    const s = getPreviewSeedState();
    const fresh = defaultPreviewSettings();
    fresh.activeServerId = s.settings.activeServerId;
    s.settings = fresh;
    return { ...s };
  },

  async checkForUpdates(): Promise<UpdateCheckResult> {
    return {
      currentVersion: BRAND.version,
      latestVersion: null,
      updateAvailable: false,
      status: 'unconfigured',
      message: 'Сервер обновлений не настроен (превью в браузере).',
      releaseUrl: null,
      checkedAt: new Date().toISOString(),
    };
  },

  async getLogs(): Promise<LogEntry[]> {
    return [
      {
        id: 1,
        timestamp: '19:00:00',
        level: 'info',
        source: 'system',
        message: `AURA VPN ${BRAND.version} — демонстрационный режим интерфейса без ядра`,
      },
    ];
  },

  async getDiagnostics(): Promise<CoreDiagnostics> {
    return getPreviewSeedState().diagnostics;
  },

  async bulkDeleteServers(ids: string[]): Promise<BootstrapState> {
    const s = getPreviewSeedState();
    const idSet = new Set(ids);
    s.profiles = s.profiles.filter((p) => !idSet.has(p.id));
    if (s.settings.activeServerId && idSet.has(s.settings.activeServerId)) {
      s.settings.activeServerId = s.profiles[0]?.id ?? null;
    }
    return { ...s };
  },

  async bulkSetFavoriteServers(ids: string[], favorite: boolean): Promise<BootstrapState> {
    const s = getPreviewSeedState();
    const idSet = new Set(ids);
    s.profiles = s.profiles.map((p) => (idSet.has(p.id) ? { ...p, favorite } : p));
    return { ...s };
  },

  async getWindowModeState() {
    const isMini =
      typeof window !== 'undefined' &&
      new URLSearchParams(window.location.search).get('mode') === 'mini';
    return { miniMode: isMini, alwaysOnTop: false };
  },

  async setMiniMode(enabled: boolean, alwaysOnTop?: boolean) {
    return { miniMode: enabled, alwaysOnTop: Boolean(alwaysOnTop) };
  },

  async setAlwaysOnTop(enabled: boolean) {
    return { miniMode: true, alwaysOnTop: enabled };
  },

  async getKillSwitchStatus(): Promise<KillSwitchSnapshot> {
    const s = getPreviewSeedState();
    return (
      s.killSwitch ?? {
        mode: s.settings.killSwitch?.mode ?? 'off',
        status: 'inactive',
        enforcement: 'none',
        blockingActive: false,
        needsElevation: false,
        allowedExceptions: [],
      }
    );
  },

  async setKillSwitchConfig(config: KillSwitchConfig): Promise<BootstrapState> {
    const s = getPreviewSeedState();
    s.settings = {
      ...s.settings,
      killSwitch: config,
      killSwitchEnabled: config.mode !== 'off',
    };
    const nextKs: KillSwitchSnapshot = {
      mode: config.mode,
      status: config.mode === 'always_on' ? 'blocking' : config.mode === 'off' ? 'inactive' : 'armed',
      enforcement: config.mode === 'off' ? 'none' : 'proxy_guard',
      blockingActive: config.mode === 'always_on',
      needsElevation: false,
      allowedExceptions:
        config.mode === 'routing_aware' ? ['Прямые правила маршрутизации сохраняются'] : [],
      updatedAt: new Date().toISOString(),
    };
    s.killSwitch = nextKs;
    s.connection = { ...s.connection, killSwitch: nextKs, killSwitchEngaged: nextKs.blockingActive };
    return { ...s };
  },

  async emergencyRecoverNetwork(): Promise<EmergencyRecoveryOutcome> {
    const s = getPreviewSeedState();
    const cleanKs: KillSwitchSnapshot = {
      mode: s.settings.killSwitch?.mode ?? 'off',
      status: 'inactive',
      enforcement: 'none',
      blockingActive: false,
      needsElevation: false,
      allowedExceptions: [],
      updatedAt: new Date().toISOString(),
    };
    s.killSwitch = cleanKs;
    s.connection = { ...s.connection, killSwitch: cleanKs, killSwitchEngaged: false };
    return {
      report: {
        wfpFiltersRemoved: false,
        legacyNetshRuleRemoved: false,
        systemProxyRestored: true,
        orphanedProcessesKilled: 0,
        staleFilesCleaned: 0,
        needsElevation: false,
        warnings: [],
      },
      state: { ...s },
    };
  },

  async checkIpMonitor(includeIpv6 = false, provider?: IpProviderId): Promise<IpMonitorState> {
    const s = getPreviewSeedState();
    const chosenProvider = provider ?? s.settings.preferredIpProvider ?? 'auto';
    const isConn = s.connection.status === 'connected';
    const next: IpMonitorState = {
      originalIp: s.ipMonitor?.originalIp ?? {
        ip: '198.51.100.18',
        ipv6: includeIpv6 ? '2001:db8::1' : null,
        country: 'Russia',
        countryCode: 'RU',
        city: 'Moscow',
        isp: 'Preview ISP',
        org: 'AS64500 Local ISP',
        asn: 'AS64500',
        timezone: 'Europe/Moscow',
        networkType: 'residential / ISP',
        latencyMs: 28,
        checkedAt: new Date().toISOString(),
        source: `preview:${chosenProvider}`,
        viaVpn: false,
        mode: s.settings.connectionMode,
      },
      vpnIp: isConn
        ? {
            ip: '203.0.113.44',
            ipv6: includeIpv6 ? '2001:db8::44' : null,
            country: 'Netherlands',
            countryCode: 'NL',
            city: 'Amsterdam',
            isp: 'Preview Exit AS',
            org: 'AS64512 Aura Network',
            asn: 'AS64512',
            timezone: 'Europe/Amsterdam',
            networkType: 'datacenter / hosting',
            latencyMs: 64,
            checkedAt: new Date().toISOString(),
            source: `preview:${chosenProvider}`,
            viaVpn: true,
            mode: s.settings.connectionMode,
          }
        : s.ipMonitor?.vpnIp ?? null,
      ipChanged: isConn ? true : null,
      ipv6Changed: isConn && includeIpv6 ? true : null,
      maskIp: s.ipMonitor?.maskIp ?? true,
      provider: chosenProvider,
      comparisonNote: isConn ? 'Выходной IPv4 отличается от сохранённого исходного адреса.' : null,
    };
    s.ipMonitor = next;
    return next;
  },

  async setIpMask(maskIp: boolean): Promise<IpMonitorState> {
    const s = getPreviewSeedState();
    const next: IpMonitorState = {
      ...(s.ipMonitor ?? { maskIp }),
      maskIp,
    };
    s.ipMonitor = next;
    return next;
  },

  async getProtectionCenter(): Promise<ProtectionCenterSnapshot> {
    const s = getPreviewSeedState();
    const ks = await previewApi.getKillSwitchStatus();
    const isConn = s.connection.status === 'connected';
    return {
      checkedAt: new Date().toISOString(),
      items: [
        {
          id: 'vpn_tunnel',
          label: 'Состояние VPN-туннеля',
          status: isConn ? 'verified' : 'unchecked',
          value: isConn ? 'Активен' : 'Отключён',
          detail: isConn ? 'Соединение установлено (демо).' : 'Подключитесь для проверки туннеля.',
          kind: 'network',
        },
        {
          id: 'kill_switch',
          label: 'Kill Switch',
          status: ks.mode === 'off' ? 'limited' : 'verified',
          value: ks.mode === 'off' ? 'Выключен' : 'Активен',
          detail: 'Режим защиты настраивается в Разделе Безопасность.',
          kind: 'config',
        },
        {
          id: 'ip_change',
          label: 'Контроль внешнего IP',
          status: s.ipMonitor?.ipChanged ? 'verified' : 'unchecked',
          value: s.ipMonitor?.ipChanged ? 'Изменён через VPN' : 'Не проверено',
          detail: 'Проверяется только по явному запросу пользователя.',
          kind: 'network',
        },
        {
          id: 'ipv6_protection',
          label: 'Защита от утечек IPv6',
          status: s.settings.ipv6Enabled ? 'limited' : 'verified',
          value: s.settings.ipv6Enabled ? 'IPv6 включён' : 'IPv6 блокируется',
          detail: 'Без IPv6 TUN блокирует ::/0 по умолчанию.',
          kind: 'config',
        },
      ],
      killSwitch: ks,
      ipMonitor: s.ipMonitor ?? { maskIp: true },
    };
  },

  async analyzeServerProfile(id: string): Promise<ProfileAnalysisReport> {
    const s = getPreviewSeedState();
    const p = s.profiles.find((x) => x.id === id) ?? s.profiles[0];
    return {
      serverId: p?.id ?? id,
      status: 'valid',
      coreAvailable: true,
      protocolSupported: true,
      capabilities: {
        protocol: (p?.protocol ?? 'vless').toUpperCase(),
        transport: 'TCP / REALITY',
        security: 'REALITY',
        requiresUdp: p?.protocol === 'hysteria2' || p?.protocol === 'wireguard' || p?.protocol === 'amneziawg',
        supportsSystemProxy: true,
        supportsTun: true,
        mtu: p?.overrides?.mtu ?? 1420,
        dnsServers: p?.overrides?.customDns ? [p.overrides.customDns] : [],
        nodeCount: 1,
        hasBalancer: false,
        minCoreRequirement: 'Xray-core 26.x',
        features: ['TLS 1.3', 'X25519'],
      },
      warnings: [],
      unsupportedFields: [],
      proposals:
        p?.overrides?.mtu == null && (p?.protocol === 'wireguard' || p?.protocol === 'amneziawg')
          ? [
              {
                field: 'mtu',
                label: 'MTU туннеля',
                currentValue: 'Авто',
                proposedValue: '1380',
                reason: 'Устойчивый MTU для сетей с фрагментацией.',
                requiresConfirmation: false,
                safeToAutoApply: true,
              },
            ]
          : [],
    };
  },

  async applyProfileOverrides(id: string, overrides: ProfileOverrides): Promise<BootstrapState> {
    const s = getPreviewSeedState();
    s.profiles = s.profiles.map((p) => (p.id === id ? { ...p, overrides } : p));
    return { ...s };
  },

  async setWindowBackgroundStyle(style: BackgroundStyle): Promise<AppSettings> {
    const s = getPreviewSeedState();
    s.settings = { ...s.settings, backgroundStyle: style };
    return s.settings;
  },

  // ===== v0.8.0 Preview Implementations =====

  async getCoreInventory(): Promise<CoreInventorySnapshot> {
    const s = getPreviewSeedState();
    return {
      checkedAt: new Date().toISOString(),
      activeSelection: s.settings.advanced?.coreSelection ?? 'auto',
      singBoxNote:
        'sing-box (GPL-3.0-or-later) в сборку v0.8.0 не включён: все поддерживаемые протоколы покрыты встроенными Xray-core 26.11.9 (MPL-2.0) и wireproxy-awg (ISC) + Wintun 0.14.1.',
      cores: [
        {
          id: 'xray',
          kind: 'xray',
          name: 'Xray-core',
          license: 'MPL-2.0',
          version: 'Xray 26.11.9',
          availableVersion: null,
          arch: 'windows/amd64',
          path: 'resources/core/xray.exe',
          sizeBytes: 34_615_296,
          installedAt: '2026-11-25T10:00:00Z',
          sha256: 'preview_sha256_xray_verified',
          expectedSha256: 'preview_sha256_xray_verified',
          integrityOk: true,
          source: 'Встроено в установщик',
          sourceOrigin: 'XTLS/Xray-core (v26.11.9)',
          status: 'active',
          permissionsNote: 'Запускается без прав администратора в режиме Системного прокси',
          isActive: true,
          supportedProtocols: ['vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'wireguard', 'rawxray'],
          capabilities: {
            supportsTun: true,
            supportsSystemProxy: true,
            supportsDoh: true,
            supportsDot: true,
            supportsDoq: true,
            supportsMux: true,
            supportsReality: true,
            supportsXhttp: true,
            supportsHysteria2: true,
            supportsAwg: false,
          },
          history: [
            {
              version: '26.11.9',
              installedAt: '2026-11-25T10:00:00Z',
              sha256: 'preview_sha256_xray',
              path: 'resources/core/xray.exe',
              canRollback: false,
            },
          ],
        },
        {
          id: 'wireproxy_awg',
          kind: 'wireproxy_awg',
          name: 'wireproxy-awg',
          license: 'ISC',
          version: '1.0.18',
          availableVersion: null,
          arch: 'windows/amd64',
          path: 'resources/core/wireproxy-awg.exe',
          sizeBytes: 9_842_688,
          installedAt: '2026-11-25T10:00:00Z',
          sha256: 'preview_sha256_awg_verified',
          expectedSha256: 'preview_sha256_awg_verified',
          integrityOk: true,
          source: 'Встроено в установщик',
          sourceOrigin: 'amnezia-vpn / wireproxy',
          status: 'ready',
          permissionsNote: 'Работает в user-space поверх локального SOCKS5-моста Xray',
          isActive: false,
          supportedProtocols: ['amneziawg', 'wireguard'],
          capabilities: {
            supportsTun: true,
            supportsSystemProxy: true,
            supportsDoh: false,
            supportsDot: false,
            supportsDoq: false,
            supportsMux: false,
            supportsReality: false,
            supportsXhttp: false,
            supportsHysteria2: false,
            supportsAwg: true,
          },
          history: [],
        },
        {
          id: 'wintun',
          kind: 'wintun',
          name: 'Wintun Driver DLL',
          license: 'GPL-2.0 (precompiled signed DLL)',
          version: '0.14.1',
          availableVersion: null,
          arch: 'windows/amd64',
          path: 'resources/core/wintun.dll',
          sizeBytes: 424_960,
          installedAt: '2026-11-25T10:00:00Z',
          sha256: 'preview_sha256_wintun_verified',
          expectedSha256: 'preview_sha256_wintun_verified',
          integrityOk: true,
          source: 'Встроено в установщик',
          sourceOrigin: 'WireGuard / Wintun.net',
          status: 'ready',
          permissionsNote: 'Для создания системного адаптера L3 требуется запуск от администратора (UAC)',
          isActive: s.connection.mode === 'tun',
          supportedProtocols: ['vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'wireguard', 'amneziawg', 'rawxray'],
          capabilities: {
            supportsTun: true,
            supportsSystemProxy: false,
            supportsDoh: false,
            supportsDot: false,
            supportsDoq: false,
            supportsMux: false,
            supportsReality: false,
            supportsXhttp: false,
            supportsHysteria2: false,
            supportsAwg: false,
          },
          history: [],
        },
      ],
      compatibilityMatrix: [
        {
          protocol: 'vless',
          protocolLabel: 'VLESS (Reality / Vision / XHTTP / gRPC)',
          supportedCores: ['Xray-core'],
          requiredAux: 'Wintun 0.14.1 (в TUN)',
          minVersion: '26.11.9',
          notes: 'Полная поддержка XTLS-Vision, REALITY, ML-DSA-65 и DoH/DoT/DoQ.',
        },
        {
          protocol: 'amneziawg',
          protocolLabel: 'AmneziaWG (Jc/Jmin/Jmax/S1/S2/H1..H4)',
          supportedCores: ['wireproxy-awg + Xray-core'],
          requiredAux: 'wireproxy-awg.exe',
          minVersion: '1.0.18',
          notes: 'Требует wireproxy-awg; маршрутизация выполняется через Xray-core.',
        },
        {
          protocol: 'wireguard',
          protocolLabel: 'WireGuard',
          supportedCores: ['Xray-core', 'wireproxy-awg'],
          requiredAux: null,
          minVersion: '26.11.9',
          notes: 'Поддерживается переключение ядра между нативным Xray и wireproxy-awg.',
        },
      ],
    };
  },

  async verifyCoreIntegrity(): Promise<CoreDiagnostics> {
    return getPreviewSeedState().diagnostics;
  },

  async checkCoreUpdates(kind: CoreKind): Promise<CoreUpdateCheckResult> {
    return {
      coreKind: kind,
      currentVersion: kind === 'xray' ? '26.11.9' : kind === 'wireproxy_awg' ? '1.0.18' : '0.14.1',
      latestVersion: kind === 'xray' ? '26.11.9' : null,
      updateAvailable: false,
      releaseUrl: kind === 'xray' ? 'https://github.com/XTLS/Xray-core/releases' : null,
      assetName: kind === 'xray' ? 'Xray-windows-64.zip' : null,
      expectedSha256: null,
      publishedAt: new Date().toISOString(),
      blockedByActiveConnection: false,
      status: kind === 'xray' ? 'up_to_date' : 'pinned',
      message: 'Установлена актуальная версия компонента (демо-режим).',
    };
  },

  async getDnsInspectorReport(): Promise<DnsInspectorReport> {
    const s = getPreviewSeedState();
    return {
      checkedAt: new Date().toISOString(),
      configAnalysis: {
        effectiveMode: s.settings.dns.mode,
        activeServers: [s.settings.dns.primaryDns, s.settings.dns.fallbackDns ?? '8.8.8.8'],
        directServers: [s.settings.dns.directDns],
        directDomainsCount: 158,
        tunDnsHijackActive: s.connection.mode === 'tun',
        systemProxyDnsNote: 'В режиме системного прокси локальный DoH браузера может резолвить имена самостоятельно.',
        cacheEnabled: !(s.settings.dns.disableCache ?? false),
        fallbackEnabled: !(s.settings.dns.disableFallback ?? false),
        ipv6QueryStrategy: s.settings.dns.queryStrategy ?? 'UseIPv4',
        leakRiskLevel: s.connection.mode === 'tun' ? 'low' : 'medium',
        warnings: [],
      },
      liveLookup: null,
    };
  },

  async testDnsServer(server: string, _domain?: string): Promise<DnsServerTestResult> {
    return {
      server,
      protocol: server.startsWith('https://') ? 'DoH' : server.startsWith('tls://') ? 'DoT' : 'UDP/TCP 53',
      reachable: true,
      latencyMs: 22,
      resolvedIps: ['1.1.1.1'],
      error: null,
      viaVpn: getPreviewSeedState().connection.status === 'connected',
    };
  },

  async runDnsInspectorLookup(domain: string): Promise<DnsLiveLookupResult> {
    return {
      domain,
      resolverUsed: getPreviewSeedState().settings.dns.primaryDns,
      resolvedIps: ['203.0.113.10', '203.0.113.11'],
      latencyMs: 24,
      bypassedVpnWarning: getPreviewSeedState().connection.status !== 'connected',
      error: null,
    };
  },

  async getTunStatus(): Promise<TunManagerSnapshot> {
    const s = getPreviewSeedState();
    const tun = s.settings.tun ?? DEFAULT_SETTINGS.tun!;
    return {
      checkedAt: new Date().toISOString(),
      settings: tun,
      adapter: {
        adapterPresent: s.connection.mode === 'tun' && s.connection.status === 'connected',
        adapterName: tun.adapterName,
        interfaceIndex: s.connection.status === 'connected' ? 42 : null,
        status: s.connection.mode === 'tun' && s.connection.status === 'connected' ? 'Up' : 'Disconnected',
        mtu: tun.mtu,
        ipv4Addresses: [tun.ipv4Address],
        ipv6Addresses: tun.enableIpv6 ? [tun.ipv6Address] : [],
        dnsServers: [s.settings.dns.primaryDns],
        wintunVersion: '0.14.1',
        wintunPresent: true,
        wintunIntegrityOk: true,
        driverStatus: 'Готов к запуску (превью)',
        isElevated: false,
      },
      conflicts: [],
    };
  },

  async detectTunConflicts(): Promise<VirtualAdapterConflict[]> {
    return [];
  },

  async getConnectionInspector(): Promise<ConnectionInspectorSnapshot> {
    const s = getPreviewSeedState();
    const isConn = s.connection.status === 'connected';
    const srv = s.profiles.find((p) => p.id === (s.connection.activeServerId ?? s.settings.activeServerId));
    return {
      status: s.connection.status,
      stages: {
        coreProcessRunning: isConn,
        auxProcessRunning: null,
        localProxyListening: isConn && s.connection.mode === 'system_proxy',
        tunAdapterUp: isConn && s.connection.mode === 'tun',
        tunnelEstablished: isConn,
        internetVerified: isConn,
      },
      mode: s.connection.mode,
      activeServerId: srv?.id ?? null,
      activeServerName: srv?.name ?? null,
      protocol: srv?.protocol ?? null,
      activeCoreName: 'Xray-core',
      activeCoreVersion: '26.11.9',
      activeAdapterName: s.connection.mode === 'tun' ? (s.settings.tun?.adapterName ?? 'aura_tun') : null,
      routingProfile: s.settings.routing.profile,
      dnsMode: s.settings.dns.mode,
      tcpLatencyMs: srv?.latencyMs ?? null,
      httpRttMs: isConn ? 64 : null,
      uptimeSecs: isConn ? 325 : 0,
      reconnectCount: 0,
      killSwitch: await previewApi.getKillSwitchStatus(),
      throughput: {
        currentRxBps: s.traffic.rxBytesPerSec,
        currentTxBps: s.traffic.txBytesPerSec,
        avgRxBps: Math.round(s.traffic.rxBytesPerSec * 0.72),
        avgTxBps: Math.round(s.traffic.txBytesPerSec * 0.75),
        peakRxBps: Math.round(s.traffic.rxBytesPerSec * 1.35),
        peakTxBps: Math.round(s.traffic.txBytesPerSec * 1.4),
        totalRxBytes: s.traffic.totalRxBytes,
        totalTxBytes: s.traffic.totalTxBytes,
        sampleCount: 120,
      },
      timeline: [
        {
          id: 1,
          timestamp: new Date().toISOString(),
          stage: 'core',
          level: 'info',
          message: isConn ? 'Xray-core запущен и слушает локальные порты' : 'Ожидание подключения',
          latencyMs: isConn ? 38 : null,
        },
      ],
    };
  },

  async getConnectionTimeline(): Promise<ConnectionTimelineEvent[]> {
    return (await previewApi.getConnectionInspector()).timeline;
  },

  async clearConnectionTimeline(): Promise<ConnectionTimelineEvent[]> {
    return [];
  },

  async getConfigStudioView(id: string, revealSecrets: boolean): Promise<ConfigStudioView> {
    const s = getPreviewSeedState();
    const srv = s.profiles.find((p) => p.id === id) ?? s.profiles[0];
    const baseOutbound = {
      tag: 'proxy',
      protocol: srv.protocol,
      settings: {
        address: srv.address,
        port: srv.port,
        secret: revealSecrets ? 'demo-secret-token' : '••••••••',
      },
    };
    const effectiveMtu = srv.overrides?.mtu ?? s.settings.advanced?.manualMtu ?? 1420;
    return {
      profileId: srv.id,
      format: 'xray_json',
      effectiveCore: srv.protocol === 'amneziawg' ? 'wireproxy-awg + Xray-core' : 'Xray-core',
      effectiveMtu,
      mtuSource: srv.overrides?.mtu ? 'Переопределено в профиле' : 'Глобальный профиль',
      effectiveDns: srv.overrides?.customDns ?? s.settings.dns.primaryDns,
      dnsSource: srv.overrides?.customDns ? 'Индивидуальный DNS профиля' : 'Глобальный DNS',
      effectiveMode: srv.overrides?.preferredMode ?? s.settings.connectionMode,
      modeSource: srv.overrides?.preferredMode ? 'Переопределено в профиле' : 'Глобальный режим',
      layer1Imported: baseOutbound,
      layer2WithOverrides: {
        ...baseOutbound,
        streamSettings: { sockopt: { tcpNoDelay: true, mtu: effectiveMtu } },
      },
      layer3InjectedSummary: [
        `Режим туннеля: ${srv.overrides?.preferredMode ?? s.settings.connectionMode}`,
        `DNS режим: ${s.settings.dns.mode}`,
        `Маршрутизация: ${s.settings.routing.profile}`,
      ],
      layer4FinalSanitized: {
        log: { loglevel: s.settings.logLevel },
        outbounds: [baseOutbound, { tag: 'direct', protocol: 'freedom' }],
      },
      awgConfigPreview: null,
      strippedGuardrails: [],
      diffs: [
        {
          path: 'streamSettings.sockopt.tcpNoDelay',
          layer: 'Layer 3 (Client)',
          changeType: 'added',
          before: null,
          after: 'true',
          reason: 'Активировано в Расширенных настройках VPN',
        },
      ],
      validationOk: true,
      validationError: null,
      revisions: [],
    };
  },

  async validateCustomProfileConfig(_id: string, rawJson: string): Promise<ConfigValidationResult> {
    try {
      const parsed = JSON.parse(rawJson) as Record<string, unknown>;
      const validProto = typeof parsed.protocol === 'string' || Array.isArray(parsed.outbounds);
      return {
        ok: validProto,
        coreTested: false,
        errors: validProto ? [] : ['Отсутствует поле `protocol` или массив `outbounds`'],
        warnings: ['В режиме превью проверка синтаксиса выполняется без бинарного xray -test.'],
        strippedFields: [],
      };
    } catch (e) {
      return {
        ok: false,
        coreTested: false,
        errors: [e instanceof Error ? e.message : 'Некорректный JSON'],
        warnings: [],
        strippedFields: [],
      };
    }
  },

  async saveProfileConfigEdit(
    id: string,
    _rawJson: string,
    _note?: string | null,
  ): Promise<BootstrapState> {
    const s = getPreviewSeedState();
    s.profiles = s.profiles.map((p) =>
      p.id === id ? { ...p, configRevision: (p.configRevision ?? 0) + 1 } : p,
    );
    return { ...s };
  },

  async rollbackProfileConfig(_id: string, _revisionId: string): Promise<BootstrapState> {
    return { ...getPreviewSeedState() };
  },

  async duplicateServerProfile(id: string, customName?: string | null): Promise<BootstrapState> {
    const s = getPreviewSeedState();
    const src = s.profiles.find((p) => p.id === id);
    if (src) {
      const name = customName?.trim() || `${src.name} (копия)`;
      s.profiles = [
        ...s.profiles,
        {
          ...src,
          id: `srv-copy-${Date.now()}`,
          name,
          customName: name,
          subscriptionId: null,
          favorite: false,
          createdAt: new Date().toISOString(),
        },
      ];
    }
    return { ...s };
  },

  async runNetworkDoctor(includeExternalProbes: boolean): Promise<NetworkDoctorReport> {
    return {
      checkedAt: new Date().toISOString(),
      overallStatus: 'pass',
      passCount: includeExternalProbes ? 10 : 6,
      warnCount: 0,
      failCount: 0,
      checks: [
        {
          id: 'core_sha',
          category: 'Целостность',
          title: 'Xray-core + wireproxy-awg + Wintun SHA-256',
          severity: 'pass',
          summary: 'Все 3 бинарных компонента совпадают с манифестом',
          detail: 'Проверка SHA-256 пройдена.',
          recommendedAction: null,
          durationMs: 12,
        },
        {
          id: 'ports_free',
          category: 'Локальная сеть',
          title: 'Локальные порты HTTP / SOCKS5 и excludedportrange',
          severity: 'pass',
          summary: 'Порты 10809 / 10808 свободны',
          detail: 'Конфликтов с Hyper-V / WSL диапазонами нет.',
          recommendedAction: null,
          durationMs: 19,
        },
        {
          id: 'dns_config',
          category: 'DNS',
          title: 'Настройка резолвера и риск утечек',
          severity: 'pass',
          summary: 'Режим Hybrid (1.1.1.1 / 77.88.8.8)',
          detail: 'Fallback настроен, кэш активен.',
          recommendedAction: null,
          durationMs: 4,
        },
        {
          id: 'ext_probe',
          category: 'Сетевые проверки',
          title: 'Внешняя проверка туннеля и DNS',
          severity: includeExternalProbes ? 'pass' : 'skipped',
          summary: includeExternalProbes ? 'Доступ подтверждён (64 мс)' : 'Пропущено (только по запросу)',
          detail: 'Внешние запросы выполняются только по явному действию пользователя.',
          recommendedAction: null,
          durationMs: includeExternalProbes ? 64 : 0,
        },
      ],
    };
  },

  async getPrivacyInventory(): Promise<PrivacyInventory> {
    const s = getPreviewSeedState();
    return {
      configDir: '%APPDATA%\\app.auravpn.desktop',
      dpapiEncryptedFiles: ['profiles.json', 'subscriptions.json', 'history.json', 'ip-monitor.json'],
      plaintextFiles: ['settings.json', 'server-quality.json', 'window-state.json'],
      historyEntriesCount: getPreviewHistory().length,
      savedOriginalIpPresent: Boolean(s.ipMonitor?.originalIp),
      savedVpnIpPresent: Boolean(s.ipMonitor?.vpnIp),
      logsCount: 1,
      subBackupsCount: 0,
      syncHistoryCount: s.subscriptions.reduce((acc, sub) => acc + (sub.syncHistory?.length ?? 0), 0),
      sendHwid: s.settings.sendHwid,
      hwidMasked: 'aura••••7d10',
      externalNetworkFeatures: [
        {
          id: 'ip_monitor',
          title: 'Монитор внешнего IP (Мой IP 2.0)',
          enabled: (s.settings.autoCheckIpIntervalSecs ?? 0) > 0,
          trigger: 'По умолчанию вручную (opt-in)',
          destination: `${s.settings.preferredIpProvider ?? 'auto'}`,
          dataSent: 'Стандартный HTTPS-запрос',
        },
      ],
    };
  },

  async rotateDeviceHwid(): Promise<BootstrapState> {
    const s = getPreviewSeedState();
    s.settings = { ...s.settings, deviceHwid: `aura-hwid-${Date.now().toString(16)}` };
    return { ...s };
  },

  async purgePrivacyData(scope: PrivacyPurgeScope): Promise<PrivacyPurgeReport> {
    let removed = 0;
    const s = getPreviewSeedState();
    if (scope.clearHistory) {
      previewHistory = [];
      removed += 1;
    }
    if (scope.clearOriginalIp && s.ipMonitor) {
      s.ipMonitor = { ...s.ipMonitor, originalIp: null };
      removed += 1;
    }
    if (scope.clearVpnIp && s.ipMonitor) {
      s.ipMonitor = { ...s.ipMonitor, vpnIp: null };
      removed += 1;
    }
    if (scope.clearLogs || scope.clearServerQuality || scope.clearSubBackups || scope.clearSyncHistory || scope.clearProfileEditHistory) {
      removed += 1;
    }
    return { itemsRemoved: removed, summary: `Очищено категорий: ${removed}` };
  },

  async setIpProvider(provider: IpProviderId): Promise<IpMonitorState> {
    const s = getPreviewSeedState();
    s.settings = { ...s.settings, preferredIpProvider: provider };
    s.ipMonitor = { ...(s.ipMonitor ?? { maskIp: true }), provider };
    return s.ipMonitor;
  },

  async clearOriginalIp(): Promise<IpMonitorState> {
    const s = getPreviewSeedState();
    s.ipMonitor = { ...(s.ipMonitor ?? { maskIp: true }), originalIp: null, ipChanged: null };
    return s.ipMonitor;
  },

  async clearIpMonitorCache(): Promise<IpMonitorState> {
    const s = getPreviewSeedState();
    s.ipMonitor = { ...(s.ipMonitor ?? { maskIp: true }), vpnIp: null, ipChanged: null };
    return s.ipMonitor;
  },

  async getSubscriptionSyncHistory(id: string): Promise<SubscriptionSyncEntry[]> {
    const sub = getPreviewSeedState().subscriptions.find((x) => x.id === id);
    return sub?.syncHistory ?? [];
  },

  async runServerSpeedTest(id: string): Promise<SpeedTestResult> {
    return {
      ok: true,
      serverId: id,
      bytesDownloaded: 1_500_000,
      durationMs: 420,
      mbps: 28.57,
      viaVpn: getPreviewSeedState().connection.status === 'connected',
      note: 'Ручной одноразовый замер ограничен лимитом 1.5 МБ для защиты квоты (превью).',
    };
  },
};
