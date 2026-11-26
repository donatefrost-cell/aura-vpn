import { DEFAULT_SETTINGS, normalizeDnsMode } from './defaultSettings';
import type { AppSettings } from '../types/vpn';

export type SettingsGroupId = 'general' | 'network' | 'security' | 'system';
export type SettingLevel = 'basic' | 'advanced' | 'expert';

export type SettingsCategoryId =
  | 'general'
  | 'interface'
  | 'behavior-profiles'
  | 'vpn-core'
  | 'advanced-vpn'
  | 'dns-manager'
  | 'tun-adapters'
  | 'routing-shortcut'
  | 'kill-switch'
  | 'my-ip'
  | 'privacy-telemetry'
  | 'network-doctor'
  | 'subscriptions-defaults'
  | 'updates'
  | 'backup'
  | 'about';

export interface SettingsGroupMeta {
  id: SettingsGroupId;
  title: string;
  categories: Array<{
    id: SettingsCategoryId;
    title: string;
    subtitle: string;
    minLevel?: SettingLevel;
  }>;
}

export interface SettingItemMeta {
  id: string;
  category: SettingsCategoryId;
  level: SettingLevel;
  title: string;
  description: string;
  keywords: string;
  defaultLabel: string;
  recommendedLabel?: string;
  rangeLabel?: string;
  impact: string;
  compatibility: string;
  requiresReconnect: boolean;
  isModified: (s: AppSettings) => boolean;
  reset: (s: AppSettings) => AppSettings;
}

export const SETTINGS_GROUPS: SettingsGroupMeta[] = [
  {
    id: 'general',
    title: 'Основное и интерфейс',
    categories: [
      { id: 'general', title: 'Общие и Windows', subtitle: 'Автозапуск, трей и сворачивание' },
      { id: 'interface', title: 'Интерфейс и Material You', subtitle: 'Тема, акцент, фон, масштаб и компактность' },
      { id: 'behavior-profiles', title: 'Профили поведения', subtitle: 'Повседневный, Рабочий, Игровой, Свой' },
    ],
  },
  {
    id: 'network',
    title: 'VPN и сеть',
    categories: [
      { id: 'vpn-core', title: 'Ядра и совместимость', subtitle: 'Xray-core, wireproxy-awg, Wintun и SHA-256' },
      { id: 'advanced-vpn', title: 'Расширенный VPN', subtitle: 'Таймауты, Sockopt, Mux, MTU и Health Probe', minLevel: 'advanced' },
      { id: 'dns-manager', title: 'DNS-менеджер', subtitle: 'Режимы DNS, DoH/DoT/DoQ и живая проверка' },
      { id: 'tun-adapters', title: 'TUN и адаптеры', subtitle: 'Wintun 0.14.1, MTU, подсети и конфликты' },
      { id: 'routing-shortcut', title: 'Маршрутизация', subtitle: 'Быстрый переход к правилам, Split App и РФ-паку' },
    ],
  },
  {
    id: 'security',
    title: 'Безопасность и приватность',
    categories: [
      { id: 'kill-switch', title: 'Kill Switch 2.0', subtitle: 'Блокировка утечек при обрыве и Always-On' },
      { id: 'my-ip', title: 'Мой IP 2.0', subtitle: 'Провайдеры определения IP, IPv6 и маскировка' },
      { id: 'privacy-telemetry', title: 'Приватность и очистка', subtitle: 'DPAPI-хранилище, HWID и выборочная очистка' },
      { id: 'network-doctor', title: 'Сетевой доктор', subtitle: '12 комплексных проверок и экспорт отчёта' },
    ],
  },
  {
    id: 'system',
    title: 'Подписки и система',
    categories: [
      { id: 'subscriptions-defaults', title: 'Подписки и импорт', subtitle: 'Дубликаты, Smart Config и локальные правки' },
      { id: 'updates', title: 'Обновления и логи', subtitle: 'Канал релизов и уровень журналирования ядра' },
      { id: 'backup', title: 'Резервное копирование', subtitle: 'JSON-экспорт и восстановление параметров' },
      { id: 'about', title: 'О программе', subtitle: 'Версия, лицензии, компоненты и аудит' },
    ],
  },
];

export const SETTING_LEVEL_ORDER: Record<SettingLevel, number> = {
  basic: 0,
  advanced: 1,
  expert: 2,
};

export function isSettingVisibleForLevel(itemLevel: SettingLevel, activeLevel: SettingLevel): boolean {
  return SETTING_LEVEL_ORDER[itemLevel] <= SETTING_LEVEL_ORDER[activeLevel];
}

export function resolveCategoryFromLegacySection(raw?: string | null): SettingsCategoryId {
  if (!raw) return 'general';
  const low = raw.trim().toLowerCase();
  const known: SettingsCategoryId[] = [
    'general',
    'interface',
    'behavior-profiles',
    'vpn-core',
    'advanced-vpn',
    'dns-manager',
    'tun-adapters',
    'routing-shortcut',
    'kill-switch',
    'my-ip',
    'privacy-telemetry',
    'network-doctor',
    'subscriptions-defaults',
    'updates',
    'backup',
    'about',
  ];
  if (known.includes(low as SettingsCategoryId)) return low as SettingsCategoryId;
  switch (low) {
    case 'connection':
      return 'behavior-profiles';
    case 'security':
      return 'kill-switch';
    case 'appearance':
      return 'interface';
    case 'windows':
      return 'general';
    case 'diagnostics':
      return 'network-doctor';
    case 'history':
      return 'privacy-telemetry';
    case 'advanced':
      return 'advanced-vpn';
    default:
      return 'general';
  }
}

const adv = (s: AppSettings) => s.advanced ?? DEFAULT_SETTINGS.advanced!;
const tun = (s: AppSettings) => s.tun ?? DEFAULT_SETTINGS.tun!;

export const SETTINGS_REGISTRY: SettingItemMeta[] = [
  // === GENERAL ===
  {
    id: 'autostart',
    category: 'general',
    level: 'basic',
    title: 'Запуск вместе с Windows',
    description: 'Добавляет или убирает ярлык AURA VPN в стандартной автозагрузке Windows',
    keywords: 'autostart windows startup автозапуск старт система',
    defaultLabel: 'Выкл.',
    impact: 'Влияет только на регистрацию запуска при входе в систему',
    compatibility: 'Windows 10 / 11 (без прав администратора через реестр пользователя)',
    requiresReconnect: false,
    isModified: (s) => s.autostart !== DEFAULT_SETTINGS.autostart,
    reset: (s) => ({ ...s, autostart: DEFAULT_SETTINGS.autostart }),
  },
  {
    id: 'start-minimized',
    category: 'general',
    level: 'basic',
    title: 'Сворачивать в трей при запуске',
    description: 'Скрывает главное окно после запуска, оставляя быстрый доступ через значок в трее',
    keywords: 'tray minimize startup трей сворачивать фоновый запуск',
    defaultLabel: 'Выкл.',
    impact: 'Удобно совместно с автоподключением и автозапуском',
    compatibility: 'Все режимы',
    requiresReconnect: false,
    isModified: (s) =>
      s.startMinimized !== DEFAULT_SETTINGS.startMinimized ||
      s.minimizeToTray !== DEFAULT_SETTINGS.minimizeToTray,
    reset: (s) => ({
      ...s,
      startMinimized: DEFAULT_SETTINGS.startMinimized,
      minimizeToTray: DEFAULT_SETTINGS.minimizeToTray,
    }),
  },
  {
    id: 'auto-connect-launch',
    category: 'general',
    level: 'basic',
    title: 'Автоподключение при старте и пробуждении',
    description: 'Автоматически поднимает VPN при запуске и восстанавливает туннель после сна ПК',
    keywords: 'autoconnect wake reconnect сон автоподключение переподключение',
    defaultLabel: 'При запуске: Выкл., Пробуждение: Вкл.',
    impact: 'Ускоряет восстановление связи при смене Wi-Fi или выходе из сна',
    compatibility: 'Откладывается, если Kill Switch ожидает UAC',
    requiresReconnect: false,
    isModified: (s) =>
      s.autoConnectOnLaunch !== DEFAULT_SETTINGS.autoConnectOnLaunch ||
      s.autoReconnect !== DEFAULT_SETTINGS.autoReconnect ||
      s.reconnectOnWake !== DEFAULT_SETTINGS.reconnectOnWake,
    reset: (s) => ({
      ...s,
      autoConnectOnLaunch: DEFAULT_SETTINGS.autoConnectOnLaunch,
      autoReconnect: DEFAULT_SETTINGS.autoReconnect,
      reconnectOnWake: DEFAULT_SETTINGS.reconnectOnWake,
    }),
  },
  {
    id: 'notifications',
    category: 'general',
    level: 'basic',
    title: 'Системные уведомления',
    description: 'Показывать уведомления о подключении, сбоях, обновлениях подписок и Kill Switch',
    keywords: 'notifications toast alerts уведомления события',
    defaultLabel: 'Вкл.',
    impact: 'Уведомления о критических обрывах в трее',
    compatibility: 'Все режимы',
    requiresReconnect: false,
    isModified: (s) => s.systemNotifications !== DEFAULT_SETTINGS.systemNotifications,
    reset: (s) => ({ ...s, systemNotifications: DEFAULT_SETTINGS.systemNotifications }),
  },

  // === INTERFACE ===
  {
    id: 'theme-mode',
    category: 'interface',
    level: 'basic',
    title: 'Тема и акцент Material You',
    description: 'Тёмная, светлая или системная тема, динамический акцент и фон окна',
    keywords: 'theme dark light accent mica aura background цвет тема акцент фон',
    defaultLabel: 'Тёмная • Индиго • Фон Aura',
    recommendedLabel: 'Тёмная / Aura',
    impact: 'Мгновенно применяет цветовую схему и фон окна без разрыва VPN',
    compatibility: 'Эффект Mica зависит от поддержки DWM в Windows 11',
    requiresReconnect: false,
    isModified: (s) =>
      s.theme !== DEFAULT_SETTINGS.theme ||
      s.accentPreset !== DEFAULT_SETTINGS.accentPreset ||
      s.dynamicColor !== DEFAULT_SETTINGS.dynamicColor ||
      (s.backgroundStyle ?? 'aura') !== DEFAULT_SETTINGS.backgroundStyle,
    reset: (s) => ({
      ...s,
      theme: DEFAULT_SETTINGS.theme,
      accentPreset: DEFAULT_SETTINGS.accentPreset,
      customAccentHex: DEFAULT_SETTINGS.customAccentHex,
      dynamicColor: DEFAULT_SETTINGS.dynamicColor,
      backgroundStyle: DEFAULT_SETTINGS.backgroundStyle,
    }),
  },
  {
    id: 'ui-scale',
    category: 'interface',
    level: 'basic',
    title: 'Масштаб, компактность и анимации',
    description: 'Масштабирование 90%–120%, плотный список карточек и плавные переходы',
    keywords: 'scale compact animations масштаб плотность анимация шрифт',
    defaultLabel: '100% • Анимации Вкл.',
    rangeLabel: '90% – 120%',
    impact: 'Подстраивает плотность интерфейса под 1366×768 или 4K мониторы',
    compatibility: 'Без влияния на сеть',
    requiresReconnect: false,
    isModified: (s) =>
      s.uiScale !== DEFAULT_SETTINGS.uiScale ||
      s.compactMode !== DEFAULT_SETTINGS.compactMode ||
      s.animationsEnabled !== DEFAULT_SETTINGS.animationsEnabled,
    reset: (s) => ({
      ...s,
      uiScale: DEFAULT_SETTINGS.uiScale,
      compactMode: DEFAULT_SETTINGS.compactMode,
      animationsEnabled: DEFAULT_SETTINGS.animationsEnabled,
    }),
  },

  // === BEHAVIOR & CONNECTION MODE ===
  {
    id: 'behavior-profiles',
    category: 'behavior-profiles',
    level: 'basic',
    title: 'Профили поведения и режим перехвата',
    description: 'Готовые сценарии перехвата трафика, маршрутизации и Kill Switch',
    keywords: 'profile mode system proxy tun перехват режим профиль повседневный игровой',
    defaultLabel: 'Системный прокси',
    impact: 'Переключение Системный прокси ↔ TUN меняет способ перехвата всего трафика ОС',
    compatibility: 'TUN требует прав администратора (UAC) и Wintun 0.14.1',
    requiresReconnect: true,
    isModified: (s) => s.connectionMode !== DEFAULT_SETTINGS.connectionMode,
    reset: (s) => ({ ...s, connectionMode: DEFAULT_SETTINGS.connectionMode }),
  },

  // === VPN CORE ===
  {
    id: 'core-selection',
    category: 'vpn-core',
    level: 'basic',
    title: 'Выбор ядра маршрутизации',
    description: 'Автоматический или явный выбор движка там, где протокол поддерживает несколько ядер',
    keywords: 'core xray wireproxy wintun singbox sha256 ядро движок целостность',
    defaultLabel: 'Авто (рекомендуется)',
    recommendedLabel: 'Авто',
    impact: 'Определяет исполнительный бинарник для туннеля и запрещает несовместимые пары',
    compatibility: 'VLESS/Trojan/VMess/Hy2 работают только в Xray-core; AmneziaWG требует wireproxy-awg',
    requiresReconnect: true,
    isModified: (s) => adv(s).coreSelection !== DEFAULT_SETTINGS.advanced!.coreSelection,
    reset: (s) => ({
      ...s,
      advanced: { ...adv(s), coreSelection: DEFAULT_SETTINGS.advanced!.coreSelection },
    }),
  },

  // === ADVANCED VPN ===
  {
    id: 'adv-ports',
    category: 'advanced-vpn',
    level: 'advanced',
    title: 'Локальные порты HTTP и SOCKS5',
    description: 'Внутренние порты 127.0.0.1 для системного прокси и локальных приложений',
    keywords: 'ports http socks5 10808 10809 порты прокси',
    defaultLabel: 'HTTP 10809 / SOCKS5 10808',
    rangeLabel: '1024 – 65535',
    impact: 'Помогает избежать конфликтов с Hyper-V/WSL2 или другим локальным софтом',
    compatibility: 'Порты не должны совпадать или попадать в excludedportrange',
    requiresReconnect: true,
    isModified: (s) =>
      s.httpPort !== DEFAULT_SETTINGS.httpPort || s.socksPort !== DEFAULT_SETTINGS.socksPort,
    reset: (s) => ({
      ...s,
      httpPort: DEFAULT_SETTINGS.httpPort,
      socksPort: DEFAULT_SETTINGS.socksPort,
    }),
  },
  {
    id: 'adv-timeouts-health',
    category: 'advanced-vpn',
    level: 'advanced',
    title: 'Таймауты и проверка стабильности (Health Probe)',
    description: 'Интервал проверки туннеля, порог отказов и задержка экспоненциального реконнекта',
    keywords: 'timeout health probe reconnect backoff таймаут здоровье реконнект',
    defaultLabel: 'Старт 6с • Проба 10с • Интервал 30с',
    recommendedLabel: 'Интервал 30с, порог 2',
    rangeLabel: 'Старт 3–20с, интервал 10–300с',
    impact: 'Ускоряет распознавание «зависшего» туннеля или уменьшает фоновый опрос',
    compatibility: 'При обрыве запускает автопереподключение или Kill Switch',
    requiresReconnect: true,
    isModified: (s) => {
      const a = adv(s);
      const d = DEFAULT_SETTINGS.advanced!;
      return (
        a.coreStartTimeoutSecs !== d.coreStartTimeoutSecs ||
        a.probeTimeoutSecs !== d.probeTimeoutSecs ||
        a.healthCheckEnabled !== d.healthCheckEnabled ||
        a.healthCheckIntervalSecs !== d.healthCheckIntervalSecs ||
        a.healthFailureThreshold !== d.healthFailureThreshold ||
        a.reconnectBaseDelaySecs !== d.reconnectBaseDelaySecs ||
        a.reconnectMaxDelaySecs !== d.reconnectMaxDelaySecs ||
        s.connectTimeoutSecs !== DEFAULT_SETTINGS.connectTimeoutSecs
      );
    },
    reset: (s) => {
      const d = DEFAULT_SETTINGS.advanced!;
      return {
        ...s,
        connectTimeoutSecs: DEFAULT_SETTINGS.connectTimeoutSecs,
        advanced: {
          ...adv(s),
          coreStartTimeoutSecs: d.coreStartTimeoutSecs,
          probeTimeoutSecs: d.probeTimeoutSecs,
          healthCheckEnabled: d.healthCheckEnabled,
          healthCheckIntervalSecs: d.healthCheckIntervalSecs,
          healthFailureThreshold: d.healthFailureThreshold,
          reconnectBaseDelaySecs: d.reconnectBaseDelaySecs,
          reconnectMaxDelaySecs: d.reconnectMaxDelaySecs,
        },
      };
    },
  },
  {
    id: 'adv-ping-concurrency',
    category: 'advanced-vpn',
    level: 'advanced',
    title: 'Параллельность пинга подписок',
    description: 'Максимум одновременных TCP-проверок при «Пинговать все»',
    keywords: 'ping parallel concurrency пинг потоки нагрузка',
    defaultLabel: '12 потоков',
    rangeLabel: '1 – 32',
    impact: 'Меньше значение снижает риск временной блокировки провайдером при больших списках',
    compatibility: 'Без влияния на активный туннель',
    requiresReconnect: false,
    isModified: (s) => adv(s).maxParallelPings !== DEFAULT_SETTINGS.advanced!.maxParallelPings,
    reset: (s) => ({
      ...s,
      advanced: { ...adv(s), maxParallelPings: DEFAULT_SETTINGS.advanced!.maxParallelPings },
    }),
  },
  {
    id: 'adv-sockopt',
    category: 'advanced-vpn',
    level: 'expert',
    title: 'Сокеты и стратегия домена (Sockopt)',
    description: 'TCP Keepalive, TCP_NODELAY, TCP Fast Open и стратегия резолвинга dialer',
    keywords: 'sockopt keepalive tfo tcpnodelay domainStrategy сокеты транспорт',
    defaultLabel: 'NoDelay Вкл. • Keepalive 0с • AsIs',
    recommendedLabel: 'NoDelay Вкл., TFO Выкл.',
    rangeLabel: 'Keepalive 0–120с',
    impact: 'Снижает накладные задержки или удерживает NAT-сессии через мобильную связь',
    compatibility: 'Применяется только к Xray TCP/WS/gRPC/SplitHTTP outbound',
    requiresReconnect: true,
    isModified: (s) => {
      const a = adv(s);
      const d = DEFAULT_SETTINGS.advanced!;
      return (
        a.tcpKeepaliveIntervalSecs !== d.tcpKeepaliveIntervalSecs ||
        a.tcpFastOpen !== d.tcpFastOpen ||
        a.tcpNoDelay !== d.tcpNoDelay ||
        a.dialerDomainStrategy !== d.dialerDomainStrategy
      );
    },
    reset: (s) => {
      const d = DEFAULT_SETTINGS.advanced!;
      return {
        ...s,
        advanced: {
          ...adv(s),
          tcpKeepaliveIntervalSecs: d.tcpKeepaliveIntervalSecs,
          tcpFastOpen: d.tcpFastOpen,
          tcpNoDelay: d.tcpNoDelay,
          dialerDomainStrategy: d.dialerDomainStrategy,
        },
      };
    },
  },
  {
    id: 'adv-mux',
    category: 'advanced-vpn',
    level: 'expert',
    title: 'Мультиплексирование (Mux / XUDP)',
    description: 'Объединяет короткие TCP-запросы в один поток (автоматически отключается для VLESS+Vision)',
    keywords: 'mux xudp concurrency vision мультиплексирование',
    defaultLabel: 'Выкл. (Concurrency 8)',
    rangeLabel: '1 – 16 потоков',
    impact: 'Может ускорять мелкие запросы, но несовместимо с XTLS-Vision и gRPC',
    compatibility: 'Автозащита запрещает Mux на VLESS+Vision, gRPC, XHTTP, Hy2, WireGuard',
    requiresReconnect: true,
    isModified: (s) => {
      const a = adv(s);
      const d = DEFAULT_SETTINGS.advanced!;
      return (
        a.muxEnabled !== d.muxEnabled ||
        a.muxConcurrency !== d.muxConcurrency ||
        a.muxXudpConcurrency !== d.muxXudpConcurrency
      );
    },
    reset: (s) => {
      const d = DEFAULT_SETTINGS.advanced!;
      return {
        ...s,
        advanced: {
          ...adv(s),
          muxEnabled: d.muxEnabled,
          muxConcurrency: d.muxConcurrency,
          muxXudpConcurrency: d.muxXudpConcurrency,
        },
      };
    },
  },
  {
    id: 'adv-mtu-stats',
    category: 'advanced-vpn',
    level: 'expert',
    title: 'Глобальный MTU и режим Stats API',
    description: 'Режим подбора MTU и выбор эфемерного или фиксированного локального gRPC порта статистики',
    keywords: 'mtu stats api grpc port фрагментация статистика',
    defaultLabel: 'MTU Авто • Stats API Эфемерный',
    rangeLabel: 'MTU 1280 – 1500',
    impact: 'Определяет фрагментацию пакетов TUN/WG и источник метрик трафика',
    compatibility: 'Индивидуальный MTU профиля имеет более высокий приоритет',
    requiresReconnect: true,
    isModified: (s) => {
      const a = adv(s);
      const d = DEFAULT_SETTINGS.advanced!;
      return (
        a.mtuMode !== d.mtuMode ||
        (a.manualMtu ?? null) !== (d.manualMtu ?? null) ||
        a.statsApiMode !== d.statsApiMode
      );
    },
    reset: (s) => {
      const d = DEFAULT_SETTINGS.advanced!;
      return {
        ...s,
        advanced: {
          ...adv(s),
          mtuMode: d.mtuMode,
          manualMtu: d.manualMtu,
          statsApiMode: d.statsApiMode,
          statsApiPort: d.statsApiPort,
        },
      };
    },
  },

  // === DNS MANAGER ===
  {
    id: 'dns-config',
    category: 'dns-manager',
    level: 'basic',
    title: 'Режим DNS, основной и прямой серверы',
    description: 'Выбор стратегии резолвинга (Hybrid / VPN / Direct / Из конфига / Системный) и пресеты DoH/DoT',
    keywords: 'dns doh dot doq cloudflare quad9 google yandex резолвер утечка',
    defaultLabel: 'Hybrid • 1.1.1.1 / 77.88.8.8',
    recommendedLabel: 'Hybrid или VPN + DoH',
    impact: 'Устраняет подмену DNS провайдером и ускоряет локальные домены в РФ',
    compatibility: 'Перехват DNS полностью надёжен в режиме TUN',
    requiresReconnect: true,
    isModified: (s) =>
      normalizeDnsMode(s.dns.mode) !== DEFAULT_SETTINGS.dns.mode ||
      s.dns.primaryDns !== DEFAULT_SETTINGS.dns.primaryDns ||
      s.dns.directDns !== DEFAULT_SETTINGS.dns.directDns ||
      (s.dns.fallbackDns ?? DEFAULT_SETTINGS.dns.fallbackDns) !== DEFAULT_SETTINGS.dns.fallbackDns ||
      Boolean(s.dns.disableCache) !== Boolean(DEFAULT_SETTINGS.dns.disableCache) ||
      Boolean(s.dns.disableFallback) !== Boolean(DEFAULT_SETTINGS.dns.disableFallback),
    reset: (s) => ({ ...s, dns: { ...DEFAULT_SETTINGS.dns } }),
  },

  // === TUN & ADAPTERS ===
  {
    id: 'tun-config',
    category: 'tun-adapters',
    level: 'advanced',
    title: 'Параметры адаптера Wintun (TUN)',
    description: 'Имя интерфейса, подсети IPv4/IPv6, MTU, strictRoute, autoRoute и IPv6 sinkhole',
    keywords: 'tun wintun adapter mtu strict route ipv4 ipv6 конфликт vpn адаптер',
    defaultLabel: 'aura_tun • MTU 1500 • strictRoute Вкл.',
    rangeLabel: 'MTU 1280 – 1500',
    impact: 'Перенаправляет весь системный трафик и UDP-игры в зашифрованный туннель',
    compatibility: 'Требует прав администратора Windows (UAC) и отсутствия конфликта других VPN',
    requiresReconnect: true,
    isModified: (s) => {
      const t = tun(s);
      const d = DEFAULT_SETTINGS.tun!;
      return (
        t.adapterName !== d.adapterName ||
        t.mtu !== d.mtu ||
        t.strictRoute !== d.strictRoute ||
        t.bypassLan !== d.bypassLan ||
        t.autoRoute !== d.autoRoute ||
        t.enableIpv6 !== d.enableIpv6 ||
        s.ipv6Enabled !== DEFAULT_SETTINGS.ipv6Enabled
      );
    },
    reset: (s) => ({
      ...s,
      ipv6Enabled: DEFAULT_SETTINGS.ipv6Enabled,
      tun: { ...DEFAULT_SETTINGS.tun! },
    }),
  },

  // === KILL SWITCH ===
  {
    id: 'kill-switch',
    category: 'kill-switch',
    level: 'basic',
    title: 'Kill Switch 2.0 (защита от утечек)',
    description: 'Блокировка трафика при обрыве, режим Always-On, разрешение LAN и защита от утечек IPv6',
    keywords: 'kill switch wfp firewall netsh lan ipv6 утечка блокировка',
    defaultLabel: 'Выкл. • LAN Вкл. • Блок IPv6 Вкл.',
    recommendedLabel: 'On-Drop (или Always-On с UAC)',
    rangeLabel: 'Попыток: 0 – 10',
    impact: 'При активной блокировке останавливает весь прямой трафик мимо VPN',
    compatibility: 'Always-On/WFP требует прав администратора',
    requiresReconnect: false,
    isModified: (s) => {
      const ks = s.killSwitch ?? DEFAULT_SETTINGS.killSwitch!;
      const dk = DEFAULT_SETTINGS.killSwitch!;
      return (
        ks.mode !== dk.mode ||
        ks.allowLan !== dk.allowLan ||
        ks.blockIpv6Leaks !== dk.blockIpv6Leaks ||
        ks.persistOnExit !== dk.persistOnExit ||
        ks.reconnectAttempts !== dk.reconnectAttempts
      );
    },
    reset: (s) => ({
      ...s,
      killSwitchEnabled: false,
      killSwitch: { ...DEFAULT_SETTINGS.killSwitch! },
    }),
  },

  // === MY IP 2.0 ===
  {
    id: 'my-ip-provider',
    category: 'my-ip',
    level: 'basic',
    title: 'Провайдер Мой IP 2.0 и автопроверка',
    description: 'Выбор источника внешнего IP, ASN/ISP/TZ метаданные и маскировка в интерфейсе',
    keywords: 'ip provider ipwhois ipapi ipinfo ipify ipv6 asn mask внешний адрес',
    defaultLabel: 'Авто • Автопроверка Выкл. (opt-in)',
    recommendedLabel: 'Автопроверка Выкл. (ручная)',
    impact: 'Внешние IP-запросы выполняются только по клику или при явно включённом интервале',
    compatibility: 'При включённом Kill Switch внешние запросы без туннеля блокируются',
    requiresReconnect: false,
    isModified: (s) =>
      (s.preferredIpProvider ?? 'auto') !== 'auto' ||
      (s.autoCheckIpIntervalSecs ?? 0) !== 0,
    reset: (s) => ({
      ...s,
      preferredIpProvider: 'auto',
      autoCheckIpIntervalSecs: 0,
    }),
  },

  // === PRIVACY ===
  {
    id: 'privacy-hwid',
    category: 'privacy-telemetry',
    level: 'basic',
    title: 'Отправка HWID и локальное хранилище DPAPI',
    description: 'Передача обезличенного идентификатора устройства провайдеру подписки и сохранение истории сессий',
    keywords: 'privacy hwid dpapi history purge логи приватность очистка',
    defaultLabel: 'HWID Вкл. • История Вкл.',
    impact: 'Отключение HWID может вызывать отказ провайдеров подписок с лимитом устройств',
    compatibility: 'Ключи и токены на диске всегда шифруются Windows DPAPI',
    requiresReconnect: false,
    isModified: (s) =>
      s.sendHwid !== DEFAULT_SETTINGS.sendHwid ||
      s.historyEnabled !== DEFAULT_SETTINGS.historyEnabled,
    reset: (s) => ({
      ...s,
      sendHwid: DEFAULT_SETTINGS.sendHwid,
      historyEnabled: DEFAULT_SETTINGS.historyEnabled,
    }),
  },

  // === SUBSCRIPTIONS & IMPORT DEFAULTS ===
  {
    id: 'subs-defaults',
    category: 'subscriptions-defaults',
    level: 'advanced',
    title: 'Политика подписок, дубликатов и Smart Config',
    description: 'Сохранение локальных переопределений при обновлении, обработка дублей и автоадаптация',
    keywords: 'subscription duplicates smart config adaptation overrides подписки дубликаты',
    defaultLabel: 'Сохранять overrides Вкл. • Дубликаты Merge • Smart Авто',
    impact: 'Защищает ручные правки и переименования узлов от затирания провайдером',
    compatibility: 'Применяется при импорте и обновлении подписок',
    requiresReconnect: false,
    isModified: (s) =>
      (s.configAdaptationMode ?? 'auto') !== DEFAULT_SETTINGS.configAdaptationMode ||
      (s.keepLocalSubOverrides ?? true) !== true ||
      (s.duplicatePolicy ?? 'merge') !== 'merge' ||
      (s.autoUpdateRulepack ?? true) !== true,
    reset: (s) => ({
      ...s,
      configAdaptationMode: DEFAULT_SETTINGS.configAdaptationMode,
      keepLocalSubOverrides: true,
      duplicatePolicy: 'merge',
      autoUpdateRulepack: true,
    }),
  },

  // === UPDATES & LOGS ===
  {
    id: 'updates-logs',
    category: 'updates',
    level: 'basic',
    title: 'Обновления клиента и детализация логов',
    description: 'Канал релизов (Стабильный / Beta) и уровень журналирования ядра Xray-core',
    keywords: 'updates channel feed loglevel релиз обновления логи уровень',
    defaultLabel: 'Канал Stable • Логи warning',
    impact: 'Режим debug полезен при отладке, но увеличивает число записей в памяти',
    compatibility: 'Смена уровня логов Xray применяется при новом запуске туннеля',
    requiresReconnect: true,
    isModified: (s) =>
      s.logLevel !== DEFAULT_SETTINGS.logLevel ||
      s.autoCheckUpdates !== DEFAULT_SETTINGS.autoCheckUpdates ||
      (s.updateChannel ?? 'stable') !== DEFAULT_SETTINGS.updateChannel ||
      Boolean(s.updateFeedUrl),
    reset: (s) => ({
      ...s,
      logLevel: DEFAULT_SETTINGS.logLevel,
      autoCheckUpdates: DEFAULT_SETTINGS.autoCheckUpdates,
      updateChannel: DEFAULT_SETTINGS.updateChannel,
      updateFeedUrl: null,
    }),
  },
];

export function countModifiedSettings(s: AppSettings): number {
  return SETTINGS_REGISTRY.filter((item) => item.isModified(s)).length;
}

export function resetSettingsCategory(s: AppSettings, category: SettingsCategoryId): AppSettings {
  let next = s;
  for (const item of SETTINGS_REGISTRY) {
    if (item.category === category && item.isModified(next)) {
      next = item.reset(next);
    }
  }
  return next;
}
