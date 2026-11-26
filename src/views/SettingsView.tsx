import {
  ArchiveRestore,
  BarChart3,
  Check,
  Cpu,
  Download,
  GitFork,
  Globe,
  Info,
  Laptop,
  Network,
  Palette,
  RefreshCw,
  RotateCcw,
  Rss,
  Shield,
  Sliders,
  Sparkles,
  Stethoscope,
  Terminal,
  Upload,
} from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AuraLogo } from '../components/AuraLogo';
import {
  M3Button,
  M3Chip,
  M3Dialog,
  M3SearchBar,
  M3SegmentedButton,
  M3Select,
  M3Slider,
  M3StatusBadge,
  M3SurfaceCard,
  M3Switch,
} from '../components/md3';
import { AdvancedVpnPanel } from '../components/settings/AdvancedVpnPanel';
import { CoreManagerPanel } from '../components/settings/CoreManagerPanel';
import { DnsManagerPanel } from '../components/settings/DnsManagerPanel';
import { MyIpPanel } from '../components/settings/MyIpPanel';
import { NetworkDoctorPanel } from '../components/settings/NetworkDoctorPanel';
import { PrivacyCenterPanel } from '../components/settings/PrivacyCenterPanel';
import { SettingMetaRow } from '../components/settings/SettingMetaRow';
import { TunManagerPanel } from '../components/settings/TunManagerPanel';
import { BRAND } from '../config/brand';
import { DEFAULT_SETTINGS } from '../config/defaultSettings';
import {
  SETTINGS_GROUPS,
  SETTINGS_REGISTRY,
  countModifiedSettings,
  isSettingVisibleForLevel,
  resetSettingsCategory,
  resolveCategoryFromLegacySection,
  type SettingLevel,
  type SettingsCategoryId,
} from '../config/settingsRegistry';
import { api } from '../services/api';
import { profilesStore, useBehaviorProfiles } from '../stores/profilesStore';
import { ACCENT_PRESET_META } from '../theme/materialYou';
import type {
  AppSettings,
  BackgroundStyle,
  BehaviorProfileId,
  ConfigAdaptationMode,
  ConnectionHistoryResponse,
  ConnectionMode,
  ConnectionSnapshot,
  CoreDiagnostics,
  IpMonitorState,
  KillSwitchConfig,
  KillSwitchMode,
  RulepackStatus,
  ThemeMode,
  UpdateChannel,
  UpdateCheckResult,
} from '../types/vpn';
import { formatBytes } from '../utils/format';

export type SettingsSection = SettingsCategoryId | 'connection' | 'security' | 'appearance' | 'windows' | 'diagnostics' | 'history' | 'advanced';

interface SettingsViewProps {
  settings: AppSettings;
  connection?: ConnectionSnapshot;
  diagnostics: CoreDiagnostics;
  rulepackStatus: RulepackStatus | null;
  windowsAccentHex: string | null;
  updateResult: UpdateCheckResult | null;
  isCheckingUpdate: boolean;
  initialSection?: SettingsSection | null;
  ipMonitor?: IpMonitorState;
  onSyncIpMonitor?: (next: IpMonitorState) => void;
  onUpdateSettings: (next: AppSettings) => void;
  onSetKillSwitchConfig?: (config: KillSwitchConfig) => Promise<void> | void;
  onEmergencyRecover?: () => Promise<void> | void;
  onOpenProtectionCenter?: () => void;
  onOpenConnectionInspector?: () => void;
  onOpenRouting?: () => void;
  onSelectBehaviorProfile?: (id: BehaviorProfileId) => void;
  onRefreshBootstrap?: () => Promise<void>;
  onRelaunchAdmin: () => void;
  onCheckUpdates: () => void;
  onOpenDiagnostics: () => void;
  onExportDiagnostics: () => Promise<void>;
  onExportSettings: () => Promise<void>;
  onImportSettings: (rawJson: string) => Promise<void>;
  onResetSettings: () => Promise<void>;
}

const CATEGORY_ICON: Record<SettingsCategoryId, typeof Sliders> = {
  general: Laptop,
  interface: Palette,
  'behavior-profiles': Sliders,
  'vpn-core': Cpu,
  'advanced-vpn': Sliders,
  'dns-manager': Globe,
  'tun-adapters': Network,
  'routing-shortcut': GitFork,
  'kill-switch': Shield,
  'my-ip': Globe,
  'privacy-telemetry': Shield,
  'network-doctor': Stethoscope,
  'subscriptions-defaults': Rss,
  updates: RefreshCw,
  backup: ArchiveRestore,
  about: Info,
};

export function SettingsView({
  settings,
  connection,
  diagnostics,
  rulepackStatus,
  windowsAccentHex,
  updateResult,
  isCheckingUpdate,
  initialSection,
  ipMonitor,
  onSyncIpMonitor,
  onUpdateSettings,
  onSetKillSwitchConfig,
  onEmergencyRecover,
  onOpenProtectionCenter,
  onOpenConnectionInspector,
  onOpenRouting,
  onSelectBehaviorProfile,
  onRefreshBootstrap,
  onRelaunchAdmin,
  onCheckUpdates,
  onOpenDiagnostics,
  onExportDiagnostics,
  onExportSettings,
  onImportSettings,
  onResetSettings,
}: SettingsViewProps) {
  const behaviorState = useBehaviorProfiles();
  const [category, setCategory] = useState<SettingsCategoryId>(() =>
    resolveCategoryFromLegacySection(initialSection),
  );
  const [level, setLevel] = useState<SettingLevel>('advanced');
  const [onlyModified, setOnlyModified] = useState(false);
  const [search, setSearch] = useState('');
  const [highlightId, setHighlightId] = useState<string | null>(null);
  const [pendingResetCategory, setPendingResetCategory] = useState<SettingsCategoryId | null>(null);
  const [resetConfirmOpen, setResetConfirmOpen] = useState(false);
  const [savedCustomBadge, setSavedCustomBadge] = useState(false);

  const [uiScaleDraft, setUiScaleDraft] = useState(settings.uiScale);
  const [customHexDraft, setCustomHexDraft] = useState(settings.customAccentHex ?? '#6366F1');
  const [updateFeedDraft, setUpdateFeedDraft] = useState(settings.updateFeedUrl ?? '');
  const [ksReconnectDraft, setKsReconnectDraft] = useState(
    settings.killSwitch?.reconnectAttempts ?? 3,
  );
  const [historyData, setHistoryData] = useState<ConnectionHistoryResponse | null>(null);
  const importBackupRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (initialSection) {
      const target = resolveCategoryFromLegacySection(initialSection);
      setCategory(target);
      if (target === 'advanced-vpn') {
        setLevel((prev) => (prev === 'basic' ? 'advanced' : prev));
      }
    }
  }, [initialSection]);

  useEffect(() => {
    setUiScaleDraft(settings.uiScale);
    setCustomHexDraft(settings.customAccentHex ?? '#6366F1');
    setUpdateFeedDraft(settings.updateFeedUrl ?? '');
    setKsReconnectDraft(settings.killSwitch?.reconnectAttempts ?? 3);
  }, [
    settings.uiScale,
    settings.customAccentHex,
    settings.updateFeedUrl,
    settings.killSwitch?.reconnectAttempts,
  ]);

  const loadHistory = useCallback(async () => {
    try {
      const h = await api.getConnectionHistory();
      setHistoryData(h);
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => {
    if (category === 'privacy-telemetry') {
      void loadHistory();
    }
  }, [category, loadHistory]);

  const modifiedTotal = useMemo(() => countModifiedSettings(settings), [settings]);

  const modifiedByCategory = useMemo(() => {
    const map = new Map<SettingsCategoryId, number>();
    for (const item of SETTINGS_REGISTRY) {
      if (item.isModified(settings)) {
        map.set(item.category, (map.get(item.category) ?? 0) + 1);
      }
    }
    return map;
  }, [settings]);

  const searchResults = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return [];
    return SETTINGS_REGISTRY.filter((item) => {
      if (onlyModified && !item.isModified(settings)) return false;
      return `${item.title} ${item.description} ${item.keywords}`.toLowerCase().includes(q);
    }).slice(0, 12);
  }, [search, onlyModified, settings]);

  const jumpToSetting = (itemId: string, cat: SettingsCategoryId, itemLevel: SettingLevel) => {
    setCategory(cat);
    if (!isSettingVisibleForLevel(itemLevel, level)) {
      setLevel(itemLevel);
    }
    setHighlightId(itemId);
    window.setTimeout(() => {
      const el = document.querySelector(`[data-setting-id="${itemId}"]`);
      if (el && typeof el.scrollIntoView === 'function') {
        el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }, 60);
    window.setTimeout(() => setHighlightId(null), 2000);
  };

  const ksCfg: KillSwitchConfig = settings.killSwitch ?? {
    mode: settings.killSwitchEnabled ? 'on_drop' : 'off',
    allowLan: true,
    blockIpv6Leaks: true,
    persistOnExit: false,
    reconnectAttempts: 3,
  };
  const ksSnap = connection?.killSwitch;
  const applyKs = (patch: Partial<KillSwitchConfig>) => {
    const nextCfg: KillSwitchConfig = { ...ksCfg, ...patch };
    if (onSetKillSwitchConfig) {
      void onSetKillSwitchConfig(nextCfg);
    } else {
      onUpdateSettings({
        ...settings,
        killSwitch: nextCfg,
        killSwitchEnabled: nextCfg.mode !== 'off',
      });
    }
  };

  const activeCategoryMods = modifiedByCategory.get(category) ?? 0;

  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-3" data-testid="settings-view">
      {/* Sticky Top Toolbar */}
      <M3SurfaceCard level="default" className="p-3 space-y-2.5">
        <div className="flex flex-wrap items-center justify-between gap-2.5">
          <div>
            <h1 className="font-display text-[1.0625rem] font-bold text-[var(--md-on-surface)]">
              Настройки
            </h1>
            <p className="text-[0.7rem] text-[var(--md-on-surface-variant)]">
              3 уровня детализации • Центр управления ядрами, DNS, TUN и приватностью
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <M3SegmentedButton<SettingLevel>
              size="sm"
              value={level}
              onChange={(lvl) => setLevel(lvl)}
              options={[
                { id: 'basic', label: 'Основной' },
                { id: 'advanced', label: 'Расширенный' },
                { id: 'expert', label: 'Экспертный' },
              ]}
            />
            <M3Chip
              active={onlyModified}
              onClick={() => setOnlyModified((v) => !v)}
              className="text-[0.7rem]"
            >
              Изменённые ({modifiedTotal})
            </M3Chip>
            {activeCategoryMods > 0 && (
              <M3Button
                size="sm"
                variant="text"
                onClick={() => setPendingResetCategory(category)}
                leadingIcon={<RotateCcw className="h-3.5 w-3.5" />}
              >
                Сбросить раздел ({activeCategoryMods})
              </M3Button>
            )}
          </div>
        </div>

        <M3SearchBar
          value={search}
          onChange={setSearch}
          placeholder="Поиск по настройкам: MTU, DoH, Xray, Keepalive, Kill Switch, HWID..."
        />

        {searchResults.length > 0 && (
          <div className="flex flex-wrap gap-1.5 rounded-xl bg-[var(--md-surface-container-low)] p-2">
            {searchResults.map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => {
                  jumpToSetting(item.id, item.category, item.level);
                  setSearch('');
                }}
                className="inline-flex items-center gap-1.5 rounded-full border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] px-2.5 py-1 text-[0.7rem] text-[var(--md-on-surface)] hover:border-[var(--md-primary)]"
              >
                <span className="font-semibold">{item.title}</span>
              </button>
            ))}
          </div>
        )}
      </M3SurfaceCard>

      {/* Master-Detail 2-Column Workspace */}
      <div className="flex flex-col gap-3 md:flex-row md:items-start">
        {/* Left Navigation Sidebar */}
        <nav
          aria-label="Категории настроек"
          className="w-full shrink-0 space-y-2.5 md:w-64"
        >
          {SETTINGS_GROUPS.map((group) => {
            const visibleCats = group.categories.filter((c) => {
              if (onlyModified && (modifiedByCategory.get(c.id) ?? 0) === 0) {
                return c.id === category;
              }
              return true;
            });
            if (visibleCats.length === 0) return null;

            return (
              <M3SurfaceCard key={group.id} level="low" className="p-2 space-y-0.5">
                <div className="px-2.5 py-1 text-[0.65rem] font-bold uppercase tracking-wider text-[var(--md-on-surface-variant)]">
                  {group.title}
                </div>
                {visibleCats.map((cat) => {
                  const Icon = CATEGORY_ICON[cat.id];
                  const active = category === cat.id;
                  const modCount = modifiedByCategory.get(cat.id) ?? 0;
                  return (
                    <button
                      key={cat.id}
                      type="button"
                      data-testid={`settings-cat-${cat.id}`}
                      onClick={() => {
                        setCategory(cat.id);
                        if (cat.minLevel && !isSettingVisibleForLevel(cat.minLevel, level)) {
                          setLevel(cat.minLevel);
                        }
                      }}
                      className={`flex w-full items-center justify-between gap-2 rounded-xl px-2.5 py-2 text-left transition-colors ${
                        active
                          ? 'bg-[var(--md-primary-container)] text-[var(--md-on-primary-container)]'
                          : 'text-[var(--md-on-surface)] hover:bg-[var(--md-surface-container-high)]'
                      }`}
                    >
                      <div className="flex min-w-0 items-center gap-2">
                        <Icon className="h-3.5 w-3.5 shrink-0" />
                        <span className="truncate text-[0.75rem] font-semibold">{cat.title}</span>
                      </div>
                      {modCount > 0 && (
                        <span className="shrink-0 rounded-full bg-[var(--md-primary)] px-1.5 py-0.5 font-mono-num text-[0.6rem] font-bold text-[var(--md-on-primary)]">
                          {modCount}
                        </span>
                      )}
                    </button>
                  );
                })}
              </M3SurfaceCard>
            );
          })}
        </nav>

        {/* Right Detail Panel */}
        <div className="min-w-0 flex-1 space-y-3">
          {category === 'general' && (
            <div className="space-y-3">
              <SettingMetaRow
                id="autostart"
                level="basic"
                title="Запуск с Windows и поведение окна"
                description="Автозапуск в реестре текущего пользователя и сворачивание в трей"
                defaultLabel="Автозапуск Выкл. • Трей Вкл."
                impact="Позволяет VPN стартовать незаметно в фоне при входе в Windows."
                compatibility="Windows 10 / 11 без прав администратора"
                modified={
                  settings.autostart !== DEFAULT_SETTINGS.autostart ||
                  settings.startMinimized !== DEFAULT_SETTINGS.startMinimized ||
                  settings.minimizeToTray !== DEFAULT_SETTINGS.minimizeToTray ||
                  settings.systemNotifications !== DEFAULT_SETTINGS.systemNotifications
                }
                highlighted={highlightId === 'autostart' || highlightId === 'start-minimized' || highlightId === 'notifications'}
                onReset={() =>
                  onUpdateSettings({
                    ...settings,
                    autostart: DEFAULT_SETTINGS.autostart,
                    startMinimized: DEFAULT_SETTINGS.startMinimized,
                    minimizeToTray: DEFAULT_SETTINGS.minimizeToTray,
                    systemNotifications: DEFAULT_SETTINGS.systemNotifications,
                  })
                }
              >
                <div className="space-y-2">
                  {[
                    ['autostart', 'Запускать AURA VPN при входе в Windows'] as const,
                    ['startMinimized', 'Запускать свёрнутым в трей'] as const,
                    ['minimizeToTray', 'Сворачивать в трей при закрытии окна'] as const,
                    ['systemNotifications', 'Показывать системные уведомления'] as const,
                  ].map(([key, label]) => (
                    <div key={key} className="flex items-center justify-between rounded-xl bg-[var(--md-surface-container)] px-3 py-2 text-[0.74rem]">
                      <span>{label}</span>
                      <M3Switch
                        checked={settings[key]}
                        onChange={(v) => onUpdateSettings({ ...settings, [key]: v })}
                        ariaLabel={label}
                      />
                    </div>
                  ))}
                </div>
              </SettingMetaRow>

              <SettingMetaRow
                id="auto-connect-launch"
                level="basic"
                title="Автоподключение и восстановление после сна"
                description="Поднимать туннель автоматически при запуске и пробуждении ПК"
                defaultLabel="При запуске Выкл. • Реконнект и Пробуждение Вкл."
                impact="Минимизирует время без VPN после выхода компьютера из спящего режима."
                compatibility="Работает с активным профилем и маршрутизацией"
                modified={
                  settings.autoConnectOnLaunch !== DEFAULT_SETTINGS.autoConnectOnLaunch ||
                  settings.autoReconnect !== DEFAULT_SETTINGS.autoReconnect ||
                  settings.reconnectOnWake !== DEFAULT_SETTINGS.reconnectOnWake
                }
                highlighted={highlightId === 'auto-connect-launch'}
                onReset={() =>
                  onUpdateSettings({
                    ...settings,
                    autoConnectOnLaunch: DEFAULT_SETTINGS.autoConnectOnLaunch,
                    autoReconnect: DEFAULT_SETTINGS.autoReconnect,
                    reconnectOnWake: DEFAULT_SETTINGS.reconnectOnWake,
                  })
                }
              >
                <div className="space-y-2">
                  {[
                    ['autoConnectOnLaunch', 'Автоподключение к последнему серверу при старте'] as const,
                    ['autoReconnect', 'Автоматическое переподключение при обрыве туннеля'] as const,
                    ['reconnectOnWake', 'Восстанавливать туннель после выхода Windows из сна'] as const,
                  ].map(([key, label]) => (
                    <div key={key} className="flex items-center justify-between rounded-xl bg-[var(--md-surface-container)] px-3 py-2 text-[0.74rem]">
                      <span>{label}</span>
                      <M3Switch
                        checked={settings[key]}
                        onChange={(v) => onUpdateSettings({ ...settings, [key]: v })}
                        ariaLabel={label}
                      />
                    </div>
                  ))}
                </div>
              </SettingMetaRow>

              <M3SurfaceCard level="default" className="flex flex-wrap items-center justify-between gap-2 p-3.5">
                <div className="text-[0.75rem]">
                  <span className="font-bold">Права процесса (UAC): </span>
                  <M3StatusBadge tone={diagnostics.isElevated ? 'success' : 'neutral'}>
                    {diagnostics.isElevated ? 'Администратор' : 'Обычный пользователь'}
                  </M3StatusBadge>
                </div>
                {!diagnostics.isElevated && (
                  <M3Button size="sm" variant="tonal" onClick={onRelaunchAdmin}>
                    Перезапустить от администратора
                  </M3Button>
                )}
              </M3SurfaceCard>
            </div>
          )}

          {category === 'interface' && (
            <div className="space-y-3">
              <SettingMetaRow
                id="theme-mode"
                level="basic"
                title="Тема оформления, фон и Material You"
                description="Тёмная/Светлая/Системная тема, стиль фона окна и акцентная палитра"
                defaultLabel="Тёмная • Индиго • Aura"
                impact="Применяется мгновенно без переподключения туннеля."
                compatibility="Фон Mica использует нативный DWM Windows 11"
                modified={
                  settings.theme !== DEFAULT_SETTINGS.theme ||
                  settings.accentPreset !== DEFAULT_SETTINGS.accentPreset ||
                  (settings.backgroundStyle ?? 'aura') !== DEFAULT_SETTINGS.backgroundStyle ||
                  settings.dynamicColor !== DEFAULT_SETTINGS.dynamicColor
                }
                highlighted={highlightId === 'theme-mode'}
                onReset={() => {
                  void api.setWindowBackgroundStyle(DEFAULT_SETTINGS.backgroundStyle!);
                  onUpdateSettings({
                    ...settings,
                    theme: DEFAULT_SETTINGS.theme,
                    accentPreset: DEFAULT_SETTINGS.accentPreset,
                    customAccentHex: DEFAULT_SETTINGS.customAccentHex,
                    dynamicColor: DEFAULT_SETTINGS.dynamicColor,
                    backgroundStyle: DEFAULT_SETTINGS.backgroundStyle,
                  });
                }}
              >
                <div className="space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-[0.74rem] font-semibold">Тема</span>
                    <M3SegmentedButton<ThemeMode>
                      size="sm"
                      value={settings.theme}
                      onChange={(theme) => onUpdateSettings({ ...settings, theme })}
                      options={[
                        { id: 'dark', label: 'Тёмная' },
                        { id: 'light', label: 'Светлая' },
                        { id: 'system', label: 'Системная' },
                      ]}
                    />
                  </div>
                  <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[var(--md-outline-variant)] pt-2.5">
                    <span className="text-[0.74rem] font-semibold">Стиль фона окна</span>
                    <M3SegmentedButton<BackgroundStyle>
                      size="sm"
                      value={settings.backgroundStyle ?? 'aura'}
                      onChange={(backgroundStyle) => {
                        void api.setWindowBackgroundStyle(backgroundStyle).catch(() => undefined);
                        onUpdateSettings({ ...settings, backgroundStyle });
                      }}
                      options={[
                        { id: 'aura', label: 'Aura' },
                        { id: 'standard', label: 'Стандарт' },
                        { id: 'minimal', label: 'Минимал' },
                        { id: 'mica', label: 'Mica' },
                      ]}
                    />
                  </div>
                  <div className="flex items-center justify-between border-t border-[var(--md-outline-variant)] pt-2.5 text-[0.74rem]">
                    <span className="inline-flex items-center gap-1.5 font-semibold">
                      <Sparkles className="h-3.5 w-3.5 text-[var(--md-primary)]" />
                      Динамическая палитра WCAG AA
                    </span>
                    <M3Switch
                      checked={settings.dynamicColor}
                      onChange={(dynamicColor) => onUpdateSettings({ ...settings, dynamicColor })}
                      ariaLabel="Динамическая палитра"
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-2 border-t border-[var(--md-outline-variant)] pt-2.5 sm:grid-cols-4">
                    {ACCENT_PRESET_META.map((meta) => {
                      const active = settings.accentPreset === meta.id;
                      const swatch =
                        meta.id === 'windows'
                          ? windowsAccentHex ?? meta.hex
                          : meta.id === 'custom'
                            ? settings.customAccentHex ?? meta.hex
                            : meta.hex;
                      return (
                        <button
                          key={meta.id}
                          type="button"
                          onClick={() => onUpdateSettings({ ...settings, accentPreset: meta.id })}
                          className={`flex items-center gap-2 rounded-xl border px-2.5 py-2 text-left ${
                            active
                              ? 'border-[var(--md-primary)] bg-[var(--md-primary-container)]/35'
                              : 'border-[var(--md-outline-variant)] bg-[var(--md-surface-container)]'
                          }`}
                        >
                          <span
                            className="h-3.5 w-3.5 shrink-0 rounded-full border border-[var(--md-outline-variant)]"
                            style={{ backgroundColor: swatch }}
                          />
                          <span className="truncate text-[0.72rem] font-medium">{meta.label}</span>
                        </button>
                      );
                    })}
                  </div>
                  {settings.accentPreset === 'custom' && (
                    <div className="flex items-center gap-2 rounded-xl bg-[var(--md-surface-container)] px-3 py-2">
                      <input
                        type="color"
                        value={customHexDraft}
                        onChange={(e) => {
                          setCustomHexDraft(e.target.value);
                          onUpdateSettings({
                            ...settings,
                            accentPreset: 'custom',
                            customAccentHex: e.target.value,
                          });
                        }}
                        className="h-7 w-9 cursor-pointer bg-transparent"
                      />
                      <input
                        value={customHexDraft}
                        onChange={(e) => setCustomHexDraft(e.target.value)}
                        onBlur={() => {
                          if (/^#[0-9a-fA-F]{6}$/.test(customHexDraft.trim())) {
                            onUpdateSettings({
                              ...settings,
                              accentPreset: 'custom',
                              customAccentHex: customHexDraft.trim(),
                            });
                          }
                        }}
                        className="h-7 w-28 rounded-lg border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-highest)] px-2 font-mono text-[0.72rem]"
                      />
                    </div>
                  )}
                </div>
              </SettingMetaRow>

              <SettingMetaRow
                id="ui-scale"
                level="basic"
                title="Масштаб, компактность и анимации"
                description="Размер элементов управления и плотность списков серверов"
                defaultLabel="100% • Компактный Выкл. • Анимации Вкл."
                rangeLabel="90% – 120%"
                impact="Упрощает работу на небольших ноутбуках 1366×768 или 4K экранах."
                compatibility="Мгновенное применение"
                modified={
                  settings.uiScale !== DEFAULT_SETTINGS.uiScale ||
                  settings.compactMode !== DEFAULT_SETTINGS.compactMode ||
                  settings.animationsEnabled !== DEFAULT_SETTINGS.animationsEnabled
                }
                highlighted={highlightId === 'ui-scale'}
                onReset={() => {
                  setUiScaleDraft(DEFAULT_SETTINGS.uiScale);
                  onUpdateSettings({
                    ...settings,
                    uiScale: DEFAULT_SETTINGS.uiScale,
                    compactMode: DEFAULT_SETTINGS.compactMode,
                    animationsEnabled: DEFAULT_SETTINGS.animationsEnabled,
                  });
                }}
              >
                <div className="space-y-3">
                  <div className="space-y-1">
                    <div className="flex justify-between text-[0.72rem]">
                      <span>Масштаб интерфейса</span>
                      <span className="font-mono-num text-[var(--md-primary)]">{uiScaleDraft}%</span>
                    </div>
                    <M3Slider
                      min={90}
                      max={120}
                      step={5}
                      value={uiScaleDraft}
                      showTicks
                      onChange={setUiScaleDraft}
                      onCommit={(uiScale) => onUpdateSettings({ ...settings, uiScale })}
                      ariaLabel="Масштаб интерфейса"
                    />
                  </div>
                  <div className="flex items-center justify-between rounded-xl bg-[var(--md-surface-container)] px-3 py-2 text-[0.72rem]">
                    <span>Компактный режим карточек</span>
                    <M3Switch
                      checked={settings.compactMode}
                      onChange={(compactMode) => onUpdateSettings({ ...settings, compactMode })}
                      ariaLabel="Компактный режим"
                    />
                  </div>
                  <div className="flex items-center justify-between rounded-xl bg-[var(--md-surface-container)] px-3 py-2 text-[0.72rem]">
                    <span>Плавные анимации интерфейса</span>
                    <M3Switch
                      checked={settings.animationsEnabled}
                      onChange={(animationsEnabled) =>
                        onUpdateSettings({ ...settings, animationsEnabled })
                      }
                      ariaLabel="Анимации"
                    />
                  </div>
                </div>
              </SettingMetaRow>
            </div>
          )}

          {category === 'behavior-profiles' && (
            <SettingMetaRow
              id="behavior-profiles"
              level="basic"
              title="Режим перехвата и профили поведения"
              description="Быстрое переключение сценария (Повседневный / Рабочий / Игровой / Пользовательский)"
              defaultLabel="Системный прокси"
              impact="TUN перехватывает весь трафик ПК; Системный прокси работает через localhost без UAC."
              compatibility="TUN требует прав администратора Windows"
              requiresReconnect
              modified={settings.connectionMode !== DEFAULT_SETTINGS.connectionMode}
              highlighted={highlightId === 'behavior-profiles'}
              onReset={() =>
                onUpdateSettings({ ...settings, connectionMode: DEFAULT_SETTINGS.connectionMode })
              }
              control={
                <M3SegmentedButton<ConnectionMode>
                  size="sm"
                  value={settings.connectionMode}
                  onChange={(connectionMode) => onUpdateSettings({ ...settings, connectionMode })}
                  options={[
                    { id: 'system_proxy', label: 'Системный прокси' },
                    { id: 'tun', label: 'TUN (весь ПК)' },
                  ]}
                />
              }
            >
              <div className="space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-[0.72rem] text-[var(--md-on-surface-variant)]">
                    Выберите пресет или сохраните текущую конфигурацию как «Пользовательский»
                  </span>
                  <M3Button
                    size="sm"
                    variant="tonal"
                    onClick={() => {
                      profilesStore.saveCustomFromSettings(settings);
                      setSavedCustomBadge(true);
                      window.setTimeout(() => setSavedCustomBadge(false), 1800);
                    }}
                  >
                    {savedCustomBadge ? 'Сохранено ✓' : 'Сохранить в «Пользовательский»'}
                  </M3Button>
                </div>
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                  {(Object.keys(behaviorState.profiles) as BehaviorProfileId[]).map((id) => {
                    const prof = behaviorState.profiles[id];
                    const active = behaviorState.activeProfileId === id;
                    return (
                      <button
                        key={id}
                        type="button"
                        onClick={() => onSelectBehaviorProfile?.(id)}
                        className={`flex flex-col items-start rounded-xl border p-3 text-left transition-colors ${
                          active
                            ? 'border-[var(--md-primary)] bg-[var(--md-primary-container)]/35'
                            : 'border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] hover:bg-[var(--md-surface-container-high)]'
                        }`}
                      >
                        <div className="flex w-full items-center justify-between gap-2">
                          <span className="text-[0.76rem] font-bold">{prof.name}</span>
                          {active && <Check className="h-3.5 w-3.5 text-[var(--md-primary)]" />}
                        </div>
                        <span className="mt-1 text-[0.68rem] text-[var(--md-on-surface-variant)]">
                          {prof.description}
                        </span>
                      </button>
                    );
                  })}
                </div>
              </div>
            </SettingMetaRow>
          )}

          {category === 'vpn-core' && (
            <CoreManagerPanel
              settings={settings}
              onUpdateSettings={onUpdateSettings}
              highlightSettingId={highlightId}
            />
          )}

          {category === 'advanced-vpn' && (
            <AdvancedVpnPanel
              settings={settings}
              level={level}
              onUpdateSettings={onUpdateSettings}
              highlightSettingId={highlightId}
            />
          )}

          {category === 'dns-manager' && (
            <DnsManagerPanel
              settings={settings}
              level={level}
              onUpdateSettings={onUpdateSettings}
              highlightSettingId={highlightId}
            />
          )}

          {category === 'tun-adapters' && (
            <TunManagerPanel
              settings={settings}
              level={level}
              onUpdateSettings={onUpdateSettings}
              highlightSettingId={highlightId}
            />
          )}

          {category === 'routing-shortcut' && (
            <M3SurfaceCard level="default" className="p-4 space-y-2.5">
              <h2 className="text-[0.84rem] font-bold">Маршрутизация и Split Tunneling</h2>
              <p className="text-[0.72rem] text-[var(--md-on-surface-variant)]">
                Текущий профиль:{' '}
                <span className="font-semibold text-[var(--md-on-surface)]">
                  {settings.routing.profile === 'ru_direct'
                    ? 'Российские сервисы напрямую'
                    : settings.routing.profile === 'all_vpn'
                      ? 'Весь трафик через VPN'
                      : settings.routing.profile === 'bypass_apps'
                        ? 'Исключения приложений'
                        : settings.routing.profile === 'only_apps'
                          ? 'Только выбранные приложения'
                          : 'Пользовательский'}
                </span>{' '}
                • База РФ: <span className="font-mono">{rulepackStatus?.version ?? 'builtin'}</span> ({rulepackStatus?.totalDomains ?? 158} доменов) •
                Приложений Split Tunneling: <span className="font-mono-num">{settings.routing.splitApps.length}</span>
              </p>
              {onOpenRouting && (
                <M3Button size="sm" variant="tonal" onClick={onOpenRouting}>
                  Перейти в раздел Маршрутизация
                </M3Button>
              )}
            </M3SurfaceCard>
          )}

          {category === 'kill-switch' && (
            <SettingMetaRow
              id="kill-switch"
              level="basic"
              title="Kill Switch 2.0 (защита от утечек трафика)"
              description="WFP-фильтры в TUN и Proxy Guard на 127.0.0.1 в системном прокси"
              defaultLabel="Выкл. • LAN Вкл. • IPv6 блок Вкл."
              recommendedLabel="On-Drop (или Always-On с UAC)"
              rangeLabel="Попыток реконнекта: 0 – 10"
              impact="При срабатывании блокирует весь незашифрованный трафик до восстановления туннеля."
              compatibility="Always-On с блокировкой на уровне ядра Windows требует UAC"
              highlighted={highlightId === 'kill-switch'}
              modified={ksCfg.mode !== 'off'}
              onReset={() =>
                applyKs({
                  mode: 'off',
                  allowLan: true,
                  blockIpv6Leaks: true,
                  persistOnExit: false,
                  reconnectAttempts: 3,
                })
              }
            >
              <div className="space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    {(diagnostics.killSwitchEngaged || ksSnap?.blockingActive) && (
                      <M3StatusBadge tone="error">Блокировка активна</M3StatusBadge>
                    )}
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {onOpenProtectionCenter && (
                      <M3Button size="sm" variant="outlined" onClick={onOpenProtectionCenter}>
                        Центр защиты
                      </M3Button>
                    )}
                    {onEmergencyRecover && (
                      <M3Button size="sm" variant="tonal" onClick={() => void onEmergencyRecover()}>
                        Экстренно восстановить сеть
                      </M3Button>
                    )}
                  </div>
                </div>

                <M3SegmentedButton<KillSwitchMode>
                  fullWidth
                  size="sm"
                  value={ksCfg.mode}
                  onChange={(mode) => applyKs({ mode })}
                  options={[
                    { id: 'off', label: 'Выключен' },
                    { id: 'on_drop', label: 'При обрыве' },
                    { id: 'always_on', label: 'Always-On' },
                    { id: 'routing_aware', label: 'Routing-Aware' },
                  ]}
                />

                {ksCfg.mode !== 'off' && (
                  <div className="space-y-2 border-t border-[var(--md-outline-variant)] pt-2.5 text-[0.72rem]">
                    <div className="flex items-center justify-between rounded-xl bg-[var(--md-surface-container)] px-3 py-2">
                      <span>Разрешать локальную сеть (LAN / DHCP)</span>
                      <M3Switch
                        checked={ksCfg.allowLan}
                        onChange={(allowLan) => applyKs({ allowLan })}
                        ariaLabel="Разрешать LAN"
                      />
                    </div>
                    <div className="flex items-center justify-between rounded-xl bg-[var(--md-surface-container)] px-3 py-2">
                      <span>Блокировать IPv6 при активном Kill Switch</span>
                      <M3Switch
                        checked={ksCfg.blockIpv6Leaks}
                        onChange={(blockIpv6Leaks) => applyKs({ blockIpv6Leaks })}
                        ariaLabel="Блокировать IPv6"
                      />
                    </div>
                    <div className="flex items-center justify-between rounded-xl bg-[var(--md-surface-container)] px-3 py-2">
                      <span>Удерживать блокировку после выхода (Always-On Persist)</span>
                      <M3Switch
                        checked={ksCfg.persistOnExit}
                        onChange={(persistOnExit) => applyKs({ persistOnExit })}
                        ariaLabel="Удерживать после выхода"
                      />
                    </div>
                    <div className="space-y-1 pt-1">
                      <div className="flex justify-between">
                        <span>Попыток автопереподключения до блокировки</span>
                        <span className="font-mono-num font-bold text-[var(--md-primary)]">
                          {ksReconnectDraft}
                        </span>
                      </div>
                      <M3Slider
                        min={0}
                        max={10}
                        step={1}
                        value={ksReconnectDraft}
                        onChange={setKsReconnectDraft}
                        onCommit={(reconnectAttempts) => applyKs({ reconnectAttempts })}
                        ariaLabel="Попыток автопереподключения"
                      />
                    </div>
                  </div>
                )}
              </div>
            </SettingMetaRow>
          )}

          {category === 'my-ip' && (
            <MyIpPanel
              settings={settings}
              ipMonitor={ipMonitor}
              onUpdateSettings={onUpdateSettings}
              onSyncIpMonitor={onSyncIpMonitor}
              highlightSettingId={highlightId}
            />
          )}

          {category === 'privacy-telemetry' && (
            <div className="space-y-3">
              <PrivacyCenterPanel
                settings={settings}
                onUpdateSettings={onUpdateSettings}
                onRefreshBootstrap={onRefreshBootstrap}
                highlightSettingId={highlightId}
              />

              <M3SurfaceCard level="default" className="p-3.5 space-y-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <BarChart3 className="h-4 w-4 text-[var(--md-primary)]" />
                    <span className="text-[0.8rem] font-bold">Сводка трафика за 30 дней</span>
                  </div>
                  <M3Button size="sm" variant="outlined" onClick={() => void loadHistory()}>
                    Обновить
                  </M3Button>
                </div>
                {historyData && (
                  <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 text-[0.7rem]">
                    <div className="rounded-xl bg-[var(--md-surface-container-low)] p-2">
                      <div className="text-[var(--md-on-surface-variant)]">Сегодня</div>
                      <div className="font-mono font-bold">
                        {formatBytes(historyData.aggregates.todayRxBytes + historyData.aggregates.todayTxBytes)}
                      </div>
                    </div>
                    <div className="rounded-xl bg-[var(--md-surface-container-low)] p-2">
                      <div className="text-[var(--md-on-surface-variant)]">За 7 дней</div>
                      <div className="font-mono font-bold">
                        {formatBytes(historyData.aggregates.weekRxBytes + historyData.aggregates.weekTxBytes)}
                      </div>
                    </div>
                    <div className="rounded-xl bg-[var(--md-surface-container-low)] p-2">
                      <div className="text-[var(--md-on-surface-variant)]">За 30 дней</div>
                      <div className="font-mono font-bold">
                        {formatBytes(historyData.aggregates.monthRxBytes + historyData.aggregates.monthTxBytes)}
                      </div>
                    </div>
                    <div className="rounded-xl bg-[var(--md-surface-container-low)] p-2">
                      <div className="text-[var(--md-on-surface-variant)]">Сессий / реконнектов</div>
                      <div className="font-mono font-bold">
                        {historyData.aggregates.totalSessions} / {historyData.aggregates.totalReconnects}
                      </div>
                    </div>
                  </div>
                )}
              </M3SurfaceCard>
            </div>
          )}

          {category === 'network-doctor' && (
            <NetworkDoctorPanel
              onExportDiagnostics={onExportDiagnostics}
              onOpenConnectionInspector={onOpenConnectionInspector}
            />
          )}

          {category === 'subscriptions-defaults' && (
            <SettingMetaRow
              id="subs-defaults"
              level="advanced"
              title="Политика импорта, подписок и Smart Config"
              description="Как обрабатывать дубликаты серверов и сохранять локальные правки при обновлении"
              defaultLabel="Overrides Вкл. • Дубликаты Merge • Smart Авто"
              impact="Сохранение переопределений не даёт автообновлению подписки сбросить ваши имена и MTU."
              compatibility="Действует для всех подписок и ручного импорта"
              highlighted={highlightId === 'subs-defaults'}
              modified={
                (settings.configAdaptationMode ?? 'auto') !== DEFAULT_SETTINGS.configAdaptationMode ||
                (settings.keepLocalSubOverrides ?? true) !== true ||
                (settings.duplicatePolicy ?? 'merge') !== 'merge'
              }
              onReset={() =>
                onUpdateSettings({
                  ...settings,
                  configAdaptationMode: DEFAULT_SETTINGS.configAdaptationMode,
                  keepLocalSubOverrides: true,
                  duplicatePolicy: 'merge',
                })
              }
            >
              <div className="space-y-3 text-[0.72rem]">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-semibold">Адаптация импортируемых конфигураций</span>
                  <M3SegmentedButton<ConfigAdaptationMode>
                    size="sm"
                    value={settings.configAdaptationMode ?? 'auto'}
                    onChange={(configAdaptationMode) =>
                      onUpdateSettings({ ...settings, configAdaptationMode })
                    }
                    options={[
                      { id: 'auto', label: 'Авто' },
                      { id: 'profile', label: 'Профиль' },
                      { id: 'manual', label: 'Вручную' },
                    ]}
                  />
                </div>
                <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[var(--md-outline-variant)] pt-2.5">
                  <span className="font-semibold">Политика при дубликатах узлов</span>
                  <M3Select
                    size="sm"
                    ariaLabel="Политика дубликатов"
                    value={settings.duplicatePolicy ?? 'merge'}
                    onChange={(duplicatePolicy) => onUpdateSettings({ ...settings, duplicatePolicy })}
                    options={[
                      { value: 'merge', label: 'Объединять / добавлять' },
                      { value: 'skip', label: 'Пропускать дубликаты' },
                      { value: 'replace', label: 'Заменять существующий' },
                      { value: 'keep', label: 'Оставлять оба' },
                    ]}
                  />
                </div>
                <div className="flex items-center justify-between rounded-xl bg-[var(--md-surface-container)] px-3 py-2">
                  <span>Сохранять локальные переопределения и имена при обновлении подписки</span>
                  <M3Switch
                    checked={settings.keepLocalSubOverrides ?? true}
                    onChange={(keepLocalSubOverrides) =>
                      onUpdateSettings({ ...settings, keepLocalSubOverrides })
                    }
                    ariaLabel="Сохранять локальные переопределения"
                  />
                </div>
                <div className="rounded-xl bg-[var(--md-surface-container-low)] px-3 py-2 text-[0.7rem] text-[var(--md-on-surface-variant)]">
                  База правил РФ обновляется только по вашему явному действию в разделе «Маршрутизация» по заданному HTTPS URL.
                </div>
              </div>
            </SettingMetaRow>
          )}

          {category === 'updates' && (
            <div className="space-y-3">
              <SettingMetaRow
                id="updates-logs"
                level="basic"
                title="Обновления клиента и логирование Xray-core"
                description="Канал обновлений AURA VPN и уровень детализации журнала ядра"
                defaultLabel="Stable • warning"
                impact="Режим Debug помогает диагностировать сложные разрывы, но генерирует больше записей."
                compatibility="Смена уровня логов Xray требует перезапуска туннеля"
                requiresReconnect
                highlighted={highlightId === 'updates-logs'}
                modified={
                  settings.logLevel !== DEFAULT_SETTINGS.logLevel ||
                  settings.autoCheckUpdates !== DEFAULT_SETTINGS.autoCheckUpdates ||
                  (settings.updateChannel ?? 'stable') !== DEFAULT_SETTINGS.updateChannel
                }
                onReset={() =>
                  onUpdateSettings({
                    ...settings,
                    logLevel: DEFAULT_SETTINGS.logLevel,
                    autoCheckUpdates: DEFAULT_SETTINGS.autoCheckUpdates,
                    updateChannel: DEFAULT_SETTINGS.updateChannel,
                    updateFeedUrl: null,
                  })
                }
              >
                <div className="space-y-3 text-[0.72rem]">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-semibold">Канал обновлений</span>
                    <M3Select<UpdateChannel>
                      size="sm"
                      ariaLabel="Канал обновлений"
                      value={settings.updateChannel ?? 'stable'}
                      onChange={(updateChannel) => onUpdateSettings({ ...settings, updateChannel })}
                      options={[
                        { value: 'stable', label: 'Стабильный (Stable)' },
                        { value: 'beta', label: 'Бета-канал (Beta)' },
                      ]}
                    />
                  </div>
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-semibold">Уровень логирования Xray-core</span>
                    <M3Select
                      size="sm"
                      ariaLabel="Уровень логирования"
                      value={settings.logLevel}
                      onChange={(logLevel) => onUpdateSettings({ ...settings, logLevel })}
                      options={[
                        { value: 'warning', label: 'Warning (Стандарт)' },
                        { value: 'info', label: 'Info (Подробно)' },
                        { value: 'debug', label: 'Debug (Отладка)' },
                        { value: 'error', label: 'Error (Ошибки)' },
                      ]}
                    />
                  </div>
                  {level !== 'basic' && (
                    <label className="block space-y-1">
                      <span className="text-[var(--md-on-surface-variant)]">HTTPS URL ленты обновлений (опционально)</span>
                      <input
                        value={updateFeedDraft}
                        onChange={(e) => setUpdateFeedDraft(e.target.value)}
                        onBlur={() =>
                          onUpdateSettings({
                            ...settings,
                            updateFeedUrl: updateFeedDraft.trim() || null,
                          })
                        }
                        placeholder="https://example.com/aura-vpn/releases/latest.json"
                        className="h-8 w-full rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] px-3 font-mono text-[0.72rem]"
                      />
                    </label>
                  )}
                  <div className="flex flex-wrap items-center gap-2 pt-1">
                    <M3Button
                      size="sm"
                      variant="tonal"
                      loading={isCheckingUpdate}
                      onClick={onCheckUpdates}
                      leadingIcon={<RefreshCw className="h-3.5 w-3.5" />}
                    >
                      Проверить обновления
                    </M3Button>
                    <M3Button
                      size="sm"
                      variant="outlined"
                      onClick={onOpenDiagnostics}
                      leadingIcon={<Terminal className="h-3.5 w-3.5" />}
                    >
                      Открыть журнал ядра
                    </M3Button>
                  </div>
                  {updateResult && (
                    <div className="space-y-1 rounded-xl bg-[var(--md-surface-container)] px-3 py-2">
                      <div>
                        {updateResult.updateAvailable
                          ? `Доступна версия ${updateResult.latestVersion}! ${updateResult.message}`
                          : updateResult.message}
                      </div>
                      {updateResult.releaseUrl && (
                        <button
                          type="button"
                          onClick={() => void navigator.clipboard?.writeText(updateResult.releaseUrl ?? '')}
                          className="font-mono text-[0.65rem] text-[var(--md-primary)] hover:underline"
                        >
                          {updateResult.releaseUrl} (копировать)
                        </button>
                      )}
                    </div>
                  )}
                </div>
              </SettingMetaRow>
            </div>
          )}

          {category === 'backup' && (
            <M3SurfaceCard level="default" className="p-4 space-y-3" data-setting-id="backup">
              <h2 className="text-[0.84rem] font-bold">Резервная копия и сброс параметров</h2>
              <p className="text-[0.72rem] text-[var(--md-on-surface-variant)]">
                При экспорте настроек HWID и ключи подписок не включаются. Папка профиля: <code className="font-mono">{diagnostics.configDir}</code>
              </p>
              <div className="flex flex-wrap gap-2">
                <input
                  ref={importBackupRef}
                  type="file"
                  accept="application/json,.json"
                  className="hidden"
                  onChange={async (e) => {
                    const f = e.target.files?.[0];
                    e.target.value = '';
                    if (!f) return;
                    try {
                      await onImportSettings(await f.text());
                    } catch {
                      // Toast error handled by parent handler
                    }
                  }}
                />
                <M3Button
                  size="sm"
                  variant="tonal"
                  onClick={() => void onExportSettings()}
                  leadingIcon={<ArchiveRestore className="h-3.5 w-3.5" />}
                >
                  Экспорт настроек (.json)
                </M3Button>
                <M3Button
                  size="sm"
                  variant="outlined"
                  onClick={() => importBackupRef.current?.click()}
                  leadingIcon={<Upload className="h-3.5 w-3.5" />}
                >
                  Восстановить из JSON
                </M3Button>
                <M3Button
                  size="sm"
                  variant="outlined"
                  onClick={() => void onExportDiagnostics()}
                  leadingIcon={<Download className="h-3.5 w-3.5" />}
                >
                  Отчёт диагностики (без секретов)
                </M3Button>
                <M3Button
                  size="sm"
                  variant="danger"
                  onClick={() => setResetConfirmOpen(true)}
                  leadingIcon={<RotateCcw className="h-3.5 w-3.5" />}
                >
                  Сбросить все настройки
                </M3Button>
              </div>
            </M3SurfaceCard>
          )}

          {category === 'about' && (
            <M3SurfaceCard level="default" className="p-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <AuraLogo variant="horizontal" className="h-10 w-10" />
                <div className="flex items-center gap-2">
                  <M3StatusBadge tone="primary" dot={false}>
                    Версия {BRAND.version}
                  </M3StatusBadge>
                  <M3StatusBadge tone={diagnostics.coreIntegrityOk ? 'success' : 'warning'} dot={false}>
                    {diagnostics.coreIntegrityOk ? 'SHA-256 OK' : 'Проверка'}
                  </M3StatusBadge>
                </div>
              </div>
              <div className="text-[0.74rem] text-[var(--md-on-surface-variant)] space-y-1.5">
                <div className="font-bold text-[var(--md-on-surface)]">
                  AURA VPN v{BRAND.version} — Advanced Network Engine & Core Manager
                </div>
                <ul className="list-disc pl-4 space-y-0.5">
                  <li>Двухколоночный Центр настроек (Basic / Advanced / Expert) с реестром метаданных и сбросом разделов.</li>
                  <li>Core Manager с проверкой SHA-256 и матрицей совместимости для Xray-core 26.11.9, wireproxy-awg и Wintun 0.14.1.</li>
                  <li>Config Studio с инспектором протоколов, JSON-редактором, live xray -test, 4-уровневым diff и DPAPI-ревизиями.</li>
                  <li>DNS-менеджер (Hybrid / DoH / DoT / DoQ), Инспектор подключения с таймлайном, Сетевой доктор (12 проверок), Мой IP 2.0 и Центр приватности.</li>
                </ul>
              </div>
            </M3SurfaceCard>
          )}
        </div>
      </div>

      {/* Section reset confirmation */}
      <M3Dialog
        open={pendingResetCategory !== null}
        onClose={() => setPendingResetCategory(null)}
        title="Сбросить настройки текущего раздела?"
        description="Параметры выбранной категории будут возвращены к значениям по умолчанию."
        footer={
          <>
            <M3Button variant="text" onClick={() => setPendingResetCategory(null)}>
              Отмена
            </M3Button>
            <M3Button
              variant="danger"
              onClick={() => {
                if (pendingResetCategory) {
                  onUpdateSettings(resetSettingsCategory(settings, pendingResetCategory));
                }
                setPendingResetCategory(null);
              }}
            >
              Сбросить раздел
            </M3Button>
          </>
        }
      >
        <p className="text-[0.75rem] text-[var(--md-on-surface-variant)]">
          Остальные категории настроек и профили серверов останутся без изменений.
        </p>
      </M3Dialog>

      {/* Full settings reset confirmation */}
      <M3Dialog
        open={resetConfirmOpen}
        onClose={() => setResetConfirmOpen(false)}
        title="Сбросить все настройки до значений по умолчанию?"
        description="Ваши серверы и подписки сохранятся."
        footer={
          <>
            <M3Button variant="text" onClick={() => setResetConfirmOpen(false)}>
              Отмена
            </M3Button>
            <M3Button
              variant="danger"
              onClick={async () => {
                setResetConfirmOpen(false);
                await onResetSettings();
              }}
            >
              Сбросить
            </M3Button>
          </>
        }
      >
        <p className="text-[0.75rem] text-[var(--md-on-surface-variant)]">
          Сетевые параметры, тема Material You и политики DNS вернутся к стандартным значениям.
        </p>
      </M3Dialog>
    </div>
  );
}
