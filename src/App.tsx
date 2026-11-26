import { AlertTriangle, RotateCw, ShieldAlert } from 'lucide-react';
import { MotionConfig } from 'motion/react';
import { Suspense, lazy, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { M3Button, M3Dialog, M3Skeleton, M3SurfaceCard } from './components/md3';
import { NavigationRail } from './components/NavigationRail';
import { TitleBar } from './components/TitleBar';
import { ToastContainer, type ToastMessage } from './components/ToastContainer';
import { IS_PREVIEW_BUILD, api, isTauriRuntime } from './services/api';
import { liveStore } from './stores/liveStore';
import { notificationStore } from './stores/notificationStore';
import {
  analyzeProfileDiff,
  applyBehaviorProfileToSettings,
  profilesStore,
  useBehaviorProfiles,
  type ProfileDiffSummary,
} from './stores/profilesStore';
import { applyMaterialTheme } from './theme/materialYou';
import type {
  AppNotification,
  AppSettings,
  BehaviorProfileId,
  BootstrapState,
  ConnectionStatus,
  KillSwitchConfig,
  NavTab,
  NotificationCategory,
  ProfileOverrides,
  ProxyProbeResult,
  RulepackStatus,
  SubscriptionRefreshDiff,
  ThemeMode,
  UpdateCheckResult,
} from './types/vpn';
import type { SettingsSection } from './views/SettingsView';
import { isRuBypassActive } from './utils/format';
import { looksLikeImportableText, splitSubscriptionUrls } from './utils/importHelpers';
import { HomeView } from './views/HomeView';

const ServersView = lazy(() =>
  import('./views/ServersView').then((m) => ({ default: m.ServersView })),
);
const SubscriptionsView = lazy(() =>
  import('./views/SubscriptionsView').then((m) => ({ default: m.SubscriptionsView })),
);
const RoutingView = lazy(() =>
  import('./views/RoutingView').then((m) => ({ default: m.RoutingView })),
);
const SettingsView = lazy(() =>
  import('./views/SettingsView').then((m) => ({ default: m.SettingsView })),
);
const MiniModeView = lazy(() =>
  import('./views/MiniModeView').then((m) => ({ default: m.MiniModeView })),
);
const CommandPalette = lazy(() =>
  import('./components/CommandPalette').then((m) => ({ default: m.CommandPalette })),
);
const ImportModal = lazy(() =>
  import('./components/ImportModal').then((m) => ({ default: m.ImportModal })),
);
const DiagnosticsDrawer = lazy(() =>
  import('./components/DiagnosticsDrawer').then((m) => ({ default: m.DiagnosticsDrawer })),
);
const OnboardingModal = lazy(() =>
  import('./components/OnboardingModal').then((m) => ({ default: m.OnboardingModal })),
);
const ProtectionCenterModal = lazy(() =>
  import('./components/ProtectionCenterModal').then((m) => ({ default: m.ProtectionCenterModal })),
);
const ConfigStudioModal = lazy(() =>
  import('./components/ConfigStudioModal').then((m) => ({ default: m.ConfigStudioModal })),
);
const ConnectionInspectorDrawer = lazy(() =>
  import('./components/ConnectionInspectorDrawer').then((m) => ({
    default: m.ConnectionInspectorDrawer,
  })),
);

function downloadJsonFile(filename: string, rawJson: string) {
  const blob = new Blob([rawJson], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function ViewFallback() {
  return (
    <div className="space-y-3 p-5">
      <M3Skeleton className="h-8 w-52" />
      <M3Skeleton className="h-28 w-full" />
      <M3Skeleton className="h-24 w-full" />
    </div>
  );
}

export function App() {
  const [state, setState] = useState<BootstrapState | null>(null);
  const [bootstrapError, setBootstrapError] = useState<string | null>(null);
  const [rulepackStatus, setRulepackStatus] = useState<RulepackStatus | null>(null);
  const [windowsAccentHex, setWindowsAccentHex] = useState<string | null>(null);
  const [systemPrefersDark, setSystemPrefersDark] = useState<boolean>(() =>
    typeof window !== 'undefined' && window.matchMedia
      ? window.matchMedia('(prefers-color-scheme: dark)').matches
      : true,
  );

  const [tab, setTab] = useState<NavTab>('home');
  const [importOpen, setImportOpen] = useState(false);
  const [importPrefill, setImportPrefill] = useState('');
  const [diagnosticsOpen, setDiagnosticsOpen] = useState(false);
  const [configStudioServerId, setConfigStudioServerId] = useState<string | null>(null);
  const [connectionInspectorOpen, setConnectionInspectorOpen] = useState(false);
  const [speedTestingId, setSpeedTestingId] = useState<string | null>(null);
  const [protectionCenterOpen, setProtectionCenterOpen] = useState(false);
  const [settingsDeepLinkSection, setSettingsDeepLinkSection] = useState<SettingsSection | null>(
    null,
  );
  const [lastRefreshDiff, setLastRefreshDiff] = useState<SubscriptionRefreshDiff | null>(null);
  const [paletteOpen, setPaletteOpen] = useState<boolean>(() =>
    IS_PREVIEW_BUILD &&
    typeof window !== 'undefined' &&
    new URLSearchParams(window.location.search).get('palette') === '1',
  );
  const [miniMode, setMiniMode] = useState(() =>
    IS_PREVIEW_BUILD &&
    typeof window !== 'undefined' &&
    new URLSearchParams(window.location.search).get('mode') === 'mini',
  );
  const [alwaysOnTop, setAlwaysOnTop] = useState(false);
  const [externalIp, setExternalIp] = useState<string | null>(null);
  const [isFetchingIp, setIsFetchingIp] = useState(false);
  const [lastReconnectAt, setLastReconnectAt] = useState<number | null>(null);
  const [dnsStatus, setDnsStatus] = useState<'ok' | 'warn' | 'fail' | 'unknown'>('unknown');
  const [pendingProfileChange, setPendingProfileChange] = useState<{
    profileId: BehaviorProfileId;
    diff: ProfileDiffSummary;
  } | null>(null);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const [isPingingAll, setIsPingingAll] = useState(false);
  const [isAutoSelecting, setIsAutoSelecting] = useState(false);
  const [isProbingProxy, setIsProbingProxy] = useState(false);
  const [lastProbe, setLastProbe] = useState<ProxyProbeResult | null>(null);
  const [pingingIds, setPingingIds] = useState<Set<string>>(() => new Set());
  const [refreshingSubIds, setRefreshingSubIds] = useState<Set<string>>(() => new Set());
  const [updateResult, setUpdateResult] = useState<UpdateCheckResult | null>(null);
  const [isCheckingUpdates, setIsCheckingUpdates] = useState(false);

  const prevStatusRef = useRef<ConnectionStatus | null>(null);
  const prevKsBlockingRef = useRef<boolean>(false);
  const connectingManuallyRef = useRef<boolean>(false);
  const settingsRef = useRef<AppSettings | null>(null);
  const behaviorProfilesState = useBehaviorProfiles();

  useEffect(() => {
    if (state) {
      settingsRef.current = state.settings;
    }
  }, [state]);

  const pushToast = useCallback(
    (
      tone: ToastMessage['tone'],
      title: string,
      description?: string,
      category?: NotificationCategory,
      deepLink?: AppNotification['deepLink'],
    ) => {
      if (category) {
        const stored = notificationStore.push({
          category,
          tone,
          title,
          description,
          deepLink,
        });
        if (!stored) {
          return;
        }
      }
      const sysNotify = settingsRef.current?.systemNotifications ?? true;
      if (!sysNotify && tone !== 'error' && category) {
        return;
      }
      const id = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
      setToasts((prev) => [...prev.slice(-3), { id, tone, title, description }]);
      window.setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== id));
      }, 4200);
    },
    [],
  );

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  // Track OS dark/light preference dynamically
  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return;
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    setSystemPrefersDark(mq.matches);
    const onChange = (e: MediaQueryListEvent) => setSystemPrefersDark(e.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);

  useEffect(() => {
    if (tab !== 'settings' && settingsDeepLinkSection !== null) {
      setSettingsDeepLinkSection(null);
    }
  }, [tab, settingsDeepLinkSection]);

  useEffect(() => {
    const intervalSecs = state?.settings.autoCheckIpIntervalSecs ?? 0;
    if (!state || intervalSecs < 60) return;
    const id = window.setInterval(() => {
      const cur = settingsRef.current;
      if (!cur || (cur.autoCheckIpIntervalSecs ?? 0) < 60) return;
      if (state.connection.killSwitchEngaged || state.connection.killSwitch?.blockingActive) return;
      void api
        .checkIpMonitor(false, cur.preferredIpProvider)
        .then((nextIp) => setState((prev) => (prev ? { ...prev, ipMonitor: nextIp } : prev)))
        .catch(() => undefined);
    }, intervalSecs * 1000);
    return () => window.clearInterval(id);
  }, [
    state?.settings.autoCheckIpIntervalSecs,
    state?.connection.killSwitchEngaged,
    state?.connection.killSwitch?.blockingActive,
  ]);

  const autoUpdateCheckedRef = useRef(false);
  useEffect(() => {
    if (
      !state ||
      autoUpdateCheckedRef.current ||
      !state.settings.autoCheckUpdates ||
      !state.settings.updateFeedUrl ||
      state.connection.killSwitchEngaged ||
      state.connection.killSwitch?.blockingActive
    ) {
      return;
    }
    autoUpdateCheckedRef.current = true;
    void api
      .checkForUpdates()
      .then((res) => {
        setUpdateResult(res);
        if (res.updateAvailable && res.latestVersion) {
          pushToast('info', `Доступна v${res.latestVersion}`, res.message, 'update', {
            tab: 'settings',
            settingsSection: 'updates',
          });
        }
      })
      .catch(() => undefined);
  }, [state, pushToast]);

  const bootstrapApp = useCallback(async () => {
    setBootstrapError(null);
    try {
      const [boot, initialLogs, packStatus, winAccent, winMode] = await Promise.all([
        api.getBootstrapState(),
        api.getLogs(),
        api.getRulepackStatus(),
        api.getWindowsAccentColor().catch(() => null),
        api.getWindowModeState().catch(() => ({ miniMode: false, alwaysOnTop: false })),
      ]);

      setState(boot);
      settingsRef.current = boot.settings;
      prevStatusRef.current = boot.connection.status;
      prevKsBlockingRef.current = Boolean(
        boot.connection.killSwitchEngaged || boot.connection.killSwitch?.blockingActive,
      );
      liveStore.setInitialLogs(initialLogs);
      liveStore.setInitialTraffic(boot.traffic);
      setRulepackStatus(packStatus);
      setWindowsAccentHex(winAccent);

      if (IS_PREVIEW_BUILD) {
        const params = new URLSearchParams(window.location.search);
        const qMini = params.get('mode') === 'mini';
        setMiniMode(qMini || winMode.miniMode);
        setAlwaysOnTop(winMode.alwaysOnTop);
        if (params.get('palette') === '1') {
          setPaletteOpen(true);
        }
        const tabParam = params.get('tab') as NavTab | null;
        if (
          tabParam &&
          ['home', 'servers', 'subscriptions', 'routing', 'settings'].includes(tabParam)
        ) {
          setTab(tabParam);
        }
        if (params.get('modal') === 'import') {
          setImportOpen(true);
        }
        if (params.get('modal') === 'diagnostics') {
          setDiagnosticsOpen(true);
        }
        if (params.get('modal') === 'protection') {
          setProtectionCenterOpen(true);
        }
        if (params.get('preview') === 'connected') {
          const now = Date.now();
          liveStore.seedPreviewTraffic(
            Array.from({ length: 180 }, (_, i) => ({
              ts: now - (180 - i) * 1000,
              rx: Math.round((1.8 + Math.sin(i * 0.25) * 1.15 + (i % 5) * 0.35) * 1024 * 1024),
              tx: Math.round((0.35 + Math.cos(i * 0.2) * 0.18) * 1024 * 1024),
            })),
          );
        }
      } else {
        setMiniMode(winMode.miniMode);
        setAlwaysOnTop(winMode.alwaysOnTop);
      }

      // Background subscription recovery & interval auto-update (Tauri runtime)
      if (isTauriRuntime() && boot.subscriptions.length > 0) {
        const subsNeedingRefresh: Array<{ id: string; title: string; toastTitle: string }> = [];
        const nowMs = Date.now();

        for (const sub of boot.subscriptions) {
          const subServers = boot.profiles.filter((p) => p.subscriptionId === sub.id);
          const isStaleHwid =
            boot.settings.sendHwid &&
            subServers.length === 1 &&
            /hwid/i.test(subServers[0].name) &&
            /(не поддерж|not support|unsupport)/i.test(subServers[0].name);

          if (isStaleHwid) {
            subsNeedingRefresh.push({
              id: sub.id,
              title: sub.title,
              toastTitle: 'Подписка обновлена с HWID',
            });
            continue;
          }

          const rawServers = subServers.filter((p) => p.protocol === 'rawxray');
          const isLegacyUngroupedJson =
            rawServers.length > 1 &&
            rawServers.some(
              (p) => p.details.kind === 'rawxray' && p.details.data.nodeCount == null,
            ) &&
            new Set(rawServers.map((p) => p.name)).size < rawServers.length;

          if (isLegacyUngroupedJson) {
            subsNeedingRefresh.push({
              id: sub.id,
              title: sub.title,
              toastTitle: 'Список серверов обновлён',
            });
            continue;
          }

          if (sub.enabled && sub.autoUpdate && (sub.updateIntervalHours ?? 0) > 0) {
            const updatedAtMs = Date.parse(sub.updatedAt);
            const intervalMs = (sub.updateIntervalHours ?? 12) * 3_600_000;
            if (Number.isFinite(updatedAtMs) && nowMs - updatedAtMs >= intervalMs) {
              subsNeedingRefresh.push({
                id: sub.id,
                title: sub.title,
                toastTitle: 'Подписка синхронизирована',
              });
            }
          }
        }

        if (subsNeedingRefresh.length > 0) {
          void (async () => {
            for (const item of subsNeedingRefresh) {
              try {
                const outcome = await api.refreshSubscription(item.id);
                setState(outcome.state);
                setLastRefreshDiff(outcome.diff);
                pushToast('success', item.toastTitle, item.title);
              } catch {
                // Ignore offline startup refresh errors silently
              }
            }
          })();
        }
      }
    } catch (err) {
      const msg =
        typeof err === 'string'
          ? err
          : err instanceof Error
            ? err.message
            : 'Не удалось загрузить состояние приложения';
      setBootstrapError(msg);
      pushToast('error', 'Ошибка инициализации', msg);
    }
  }, [pushToast]);

  // Register Tauri event listeners BEFORE initial bootstrap so no early state updates are lost
  useEffect(() => {
    let active = true;
    const unlisteners: Array<() => void> = [];

    void (async () => {
      try {
        const [u1, u2, u3, u4, u5] = await Promise.all([
          api.onConnectionState((conn) => {
            const prevStatus = prevStatusRef.current;
            const prevKsBlocking = prevKsBlockingRef.current;
            const nextKsBlocking = Boolean(conn.killSwitchEngaged || conn.killSwitch?.blockingActive);
            prevStatusRef.current = conn.status;
            prevKsBlockingRef.current = nextKsBlocking;
            setState((prev) =>
              prev
                ? {
                    ...prev,
                    connection: conn,
                    killSwitch: conn.killSwitch ?? prev.killSwitch,
                  }
                : prev,
            );
            if (prevStatus === 'reconnecting' && conn.status === 'connected') {
              setLastReconnectAt(Date.now());
              pushToast('success', 'Соединение восстановлено', undefined, 'connection', { tab: 'home' });
            } else if (conn.status === 'error' && conn.errorMessage && !connectingManuallyRef.current) {
              pushToast('error', 'Ошибка подключения', conn.errorMessage, 'connection', { tab: 'home' });
            }
            if (nextKsBlocking && !prevKsBlocking) {
              pushToast(
                'info',
                'Kill Switch заблокировал трафик',
                conn.killSwitch?.lastReason ?? 'Снятие доступно в Центре защиты и на главном экране',
                'connection',
                { tab: 'home' },
              );
            }
            if (conn.status === 'disconnected') {
              liveStore.resetTraffic();
              setLastProbe(null);
              setExternalIp(null);
            }
          }),
          api.onTrafficStats((traffic) => {
            liveStore.pushTraffic(traffic);
          }),
          api.onLogEntry((entry) => {
            liveStore.pushLog(entry);
          }),
          api.onBootstrapSync((bootSync) => {
            settingsRef.current = bootSync.settings;
            setState(bootSync);
          }),
          api.onConnectionTimelineEvent((ev) => {
            liveStore.pushTimelineEvent(ev);
          }),
        ]);
        if (!active) {
          u1();
          u2();
          u3();
          u4();
          u5();
        } else {
          unlisteners.push(u1, u2, u3, u4, u5);
        }
        if (active) {
          await bootstrapApp();
        }
      } catch (err) {
        if (active) {
          setBootstrapError(typeof err === 'string' ? err : String(err));
        }
      }
    })();

    return () => {
      active = false;
      unlisteners.forEach((u) => u());
    };
  }, [bootstrapApp, pushToast]);

  const handleToggleMiniMode = useCallback(async () => {
    const nextMini = !miniMode;
    try {
      const res = await api.setMiniMode(nextMini, nextMini ? alwaysOnTop : false);
      setMiniMode(res.miniMode);
      setAlwaysOnTop(res.alwaysOnTop);
    } catch {
      setMiniMode(nextMini);
    }
  }, [miniMode, alwaysOnTop]);

  const handleToggleAlwaysOnTop = useCallback(async () => {
    const nextTop = !alwaysOnTop;
    try {
      const res = await api.setAlwaysOnTop(nextTop);
      setAlwaysOnTop(res.alwaysOnTop);
    } catch {
      setAlwaysOnTop(nextTop);
    }
  }, [alwaysOnTop]);

  // Keyboard shortcuts (Ctrl+K palette, Ctrl+Shift+M mini mode, Alt+1..5 navigation, Escape modal close)
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen((v) => !v);
        return;
      }
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === 'm') {
        e.preventDefault();
        void handleToggleMiniMode();
        return;
      }
      if (e.key === 'Escape') {
        if (paletteOpen) setPaletteOpen(false);
        else if (pendingProfileChange) setPendingProfileChange(null);
        else if (configStudioServerId) setConfigStudioServerId(null);
        else if (protectionCenterOpen) setProtectionCenterOpen(false);
        else if (connectionInspectorOpen) setConnectionInspectorOpen(false);
        else if (importOpen) setImportOpen(false);
        else if (diagnosticsOpen) setDiagnosticsOpen(false);
        return;
      }
      if (e.altKey && !e.ctrlKey && !e.metaKey) {
        const tabs: Record<string, NavTab> = {
          '1': 'home',
          '2': 'servers',
          '3': 'subscriptions',
          '4': 'routing',
          '5': 'settings',
        };
        const target = tabs[e.key];
        if (target) {
          e.preventDefault();
          if (miniMode) {
            void api
              .setMiniMode(false, false)
              .then((res) => {
                setMiniMode(res.miniMode);
                setAlwaysOnTop(res.alwaysOnTop);
              })
              .catch(() => setMiniMode(false));
          }
          setTab(target);
        }
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [
    importOpen,
    diagnosticsOpen,
    paletteOpen,
    pendingProfileChange,
    configStudioServerId,
    protectionCenterOpen,
    connectionInspectorOpen,
    miniMode,
    handleToggleMiniMode,
  ]);

  // Apply Material You dynamic tonal palette whenever appearance settings change
  useEffect(() => {
    if (!state) return;
    applyMaterialTheme(
      document.documentElement,
      state.settings,
      windowsAccentHex,
      systemPrefersDark,
    );
  }, [
    state?.settings.theme,
    state?.settings.accentPreset,
    state?.settings.customAccentHex,
    state?.settings.dynamicColor,
    state?.settings.uiScale,
    state?.settings.compactMode,
    state?.settings.animationsEnabled,
    state?.settings.backgroundStyle,
    windowsAccentHex,
    systemPrefersDark,
  ]);

  const disabledSubIds = useMemo(() => {
    if (!state) return new Set<string>();
    return new Set(state.subscriptions.filter((s) => !s.enabled).map((s) => s.id));
  }, [state]);

  const enabledProfiles = useMemo(() => {
    if (!state) return [];
    return state.profiles.filter((p) => !p.subscriptionId || !disabledSubIds.has(p.subscriptionId));
  }, [state, disabledSubIds]);

  const activeServer = useMemo(() => {
    if (enabledProfiles.length === 0 || !state) return null;
    const id = state.connection.activeServerId ?? state.settings.activeServerId;
    return enabledProfiles.find((p) => p.id === id) ?? enabledProfiles[0] ?? null;
  }, [enabledProfiles, state]);

  const studioServer = useMemo(() => {
    if (!configStudioServerId || !state) return null;
    return state.profiles.find((p) => p.id === configStudioServerId) ?? null;
  }, [configStudioServerId, state]);

  const activeRoutingCount = useMemo(() => {
    if (!state) return 0;
    const r = state.settings.routing;
    let count = r.customRules.filter((x) => x.enabled).length;
    if (r.bypassRuDomains && r.profile !== 'all_vpn') count += 1;
    if (r.splitTunnelMode !== 'all_vpn' && r.splitApps.length > 0) count += r.splitApps.length;
    return count;
  }, [state]);

  const handleSmartImport = async (
    raw: string,
    onProgress?: (current: number, total: number) => void,
    applyAdaptations?: boolean,
  ) => {
    const multiUrls = splitSubscriptionUrls(raw);
    if (multiUrls.length >= 2) {
      let okCount = 0;
      let totalNodes = 0;
      const failures: string[] = [];
      let latestState = state;

      for (let i = 0; i < multiUrls.length; i++) {
        onProgress?.(i + 1, multiUrls.length);
        try {
          const out = await api.smartImport(multiUrls[i], applyAdaptations);
          latestState = out.state;
          okCount += 1;
          totalNodes += out.importedCount;
        } catch (err) {
          failures.push(`${i + 1}. ${typeof err === 'string' ? err : String(err)}`);
        }
      }
      if (latestState) setState(latestState);
      if (okCount === 0) {
        throw new Error(failures.join('\n') || 'Не удалось загрузить ни одну подписку');
      }
      pushToast(
        failures.length > 0 ? 'info' : 'success',
        `Загружено подписок: ${okCount} из ${multiUrls.length}`,
        failures.length > 0
          ? `Узлов: ${totalNodes}. Ошибок: ${failures.length}`
          : `Всего добавлено узлов: ${totalNodes}`,
        'import',
        { tab: 'subscriptions' },
      );
      if (failures.length > 0) {
        throw new Error(failures.join('\n'));
      }
      return;
    }

    const outcome = await api.smartImport(raw, applyAdaptations);
    setState(outcome.state);
    if (outcome.kind === 'subscription') {
      pushToast(
        'success',
        `Подписка «${outcome.title ?? 'Профиль'}» загружена`,
        `Импортировано серверов: ${outcome.importedCount}`,
        'import',
        { tab: 'subscriptions' },
      );
    } else {
      pushToast(
        'success',
        outcome.importedCount === 1
          ? 'Сервер добавлен'
          : `Импортировано серверов: ${outcome.importedCount}`,
        outcome.skippedLines > 0
          ? `Пропущено некорректных строк: ${outcome.skippedLines}`
          : outcome.title ?? undefined,
        'import',
        { tab: 'servers' },
      );
    }
  };

  const handlePasteClipboard = async () => {
    try {
      const clip = (await api.readClipboard()).trim();
      if (!clip) {
        setImportPrefill('');
        setImportOpen(true);
        pushToast('info', 'Буфер обмена пуст', 'Вставьте ключ или выберите файл в окне импорта');
        return;
      }

      if (looksLikeImportableText(clip) && splitSubscriptionUrls(clip).length < 2) {
        if (/https?:\/\/|happ:\/\/|v2raytun:\/\/|hiddify:\/\/|sub:\/\//i.test(clip)) {
          pushToast('info', 'Загрузка подписки...', 'Обработка ссылки и перенаправлений');
        }
        await handleSmartImport(clip);
      } else {
        setImportPrefill(clip);
        setImportOpen(true);
      }
    } catch (err) {
      pushToast(
        'error',
        'Не удалось импортировать из буфера',
        typeof err === 'string' ? err : undefined,
      );
    }
  };

  const handleToggleConnect = async () => {
    if (!state) return;
    const status = state.connection.status;
    connectingManuallyRef.current = true;
    try {
      if (
        status === 'connected' ||
        status === 'connecting' ||
        status === 'verifying' ||
        status === 'switching' ||
        status === 'reconnecting'
      ) {
        const snap = await api.disconnect();
        liveStore.resetTraffic();
        setLastProbe(null);
        setState((prev) => (prev ? { ...prev, connection: snap } : prev));
      } else {
        liveStore.resetTraffic();
        setLastProbe(null);
        const snap = await api.connect(activeServer?.id ?? null);
        const freshBoot = await api.getBootstrapState();
        setState({ ...freshBoot, connection: snap });
        pushToast('success', 'Подключено', activeServer?.name);
      }
    } catch (err) {
      const boot = await api.getBootstrapState().catch(() => null);
      if (boot) setState(boot);
      pushToast(
        'error',
        'Не удалось подключиться',
        typeof err === 'string' ? err : undefined,
      );
    } finally {
      connectingManuallyRef.current = false;
    }
  };

  const handleDisengageKillSwitch = async () => {
    try {
      const snap = await api.disengageKillSwitch();
      setState((prev) =>
        prev
          ? {
              ...prev,
              connection: snap,
              killSwitch: snap.killSwitch ?? prev.killSwitch,
              needsKillSwitchElevation: false,
            }
          : prev,
      );
      pushToast('info', 'Блокировка Kill Switch снята', 'Сетевое соединение восстановлено');
    } catch (err) {
      pushToast(
        'error',
        'Ошибка снятия блокировки',
        typeof err === 'string' ? err : undefined,
      );
    }
  };

  const handleProbeProxy = async () => {
    setIsProbingProxy(true);
    try {
      const res = await api.probeActiveConnection();
      setLastProbe(res);
      pushToast(
        res.ok ? 'success' : 'error',
        res.ok ? `Туннель работает (${res.rttMs ?? '—'} мс)` : 'Прокси не отвечает',
        res.message,
      );
    } catch (err) {
      pushToast('error', 'Ошибка теста прокси', String(err));
    } finally {
      setIsProbingProxy(false);
    }
  };

  const handleConnectSpecific = async (id: string) => {
    connectingManuallyRef.current = true;
    try {
      liveStore.resetTraffic();
      setLastProbe(null);
      const snap = await api.connect(id);
      const boot = await api.getBootstrapState();
      setState({ ...boot, connection: snap });
      setTab('home');
    } catch (err) {
      const boot = await api.getBootstrapState().catch(() => null);
      if (boot) setState(boot);
      pushToast(
        'error',
        'Не удалось подключиться',
        typeof err === 'string' ? err : undefined,
      );
    } finally {
      connectingManuallyRef.current = false;
    }
  };

  const handleSelectServer = async (id: string) => {
    try {
      const next = await api.selectServer(id);
      setState(next);
    } catch (err) {
      pushToast(
        'error',
        'Ошибка переключения сервера',
        typeof err === 'string' ? err : undefined,
      );
    }
  };

  const handleToggleFavorite = async (id: string) => {
    try {
      const next = await api.toggleFavoriteServer(id);
      setState(next);
    } catch (err) {
      pushToast('error', 'Не удалось изменить избранное', String(err));
    }
  };

  const handleRenameServer = async (id: string, newName: string) => {
    try {
      const next = await api.renameServer(id, newName);
      setState(next);
    } catch (err) {
      pushToast('error', 'Ошибка переименования', String(err));
    }
  };

  const handleDeleteServer = async (id: string) => {
    try {
      const next = await api.deleteServer(id);
      setState(next);
      pushToast('info', 'Сервер удалён');
    } catch (err) {
      pushToast('error', 'Ошибка удаления', String(err));
    }
  };

  const handleBulkDeleteServers = async (ids: string[]) => {
    if (ids.length === 0) return;
    try {
      const next = await api.bulkDeleteServers(ids);
      setState(next);
      pushToast('info', `Удалено серверов: ${ids.length}`);
    } catch (err) {
      pushToast('error', 'Ошибка массового удаления', String(err));
    }
  };

  const handleBulkFavoriteServers = async (ids: string[], favorite: boolean) => {
    if (ids.length === 0) return;
    try {
      const next = await api.bulkSetFavoriteServers(ids, favorite);
      setState(next);
      pushToast(
        'info',
        favorite ? `Добавлено в избранное: ${ids.length}` : `Снято из избранного: ${ids.length}`,
      );
    } catch (err) {
      pushToast('error', 'Ошибка массового изменения избранного', String(err));
    }
  };

  const handlePingServer = async (id: string) => {
    setPingingIds((prev) => new Set(prev).add(id));
    try {
      await api.pingServer(id);
      const refreshed = await api.getBootstrapState();
      setState(refreshed);
      const prof = refreshed.profiles.find((p) => p.id === id);
      if (prof) {
        liveStore.recordServerLatencies([{ id: prof.id, latencyMs: prof.latencyMs ?? null }]);
      }
    } catch (err) {
      pushToast('error', 'Ошибка замера задержки', typeof err === 'string' ? err : String(err));
    } finally {
      setPingingIds((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }
  };

  const handlePingAll = async () => {
    setIsPingingAll(true);
    try {
      await api.pingAllServers();
      const refreshed = await api.getBootstrapState();
      setState(refreshed);
      liveStore.recordServerLatencies(
        refreshed.profiles.map((p) => ({ id: p.id, latencyMs: p.latencyMs ?? null })),
      );
    } catch (err) {
      pushToast('error', 'Ошибка массового пинга', typeof err === 'string' ? err : String(err));
    } finally {
      setIsPingingAll(false);
    }
  };

  const handleAutoSelectFastest = async () => {
    setIsAutoSelecting(true);
    try {
      const res = await api.autoSelectFastestServer();
      setState(res.state);
      liveStore.recordServerLatencies(
        res.state.profiles.map((p) => ({ id: p.id, latencyMs: p.latencyMs ?? null })),
      );
      pushToast('success', 'Выбран самый быстрый узел', `${res.serverName} (${res.latencyMs} мс)`);
    } catch (err) {
      pushToast(
        'error',
        'Не удалось выбрать сервер',
        typeof err === 'string' ? err : undefined,
      );
    } finally {
      setIsAutoSelecting(false);
    }
  };

  const handleRefreshSubscription = async (id: string) => {
    setRefreshingSubIds((prev) => new Set(prev).add(id));
    try {
      const outcome = await api.refreshSubscription(id);
      setState(outcome.state);
      setLastRefreshDiff(outcome.diff);
      const diffSummary = `+${outcome.diff.added} / -${outcome.diff.removed} / ~${outcome.diff.updated}`;
      pushToast('success', 'Подписка обновлена', diffSummary, 'subscription', { tab: 'subscriptions' });
    } catch (err) {
      const boot = await api.getBootstrapState().catch(() => null);
      if (boot) setState(boot);
      pushToast(
        'error',
        'Не удалось обновить подписку',
        typeof err === 'string' ? err : undefined,
        'subscription',
        { tab: 'subscriptions' },
      );
    } finally {
      setRefreshingSubIds((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }
  };

  const handleRollbackSubscription = async (id: string) => {
    try {
      const next = await api.rollbackSubscription(id);
      setState(next);
      setLastRefreshDiff(null);
      pushToast('info', 'Узлы подписки восстановлены из резервной копии');
    } catch (err) {
      pushToast('error', 'Не удалось выполнить откат подписки', String(err));
    }
  };

  const handleRefreshAllSubscriptions = async () => {
    if (!state) return;
    for (const sub of state.subscriptions) {
      await handleRefreshSubscription(sub.id);
    }
  };

  const handleRenameSubscription = async (id: string, title: string) => {
    try {
      const next = await api.renameSubscription(id, title);
      setState(next);
      pushToast('success', 'Подписка переименована');
    } catch (err) {
      pushToast('error', 'Ошибка переименования подписки', String(err));
    }
  };

  const handleToggleSubscriptionEnabled = async (id: string, enabled: boolean) => {
    try {
      const next = await api.toggleSubscriptionEnabled(id, enabled);
      setState(next);
      pushToast('info', enabled ? 'Подписка включена' : 'Подписка скрыта из списка серверов');
    } catch (err) {
      pushToast('error', 'Ошибка изменения статуса подписки', String(err));
    }
  };

  const handleUpdateSubscriptionConfig = async (
    id: string,
    autoUpdate: boolean,
    intervalHours: number | null,
  ) => {
    try {
      const next = await api.updateSubscriptionConfig(id, autoUpdate, intervalHours);
      setState(next);
    } catch (err) {
      pushToast('error', 'Ошибка настройки автообновления', String(err));
    }
  };

  const handleDeleteSubscription = async (id: string) => {
    try {
      const next = await api.deleteSubscription(id);
      setState(next);
      pushToast('info', 'Подписка удалена');
    } catch (err) {
      pushToast('error', 'Ошибка удаления подписки', String(err));
    }
  };

  const handleUpdateSettings = useCallback(async (next: AppSettings) => {
    const previous = settingsRef.current;
    settingsRef.current = next;
    try {
      const saved = await api.updateSettings(next);
      settingsRef.current = saved;
      setState((prev) => (prev ? { ...prev, settings: saved } : prev));
      return saved;
    } catch (err) {
      settingsRef.current = previous;
      pushToast(
        'error',
        'Ошибка сохранения настроек',
        typeof err === 'string' ? err : undefined,
      );
      return null;
    }
  }, [pushToast]);

  const patchSettings = useCallback(
    (updater: (cur: AppSettings) => AppSettings) => {
      const base = settingsRef.current ?? state?.settings;
      if (!base) return Promise.resolve(null);
      const next = updater(base);
      return handleUpdateSettings(next);
    },
    [handleUpdateSettings, state?.settings],
  );

  const handleToggleRuDirect = () => {
    void patchSettings((s) => {
      const current = s.routing;
      const active =
        current.profile === 'ru_direct' ||
        (current.profile !== 'all_vpn' && current.bypassRuDomains);
      const nextEnabled = !active;
      const nextProfile =
        nextEnabled && current.profile === 'all_vpn'
          ? 'ru_direct'
          : !nextEnabled && current.profile === 'ru_direct'
            ? 'all_vpn'
            : current.profile;
      return {
        ...s,
        routing: {
          ...current,
          profile: nextProfile,
          bypassRuDomains: nextEnabled,
        },
      };
    });
  };

  const handleCycleTheme = () => {
    void patchSettings((s) => {
      const order: ThemeMode[] = ['dark', 'light', 'system'];
      const idx = order.indexOf(s.theme);
      const nextTheme = order[(idx + 1) % order.length];
      return { ...s, theme: nextTheme };
    });
  };

  const handleSetKillSwitchConfig = async (config: KillSwitchConfig) => {
    try {
      const next = await api.setKillSwitchConfig(config);
      settingsRef.current = next.settings;
      setState(next);
    } catch (err) {
      pushToast('error', 'Ошибка настройки Kill Switch', String(err));
    }
  };

  const handleEmergencyRecover = async () => {
    try {
      const out = await api.emergencyRecoverNetwork();
      settingsRef.current = out.state.settings;
      setState(out.state);
      pushToast(
        out.report.needsElevation ? 'info' : 'success',
        'Экстренное восстановление сети выполнено',
        out.report.warnings[0] ?? 'Прокси и фильтры очищены',
      );
      return out.report;
    } catch (err) {
      pushToast('error', 'Ошибка восстановления сети', String(err));
      throw err;
    }
  };

  const handleApplyProfileOverrides = async (id: string, overrides: ProfileOverrides) => {
    try {
      const next = await api.applyProfileOverrides(id, overrides);
      setState(next);
      pushToast('success', 'Параметры профиля сохранены');
    } catch (err) {
      pushToast('error', 'Ошибка сохранения Overrides', String(err));
      throw err;
    }
  };

  const handleCheckIpMonitor = async (includeIpv6: boolean) => {
    try {
      const res = await api.checkIpMonitor(includeIpv6);
      setState((prev) => (prev ? { ...prev, ipMonitor: res } : prev));
    } catch (err) {
      pushToast('error', 'Ошибка проверки IP', String(err));
    }
  };

  const handleSetIpMask = async (maskIp: boolean) => {
    try {
      const res = await api.setIpMask(maskIp);
      setState((prev) => (prev ? { ...prev, ipMonitor: res } : prev));
    } catch (err) {
      pushToast('error', 'Ошибка переключения маски IP', String(err));
    }
  };

  const handleUpdateRulepack = async (url?: string | null) => {
    try {
      const status = await api.updateRulepack(url);
      setRulepackStatus(status);
      pushToast('success', 'Пакет российских правил обновлён', `Доменов: ${status.totalDomains}`);
    } catch (err) {
      pushToast('error', 'Не удалось обновить пакет правил', String(err));
    }
  };

  const handleRollbackRulepack = async () => {
    try {
      const status = await api.rollbackRulepack();
      setRulepackStatus(status);
      pushToast('info', 'Выполнен откат пакета правил РФ');
    } catch (err) {
      pushToast('error', 'Не удалось откатить пакет правил', String(err));
    }
  };

  const handleRelaunchAsAdmin = async () => {
    try {
      await api.relaunchAsAdmin();
    } catch (err) {
      pushToast(
        'error',
        'Не удалось запросить права администратора',
        typeof err === 'string' ? err : undefined,
      );
    }
  };

  const handleCheckUpdates = async () => {
    setIsCheckingUpdates(true);
    try {
      const res = await api.checkForUpdates();
      setUpdateResult(res);
      pushToast(
        res.updateAvailable ? 'success' : res.status === 'error' ? 'error' : 'info',
        res.updateAvailable ? `Доступна v${res.latestVersion}` : 'Проверка обновлений',
        res.message,
        'update',
        { tab: 'settings', settingsSection: 'updates' },
      );
    } catch (err) {
      pushToast('error', 'Ошибка проверки обновлений', String(err));
    } finally {
      setIsCheckingUpdates(false);
    }
  };

  const handleFetchExternalIp = async () => {
    setIsFetchingIp(true);
    try {
      const [ipRes, dnsRep] = await Promise.all([
        api.checkIpMonitor(false, state?.settings.preferredIpProvider),
        api.getDnsInspectorReport().catch(() => null),
      ]);
      if (dnsRep) {
        setDnsStatus(
          dnsRep.configAnalysis.leakRiskLevel === 'low'
            ? 'ok'
            : dnsRep.configAnalysis.leakRiskLevel === 'medium'
              ? 'warn'
              : 'fail',
        );
      }
      setState((prev) => (prev ? { ...prev, ipMonitor: ipRes } : prev));
      const chosenIp =
        state?.connection.status === 'connected' ? ipRes.vpnIp?.ip ?? null : ipRes.originalIp?.ip ?? null;
      if (chosenIp) {
        setExternalIp(chosenIp);
      } else {
        pushToast('info', 'Внешний IP', ipRes.comparisonNote ?? 'Не удалось определить IP');
      }
    } catch (err) {
      pushToast('error', 'Ошибка запроса внешнего IP', String(err));
    } finally {
      setIsFetchingIp(false);
    }
  };

  const handleSpeedTestServer = async (id: string) => {
    setSpeedTestingId(id);
    try {
      const res = await api.runServerSpeedTest(id);
      pushToast('success', `Скорость: ${res.mbps.toFixed(1)} Мбит/с`, res.note);
    } catch (err) {
      pushToast('error', 'Ошибка замера скорости', String(err));
    } finally {
      setSpeedTestingId(null);
    }
  };

  const handleCopyExternalIp = async () => {
    if (!externalIp) return;
    try {
      await navigator.clipboard?.writeText(externalIp);
      pushToast('success', 'Внешний IP скопирован', externalIp);
    } catch {
      // Ignore clipboard unavailability
    }
  };

  const applyBehaviorProfileNow = async (
    id: BehaviorProfileId,
    forceReconnect = false,
  ) => {
    if (!state) return;
    try {
      const target = behaviorProfilesState.profiles[id];
      const nextSettings = applyBehaviorProfileToSettings(state.settings, target);
      const saved = await handleUpdateSettings(nextSettings);
      if (!saved) return;
      profilesStore.setActiveProfileId(id);
      if (forceReconnect && state.connection.status === 'connected') {
        const snap = await api.connect(nextSettings.activeServerId ?? activeServer?.id ?? null);
        const fresh = await api.getBootstrapState();
        setState({ ...fresh, connection: snap });
        pushToast('success', `Профиль «${target.name}» применён`, 'Туннель переподключён');
      } else {
        pushToast('success', `Профиль «${target.name}» применён`);
      }
    } catch (err) {
      pushToast('error', 'Не удалось применить профиль', String(err));
    }
  };

  const handleSelectBehaviorProfile = (id: BehaviorProfileId) => {
    if (!state) return;
    const target = behaviorProfilesState.profiles[id];
    const diff = analyzeProfileDiff(
      state.settings,
      target,
      state.connection.status === 'connected',
    );
    if (diff.securityDowngrades.length > 0 || diff.requiresReconnect) {
      setPendingProfileChange({ profileId: id, diff });
    } else {
      void applyBehaviorProfileNow(id, false);
    }
  };

  const handleNavigateNotification = (link: NonNullable<AppNotification['deepLink']>) => {
    if (miniMode) {
      void api
        .setMiniMode(false, false)
        .then((res) => {
          setMiniMode(res.miniMode);
          setAlwaysOnTop(res.alwaysOnTop);
        })
        .catch(() => setMiniMode(false));
    }
    setTab(link.tab);
    if (link.settingsSection && link.tab === 'settings') {
      setSettingsDeepLinkSection(link.settingsSection as SettingsSection);
    }
    if (link.openDiagnostics) {
      void handleOpenDiagnostics();
    }
  };

  const handleOpenDiagnostics = async () => {
    setDiagnosticsOpen(true);
    try {
      const [diag, freshLogs] = await Promise.all([api.getDiagnostics(), api.getLogs()]);
      liveStore.setInitialLogs(freshLogs);
      setState((prev) => (prev ? { ...prev, diagnostics: diag } : prev));
    } catch (err) {
      pushToast('error', 'Ошибка загрузки диагностики', String(err));
    }
  };

  const handleExportDiagnostics = async () => {
    try {
      const bundle = await api.exportDiagnosticsBundle();
      downloadJsonFile(`aura-diagnostics-${new Date().toISOString().slice(0, 10)}.json`, bundle);
      pushToast('success', 'Диагностический отчёт сохранён', 'Персональные токены и HWID скрыты');
    } catch (err) {
      pushToast('error', 'Ошибка экспорта диагностики', String(err));
    }
  };

  const handleExportSettings = async () => {
    try {
      const raw = await api.exportSettingsBackup();
      downloadJsonFile(`aura-settings-${new Date().toISOString().slice(0, 10)}.json`, raw);
      pushToast('success', 'Резервная копия настроек сохранена');
    } catch (err) {
      pushToast('error', 'Ошибка экспорта настроек', String(err));
    }
  };

  const handleImportSettings = async (rawJson: string) => {
    try {
      const saved = await api.importSettingsBackup(rawJson);
      setState((prev) => (prev ? { ...prev, settings: saved } : prev));
      pushToast('success', 'Настройки восстановлены из резервной копии');
    } catch (err) {
      pushToast('error', 'Ошибка импорта настроек', String(err));
    }
  };

  const handleResetSettings = async () => {
    try {
      const freshState = await api.resetSettingsToDefault();
      notificationStore.clear();
      liveStore.clearLatencyMeta();
      profilesStore.resetAll();
      setState(freshState);
      pushToast('info', 'Настройки сброшены до значений по умолчанию');
    } catch (err) {
      pushToast('error', 'Ошибка сброса настроек', String(err));
    }
  };

  if (bootstrapError && !state) {
    return (
      <div className="flex h-full w-full items-center justify-center bg-[var(--md-surface)] p-6 text-[var(--md-on-surface)]">
        <M3SurfaceCard className="w-full max-w-md p-6 text-center">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-[var(--md-error-container)] text-[var(--md-error)]">
            <AlertTriangle className="h-6 w-6" />
          </div>
          <h1 className="mt-4 font-display text-base font-bold">
            Не удалось запустить AURA VPN
          </h1>
          <p className="mt-1.5 text-xs text-[var(--md-on-surface-variant)]">{bootstrapError}</p>
          <div className="mt-5 flex justify-center">
            <M3Button
              variant="filled"
              leadingIcon={<RotateCw className="h-4 w-4" />}
              onClick={() => void bootstrapApp()}
            >
              Повторить
            </M3Button>
          </div>
        </M3SurfaceCard>
      </div>
    );
  }

  if (!state) {
    return (
      <div className="flex h-full w-full flex-col bg-[var(--md-surface)]">
        <div className="h-9.5 border-b border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] px-4 flex items-center">
          <M3Skeleton className="h-4 w-32" />
        </div>
        <div className="flex min-h-0 flex-1">
          <div className="w-[74px] border-r border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] p-3 space-y-3">
            <M3Skeleton className="h-10 w-10 rounded-2xl" />
            <M3Skeleton className="h-8 w-10 rounded-xl" />
            <M3Skeleton className="h-8 w-10 rounded-xl" />
          </div>
          <div className="flex-1 p-5 space-y-4">
            <M3Skeleton className="h-6 w-48" />
            <M3Skeleton className="h-44 w-full rounded-2xl" />
            <M3Skeleton className="h-14 w-full rounded-2xl" />
            <div className="grid grid-cols-3 gap-2.5">
              <M3Skeleton className="h-20 w-full rounded-2xl" />
              <M3Skeleton className="h-20 w-full rounded-2xl" />
              <M3Skeleton className="h-20 w-full rounded-2xl" />
            </div>
          </div>
        </div>
      </div>
    );
  }

  const ruDirectActive = isRuBypassActive(state.settings.routing);

  const showOnboarding =
    !state.settings.onboardingCompleted &&
    state.profiles.length === 0 &&
    state.subscriptions.length === 0;

  const isBrowserMiniPreview = miniMode && !isTauriRuntime();
  const isKsActive =
    (state.settings.killSwitch?.mode ?? 'off') !== 'off' || state.settings.killSwitchEnabled;
  const isKsBlocking = Boolean(
    state.connection.killSwitchEngaged || state.connection.killSwitch?.blockingActive,
  );
  const toggleQuickKillSwitch = () => {
    const base = state.settings.killSwitch ?? {
      mode: 'off' as const,
      allowLan: true,
      blockIpv6Leaks: true,
      persistOnExit: false,
      reconnectAttempts: 3,
    };
    void handleSetKillSwitchConfig({
      ...base,
      mode: base.mode === 'off' ? 'on_drop' : 'off',
    });
  };

  const shellContent = (
    <div className="flex h-full w-full flex-col overflow-hidden bg-transparent text-[var(--md-on-surface)]">
      <TitleBar
        theme={state.settings.theme}
        status={state.connection.status}
        mode={state.settings.connectionMode}
        ruDirectActive={ruDirectActive}
        killSwitchEnabled={isKsActive}
        killSwitchEngaged={isKsBlocking}
        miniMode={miniMode}
        alwaysOnTop={alwaysOnTop}
        onCycleTheme={handleCycleTheme}
        onOpenDiagnostics={() => void handleOpenDiagnostics()}
        onOpenCommandPalette={() => setPaletteOpen(true)}
        onToggleMiniMode={() => void handleToggleMiniMode()}
        onToggleAlwaysOnTop={() => void handleToggleAlwaysOnTop()}
        onNavigateNotification={handleNavigateNotification}
        onMinimize={() => void api.windowMinimize()}
        onClose={() => void api.windowCloseAction()}
      />

      {state.needsKillSwitchElevation && (
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--md-error)]/30 bg-[var(--md-error-container)] px-4 py-2 text-[0.75rem] text-[var(--md-error)]">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 shrink-0" />
            <span>
              От прошлой сессии осталось правило брандмауэра Kill Switch. Перезапустите с правами администратора для его автоматического снятия.
            </span>
          </div>
          <M3Button variant="danger" size="sm" onClick={() => void handleRelaunchAsAdmin()}>
            Снять с правами UAC
          </M3Button>
        </div>
      )}

      {miniMode ? (
        <main className="min-h-0 flex-1 overflow-hidden bg-transparent">
          <Suspense fallback={<ViewFallback />}>
            <MiniModeView
              profiles={enabledProfiles}
              activeServer={activeServer}
              connection={state.connection}
              settings={state.settings}
              isPingingActive={activeServer ? pingingIds.has(activeServer.id) : false}
              isAutoSelecting={isAutoSelecting}
              onToggleConnect={() => void handleToggleConnect()}
              onSelectServer={(id) => void handleSelectServer(id)}
              onPingActive={(id) => void handlePingServer(id)}
              onAutoSelectFastest={() => void handleAutoSelectFastest()}
              onToggleMode={(mode) =>
                void patchSettings((s) => ({ ...s, connectionMode: mode }))
              }
              onToggleRuDirect={handleToggleRuDirect}
              onToggleKillSwitch={toggleQuickKillSwitch}
              onOpenFullMode={() => void handleToggleMiniMode()}
              onOpenDiagnostics={() => void handleOpenDiagnostics()}
            />
          </Suspense>
        </main>
      ) : (
        <div className="flex min-h-0 flex-1">
          <NavigationRail
            activeTab={tab}
            expanded={state.settings.sidebarExpanded}
            serverCount={enabledProfiles.length}
            subscriptionCount={state.subscriptions.length}
            activeRoutingCount={activeRoutingCount}
            diagnostics={state.diagnostics}
            onSelectTab={setTab}
            onToggleExpanded={() =>
              void patchSettings((s) => ({
                ...s,
                sidebarExpanded: !s.sidebarExpanded,
              }))
            }
            onOpenImport={() => {
              setImportPrefill('');
              setImportOpen(true);
            }}
            onPasteClipboard={() => void handlePasteClipboard()}
            onOpenDiagnostics={() => void handleOpenDiagnostics()}
          />

          <main className="min-w-0 flex-1 overflow-hidden bg-transparent">
            {tab === 'home' ? (
              <HomeView
                profiles={enabledProfiles}
                activeServer={activeServer}
                connection={state.connection}
                settings={state.settings}
                serverQuality={state.serverQuality}
                isPinging={activeServer ? pingingIds.has(activeServer.id) : false}
                isAutoSelecting={isAutoSelecting}
                isProbingProxy={isProbingProxy}
                lastProbe={lastProbe}
                externalIp={externalIp}
                maskExternalIp={state.ipMonitor?.maskIp ?? true}
                isFetchingIp={isFetchingIp}
                lastReconnectAt={lastReconnectAt}
                dnsStatus={dnsStatus}
                onToggleConnect={() => void handleToggleConnect()}
                onDisengageKillSwitch={() => void handleDisengageKillSwitch()}
                onSelectServer={(id) => void handleSelectServer(id)}
                onPingActive={(id) => void handlePingServer(id)}
                onProbeProxy={() => void handleProbeProxy()}
                onFetchExternalIp={() => void handleFetchExternalIp()}
                onCopyExternalIp={() => void handleCopyExternalIp()}
                onAutoSelectFastest={() => void handleAutoSelectFastest()}
                onChangeMode={(mode) =>
                  void patchSettings((s) => ({ ...s, connectionMode: mode }))
                }
                onToggleRuDirect={handleToggleRuDirect}
                onToggleKillSwitch={toggleQuickKillSwitch}
                onSelectBehaviorProfile={handleSelectBehaviorProfile}
                onOpenImport={() => {
                  setImportPrefill('');
                  setImportOpen(true);
                }}
                onPasteClipboard={() => void handlePasteClipboard()}
                onOpenDiagnostics={() => void handleOpenDiagnostics()}
                onOpenConnectionInspector={() => setConnectionInspectorOpen(true)}
                onOpenRouting={() => setTab('routing')}
                onOpenSettings={() => setTab('settings')}
                onRelaunchAdmin={() => void handleRelaunchAsAdmin()}
                onOpenProtectionCenter={() => setProtectionCenterOpen(true)}
                onInspectServer={(id) => setConfigStudioServerId(id)}
              />
            ) : (
              <div className="aura-scroll h-full overflow-y-auto px-5 py-4">
                <Suspense fallback={<ViewFallback />}>
                  {tab === 'servers' && (
                    <ServersView
                      profiles={state.profiles}
                      subscriptions={state.subscriptions}
                      activeServerId={activeServer?.id}
                      connectedServerId={state.connection.activeServerId}
                      connectionStatus={state.connection.status}
                      compactDefault={state.settings.compactMode}
                      serverQuality={state.serverQuality}
                      isPingingAll={isPingingAll}
                      pingingIds={pingingIds}
                      onSelect={(id) => void handleSelectServer(id)}
                      onConnect={(id) => void handleConnectSpecific(id)}
                      onToggleFavorite={(id) => void handleToggleFavorite(id)}
                      onPing={(id) => void handlePingServer(id)}
                      onPingAll={() => void handlePingAll()}
                      onAutoSelect={() => void handleAutoSelectFastest()}
                      onRename={(id, name) => void handleRenameServer(id, name)}
                      onDelete={(id) => void handleDeleteServer(id)}
                      onBulkDelete={handleBulkDeleteServers}
                      onBulkFavorite={handleBulkFavoriteServers}
                      onOpenImport={() => {
                        setImportPrefill('');
                        setImportOpen(true);
                      }}
                      onGoToSubscriptions={() => setTab('subscriptions')}
                      onOpenConfigStudio={(id) => setConfigStudioServerId(id)}
                      onSpeedTest={handleSpeedTestServer}
                      speedTestingId={speedTestingId}
                    />
                  )}

                  {tab === 'subscriptions' && (
                    <SubscriptionsView
                      subscriptions={state.subscriptions}
                      profiles={state.profiles}
                      refreshingIds={refreshingSubIds}
                      lastRefreshDiff={lastRefreshDiff}
                      onRefresh={(id) => void handleRefreshSubscription(id)}
                      onRollback={(id) => void handleRollbackSubscription(id)}
                      onRefreshAll={() => void handleRefreshAllSubscriptions()}
                      onRename={(id, title) => void handleRenameSubscription(id, title)}
                      onToggleEnabled={(id, enabled) =>
                        void handleToggleSubscriptionEnabled(id, enabled)
                      }
                      onUpdateConfig={(id, auto, hrs) =>
                        void handleUpdateSubscriptionConfig(id, auto, hrs)
                      }
                      onDelete={(id) => void handleDeleteSubscription(id)}
                      onOpenImport={() => {
                        setImportPrefill('');
                        setImportOpen(true);
                      }}
                    />
                  )}

                  {tab === 'routing' && (
                    <RoutingView
                      settings={state.settings}
                      rulepackStatus={rulepackStatus}
                      onUpdateRouting={(routing) =>
                        void patchSettings((s) => ({ ...s, routing }))
                      }
                      onSwitchToTun={() => {
                        void patchSettings((s) => ({ ...s, connectionMode: 'tun' }));
                        pushToast(
                          'info',
                          'Выбран режим TUN',
                          'Правила по приложениям применяются автоматически',
                        );
                      }}
                      onUpdateRulepack={handleUpdateRulepack}
                      onRollbackRulepack={handleRollbackRulepack}
                      onNotify={pushToast}
                    />
                  )}

                  {tab === 'settings' && (
                    <SettingsView
                      settings={state.settings}
                      connection={state.connection}
                      diagnostics={state.diagnostics}
                      rulepackStatus={rulepackStatus}
                      windowsAccentHex={windowsAccentHex}
                      updateResult={updateResult}
                      isCheckingUpdate={isCheckingUpdates}
                      initialSection={settingsDeepLinkSection}
                      ipMonitor={state.ipMonitor}
                      onSyncIpMonitor={(ipMon) =>
                        setState((prev) => (prev ? { ...prev, ipMonitor: ipMon } : prev))
                      }
                      onUpdateSettings={(next) => void handleUpdateSettings(next)}
                      onSetKillSwitchConfig={handleSetKillSwitchConfig}
                      onEmergencyRecover={async () => {
                        await handleEmergencyRecover();
                      }}
                      onOpenProtectionCenter={() => setProtectionCenterOpen(true)}
                      onOpenConnectionInspector={() => setConnectionInspectorOpen(true)}
                      onOpenRouting={() => setTab('routing')}
                      onRefreshBootstrap={async () => {
                        const fresh = await api.getBootstrapState();
                        setState(fresh);
                      }}
                      onSelectBehaviorProfile={handleSelectBehaviorProfile}
                      onRelaunchAdmin={() => void handleRelaunchAsAdmin()}
                      onCheckUpdates={() => void handleCheckUpdates()}
                      onOpenDiagnostics={() => void handleOpenDiagnostics()}
                      onExportDiagnostics={handleExportDiagnostics}
                      onExportSettings={handleExportSettings}
                      onImportSettings={handleImportSettings}
                      onResetSettings={handleResetSettings}
                    />
                  )}
                </Suspense>
              </div>
            )}
          </main>
        </div>
      )}

      <Suspense fallback={null}>
        {paletteOpen && (
          <CommandPalette
            open={paletteOpen}
            onClose={() => setPaletteOpen(false)}
            status={state.connection.status}
            profiles={enabledProfiles}
            subscriptions={state.subscriptions}
            behaviorProfiles={Object.values(behaviorProfilesState.profiles)}
            onToggleConnect={() => void handleToggleConnect()}
            onAutoSelectFastest={() => void handleAutoSelectFastest()}
            onRefreshAllSubs={() => void handleRefreshAllSubscriptions()}
            onOpenDiagnostics={() => void handleOpenDiagnostics()}
            onCycleTheme={handleCycleTheme}
            onToggleMiniMode={() => void handleToggleMiniMode()}
            onSelectTab={(nextTab, settingsSection) => {
              if (miniMode) void handleToggleMiniMode();
              setTab(nextTab);
              if (settingsSection && nextTab === 'settings') {
                setSettingsDeepLinkSection(settingsSection as SettingsSection);
              }
            }}
            onSelectServer={(id) => void handleSelectServer(id)}
            onConnectServer={(id) => void handleConnectSpecific(id)}
            onApplyBehaviorProfile={handleSelectBehaviorProfile}
          />
        )}

        {importOpen && (
          <ImportModal
            open={importOpen}
            initialText={importPrefill}
            onClose={() => setImportOpen(false)}
            onSmartImport={handleSmartImport}
          />
        )}

        {diagnosticsOpen && (
          <DiagnosticsDrawer
            open={diagnosticsOpen}
            diagnostics={state.diagnostics}
            onClose={() => setDiagnosticsOpen(false)}
            onClearLogs={() => {
              void api
                .clearLogs()
                .then(() => liveStore.clearLogs())
                .catch((err) => pushToast('error', 'Ошибка очистки журнала', String(err)));
            }}
            onExportDiagnostics={handleExportDiagnostics}
          />
        )}

        {showOnboarding && (
          <OnboardingModal
            open={showOnboarding}
            onComplete={() =>
              void patchSettings((s) => ({ ...s, onboardingCompleted: true }))
            }
            onOpenImport={() => {
              setImportPrefill('');
              setImportOpen(true);
            }}
            onPasteClipboard={() => void handlePasteClipboard()}
          />
        )}

        {configStudioServerId && (
          <ConfigStudioModal
            open={Boolean(studioServer)}
            server={studioServer}
            onClose={() => setConfigStudioServerId(null)}
            onApplyOverrides={handleApplyProfileOverrides}
            onAfterProfileChange={async () => {
              const fresh = await api.getBootstrapState();
              setState(fresh);
            }}
          />
        )}

        {connectionInspectorOpen && (
          <ConnectionInspectorDrawer
            open={connectionInspectorOpen}
            onClose={() => setConnectionInspectorOpen(false)}
          />
        )}

        {protectionCenterOpen && (
          <ProtectionCenterModal
            open={protectionCenterOpen}
            onClose={() => setProtectionCenterOpen(false)}
            onCheckIp={handleCheckIpMonitor}
            onSetIpMask={handleSetIpMask}
            onEmergencyRecover={handleEmergencyRecover}
            onDisengageKillSwitch={handleDisengageKillSwitch}
            onOpenSecuritySettings={() => {
              setProtectionCenterOpen(false);
              setTab('settings');
              setSettingsDeepLinkSection('security');
            }}
          />
        )}
      </Suspense>

      {/* Behavior profile confirmation / security downgrade warning */}
      <M3Dialog
        open={pendingProfileChange !== null}
        onClose={() => setPendingProfileChange(null)}
        title={
          pendingProfileChange
            ? `Применить профиль «${behaviorProfilesState.profiles[pendingProfileChange.profileId].name}»?`
            : 'Применить профиль'
        }
        description="Смена профиля изменяет параметры активной или будущей VPN-сессии."
        footer={
          <>
            <M3Button variant="text" onClick={() => setPendingProfileChange(null)}>
              Отмена
            </M3Button>
            {pendingProfileChange?.diff.requiresReconnect ? (
              <M3Button
                variant="filled"
                onClick={() => {
                  const pid = pendingProfileChange.profileId;
                  setPendingProfileChange(null);
                  void applyBehaviorProfileNow(pid, true);
                }}
              >
                Применить и переподключить
              </M3Button>
            ) : (
              <M3Button
                variant="filled"
                onClick={() => {
                  if (!pendingProfileChange) return;
                  const pid = pendingProfileChange.profileId;
                  setPendingProfileChange(null);
                  void applyBehaviorProfileNow(pid, false);
                }}
              >
                Подтвердить
              </M3Button>
            )}
          </>
        }
      >
        {pendingProfileChange && (
          <div className="space-y-2.5 text-[0.76rem]">
            {pendingProfileChange.diff.securityDowngrades.length > 0 && (
              <div className="rounded-xl border border-[var(--md-warning)]/40 bg-[var(--md-warning-container)] p-3 space-y-1">
                <div className="font-bold text-[var(--md-on-surface)]">
                  Предупреждение о снижении уровня защиты:
                </div>
                <ul className="list-disc pl-4 space-y-0.5 text-[var(--md-on-surface)]">
                  {pendingProfileChange.diff.securityDowngrades.map((item, idx) => (
                    <li key={idx}>{item}</li>
                  ))}
                </ul>
              </div>
            )}
            {pendingProfileChange.diff.changesSummary.length > 0 && (
              <ul className="list-disc pl-4 space-y-0.5 text-[var(--md-on-surface-variant)]">
                {pendingProfileChange.diff.changesSummary.map((item, idx) => (
                  <li key={idx}>{item}</li>
                ))}
              </ul>
            )}
          </div>
        )}
      </M3Dialog>

      <ToastContainer toasts={toasts} onDismiss={dismissToast} />
    </div>
  );

  return (
    <MotionConfig reducedMotion={state.settings.animationsEnabled ? 'user' : 'always'}>
      {isBrowserMiniPreview ? (
        <div className="flex h-full w-full items-center justify-center bg-[var(--md-surface-container-lowest)] p-4">
          <div className="h-[540px] w-[380px] overflow-hidden rounded-3xl border border-[var(--md-outline-variant)] shadow-2xl">
            {shellContent}
          </div>
        </div>
      ) : (
        shellContent
      )}
    </MotionConfig>
  );
}

export default App;
