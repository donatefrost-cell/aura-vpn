import {
  Activity,
  AlertTriangle,
  ClipboardPaste,
  Copy,
  GitFork,
  Globe,
  Plus,
  RotateCw,
  Settings,
  Shield,
  ShieldAlert,
  Sliders,
  Unlock,
  Zap,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import { AuraLogo } from '../components/AuraLogo';
import { ConnectionDial } from '../components/ConnectionDial';
import {
  M3Button,
  M3Chip,
  M3SegmentedButton,
  M3Select,
  M3StatusBadge,
  M3SurfaceCard,
  M3Tooltip,
} from '../components/md3';
import { ServerQuickPick } from '../components/ServerQuickPick';
import { TelemetryStrip } from '../components/TelemetryStrip';
import { TrafficGraph } from '../components/TrafficGraph';
import { useBehaviorProfiles } from '../stores/profilesStore';
import type {
  AppSettings,
  BehaviorProfileId,
  ConnectionMode,
  ConnectionSnapshot,
  ProxyProbeResult,
  ServerProfile,
  ServerQualityMetrics,
} from '../types/vpn';
import {
  formatDuration,
  formatNodePoolLabel,
  formatServerDisplayName,
  getCountryName,
  getProfileNodeCount,
  isRuBypassActive,
} from '../utils/format';

interface HomeViewProps {
  profiles: ServerProfile[];
  activeServer: ServerProfile | null;
  connection: ConnectionSnapshot;
  settings: AppSettings;
  serverQuality?: Record<string, ServerQualityMetrics>;
  isPinging: boolean;
  isAutoSelecting: boolean;
  isProbingProxy: boolean;
  lastProbe: ProxyProbeResult | null;
  externalIp: string | null;
  maskExternalIp?: boolean;
  isFetchingIp: boolean;
  lastReconnectAt: number | null;
  dnsStatus: 'ok' | 'warn' | 'fail' | 'unknown';
  onToggleConnect: () => void;
  onDisengageKillSwitch: () => void;
  onSelectServer: (id: string) => void;
  onPingActive: (id: string) => void;
  onProbeProxy: () => void;
  onFetchExternalIp: () => void;
  onCopyExternalIp: () => void;
  onAutoSelectFastest: () => void;
  onChangeMode: (mode: ConnectionMode) => void;
  onToggleRuDirect: () => void;
  onToggleKillSwitch: () => void;
  onToggleClaudeGuard?: () => void;
  onSelectBehaviorProfile: (id: BehaviorProfileId) => void;
  onOpenImport: () => void;
  onPasteClipboard: () => void;
  onOpenDiagnostics: () => void;
  onOpenConnectionInspector?: () => void;
  onOpenRouting?: () => void;
  onOpenSettings?: () => void;
  onRelaunchAdmin?: () => void;
  onOpenProtectionCenter?: () => void;
  onInspectServer?: (id: string) => void;
}

function formatTimeShort(ts: number): string {
  return new Date(ts).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
}

function maskIpHome(ip: string, mask: boolean): string {
  if (!mask) return ip;
  if (ip.includes('.')) {
    const parts = ip.split('.');
    if (parts.length === 4) return `${parts[0]}.${parts[1]}.•.•`;
  }
  return ip.length > 9 ? `${ip.slice(0, 9)}••••` : '•••';
}

export function HomeView({
  profiles,
  activeServer,
  connection,
  settings,
  serverQuality,
  isPinging,
  isAutoSelecting,
  isProbingProxy,
  lastProbe,
  externalIp,
  maskExternalIp = true,
  isFetchingIp,
  lastReconnectAt,
  dnsStatus,
  onToggleConnect,
  onDisengageKillSwitch,
  onSelectServer,
  onPingActive,
  onProbeProxy,
  onFetchExternalIp,
  onCopyExternalIp,
  onAutoSelectFastest,
  onChangeMode,
  onToggleRuDirect,
  onToggleKillSwitch,
  onToggleClaudeGuard,
  onSelectBehaviorProfile,
  onOpenImport,
  onPasteClipboard,
  onOpenDiagnostics,
  onOpenConnectionInspector,
  onOpenRouting,
  onOpenSettings,
  onRelaunchAdmin,
  onOpenProtectionCenter,
  onInspectServer,
}: HomeViewProps) {
  const [nowMs, setNowMs] = useState(() => Date.now());
  const behaviorState = useBehaviorProfiles();

  useEffect(() => {
    if (connection.status !== 'connected' || !connection.connectedSince) return;
    setNowMs(Date.now());
    const id = window.setInterval(() => setNowMs(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, [connection.status, connection.connectedSince]);

  const ruDirectActive = isRuBypassActive(settings.routing);

  if (profiles.length === 0) {
    return (
      <div className="flex h-full flex-col items-center justify-center px-8">
        <M3SurfaceCard className="w-full max-w-[480px] p-7 text-center">
          <div className="mx-auto flex h-14 w-14 items-center justify-center">
            <AuraLogo variant="mark" className="h-14 w-14" />
          </div>
          <h1 className="mt-4 font-display text-[1.25rem] font-bold tracking-tight text-[var(--md-on-surface)]">
            Добро пожаловать в AURA VPN
          </h1>
          <p className="mt-2 text-[0.8125rem] leading-relaxed text-[var(--md-on-surface-variant)]">
            Добавьте VPN-ключ доступа или ссылку подписки — профиль, флаг страны и протокол определятся автоматически.
          </p>

          <div className="mt-6 flex flex-col gap-2.5 sm:flex-row sm:justify-center">
            <M3Button
              variant="filled"
              size="lg"
              leadingIcon={<ClipboardPaste className="h-4 w-4" />}
              onClick={onPasteClipboard}
            >
              Вставить из буфера
            </M3Button>
            <M3Button
              variant="tonal"
              size="lg"
              leadingIcon={<Plus className="h-4 w-4" />}
              onClick={onOpenImport}
            >
              Добавить вручную
            </M3Button>
          </div>

          <div className="mt-6 flex flex-wrap items-center justify-center gap-1.5 border-t border-[var(--md-outline-variant)] pt-4">
            {[
              'VLESS Reality',
              'Hysteria2',
              'AmneziaWG',
              'WireGuard',
              'VMess / Trojan / SS',
              'Xray JSON / Clash',
              'Подписки (HWID)',
            ].map((tag) => (
              <span
                key={tag}
                className="rounded-lg bg-[var(--md-surface-container-high)] px-2 py-0.5 text-[0.6875rem] font-medium text-[var(--md-on-surface-variant)]"
              >
                {tag}
              </span>
            ))}
          </div>
        </M3SurfaceCard>
      </div>
    );
  }

  const statusMeta = (() => {
    if (connection.killSwitchEngaged) {
      return { title: 'Kill Switch активен', tone: 'error' as const };
    }
    switch (connection.status) {
      case 'connected':
        return { title: 'Защита активна', tone: 'success' as const };
      case 'connecting':
        return { title: 'Подключение...', tone: 'primary' as const };
      case 'verifying':
        return { title: 'Проверка туннеля...', tone: 'primary' as const };
      case 'switching':
        return { title: 'Переключение узла...', tone: 'primary' as const };
      case 'reconnecting':
        return { title: 'Переподключение...', tone: 'warning' as const };
      case 'disconnecting':
        return { title: 'Отключение...', tone: 'primary' as const };
      case 'error':
        return { title: 'Ошибка соединения', tone: 'error' as const };
      default:
        return { title: 'Не подключено', tone: 'neutral' as const };
    }
  })();

  const isBusy =
    connection.status === 'connecting' ||
    connection.status === 'verifying' ||
    connection.status === 'switching' ||
    connection.status === 'reconnecting' ||
    connection.status === 'disconnecting';
  const activeMode = connection.status === 'connected' ? connection.mode : settings.connectionMode;

  const customRuleCount = settings.routing.customRules.filter((r) => r.enabled).length;
  const routingSummaryLabel = (() => {
    const base = (() => {
      switch (settings.routing.profile) {
        case 'ru_direct':
          return 'РФ сервисы напрямую';
        case 'bypass_apps':
          return 'Исключённые приложения напрямую';
        case 'only_apps':
          return 'Только выбранные приложения';
        case 'custom':
          return ruDirectActive ? 'Свои правила + РФ напрямую' : 'Свои правила';
        default:
          return 'Весь трафик через VPN';
      }
    })();
    return customRuleCount > 0 ? `${base} • +${customRuleCount}` : base;
  })();

  const dnsModeLabel =
    settings.dns.mode === 'vpn'
      ? `VPN DNS (${settings.dns.primaryDns})`
      : settings.dns.mode === 'direct'
        ? `Прямой DNS (${settings.dns.directDns})`
        : settings.dns.mode === 'config'
          ? 'DNS из конфига'
          : settings.dns.mode === 'system'
            ? 'Системный DNS'
            : settings.dns.mode === 'custom'
              ? `Свой DNS (${settings.dns.primaryDns})`
              : `Гибридный DNS (${settings.dns.primaryDns} / ${settings.dns.directDns})`;

  const dnsDotClass =
    dnsStatus === 'ok'
      ? 'bg-[var(--md-success)]'
      : dnsStatus === 'fail'
        ? 'bg-[var(--md-error)]'
        : dnsStatus === 'warn'
          ? 'bg-[var(--md-warning)]'
          : 'bg-[var(--md-on-surface-variant)]/60';

  const activeName = activeServer
    ? formatServerDisplayName(activeServer.name, activeServer.countryCode)
    : 'Не выбран';
  const activeCountry = activeServer ? getCountryName(activeServer.countryCode) : null;
  const activeNodes = activeServer ? getProfileNodeCount(activeServer) : 1;
  const activeQuality = activeServer ? serverQuality?.[activeServer.id] : undefined;

  const profileOptions = (['daily', 'work', 'gaming', 'custom'] as BehaviorProfileId[]).map((id) => ({
    value: id,
    label: behaviorState.profiles[id].name,
    description: behaviorState.profiles[id].description,
    icon: <Sliders className="h-3.5 w-3.5 text-[var(--md-primary)]" />,
  }));

  return (
    <div className="aura-scroll flex h-full flex-col justify-between gap-2.5 overflow-y-auto px-5 py-3">
      {/* Top status summary bar */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <M3StatusBadge tone={statusMeta.tone}>
            <span>{statusMeta.title}</span>
            {connection.status === 'connected' && (
              <span className="border-l border-current/25 pl-1.5 font-mono-num">
                {formatDuration(connection.connectedSince, nowMs)}
              </span>
            )}
          </M3StatusBadge>

          <button
            type="button"
            onClick={onOpenRouting}
            className="inline-flex items-center rounded-full transition-opacity hover:opacity-85"
          >
            <M3StatusBadge tone={ruDirectActive ? 'primary' : 'neutral'} dot={false}>
              <GitFork className="h-3 w-3" />
              <span>{routingSummaryLabel}</span>
            </M3StatusBadge>
          </button>
        </div>

        <div className="flex items-center gap-2.5">
          <M3Select
            size="sm"
            align="right"
            ariaLabel="Профиль поведения приложения"
            value={behaviorState.activeProfileId}
            onChange={onSelectBehaviorProfile}
            options={profileOptions}
            className="min-w-[148px]"
          />
          <M3Tooltip
            label={
              activeMode === 'tun'
                ? 'Виртуальный адаптер Wintun перехватывает трафик всего ПК'
                : 'Локальный системный прокси Windows для браузеров и приложений'
            }
          >
            <div className="hidden md:block text-[0.72rem] text-[var(--md-on-surface-variant)]">
              Туннель:{' '}
              <span className="font-semibold text-[var(--md-on-surface)]">
                {activeMode === 'tun' ? 'TUN (весь ПК)' : 'Системный прокси'}
              </span>
            </div>
          </M3Tooltip>
        </div>
      </div>

      {/* Balanced Hero Connection Card */}
      <M3SurfaceCard
        level="default"
        className={`flex flex-col justify-between gap-3 p-4 ${
          connection.status === 'connected' ? 'border-[var(--md-success)]/35' : ''
        }`}
      >
        <div className="flex flex-col items-center gap-4 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-4 min-w-0">
            <ConnectionDial
              status={connection.status}
              disabled={!activeServer}
              compact={settings.compactMode}
              onToggle={onToggleConnect}
            />

            <div className="min-w-0 space-y-2">
              <div className="min-w-0">
                <div className="font-display text-[1.0625rem] font-bold text-[var(--md-on-surface)]">
                  {statusMeta.title}
                </div>
                <div className="text-[0.72rem] text-[var(--md-on-surface-variant)]">
                  {connection.status === 'connected'
                    ? connection.health?.reason ?? 'Туннель активен и пропускает трафик'
                    : activeServer
                      ? `Готов к подключению: ${activeCountry ?? activeName}`
                      : 'Добавьте сервер для начала работы'}
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-1.5">
                {onOpenProtectionCenter && (
                  <button
                    type="button"
                    data-testid="protection-center-trigger"
                    onClick={onOpenProtectionCenter}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-high)] px-2.5 py-1 text-[0.6875rem] font-semibold text-[var(--md-on-surface)] transition-colors hover:border-[var(--md-primary)]"
                  >
                    <Shield className="h-3.5 w-3.5 text-[var(--md-primary)]" />
                    <span>Центр защиты</span>
                  </button>
                )}

                {onOpenConnectionInspector && (
                  <button
                    type="button"
                    data-testid="connection-inspector-trigger"
                    onClick={onOpenConnectionInspector}
                    className="inline-flex items-center gap-1 rounded-lg border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-high)] px-2.5 py-1 text-[0.6875rem] font-semibold text-[var(--md-on-surface)] transition-colors hover:border-[var(--md-primary)]"
                  >
                    <Activity className="h-3.5 w-3.5 text-[var(--md-primary)]" />
                    <span>Инспектор</span>
                  </button>
                )}

                {activeNodes > 1 && (
                  <span className="rounded-lg bg-[var(--md-surface-container-high)] px-2 py-0.5 text-[0.6875rem] font-medium text-[var(--md-on-surface-variant)] font-mono-num">
                    {formatNodePoolLabel(activeNodes)}
                  </span>
                )}

                {activeQuality && activeQuality.qualityLabel && (
                  <M3Tooltip
                    label={`Надёжность узла: ${activeQuality.qualityScore}/100 (${activeQuality.successCount} усп., ${activeQuality.failCount} сб.)`}
                  >
                    <span
                      className={`rounded-lg px-2 py-0.5 text-[0.6875rem] font-medium ${
                        activeQuality.qualityScore >= 80
                          ? 'bg-[var(--md-success-container)] text-[var(--md-success)]'
                          : activeQuality.qualityScore >= 55
                            ? 'bg-[var(--md-primary-container)] text-[var(--md-on-primary-container)]'
                            : 'bg-[var(--md-warning-container)] text-[var(--md-warning)]'
                      }`}
                    >
                      {activeQuality.qualityLabel}
                    </span>
                  </M3Tooltip>
                )}

                {connection.status === 'connected' && (
                  <M3Tooltip label="Проверить реальный отклик интернета через VPN-туннель (HTTP RTT)">
                    <button
                      type="button"
                      disabled={isProbingProxy}
                      onClick={onProbeProxy}
                      className="inline-flex items-center gap-1 rounded-lg bg-[var(--md-primary-container)] px-2 py-0.5 text-[0.6875rem] font-semibold text-[var(--md-on-primary-container)] transition-opacity hover:opacity-90 disabled:opacity-55 font-mono-num"
                    >
                      <Activity className={`h-3 w-3 ${isProbingProxy ? 'animate-pulse' : ''}`} />
                      {isProbingProxy
                        ? 'Проверка...'
                        : lastProbe?.ok && lastProbe.rttMs
                          ? `HTTP ${lastProbe.rttMs} мс`
                          : 'Проверить туннель'}
                    </button>
                  </M3Tooltip>
                )}
              </div>
            </div>
          </div>

          {/* Integrated Quick Controls Panel */}
          <div className="flex w-full flex-col gap-2 rounded-2xl bg-[var(--md-surface-container-low)] p-2.5 md:w-[324px] shrink-0">
            <div className="flex items-center justify-between gap-2">
              <span className="text-[0.6875rem] font-semibold text-[var(--md-on-surface-variant)]">
                Быстрые действия
              </span>
              <M3SegmentedButton
                size="sm"
                value={settings.connectionMode}
                onChange={onChangeMode}
                options={[
                  { id: 'system_proxy', label: 'Прокси', icon: <Globe className="h-3 w-3" /> },
                  { id: 'tun', label: 'TUN', icon: <Shield className="h-3 w-3" /> },
                ]}
              />
            </div>

            <div className="grid grid-cols-2 gap-1.5">
              <M3Chip
                active={ruDirectActive}
                onClick={onToggleRuDirect}
                tooltip="Российские банки, Госуслуги и сайты .ru напрямую без VPN"
                className="w-full justify-center text-[0.6875rem]"
              >
                РФ напрямую
              </M3Chip>

              <M3Chip
                active={(settings.killSwitch?.mode ?? 'off') !== 'off' || settings.killSwitchEnabled}
                onClick={onToggleKillSwitch}
                tooltip="Заблокировать утечку трафика при обрыве ядра VPN"
                className="w-full justify-center text-[0.6875rem]"
              >
                Kill Switch
              </M3Chip>

              <M3Chip
                active={Boolean(settings.routing.claudeGuard?.enabled)}
                onClick={() => (onToggleClaudeGuard ? onToggleClaudeGuard() : onOpenRouting?.())}
                tooltip={
                  connection.claudeGuard?.wfpBlockingActive
                    ? 'WFP-блокировка активна: при отключённом VPN трафик Claude/Anthropic заблокирован от РФ-утечек'
                    : 'Направлять Claude Desktop, Claude Code CLI и claude.ai только через VPN с блокировкой при разрыве'
                }
                className="w-full justify-center text-[0.6875rem]"
              >
                {connection.claudeGuard?.wfpBlockingActive ? 'Claude: WFP-блок' : 'Защита Claude'}
              </M3Chip>

              <M3Chip
                variant="assist"
                onClick={onAutoSelectFastest}
                tooltip="Найти узел с минимальной задержкой и высокой стабильностью"
                className="w-full justify-center text-[0.6875rem]"
                leading={
                  <Zap
                    className={`h-3 w-3 shrink-0 text-[var(--md-primary)] ${
                      isAutoSelecting ? 'animate-pulse' : ''
                    }`}
                  />
                }
              >
                Автопинг
              </M3Chip>
            </div>
          </div>
        </div>

        {/* Compact Connection Health Strip (§9) */}
        <div
          data-testid="connection-health-strip"
          className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--md-outline-variant)]/70 bg-[var(--md-surface-container-low)] px-3 py-1.5 text-[0.6875rem] text-[var(--md-on-surface-variant)]"
        >
          <div className="flex flex-wrap items-center gap-3">
            <span className="inline-flex items-center gap-1.5">
              <span className={`h-1.5 w-1.5 rounded-full ${dnsDotClass}`} />
              <span>{dnsModeLabel}</span>
            </span>

            {connection.health && connection.status === 'connected' && (
              <span className="inline-flex items-center gap-1 font-mono-num">
                <span
                  className={
                    connection.health.state === 'verified'
                      ? 'text-[var(--md-success)]'
                      : connection.health.state === 'unstable' || connection.health.state === 'lost'
                        ? 'text-[var(--md-warning)]'
                        : 'text-[var(--md-on-surface-variant)]'
                  }
                >
                  {connection.health.lastProbeRttMs
                    ? `Монитор: OK (${connection.health.lastProbeRttMs} мс)`
                    : connection.health.state === 'verified'
                      ? 'Монитор: Подтверждён'
                      : 'Монитор: Активен'}
                </span>
              </span>
            )}

            {lastReconnectAt && (
              <span className="font-mono-num">
                Переподключение: {formatTimeShort(lastReconnectAt)}
              </span>
            )}
          </div>

          <div className="flex items-center gap-2">
            {externalIp ? (
              <M3Tooltip label="Нажмите, чтобы скопировать внешний IP">
                <button
                  type="button"
                  onClick={onCopyExternalIp}
                  className="inline-flex items-center gap-1 rounded-lg bg-[var(--md-surface-container-high)] px-2 py-0.5 text-[0.6875rem] font-medium text-[var(--md-on-surface)] font-mono-num hover:brightness-105"
                >
                  <span>IP: {maskIpHome(externalIp, maskExternalIp)}</span>
                  <Copy className="h-2.5 w-2.5 opacity-75" />
                </button>
              </M3Tooltip>
            ) : (
              <M3Tooltip label="Запрос внешнего IP отправляется только по вашему клику (приватный режим)">
                <button
                  type="button"
                  disabled={isFetchingIp}
                  onClick={onFetchExternalIp}
                  className="inline-flex items-center gap-1 rounded-lg border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] px-2 py-0.5 text-[0.6875rem] font-medium text-[var(--md-on-surface)] transition-colors hover:border-[var(--md-primary)] disabled:opacity-50"
                >
                  <Globe className="h-3 w-3 text-[var(--md-primary)]" />
                  <span>{isFetchingIp ? 'Запрос IP...' : 'Узнать внешний IP'}</span>
                </button>
              </M3Tooltip>
            )}
          </div>
        </div>

        {/* Contextual Alert Banners inside hero footer */}
        {connection.killSwitchEngaged && (
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl bg-[var(--md-error-container)] px-3.5 py-2.5 text-[0.75rem] text-[var(--md-error)]">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 shrink-0" />
              <span>
                {connection.killSwitch?.lastReason ??
                  'Kill Switch заблокировал прямой выход трафика после обрыва ядра.'}
              </span>
            </div>
            <M3Button
              variant="danger"
              size="sm"
              leadingIcon={<Unlock className="h-3 w-3" />}
              onClick={onDisengageKillSwitch}
            >
              Снять блокировку
            </M3Button>
          </div>
        )}

        {!connection.killSwitchEngaged &&
          connection.status === 'error' &&
          (connection.errorInfo || connection.errorMessage) && (
            <div className="flex flex-col gap-2 rounded-xl bg-[var(--md-error-container)] px-3.5 py-2.5 text-[0.75rem] text-[var(--md-error)] sm:flex-row sm:items-start sm:justify-between">
              <div className="flex items-start gap-2.5 min-w-0">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <div className="min-w-0">
                  <div className="font-bold">
                    {connection.errorInfo?.title ?? 'Ошибка подключения'}
                  </div>
                  <div className="mt-0.5 leading-snug text-[var(--md-on-error-container)]">
                    {connection.errorInfo?.message ?? connection.errorMessage}
                  </div>
                  {connection.errorInfo?.hint && (
                    <div className="mt-1 text-[0.7rem] text-[var(--md-on-error-container)]/85">
                      {connection.errorInfo.hint}
                    </div>
                  )}
                </div>
              </div>
              <div className="flex shrink-0 items-center gap-1.5 self-end sm:self-center">
                {connection.errorInfo?.action === 'relaunch_admin' && onRelaunchAdmin ? (
                  <M3Button variant="tonal" size="sm" onClick={onRelaunchAdmin}>
                    От администратора
                  </M3Button>
                ) : connection.errorInfo?.action === 'open_settings' && onOpenSettings ? (
                  <M3Button
                    variant="tonal"
                    size="sm"
                    leadingIcon={<Settings className="h-3 w-3" />}
                    onClick={onOpenSettings}
                  >
                    Настройки
                  </M3Button>
                ) : (
                  <M3Button
                    variant="tonal"
                    size="sm"
                    leadingIcon={<RotateCw className="h-3 w-3" />}
                    onClick={onToggleConnect}
                  >
                    Повторить
                  </M3Button>
                )}
                <M3Button variant="text" size="sm" onClick={onOpenDiagnostics}>
                  Логи
                </M3Button>
              </div>
            </div>
          )}
      </M3SurfaceCard>

      {/* Bottom Server Selector + Telemetry + Traffic */}
      <div className="space-y-2.5">
        <ServerQuickPick
          profiles={profiles}
          activeServer={activeServer}
          isBusy={isBusy}
          isPinging={isPinging}
          isAutoSelecting={isAutoSelecting}
          onSelectServer={onSelectServer}
          onPingActive={onPingActive}
          onAutoSelectFastest={onAutoSelectFastest}
          onInspectActive={onInspectServer}
        />
        <TelemetryStrip connection={connection} />
        <TrafficGraph status={connection.status} />
      </div>
    </div>
  );
}
