import {
  Check,
  CheckSquare,
  ChevronDown,
  ChevronRight,
  Clock,
  Filter,
  FolderTree,
  Gauge,
  Globe,
  MoreVertical,
  Pencil,
  Play,
  Plus,
  Radio,
  RefreshCw,
  Sliders,
  Star,
  Trash2,
  X,
  Zap,
} from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { CountryBadge } from '../components/CountryBadge';
import {
  M3Button,
  M3Checkbox,
  M3Chip,
  M3Dialog,
  M3DropdownMenu,
  M3EmptyState,
  M3IconButton,
  M3SearchBar,
  M3SegmentedButton,
  M3Select,
  M3StatusBadge,
  M3SurfaceCard,
  M3Tooltip,
} from '../components/md3';
import { useServerLatencyMeta } from '../stores/liveStore';
import type {
  ConnectionStatus,
  ServerProfile,
  ServerQualityMetrics,
  Subscription,
} from '../types/vpn';
import {
  formatNodePoolLabel,
  formatProtocolBadge,
  formatServerDisplayName,
  formatTransportInfo,
  getCountryName,
  getLatencyTone,
  getProfileNodeCount,
  hasAutoBalancer,
  shouldShowCountryInSubtitle,
} from '../utils/format';

type SortKey = 'smart' | 'latency' | 'name' | 'country';
type DensityMode = 'compact' | 'detailed';

interface ServersViewProps {
  profiles: ServerProfile[];
  subscriptions: Subscription[];
  activeServerId?: string | null;
  connectedServerId?: string | null;
  connectionStatus: ConnectionStatus;
  compactDefault?: boolean;
  serverQuality?: Record<string, ServerQualityMetrics>;
  isPingingAll: boolean;
  pingingIds: Set<string>;
  onSelect: (id: string) => void;
  onConnect: (id: string) => void;
  onToggleFavorite: (id: string) => void;
  onPing: (id: string) => void;
  onPingAll: () => void;
  onAutoSelect: () => void;
  onRename: (id: string, newName: string) => void;
  onDelete: (id: string) => void;
  onBulkDelete?: (ids: string[]) => Promise<void> | void;
  onBulkFavorite?: (ids: string[], favorite: boolean) => Promise<void> | void;
  onOpenImport: () => void;
  onGoToSubscriptions?: () => void;
  onInspect?: (id: string) => void;
  onOpenConfigStudio?: (id: string) => void;
  onSpeedTest?: (id: string) => Promise<void> | void;
  speedTestingId?: string | null;
}

const PAGE_SIZE = 100;
const STALE_LATENCY_MS = 15 * 60_000;

function formatAgoShort(ts: number): string {
  const diffMin = Math.max(0, Math.round((Date.now() - ts) / 60_000));
  if (diffMin < 1) return 'только что';
  if (diffMin < 60) return `${diffMin} мин назад`;
  const h = Math.round(diffMin / 60);
  return `${h} ч назад`;
}

function LatencySparkline({ history }: { history: number[] }) {
  if (history.length < 2) return null;
  const w = 44;
  const h = 14;
  const min = Math.min(...history);
  const max = Math.max(min + 15, ...history);
  const pts = history
    .map((v, i) => {
      const x = (i / (history.length - 1)) * w;
      const y = h - 2 - ((v - min) / (max - min)) * (h - 4);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(' ');
  const latest = history[history.length - 1];
  const tone = getLatencyTone(latest);
  const stroke =
    tone === 'good'
      ? 'var(--md-success)'
      : tone === 'medium'
        ? 'var(--md-warning)'
        : 'var(--md-error)';
  return (
    <M3Tooltip label={`История TCP: ${history.join(' → ')} мс`}>
      <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} className="hidden lg:block shrink-0 opacity-85">
        <polyline
          fill="none"
          stroke={stroke}
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
          points={pts}
        />
      </svg>
    </M3Tooltip>
  );
}

export function ServersView({
  profiles,
  subscriptions,
  activeServerId,
  connectedServerId,
  connectionStatus,
  compactDefault = false,
  serverQuality,
  isPingingAll,
  pingingIds,
  onSelect,
  onConnect,
  onToggleFavorite,
  onPing,
  onPingAll,
  onAutoSelect,
  onRename,
  onDelete,
  onBulkDelete,
  onBulkFavorite,
  onOpenImport,
  onGoToSubscriptions,
  onInspect,
  onOpenConfigStudio,
  onSpeedTest,
  speedTestingId,
}: ServersViewProps) {
  const latencyMeta = useServerLatencyMeta();
  const [search, setSearch] = useState('');
  const [countryFilter, setCountryFilter] = useState<string>('all');
  const [protocolFilter, setProtocolFilter] = useState<string>('all');
  const [subFilter, setSubFilter] = useState<string>('all');
  const [onlyFavorites, setOnlyFavorites] = useState(false);
  const [onlyRecent, setOnlyRecent] = useState(false);
  const [groupByCountry, setGroupByCountry] = useState(false);
  const [selectionMode, setSelectionMode] = useState(false);
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(() => new Set());
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set());
  const [confirmBulkDelete, setConfirmBulkDelete] = useState(false);

  const [sortBy, setSortBy] = useState<SortKey>('smart');
  const [density, setDensity] = useState<DensityMode>(compactDefault ? 'compact' : 'detailed');
  const [visibleLimit, setVisibleLimit] = useState(PAGE_SIZE);

  const [editingId, setEditingId] = useState<string | null>(null);
  const [draftName, setDraftName] = useState('');
  const [contextMenu, setContextMenu] = useState<{
    profile: ServerProfile;
    x: number;
    y: number;
  } | null>(null);

  useEffect(() => {
    setDensity(compactDefault ? 'compact' : 'detailed');
  }, [compactDefault]);

  useEffect(() => {
    const valid = new Set(profiles.map((p) => p.id));
    setSelectedIds((prev) => {
      let changed = false;
      const next = new Set<string>();
      for (const id of prev) {
        if (valid.has(id)) next.add(id);
        else changed = true;
      }
      return changed ? next : prev;
    });
  }, [profiles]);

  useEffect(() => {
    if (!contextMenu) return;
    const close = () => setContextMenu(null);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setContextMenu(null);
    };
    window.addEventListener('click', close);
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('click', close);
      window.removeEventListener('keydown', onKey);
    };
  }, [contextMenu]);

  const disabledSubIds = useMemo(() => {
    return new Set(subscriptions.filter((s) => !s.enabled).map((s) => s.id));
  }, [subscriptions]);

  const enabledProfiles = useMemo(() => {
    return profiles.filter((p) => !p.subscriptionId || !disabledSubIds.has(p.subscriptionId));
  }, [profiles, disabledSubIds]);

  const hiddenBySubCount = profiles.length - enabledProfiles.length;

  const countries = useMemo(() => {
    const counts = new Map<string, number>();
    for (const p of enabledProfiles) {
      if (p.countryCode) {
        const code = p.countryCode.toUpperCase();
        counts.set(code, (counts.get(code) ?? 0) + 1);
      }
    }
    return Array.from(counts.entries()).sort((a, b) => {
      const nameA = getCountryName(a[0]) ?? a[0];
      const nameB = getCountryName(b[0]) ?? b[0];
      return nameA.localeCompare(nameB, 'ru');
    });
  }, [enabledProfiles]);

  const protocols = useMemo(() => {
    const set = new Set<string>();
    for (const p of enabledProfiles) set.add(p.protocol);
    return Array.from(set).sort();
  }, [enabledProfiles]);

  const activeSubs = useMemo(
    () => subscriptions.filter((s) => s.enabled),
    [subscriptions],
  );

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    const list = enabledProfiles.filter((p) => {
      if (onlyFavorites && !p.favorite) return false;
      if (onlyRecent && !p.lastUsedAt) return false;
      if (countryFilter !== 'all' && (p.countryCode ?? '').toUpperCase() !== countryFilter) {
        return false;
      }
      if (protocolFilter !== 'all' && p.protocol !== protocolFilter) {
        return false;
      }
      if (subFilter === 'manual' && p.subscriptionId) return false;
      if (subFilter !== 'all' && subFilter !== 'manual' && p.subscriptionId !== subFilter) {
        return false;
      }
      if (!q) return true;
      const cName = getCountryName(p.countryCode)?.toLowerCase() ?? '';
      return (
        p.name.toLowerCase().includes(q) ||
        p.address.toLowerCase().includes(q) ||
        formatProtocolBadge(p).toLowerCase().includes(q) ||
        (p.countryCode ?? '').toLowerCase().includes(q) ||
        cName.includes(q)
      );
    });

    return [...list].sort((a, b) => {
      if (sortBy === 'smart') {
        if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
        if (a.id === activeServerId) return -1;
        if (b.id === activeServerId) return 1;
        const la = a.latencyMs ?? 999_999;
        const lb = b.latencyMs ?? 999_999;
        if (la !== lb) return la - lb;
        return a.name.localeCompare(b.name, 'ru');
      }
      if (sortBy === 'latency') {
        return (a.latencyMs ?? 999_999) - (b.latencyMs ?? 999_999);
      }
      if (sortBy === 'country') {
        const ca = getCountryName(a.countryCode) ?? 'ЯЯ';
        const cb = getCountryName(b.countryCode) ?? 'ЯЯ';
        const cmp = ca.localeCompare(cb, 'ru');
        return cmp !== 0 ? cmp : a.name.localeCompare(b.name, 'ru');
      }
      return a.name.localeCompare(b.name, 'ru');
    });
  }, [
    enabledProfiles,
    search,
    onlyFavorites,
    onlyRecent,
    countryFilter,
    protocolFilter,
    subFilter,
    sortBy,
    activeServerId,
  ]);

  useEffect(() => {
    setVisibleLimit(PAGE_SIZE);
  }, [search, onlyFavorites, onlyRecent, countryFilter, protocolFilter, subFilter, sortBy]);

  const visibleServers = filtered.slice(0, visibleLimit);
  const favoritesCount = useMemo(
    () => enabledProfiles.filter((p) => p.favorite).length,
    [enabledProfiles],
  );
  const recentCount = useMemo(
    () => enabledProfiles.filter((p) => Boolean(p.lastUsedAt)).length,
    [enabledProfiles],
  );

  const subTitleMap = useMemo(() => {
    const m = new Map<string, string>();
    for (const s of subscriptions) m.set(s.id, s.title);
    return m;
  }, [subscriptions]);

  const groupedCountries = useMemo(() => {
    if (!groupByCountry) return [];
    const map = new Map<string, ServerProfile[]>();
    for (const srv of visibleServers) {
      const code = (srv.countryCode ?? 'OTHER').toUpperCase();
      const arr = map.get(code) ?? [];
      arr.push(srv);
      map.set(code, arr);
    }
    return Array.from(map.entries()).sort((a, b) => {
      if (a[0] === 'OTHER') return 1;
      if (b[0] === 'OTHER') return -1;
      const na = getCountryName(a[0]) ?? a[0];
      const nb = getCountryName(b[0]) ?? b[0];
      return na.localeCompare(nb, 'ru');
    });
  }, [groupByCountry, visibleServers]);

  const startRename = (p: ServerProfile) => {
    setEditingId(p.id);
    setDraftName(p.name);
  };

  const commitRename = (id: string) => {
    const trimmed = draftName.trim();
    if (trimmed) onRename(id, trimmed);
    setEditingId(null);
  };

  const toggleSelectId = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const allVisibleSelected =
    visibleServers.length > 0 && visibleServers.every((s) => selectedIds.has(s.id));
  const someVisibleSelected = visibleServers.some((s) => selectedIds.has(s.id));

  const toggleSelectAllVisible = () => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (allVisibleSelected) {
        for (const s of visibleServers) next.delete(s.id);
      } else {
        for (const s of visibleServers) next.add(s.id);
      }
      return next;
    });
  };

  const renderLatencyBadges = (profile: ServerProfile, q?: ServerQualityMetrics) => {
    const meta = latencyMeta[profile.id];
    const isStale = Boolean(meta?.checkedAt && Date.now() - meta.checkedAt > STALE_LATENCY_MS);
    const tone = getLatencyTone(profile.latencyMs);

    const tcpColorClass =
      tone === 'good'
        ? 'bg-[var(--md-success-container)] text-[var(--md-success)]'
        : tone === 'medium'
          ? 'bg-[var(--md-warning-container)] text-[var(--md-warning)]'
          : tone === 'poor'
            ? 'bg-[var(--md-error-container)] text-[var(--md-error)]'
            : 'bg-[var(--md-surface-container-high)] text-[var(--md-on-surface-variant)]';

    const tcpTooltip =
      tone === 'none'
        ? 'TCP-задержка рукопожатия ещё не измерена'
        : `TCP-рукопожатие до сервера (не скорость туннеля)${
            meta?.checkedAt ? ` • Проверено: ${formatAgoShort(meta.checkedAt)}` : ''
          }${isStale ? ' • Данные устарели (>15 мин)' : ''}`;

    return (
      <div className="flex items-center gap-1.5">
        {meta && meta.history.length >= 2 && <LatencySparkline history={meta.history} />}

        {q?.lastHttpRttMs !== undefined && q.lastHttpRttMs !== null && (
          <M3Tooltip label="Реальный HTTP RTT отклик через активный VPN-туннель">
            <span className="hidden md:inline-flex items-center rounded-full bg-[var(--md-primary-container)] px-2 py-0.5 text-[0.65rem] font-semibold text-[var(--md-on-primary-container)] font-mono-num">
              HTTP {q.lastHttpRttMs} мс
            </span>
          </M3Tooltip>
        )}

        <M3Tooltip label={tcpTooltip}>
          <span
            className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[0.6875rem] font-semibold font-mono-num ${tcpColorClass} ${
              isStale ? 'border border-[var(--md-warning)]/40 opacity-85' : ''
            }`}
          >
            {isStale && <Clock className="h-2.5 w-2.5 text-[var(--md-warning)]" />}
            {tone === 'none' ? '—' : `TCP ${profile.latencyMs} мс`}
          </span>
        </M3Tooltip>
      </div>
    );
  };

  const hasActiveFilters =
    Boolean(search) ||
    countryFilter !== 'all' ||
    protocolFilter !== 'all' ||
    subFilter !== 'all' ||
    onlyFavorites ||
    onlyRecent;

  const resetFilters = () => {
    setSearch('');
    setCountryFilter('all');
    setProtocolFilter('all');
    setSubFilter('all');
    setOnlyFavorites(false);
    setOnlyRecent(false);
  };

  const countryOptions = [
    {
      value: 'all',
      label: 'Все страны',
      badge: enabledProfiles.length,
      icon: <Globe className="h-3.5 w-3.5" />,
    },
    ...countries.map(([code, count]) => ({
      value: code,
      label: getCountryName(code) ?? code,
      badge: count,
      icon: <CountryBadge code={code} size="sm" />,
    })),
  ];

  const protocolOptions = [
    { value: 'all', label: 'Все протоколы' },
    ...protocols.map((proto) => ({ value: proto, label: proto.toUpperCase() })),
  ];

  const subOptions = [
    { value: 'all', label: 'Все источники' },
    { value: 'manual', label: 'Добавлены вручную' },
    ...activeSubs.map((s) => ({ value: s.id, label: s.title })),
  ];

  const renderServerCard = (profile: ServerProfile) => {
    const isSelected = profile.id === activeServerId;
    const isConnected = profile.id === connectedServerId && connectionStatus === 'connected';
    const isPinging = pingingIds.has(profile.id);
    const isEditing = editingId === profile.id;
    const isChecked = selectedIds.has(profile.id);
    const displayName = formatServerDisplayName(profile.name, profile.countryCode);
    const countryName = getCountryName(profile.countryCode);
    const showCountry = shouldShowCountryInSubtitle(displayName, countryName);
    const nodeCount = getProfileNodeCount(profile);
    const poolLabel = nodeCount > 1 ? formatNodePoolLabel(nodeCount) : null;
    const balancer = hasAutoBalancer(profile);
    const subName = profile.subscriptionId ? subTitleMap.get(profile.subscriptionId) : null;
    const q = serverQuality?.[profile.id];

    return (
      <div
        key={profile.id}
        role="button"
        tabIndex={0}
        onClick={() => {
          if (!isEditing) onSelect(profile.id);
        }}
        onKeyDown={(e) => {
          if (isEditing) return;
          if (e.key === 'Enter' && e.target === e.currentTarget) {
            e.preventDefault();
            onSelect(profile.id);
          } else if (e.key === ' ' && e.target === e.currentTarget) {
            e.preventDefault();
            onSelect(profile.id);
          }
        }}
        onDoubleClick={() => {
          if (!isEditing) onConnect(profile.id);
        }}
        onContextMenu={(e) => {
          e.preventDefault();
          setContextMenu({
            profile,
            x: Math.min(e.clientX, window.innerWidth - 220),
            y: Math.min(e.clientY, window.innerHeight - 230),
          });
        }}
        className={`group flex cursor-pointer items-center justify-between gap-3 rounded-2xl border transition-all duration-150 ${
          density === 'compact' ? 'px-3 py-2' : 'px-3.5 py-2.5'
        } ${
          isConnected
            ? 'border-[var(--md-success)] bg-[color-mix(in_srgb,var(--md-success-container)_35%,var(--md-surface-container))]'
            : isSelected
              ? 'border-[var(--md-primary)] bg-[color-mix(in_srgb,var(--md-primary-container)_32%,var(--md-surface-container))]'
              : 'border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] hover:bg-[var(--md-surface-container-high)]'
        }`}
      >
        <div className="flex min-w-0 flex-1 items-center gap-2">
          {(selectionMode || isChecked) && (
            <div onClick={(e) => e.stopPropagation()} className="shrink-0">
              <M3Checkbox
                size="sm"
                checked={isChecked}
                onChange={() => toggleSelectId(profile.id)}
                ariaLabel={`Выбрать сервер ${displayName}`}
              />
            </div>
          )}

          <M3Tooltip label={profile.favorite ? 'Убрать из избранного' : 'В избранное'}>
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                onToggleFavorite(profile.id);
              }}
              aria-label={profile.favorite ? 'Убрать из избранного' : 'В избранное'}
              className={`rounded-lg p-1 transition-colors ${
                profile.favorite
                  ? 'text-[var(--md-warning)] hover:bg-[var(--md-warning-container)]'
                  : 'text-[var(--md-on-surface-variant)]/45 hover:bg-[var(--md-surface-container-highest)] hover:text-[var(--md-warning)]'
              }`}
            >
              <Star
                className={`h-4 w-4 ${profile.favorite ? 'fill-[var(--md-warning)]' : ''}`}
              />
            </button>
          </M3Tooltip>

          <CountryBadge code={profile.countryCode} size={density === 'compact' ? 'sm' : 'md'} />

          <div className="min-w-0 flex-1">
            {isEditing ? (
              <div className="flex items-center gap-1.5" onClick={(e) => e.stopPropagation()}>
                <input
                  value={draftName}
                  onChange={(e) => setDraftName(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') commitRename(profile.id);
                    if (e.key === 'Escape') setEditingId(null);
                  }}
                  autoFocus
                  className="h-7.5 w-64 rounded-xl border border-[var(--md-primary)] bg-[var(--md-surface)] px-2.5 text-[0.8125rem] text-[var(--md-on-surface)]"
                />
                <M3IconButton
                  size="sm"
                  variant="tonal"
                  onClick={() => commitRename(profile.id)}
                  aria-label="Сохранить"
                >
                  <Check className="h-3.5 w-3.5" />
                </M3IconButton>
                <M3IconButton
                  size="sm"
                  onClick={() => setEditingId(null)}
                  aria-label="Отменить"
                >
                  <X className="h-3.5 w-3.5" />
                </M3IconButton>
              </div>
            ) : (
              <div className="flex items-center gap-1.5 min-w-0">
                <M3Tooltip label={displayName} className="min-w-0">
                  <span className="truncate block text-[0.8125rem] font-semibold text-[var(--md-on-surface)]">
                    {displayName}
                  </span>
                </M3Tooltip>
                <span className="shrink-0 rounded-md bg-[var(--md-surface-container-high)] px-1.5 py-0.5 text-[0.625rem] font-medium text-[var(--md-on-surface-variant)]">
                  {formatProtocolBadge(profile)}
                </span>
                {isConnected && (
                  <M3StatusBadge tone="success" dot>
                    Активен
                  </M3StatusBadge>
                )}
                {!isConnected && isSelected && <M3StatusBadge tone="primary">Выбран</M3StatusBadge>}
                {balancer && poolLabel && (
                  <span className="shrink-0 rounded-md bg-[var(--md-surface-container-highest)] px-1.5 py-0.5 text-[0.625rem] font-medium text-[var(--md-on-surface-variant)] font-mono-num">
                    {poolLabel}
                  </span>
                )}
              </div>
            )}

            {density === 'detailed' && !isEditing && (
              <div className="mt-0.5 flex flex-wrap items-center gap-x-2 text-[0.6875rem] text-[var(--md-on-surface-variant)]">
                {showCountry && countryName && <span>{countryName}</span>}
                <span>{formatTransportInfo(profile)}</span>
                <span className="font-mono-num text-[0.65rem] opacity-80">
                  {profile.address}:{profile.port}
                </span>
                {subName && (
                  <span className="rounded bg-[var(--md-surface-container-highest)] px-1.5 py-0.5 text-[0.625rem]">
                    {subName}
                  </span>
                )}
              </div>
            )}
          </div>
        </div>

        <div className="flex shrink-0 items-center gap-1.5" onClick={(e) => e.stopPropagation()}>
          {q && q.qualityLabel && (
            <M3Tooltip
              label={`Локальная статистика запусков: ${q.qualityScore}/100 (${q.successCount} усп., ${q.failCount} сб.) — не измеряет потери пакетов`}
            >
              <span
                className={`hidden sm:inline-flex items-center rounded-full px-2 py-0.5 text-[0.65rem] font-medium ${
                  q.qualityScore >= 80
                    ? 'bg-[var(--md-success-container)] text-[var(--md-success)]'
                    : q.qualityScore >= 55
                      ? 'bg-[var(--md-surface-container-high)] text-[var(--md-on-surface)]'
                      : 'bg-[var(--md-warning-container)] text-[var(--md-warning)]'
                }`}
              >
                {q.qualityLabel}
              </span>
            </M3Tooltip>
          )}
          {renderLatencyBadges(profile, q)}

          {(onOpenConfigStudio || onInspect) && (
            <M3IconButton
              size="sm"
              tooltip="Config Studio / Инспектор профиля"
              onClick={() => (onOpenConfigStudio ?? onInspect)?.(profile.id)}
              aria-label="Config Studio"
            >
              <Sliders className="h-3.5 w-3.5" />
            </M3IconButton>
          )}

          <M3IconButton
            size="sm"
            tooltip="Проверить TCP-задержку"
            onClick={() => onPing(profile.id)}
            aria-label="Проверить TCP-задержку"
          >
            <Gauge
              className={`h-3.5 w-3.5 ${isPinging ? 'animate-spin text-[var(--md-primary)]' : ''}`}
            />
          </M3IconButton>

          <M3Button
            size="sm"
            variant={isConnected ? 'outlined' : 'tonal'}
            onClick={() => onConnect(profile.id)}
            leadingIcon={<Play className="h-3 w-3" />}
          >
            {isConnected ? 'Перезапуск' : 'Подкл.'}
          </M3Button>

          <M3DropdownMenu
            trigger={
              <span className="inline-flex h-7 w-7 items-center justify-center rounded-lg text-[var(--md-on-surface-variant)] transition-colors hover:bg-[var(--md-surface-container-highest)] hover:text-[var(--md-on-surface)]">
                <MoreVertical className="h-4 w-4" />
              </span>
            }
            items={[
              {
                id: 'connect',
                label: isConnected ? 'Переподключить' : 'Подключиться',
                icon: <Play className="h-3.5 w-3.5" />,
                onClick: () => onConnect(profile.id),
              },
              ...(onOpenConfigStudio || onInspect
                ? [
                    {
                      id: 'studio',
                      label: 'Config Studio и JSON',
                      icon: <Sliders className="h-3.5 w-3.5" />,
                      onClick: () => (onOpenConfigStudio ?? onInspect)?.(profile.id),
                    },
                  ]
                : []),
              ...(isConnected && onSpeedTest
                ? [
                    {
                      id: 'speedtest',
                      label: speedTestingId === profile.id ? 'Замер скорости...' : 'Замер скорости (1.5 МБ)',
                      icon: <Zap className="h-3.5 w-3.5" />,
                      onClick: () => void onSpeedTest(profile.id),
                    },
                  ]
                : []),
              {
                id: 'fav',
                label: profile.favorite ? 'Убрать из избранного' : 'Добавить в избранное',
                icon: <Star className="h-3.5 w-3.5" />,
                onClick: () => onToggleFavorite(profile.id),
              },
              {
                id: 'ping',
                label: 'Проверить задержку TCP',
                icon: <Gauge className="h-3.5 w-3.5" />,
                onClick: () => onPing(profile.id),
              },
              {
                id: 'rename',
                label: 'Переименовать',
                icon: <Pencil className="h-3.5 w-3.5" />,
                onClick: () => startRename(profile),
              },
              {
                id: 'delete',
                label: 'Удалить сервер',
                icon: <Trash2 className="h-3.5 w-3.5" />,
                danger: true,
                onClick: () => onDelete(profile.id),
              },
            ]}
          />
        </div>
      </div>
    );
  };

  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-3">
      {/* Header row */}
      <div className="flex flex-wrap items-center justify-between gap-2.5">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="font-display text-[1.125rem] font-bold tracking-tight text-[var(--md-on-surface)]">
              Серверы
            </h1>
            <M3StatusBadge tone="neutral" className="font-mono-num">
              {enabledProfiles.length}
            </M3StatusBadge>
            {hiddenBySubCount > 0 && (
              <M3Tooltip label="Некоторые узлы скрыты, так как их подписка отключена">
                <button
                  type="button"
                  onClick={onGoToSubscriptions}
                  className="inline-flex items-center gap-1 rounded-full bg-[var(--md-warning-container)] px-2.5 py-0.5 text-[0.6875rem] font-medium text-[var(--md-warning)] hover:brightness-105 font-mono-num"
                >
                  Скрыто: {hiddenBySubCount} (подписка выкл.)
                </button>
              </M3Tooltip>
            )}
          </div>
          <p className="text-[0.75rem] text-[var(--md-on-surface-variant)]">
            Локации упорядочены по избранному, TCP-задержке и истории качества
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <M3SegmentedButton
            size="sm"
            value={density}
            onChange={setDensity}
            options={[
              { id: 'compact', label: 'Компактно' },
              { id: 'detailed', label: 'Подробно' },
            ]}
          />
          <M3Button
            variant="tonal"
            size="sm"
            onClick={onAutoSelect}
            disabled={enabledProfiles.length === 0 || isPingingAll}
            leadingIcon={<Zap className="h-3.5 w-3.5" />}
          >
            Быстрый узел
          </M3Button>
          <M3Button
            variant="outlined"
            size="sm"
            loading={isPingingAll}
            loadingText="Замер..."
            onClick={onPingAll}
            disabled={enabledProfiles.length === 0}
            leadingIcon={<RefreshCw className="h-3.5 w-3.5" />}
          >
            Проверить все
          </M3Button>
          <M3Button
            variant="filled"
            size="sm"
            onClick={onOpenImport}
            leadingIcon={<Plus className="h-3.5 w-3.5" />}
          >
            Добавить
          </M3Button>
        </div>
      </div>

      {/* Filter Toolbar */}
      <M3SurfaceCard level="low" className="p-2.5">
        <div className="flex flex-wrap items-center gap-2">
          <M3SearchBar
            value={search}
            onChange={setSearch}
            placeholder="Поиск по стране, названию, протоколу или хосту..."
            className="min-w-[200px] flex-1"
          />

          <M3Select
            searchable
            searchPlaceholder="Страна или код..."
            ariaLabel="Фильтр по стране"
            value={countryFilter}
            onChange={setCountryFilter}
            options={countryOptions}
            className="min-w-[155px]"
          />

          <M3Select
            ariaLabel="Фильтр по протоколу"
            value={protocolFilter}
            onChange={setProtocolFilter}
            options={protocolOptions}
            className="min-w-[140px]"
          />

          {(activeSubs.length > 0 || enabledProfiles.some((p) => !p.subscriptionId)) && (
            <M3Select
              ariaLabel="Фильтр по подписке"
              value={subFilter}
              onChange={setSubFilter}
              options={subOptions}
              className="max-w-[180px]"
            />
          )}

          <M3Select
            align="right"
            ariaLabel="Сортировка"
            value={sortBy}
            onChange={setSortBy}
            options={[
              { value: 'smart', label: 'Умная (Избранные)' },
              { value: 'latency', label: 'По задержке TCP' },
              { value: 'name', label: 'По названию' },
              { value: 'country', label: 'По стране' },
            ]}
          />
        </div>

        {/* Quick toggle chips + Grouping + Selection Mode */}
        <div className="mt-2 flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-1.5">
            {visibleServers.length > 0 && (
              <M3Chip
                active={selectionMode}
                leading={<CheckSquare className="h-3.5 w-3.5" />}
                onClick={() => {
                  setSelectionMode((v) => {
                    if (v) setSelectedIds(new Set());
                    return !v;
                  });
                }}
                tooltip="Показать чекбоксы для массового выбора серверов"
              >
                Выбрать
              </M3Chip>
            )}
            {(selectionMode || selectedIds.size > 0) && visibleServers.length > 0 && (
              <M3Checkbox
                size="sm"
                checked={allVisibleSelected}
                indeterminate={someVisibleSelected && !allVisibleSelected}
                onChange={toggleSelectAllVisible}
                label="Выбрать все"
                className="mr-1"
              />
            )}
            <M3Chip
              active={groupByCountry}
              leading={<FolderTree className="h-3.5 w-3.5" />}
              onClick={() => setGroupByCountry((v) => !v)}
              tooltip="Сгруппировать серверы по странам в сворачиваемые списки"
            >
              По странам
            </M3Chip>
            <M3Chip
              active={onlyFavorites}
              leading={<Star className="h-3.5 w-3.5" />}
              onClick={() => setOnlyFavorites((v) => !v)}
            >
              Избранные ({favoritesCount})
            </M3Chip>
            <M3Chip
              active={onlyRecent}
              leading={<Clock className="h-3.5 w-3.5" />}
              onClick={() => setOnlyRecent((v) => !v)}
            >
              Недавние ({recentCount})
            </M3Chip>
            {hasActiveFilters && (
              <M3Chip variant="assist" leading={<X className="h-3 w-3" />} onClick={resetFilters}>
                Сбросить фильтры
              </M3Chip>
            )}
          </div>
          <span className="text-[0.6875rem] text-[var(--md-on-surface-variant)] font-mono-num">
            Показано {visibleServers.length} из {filtered.length}
          </span>
        </div>

        {/* Sticky Bulk Actions Bar */}
        {selectedIds.size > 0 && (
          <div
            data-testid="servers-bulk-bar"
            className="mt-2.5 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--md-primary)]/40 bg-[var(--md-primary-container)]/45 px-3 py-2"
          >
            <span className="text-[0.75rem] font-semibold text-[var(--md-on-surface)] font-mono-num">
              Выбрано: {selectedIds.size}
            </span>
            <div className="flex flex-wrap items-center gap-1.5">
              <M3Button
                size="sm"
                variant="tonal"
                leadingIcon={<Star className="h-3 w-3" />}
                onClick={async () => {
                  const ids = Array.from(selectedIds);
                  if (onBulkFavorite) {
                    await onBulkFavorite(ids, true);
                  } else {
                    for (const id of ids) onToggleFavorite(id);
                  }
                }}
              >
                В избранное
              </M3Button>
              <M3Button
                size="sm"
                variant="tonal"
                leadingIcon={<Gauge className="h-3 w-3" />}
                onClick={() => {
                  const ids = Array.from(selectedIds).slice(0, 12);
                  for (const id of ids) onPing(id);
                }}
              >
                Проверить TCP
              </M3Button>
              <M3Button
                size="sm"
                variant="danger"
                leadingIcon={<Trash2 className="h-3 w-3" />}
                onClick={() => setConfirmBulkDelete(true)}
              >
                Удалить ({selectedIds.size})
              </M3Button>
              <M3Button size="sm" variant="text" onClick={() => setSelectedIds(new Set())}>
                Снять выделение
              </M3Button>
            </div>
          </div>
        )}
      </M3SurfaceCard>

      {/* Server List / Country Groups / Empty State */}
      {enabledProfiles.length === 0 ? (
        <M3EmptyState
          icon={<Radio className="h-7 w-7" />}
          title={profiles.length > 0 ? 'Все подписки отключены' : 'Нет добавленных серверов'}
          description={
            profiles.length > 0
              ? 'Включите нужную подписку во вкладке «Подписки», чтобы серверы снова появились в списке.'
              : 'Импортируйте ссылку подписки или ключ (VLESS, VMess, Trojan, Shadowsocks, Hysteria2, WireGuard, AmneziaWG).'
          }
          action={
            profiles.length > 0 && onGoToSubscriptions ? (
              <M3Button variant="tonal" onClick={onGoToSubscriptions}>
                Открыть подписки
              </M3Button>
            ) : (
              <M3Button
                variant="filled"
                onClick={onOpenImport}
                leadingIcon={<Plus className="h-4 w-4" />}
              >
                Добавить ключ или подписку
              </M3Button>
            )
          }
        />
      ) : filtered.length === 0 ? (
        <M3EmptyState
          icon={<Filter className="h-7 w-7" />}
          title="Ничего не найдено"
          description="Попробуйте изменить поисковый запрос или сбросить активные фильтры."
          action={
            <M3Button variant="tonal" onClick={resetFilters}>
              Сбросить фильтры
            </M3Button>
          }
        />
      ) : groupByCountry ? (
        <div className="space-y-2.5">
          {groupedCountries.map(([code, items]) => {
            const isCollapsed = collapsedGroups.has(code);
            const bestMs = items.reduce<number | null>(
              (best, it) =>
                it.latencyMs !== null && it.latencyMs !== undefined
                  ? best === null
                    ? it.latencyMs
                    : Math.min(best, it.latencyMs)
                  : best,
              null,
            );
            const title = code === 'OTHER' ? 'Прочие регионы' : getCountryName(code) ?? code;

            return (
              <div
                key={code}
                className="rounded-2xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] p-2"
              >
                <button
                  type="button"
                  onClick={() =>
                    setCollapsedGroups((prev) => {
                      const next = new Set(prev);
                      if (next.has(code)) next.delete(code);
                      else next.add(code);
                      return next;
                    })
                  }
                  className="flex w-full items-center justify-between gap-2 rounded-xl px-2 py-1.5 text-left transition-colors hover:bg-[var(--md-surface-container)]"
                >
                  <span className="flex items-center gap-2">
                    {isCollapsed ? (
                      <ChevronRight className="h-4 w-4 text-[var(--md-on-surface-variant)]" />
                    ) : (
                      <ChevronDown className="h-4 w-4 text-[var(--md-on-surface-variant)]" />
                    )}
                    <CountryBadge code={code === 'OTHER' ? null : code} size="sm" />
                    <span className="text-[0.8125rem] font-bold text-[var(--md-on-surface)]">
                      {title}
                    </span>
                    <M3StatusBadge tone="neutral" className="font-mono-num">
                      {items.length}
                    </M3StatusBadge>
                  </span>
                  {bestMs !== null && (
                    <span className="text-[0.6875rem] font-semibold text-[var(--md-success)] font-mono-num">
                      от {bestMs} мс
                    </span>
                  )}
                </button>

                {!isCollapsed && (
                  <div className={`mt-2 ${density === 'compact' ? 'space-y-1.5' : 'space-y-2'}`}>
                    {items.map(renderServerCard)}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      ) : (
        <div className={density === 'compact' ? 'space-y-1.5' : 'space-y-2'}>
          {visibleServers.map(renderServerCard)}

          {filtered.length > visibleLimit && (
            <div className="flex justify-center pt-1">
              <M3Button
                variant="tonal"
                onClick={() => setVisibleLimit((n) => n + PAGE_SIZE)}
              >
                Показать ещё {Math.min(PAGE_SIZE, filtered.length - visibleLimit)} из{' '}
                {filtered.length - visibleLimit}
              </M3Button>
            </div>
          )}
        </div>
      )}

      {/* Bulk Delete Confirmation Dialog */}
      <M3Dialog
        open={confirmBulkDelete}
        onClose={() => setConfirmBulkDelete(false)}
        title={`Удалить выбранные серверы (${selectedIds.size})?`}
        description="Выбранные серверы будут удалены из локального профиля без возможности восстановления."
        footer={
          <>
            <M3Button variant="text" onClick={() => setConfirmBulkDelete(false)}>
              Отмена
            </M3Button>
            <M3Button
              variant="danger"
              onClick={async () => {
                const ids = Array.from(selectedIds);
                setConfirmBulkDelete(false);
                setSelectedIds(new Set());
                if (onBulkDelete) {
                  await onBulkDelete(ids);
                } else {
                  for (const id of ids) onDelete(id);
                }
              }}
            >
              Удалить ({selectedIds.size})
            </M3Button>
          </>
        }
      >
        <p className="text-[0.75rem] text-[var(--md-on-surface-variant)]">
          Если среди выбранных есть активно подключённый узел, VPN-соединение будет предварительно остановлено.
        </p>
      </M3Dialog>

      {/* Right-click context menu */}
      {contextMenu && (
        <div
          style={{ left: contextMenu.x, top: contextMenu.y }}
          className="fixed z-50 w-52 rounded-2xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-high)] p-1.5 shadow-2xl"
          onClick={(e) => e.stopPropagation()}
        >
          <div className="truncate px-2.5 py-1 text-[0.6875rem] font-semibold text-[var(--md-on-surface-variant)]">
            {formatServerDisplayName(contextMenu.profile.name, contextMenu.profile.countryCode)}
          </div>
          <button
            type="button"
            onClick={() => {
              onConnect(contextMenu.profile.id);
              setContextMenu(null);
            }}
            className="flex w-full items-center gap-2 rounded-xl px-2.5 py-1.5 text-left text-[0.75rem] text-[var(--md-on-surface)] hover:bg-[var(--md-surface-container-highest)]"
          >
            <Play className="h-3.5 w-3.5 text-[var(--md-primary)]" />
            Подключиться
          </button>
          <button
            type="button"
            onClick={() => {
              onToggleFavorite(contextMenu.profile.id);
              setContextMenu(null);
            }}
            className="flex w-full items-center gap-2 rounded-xl px-2.5 py-1.5 text-left text-[0.75rem] text-[var(--md-on-surface)] hover:bg-[var(--md-surface-container-highest)]"
          >
            <Star className="h-3.5 w-3.5 text-[var(--md-warning)]" />
            {contextMenu.profile.favorite ? 'Убрать из избранного' : 'В избранное'}
          </button>
          <button
            type="button"
            onClick={() => {
              onPing(contextMenu.profile.id);
              setContextMenu(null);
            }}
            className="flex w-full items-center gap-2 rounded-xl px-2.5 py-1.5 text-left text-[0.75rem] text-[var(--md-on-surface)] hover:bg-[var(--md-surface-container-highest)]"
          >
            <Gauge className="h-3.5 w-3.5" />
            Проверить TCP
          </button>
          <button
            type="button"
            onClick={() => {
              startRename(contextMenu.profile);
              setContextMenu(null);
            }}
            className="flex w-full items-center gap-2 rounded-xl px-2.5 py-1.5 text-left text-[0.75rem] text-[var(--md-on-surface)] hover:bg-[var(--md-surface-container-highest)]"
          >
            <Pencil className="h-3.5 w-3.5" />
            Переименовать
          </button>
          <button
            type="button"
            onClick={() => {
              onDelete(contextMenu.profile.id);
              setContextMenu(null);
            }}
            className="mt-0.5 flex w-full items-center gap-2 rounded-xl px-2.5 py-1.5 text-left text-[0.75rem] text-[var(--md-error)] hover:bg-[var(--md-error-container)]"
          >
            <Trash2 className="h-3.5 w-3.5" />
            Удалить
          </button>
        </div>
      )}
    </div>
  );
}
