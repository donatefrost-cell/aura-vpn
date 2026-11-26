import {
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  ChevronDown,
  Download,
  GitFork,
  Globe,
  Laptop,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
  Upload,
} from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { isRuBypassActive } from '../utils/format';
import {
  M3Button,
  M3Checkbox,
  M3Chip,
  M3EmptyState,
  M3IconButton,
  M3SearchBar,
  M3SegmentedButton,
  M3Select,
  M3StatusBadge,
  M3SurfaceCard,
  M3Switch,
  M3Tooltip,
} from '../components/md3';
import { api } from '../services/api';
import type {
  AppSettings,
  DnsRouteCheckResult,
  RouteTestResult,
  RoutingConfig,
  RoutingProfile,
  RoutingRule,
  RuleAction,
  RuleMatchType,
  RulepackStatus,
  RuCategoriesConfig,
  SplitTunnelMode,
} from '../types/vpn';

type RoutingUiMode = 'simple' | 'advanced';

interface RoutingViewProps {
  settings: AppSettings;
  rulepackStatus: RulepackStatus | null;
  onUpdateRouting: (next: RoutingConfig) => void;
  onSwitchToTun: () => void;
  onUpdateRulepack: (url?: string | null) => Promise<void>;
  onRollbackRulepack: () => Promise<void>;
  onNotify: (tone: 'success' | 'error' | 'info', title: string, description?: string) => void;
}

const PROFILE_CARDS: Array<{
  id: RoutingProfile;
  title: string;
  subtitle: string;
  badge?: string;
}> = [
  {
    id: 'ru_direct',
    title: 'Российские сервисы напрямую',
    subtitle: 'Банки, Госуслуги, маркетплейсы и .ru без VPN; остальной интернет — через туннель',
    badge: 'Рекомендуемый',
  },
  {
    id: 'all_vpn',
    title: 'Весь трафик через VPN',
    subtitle: 'Максимальная приватность: все внешние подключения идут через сервер VPN',
  },
  {
    id: 'bypass_apps',
    title: 'Кроме выбранных приложений',
    subtitle: 'Игры, торренты или указанные программы обходят VPN (требуется режим TUN)',
  },
  {
    id: 'only_apps',
    title: 'Только выбранные приложения',
    subtitle: 'Через VPN работают только программы из списка (требуется режим TUN)',
  },
  {
    id: 'custom',
    title: 'Пользовательский',
    subtitle: 'Гибкая комбинация ваших правил, категорий РФ и раздельного туннелирования',
  },
];

const SUGGESTED_APPS = [
  { exe: 'steam.exe', label: 'Steam' },
  { exe: 'discord.exe', label: 'Discord' },
  { exe: 'telegram.exe', label: 'Telegram' },
  { exe: 'chrome.exe', label: 'Chrome' },
  { exe: 'qbittorrent.exe', label: 'qBittorrent' },
];

function toCategoryKey(id: string): keyof RuCategoriesConfig {
  if (id === 'ru_tlds') return 'ruTlds';
  if (id === 'other_ru') return 'otherRu';
  return id as keyof RuCategoriesConfig;
}

export function RoutingView({
  settings,
  rulepackStatus,
  onUpdateRouting,
  onSwitchToTun,
  onUpdateRulepack,
  onRollbackRulepack,
  onNotify,
}: RoutingViewProps) {
  const { routing } = settings;

  const [uiMode, setUiMode] = useState<RoutingUiMode>('simple');
  const [ruExpanded, setRuExpanded] = useState(true);

  // Split Tunneling input
  const [appInput, setAppInput] = useState('');

  // Custom rules form & search
  const [ruleSearch, setRuleSearch] = useState('');
  const [newMatchType, setNewMatchType] = useState<RuleMatchType>('domain');
  const [newPattern, setNewPattern] = useState('');
  const [newAction, setNewAction] = useState<RuleAction>('direct');
  const [newNote, setNewNote] = useState('');
  const [ruleFormError, setRuleFormError] = useState<string | null>(null);

  // Route diagnostics tool
  const [testQuery, setTestQuery] = useState('');
  const [testProcess, setTestProcess] = useState('');
  const [isTestingRoute, setIsTestingRoute] = useState(false);
  const [routeResult, setRouteResult] = useState<RouteTestResult | null>(null);
  const [isCheckingDns, setIsCheckingDns] = useState(false);
  const [dnsResult, setDnsResult] = useState<DnsRouteCheckResult | null>(null);

  // Rulepack updater state
  const [rulepackUrlDraft, setRulepackUrlDraft] = useState(routing.rulepackUpdateUrl ?? '');
  const [isUpdatingPack, setIsUpdatingPack] = useState(false);

  const importRulesRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    setRulepackUrlDraft(routing.rulepackUpdateUrl ?? '');
  }, [routing.rulepackUpdateUrl]);

  const categories = rulepackStatus?.categories ?? [];
  const activeCategoryCount = useMemo(() => {
    const cfg = routing.ruCategories;
    return Object.values(cfg).filter(Boolean).length;
  }, [routing.ruCategories]);

  const applyProfile = (profile: RoutingProfile) => {
    if (profile === 'all_vpn') {
      onUpdateRouting({
        ...routing,
        profile,
        bypassRuDomains: false,
        splitTunnelMode: 'all_vpn',
      });
    } else if (profile === 'ru_direct') {
      onUpdateRouting({
        ...routing,
        profile,
        bypassRuDomains: true,
        splitTunnelMode: 'all_vpn',
      });
    } else if (profile === 'bypass_apps') {
      onUpdateRouting({
        ...routing,
        profile,
        splitTunnelMode: 'bypass_apps',
      });
    } else if (profile === 'only_apps') {
      onUpdateRouting({
        ...routing,
        profile,
        splitTunnelMode: 'only_apps',
      });
    } else {
      onUpdateRouting({
        ...routing,
        profile: 'custom',
      });
    }
  };

  const toggleRuDirect = (enabled: boolean) => {
    const nextProfile: RoutingProfile =
      enabled && routing.profile === 'all_vpn'
        ? 'ru_direct'
        : !enabled && routing.profile === 'ru_direct'
          ? 'all_vpn'
          : routing.profile;
    onUpdateRouting({
      ...routing,
      profile: nextProfile,
      bypassRuDomains: enabled,
    });
  };

  const toggleCategory = (id: keyof RuCategoriesConfig, val: boolean) => {
    const nextCats = { ...routing.ruCategories, [id]: val };
    onUpdateRouting({
      ...routing,
      bypassRuDomains: true,
      profile: routing.profile === 'all_vpn' ? 'ru_direct' : routing.profile,
      ruCategories: nextCats,
    });
  };

  const setAllCategories = (enabled: boolean) => {
    onUpdateRouting({
      ...routing,
      bypassRuDomains: enabled ? true : routing.bypassRuDomains,
      ruCategories: {
        banks: enabled,
        gov: enabled,
        marketplaces: enabled,
        search: enabled,
        social: enabled,
        mail: enabled,
        telecom: enabled,
        education: enabled,
        ruTlds: enabled,
        otherRu: enabled,
      },
    });
  };

  const handleAddApp = (rawName?: string) => {
    const candidate = (rawName ?? appInput).trim().toLowerCase();
    if (!candidate) return;
    if (routing.splitApps.some((a) => a.toLowerCase() === candidate)) {
      if (!rawName) setAppInput('');
      return;
    }
    const nextMode: SplitTunnelMode =
      routing.splitTunnelMode === 'all_vpn' ? 'bypass_apps' : routing.splitTunnelMode;
    onUpdateRouting({
      ...routing,
      splitTunnelMode: nextMode,
      splitApps: [...routing.splitApps, candidate],
    });
    if (!rawName) setAppInput('');
  };

  const handleRemoveApp = (exe: string) => {
    onUpdateRouting({
      ...routing,
      splitApps: routing.splitApps.filter((a) => a !== exe),
    });
  };

  const handleAddRule = () => {
    const pattern = newPattern.trim();
    if (!pattern) {
      setRuleFormError('Введите шаблон правила (домен, CIDR или имя процесса)');
      return;
    }
    if (pattern.length > 240) {
      setRuleFormError('Слишком длинный шаблон (максимум 240 символов)');
      return;
    }
    setRuleFormError(null);

    const normalized =
      newMatchType === 'domain' &&
      !pattern.includes(':') &&
      !pattern.startsWith('domain:') &&
      !pattern.startsWith('full:') &&
      !pattern.startsWith('keyword:')
        ? `domain:${pattern}`
        : pattern;

    const rule: RoutingRule = {
      id: `rule-${Date.now()}-${Math.random().toString(16).slice(2, 6)}`,
      enabled: true,
      matchType: newMatchType,
      pattern: normalized,
      action: newAction,
      note: newNote.trim() || null,
    };

    onUpdateRouting({
      ...routing,
      customRules: [rule, ...routing.customRules],
    });
    setNewPattern('');
    setNewNote('');
  };

  const moveRule = (index: number, delta: -1 | 1) => {
    const target = index + delta;
    if (target < 0 || target >= routing.customRules.length) return;
    const copy = [...routing.customRules];
    const [item] = copy.splice(index, 1);
    copy.splice(target, 0, item);
    onUpdateRouting({ ...routing, customRules: copy });
  };

  const toggleRuleEnabled = (id: string) => {
    onUpdateRouting({
      ...routing,
      customRules: routing.customRules.map((r) =>
        r.id === id ? { ...r, enabled: !r.enabled } : r,
      ),
    });
  };

  const deleteRule = (id: string) => {
    onUpdateRouting({
      ...routing,
      customRules: routing.customRules.filter((r) => r.id !== id),
    });
  };

  const handleExportRulesJson = () => {
    const payload = JSON.stringify(routing.customRules, null, 2);
    const blob = new Blob([payload], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aura-routing-rules-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    onNotify('success', 'Правила экспортированы', `Выгружено правил: ${routing.customRules.length}`);
  };

  const handleImportRulesJson = async (file?: File | null) => {
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = JSON.parse(text) as unknown;
      if (!Array.isArray(parsed)) {
        throw new Error('Ожидается JSON-массив правил маршрутизации');
      }
      const imported: RoutingRule[] = [];
      for (const raw of parsed) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Partial<RoutingRule>;
        if (!r.pattern || typeof r.pattern !== 'string') continue;
        const matchType: RuleMatchType =
          r.matchType === 'ip' || r.matchType === 'process' ? r.matchType : 'domain';
        const action: RuleAction =
          r.action === 'proxy' || r.action === 'block' ? r.action : 'direct';
        imported.push({
          id: `rule-imp-${Date.now()}-${Math.random().toString(16).slice(2, 6)}`,
          enabled: r.enabled !== false,
          matchType,
          pattern: r.pattern.trim(),
          action,
          note: typeof r.note === 'string' ? r.note : null,
        });
      }
      if (imported.length === 0) {
        throw new Error('В файле не найдено корректных правил');
      }
      onUpdateRouting({
        ...routing,
        customRules: [...imported, ...routing.customRules],
      });
      onNotify('success', 'Правила импортированы', `Добавлено правил: ${imported.length}`);
    } catch (err) {
      onNotify('error', 'Ошибка импорта правил', String(err));
    }
  };

  const handleRunRouteTest = async () => {
    if (!testQuery.trim() && !testProcess.trim()) {
      onNotify('info', 'Введите домен, IP или процесс', 'Например: sberbank.ru или youtube.com');
      return;
    }
    setIsTestingRoute(true);
    try {
      const res = await api.testRoute(testQuery, testProcess || null);
      setRouteResult(res);
    } catch (err) {
      onNotify('error', 'Ошибка проверки маршрута', String(err));
    } finally {
      setIsTestingRoute(false);
    }
  };

  const handleRunDnsLookup = async () => {
    const clean = testQuery.trim();
    if (!clean) {
      onNotify('info', 'Укажите домен для DNS-запроса');
      return;
    }
    setIsCheckingDns(true);
    try {
      const res = await api.dnsLookupRoute(clean);
      setDnsResult(res);
    } catch (err) {
      onNotify('error', 'Ошибка DNS-проверки', String(err));
    } finally {
      setIsCheckingDns(false);
    }
  };

  const filteredRules = useMemo(() => {
    const q = ruleSearch.trim().toLowerCase();
    if (!q) return routing.customRules;
    return routing.customRules.filter(
      (r) =>
        r.pattern.toLowerCase().includes(q) ||
        (r.note ?? '').toLowerCase().includes(q) ||
        r.action.toLowerCase().includes(q),
    );
  }, [routing.customRules, ruleSearch]);

  const splitTunnelNeedsTun =
    (routing.splitTunnelMode !== 'all_vpn' ||
      routing.customRules.some((r) => r.enabled && r.matchType === 'process')) &&
    settings.connectionMode !== 'tun';

  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-3">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-2.5">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="font-display text-lg font-bold tracking-tight text-[var(--md-on-surface)]">
              Маршрутизация
            </h1>
            <M3StatusBadge tone={isRuBypassActive(routing) ? 'success' : 'neutral'}>
              {isRuBypassActive(routing) ? `РФ напрямую (${activeCategoryCount}/10)` : 'Весь трафик в VPN'}
            </M3StatusBadge>
          </div>
          <p className="text-[12px] text-[var(--md-on-surface-variant)]">
            Умные правила Xray-core для российских сервисов, приложений и пользовательских доменов
          </p>
        </div>

        <M3SegmentedButton
          size="sm"
          value={uiMode}
          onChange={setUiMode}
          options={[
            { id: 'simple', label: 'Простой режим' },
            { id: 'advanced', label: 'Расширенный режим' },
          ]}
        />
      </div>

      {/* Honest SystemProxy -> TUN banner whenever app-level rules are configured */}
      {splitTunnelNeedsTun && (
        <div className="flex flex-wrap items-center justify-between gap-2 rounded-2xl border border-[var(--md-warning)]/40 bg-[var(--md-warning-container)] px-3.5 py-2.5">
          <div className="flex items-start gap-2.5">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-[var(--md-warning)]" />
            <div className="text-[12px] text-[var(--md-on-surface)]">
              <div className="font-semibold">
                Раздельное туннелирование по имени процесса работает только в режиме TUN
              </div>
              <div className="text-[11px] text-[var(--md-on-surface-variant)]">
                Сейчас активен «Системный прокси» — доменные и IP-правила работают, но правила по процессам (.exe) требуют виртуальный интерфейс TUN.
              </div>
            </div>
          </div>
          <M3Button variant="tonal" size="sm" onClick={onSwitchToTun}>
            Переключить на TUN
          </M3Button>
        </div>
      )}

      {uiMode === 'simple' ? (
        <div className="space-y-3">
          {/* Profile selector */}
          <M3SurfaceCard level="default" className="p-3.5">
            <div className="mb-2.5 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Sparkles className="h-4 w-4 text-[var(--md-primary)]" />
                <h2 className="text-[13.5px] font-bold text-[var(--md-on-surface)]">
                  Профиль маршрутизации
                </h2>
              </div>
              <span className="text-[11px] text-[var(--md-on-surface-variant)]">
                Применяется при следующем переподключении
              </span>
            </div>

            <div className="grid grid-cols-1 gap-2 md:grid-cols-2 lg:grid-cols-3">
              {PROFILE_CARDS.map((card) => {
                const selected = routing.profile === card.id;
                return (
                  <button
                    key={card.id}
                    type="button"
                    onClick={() => applyProfile(card.id)}
                    className={`flex flex-col justify-between rounded-2xl border p-3 text-left transition-all ${
                      selected
                        ? 'border-[var(--md-primary)] bg-[var(--md-primary-container)]/35'
                        : 'border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] hover:bg-[var(--md-surface-container-high)]'
                    }`}
                  >
                    <div>
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-[12.5px] font-bold text-[var(--md-on-surface)]">
                          {card.title}
                        </span>
                        {card.badge && (
                          <span className="rounded-md bg-[var(--md-secondary-container)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--md-on-secondary-container)]">
                            {card.badge}
                          </span>
                        )}
                      </div>
                      <p className="mt-1 text-[11px] leading-snug text-[var(--md-on-surface-variant)]">
                        {card.subtitle}
                      </p>
                    </div>
                  </button>
                );
              })}
            </div>
          </M3SurfaceCard>

          {/* Featured Card: Российские сервисы напрямую */}
          <M3SurfaceCard level="default" className="p-3.5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="flex min-w-0 flex-1 items-start gap-3">
                <div className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--md-primary-container)] text-[var(--md-on-primary-container)]">
                  <Globe className="h-4.5 w-4.5" />
                </div>
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <h2 className="text-[14px] font-bold text-[var(--md-on-surface)]">
                      Российские сервисы напрямую
                    </h2>
                    <M3StatusBadge tone={routing.bypassRuDomains ? 'success' : 'neutral'}>
                      {routing.bypassRuDomains
                        ? `${activeCategoryCount} из ${categories.length || 10} категорий`
                        : 'Отключено'}
                    </M3StatusBadge>
                  </div>
                  <p className="mt-0.5 text-[12px] text-[var(--md-on-surface-variant)]">
                    Локальный пакет правил + Split DNS ({settings.dns.directDns}) позволяют открывать банки, Госуслуги и российские сайты без отключения VPN.
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <M3Switch
                  checked={routing.bypassRuDomains}
                  onChange={toggleRuDirect}
                  ariaLabel="Российские сервисы напрямую"
                />
                <M3IconButton
                  size="sm"
                  onClick={() => setRuExpanded((v) => !v)}
                  aria-label="Раскрыть категории РФ"
                >
                  <ChevronDown
                    className={`h-4 w-4 transition-transform ${ruExpanded ? 'rotate-180' : ''}`}
                  />
                </M3IconButton>
              </div>
            </div>

            {/* Security disclosure notice */}
            <div className="mt-3 flex items-start gap-2 rounded-xl bg-[var(--md-surface-container-low)] px-3 py-2 text-[11.5px] text-[var(--md-on-surface-variant)]">
              <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--md-primary)]" />
              <span>
                Российские ресурсы будут идти напрямую через вашего провайдера без VPN-туннеля. Внешние глобальные CDN (Cloudflare, Akamai, Fastly) в эти списки не включены.
              </span>
            </div>

            {ruExpanded && (
              <div className="mt-3 space-y-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-[11.5px] font-semibold text-[var(--md-on-surface-variant)]">
                    Категории прямого маршрута ({rulepackStatus?.totalDomains ?? 150}+ правил)
                  </span>
                  <div className="flex items-center gap-1.5">
                    <M3Chip variant="assist" onClick={() => setAllCategories(true)}>
                      Включить все
                    </M3Chip>
                    <M3Chip variant="assist" onClick={() => setAllCategories(false)}>
                      Выключить все
                    </M3Chip>
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                  {categories.map((cat) => {
                    const catKey = toCategoryKey(cat.id);
                    const checked = routing.ruCategories[catKey];
                    return (
                      <div
                        key={cat.id}
                        className={`flex items-start justify-between gap-2.5 rounded-xl border p-2.5 transition-colors ${
                          routing.bypassRuDomains && checked
                            ? 'border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)]'
                            : 'border-[var(--md-outline-variant)]/60 bg-[var(--md-surface-container-lowest)] opacity-75'
                        }`}
                      >
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-1.5">
                            <span className="text-[12.5px] font-semibold text-[var(--md-on-surface)]">
                              {cat.title}
                            </span>
                            <span className="rounded bg-[var(--md-surface-container-highest)] px-1.5 py-0.2 font-mono text-[10px] text-[var(--md-on-surface-variant)]">
                              {cat.domainCount}
                            </span>
                          </div>
                          <p className="mt-0.5 text-[11px] text-[var(--md-on-surface-variant)]">
                            {cat.description}
                          </p>
                          <div className="mt-1 truncate font-mono text-[10px] text-[var(--md-on-surface-variant)]/80">
                            {cat.examples.join(', ')}
                          </div>
                        </div>

                        <M3Switch
                          checked={checked}
                          disabled={!routing.bypassRuDomains}
                          onChange={(v) => toggleCategory(catKey, v)}
                          ariaLabel={cat.title}
                        />
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </M3SurfaceCard>

          {/* Bottom Grid: LAN Bypass + Split Tunneling Apps */}
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-12">
            <M3SurfaceCard level="default" className="p-3.5 lg:col-span-5">
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-start gap-2.5">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-[var(--md-surface-container-highest)] text-[var(--md-on-surface)]">
                    <Laptop className="h-4 w-4" />
                  </div>
                  <div>
                    <h3 className="text-[13px] font-bold text-[var(--md-on-surface)]">
                      Локальная сеть (LAN) напрямую
                    </h3>
                    <p className="mt-0.5 text-[11px] text-[var(--md-on-surface-variant)]">
                      Роутер (192.168.*), localhost, принтеры и адреса корпоративной подсети всегда работают напрямую в обход VPN.
                    </p>
                  </div>
                </div>
                <M3Switch
                  checked={routing.bypassLan}
                  onChange={(v) => onUpdateRouting({ ...routing, bypassLan: v })}
                  ariaLabel="Локальная сеть напрямую"
                />
              </div>
            </M3SurfaceCard>

            <M3SurfaceCard level="default" className="p-3.5 lg:col-span-7">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <GitFork className="h-4 w-4 text-[var(--md-primary)]" />
                  <h3 className="text-[0.8125rem] font-bold text-[var(--md-on-surface)]">
                    Раздельное туннелирование (приложения)
                  </h3>
                </div>
                <M3Select
                  size="sm"
                  align="right"
                  ariaLabel="Режим раздельного туннелирования"
                  value={routing.splitTunnelMode}
                  onChange={(m) => {
                    onUpdateRouting({
                      ...routing,
                      splitTunnelMode: m,
                      profile:
                        m === 'bypass_apps'
                          ? 'bypass_apps'
                          : m === 'only_apps'
                            ? 'only_apps'
                            : routing.profile,
                    });
                  }}
                  options={[
                    { value: 'all_vpn', label: 'Не использовать (все по правилам)' },
                    { value: 'bypass_apps', label: 'В обход VPN для списка' },
                    { value: 'only_apps', label: 'Только для списка' },
                  ]}
                />
              </div>

              {settings.connectionMode !== 'tun' && routing.splitTunnelMode !== 'all_vpn' && (
                <div className="mt-2.5 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--md-warning)]/40 bg-[var(--md-warning-container)] px-3 py-2 text-[0.72rem] text-[var(--md-on-surface)]">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-[var(--md-warning)]" />
                    <span>
                      Раздельное туннелирование по процессам активно только в режиме TUN (весь ПК).
                    </span>
                  </div>
                  <M3Button variant="tonal" size="sm" onClick={onSwitchToTun}>
                    Включить TUN
                  </M3Button>
                </div>
              )}

              <div className="mt-2.5 flex gap-2">
                <input
                  value={appInput}
                  onChange={(e) => setAppInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleAddApp();
                  }}
                  placeholder="Имя процесса (например, steam.exe)"
                  className="h-8.5 flex-1 rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-highest)] px-2.5 text-[0.75rem] text-[var(--md-on-surface)] focus:border-[var(--md-primary)]"
                />
                <M3Button
                  variant="tonal"
                  size="sm"
                  onClick={() => handleAddApp()}
                  leadingIcon={<Plus className="h-3.5 w-3.5" />}
                >
                  Добавить
                </M3Button>
              </div>

              <div className="mt-2 flex flex-wrap items-center gap-1.5">
                {SUGGESTED_APPS.map((s) => {
                  const exists = routing.splitApps.some(
                    (a) => a.toLowerCase() === s.exe.toLowerCase(),
                  );
                  return (
                    <M3Chip
                      key={s.exe}
                      active={exists}
                      onClick={() => (exists ? handleRemoveApp(s.exe) : handleAddApp(s.exe))}
                    >
                      {exists ? `✓ ${s.label}` : `+ ${s.label}`}
                    </M3Chip>
                  );
                })}
              </div>

              {routing.splitApps.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {routing.splitApps.map((exe) => (
                    <span
                      key={exe}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--md-secondary-container)] px-2 py-0.5 font-mono text-[11px] font-medium text-[var(--md-on-secondary-container)]"
                    >
                      {exe}
                      <button
                        type="button"
                        onClick={() => handleRemoveApp(exe)}
                        className="opacity-70 hover:opacity-100"
                        aria-label={`Удалить ${exe}`}
                      >
                        ×
                      </button>
                    </span>
                  ))}
                </div>
              )}
            </M3SurfaceCard>
          </div>
        </div>
      ) : (
        /* ADVANCED MODE */
        <div className="space-y-3">
          {/* Route Diagnostics + OS DNS Lookup */}
          <M3SurfaceCard level="default" className="p-3.5">
            <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
              <div>
                <h2 className="text-[13.5px] font-bold text-[var(--md-on-surface)]">
                  Диагностика маршрута и DNS
                </h2>
                <p className="text-[11px] text-[var(--md-on-surface-variant)]">
                  Статический анализ активной конфигурации правил (до отправки сетевого пакета) и живая DNS-проверка ОС
                </p>
              </div>
              <M3StatusBadge tone="primary">4-уровневый приоритет</M3StatusBadge>
            </div>

            <div className="grid grid-cols-1 gap-2 sm:grid-cols-12">
              <input
                value={testQuery}
                onChange={(e) => setTestQuery(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') handleRunRouteTest();
                }}
                placeholder="Домен, URL или IP (например, online.sberbank.ru)"
                className="h-9 rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-highest)] px-3 text-[12.5px] text-[var(--md-on-surface)] outline-none focus:border-[var(--md-primary)] sm:col-span-6"
              />
              <input
                value={testProcess}
                onChange={(e) => setTestProcess(e.target.value)}
                placeholder="Процесс (опц., chrome.exe)"
                className="h-9 rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-highest)] px-3 text-[12.5px] text-[var(--md-on-surface)] outline-none focus:border-[var(--md-primary)] sm:col-span-3"
              />
              <div className="flex gap-1.5 sm:col-span-3">
                <M3Button
                  variant="filled"
                  size="sm"
                  onClick={handleRunRouteTest}
                  disabled={isTestingRoute}
                  leadingIcon={<Search className="h-3.5 w-3.5" />}
                  className="flex-1"
                >
                  Маршрут
                </M3Button>
                <M3Button
                  variant="tonal"
                  size="sm"
                  onClick={handleRunDnsLookup}
                  disabled={isCheckingDns}
                >
                  DNS
                </M3Button>
              </div>
            </div>

            {routeResult && (
              <div className="mt-2.5 rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <M3StatusBadge
                      tone={
                        routeResult.action === 'proxy'
                          ? 'primary'
                          : routeResult.action === 'direct'
                            ? 'success'
                            : 'error'
                      }
                    >
                      {routeResult.action === 'proxy'
                        ? 'ЧЕРЕЗ VPN'
                        : routeResult.action === 'direct'
                          ? 'НАПРЯМУЮ (DIRECT)'
                          : 'БЛОКИРОВАТЬ'}
                    </M3StatusBadge>
                    <span className="font-mono text-[12px] font-semibold text-[var(--md-on-surface)]">
                      {routeResult.normalizedHost}
                    </span>
                  </div>
                  <span className="text-[11px] font-medium text-[var(--md-on-surface-variant)]">
                    {routeResult.priorityLabel}
                  </span>
                </div>
                <p className="mt-1.5 text-[12px] text-[var(--md-on-surface)]">
                  {routeResult.explanation}
                </p>
                <div className="mt-1.5 flex flex-wrap gap-2 text-[11px] text-[var(--md-on-surface-variant)]">
                  <span>
                    Правило:{' '}
                    <code className="rounded bg-[var(--md-surface-container-highest)] px-1.5 py-0.5 font-mono text-[var(--md-on-surface)]">
                      {routeResult.matchedRule}
                    </code>
                  </span>
                  {routeResult.matchedCategory && (
                    <span>Категория: {routeResult.matchedCategory}</span>
                  )}
                </div>
                {routeResult.requiresTunNote && (
                  <div className="mt-1.5 text-[11px] font-medium text-[var(--md-warning)]">
                    Внимание: правило процесса действует только при подключении через TUN.
                  </div>
                )}
              </div>
            )}

            {dnsResult && (
              <div className="mt-2 rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] px-3 py-2 text-[11.5px]">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-semibold text-[var(--md-on-surface)]">
                    DNS-резолв ОС для <code className="font-mono">{dnsResult.domain}</code>:
                  </span>
                  {dnsResult.error ? (
                    <span className="text-[var(--md-error)]">{dnsResult.error}</span>
                  ) : (
                    <span className="font-mono text-[var(--md-on-surface)]">
                      {dnsResult.resolvedIps.join(', ') || 'Нет A/AAAA записей'}
                    </span>
                  )}
                </div>
              </div>
            )}
          </M3SurfaceCard>

          {/* Custom Rules Editor */}
          <M3SurfaceCard level="default" className="p-3.5">
            <div className="mb-2.5 flex flex-wrap items-center justify-between gap-2">
              <div>
                <h2 className="text-[13.5px] font-bold text-[var(--md-on-surface)]">
                  Пользовательские правила ({routing.customRules.length})
                </h2>
                <p className="text-[11px] text-[var(--md-on-surface-variant)]">
                  Приоритет: 1. LAN → 2. Ваши правила (сверху вниз) → 3. Российские сервисы → 4. По умолчанию
                </p>
              </div>
              <div className="flex items-center gap-1.5">
                <input
                  ref={importRulesRef}
                  type="file"
                  accept="application/json,.json"
                  className="hidden"
                  onChange={(e) => {
                    handleImportRulesJson(e.target.files?.[0]);
                    e.target.value = '';
                  }}
                />
                <M3Button
                  variant="outlined"
                  size="sm"
                  onClick={() => importRulesRef.current?.click()}
                  leadingIcon={<Upload className="h-3.5 w-3.5" />}
                >
                  Импорт JSON
                </M3Button>
                <M3Button
                  variant="outlined"
                  size="sm"
                  onClick={handleExportRulesJson}
                  disabled={routing.customRules.length === 0}
                  leadingIcon={<Download className="h-3.5 w-3.5" />}
                >
                  Экспорт JSON
                </M3Button>
              </div>
            </div>

            {/* Add Rule Form */}
            <div className="rounded-xl bg-[var(--md-surface-container-low)] p-2.5">
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-12">
                <M3Select
                  size="sm"
                  ariaLabel="Тип совпадения"
                  value={newMatchType}
                  onChange={setNewMatchType}
                  options={[
                    { value: 'domain', label: 'Домен' },
                    { value: 'ip', label: 'IP / CIDR' },
                    { value: 'process', label: 'Процесс' },
                  ]}
                  className="sm:col-span-2 w-full"
                />
                <input
                  value={newPattern}
                  onChange={(e) => {
                    setNewPattern(e.target.value);
                    if (ruleFormError) setRuleFormError(null);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleAddRule();
                  }}
                  placeholder={
                    newMatchType === 'domain'
                      ? 'example.com или keyword:bank'
                      : newMatchType === 'ip'
                        ? '10.0.0.0/8'
                        : 'chrome.exe'
                  }
                  className="h-8 rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-highest)] px-2.5 text-[0.75rem] text-[var(--md-on-surface)] focus:border-[var(--md-primary)] sm:col-span-4"
                />
                <M3Select
                  size="sm"
                  ariaLabel="Действие правила"
                  value={newAction}
                  onChange={setNewAction}
                  options={[
                    { value: 'direct', label: 'Напрямую' },
                    { value: 'proxy', label: 'Через VPN' },
                    { value: 'block', label: 'Блок' },
                  ]}
                  className="sm:col-span-2 w-full"
                />
                <input
                  value={newNote}
                  onChange={(e) => setNewNote(e.target.value)}
                  placeholder="Заметка"
                  className="h-8 rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-highest)] px-2.5 text-[0.75rem] text-[var(--md-on-surface)] focus:border-[var(--md-primary)] sm:col-span-2"
                />
                <M3Button
                  variant="filled"
                  size="sm"
                  onClick={handleAddRule}
                  leadingIcon={<Plus className="h-3.5 w-3.5" />}
                  className="sm:col-span-2"
                >
                  Добавить
                </M3Button>
              </div>
              {ruleFormError && (
                <p className="mt-1.5 text-[0.6875rem] font-medium text-[var(--md-error)]">
                  {ruleFormError}
                </p>
              )}
            </div>

            {routing.customRules.length > 0 && (
              <div className="mt-2.5">
                <M3SearchBar
                  value={ruleSearch}
                  onChange={setRuleSearch}
                  placeholder="Поиск по правилам..."
                />
              </div>
            )}

            <div className="mt-2.5 space-y-1.5">
              {filteredRules.length === 0 ? (
                <M3EmptyState
                  icon={<GitFork className="h-6 w-6" />}
                  title={routing.customRules.length === 0 ? 'Пользовательских правил нет' : 'Правила не найдены'}
                  description="Добавьте индивидуальные исключения доменов, подсетей IP или процессов с приоритетом выше глобальных списков."
                />
              ) : (
                filteredRules.map((rule) => {
                  const realIndex = routing.customRules.findIndex((r) => r.id === rule.id);
                  return (
                    <div
                      key={rule.id}
                      className={`flex flex-wrap items-center justify-between gap-2 rounded-xl border px-3 py-2 ${
                        rule.enabled
                          ? 'border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)]'
                          : 'border-[var(--md-outline-variant)]/50 bg-[var(--md-surface-container-lowest)] opacity-60'
                      }`}
                    >
                      <div className="flex min-w-0 flex-1 items-center gap-2">
                        <M3Checkbox
                          size="sm"
                          checked={rule.enabled}
                          onChange={() => toggleRuleEnabled(rule.id)}
                          ariaLabel={`Включить правило ${rule.pattern}`}
                        />
                        <span className="rounded bg-[var(--md-surface-container-highest)] px-1.5 py-0.5 text-[0.625rem] font-semibold uppercase text-[var(--md-on-surface-variant)]">
                          {rule.matchType}
                        </span>
                        <code className="truncate font-mono text-[0.75rem] font-semibold text-[var(--md-on-surface)]">
                          {rule.pattern}
                        </code>
                        <M3StatusBadge
                          tone={
                            rule.action === 'proxy'
                              ? 'primary'
                              : rule.action === 'direct'
                                ? 'success'
                                : 'error'
                          }
                        >
                          {rule.action === 'proxy'
                            ? 'Через VPN'
                            : rule.action === 'direct'
                              ? 'Напрямую'
                              : 'Блок'}
                        </M3StatusBadge>
                        {rule.note && (
                          <span className="truncate text-[0.6875rem] text-[var(--md-on-surface-variant)]">
                            {rule.note}
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-1">
                        <M3IconButton
                          size="sm"
                          disabled={realIndex <= 0}
                          onClick={() => moveRule(realIndex, -1)}
                          tooltip="Выше по приоритету"
                          aria-label="Выше по приоритету"
                        >
                          <ArrowUp className="h-3.5 w-3.5" />
                        </M3IconButton>
                        <M3IconButton
                          size="sm"
                          disabled={realIndex >= routing.customRules.length - 1}
                          onClick={() => moveRule(realIndex, 1)}
                          tooltip="Ниже по приоритету"
                          aria-label="Ниже по приоритету"
                        >
                          <ArrowDown className="h-3.5 w-3.5" />
                        </M3IconButton>
                        <M3IconButton
                          size="sm"
                          onClick={() => deleteRule(rule.id)}
                          tooltip="Удалить правило"
                          aria-label="Удалить правило"
                          className="text-[var(--md-error)] hover:bg-[var(--md-error-container)]"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </M3IconButton>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </M3SurfaceCard>

          {/* Local Rulepack Updates & Rollback */}
          <M3SurfaceCard level="default" className="p-3.5">
            <div className="flex flex-wrap items-start justify-between gap-2">
              <div>
                <div className="flex items-center gap-2">
                  <ShieldCheck className="h-4 w-4 text-[var(--md-success)]" />
                  <h2 className="text-[0.84375rem] font-bold text-[var(--md-on-surface)]">
                    Локальный пакет российских правил
                  </h2>
                </div>
                <p className="mt-0.5 text-[0.72rem] text-[var(--md-on-surface-variant)] font-mono-num">
                  Версия: <strong>{rulepackStatus?.version ?? 'встроенная'}</strong> • Доменов:{' '}
                  {rulepackStatus?.totalDomains ?? 150}+ • Источник: {rulepackStatus?.source ?? 'builtin'}
                </p>
              </div>
              <div className="flex items-center gap-1.5">
                <M3Tooltip label="База геодоменов Xray">
                  <M3StatusBadge tone={rulepackStatus?.geositePresent ? 'success' : 'neutral'}>
                    geosite: {rulepackStatus?.geositePresent ? 'есть' : 'встроенный'}
                  </M3StatusBadge>
                </M3Tooltip>
                <M3Tooltip label="База GeoIP адресов Xray">
                  <M3StatusBadge tone={rulepackStatus?.geoipPresent ? 'success' : 'neutral'}>
                    geoip: {rulepackStatus?.geoipPresent ? 'есть' : 'встроенный'}
                  </M3StatusBadge>
                </M3Tooltip>
              </div>
            </div>

            <div className="mt-3 flex flex-wrap items-center gap-2">
              <input
                value={rulepackUrlDraft}
                onChange={(e) => setRulepackUrlDraft(e.target.value)}
                onBlur={() =>
                  onUpdateRouting({
                    ...routing,
                    rulepackUpdateUrl: rulepackUrlDraft.trim() || null,
                  })
                }
                placeholder="HTTPS URL JSON-пакета правил РФ (необязательно)"
                className="h-8.5 min-w-[240px] flex-1 rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-highest)] px-3 text-[0.75rem] text-[var(--md-on-surface)] focus:border-[var(--md-primary)]"
              />
              <M3Button
                variant="tonal"
                size="sm"
                loading={isUpdatingPack}
                onClick={async () => {
                  setIsUpdatingPack(true);
                  try {
                    await onUpdateRulepack(rulepackUrlDraft.trim() || null);
                  } finally {
                    setIsUpdatingPack(false);
                  }
                }}
                leadingIcon={<RefreshCw className="h-3.5 w-3.5" />}
              >
                Обновить пакет правил
              </M3Button>
              {rulepackStatus?.hasBackup && (
                <M3Button
                  variant="outlined"
                  size="sm"
                  onClick={() => onRollbackRulepack()}
                  leadingIcon={<RotateCcw className="h-3.5 w-3.5" />}
                >
                  Восстановить прошлую версию
                </M3Button>
              )}
            </div>
          </M3SurfaceCard>
        </div>
      )}
    </div>
  );
}
