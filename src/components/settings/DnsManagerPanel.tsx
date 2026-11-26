import { Globe, Play, RefreshCw, ShieldAlert } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { DEFAULT_SETTINGS, normalizeDnsMode } from '../../config/defaultSettings';
import type { SettingLevel } from '../../config/settingsRegistry';
import { api } from '../../services/api';
import type {
  AppSettings,
  DnsInspectorReport,
  DnsLiveLookupResult,
  DnsServerTestResult,
} from '../../types/vpn';
import { M3Button, M3Chip, M3SegmentedButton, M3Select, M3StatusBadge, M3SurfaceCard, M3Switch } from '../md3';
import { SettingMetaRow } from './SettingMetaRow';

interface DnsManagerPanelProps {
  settings: AppSettings;
  level: SettingLevel;
  onUpdateSettings: (next: AppSettings) => void;
  highlightSettingId?: string | null;
}

const DNS_PRESETS = [
  { label: 'Cloudflare', value: '1.1.1.1' },
  { label: 'Cloudflare DoH', value: 'https://1.1.1.1/dns-query' },
  { label: 'Quad9', value: '9.9.9.9' },
  { label: 'Quad9 DoT', value: 'tls://dns.quad9.net' },
  { label: 'Google DoH', value: 'https://8.8.8.8/dns-query' },
  { label: 'Яндекс РФ', value: '77.88.8.8' },
];

export function DnsManagerPanel({
  settings,
  level,
  onUpdateSettings,
  highlightSettingId,
}: DnsManagerPanelProps) {
  const [report, setReport] = useState<DnsInspectorReport | null>(null);
  const [serverTest, setServerTest] = useState<DnsServerTestResult | null>(null);
  const [lookupRes, setLookupRes] = useState<DnsLiveLookupResult | null>(null);
  const [lookupDomain, setLookupDomain] = useState('one.one.one.one');
  const [testingServer, setTestingServer] = useState(false);
  const [testingLookup, setTestingLookup] = useState(false);
  const [primaryDraft, setPrimaryDraft] = useState(settings.dns.primaryDns);
  const [directDraft, setDirectDraft] = useState(settings.dns.directDns);
  const [fallbackDraft, setFallbackDraft] = useState(settings.dns.fallbackDns ?? '');
  const [directFallbackDraft, setDirectFallbackDraft] = useState(settings.dns.directFallbackDns ?? '');

  useEffect(() => {
    setPrimaryDraft(settings.dns.primaryDns);
    setDirectDraft(settings.dns.directDns);
    setFallbackDraft(settings.dns.fallbackDns ?? '');
    setDirectFallbackDraft(settings.dns.directFallbackDns ?? '');
  }, [
    settings.dns.primaryDns,
    settings.dns.directDns,
    settings.dns.fallbackDns,
    settings.dns.directFallbackDns,
  ]);

  const loadReport = useCallback(async () => {
    try {
      const r = await api.getDnsInspectorReport();
      setReport(r);
    } catch {
      // Ignore transient errors
    }
  }, []);

  useEffect(() => {
    void loadReport();
  }, [loadReport, settings.dns]);

  const dnsMode = normalizeDnsMode(settings.dns.mode);
  const patchDns = (patch: Partial<AppSettings['dns']>) => {
    onUpdateSettings({
      ...settings,
      dns: { ...settings.dns, ...patch },
    });
  };

  const handleTestPrimary = async (target: string) => {
    setTestingServer(true);
    try {
      const res = await api.testDnsServer(target, 'one.one.one.one');
      setServerTest(res);
    } catch (err) {
      setServerTest({
        server: target,
        protocol: 'dns',
        reachable: false,
        resolvedIps: [],
        error: typeof err === 'string' ? err : String(err),
        viaVpn: false,
      });
    } finally {
      setTestingServer(false);
    }
  };

  const handleLiveLookup = async () => {
    setTestingLookup(true);
    try {
      const res = await api.runDnsInspectorLookup(lookupDomain);
      setLookupRes(res);
    } catch (err) {
      setLookupRes({
        domain: lookupDomain,
        resolverUsed: 'Ошибка',
        resolvedIps: [],
        bypassedVpnWarning: false,
        error: typeof err === 'string' ? err : String(err),
      });
    } finally {
      setTestingLookup(false);
    }
  };

  const analysis = report?.configAnalysis;

  return (
    <div className="space-y-3" data-testid="panel-dns-manager">
      <SettingMetaRow
        id="dns-config"
        level="basic"
        title="Стратегия DNS, серверы и DoH/DoT"
        description="Управление резолвингом внутри и вне туннеля с защитой от DNS-утечек"
        defaultLabel="Hybrid • 1.1.1.1 / 77.88.8.8"
        recommendedLabel="Hybrid или VPN + DoH"
        impact="Режим Hybrid направляет зарубежные домены через VPN DNS, а российские домены — в Direct DNS."
        compatibility="В режиме TUN весь UDP/53 системный DNS перехватывается принудительно"
        requiresReconnect
        highlighted={highlightSettingId === 'dns-config'}
        modified={
          dnsMode !== DEFAULT_SETTINGS.dns.mode ||
          settings.dns.primaryDns !== DEFAULT_SETTINGS.dns.primaryDns ||
          settings.dns.directDns !== DEFAULT_SETTINGS.dns.directDns ||
          (settings.dns.fallbackDns ?? DEFAULT_SETTINGS.dns.fallbackDns) !== DEFAULT_SETTINGS.dns.fallbackDns ||
          Boolean(settings.dns.disableCache) ||
          Boolean(settings.dns.disableFallback)
        }
        onReset={() => onUpdateSettings({ ...settings, dns: { ...DEFAULT_SETTINGS.dns } })}
      >
        <div className="space-y-3">
          <div className="flex flex-wrap gap-1.5">
            <M3SegmentedButton
              size="sm"
              value={dnsMode}
              onChange={(mode) => patchDns({ mode })}
              options={[
                { id: 'hybrid', label: 'Гибридный' },
                { id: 'vpn', label: 'VPN DNS' },
                { id: 'config', label: 'Из конфига' },
                { id: 'system', label: 'Системный' },
                { id: 'custom', label: 'Свой' },
              ]}
            />
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <label className="space-y-1 text-[0.72rem]">
              <div className="flex items-center justify-between">
                <span className="font-medium text-[var(--md-on-surface-variant)]">Основной VPN DNS</span>
                <button
                  type="button"
                  onClick={() => void handleTestPrimary(settings.dns.primaryDns)}
                  disabled={testingServer}
                  className="text-[0.65rem] font-semibold text-[var(--md-primary)] hover:underline"
                >
                  {testingServer ? 'Проверка...' : 'Проверить'}
                </button>
              </div>
              <input
                type="text"
                aria-label="Основной VPN DNS"
                value={primaryDraft}
                onChange={(e) => setPrimaryDraft(e.target.value)}
                onBlur={() => {
                  const clean = primaryDraft.trim();
                  if (clean && clean !== settings.dns.primaryDns) {
                    patchDns({ primaryDns: clean });
                  } else if (!clean) {
                    setPrimaryDraft(settings.dns.primaryDns);
                  }
                }}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') e.currentTarget.blur();
                }}
                placeholder="1.1.1.1 или https://1.1.1.1/dns-query"
                className="w-full rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] px-3 py-1.5 font-mono text-[0.72rem] text-[var(--md-on-surface)]"
              />
            </label>

            <label className="space-y-1 text-[0.72rem]">
              <span className="font-medium text-[var(--md-on-surface-variant)]">Прямой DNS (для РФ / Direct)</span>
              <input
                type="text"
                aria-label="Прямой DNS"
                value={directDraft}
                onChange={(e) => setDirectDraft(e.target.value)}
                onBlur={() => {
                  const clean = directDraft.trim();
                  if (clean && clean !== settings.dns.directDns) {
                    patchDns({ directDns: clean });
                  } else if (!clean) {
                    setDirectDraft(settings.dns.directDns);
                  }
                }}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') e.currentTarget.blur();
                }}
                placeholder="77.88.8.8"
                className="w-full rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] px-3 py-1.5 font-mono text-[0.72rem] text-[var(--md-on-surface)]"
              />
            </label>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[0.65rem] text-[var(--md-on-surface-variant)]">Быстрый выбор VPN DNS:</span>
            {DNS_PRESETS.map((p) => (
              <M3Chip
                key={p.value}
                active={settings.dns.primaryDns === p.value}
                onClick={() => patchDns({ primaryDns: p.value })}
                className="text-[0.65rem]"
              >
                {p.label}
              </M3Chip>
            ))}
          </div>

          {level !== 'basic' && (
            <div className="grid grid-cols-1 gap-3 border-t border-[var(--md-outline-variant)] pt-2.5 sm:grid-cols-2">
              <label className="space-y-1 text-[0.7rem]">
                <span className="text-[var(--md-on-surface-variant)]">Резервный VPN DNS (Fallback)</span>
                <input
                  type="text"
                  aria-label="Резервный VPN DNS"
                  value={fallbackDraft}
                  onChange={(e) => setFallbackDraft(e.target.value)}
                  onBlur={() => {
                    const nextVal = fallbackDraft.trim() || null;
                    if (nextVal !== (settings.dns.fallbackDns ?? null)) {
                      patchDns({ fallbackDns: nextVal });
                    }
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') e.currentTarget.blur();
                  }}
                  placeholder="8.8.8.8"
                  className="w-full rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] px-3 py-1.5 font-mono text-[0.72rem]"
                />
              </label>
              <label className="space-y-1 text-[0.7rem]">
                <span className="text-[var(--md-on-surface-variant)]">Резервный Direct DNS</span>
                <input
                  type="text"
                  aria-label="Резервный прямой DNS"
                  value={directFallbackDraft}
                  onChange={(e) => setDirectFallbackDraft(e.target.value)}
                  onBlur={() => {
                    const nextVal = directFallbackDraft.trim() || null;
                    if (nextVal !== (settings.dns.directFallbackDns ?? null)) {
                      patchDns({ directFallbackDns: nextVal });
                    }
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') e.currentTarget.blur();
                  }}
                  placeholder="77.88.8.1"
                  className="w-full rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] px-3 py-1.5 font-mono text-[0.72rem]"
                />
              </label>

              <div className="flex items-center justify-between rounded-xl bg-[var(--md-surface-container)] px-3 py-2 text-[0.7rem]">
                <span>Отключить кэш DNS в Xray (disableCache)</span>
                <M3Switch
                  checked={Boolean(settings.dns.disableCache)}
                  onChange={(disableCache) => patchDns({ disableCache })}
                  ariaLabel="Отключить кэш DNS"
                />
              </div>
              <div className="flex items-center justify-between rounded-xl bg-[var(--md-surface-container)] px-3 py-2 text-[0.7rem]">
                <span>Запретить DNS fallback</span>
                <M3Switch
                  checked={Boolean(settings.dns.disableFallback)}
                  onChange={(disableFallback) => patchDns({ disableFallback })}
                  ariaLabel="Запретить DNS fallback"
                />
              </div>

              {level === 'expert' && (
                <div className="space-y-1 text-[0.7rem] sm:col-span-2">
                  <span>Query Strategy (Xray DNS)</span>
                  <M3Select
                    size="sm"
                    ariaLabel="DNS Query Strategy"
                    value={settings.dns.queryStrategy ?? 'auto'}
                    onChange={(v) => patchDns({ queryStrategy: v === 'auto' ? null : v })}
                    options={[
                      { value: 'auto', label: 'Авто (UseIP / UseIPv4 по настройке IPv6)' },
                      { value: 'UseIPv4', label: 'Только IPv4 (UseIPv4)' },
                      { value: 'UseIP', label: 'IPv4 + IPv6 (UseIP)' },
                      { value: 'UseIPv6', label: 'Только IPv6 (UseIPv6)' },
                    ]}
                  />
                </div>
              )}
            </div>
          )}
        </div>
      </SettingMetaRow>

      {/* DNS Inspector & Live Tester */}
      <M3SurfaceCard level="default" className="p-3.5 space-y-2.5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Globe className="h-4 w-4 text-[var(--md-primary)]" />
            <span className="text-[0.8rem] font-bold text-[var(--md-on-surface)]">
              DNS-инспектор и живая проверка резолвинга
            </span>
          </div>
          {analysis && (
            <M3StatusBadge
              tone={
                analysis.leakRiskLevel === 'low'
                  ? 'success'
                  : analysis.leakRiskLevel === 'medium'
                    ? 'warning'
                    : 'error'
              }
            >
              Риск утечки:{' '}
              {analysis.leakRiskLevel === 'low'
                ? 'низкий'
                : analysis.leakRiskLevel === 'medium'
                  ? 'средний'
                  : 'высокий'}
            </M3StatusBadge>
          )}
        </div>

        {analysis && (
          <div className="space-y-1.5 rounded-xl bg-[var(--md-surface-container-low)] p-2.5 text-[0.7rem] text-[var(--md-on-surface-variant)]">
            <div>
              Активные VPN DNS: <span className="font-mono text-[var(--md-on-surface)]">{analysis.activeServers.join(', ') || '—'}</span>
            </div>
            <div>
              Перехват DNS в TUN:{' '}
              <span className="font-semibold text-[var(--md-on-surface)]">
                {analysis.tunDnsHijackActive ? 'активен (перехват UDP/TCP :53)' : 'режим Системного прокси'}
              </span>{' '}
              • Стратегия IP: <span className="font-mono">{analysis.ipv6QueryStrategy}</span>
            </div>
            <div>{analysis.systemProxyDnsNote}</div>
            {analysis.warnings.map((w, i) => (
              <div key={i} className="flex items-start gap-1.5 text-[var(--md-warning)]">
                <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                <span>{w}</span>
              </div>
            ))}
          </div>
        )}

        {serverTest && (
          <div className="rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] px-3 py-2 text-[0.7rem]">
            Сервер <span className="font-mono font-semibold">{serverTest.server}</span> ({serverTest.protocol}):{' '}
            {serverTest.reachable
              ? `ответил за ${serverTest.latencyMs ?? 0} мс (${serverTest.resolvedIps.join(', ') || 'OK'})`
              : `недоступен — ${serverTest.error ?? 'таймаут'}`}
          </div>
        )}

        <div className="flex flex-wrap items-center gap-2 pt-0.5">
          <input
            type="text"
            aria-label="Домен для проверки DNS"
            value={lookupDomain}
            onChange={(e) => setLookupDomain(e.target.value)}
            placeholder="Домен для проверки (например cloudflare.com)"
            className="min-w-[200px] flex-1 rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] px-3 py-1.5 font-mono text-[0.72rem] text-[var(--md-on-surface)]"
          />
          <M3Button
            size="sm"
            variant="tonal"
            loading={testingLookup}
            onClick={() => void handleLiveLookup()}
            leadingIcon={<Play className="h-3.5 w-3.5" />}
          >
            Проверить домен
          </M3Button>
          <M3Button
            size="sm"
            variant="outlined"
            onClick={() => void loadReport()}
            leadingIcon={<RefreshCw className="h-3.5 w-3.5" />}
          >
            Обновить анализ
          </M3Button>
        </div>

        {lookupRes && (
          <div className="rounded-xl bg-[var(--md-surface-container-low)] px-3 py-2 text-[0.7rem]">
            <div className="font-semibold text-[var(--md-on-surface)]">
              {lookupRes.domain} → {lookupRes.resolvedIps.join(', ') || 'нет адресов'}
              {lookupRes.latencyMs != null && ` (${lookupRes.latencyMs} мс)`}
            </div>
            <div className="text-[var(--md-on-surface-variant)]">
              Источник: {lookupRes.resolverUsed}
              {lookupRes.error ? ` • ${lookupRes.error}` : ''}
            </div>
            {lookupRes.bypassedVpnWarning && (
              <div className="mt-0.5 text-[var(--md-warning)]">
                Запрос выполнен системным резолвером без перехвата TUN (VPN не подключён).
              </div>
            )}
          </div>
        )}
      </M3SurfaceCard>
    </div>
  );
}
