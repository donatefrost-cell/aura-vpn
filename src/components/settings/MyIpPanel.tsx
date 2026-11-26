import { Eye, EyeOff, Globe, RefreshCw, ShieldCheck, Trash2 } from 'lucide-react';
import { useState } from 'react';
import { api } from '../../services/api';
import type { AppSettings, IpEndpointInfo, IpMonitorState, IpProviderId } from '../../types/vpn';
import { M3Button, M3Select, M3StatusBadge, M3SurfaceCard, M3Switch } from '../md3';
import { SettingMetaRow } from './SettingMetaRow';

interface MyIpPanelProps {
  settings: AppSettings;
  ipMonitor?: IpMonitorState;
  onUpdateSettings: (next: AppSettings) => void;
  onSyncIpMonitor?: (next: IpMonitorState) => void;
  highlightSettingId?: string | null;
}

const PROVIDERS: Array<{ value: IpProviderId; label: string }> = [
  { value: 'auto', label: 'Авто (ipwho.is → ipapi.co → ipinfo.io → ipify)' },
  { value: 'ip_who_is', label: 'ipwho.is (ASN / ISP / TZ)' },
  { value: 'ip_api_co', label: 'ipapi.co (детальное GeoIP)' },
  { value: 'ip_info_io', label: 'ipinfo.io' },
  { value: 'ipify_only', label: 'api.ipify.org (только IP без GeoIP)' },
];

function maskIpText(ip: string, mask: boolean): string {
  if (!mask) return ip;
  if (ip.includes('.')) {
    const parts = ip.split('.');
    if (parts.length === 4) return `${parts[0]}.${parts[1]}.•.•`;
  }
  return ip.length > 9 ? `${ip.slice(0, 9)}••••` : '••••';
}

function EndpointCard({
  title,
  info,
  maskIp,
}: {
  title: string;
  info?: IpEndpointInfo | null;
  maskIp: boolean;
}) {
  return (
    <div className="rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] p-3 space-y-1.5">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[0.75rem] font-bold text-[var(--md-on-surface)]">{title}</span>
        {info && (
          <M3StatusBadge tone={info.viaVpn ? 'success' : 'neutral'}>
            {info.viaVpn ? 'Через VPN' : 'Напрямую'}
          </M3StatusBadge>
        )}
      </div>
      {info ? (
        <div className="space-y-1 text-[0.6875rem] text-[var(--md-on-surface-variant)]">
          <div className="font-mono text-[0.82rem] font-bold text-[var(--md-on-surface)]">
            {maskIpText(info.ip, maskIp)}
          </div>
          {info.ipv6 && (
            <div className="font-mono text-[0.6875rem]">IPv6: {maskIpText(info.ipv6, maskIp)}</div>
          )}
          <div>
            {[info.country, info.region, info.city].filter(Boolean).join(', ') || 'Локация не определена'}
          </div>
          <div>
            {info.isp ?? info.org ?? 'Провайдер не указан'}
            {info.asn ? ` (${info.asn})` : ''}
            {info.networkType ? ` • ${info.networkType}` : ''}
          </div>
          <div className="font-mono-num text-[0.65rem] opacity-80">
            Источник: {info.source}
            {info.latencyMs != null ? ` • ${info.latencyMs} мс` : ''}
            {info.timezone ? ` • ${info.timezone}` : ''}
          </div>
        </div>
      ) : (
        <div className="text-[0.7rem] text-[var(--md-on-surface-variant)]">
          Ещё не проверялся — нажмите «Проверить сейчас».
        </div>
      )}
    </div>
  );
}

export function MyIpPanel({
  settings,
  ipMonitor,
  onUpdateSettings,
  onSyncIpMonitor,
  highlightSettingId,
}: MyIpPanelProps) {
  const [checking, setChecking] = useState(false);
  const [includeIpv6, setIncludeIpv6] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const maskIp = ipMonitor?.maskIp ?? true;
  const provider = settings.preferredIpProvider ?? ipMonitor?.provider ?? 'auto';
  const intervalSecs = settings.autoCheckIpIntervalSecs ?? 0;

  const handleCheck = async () => {
    setChecking(true);
    setError(null);
    try {
      const next = await api.checkIpMonitor(includeIpv6, provider);
      onSyncIpMonitor?.(next);
    } catch (err) {
      setError(String(err));
    } finally {
      setChecking(false);
    }
  };

  const handleToggleMask = async () => {
    try {
      const next = await api.setIpMask(!maskIp);
      onSyncIpMonitor?.(next);
    } catch (err) {
      setError(String(err));
    }
  };

  const handleClearOriginal = async () => {
    try {
      const next = await api.clearOriginalIp();
      onSyncIpMonitor?.(next);
    } catch (err) {
      setError(String(err));
    }
  };

  const handleClearCache = async () => {
    try {
      const next = await api.clearIpMonitorCache();
      onSyncIpMonitor?.(next);
    } catch (err) {
      setError(String(err));
    }
  };

  return (
    <div className="space-y-3" data-testid="panel-my-ip">
      <M3SurfaceCard level="default" className="p-3.5 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Globe className="h-4 w-4 text-[var(--md-primary)]" />
            <div>
              <h3 className="text-[0.82rem] font-bold text-[var(--md-on-surface)]">
                Мой IP 2.0 — сравнение реального и VPN-адреса
              </h3>
              <p className="text-[0.7rem] text-[var(--md-on-surface-variant)]">
                Определение IPv4/IPv6, ASN, провайдера, города и типа сети только по явному запросу или при включённом интервале
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => void handleToggleMask()}
              className="inline-flex items-center gap-1 rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] px-2.5 py-1 text-[0.7rem] text-[var(--md-on-surface)]"
            >
              {maskIp ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
              {maskIp ? 'Скрыт' : 'Показан'}
            </button>
            <M3Button
              size="sm"
              variant="filled"
              loading={checking}
              onClick={() => void handleCheck()}
              leadingIcon={<RefreshCw className="h-3.5 w-3.5" />}
            >
              Проверить сейчас
            </M3Button>
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl bg-[var(--md-surface-container-low)] px-3 py-2 text-[0.7rem]">
          <div className="flex items-center gap-2">
            <M3Switch
              checked={includeIpv6}
              onChange={setIncludeIpv6}
              ariaLabel="Включить проверку IPv6"
            />
            <span>Проверять также публичный IPv6</span>
          </div>
          {ipMonitor?.ipChanged != null && (
            <M3StatusBadge tone={ipMonitor.ipChanged ? 'success' : 'error'}>
              {ipMonitor.ipChanged ? 'Выходной IP изменён' : 'IP совпадает с исходным'}
            </M3StatusBadge>
          )}
        </div>

        {error && (
          <div className="rounded-xl bg-[var(--md-error-container)] px-3 py-2 text-[0.72rem] text-[var(--md-error)]">
            {error}
          </div>
        )}

        <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
          <EndpointCard title="Исходный (реальный) IP" info={ipMonitor?.originalIp} maskIp={maskIp} />
          <EndpointCard title="Выходной IP через VPN" info={ipMonitor?.vpnIp} maskIp={maskIp} />
        </div>

        {ipMonitor?.comparisonNote && (
          <div className="flex items-center gap-1.5 text-[0.7rem] text-[var(--md-on-surface-variant)]">
            <ShieldCheck className="h-3.5 w-3.5 text-[var(--md-primary)]" />
            <span>{ipMonitor.comparisonNote}</span>
          </div>
        )}

        <div className="flex flex-wrap items-center gap-2">
          <M3Button
            size="sm"
            variant="outlined"
            onClick={() => void handleClearOriginal()}
            leadingIcon={<Trash2 className="h-3.5 w-3.5" />}
          >
            Стереть сохранённый реальный IP
          </M3Button>
          <M3Button
            size="sm"
            variant="text"
            onClick={() => void handleClearCache()}
          >
            Очистить кэш VPN IP
          </M3Button>
        </div>
      </M3SurfaceCard>

      <SettingMetaRow
        id="my-ip-provider"
        level="basic"
        title="Провайдер определения IP и фоновый интервал"
        description="По умолчанию автопроверка выключена для строгой сетевой приватности"
        defaultLabel="Авто • Автопроверка Выкл."
        recommendedLabel="Авто (ручной запуск)"
        impact="При включении интервала клиент периодически обращается к выбранному HTTPS-провайдеру."
        compatibility="Не выполняется во время блокировки Kill Switch"
        highlighted={highlightSettingId === 'my-ip-provider'}
        modified={provider !== 'auto' || intervalSecs !== 0}
        onReset={() => {
          onUpdateSettings({
            ...settings,
            preferredIpProvider: 'auto',
            autoCheckIpIntervalSecs: 0,
          });
          void api
            .setIpProvider('auto')
            .then((n) => onSyncIpMonitor?.(n))
            .catch((err) => setError(String(err)));
        }}
      >
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="space-y-1 text-[0.72rem]">
            <span className="text-[var(--md-on-surface-variant)]">Сервис определения IP</span>
            <M3Select
              size="sm"
              ariaLabel="Провайдер Мой IP"
              value={provider}
              onChange={(v) => {
                const nextP = v as IpProviderId;
                onUpdateSettings({ ...settings, preferredIpProvider: nextP });
                void api
                  .setIpProvider(nextP)
                  .then((n) => onSyncIpMonitor?.(n))
                  .catch((err) => setError(String(err)));
              }}
              options={PROVIDERS}
            />
          </div>

          <div className="space-y-1 text-[0.72rem]">
            <span className="text-[var(--md-on-surface-variant)]">Автообновление (opt-in)</span>
            <M3Select
              size="sm"
              ariaLabel="Интервал автообновления IP"
              value={String(intervalSecs)}
              onChange={(v) =>
                onUpdateSettings({ ...settings, autoCheckIpIntervalSecs: Number(v) })
              }
              options={[
                { value: '0', label: 'Только вручную (рекомендуется)' },
                { value: '60', label: 'Каждую минуту (60с)' },
                { value: '300', label: 'Каждые 5 минут' },
                { value: '900', label: 'Каждые 15 минут' },
              ]}
            />
          </div>
        </div>
      </SettingMetaRow>
    </div>
  );
}
