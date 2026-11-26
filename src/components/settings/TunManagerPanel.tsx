import { AlertTriangle, Network, RefreshCw } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { DEFAULT_SETTINGS } from '../../config/defaultSettings';
import type { SettingLevel } from '../../config/settingsRegistry';
import { api } from '../../services/api';
import type { AppSettings, MtuMode, TunManagerSnapshot, TunSettings } from '../../types/vpn';
import { M3Button, M3SegmentedButton, M3Slider, M3StatusBadge, M3SurfaceCard, M3Switch } from '../md3';
import { SettingMetaRow } from './SettingMetaRow';

interface TunManagerPanelProps {
  settings: AppSettings;
  level: SettingLevel;
  onUpdateSettings: (next: AppSettings) => void;
  highlightSettingId?: string | null;
}

export function TunManagerPanel({
  settings,
  level,
  onUpdateSettings,
  highlightSettingId,
}: TunManagerPanelProps) {
  const tun = settings.tun ?? DEFAULT_SETTINGS.tun!;
  const def = DEFAULT_SETTINGS.tun!;

  const [snap, setSnap] = useState<TunManagerSnapshot | null>(null);
  const [loading, setLoading] = useState(false);
  const [alwaysAdmin, setAlwaysAdmin] = useState(false);
  const [togglingAdmin, setTogglingAdmin] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [mtuDraft, setMtuDraft] = useState(tun.mtu);
  const [adapterNameDraft, setAdapterNameDraft] = useState(tun.adapterName);
  const [ipv4Draft, setIpv4Draft] = useState(tun.ipv4Address);
  const [ipv6Draft, setIpv6Draft] = useState(tun.ipv6Address);

  useEffect(() => {
    setMtuDraft(tun.mtu);
    setAdapterNameDraft(tun.adapterName);
    setIpv4Draft(tun.ipv4Address);
    setIpv6Draft(tun.ipv6Address);
  }, [tun.mtu, tun.adapterName, tun.ipv4Address, tun.ipv6Address]);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const [res, diag] = await Promise.all([api.getTunStatus(), api.getDiagnostics()]);
      setSnap(res);
      setAlwaysAdmin(Boolean(diag.alwaysRunAsAdmin));
    } catch (err) {
      setLoadError(typeof err === 'string' ? err : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const patchTun = (patch: Partial<TunSettings>) => {
    onUpdateSettings({
      ...settings,
      tun: { ...tun, ...patch },
    });
  };

  return (
    <div className="space-y-3" data-testid="panel-tun-manager">
      {/* Live Adapter Telemetry Card */}
      <M3SurfaceCard level="default" className="p-3.5 space-y-2.5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Network className="h-4 w-4 text-[var(--md-primary)]" />
            <div>
              <h3 className="text-[0.82rem] font-bold text-[var(--md-on-surface)]">
                Адаптер Wintun и сетевые интерфейсы Windows
              </h3>
              <p className="text-[0.7rem] text-[var(--md-on-surface-variant)]">
                Чтение состояния интерфейса «{tun.adapterName}», драйвера wintun.dll и поиск конфликтующих VPN-адаптеров
              </p>
            </div>
          </div>
          <M3Button
            size="sm"
            variant="outlined"
            loading={loading}
            onClick={() => void load()}
            leadingIcon={<RefreshCw className="h-3.5 w-3.5" />}
          >
            Проверить адаптеры
          </M3Button>
        </div>

        {loadError && (
          <div className="rounded-xl bg-[var(--md-error-container)] px-3 py-2 text-[0.7rem] text-[var(--md-error)]">
            {loadError}
          </div>
        )}

        {!snap && loading && (
          <div className="rounded-xl bg-[var(--md-surface-container-low)] px-3 py-2 text-[0.7rem] text-[var(--md-on-surface-variant)]">
            Проверка сетевых интерфейсов Windows...
          </div>
        )}

        {snap && (
          <div className="grid grid-cols-1 gap-2 rounded-xl bg-[var(--md-surface-container-low)] p-3 text-[0.7rem] sm:grid-cols-2">
            <div>
              <span className="text-[var(--md-on-surface-variant)]">Статус адаптера: </span>
              <M3StatusBadge tone={snap.adapter.adapterPresent ? 'success' : 'neutral'}>
                {snap.adapter.adapterPresent ? `${snap.adapter.adapterName} (${snap.adapter.status})` : 'Не создан (туннель выкл.)'}
              </M3StatusBadge>
            </div>
            <div>
              <span className="text-[var(--md-on-surface-variant)]">Wintun 0.14.1: </span>
              <M3StatusBadge tone={snap.adapter.wintunIntegrityOk ? 'success' : 'error'}>
                {snap.adapter.wintunIntegrityOk ? 'SHA-256 OK' : 'Не проверен / отсутствует'}
              </M3StatusBadge>
            </div>
            <div className="flex flex-wrap items-center gap-2 text-[var(--md-on-surface-variant)]">
              <span>
                Права процесса: <span className="font-semibold text-[var(--md-on-surface)]">{snap.adapter.isElevated ? 'Администратор (UAC)' : 'Обычный пользователь'}</span>
              </span>
              <M3Button
                size="sm"
                variant={alwaysAdmin ? 'tonal' : 'outlined'}
                loading={togglingAdmin}
                onClick={() => {
                  const next = !alwaysAdmin;
                  setTogglingAdmin(true);
                  void api
                    .setAlwaysAdmin(next, next && !snap.adapter.isElevated)
                    .then((diag) => setAlwaysAdmin(Boolean(diag.alwaysRunAsAdmin)))
                    .finally(() => setTogglingAdmin(false));
                }}
              >
                {alwaysAdmin ? 'Права админа: навсегда' : 'Права администратора навсегда'}
              </M3Button>
            </div>
            <div className="text-[var(--md-on-surface-variant)]">
              Драйвер: <span className="font-semibold text-[var(--md-on-surface)]">{snap.adapter.driverStatus}</span>
            </div>
            {snap.adapter.ipv4Addresses.length > 0 && (
              <div className="font-mono text-[var(--md-on-surface)] sm:col-span-2">
                IPv4: {snap.adapter.ipv4Addresses.join(', ')}
                {snap.adapter.mtu ? ` • MTU: ${snap.adapter.mtu}` : ''}
                {snap.adapter.interfaceIndex != null ? ` • ifIndex: ${snap.adapter.interfaceIndex}` : ''}
              </div>
            )}
          </div>
        )}

        {snap && snap.conflicts.length > 0 && (
          <div className="space-y-1.5">
            {snap.conflicts.map((c, idx) => (
              <div
                key={`${c.adapterName}-${idx}`}
                className="flex items-start gap-2 rounded-xl border border-[var(--md-warning)]/40 bg-[var(--md-warning-container)]/40 px-3 py-2 text-[0.7rem]"
              >
                <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--md-warning)]" />
                <div>
                  <div className="font-semibold text-[var(--md-on-surface)]">
                    {c.adapterName} ({c.category} • {c.status})
                  </div>
                  <div className="text-[var(--md-on-surface-variant)]">{c.detail}</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </M3SurfaceCard>

      {/* TUN Configuration */}
      <SettingMetaRow
        id="tun-config"
        level="advanced"
        title="Конфигурация TUN-интерфейса и маршрутов"
        description="Имя интерфейса Windows, MTU, strictRoute, обход LAN и обработка IPv6 в туннеле"
        defaultLabel="aura_tun • MTU 1500 • strictRoute Вкл."
        rangeLabel="MTU 1280 – 1500, имя до 32 латинских символов"
        impact="Параметр strictRoute запрещает утечку трафика по альтернативным шлюзам при активном TUN."
        compatibility="Режим TUN требует запуска от имени администратора Windows"
        requiresReconnect
        highlighted={highlightSettingId === 'tun-config'}
        modified={
          tun.adapterName !== def.adapterName ||
          tun.mtu !== def.mtu ||
          tun.strictRoute !== def.strictRoute ||
          tun.bypassLan !== def.bypassLan ||
          tun.autoRoute !== def.autoRoute ||
          tun.enableIpv6 !== def.enableIpv6 ||
          settings.ipv6Enabled !== DEFAULT_SETTINGS.ipv6Enabled
        }
        onReset={() =>
          onUpdateSettings({
            ...settings,
            ipv6Enabled: DEFAULT_SETTINGS.ipv6Enabled,
            tun: { ...def },
          })
        }
      >
        <div className="space-y-3">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <label className="space-y-1 text-[0.72rem]">
              <span className="font-medium text-[var(--md-on-surface-variant)]">Имя TUN-адаптера</span>
              <input
                type="text"
                aria-label="Имя TUN-адаптера"
                maxLength={32}
                value={adapterNameDraft}
                onChange={(e) => setAdapterNameDraft(e.target.value)}
                onBlur={() => {
                  const clean = adapterNameDraft.trim();
                  if (clean !== tun.adapterName) {
                    patchTun({ adapterName: clean });
                  }
                }}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') e.currentTarget.blur();
                }}
                className="w-full rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] px-3 py-1.5 font-mono text-[0.72rem]"
              />
            </label>
            <div className="space-y-1 text-[0.72rem]">
              <span className="font-medium text-[var(--md-on-surface-variant)]">Режим MTU в TUN</span>
              <M3SegmentedButton<MtuMode>
                size="sm"
                value={tun.mtuMode}
                onChange={(mtuMode) => patchTun({ mtuMode })}
                options={[
                  { id: 'auto', label: 'Авто' },
                  { id: 'profile', label: 'Профиль' },
                  { id: 'manual', label: 'Вручную' },
                ]}
              />
            </div>
          </div>

          <div className="space-y-1">
            <div className="flex justify-between text-[0.7rem]">
              <span>MTU виртуального интерфейса</span>
              <span className="font-mono-num text-[var(--md-primary)]">{mtuDraft} байт</span>
            </div>
            <M3Slider
              min={1280}
              max={1500}
              step={10}
              value={mtuDraft}
              onChange={setMtuDraft}
              onCommit={(mtu) => patchTun({ mtu })}
              ariaLabel="MTU адаптера TUN"
            />
          </div>

          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            <div className="flex items-center justify-between rounded-xl bg-[var(--md-surface-container)] px-3 py-2 text-[0.7rem]">
              <span>strictRoute (строгие маршруты)</span>
              <M3Switch
                checked={tun.strictRoute}
                onChange={(strictRoute) => patchTun({ strictRoute })}
                ariaLabel="strictRoute"
              />
            </div>
            <div className="flex items-center justify-between rounded-xl bg-[var(--md-surface-container)] px-3 py-2 text-[0.7rem]">
              <span>autoRoute (захват 0.0.0.0/0 и ::/0)</span>
              <M3Switch
                checked={tun.autoRoute}
                onChange={(autoRoute) => patchTun({ autoRoute })}
                ariaLabel="autoRoute"
              />
            </div>
            <div className="flex items-center justify-between rounded-xl bg-[var(--md-surface-container)] px-3 py-2 text-[0.7rem]">
              <span>Передавать IPv6 внутри Xray/TUN</span>
              <M3Switch
                checked={settings.ipv6Enabled}
                onChange={(v) =>
                  onUpdateSettings({
                    ...settings,
                    ipv6Enabled: v,
                    tun: { ...tun, enableIpv6: v },
                  })
                }
                ariaLabel="Поддержка IPv6"
              />
            </div>
            <div className="flex items-center justify-between rounded-xl bg-[var(--md-surface-container)] px-3 py-2 text-[0.7rem]">
              <span>Обход локальной сети (LAN) в TUN</span>
              <M3Switch
                checked={tun.bypassLan}
                onChange={(bypassLan) => patchTun({ bypassLan })}
                ariaLabel="Обход LAN в TUN"
              />
            </div>
          </div>

          {level === 'expert' && (
            <div className="grid grid-cols-1 gap-3 border-t border-[var(--md-outline-variant)] pt-2.5 sm:grid-cols-2">
              <label className="space-y-1 text-[0.7rem]">
                <span className="text-[var(--md-on-surface-variant)]">IPv4 подсеть TUN (CIDR)</span>
                <input
                  type="text"
                  aria-label="IPv4 подсеть TUN"
                  value={ipv4Draft}
                  onChange={(e) => setIpv4Draft(e.target.value)}
                  onBlur={() => {
                    const clean = ipv4Draft.trim();
                    if (clean !== tun.ipv4Address) {
                      patchTun({ ipv4Address: clean });
                    }
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') e.currentTarget.blur();
                  }}
                  className="w-full rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] px-3 py-1.5 font-mono text-[0.72rem]"
                />
              </label>
              <label className="space-y-1 text-[0.7rem]">
                <span className="text-[var(--md-on-surface-variant)]">IPv6 подсеть TUN (CIDR)</span>
                <input
                  type="text"
                  aria-label="IPv6 подсеть TUN"
                  value={ipv6Draft}
                  onChange={(e) => setIpv6Draft(e.target.value)}
                  onBlur={() => {
                    const clean = ipv6Draft.trim();
                    if (clean !== tun.ipv6Address) {
                      patchTun({ ipv6Address: clean });
                    }
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') e.currentTarget.blur();
                  }}
                  className="w-full rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] px-3 py-1.5 font-mono text-[0.72rem]"
                />
              </label>
            </div>
          )}
        </div>
      </SettingMetaRow>
    </div>
  );
}
