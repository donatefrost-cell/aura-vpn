import { useEffect, useState } from 'react';
import { DEFAULT_SETTINGS } from '../../config/defaultSettings';
import type { SettingLevel } from '../../config/settingsRegistry';
import type { AdvancedVpnSettings, AppSettings, MtuMode } from '../../types/vpn';
import { M3SegmentedButton, M3Select, M3Slider, M3Switch } from '../md3';
import { SettingMetaRow } from './SettingMetaRow';

interface AdvancedVpnPanelProps {
  settings: AppSettings;
  level: SettingLevel;
  onUpdateSettings: (next: AppSettings) => void;
  highlightSettingId?: string | null;
}

function parsePort(raw: string): number | null {
  const n = Number(raw.trim());
  if (!Number.isInteger(n) || n < 1024 || n > 65535) return null;
  return n;
}

export function AdvancedVpnPanel({
  settings,
  level,
  onUpdateSettings,
  highlightSettingId,
}: AdvancedVpnPanelProps) {
  const adv = settings.advanced ?? DEFAULT_SETTINGS.advanced!;
  const def = DEFAULT_SETTINGS.advanced!;

  const [httpPortDraft, setHttpPortDraft] = useState(String(settings.httpPort));
  const [socksPortDraft, setSocksPortDraft] = useState(String(settings.socksPort));
  const [statsPortDraft, setStatsPortDraft] = useState(String(adv.statsApiPort ?? 10085));

  const [coreTimeoutDraft, setCoreTimeoutDraft] = useState(adv.coreStartTimeoutSecs);
  const [probeTimeoutDraft, setProbeTimeoutDraft] = useState(adv.probeTimeoutSecs);
  const [healthIntervalDraft, setHealthIntervalDraft] = useState(adv.healthCheckIntervalSecs);
  const [healthThresholdDraft, setHealthThresholdDraft] = useState(adv.healthFailureThreshold);
  const [reconnBaseDraft, setReconnBaseDraft] = useState(adv.reconnectBaseDelaySecs);
  const [reconnMaxDraft, setReconnMaxDraft] = useState(adv.reconnectMaxDelaySecs);
  const [parallelPingsDraft, setParallelPingsDraft] = useState(adv.maxParallelPings);
  const [keepaliveDraft, setKeepaliveDraft] = useState(adv.tcpKeepaliveIntervalSecs);
  const [muxConcDraft, setMuxConcDraft] = useState(adv.muxConcurrency);
  const [xudpConcDraft, setXudpConcDraft] = useState(adv.muxXudpConcurrency);
  const [manualMtuDraft, setManualMtuDraft] = useState(adv.manualMtu ?? 1380);

  useEffect(() => {
    setHttpPortDraft(String(settings.httpPort));
    setSocksPortDraft(String(settings.socksPort));
  }, [settings.httpPort, settings.socksPort]);

  useEffect(() => {
    setStatsPortDraft(String(adv.statsApiPort ?? 10085));
    setCoreTimeoutDraft(adv.coreStartTimeoutSecs);
    setProbeTimeoutDraft(adv.probeTimeoutSecs);
    setHealthIntervalDraft(adv.healthCheckIntervalSecs);
    setHealthThresholdDraft(adv.healthFailureThreshold);
    setReconnBaseDraft(adv.reconnectBaseDelaySecs);
    setReconnMaxDraft(adv.reconnectMaxDelaySecs);
    setParallelPingsDraft(adv.maxParallelPings);
    setKeepaliveDraft(adv.tcpKeepaliveIntervalSecs);
    setMuxConcDraft(adv.muxConcurrency);
    setXudpConcDraft(adv.muxXudpConcurrency);
    setManualMtuDraft(adv.manualMtu ?? 1380);
  }, [
    adv.statsApiPort,
    adv.coreStartTimeoutSecs,
    adv.probeTimeoutSecs,
    adv.healthCheckIntervalSecs,
    adv.healthFailureThreshold,
    adv.reconnectBaseDelaySecs,
    adv.reconnectMaxDelaySecs,
    adv.maxParallelPings,
    adv.tcpKeepaliveIntervalSecs,
    adv.muxConcurrency,
    adv.muxXudpConcurrency,
    adv.manualMtu,
  ]);

  const patchAdv = (patch: Partial<AdvancedVpnSettings>) => {
    onUpdateSettings({
      ...settings,
      advanced: { ...adv, ...patch },
    });
  };

  const commitHttpPort = () => {
    const p = parsePort(httpPortDraft);
    if (p && p !== settings.socksPort) {
      if (p !== settings.httpPort) {
        onUpdateSettings({ ...settings, httpPort: p });
      }
    } else {
      setHttpPortDraft(String(settings.httpPort));
    }
  };

  const commitSocksPort = () => {
    const p = parsePort(socksPortDraft);
    if (p && p !== settings.httpPort) {
      if (p !== settings.socksPort) {
        onUpdateSettings({ ...settings, socksPort: p });
      }
    } else {
      setSocksPortDraft(String(settings.socksPort));
    }
  };

  const commitStatsPort = () => {
    const p = parsePort(statsPortDraft);
    if (p && p !== settings.httpPort && p !== settings.socksPort) {
      if (p !== adv.statsApiPort) {
        patchAdv({ statsApiPort: p });
      }
    } else {
      setStatsPortDraft(String(adv.statsApiPort ?? 10085));
    }
  };

  return (
    <div className="space-y-3" data-testid="panel-advanced-vpn">
      {/* Ports */}
      <SettingMetaRow
        id="adv-ports"
        level="advanced"
        title="Локальные порты HTTP и SOCKS5"
        description="Локальные loopback-порты 127.0.0.1 для системного прокси и входящего SOCKS5"
        defaultLabel="HTTP 10809 / SOCKS5 10808"
        rangeLabel="1024 – 65535"
        impact="Избегайте пересечения с портами других программ и зарезервированными диапазонами Windows."
        compatibility="Порты не могут совпадать друг с другом"
        requiresReconnect
        modified={settings.httpPort !== DEFAULT_SETTINGS.httpPort || settings.socksPort !== DEFAULT_SETTINGS.socksPort}
        highlighted={highlightSettingId === 'adv-ports'}
        onReset={() =>
          onUpdateSettings({
            ...settings,
            httpPort: DEFAULT_SETTINGS.httpPort,
            socksPort: DEFAULT_SETTINGS.socksPort,
          })
        }
      >
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <label className="space-y-1 text-[0.72rem]">
            <span className="font-medium text-[var(--md-on-surface-variant)]">HTTP-порт прокси</span>
            <input
              type="number"
              aria-label="HTTP-порт прокси"
              min={1024}
              max={65535}
              value={httpPortDraft}
              onChange={(e) => setHttpPortDraft(e.target.value)}
              onBlur={commitHttpPort}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.currentTarget.blur();
                }
              }}
              className="w-full rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] px-3 py-1.5 font-mono-num text-[0.75rem] text-[var(--md-on-surface)]"
            />
          </label>
          <label className="space-y-1 text-[0.72rem]">
            <span className="font-medium text-[var(--md-on-surface-variant)]">SOCKS5-порт прокси</span>
            <input
              type="number"
              aria-label="SOCKS5-порт прокси"
              min={1024}
              max={65535}
              value={socksPortDraft}
              onChange={(e) => setSocksPortDraft(e.target.value)}
              onBlur={commitSocksPort}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.currentTarget.blur();
                }
              }}
              className="w-full rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] px-3 py-1.5 font-mono-num text-[0.75rem] text-[var(--md-on-surface)]"
            />
          </label>
        </div>
      </SettingMetaRow>

      {/* Timeouts & Health Probe */}
      <SettingMetaRow
        id="adv-timeouts-health"
        level="advanced"
        title="Таймауты подключения и проверка туннеля"
        description="Периодическая проверка живости туннеля и задержка экспоненциального переподключения"
        defaultLabel="Старт 6с • Проба 10с • Интервал 30с • Порог 2"
        recommendedLabel="Интервал 30с, Порог 2"
        rangeLabel="Старт 3–20с, Проба 4–30с, Интервал 10–300с"
        impact="Определяет, как быстро watchdog обнаружит обрыв связи и перезапустит ядро."
        compatibility="Работает и в Системном прокси, и в TUN-режиме"
        requiresReconnect
        highlighted={highlightSettingId === 'adv-timeouts-health'}
        modified={
          adv.coreStartTimeoutSecs !== def.coreStartTimeoutSecs ||
          adv.probeTimeoutSecs !== def.probeTimeoutSecs ||
          adv.healthCheckEnabled !== def.healthCheckEnabled ||
          adv.healthCheckIntervalSecs !== def.healthCheckIntervalSecs ||
          adv.healthFailureThreshold !== def.healthFailureThreshold ||
          adv.reconnectBaseDelaySecs !== def.reconnectBaseDelaySecs ||
          adv.reconnectMaxDelaySecs !== def.reconnectMaxDelaySecs
        }
        onReset={() =>
          patchAdv({
            coreStartTimeoutSecs: def.coreStartTimeoutSecs,
            probeTimeoutSecs: def.probeTimeoutSecs,
            healthCheckEnabled: def.healthCheckEnabled,
            healthCheckIntervalSecs: def.healthCheckIntervalSecs,
            healthFailureThreshold: def.healthFailureThreshold,
            reconnectBaseDelaySecs: def.reconnectBaseDelaySecs,
            reconnectMaxDelaySecs: def.reconnectMaxDelaySecs,
          })
        }
        control={
          <M3Switch
            checked={adv.healthCheckEnabled}
            onChange={(healthCheckEnabled) => patchAdv({ healthCheckEnabled })}
            ariaLabel="Периодическая проверка стабильности туннеля"
          />
        }
      >
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="space-y-1">
            <div className="flex justify-between text-[0.7rem]">
              <span>Таймаут запуска ядра</span>
              <span className="font-mono-num text-[var(--md-primary)]">{coreTimeoutDraft} с</span>
            </div>
            <M3Slider
              min={3}
              max={20}
              step={1}
              value={coreTimeoutDraft}
              onChange={setCoreTimeoutDraft}
              onCommit={(v) => patchAdv({ coreStartTimeoutSecs: v })}
              ariaLabel="Таймаут запуска ядра"
            />
          </div>
          <div className="space-y-1">
            <div className="flex justify-between text-[0.7rem]">
              <span>Таймаут проверки туннеля</span>
              <span className="font-mono-num text-[var(--md-primary)]">{probeTimeoutDraft} с</span>
            </div>
            <M3Slider
              min={4}
              max={30}
              step={1}
              value={probeTimeoutDraft}
              onChange={setProbeTimeoutDraft}
              onCommit={(v) => patchAdv({ probeTimeoutSecs: v })}
              ariaLabel="Таймаут проверки туннеля"
            />
          </div>
          <div className="space-y-1">
            <div className="flex justify-between text-[0.7rem]">
              <span>Интервал проверки живости</span>
              <span className="font-mono-num text-[var(--md-primary)]">{healthIntervalDraft} с</span>
            </div>
            <M3Slider
              min={10}
              max={300}
              step={5}
              value={healthIntervalDraft}
              onChange={setHealthIntervalDraft}
              onCommit={(v) => patchAdv({ healthCheckIntervalSecs: v })}
              ariaLabel="Интервал проверки живости"
            />
          </div>
          <div className="space-y-1">
            <div className="flex justify-between text-[0.7rem]">
              <span>Порог сбоев для реконнекта</span>
              <span className="font-mono-num text-[var(--md-primary)]">{healthThresholdDraft}</span>
            </div>
            <M3Slider
              min={1}
              max={5}
              step={1}
              value={healthThresholdDraft}
              onChange={setHealthThresholdDraft}
              onCommit={(v) => patchAdv({ healthFailureThreshold: v })}
              ariaLabel="Порог сбоев"
            />
          </div>
          <div className="space-y-1">
            <div className="flex justify-between text-[0.7rem]">
              <span>Базовая задержка реконнекта</span>
              <span className="font-mono-num text-[var(--md-primary)]">{reconnBaseDraft} с</span>
            </div>
            <M3Slider
              min={1}
              max={15}
              step={1}
              value={reconnBaseDraft}
              onChange={setReconnBaseDraft}
              onCommit={(v) => patchAdv({ reconnectBaseDelaySecs: v })}
              ariaLabel="Базовая задержка реконнекта"
            />
          </div>
          <div className="space-y-1">
            <div className="flex justify-between text-[0.7rem]">
              <span>Макс. задержка реконнекта</span>
              <span className="font-mono-num text-[var(--md-primary)]">{reconnMaxDraft} с</span>
            </div>
            <M3Slider
              min={5}
              max={60}
              step={1}
              value={reconnMaxDraft}
              onChange={setReconnMaxDraft}
              onCommit={(v) => patchAdv({ reconnectMaxDelaySecs: Math.max(v, adv.reconnectBaseDelaySecs) })}
              ariaLabel="Макс. задержка реконнекта"
            />
          </div>
        </div>
      </SettingMetaRow>

      {/* Ping Concurrency */}
      <SettingMetaRow
        id="adv-ping-concurrency"
        level="advanced"
        title="Параллельность массового пинга"
        description="Ограничивает число одновременных TCP-проверок при запуске «Пинговать все»"
        defaultLabel="12"
        rangeLabel="1 – 32"
        impact="Более низкие значения уменьшают нагрузку на NAT роутера и не вызывают ложных таймаутов."
        compatibility="Не требует перезапуска туннеля"
        highlighted={highlightSettingId === 'adv-ping-concurrency'}
        modified={adv.maxParallelPings !== def.maxParallelPings}
        onReset={() => patchAdv({ maxParallelPings: def.maxParallelPings })}
      >
        <div className="space-y-1">
          <div className="flex justify-between text-[0.7rem]">
            <span>Одновременных соединений</span>
            <span className="font-mono-num text-[var(--md-primary)]">{parallelPingsDraft}</span>
          </div>
          <M3Slider
            min={1}
            max={32}
            step={1}
            value={parallelPingsDraft}
            onChange={setParallelPingsDraft}
            onCommit={(v) => patchAdv({ maxParallelPings: v })}
            ariaLabel="Параллельность пинга"
          />
        </div>
      </SettingMetaRow>

      {level === 'expert' && (
        <>
          {/* Sockopt */}
          <SettingMetaRow
            id="adv-sockopt"
            level="expert"
            title="Сокеты транспорта и стратегия домена (Sockopt)"
            description="Низкоуровневые параметры исходящего TCP-сокета Xray-core"
            defaultLabel="NoDelay Вкл. • Keepalive 0с • TFO Выкл. • AsIs"
            rangeLabel="Keepalive 0–120с"
            impact="Keepalive удерживает NAT в нестабильных мобильных сетях; domainStrategy задаёт приоритет IPv4/IPv6."
            compatibility="Применяется безопасно только для Xray outbound; для WireGuard и Hysteria2 игнорируется"
            requiresReconnect
            highlighted={highlightSettingId === 'adv-sockopt'}
            modified={
              adv.tcpKeepaliveIntervalSecs !== def.tcpKeepaliveIntervalSecs ||
              adv.tcpFastOpen !== def.tcpFastOpen ||
              adv.tcpNoDelay !== def.tcpNoDelay ||
              adv.dialerDomainStrategy !== def.dialerDomainStrategy
            }
            onReset={() =>
              patchAdv({
                tcpKeepaliveIntervalSecs: def.tcpKeepaliveIntervalSecs,
                tcpFastOpen: def.tcpFastOpen,
                tcpNoDelay: def.tcpNoDelay,
                dialerDomainStrategy: def.dialerDomainStrategy,
              })
            }
          >
            <div className="space-y-2.5">
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                <div className="flex items-center justify-between rounded-xl bg-[var(--md-surface-container)] px-3 py-2 text-[0.72rem]">
                  <span>TCP_NODELAY</span>
                  <M3Switch
                    checked={adv.tcpNoDelay}
                    onChange={(tcpNoDelay) => patchAdv({ tcpNoDelay })}
                    ariaLabel="TCP NoDelay"
                  />
                </div>
                <div className="flex items-center justify-between rounded-xl bg-[var(--md-surface-container)] px-3 py-2 text-[0.72rem]">
                  <span>TCP Fast Open (TFO)</span>
                  <M3Switch
                    checked={adv.tcpFastOpen}
                    onChange={(tcpFastOpen) => patchAdv({ tcpFastOpen })}
                    ariaLabel="TCP Fast Open"
                  />
                </div>
              </div>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div className="space-y-1">
                  <div className="flex justify-between text-[0.7rem]">
                    <span>TCP Keepalive (0 = выкл.)</span>
                    <span className="font-mono-num text-[var(--md-primary)]">{keepaliveDraft} с</span>
                  </div>
                  <M3Slider
                    min={0}
                    max={120}
                    step={5}
                    value={keepaliveDraft}
                    onChange={setKeepaliveDraft}
                    onCommit={(v) => patchAdv({ tcpKeepaliveIntervalSecs: v })}
                    ariaLabel="TCP Keepalive"
                  />
                </div>
                <div className="space-y-1 text-[0.7rem]">
                  <span>Приоритет доменов (Domain Strategy)</span>
                  <M3Select
                    size="sm"
                    ariaLabel="Dialer Domain Strategy"
                    value={adv.dialerDomainStrategy}
                    onChange={(dialerDomainStrategy) => patchAdv({ dialerDomainStrategy })}
                    options={[
                      { value: 'AsIs', label: 'AsIs (по умолчанию)' },
                      { value: 'UseIPv4', label: 'UseIPv4' },
                      { value: 'UseIPv6', label: 'UseIPv6' },
                      { value: 'UseIP', label: 'UseIP' },
                      { value: 'UseIPv4v6', label: 'UseIPv4v6' },
                    ]}
                  />
                </div>
              </div>
            </div>
          </SettingMetaRow>

          {/* Mux */}
          <SettingMetaRow
            id="adv-mux"
            level="expert"
            title="Мультиплексирование (Mux / XUDP)"
            description="Объединяет потоки поверх одного соединения. Для VLESS+XTLS-Vision, gRPC, XHTTP и Hysteria2 отключается автоматически."
            defaultLabel="Выкл. (8 / XUDP 8)"
            rangeLabel="1 – 16"
            impact="Уменьшает число TLS-рукопожатий при множестве мелких запросов, но может снижать пиковую пропускную способность."
            compatibility="Встроенная защита никогда не включает Mux на VLESS+Vision/gRPC/XHTTP/UDP-протоколах"
            requiresReconnect
            highlighted={highlightSettingId === 'adv-mux'}
            modified={
              adv.muxEnabled !== def.muxEnabled ||
              adv.muxConcurrency !== def.muxConcurrency ||
              adv.muxXudpConcurrency !== def.muxXudpConcurrency
            }
            onReset={() =>
              patchAdv({
                muxEnabled: def.muxEnabled,
                muxConcurrency: def.muxConcurrency,
                muxXudpConcurrency: def.muxXudpConcurrency,
              })
            }
            control={
              <M3Switch
                checked={adv.muxEnabled}
                onChange={(muxEnabled) => patchAdv({ muxEnabled })}
                ariaLabel="Включить Mux"
              />
            }
          >
            {adv.muxEnabled && (
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div className="space-y-1">
                  <div className="flex justify-between text-[0.7rem]">
                    <span>Mux Concurrency</span>
                    <span className="font-mono-num text-[var(--md-primary)]">{muxConcDraft}</span>
                  </div>
                  <M3Slider
                    min={1}
                    max={16}
                    step={1}
                    value={muxConcDraft}
                    onChange={setMuxConcDraft}
                    onCommit={(v) => patchAdv({ muxConcurrency: v })}
                    ariaLabel="Mux Concurrency"
                  />
                </div>
                <div className="space-y-1">
                  <div className="flex justify-between text-[0.7rem]">
                    <span>XUDP Concurrency</span>
                    <span className="font-mono-num text-[var(--md-primary)]">{xudpConcDraft}</span>
                  </div>
                  <M3Slider
                    min={1}
                    max={16}
                    step={1}
                    value={xudpConcDraft}
                    onChange={setXudpConcDraft}
                    onCommit={(v) => patchAdv({ muxXudpConcurrency: v })}
                    ariaLabel="XUDP Concurrency"
                  />
                </div>
              </div>
            )}
          </SettingMetaRow>

          {/* MTU & Stats API */}
          <SettingMetaRow
            id="adv-mtu-stats"
            level="expert"
            title="Глобальный MTU и режим Stats API"
            description="Определяет правило расчёта MTU (если не задано в профиле) и локальный порт gRPC статистики ядра"
            defaultLabel="MTU Авто • Stats API Эфемерный"
            rangeLabel="MTU 1280 – 1500"
            impact="Фиксированный порт Stats API полезен только для внешней отладки Xray."
            compatibility="Приоритет MTU: профиль -> глобальное ручное значение -> автоподбор по протоколу"
            requiresReconnect
            highlighted={highlightSettingId === 'adv-mtu-stats'}
            modified={
              adv.mtuMode !== def.mtuMode ||
              (adv.manualMtu ?? null) !== (def.manualMtu ?? null) ||
              adv.statsApiMode !== def.statsApiMode
            }
            onReset={() =>
              patchAdv({
                mtuMode: def.mtuMode,
                manualMtu: def.manualMtu,
                statsApiMode: def.statsApiMode,
                statsApiPort: def.statsApiPort,
              })
            }
          >
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div className="space-y-1.5 text-[0.7rem]">
                <span>Стратегия MTU</span>
                <M3SegmentedButton<MtuMode>
                  size="sm"
                  value={adv.mtuMode}
                  onChange={(mtuMode) => patchAdv({ mtuMode })}
                  options={[
                    { id: 'auto', label: 'Авто' },
                    { id: 'profile', label: 'Из профиля' },
                    { id: 'manual', label: 'Вручную' },
                  ]}
                />
                {adv.mtuMode === 'manual' && (
                  <div className="pt-1">
                    <M3Slider
                      min={1280}
                      max={1500}
                      step={10}
                      value={manualMtuDraft}
                      onChange={setManualMtuDraft}
                      onCommit={(manualMtu) => patchAdv({ manualMtu })}
                      ariaLabel="Ручной MTU"
                    />
                    <div className="text-right font-mono-num text-[0.65rem] text-[var(--md-primary)]">
                      {manualMtuDraft} байт
                    </div>
                  </div>
                )}
              </div>

              <div className="space-y-1.5 text-[0.7rem]">
                <span>Локальный Xray Stats API</span>
                <M3SegmentedButton
                  size="sm"
                  value={adv.statsApiMode}
                  onChange={(statsApiMode) => patchAdv({ statsApiMode })}
                  options={[
                    { id: 'ephemeral', label: 'Эфемерный порт' },
                    { id: 'fixed', label: 'Фиксированный' },
                    { id: 'disabled', label: 'Отключён' },
                  ]}
                />
                {adv.statsApiMode === 'fixed' && (
                  <input
                    type="number"
                    aria-label="Фиксированный порт Xray Stats API"
                    min={1024}
                    max={65535}
                    placeholder="10085"
                    value={statsPortDraft}
                    onChange={(e) => setStatsPortDraft(e.target.value)}
                    onBlur={commitStatsPort}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        e.currentTarget.blur();
                      }
                    }}
                    className="w-full rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] px-3 py-1 font-mono-num text-[0.72rem]"
                  />
                )}
              </div>
            </div>
          </SettingMetaRow>
        </>
      )}
    </div>
  );
}
