import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Eye,
  EyeOff,
  Globe,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Unlock,
  Wrench,
  X,
} from 'lucide-react';
import { AnimatePresence, motion } from 'motion/react';
import { useCallback, useEffect, useState } from 'react';
import { api } from '../services/api';
import type {
  EmergencyRecoveryReport,
  KillSwitchEnforcement,
  KillSwitchMode,
  ProtectionCenterSnapshot,
  ProtectionItem,
  ProtectionItemStatus,
} from '../types/vpn';
import { M3Button, M3IconButton, M3StatusBadge, M3SurfaceCard, M3Switch } from './md3';

interface ProtectionCenterModalProps {
  open: boolean;
  onClose: () => void;
  onCheckIp: (includeIpv6: boolean) => Promise<void>;
  onSetIpMask: (mask: boolean) => Promise<void>;
  onEmergencyRecover: () => Promise<EmergencyRecoveryReport>;
  onDisengageKillSwitch: () => Promise<void>;
  onOpenSecuritySettings: () => void;
}

function itemStatusBadge(status: ProtectionItemStatus): {
  label: string;
  tone: 'success' | 'error' | 'warning' | 'neutral';
} {
  switch (status) {
    case 'verified':
      return { label: 'Подтверждено', tone: 'success' };
    case 'issue':
      return { label: 'Проблема', tone: 'error' };
    case 'limited':
      return { label: 'Ограничено', tone: 'warning' };
    case 'unchecked':
      return { label: 'Не проверено', tone: 'neutral' };
    case 'unavailable':
      return { label: 'Недоступно', tone: 'neutral' };
  }
}

function ksModeLabel(mode: KillSwitchMode): string {
  switch (mode) {
    case 'off':
      return 'Выключен';
    case 'on_drop':
      return 'При обрыве (On-Drop)';
    case 'always_on':
      return 'Постоянный (Always-On)';
    case 'routing_aware':
      return 'С учётом маршрутов (Routing-Aware)';
  }
}

function enforcementLabel(e: KillSwitchEnforcement): string {
  switch (e) {
    case 'none':
      return 'Не применяется';
    case 'proxy_guard':
      return 'Локальная блокировка прокси (HTTP 503 + SOCKS5)';
    case 'wfp_firewall':
      return 'Windows Filtering Platform (WFP)';
    case 'netsh_fallback':
      return 'Правило брандмауэра Windows';
  }
}

function maskIpDisplay(ip: string, masked: boolean): string {
  if (!masked) return ip;
  if (ip.includes('.')) {
    const parts = ip.split('.');
    if (parts.length === 4) return `${parts[0]}.${parts[1]}.•.•`;
  }
  if (ip.includes(':')) {
    return `${ip.slice(0, 9)}••••`;
  }
  return '•••.•••.•••';
}

export function ProtectionCenterModal({
  open,
  onClose,
  onCheckIp,
  onSetIpMask,
  onEmergencyRecover,
  onDisengageKillSwitch,
  onOpenSecuritySettings,
}: ProtectionCenterModalProps) {
  const [snapshot, setSnapshot] = useState<ProtectionCenterSnapshot | null>(null);
  const [loading, setLoading] = useState(false);
  const [checkingIp, setCheckingIp] = useState(false);
  const [includeIpv6, setIncludeIpv6] = useState(false);
  const [recovering, setRecovering] = useState(false);
  const [recoveryReport, setRecoveryReport] = useState<EmergencyRecoveryReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadSnapshot = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const snap = await api.getProtectionCenter();
      setSnapshot(snap);
    } catch (err) {
      setError(typeof err === 'string' ? err : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (open) {
      setRecoveryReport(null);
      void loadSnapshot();
    }
  }, [open, loadSnapshot]);

  const handleCheckIp = async () => {
    setCheckingIp(true);
    setError(null);
    try {
      await onCheckIp(includeIpv6);
      await loadSnapshot();
    } catch (err) {
      setError(typeof err === 'string' ? err : String(err));
    } finally {
      setCheckingIp(false);
    }
  };

  const handleToggleMask = async () => {
    if (!snapshot) return;
    try {
      await onSetIpMask(!snapshot.ipMonitor.maskIp);
      await loadSnapshot();
    } catch (err) {
      setError(typeof err === 'string' ? err : String(err));
    }
  };

  const handleRecover = async () => {
    setRecovering(true);
    setError(null);
    try {
      const rep = await onEmergencyRecover();
      setRecoveryReport(rep);
      await loadSnapshot();
    } catch (err) {
      setError(typeof err === 'string' ? err : String(err));
    } finally {
      setRecovering(false);
    }
  };

  const handleDisengage = async () => {
    try {
      await onDisengageKillSwitch();
      await loadSnapshot();
    } catch (err) {
      setError(typeof err === 'string' ? err : String(err));
    }
  };

  const configItems: ProtectionItem[] =
    snapshot?.items.filter((i) => i.kind === 'config') ?? [];
  const networkItems: ProtectionItem[] =
    snapshot?.items.filter((i) => i.kind === 'network') ?? [];

  const renderItemRow = (item: ProtectionItem) => {
    const badge = itemStatusBadge(item.status);
    return (
      <div
        key={item.id}
        className="flex flex-wrap items-start justify-between gap-2 rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] px-3 py-2"
      >
        <div className="min-w-0 flex-1 space-y-0.5">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[0.75rem] font-semibold text-[var(--md-on-surface)]">
              {item.label}
            </span>
            <M3StatusBadge tone={badge.tone}>{badge.label}</M3StatusBadge>
          </div>
          <div className="text-[0.6875rem] text-[var(--md-on-surface-variant)]">{item.detail}</div>
        </div>
        <div className="shrink-0 font-mono text-[0.72rem] font-semibold text-[var(--md-on-surface)]">
          {item.value}
        </div>
      </div>
    );
  };

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.15 }}
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4 backdrop-blur-xs"
          onClick={onClose}
        >
          <motion.div
            role="dialog"
            aria-modal="true"
            aria-label="Центр защиты и утечек"
            initial={{ opacity: 0, scale: 0.97, y: 8 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.97, y: 8 }}
            transition={{ duration: 0.18, ease: 'easeOut' }}
            onClick={(e) => e.stopPropagation()}
            className="flex max-h-[88vh] w-full max-w-[700px] flex-col overflow-hidden rounded-3xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-high)] shadow-2xl"
          >
            {/* Header */}
            <div className="flex items-start justify-between gap-3 border-b border-[var(--md-outline-variant)] px-5 py-4">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[var(--md-primary-container)] text-[var(--md-on-primary-container)]">
                  <ShieldCheck className="h-5 w-5" />
                </div>
                <div>
                  <h2 className="font-display text-[0.98rem] font-bold text-[var(--md-on-surface)]">
                    Центр защиты и контроля утечек
                  </h2>
                  <p className="text-[0.72rem] text-[var(--md-on-surface-variant)]">
                    Честные результаты проверок конфигурации и активного сетевого выхода
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-1.5">
                <M3IconButton
                  size="sm"
                  tooltip="Обновить проверки"
                  onClick={() => void loadSnapshot()}
                  aria-label="Обновить проверки"
                >
                  <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
                </M3IconButton>
                <M3IconButton size="sm" onClick={onClose} aria-label="Закрыть центр защиты">
                  <X className="h-4 w-4" />
                </M3IconButton>
              </div>
            </div>

            {/* Body */}
            <div className="aura-scroll flex-1 space-y-3.5 overflow-y-auto px-5 py-4">
              {snapshot && (
                <>
                  {/* Kill Switch 2.0 live block */}
                  <M3SurfaceCard level="default" className="p-3.5 space-y-2.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        {snapshot.killSwitch.blockingActive ? (
                          <ShieldAlert className="h-4 w-4 text-[var(--md-error)]" />
                        ) : (
                          <Shield className="h-4 w-4 text-[var(--md-primary)]" />
                        )}
                        <span className="text-[0.8rem] font-bold text-[var(--md-on-surface)]">
                          Kill Switch: {ksModeLabel(snapshot.killSwitch.mode)}
                        </span>
                      </div>
                      <M3StatusBadge
                        tone={
                          snapshot.killSwitch.blockingActive
                            ? 'error'
                            : snapshot.killSwitch.status === 'armed'
                              ? 'success'
                              : snapshot.killSwitch.status === 'degraded' ||
                                  snapshot.killSwitch.status === 'recovery_required'
                                ? 'warning'
                                : 'neutral'
                        }
                      >
                        {snapshot.killSwitch.blockingActive
                          ? 'Блокирует утечки'
                          : snapshot.killSwitch.status === 'armed'
                            ? 'На страже'
                            : snapshot.killSwitch.status === 'degraded'
                              ? 'Ограничен'
                              : snapshot.killSwitch.status === 'recovery_required'
                                ? 'Требует сброса'
                                : 'Не активен'}
                      </M3StatusBadge>
                    </div>

                    <div className="text-[0.72rem] text-[var(--md-on-surface-variant)]">
                      Механизм: <span className="font-medium text-[var(--md-on-surface)]">{enforcementLabel(snapshot.killSwitch.enforcement)}</span>
                    </div>

                    {snapshot.killSwitch.allowedExceptions.length > 0 && (
                      <div className="rounded-xl bg-[var(--md-surface-container-low)] p-2.5 text-[0.6875rem] text-[var(--md-on-surface-variant)] space-y-0.5">
                        <div className="font-semibold text-[var(--md-on-surface)]">
                          Активные правила и исключения:
                        </div>
                        {snapshot.killSwitch.allowedExceptions.map((ex, i) => (
                          <div key={i}>• {ex}</div>
                        ))}
                      </div>
                    )}

                    <div className="flex flex-wrap items-center justify-between gap-2 pt-0.5">
                      <M3Button
                        size="sm"
                        variant="outlined"
                        onClick={() => {
                          onClose();
                          onOpenSecuritySettings();
                        }}
                      >
                        Настройки Kill Switch
                      </M3Button>
                      <div className="flex flex-wrap items-center gap-2">
                        {snapshot.killSwitch.blockingActive && (
                          <M3Button
                            size="sm"
                            variant="danger"
                            leadingIcon={<Unlock className="h-3.5 w-3.5" />}
                            onClick={() => void handleDisengage()}
                          >
                            Снять блокировку
                          </M3Button>
                        )}
                        <M3Button
                          size="sm"
                          variant="tonal"
                          loading={recovering}
                          leadingIcon={<Wrench className="h-3.5 w-3.5" />}
                          onClick={() => void handleRecover()}
                        >
                          Экстренное восстановление сети
                        </M3Button>
                      </div>
                    </div>
                  </M3SurfaceCard>

                  {/* IP Monitor comparison */}
                  <M3SurfaceCard level="default" className="p-3.5 space-y-2.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <Globe className="h-4 w-4 text-[var(--md-primary)]" />
                        <span className="text-[0.8rem] font-bold text-[var(--md-on-surface)]">
                          Монитор реального и VPN IP-адреса
                        </span>
                      </div>
                      <button
                        type="button"
                        onClick={() => void handleToggleMask()}
                        className="inline-flex items-center gap-1 rounded-lg border border-[var(--md-outline-variant)] px-2 py-1 text-[0.6875rem] font-medium text-[var(--md-on-surface)] hover:border-[var(--md-primary)]"
                      >
                        {snapshot.ipMonitor.maskIp ? (
                          <>
                            <Eye className="h-3 w-3" /> Показать IP
                          </>
                        ) : (
                          <>
                            <EyeOff className="h-3 w-3" /> Скрыть IP
                          </>
                        )}
                      </button>
                    </div>

                    <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 text-[0.72rem]">
                      <div className="rounded-xl bg-[var(--md-surface-container-low)] p-2.5 space-y-1">
                        <div className="text-[var(--md-on-surface-variant)]">Исходный IP (без VPN)</div>
                        {snapshot.ipMonitor.originalIp ? (
                          <>
                            <div className="font-mono font-semibold text-[var(--md-on-surface)]">
                              {maskIpDisplay(
                                snapshot.ipMonitor.originalIp.ip,
                                snapshot.ipMonitor.maskIp,
                              )}
                            </div>
                            {snapshot.ipMonitor.originalIp.ipv6 && (
                              <div className="font-mono text-[0.65rem] text-[var(--md-on-surface-variant)]">
                                IPv6: {maskIpDisplay(snapshot.ipMonitor.originalIp.ipv6, snapshot.ipMonitor.maskIp)}
                              </div>
                            )}
                            <div className="text-[0.65rem] text-[var(--md-on-surface-variant)]">
                              {[
                                snapshot.ipMonitor.originalIp.country,
                                snapshot.ipMonitor.originalIp.city,
                                snapshot.ipMonitor.originalIp.isp ?? snapshot.ipMonitor.originalIp.org,
                                snapshot.ipMonitor.originalIp.asn,
                              ]
                                .filter(Boolean)
                                .join(' • ') || 'Не определено'}
                            </div>
                          </>
                        ) : (
                          <div className="text-[var(--md-on-surface-variant)]">Не проверялся</div>
                        )}
                      </div>

                      <div className="rounded-xl bg-[var(--md-surface-container-low)] p-2.5 space-y-1">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-[var(--md-on-surface-variant)]">VPN IP (туннель)</span>
                          {snapshot.ipMonitor.ipChanged === true && (
                            <M3StatusBadge tone="success">IP изменён</M3StatusBadge>
                          )}
                          {snapshot.ipMonitor.ipChanged === false && (
                            <M3StatusBadge tone="error">Совпадает!</M3StatusBadge>
                          )}
                        </div>
                        {snapshot.ipMonitor.vpnIp ? (
                          <>
                            <div className="font-mono font-semibold text-[var(--md-on-surface)]">
                              {maskIpDisplay(snapshot.ipMonitor.vpnIp.ip, snapshot.ipMonitor.maskIp)}
                            </div>
                            {snapshot.ipMonitor.vpnIp.ipv6 && (
                              <div className="font-mono text-[0.65rem] text-[var(--md-on-surface-variant)]">
                                IPv6: {maskIpDisplay(snapshot.ipMonitor.vpnIp.ipv6, snapshot.ipMonitor.maskIp)}
                              </div>
                            )}
                            <div className="text-[0.65rem] text-[var(--md-on-surface-variant)]">
                              {[
                                snapshot.ipMonitor.vpnIp.country,
                                snapshot.ipMonitor.vpnIp.city,
                                snapshot.ipMonitor.vpnIp.isp ?? snapshot.ipMonitor.vpnIp.org,
                                snapshot.ipMonitor.vpnIp.asn,
                                snapshot.ipMonitor.vpnIp.networkType,
                              ]
                                .filter(Boolean)
                                .join(' • ') || 'Не определено'}
                            </div>
                          </>
                        ) : (
                          <div className="text-[var(--md-on-surface-variant)]">Не проверялся</div>
                        )}
                      </div>
                    </div>

                    {snapshot.ipMonitor.comparisonNote && (
                      <div className="text-[0.6875rem] text-[var(--md-on-surface-variant)]">
                        {snapshot.ipMonitor.comparisonNote}
                      </div>
                    )}

                    <div className="flex flex-wrap items-center justify-between gap-2 pt-0.5">
                      <label className="inline-flex items-center gap-2 text-[0.7rem] text-[var(--md-on-surface-variant)]">
                        <M3Switch
                          checked={includeIpv6}
                          onChange={setIncludeIpv6}
                          ariaLabel="Проверять IPv6 при тесте IP"
                        />
                        <span>Включить проверку IPv6</span>
                      </label>
                      <M3Button
                        size="sm"
                        variant="filled"
                        loading={checkingIp}
                        leadingIcon={<Globe className="h-3.5 w-3.5" />}
                        onClick={() => void handleCheckIp()}
                      >
                        Проверить внешний IP
                      </M3Button>
                    </div>
                  </M3SurfaceCard>

                  {/* Config vs Network Checks */}
                  <div className="space-y-2">
                    <div className="flex items-center gap-1.5 text-[0.75rem] font-bold text-[var(--md-on-surface)]">
                      <CheckCircle2 className="h-3.5 w-3.5 text-[var(--md-primary)]" />
                      <span>Параметры конфигурации</span>
                    </div>
                    <div className="space-y-1.5">{configItems.map(renderItemRow)}</div>
                  </div>

                  <div className="space-y-2">
                    <div className="flex items-center gap-1.5 text-[0.75rem] font-bold text-[var(--md-on-surface)]">
                      <Activity className="h-3.5 w-3.5 text-[var(--md-primary)]" />
                      <span>Фактические сетевые проверки</span>
                    </div>
                    <div className="space-y-1.5">{networkItems.map(renderItemRow)}</div>
                  </div>
                </>
              )}

              {recoveryReport && (
                <div className="rounded-2xl border border-[var(--md-primary)]/35 bg-[var(--md-primary-container)]/35 p-3 text-[0.72rem] space-y-1">
                  <div className="font-bold text-[var(--md-on-surface)]">
                    Отчёт экстренного восстановления сети:
                  </div>
                  <div>
                    • Прокси Windows восстановлен:{' '}
                    {recoveryReport.systemProxyRestored ? 'Да' : 'Не требовалось'}
                  </div>
                  <div>
                    • WFP фильтры сняты: {recoveryReport.wfpFiltersRemoved ? 'Да' : 'Нет активных'}
                  </div>
                  <div>
                    • Правило брандмауэра снято:{' '}
                    {recoveryReport.legacyNetshRuleRemoved ? 'Да' : 'Не найдено'}
                  </div>
                  <div>
                    • Завершено сиротских процессов: {recoveryReport.orphanedProcessesKilled}
                  </div>
                  {recoveryReport.warnings.map((w, idx) => (
                    <div key={idx} className="text-[var(--md-warning)]">
                      ! {w}
                    </div>
                  ))}
                </div>
              )}

              {error && (
                <div className="flex items-start gap-2 rounded-xl border border-[var(--md-error)]/35 bg-[var(--md-error-container)] px-3 py-2 text-[0.72rem] text-[var(--md-error)]">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>{error}</span>
                </div>
              )}
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
