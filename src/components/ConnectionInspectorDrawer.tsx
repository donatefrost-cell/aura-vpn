import { Activity, CheckCircle2, Clock, RefreshCw, Trash2, X } from 'lucide-react';
import { AnimatePresence, motion } from 'motion/react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { api } from '../services/api';
import { liveStore, useConnectionTimeline } from '../stores/liveStore';
import type { ConnectionInspectorSnapshot } from '../types/vpn';
import { formatBytes, formatDuration, formatSpeed } from '../utils/format';
import { M3Button, M3IconButton, M3StatusBadge, M3SurfaceCard } from './md3';

interface ConnectionInspectorDrawerProps {
  open: boolean;
  onClose: () => void;
}

export function ConnectionInspectorDrawer({ open, onClose }: ConnectionInspectorDrawerProps) {
  const [snap, setSnap] = useState<ConnectionInspectorSnapshot | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const liveTimeline = useConnectionTimeline();

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getConnectionInspector();
      setSnap(res);
      liveStore.setInitialTimeline(res.timeline);
    } catch (err) {
      setError(typeof err === 'string' ? err : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!open) return;
    void load();
    const timer = window.setInterval(() => {
      void load();
    }, 3000);
    return () => window.clearInterval(timer);
  }, [open, load]);

  const timeline = useMemo(() => {
    if (liveTimeline.length > 0) return liveTimeline;
    return snap?.timeline ?? [];
  }, [liveTimeline, snap]);

  const handleClearTimeline = async () => {
    try {
      await api.clearConnectionTimeline();
      liveStore.clearTimeline();
      await load();
    } catch (err) {
      setError(typeof err === 'string' ? err : String(err));
    }
  };

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.15 }}
          className="fixed inset-0 z-50 flex justify-end bg-black/55 backdrop-blur-xs"
          onClick={onClose}
        >
          <motion.aside
            role="dialog"
            aria-modal="true"
            aria-label="Инспектор подключения"
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ duration: 0.18, ease: 'easeOut' }}
            onClick={(e) => e.stopPropagation()}
            data-testid="connection-inspector-drawer"
            className="flex h-full w-full max-w-lg flex-col border-l border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] shadow-2xl"
          >
            {/* Header */}
            <div className="flex items-center justify-between border-b border-[var(--md-outline-variant)] px-4 py-3">
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4 text-[var(--md-primary)]" />
                <div>
                  <h2 className="font-display text-[0.94rem] font-bold text-[var(--md-on-surface)]">
                    Инспектор подключения
                  </h2>
                  <p className="text-[0.68rem] text-[var(--md-on-surface-variant)]">
                    Этапы запуска туннеля, пропускная способность и живой таймлайн
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-1">
                <M3IconButton size="sm" tooltip="Обновить" onClick={() => void load()} aria-label="Обновить инспектор">
                  <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
                </M3IconButton>
                <M3IconButton size="sm" onClick={onClose} aria-label="Закрыть инспектор">
                  <X className="h-4 w-4" />
                </M3IconButton>
              </div>
            </div>

            <div className="aura-scroll flex-1 space-y-3 overflow-y-auto px-4 py-3.5">
              {error && (
                <div className="rounded-xl bg-[var(--md-error-container)] px-3 py-2 text-[0.72rem] text-[var(--md-error)]">
                  {error}
                </div>
              )}

              {!snap && loading && (
                <div className="rounded-xl bg-[var(--md-surface-container-low)] px-3 py-4 text-center text-[0.72rem] text-[var(--md-on-surface-variant)]">
                  Загрузка телеметрии подключения...
                </div>
              )}

              {snap && (
                <>
                  {/* 4-stage pipeline */}
                  <M3SurfaceCard level="default" className="p-3.5 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-[0.78rem] font-bold text-[var(--md-on-surface)]">
                        Этапы соединения
                      </span>
                      <M3StatusBadge tone={snap.status === 'connected' ? 'success' : snap.status === 'error' ? 'error' : 'neutral'}>
                        {snap.status === 'connected'
                          ? 'Подключено'
                          : snap.status === 'connecting'
                            ? 'Подключение'
                            : snap.status === 'reconnecting'
                              ? 'Переподключение'
                              : snap.status === 'error'
                                ? 'Ошибка'
                                : 'Отключено'}
                      </M3StatusBadge>
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-[0.7rem]">
                      {[
                        ['1. Процесс ядра', snap.stages.coreProcessRunning],
                        [
                          snap.mode === 'tun' ? '2. TUN-адаптер' : '2. Локальный прокси',
                          snap.mode === 'tun' ? snap.stages.tunAdapterUp : snap.stages.localProxyListening,
                        ],
                        ['3. Туннель установлен', snap.stages.tunnelEstablished],
                        ['4. Выход подтверждён', snap.stages.internetVerified],
                      ].map(([label, ok], idx) => (
                        <div
                          key={idx}
                          className="flex items-center justify-between rounded-xl bg-[var(--md-surface-container-low)] px-2.5 py-2"
                        >
                          <span className="text-[var(--md-on-surface)]">{label}</span>
                          {ok ? (
                            <CheckCircle2 className="h-3.5 w-3.5 text-[var(--md-success)]" />
                          ) : (
                            <Clock className="h-3.5 w-3.5 text-[var(--md-on-surface-variant)]" />
                          )}
                        </div>
                      ))}
                    </div>
                  </M3SurfaceCard>

                  {/* Active stack */}
                  <M3SurfaceCard level="default" className="p-3.5 grid grid-cols-2 gap-2 text-[0.7rem]">
                    <div>Узел: <span className="font-semibold">{snap.activeServerName ?? '—'}</span></div>
                    <div>Ядро: <span className="font-mono font-semibold">{snap.activeCoreName} {snap.activeCoreVersion}</span></div>
                    <div>Режим: <span className="font-semibold">{snap.mode === 'tun' ? `TUN (${snap.activeAdapterName ?? 'aura_tun'})` : 'Системный прокси'}</span></div>
                    <div>DNS / Маршруты: <span className="font-semibold">{snap.dnsMode} / {snap.routingProfile}</span></div>
                    <div>TCP / HTTP RTT: <span className="font-mono-num">{snap.tcpLatencyMs ?? '—'} / {snap.httpRttMs ?? '—'} мс</span></div>
                    <div>Аптайм / реконнекты: <span className="font-mono-num">{formatDuration(snap.uptimeSecs ? Math.floor(Date.now() / 1000) - snap.uptimeSecs : null, Date.now())} / {snap.reconnectCount}</span></div>
                  </M3SurfaceCard>

                  {/* Throughput summary */}
                  <M3SurfaceCard level="default" className="p-3.5 space-y-2 text-[0.7rem]">
                    <div className="font-bold text-[var(--md-on-surface)]">Пропускная способность сессии</div>
                    <div className="grid grid-cols-2 gap-2 font-mono-num">
                      <div className="rounded-xl bg-[var(--md-surface-container-low)] px-2.5 py-2">
                        <div className="text-[0.65rem] text-[var(--md-on-surface-variant)]">Текущая ↓ / ↑</div>
                        <div className="font-semibold text-[var(--md-on-surface)]">
                          {formatSpeed(snap.throughput.currentRxBps)} / {formatSpeed(snap.throughput.currentTxBps)}
                        </div>
                      </div>
                      <div className="rounded-xl bg-[var(--md-surface-container-low)] px-2.5 py-2">
                        <div className="text-[0.65rem] text-[var(--md-on-surface-variant)]">Средняя ↓ / ↑</div>
                        <div className="font-semibold text-[var(--md-on-surface)]">
                          {formatSpeed(snap.throughput.avgRxBps)} / {formatSpeed(snap.throughput.avgTxBps)}
                        </div>
                      </div>
                      <div className="rounded-xl bg-[var(--md-surface-container-low)] px-2.5 py-2">
                        <div className="text-[0.65rem] text-[var(--md-on-surface-variant)]">Пик ↓ / ↑</div>
                        <div className="font-semibold text-[var(--md-on-surface)]">
                          {formatSpeed(snap.throughput.peakRxBps)} / {formatSpeed(snap.throughput.peakTxBps)}
                        </div>
                      </div>
                      <div className="rounded-xl bg-[var(--md-surface-container-low)] px-2.5 py-2">
                        <div className="text-[0.65rem] text-[var(--md-on-surface-variant)]">Итого ↓ / ↑</div>
                        <div className="font-semibold text-[var(--md-on-surface)]">
                          {formatBytes(snap.throughput.totalRxBytes)} / {formatBytes(snap.throughput.totalTxBytes)}
                        </div>
                      </div>
                    </div>
                  </M3SurfaceCard>

                  {/* Timeline */}
                  <M3SurfaceCard level="default" className="p-3.5 space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[0.78rem] font-bold text-[var(--md-on-surface)]">
                        Таймлайн событий ({timeline.length})
                      </span>
                      {timeline.length > 0 && (
                        <M3Button
                          size="sm"
                          variant="text"
                          onClick={() => void handleClearTimeline()}
                          leadingIcon={<Trash2 className="h-3 w-3" />}
                        >
                          Очистить
                        </M3Button>
                      )}
                    </div>
                    {timeline.length === 0 ? (
                      <div className="text-[0.7rem] text-[var(--md-on-surface-variant)]">
                        Событий за сессию ещё нет.
                      </div>
                    ) : (
                      <div className="space-y-1.5">
                        {timeline.map((ev) => (
                          <div
                            key={ev.id}
                            className="flex items-start justify-between gap-2 rounded-xl bg-[var(--md-surface-container-low)] px-2.5 py-1.5 text-[0.6875rem]"
                          >
                            <div className="min-w-0">
                              <div className="font-semibold text-[var(--md-on-surface)]">
                                [{ev.stage}] {ev.message}
                              </div>
                              <div className="font-mono text-[0.625rem] text-[var(--md-on-surface-variant)]">
                                {new Date(ev.timestamp).toLocaleTimeString('ru-RU')}
                                {ev.latencyMs != null ? ` • ${ev.latencyMs} мс` : ''}
                              </div>
                            </div>
                            <M3StatusBadge
                              tone={ev.level === 'error' ? 'error' : ev.level === 'warn' ? 'warning' : 'neutral'}
                              dot={false}
                            >
                              {ev.level === 'error' ? 'ошибка' : ev.level === 'warn' ? 'внимание' : 'инфо'}
                            </M3StatusBadge>
                          </div>
                        ))}
                      </div>
                    )}
                  </M3SurfaceCard>
                </>
              )}
            </div>
          </motion.aside>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
