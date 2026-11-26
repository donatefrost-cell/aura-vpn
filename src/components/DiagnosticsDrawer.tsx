import { Check, Copy, Download, ShieldCheck, Trash2, X } from 'lucide-react';
import { AnimatePresence, motion } from 'motion/react';
import { useState } from 'react';
import { useLiveLogs } from '../stores/liveStore';
import type { CoreDiagnostics } from '../types/vpn';
import { M3Button, M3IconButton, M3StatusBadge } from './md3';

interface DiagnosticsDrawerProps {
  open: boolean;
  diagnostics: CoreDiagnostics;
  onClose: () => void;
  onClearLogs: () => void;
  onExportDiagnostics: () => Promise<void>;
}

export function DiagnosticsDrawer({
  open,
  diagnostics,
  onClose,
  onClearLogs,
  onExportDiagnostics,
}: DiagnosticsDrawerProps) {
  const logs = useLiveLogs();
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    const text = logs
      .map((l) => `[${l.timestamp}] [${l.level.toUpperCase()}] [${l.source}] ${l.message}`)
      .join('\n');
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // Clipboard may be unavailable outside focused/secure context
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
            aria-label="Диагностика и журнал"
            initial={{ x: 440 }}
            animate={{ x: 0 }}
            exit={{ x: 440 }}
            transition={{ type: 'spring', stiffness: 420, damping: 38 }}
            onClick={(e) => e.stopPropagation()}
            className="flex h-full w-full max-w-[460px] flex-col border-l border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] shadow-2xl"
          >
            <div className="flex items-center justify-between border-b border-[var(--md-outline-variant)] px-4 py-3.5">
              <div>
                <h2 className="font-display text-[0.9375rem] font-bold text-[var(--md-on-surface)]">
                  Диагностика и журнал
                </h2>
                <p className="text-[0.72rem] text-[var(--md-on-surface-variant)]">
                  Секреты из VPN-ключей, подписок и HWID скрываются автоматически
                </p>
              </div>
              <M3IconButton size="sm" onClick={onClose} aria-label="Закрыть диагностику">
                <X className="h-4 w-4" />
              </M3IconButton>
            </div>

            <div className="grid grid-cols-2 gap-2 border-b border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] p-3.5 text-[0.72rem]">
              <div className="rounded-2xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] p-2.5">
                <div className="flex items-center justify-between text-[var(--md-on-surface-variant)]">
                  <span>Сетевое ядро</span>
                  {diagnostics.coreIntegrityOk && (
                    <ShieldCheck className="h-3.5 w-3.5 text-[var(--md-success)]" />
                  )}
                </div>
                <div className="mt-0.5 truncate font-semibold text-[var(--md-on-surface)]">
                  {diagnostics.coreName}
                </div>
                <div className="mt-0.5 truncate font-mono text-[0.65rem] text-[var(--md-on-surface-variant)]">
                  {diagnostics.coreVersion}
                </div>
              </div>
              <div className="rounded-2xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] p-2.5">
                <div className="text-[var(--md-on-surface-variant)]">Системный прокси</div>
                <div className="mt-0.5 font-semibold text-[var(--md-on-surface)]">
                  {diagnostics.systemProxyActive ? 'Активен' : 'Отключён'}
                </div>
                <div className="mt-0.5 truncate font-mono text-[0.65rem] text-[var(--md-on-surface-variant)]">
                  {diagnostics.activeProxyEndpoint ?? 'Прямое подключение'}
                </div>
              </div>
              <div className="rounded-2xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] p-2.5">
                <div className="text-[var(--md-on-surface-variant)]">TUN и AmneziaWG</div>
                <div className="mt-0.5 font-semibold text-[var(--md-on-surface)]">
                  {diagnostics.wintunAvailable
                    ? diagnostics.wintunIntegrityOk
                      ? 'Wintun SHA-256 OK'
                      : 'Wintun OK'
                    : 'Нет Wintun'}{' '}
                  •{' '}
                  {diagnostics.awgAvailable
                    ? diagnostics.awgIntegrityOk
                      ? 'AWG OK'
                      : 'AWG (?)'
                    : 'Нет AWG'}
                </div>
                <div className="mt-0.5 text-[0.65rem] text-[var(--md-on-surface-variant)]">
                  {diagnostics.isElevated ? 'Права администратора' : 'Обычный режим (без UAC)'}
                </div>
              </div>
              <div className="rounded-2xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] p-2.5">
                <div className="text-[var(--md-on-surface-variant)]">Kill Switch</div>
                <div className="mt-0.5 font-semibold text-[var(--md-on-surface)]">
                  {diagnostics.killSwitchEngaged ? 'Блокировка активна' : 'В ожидании'}
                </div>
                <div className="mt-0.5 text-[0.65rem] text-[var(--md-on-surface-variant)]">
                  Автосброс при выходе
                </div>
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--md-outline-variant)] px-4 py-2">
              <div className="flex items-center gap-2">
                <span className="text-[0.72rem] font-medium text-[var(--md-on-surface-variant)]">
                  Журнал ядра
                </span>
                  <M3StatusBadge tone="neutral" className="font-mono-num">
                    {logs.length}
                  </M3StatusBadge>
              </div>
              <div className="flex items-center gap-1.5">
                <M3Button
                  variant="tonal"
                  size="sm"
                  onClick={() => void onExportDiagnostics()}
                  leadingIcon={<Download className="h-3 w-3" />}
                >
                  Экспорт JSON
                </M3Button>
                <M3Button
                  variant="outlined"
                  size="sm"
                  onClick={handleCopy}
                  disabled={logs.length === 0}
                  leadingIcon={
                    copied ? (
                      <Check className="h-3 w-3 text-[var(--md-success)]" />
                    ) : (
                      <Copy className="h-3 w-3" />
                    )
                  }
                >
                  {copied ? 'Готово' : 'Копия'}
                </M3Button>
                <M3IconButton
                  size="sm"
                  tooltip="Очистить журнал"
                  onClick={onClearLogs}
                  disabled={logs.length === 0}
                  aria-label="Очистить журнал"
                  className="text-[var(--md-error)] hover:bg-[var(--md-error-container)]"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </M3IconButton>
              </div>
            </div>

            <div className="aura-scroll flex-1 overflow-y-auto bg-[var(--md-surface)] p-3 font-mono text-[0.6875rem] leading-relaxed selectable">
              {logs.length === 0 ? (
                <div className="flex h-full items-center justify-center text-[var(--md-on-surface-variant)]">
                  Журнал событий пуст
                </div>
              ) : (
                <div className="space-y-1.5">
                  {logs.map((entry) => {
                    const lvlColor =
                      entry.level === 'error'
                        ? 'text-[var(--md-error)]'
                        : entry.level === 'warn'
                          ? 'text-[var(--md-warning)]'
                          : 'text-[var(--md-primary)]';
                    return (
                      <div
                        key={entry.id}
                        className="rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] px-2.5 py-1.5"
                      >
                        <div className="flex items-center gap-2 text-[0.625rem] text-[var(--md-on-surface-variant)]">
                          <span>{entry.timestamp}</span>
                          <span className={`font-semibold uppercase ${lvlColor}`}>{entry.level}</span>
                          <span>[{entry.source}]</span>
                        </div>
                        <div className="mt-0.5 break-words text-[var(--md-on-surface)]">
                          {entry.message}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </motion.aside>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
