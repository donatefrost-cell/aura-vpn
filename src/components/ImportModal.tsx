import {
  AlertCircle,
  CheckCircle2,
  ClipboardPaste,
  FileUp,
  Link2,
  Loader2,
  ShieldPlus,
  X,
} from 'lucide-react';
import { AnimatePresence, motion } from 'motion/react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { api } from '../services/api';
import type { ImportPreviewResult } from '../types/vpn';
import { detectInputKind } from '../utils/importHelpers';
import { M3Button, M3IconButton, M3ProgressBar, M3Switch } from './md3';

interface ImportModalProps {
  open: boolean;
  initialText?: string;
  onClose: () => void;
  onSmartImport: (
    raw: string,
    onProgress?: (current: number, total: number) => void,
    applyAdaptations?: boolean,
  ) => Promise<void>;
}

export function ImportModal({
  open,
  initialText = '',
  onClose,
  onSmartImport,
}: ImportModalProps) {
  const [value, setValue] = useState(initialText);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState<{ current: number; total: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<ImportPreviewResult | null>(null);
  const [applyAdaptations, setApplyAdaptations] = useState(true);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setValue(initialText);
      setError(null);
      setLoading(false);
      setProgress(null);
      setPreview(null);
      setApplyAdaptations(true);
    }
  }, [open, initialText]);

  useEffect(() => {
    if (!open || loading) return;
    const trimmed = value.trim();
    if (!trimmed) {
      setPreview(null);
      return;
    }
    let cancelled = false;
    const timer = window.setTimeout(() => {
      void api
        .previewImportText(trimmed)
        .then((res) => {
          if (!cancelled) setPreview(res);
        })
        .catch(() => {
          if (!cancelled) setPreview(null);
        });
    }, 180);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [open, loading, value]);

  const detection = useMemo(() => detectInputKind(value), [value]);

  const handlePaste = async () => {
    setError(null);
    try {
      const clip = await api.readClipboard();
      if (!clip.trim()) {
        setError('Буфер обмена пуст');
        return;
      }
      setValue(clip.trim());
    } catch {
      setError('Не удалось прочитать буфер обмена');
    }
  };

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setError(null);
    try {
      const text = await file.text();
      setValue(text);
    } catch {
      setError('Не удалось прочитать выбранный файл');
    } finally {
      e.target.value = '';
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = value.trim();
    if (!trimmed) {
      setError('Вставьте ключ, конфиг или ссылку подписки');
      return;
    }

    setLoading(true);
    setError(null);
    setProgress(null);
    try {
      await onSmartImport(
        trimmed,
        (current, total) => setProgress({ current, total }),
        applyAdaptations,
      );
      onClose();
    } catch (err) {
      setError(
        typeof err === 'string'
          ? err
          : err instanceof Error
            ? err.message
            : 'Ошибка импорта',
      );
    } finally {
      setLoading(false);
      setProgress(null);
    }
  };

  const isSubKind = detection.kind === 'sub' || detection.kind === 'multi_sub';

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.15 }}
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4 backdrop-blur-xs"
          onClick={loading ? undefined : onClose}
        >
          <motion.div
            role="dialog"
            aria-modal="true"
            aria-label="Добавить ключ, конфиг или подписку"
            initial={{ opacity: 0, scale: 0.97, y: 8 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.97, y: 8 }}
            transition={{ duration: 0.18, ease: 'easeOut' }}
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-[560px] rounded-3xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-high)] p-5 shadow-2xl"
          >
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[var(--md-primary-container)] text-[var(--md-on-primary-container)]">
                  {isSubKind ? (
                    <Link2 className="h-5 w-5" />
                  ) : (
                    <ShieldPlus className="h-5 w-5" />
                  )}
                </div>
                <div>
                  <h2 className="font-display text-[0.97rem] font-bold text-[var(--md-on-surface)]">
                    Добавить ключ, конфиг или подписку
                  </h2>
                  <p className="text-[0.75rem] text-[var(--md-on-surface-variant)]">
                    Поддерживается вставка из Telegram, .conf, JSON, YAML и список подписок
                  </p>
                </div>
              </div>
              <M3IconButton
                size="sm"
                onClick={onClose}
                disabled={loading}
                aria-label="Закрыть окно импорта"
              >
                <X className="h-4 w-4" />
              </M3IconButton>
            </div>

            <form onSubmit={handleSubmit} className="mt-4 space-y-3">
              <input
                ref={fileInputRef}
                type="file"
                accept=".conf,.json,.txt,.yaml,.yml"
                onChange={handleFileSelect}
                className="hidden"
              />

              <div className="relative">
                <textarea
                  aria-label="Ключи, конфиг или URL подписки"
                  value={value}
                  onChange={(e) => {
                    setValue(e.target.value);
                    if (error) setError(null);
                  }}
                  rows={6}
                  placeholder={
                    'vless://... | hy2://... | vpn://... (Amnezia)\nhttps://sub-1.example/... (можно несколько URL построчно)\nили конфиг AmneziaWG (.conf) / Xray JSON / Clash YAML'
                  }
                  className="aura-scroll w-full resize-none rounded-2xl border border-[var(--md-outline-variant)] bg-[var(--md-surface)] p-3.5 pb-12 font-mono text-[0.75rem] leading-relaxed text-[var(--md-on-surface)] placeholder:text-[var(--md-on-surface-variant)]/60 focus:border-[var(--md-primary)] focus:outline-none"
                  autoFocus
                />
                <div className="absolute right-2.5 bottom-2.5 flex items-center gap-1.5">
                  <M3Button
                    type="button"
                    variant="tonal"
                    size="sm"
                    onClick={() => fileInputRef.current?.click()}
                    leadingIcon={<FileUp className="h-3.5 w-3.5" />}
                  >
                    Файл
                  </M3Button>
                  <M3Button
                    type="button"
                    variant="tonal"
                    size="sm"
                    onClick={handlePaste}
                    leadingIcon={<ClipboardPaste className="h-3.5 w-3.5" />}
                  >
                    Из буфера
                  </M3Button>
                </div>
              </div>

              <div className="rounded-xl bg-[var(--md-surface-container-low)] px-3 py-2 text-[0.72rem] text-[var(--md-on-surface-variant)]">
                {detection.label}
              </div>

              {/* Safe dry-run preview */}
              {preview && preview.validCount > 0 && !loading && (
                <div className="rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] px-3 py-2 text-[0.72rem]">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="inline-flex items-center gap-1.5 font-semibold text-[var(--md-on-surface)]">
                      <CheckCircle2 className="h-3.5 w-3.5 text-[var(--md-success)]" />
                      {preview.kind === 'subscription'
                        ? `Предпросмотр: найдена подписка (${preview.validCount})`
                        : `Предпросмотр: распознано узлов — ${preview.validCount}`}
                    </span>
                    <div className="flex items-center gap-2 text-[0.6875rem] text-[var(--md-on-surface-variant)]">
                      {preview.duplicateCount > 0 && (
                        <span>Дубликатов: {preview.duplicateCount}</span>
                      )}
                      {preview.skippedLines > 0 && (
                        <span>Пропущено строк: {preview.skippedLines}</span>
                      )}
                    </div>
                  </div>
                  {preview.servers.length > 0 && (
                    <div className="mt-1.5 flex flex-wrap gap-1.5">
                      {preview.servers.slice(0, 4).map((srv, idx) => (
                        <span
                          key={`${srv.address}-${srv.port}-${idx}`}
                          className="inline-flex items-center gap-1 rounded-lg bg-[var(--md-surface-container-high)] px-2 py-0.5 text-[0.65rem] text-[var(--md-on-surface)]"
                        >
                          <span className="font-semibold text-[var(--md-primary)]">
                            {srv.protocol}
                          </span>
                          <span className="max-w-[140px] truncate">{srv.name}</span>
                          {srv.isDuplicate && (
                            <span className="text-[var(--md-warning)]">(дубль)</span>
                          )}
                        </span>
                      ))}
                      {preview.servers.length > 4 && (
                        <span className="px-1 py-0.5 text-[0.65rem] text-[var(--md-on-surface-variant)]">
                          +{preview.servers.length - 4}
                        </span>
                      )}
                    </div>
                  )}

                  {preview.capabilitiesSummary && preview.capabilitiesSummary.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {preview.capabilitiesSummary.map((cap, idx) => (
                        <span
                          key={`${cap}-${idx}`}
                          className="rounded-md bg-[var(--md-surface-container)] px-1.5 py-0.5 text-[0.625rem] font-medium text-[var(--md-on-surface-variant)]"
                        >
                          {cap}
                        </span>
                      ))}
                    </div>
                  )}

                  {preview.warnings && preview.warnings.length > 0 && (
                    <div className="mt-2 space-y-0.5 rounded-lg bg-[var(--md-warning-container)]/50 px-2.5 py-1.5 text-[0.675rem] text-[var(--md-on-surface)]">
                      {preview.warnings.map((w, idx) => (
                        <div key={idx}>• {w}</div>
                      ))}
                    </div>
                  )}

                  {preview.suggestedAdaptations && preview.suggestedAdaptations.length > 0 && (
                    <div className="mt-2 space-y-1.5 rounded-lg border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] p-2">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-[0.6875rem] font-semibold text-[var(--md-on-surface)]">
                          Предлагаемые адаптации ({preview.suggestedAdaptations.length})
                        </span>
                        <label className="inline-flex items-center gap-1.5 text-[0.65rem] text-[var(--md-on-surface-variant)]">
                          <M3Switch
                            checked={applyAdaptations}
                            onChange={setApplyAdaptations}
                            ariaLabel="Применить безопасные адаптации при импорте"
                          />
                          <span>Применить безопасные</span>
                        </label>
                      </div>
                      <div className="space-y-1">
                        {preview.suggestedAdaptations.slice(0, 3).map((a, idx) => (
                          <div
                            key={`${a.field}-${idx}`}
                            className="flex items-center justify-between gap-2 text-[0.65rem]"
                          >
                            <span className="truncate text-[var(--md-on-surface-variant)]">
                              {a.label}: <span className="font-mono">{a.currentValue}</span> →{' '}
                              <span className="font-mono text-[var(--md-primary)]">
                                {a.proposedValue}
                              </span>
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {loading && progress && (
                <div className="space-y-1.5 rounded-xl bg-[var(--md-surface-container-low)] px-3 py-2.5">
                  <div className="flex items-center justify-between text-[0.72rem] font-medium text-[var(--md-on-surface)]">
                    <span>Импорт подписки {progress.current} из {progress.total}...</span>
                    <span className="font-mono tabular-nums">
                      {Math.round((progress.current / progress.total) * 100)}%
                    </span>
                  </div>
                  <M3ProgressBar percent={(progress.current / progress.total) * 100} />
                </div>
              )}

              {error && (
                <div className="flex items-start gap-2 rounded-xl border border-[var(--md-error)]/35 bg-[var(--md-error-container)] px-3 py-2.5 text-[0.75rem] text-[var(--md-error)]">
                  <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                  <span className="whitespace-pre-line">{error}</span>
                </div>
              )}

              <div className="flex items-center justify-end gap-2 pt-1">
                <M3Button type="button" variant="text" onClick={onClose} disabled={loading}>
                  Отмена
                </M3Button>
                <M3Button
                  type="submit"
                  variant="filled"
                  disabled={loading || !value.trim()}
                  leadingIcon={loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : undefined}
                >
                  {detection.kind === 'multi_sub'
                    ? 'Загрузить подписки'
                    : detection.kind === 'sub'
                      ? 'Загрузить подписку'
                      : 'Импортировать'}
                </M3Button>
              </div>
            </form>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
