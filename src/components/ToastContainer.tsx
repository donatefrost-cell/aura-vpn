import { AlertCircle, CheckCircle2, Info, X } from 'lucide-react';
import { AnimatePresence, motion } from 'motion/react';

export interface ToastMessage {
  id: string;
  tone: 'success' | 'error' | 'info';
  title: string;
  description?: string;
}

export function ToastContainer({
  toasts,
  onDismiss,
}: {
  toasts: ToastMessage[];
  onDismiss: (id: string) => void;
}) {
  return (
    <div
      role="status"
      aria-live="polite"
      className="pointer-events-none fixed right-4 bottom-4 z-50 flex w-84 flex-col gap-2"
    >
      <AnimatePresence>
        {toasts.map((toast) => {
          const Icon =
            toast.tone === 'success'
              ? CheckCircle2
              : toast.tone === 'error'
                ? AlertCircle
                : Info;

          // High-contrast semantic inverse tokens verified >= 4.5:1 against --md-inverse-surface
          const iconColor =
            toast.tone === 'success'
              ? 'text-[var(--md-inverse-success)]'
              : toast.tone === 'error'
                ? 'text-[var(--md-inverse-error)]'
                : 'text-[var(--md-inverse-primary)]';

          return (
            <motion.div
              key={toast.id}
              initial={{ opacity: 0, y: 12, scale: 0.96 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 8, scale: 0.96 }}
              transition={{ duration: 0.16 }}
              className="pointer-events-auto flex items-start gap-2.5 rounded-2xl border border-[var(--md-outline-variant)] bg-[var(--md-inverse-surface)] px-3.5 py-2.5 text-[var(--md-inverse-on-surface)] shadow-xl"
            >
              <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${iconColor}`} />
              <div className="min-w-0 flex-1">
                <div className="text-[0.78rem] font-semibold">{toast.title}</div>
                {toast.description && (
                  <div className="mt-0.5 text-[0.72rem] leading-snug opacity-85">
                    {toast.description}
                  </div>
                )}
              </div>
              <button
                type="button"
                onClick={() => onDismiss(toast.id)}
                aria-label="Скрыть уведомление"
                className="rounded-lg p-1 opacity-75 transition-opacity hover:opacity-100"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </motion.div>
          );
        })}
      </AnimatePresence>
    </div>
  );
}
