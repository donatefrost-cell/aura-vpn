import { Power } from 'lucide-react';
import { motion, useReducedMotion } from 'motion/react';
import type { ConnectionStatus } from '../types/vpn';

interface ConnectionDialProps {
  status: ConnectionStatus;
  disabled?: boolean;
  compact?: boolean;
  onToggle: () => void;
}

export function ConnectionDial({
  status,
  disabled,
  compact = false,
  onToggle,
}: ConnectionDialProps) {
  const reduced = useReducedMotion();
  const isBusy =
    status === 'connecting' ||
    status === 'verifying' ||
    status === 'switching' ||
    status === 'reconnecting' ||
    status === 'disconnecting';
  const isConnected = status === 'connected';
  const isError = status === 'error';

  const ringColor = isConnected
    ? 'var(--md-success)'
    : status === 'reconnecting'
      ? 'var(--md-warning)'
      : isBusy
        ? 'var(--md-primary)'
        : isError
          ? 'var(--md-error)'
          : 'var(--md-outline)';

  const actionLabel = isConnected
    ? 'Отключить'
    : status === 'connecting'
      ? 'Подключение...'
      : status === 'verifying'
        ? 'Проверка...'
        : status === 'switching'
          ? 'Переключение...'
          : status === 'reconnecting'
            ? 'Повтор...'
            : status === 'disconnecting'
              ? 'Отключение...'
              : isError
                ? 'Повторить'
                : 'Подключить';

  const outerSize = compact ? 'h-[124px] w-[124px]' : 'h-[138px] w-[138px]';
  const innerSize = compact ? 'h-[100px] w-[100px]' : 'h-[112px] w-[112px]';

  return (
    <div className="relative flex flex-col items-center justify-center shrink-0">
      <motion.button
        type="button"
        disabled={disabled || isBusy}
        onClick={onToggle}
        aria-label={actionLabel}
        whileHover={reduced || disabled || isBusy ? undefined : { scale: 1.02 }}
        whileTap={reduced || disabled || isBusy ? undefined : { scale: 0.96 }}
        transition={{ type: 'spring', stiffness: 420, damping: 28 }}
        className={`group relative flex items-center justify-center rounded-full focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[var(--md-primary)] disabled:cursor-wait ${outerSize}`}
      >
        <svg
          viewBox="0 0 160 160"
          className="pointer-events-none absolute inset-0 h-full w-full -rotate-90"
        >
          <circle
            cx="80"
            cy="80"
            r="74"
            fill="none"
            stroke="var(--md-outline-variant)"
            strokeWidth="2.5"
          />
          {!isBusy ? (
            <motion.circle
              cx="80"
              cy="80"
              r="74"
              fill="none"
              stroke={ringColor}
              strokeWidth={isConnected || isError ? '3.5' : '2.2'}
              strokeLinecap="round"
              initial={false}
              animate={{
                opacity: isConnected || isError ? 1 : 0.45,
                pathLength: isConnected ? 1 : 0.72,
              }}
              transition={{ duration: reduced ? 0 : 0.35, ease: 'easeOut' }}
            />
          ) : (
            <motion.circle
              cx="80"
              cy="80"
              r="74"
              fill="none"
              stroke={ringColor}
              strokeWidth="3.5"
              strokeLinecap="round"
              strokeDasharray="115 360"
              animate={reduced ? { opacity: [0.5, 1, 0.5] } : { rotate: 360 }}
              transition={
                reduced
                  ? { duration: 1.3, repeat: Infinity }
                  : { duration: 1.05, repeat: Infinity, ease: 'linear' }
              }
              style={{ transformOrigin: '80px 80px' }}
            />
          )}
        </svg>

        <div
          className={`relative flex flex-col items-center justify-center rounded-full border transition-colors duration-200 ${innerSize} ${
            isConnected
              ? 'border-[var(--md-success)]/45 bg-[var(--md-success-container)]'
              : isError
                ? 'border-[var(--md-error)]/45 bg-[var(--md-error-container)]'
                : 'border-[var(--md-outline-variant)] bg-[var(--md-surface-container-highest)] group-hover:border-[var(--md-primary)]/60'
          }`}
        >
          <Power
            className="h-7 w-7 transition-colors duration-200"
            style={{
              color: isConnected
                ? 'var(--md-success)'
                : status === 'reconnecting'
                  ? 'var(--md-warning)'
                  : isBusy
                    ? 'var(--md-primary)'
                    : isError
                      ? 'var(--md-error)'
                      : 'var(--md-on-surface)',
            }}
            strokeWidth={2.2}
          />
          <span className="mt-1.5 text-[0.6875rem] font-semibold tracking-wide text-[var(--md-on-surface)]">
            {actionLabel}
          </span>
        </div>
      </motion.button>
    </div>
  );
}
