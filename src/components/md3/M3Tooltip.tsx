import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';

export interface M3TooltipProps {
  label: ReactNode;
  shortcut?: string;
  side?: 'top' | 'bottom' | 'left' | 'right';
  delayMs?: number;
  disabled?: boolean;
  className?: string;
  children: ReactNode;
}

export function M3Tooltip({
  label,
  shortcut,
  side = 'top',
  delayMs = 280,
  disabled = false,
  className = '',
  children,
}: M3TooltipProps) {
  const triggerRef = useRef<HTMLSpanElement>(null);
  const timerRef = useRef<number | null>(null);
  const [visible, setVisible] = useState(false);
  const [coords, setCoords] = useState<{ top: number; left: number; placedSide: 'top' | 'bottom' | 'left' | 'right' }>({
    top: 0,
    left: 0,
    placedSide: side,
  });

  const updatePosition = useCallback(() => {
    const el = triggerRef.current;
    if (!el || typeof window === 'undefined') return;
    const rect = el.getBoundingClientRect();
    const gap = 8;
    const estWidth = 220;
    const estHeight = 32;

    let chosen = side;
    if (side === 'top' && rect.top < estHeight + 14) chosen = 'bottom';
    else if (side === 'bottom' && window.innerHeight - rect.bottom < estHeight + 14) chosen = 'top';
    else if (side === 'left' && rect.left < estWidth + 14) chosen = 'right';
    else if (side === 'right' && window.innerWidth - rect.right < estWidth + 14) chosen = 'left';

    let top = rect.top - gap;
    let left = rect.left + rect.width / 2;

    if (chosen === 'bottom') {
      top = rect.bottom + gap;
      left = rect.left + rect.width / 2;
    } else if (chosen === 'left') {
      top = rect.top + rect.height / 2;
      left = rect.left - gap;
    } else if (chosen === 'right') {
      top = rect.top + rect.height / 2;
      left = rect.right + gap;
    }

    if (chosen === 'top' || chosen === 'bottom') {
      left = Math.max(96, Math.min(window.innerWidth - 96, left));
    } else {
      top = Math.max(24, Math.min(window.innerHeight - 24, top));
    }

    setCoords({ top, left, placedSide: chosen });
  }, [side]);

  const show = useCallback(() => {
    if (disabled || !label) return;
    if (timerRef.current) window.clearTimeout(timerRef.current);
    timerRef.current = window.setTimeout(() => {
      updatePosition();
      setVisible(true);
    }, delayMs);
  }, [delayMs, disabled, label, updatePosition]);

  const hide = useCallback(() => {
    if (timerRef.current) {
      window.clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    setVisible(false);
  }, []);

  useEffect(() => {
    if (!visible) return;
    const onScrollOrKey = (e: Event) => {
      if (e instanceof KeyboardEvent && e.key !== 'Escape') return;
      hide();
    };
    window.addEventListener('scroll', onScrollOrKey, true);
    window.addEventListener('keydown', onScrollOrKey);
    return () => {
      window.removeEventListener('scroll', onScrollOrKey, true);
      window.removeEventListener('keydown', onScrollOrKey);
    };
  }, [hide, visible]);

  useEffect(() => () => {
    if (timerRef.current) window.clearTimeout(timerRef.current);
  }, []);

  const transformClass =
    coords.placedSide === 'top'
      ? '-translate-x-1/2 -translate-y-full'
      : coords.placedSide === 'bottom'
        ? '-translate-x-1/2'
        : coords.placedSide === 'left'
          ? '-translate-x-full -translate-y-1/2'
          : '-translate-y-1/2';

  const hasExplicitLayout =
    /\b(block|flex|inline-block|grid|w-full)\b/.test(className);

  return (
    <>
      <span
        ref={triggerRef}
        onMouseEnter={show}
        onMouseLeave={hide}
        onFocusCapture={show}
        onBlurCapture={hide}
        className={`${hasExplicitLayout ? '' : 'inline-flex '}${className}`}
      >
        {children}
      </span>
      {visible &&
        typeof document !== 'undefined' &&
        createPortal(
          <div
            role="tooltip"
            style={{ top: coords.top, left: coords.left }}
            className={`pointer-events-none fixed z-[80] max-w-[260px] rounded-xl bg-[var(--md-inverse-surface)] px-2.5 py-1.5 text-[0.7rem] leading-snug font-medium text-[var(--md-inverse-on-surface)] shadow-lg ${transformClass}`}
          >
            <div className="flex items-center gap-2">
              <span>{label}</span>
              {shortcut && (
                <kbd className="rounded bg-[var(--md-inverse-on-surface)]/15 px-1.5 py-0.5 font-mono text-[0.625rem] font-semibold">
                  {shortcut}
                </kbd>
              )}
            </div>
          </div>,
          document.body,
        )}
    </>
  );
}
