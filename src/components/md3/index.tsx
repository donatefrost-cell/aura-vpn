import { Check, Loader2, Search, X } from 'lucide-react';
import { AnimatePresence, motion, useReducedMotion } from 'motion/react';
import {
  useEffect,
  useId,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type MouseEvent as ReactMouseEvent,
  type ReactNode,
} from 'react';
import { M3Tooltip } from './M3Tooltip';

export { M3Checkbox, type M3CheckboxProps } from './M3Checkbox';
export { M3Select, type M3SelectOption, type M3SelectProps } from './M3Select';
export { M3Slider, type M3SliderProps } from './M3Slider';
export { M3Tooltip, type M3TooltipProps } from './M3Tooltip';

type ButtonVariant = 'filled' | 'tonal' | 'outlined' | 'text' | 'danger';
type ButtonSize = 'sm' | 'md' | 'lg';

interface M3ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  leadingIcon?: ReactNode;
  trailingIcon?: ReactNode;
  loading?: boolean;
  loadingText?: string;
  children: ReactNode;
}

export function M3Button({
  variant = 'filled',
  size = 'md',
  leadingIcon,
  trailingIcon,
  loading = false,
  loadingText,
  disabled,
  onClick,
  className = '',
  children,
  ...rest
}: M3ButtonProps) {
  const reduced = useReducedMotion();
  const [ripple, setRipple] = useState<{ id: number; x: number; y: number } | null>(null);

  const variantClasses: Record<ButtonVariant, string> = {
    filled:
      'bg-[var(--md-primary)] text-[var(--md-on-primary)] hover:brightness-105 shadow-xs',
    tonal:
      'bg-[var(--md-secondary-container)] text-[var(--md-on-secondary-container)] hover:brightness-105',
    outlined:
      'border border-[var(--md-outline-variant)] bg-transparent text-[var(--md-on-surface)] hover:bg-[var(--md-surface-container-high)] hover:border-[var(--md-outline)]',
    text:
      'bg-transparent text-[var(--md-primary)] hover:bg-[var(--md-primary)]/10',
    danger:
      'bg-[var(--md-error-container)] text-[var(--md-error)] hover:brightness-105',
  };

  const sizeClasses: Record<ButtonSize, string> = {
    sm: 'h-7 rounded-xl px-2.5 text-[0.72rem] gap-1.5',
    md: 'h-8.5 rounded-xl px-3.5 text-[0.75rem] gap-1.5',
    lg: 'h-10 rounded-2xl px-4.5 text-[0.8125rem] gap-2',
  };

  const handleClick = (e: ReactMouseEvent<HTMLButtonElement>) => {
    if (disabled || loading) return;
    if (!reduced) {
      const rect = e.currentTarget.getBoundingClientRect();
      const x = e.clientX > 0 ? e.clientX - rect.left : rect.width / 2;
      const y = e.clientY > 0 ? e.clientY - rect.top : rect.height / 2;
      const id = Date.now();
      setRipple({ id, x, y });
      window.setTimeout(() => {
        setRipple((prev) => (prev?.id === id ? null : prev));
      }, 360);
    }
    onClick?.(e);
  };

  return (
    <button
      {...rest}
      disabled={disabled || loading}
      onClick={handleClick}
      className={`relative inline-flex items-center justify-center overflow-hidden font-semibold transition-all duration-150 active:scale-[0.98] disabled:pointer-events-none disabled:opacity-45 shrink-0 ${variantClasses[variant]} ${sizeClasses[size]} ${className}`}
    >
      {ripple && (
        <motion.span
          key={ripple.id}
          initial={{ scale: 0, opacity: 0.3 }}
          animate={{ scale: 4.5, opacity: 0 }}
          transition={{ duration: 0.34, ease: 'easeOut' }}
          style={{ left: ripple.x, top: ripple.y }}
          className="pointer-events-none absolute -ml-3 -mt-3 h-6 w-6 rounded-full bg-current"
        />
      )}
      {loading ? (
        <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" />
      ) : (
        leadingIcon
      )}
      <span className="relative z-10">{loading && loadingText ? loadingText : children}</span>
      {!loading && trailingIcon}
    </button>
  );
}

interface M3IconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'standard' | 'tonal' | 'outlined';
  size?: 'sm' | 'md';
  tooltip?: string;
  children: ReactNode;
}

export function M3IconButton({
  variant = 'standard',
  size = 'md',
  tooltip,
  className = '',
  children,
  ...rest
}: M3IconButtonProps) {
  const styles = {
    standard:
      'text-[var(--md-on-surface-variant)] hover:bg-[var(--md-surface-container-highest)] hover:text-[var(--md-on-surface)]',
    tonal:
      'bg-[var(--md-secondary-container)] text-[var(--md-on-secondary-container)] hover:brightness-105',
    outlined:
      'border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] text-[var(--md-on-surface-variant)] hover:border-[var(--md-outline)] hover:text-[var(--md-on-surface)]',
  }[variant];

  const dims = size === 'sm' ? 'h-7 w-7 rounded-lg' : 'h-8.5 w-8.5 rounded-xl';

  const resolvedAriaLabel = rest['aria-label'] ?? tooltip;
  const btn = (
    <button
      type="button"
      {...rest}
      aria-label={resolvedAriaLabel}
      className={`inline-flex items-center justify-center transition-all duration-150 active:scale-95 disabled:pointer-events-none disabled:opacity-45 shrink-0 ${dims} ${styles} ${className}`}
    >
      {children}
    </button>
  );

  return tooltip ? <M3Tooltip label={tooltip}>{btn}</M3Tooltip> : btn;
}

export function M3SegmentedButton<T extends string>({
  options,
  value,
  onChange,
  size = 'md',
  fullWidth = false,
  className = '',
}: {
  options: Array<{ id: T; label: string; icon?: ReactNode }>;
  value: T;
  onChange: (next: T) => void;
  size?: 'sm' | 'md';
  fullWidth?: boolean;
  className?: string;
}) {
  return (
    <div
      role="group"
      className={`inline-flex flex-wrap items-center gap-0.5 rounded-2xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] p-0.5 ${
        fullWidth ? 'w-full' : ''
      } ${className}`}
    >
      {options.map((opt) => {
        const selected = opt.id === value;
        return (
          <button
            key={opt.id}
            type="button"
            onClick={() => onChange(opt.id)}
            aria-pressed={selected}
            className={`relative inline-flex items-center justify-center gap-1.5 rounded-xl font-medium transition-all duration-150 ${
              fullWidth ? 'flex-1' : ''
            } ${
              size === 'sm' ? 'px-2.5 py-1 text-[0.6875rem]' : 'px-3 py-1.5 text-[0.75rem]'
            } ${
              selected
                ? 'bg-[var(--md-secondary-container)] text-[var(--md-on-secondary-container)] shadow-xs'
                : 'text-[var(--md-on-surface-variant)] hover:bg-[var(--md-surface-container-high)]/60 hover:text-[var(--md-on-surface)]'
            }`}
          >
            <span className="relative z-10 inline-flex items-center gap-1.5">
              {opt.icon}
              <span>{opt.label}</span>
            </span>
          </button>
        );
      })}
    </div>
  );
}

export function M3Chip({
  active = false,
  variant = 'filter',
  leading,
  trailing,
  onClick,
  tooltip,
  title,
  children,
  className = '',
}: {
  active?: boolean;
  variant?: 'filter' | 'assist';
  leading?: ReactNode;
  trailing?: ReactNode;
  onClick?: () => void;
  tooltip?: string;
  title?: string;
  children: ReactNode;
  className?: string;
}) {
  const base =
    variant === 'filter'
      ? active
        ? 'bg-[var(--md-secondary-container)] text-[var(--md-on-secondary-container)] border-transparent'
        : 'border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] text-[var(--md-on-surface-variant)] hover:bg-[var(--md-surface-container-high)] hover:text-[var(--md-on-surface)]'
      : 'border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] text-[var(--md-on-surface)] hover:border-[var(--md-primary)]';

  const tip = tooltip ?? title;
  const fullW = /\bw-full\b/.test(className);
  const chipBtn = (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={variant === 'filter' ? active : undefined}
      className={`inline-flex items-center gap-1.5 rounded-xl px-2.5 py-1 text-[0.72rem] font-medium transition-all duration-150 active:scale-[0.98] ${
        fullW ? 'min-w-0 w-full' : 'shrink-0'
      } ${base} ${className}`}
    >
      {leading}
      <span className="truncate">{children}</span>
      {trailing}
    </button>
  );

  return tip ? (
    <M3Tooltip label={tip} className={fullW ? 'flex w-full min-w-0' : ''}>
      {chipBtn}
    </M3Tooltip>
  ) : (
    chipBtn
  );
}

export function M3Switch({
  checked,
  onChange,
  disabled = false,
  ariaLabel,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  disabled?: boolean;
  ariaLabel?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={ariaLabel}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`group relative inline-flex h-6.5 w-11.5 shrink-0 items-center rounded-full transition-colors duration-150 disabled:pointer-events-none disabled:opacity-45 ${
        checked
          ? 'bg-[var(--md-primary)]'
          : 'border-2 border-[var(--md-outline)] bg-[var(--md-surface-container-highest)] hover:border-[var(--md-on-surface)]'
      }`}
    >
      <span
        className={`flex items-center justify-center rounded-full transition-all duration-150 ${
          checked
            ? 'h-4.5 w-4.5 translate-x-[22px] bg-[var(--md-on-primary)] text-[var(--md-primary)] group-active:w-5'
            : 'h-3.5 w-3.5 translate-x-[3px] bg-[var(--md-outline)] text-[var(--md-surface-container-highest)] group-hover:bg-[var(--md-on-surface-variant)] group-active:w-4'
        }`}
      >
        {checked ? (
          <Check className="h-2.5 w-2.5 stroke-[3]" />
        ) : (
          <X className="h-2 w-2 stroke-[2.5] opacity-75" />
        )}
      </span>
    </button>
  );
}

export function M3SurfaceCard({
  level = 'default',
  className = '',
  children,
}: {
  level?: 'lowest' | 'low' | 'default' | 'high';
  className?: string;
  children: ReactNode;
}) {
  const bg = {
    lowest: 'bg-[var(--md-surface-container-lowest)]',
    low: 'bg-[var(--md-surface-container-low)]',
    default: 'bg-[var(--md-surface-container)]',
    high: 'bg-[var(--md-surface-container-high)]',
  }[level];

  return (
    <div
      className={`rounded-2xl border border-[var(--md-outline-variant)] transition-colors duration-150 ${bg} ${className}`}
    >
      {children}
    </div>
  );
}

export function M3StatusBadge({
  tone = 'neutral',
  dot = true,
  children,
  className = '',
}: {
  tone?: 'neutral' | 'success' | 'primary' | 'warning' | 'error';
  dot?: boolean;
  children: ReactNode;
  className?: string;
}) {
  const styles = {
    neutral: 'bg-[var(--md-surface-container-high)] text-[var(--md-on-surface-variant)]',
    success: 'bg-[var(--md-success-container)] text-[var(--md-success)]',
    primary: 'bg-[var(--md-primary-container)] text-[var(--md-on-primary-container)]',
    warning: 'bg-[var(--md-warning-container)] text-[var(--md-warning)]',
    error: 'bg-[var(--md-error-container)] text-[var(--md-error)]',
  }[tone];

  const dotBg = {
    neutral: 'bg-[var(--md-on-surface-variant)]',
    success: 'bg-[var(--md-success)]',
    primary: 'bg-[var(--md-primary)]',
    warning: 'bg-[var(--md-warning)]',
    error: 'bg-[var(--md-error)]',
  }[tone];

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[0.6875rem] font-medium ${styles} ${className}`}
    >
      {dot && <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${dotBg}`} />}
      <span className="inline-flex items-center gap-1.5">{children}</span>
    </span>
  );
}

export function M3SearchBar({
  value,
  onChange,
  placeholder = 'Поиск...',
  ariaLabel,
  className = '',
}: {
  value: string;
  onChange: (val: string) => void;
  placeholder?: string;
  ariaLabel?: string;
  className?: string;
}) {
  return (
    <div className={`relative ${className}`}>
      <Search className="pointer-events-none absolute top-1/2 left-3 h-3.5 w-3.5 -translate-y-1/2 text-[var(--md-on-surface-variant)]" />
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        aria-label={ariaLabel ?? placeholder}
        className="h-8.5 w-full rounded-2xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] pr-8 pl-8.5 text-[0.78rem] text-[var(--md-on-surface)] placeholder:text-[var(--md-on-surface-variant)]/70 transition-colors duration-150 focus:border-[var(--md-primary)] focus:bg-[var(--md-surface-container)] focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-[var(--md-primary)]"
      />
      {value && (
        <button
          type="button"
          onClick={() => onChange('')}
          aria-label="Очистить поиск"
          className="absolute top-1/2 right-2 -translate-y-1/2 rounded-full p-1 text-[var(--md-on-surface-variant)] transition-colors hover:bg-[var(--md-surface-container-highest)] hover:text-[var(--md-on-surface)]"
        >
          <X className="h-3 w-3" />
        </button>
      )}
    </div>
  );
}

export function M3EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon: ReactNode;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex h-full flex-col items-center justify-center px-6 py-8 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-[var(--md-surface-container-high)] text-[var(--md-primary)]">
        {icon}
      </div>
      <div className="mt-3.5 font-display text-[0.9375rem] font-bold text-[var(--md-on-surface)]">
        {title}
      </div>
      <p className="mt-1 max-w-sm text-[0.75rem] leading-relaxed text-[var(--md-on-surface-variant)]">
        {description}
      </p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function M3Skeleton({ className = 'h-4 w-24' }: { className?: string }) {
  return (
    <div
      className={`animate-pulse rounded-lg bg-[var(--md-surface-container-high)] ${className}`}
    />
  );
}

export function M3ProgressBar({
  percent,
  tone = 'primary',
}: {
  percent: number;
  tone?: 'primary' | 'warning' | 'error';
}) {
  const clamped = Math.max(0, Math.min(100, percent));
  const fill =
    tone === 'error'
      ? 'bg-[var(--md-error)]'
      : tone === 'warning'
        ? 'bg-[var(--md-warning)]'
        : 'bg-[var(--md-primary)]';

  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-[var(--md-surface-container-highest)]">
      <div
        className={`h-full rounded-full transition-all duration-300 ${fill} ${
          clamped > 0 && clamped < 100 ? 'min-w-[6px]' : ''
        }`}
        style={{ width: `${clamped}%` }}
      />
    </div>
  );
}

export function M3ListItem({
  title,
  description,
  leading,
  trailing,
  onClick,
  className = '',
}: {
  title: string;
  description?: string;
  leading?: ReactNode;
  trailing?: ReactNode;
  onClick?: () => void;
  className?: string;
}) {
  return (
    <div
      onClick={onClick}
      className={`flex items-center justify-between gap-3 py-2.5 ${
        onClick ? 'cursor-pointer' : ''
      } ${className}`}
    >
      <div className="flex min-w-0 items-center gap-3">
        {leading && <div className="shrink-0">{leading}</div>}
        <div className="min-w-0">
          <div className="text-[0.8125rem] font-medium text-[var(--md-on-surface)]">{title}</div>
          {description && (
            <div className="mt-0.5 text-[0.72rem] leading-snug text-[var(--md-on-surface-variant)]">
              {description}
            </div>
          )}
        </div>
      </div>
      {trailing && <div className="shrink-0">{trailing}</div>}
    </div>
  );
}

export function M3Dialog({
  open,
  onClose,
  title,
  description,
  children,
  footer,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
}) {
  const titleId = useId();
  const descId = useId();

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        onClose();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.15 }}
          onClick={onClose}
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4 backdrop-blur-xs"
        >
          <motion.div
            role="dialog"
            aria-modal="true"
            aria-labelledby={titleId}
            aria-describedby={description ? descId : undefined}
            initial={{ opacity: 0, scale: 0.96, y: 8 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.96, y: 8 }}
            transition={{ duration: 0.18, ease: 'easeOut' }}
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-[460px] rounded-3xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-high)] p-5 shadow-2xl"
          >
            <h3 id={titleId} className="font-display text-[0.97rem] font-bold text-[var(--md-on-surface)]">
              {title}
            </h3>
            {description && (
              <p id={descId} className="mt-1 text-[0.75rem] text-[var(--md-on-surface-variant)]">
                {description}
              </p>
            )}
            <div className="mt-3.5">{children}</div>
            {footer && <div className="mt-4 flex flex-wrap justify-end gap-2">{footer}</div>}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

export function M3DropdownMenu({
  trigger,
  items,
  align = 'right',
}: {
  trigger: ReactNode;
  items: Array<{
    id: string;
    label: string;
    icon?: ReactNode;
    danger?: boolean;
    onClick: () => void;
  }>;
  align?: 'left' | 'right';
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    window.addEventListener('mousedown', handler);
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('mousedown', handler);
      window.removeEventListener('keydown', onKey);
    };
  }, [open]);

  return (
    <div ref={ref} className="relative inline-flex">
      <button
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label="Открыть меню действий"
        onClick={() => setOpen((v) => !v)}
        className="inline-flex items-center justify-center rounded-lg"
      >
        {trigger}
      </button>
      <AnimatePresence>
        {open && (
          <motion.div
            role="menu"
            initial={{ opacity: 0, scale: 0.95, y: -4 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: -4 }}
            transition={{ duration: 0.14 }}
            className={`absolute top-full z-40 mt-1 min-w-[176px] rounded-2xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-highest)] p-1 shadow-xl ${
              align === 'right' ? 'right-0' : 'left-0'
            }`}
          >
            {items.map((item) => (
              <button
                key={item.id}
                role="menuitem"
                type="button"
                onClick={() => {
                  setOpen(false);
                  item.onClick();
                }}
                className={`flex w-full items-center gap-2 rounded-xl px-2.5 py-1.5 text-left text-[0.75rem] font-medium transition-colors ${
                  item.danger
                    ? 'text-[var(--md-error)] hover:bg-[var(--md-error-container)]'
                    : 'text-[var(--md-on-surface)] hover:bg-[var(--md-surface-container)]'
                }`}
              >
                {item.icon}
                <span>{item.label}</span>
              </button>
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
