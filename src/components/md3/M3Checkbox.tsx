import { Check, Minus } from 'lucide-react';

export interface M3CheckboxProps {
  checked: boolean;
  indeterminate?: boolean;
  onChange: (next: boolean) => void;
  disabled?: boolean;
  label?: string;
  ariaLabel?: string;
  size?: 'sm' | 'md';
  className?: string;
}

export function M3Checkbox({
  checked,
  indeterminate = false,
  onChange,
  disabled = false,
  label,
  ariaLabel,
  size = 'md',
  className = '',
}: M3CheckboxProps) {
  const active = checked || indeterminate;
  const boxSize = size === 'sm' ? 'h-4 w-4 rounded-[4px]' : 'h-4.5 w-4.5 rounded-[5px]';

  return (
    <button
      type="button"
      role="checkbox"
      aria-checked={indeterminate ? 'mixed' : checked}
      aria-label={ariaLabel ?? label ?? 'Выбрать'}
      disabled={disabled}
      onClick={(e) => {
        e.stopPropagation();
        if (!disabled) onChange(!checked);
      }}
      className={`group inline-flex items-center gap-2 text-left disabled:pointer-events-none disabled:opacity-45 ${className}`}
    >
      <span className="relative flex items-center justify-center p-1">
        <span className="pointer-events-none absolute inset-0 rounded-full bg-[var(--md-primary)]/12 opacity-0 transition-opacity duration-150 group-hover:opacity-100" />
        <span
          className={`relative flex items-center justify-center border-2 transition-all duration-150 ${boxSize} ${
            active
              ? 'border-[var(--md-primary)] bg-[var(--md-primary)] text-[var(--md-on-primary)]'
              : 'border-[var(--md-outline)] bg-transparent group-hover:border-[var(--md-on-surface)]'
          }`}
        >
          {indeterminate ? (
            <Minus className="h-3 w-3 stroke-[3]" />
          ) : checked ? (
            <Check className="h-3 w-3 stroke-[3]" />
          ) : null}
        </span>
      </span>
      {label && (
        <span className="text-[0.75rem] font-medium text-[var(--md-on-surface)]">{label}</span>
      )}
    </button>
  );
}
