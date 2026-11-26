import { useState } from 'react';

export interface M3SliderProps {
  min: number;
  max: number;
  step?: number;
  value: number;
  onChange: (val: number) => void;
  onCommit?: (val: number) => void;
  formatValue?: (val: number) => string;
  showValueBubble?: boolean;
  showTicks?: boolean;
  disabled?: boolean;
  ariaLabel?: string;
  id?: string;
  className?: string;
}

export function M3Slider({
  min,
  max,
  step = 1,
  value,
  onChange,
  onCommit,
  formatValue,
  showValueBubble = true,
  showTicks = false,
  disabled = false,
  ariaLabel,
  id,
  className = '',
}: M3SliderProps) {
  const [dragging, setDragging] = useState(false);
  const [focused, setFocused] = useState(false);

  const clampedValue = Number.isFinite(value) ? Math.min(max, Math.max(min, value)) : min;
  const span = max - min;
  const progress = span > 0 ? Math.min(100, Math.max(0, ((clampedValue - min) / span) * 100)) : 0;
  const bubbleLeft = Math.min(92, Math.max(8, progress));
  const showBubble = showValueBubble && !disabled && (dragging || focused);
  const formatted = formatValue ? formatValue(clampedValue) : String(clampedValue);

  const stepCount = step > 0 && span > 0 ? Math.round(span / step) : 0;
  const tickStops =
    showTicks && stepCount >= 2 && stepCount <= 16
      ? Array.from({ length: stepCount + 1 }, (_, idx) => (idx / stepCount) * 100)
      : [];

  return (
    <div
      className={`group relative flex h-8 w-full items-center select-none ${
        disabled ? 'opacity-45' : ''
      } ${className}`}
    >
      {/* Value indicator bubble */}
      {showBubble && (
        <div
          data-testid="m3-slider-bubble"
          style={{ left: `${bubbleLeft}%` }}
          className="pointer-events-none absolute bottom-full z-30 mb-1.5 -translate-x-1/2 rounded-full bg-[var(--md-inverse-surface)] px-2.5 py-0.5 text-[0.6875rem] font-semibold whitespace-nowrap text-[var(--md-inverse-on-surface)] shadow-md font-mono-num"
        >
          {formatted}
        </div>
      )}

      {/* Visual track */}
      <div className="pointer-events-none relative h-1.5 w-full rounded-full bg-[var(--md-secondary-container)]">
        <div
          data-testid="m3-slider-fill"
          data-progress={progress.toFixed(2)}
          style={{ width: `${progress}%` }}
          className="h-full rounded-full bg-[var(--md-primary)] transition-[background-color] duration-150"
        />

        {tickStops.map((pct) => {
          const activeTick = pct <= progress + 0.01;
          return (
            <span
              key={pct}
              style={{ left: `${pct}%` }}
              className={`absolute top-1/2 h-1 w-1 -translate-x-1/2 -translate-y-1/2 rounded-full ${
                activeTick
                  ? 'bg-[var(--md-on-primary)]/70'
                  : 'bg-[var(--md-on-surface-variant)]/45'
              }`}
            />
          );
        })}
      </div>

      {/* Native accessible range input on top */}
      <input
        id={id}
        type="range"
        min={min}
        max={max}
        step={step}
        value={clampedValue}
        disabled={disabled}
        aria-label={ariaLabel}
        onChange={(e) => onChange(Number(e.target.value))}
        onPointerDown={() => !disabled && setDragging(true)}
        onPointerUp={(e) => {
          if (dragging) {
            setDragging(false);
            onCommit?.(Number(e.currentTarget.value));
          }
        }}
        onPointerCancel={() => setDragging(false)}
        onFocus={() => setFocused(true)}
        onBlur={(e) => {
          setFocused(false);
          if (dragging) {
            setDragging(false);
            onCommit?.(Number(e.currentTarget.value));
          }
        }}
        onKeyUp={(e) => {
          if (
            ['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End', 'PageUp', 'PageDown'].includes(
              e.key,
            )
          ) {
            onCommit?.(Number(e.currentTarget.value));
          }
        }}
        className="peer absolute inset-0 z-20 m-0 h-full w-full cursor-pointer opacity-0 disabled:cursor-not-allowed"
      />

      {/* Thumb + Expressive state halo + Focus ring */}
      <div
        aria-hidden="true"
        style={{ left: `${progress}%` }}
        className="pointer-events-none absolute top-1/2 z-10 -translate-x-1/2 -translate-y-1/2 flex items-center justify-center"
      >
        <span
          className={`absolute h-7 w-7 rounded-full bg-[var(--md-primary)]/16 transition-transform duration-150 ${
            dragging || focused
              ? 'scale-100'
              : 'scale-0 group-hover:scale-100'
          }`}
        />
        <span
          className={`block rounded-full bg-[var(--md-primary)] ring-2 ring-[var(--md-surface-container)] shadow-sm transition-[width,height,box-shadow,transform] duration-150 peer-focus-visible:ring-2 ${
            dragging
              ? 'h-5 w-3.5 scale-105 shadow-md'
              : 'h-4.5 w-4.5 group-hover:scale-105'
          } ${
            focused
              ? 'outline-2 outline-offset-2 outline-[var(--md-primary)]'
              : ''
          }`}
        />
      </div>
    </div>
  );
}
