import { Check, ChevronDown, Search } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';

export interface M3SelectOption<T extends string> {
  value: T;
  label: string;
  description?: string;
  icon?: ReactNode;
  badge?: string | number;
  disabled?: boolean;
}

export interface M3SelectProps<T extends string> {
  value: T;
  onChange: (next: T) => void;
  options: Array<M3SelectOption<T>>;
  placeholder?: string;
  size?: 'sm' | 'md';
  searchable?: boolean;
  searchPlaceholder?: string;
  align?: 'left' | 'right';
  ariaLabel?: string;
  disabled?: boolean;
  className?: string;
}

export function M3Select<T extends string>({
  value,
  onChange,
  options,
  placeholder = 'Выберите...',
  size = 'md',
  searchable = false,
  searchPlaceholder = 'Поиск...',
  align = 'left',
  ariaLabel,
  disabled = false,
  className = '',
}: M3SelectProps<T>) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [highlightedIdx, setHighlightedIdx] = useState(0);
  const [menuPos, setMenuPos] = useState<{ top: number; left: number; minWidth: number; maxHeight: number }>({
    top: 0,
    left: 0,
    minWidth: 180,
    maxHeight: 260,
  });

  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);

  const selectedOption = useMemo(
    () => options.find((opt) => opt.value === value) ?? null,
    [options, value],
  );

  const filteredOptions = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return options;
    return options.filter(
      (opt) =>
        opt.label.toLowerCase().includes(q) ||
        opt.value.toLowerCase().includes(q) ||
        (opt.description?.toLowerCase().includes(q) ?? false),
    );
  }, [options, query]);

  const computeMenuPosition = useCallback(() => {
    const el = triggerRef.current;
    if (!el || typeof window === 'undefined') return;
    const rect = el.getBoundingClientRect();
    const minW = Math.max(rect.width, searchable ? 236 : 176);
    const spaceBelow = window.innerHeight - rect.bottom - 12;
    const spaceAbove = rect.top - 12;
    const openUp = spaceBelow < 180 && spaceAbove > spaceBelow;
    const maxHeight = Math.min(280, Math.max(140, openUp ? spaceAbove : spaceBelow));

    const left =
      align === 'right'
        ? Math.max(8, Math.min(window.innerWidth - minW - 8, rect.right - minW))
        : Math.max(8, Math.min(window.innerWidth - minW - 8, rect.left));
    const top = openUp
      ? Math.max(8, rect.top - Math.min(maxHeight, options.length * 36 + (searchable ? 52 : 16)) - 6)
      : rect.bottom + 6;

    setMenuPos({ top, left, minWidth: minW, maxHeight });
  }, [align, options.length, searchable]);

  useEffect(() => {
    if (!open) {
      setQuery('');
      return;
    }
    computeMenuPosition();
    const selectedIdx = filteredOptions.findIndex((o) => o.value === value && !o.disabled);
    setHighlightedIdx(selectedIdx >= 0 ? selectedIdx : 0);
    if (searchable) {
      window.setTimeout(() => searchRef.current?.focus(), 20);
    }

    const onOutside = (e: MouseEvent) => {
      const target = e.target as Node;
      if (
        triggerRef.current &&
        !triggerRef.current.contains(target) &&
        menuRef.current &&
        !menuRef.current.contains(target)
      ) {
        setOpen(false);
      }
    };
    const onResizeOrScroll = (e: Event) => {
      if (menuRef.current && e.target instanceof Node && menuRef.current.contains(e.target)) {
        return;
      }
      computeMenuPosition();
    };
    window.addEventListener('mousedown', onOutside);
    window.addEventListener('resize', onResizeOrScroll);
    window.addEventListener('scroll', onResizeOrScroll, true);
    return () => {
      window.removeEventListener('mousedown', onOutside);
      window.removeEventListener('resize', onResizeOrScroll);
      window.removeEventListener('scroll', onResizeOrScroll, true);
    };
  }, [open, computeMenuPosition, filteredOptions, searchable, value]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (disabled) return;
    if (!open) {
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp' || e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        setOpen(true);
      }
      return;
    }
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      setOpen(false);
      triggerRef.current?.focus();
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      setHighlightedIdx((prev) =>
        filteredOptions.length > 0 ? (prev + 1) % filteredOptions.length : 0,
      );
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setHighlightedIdx((prev) =>
        filteredOptions.length > 0
          ? (prev - 1 + filteredOptions.length) % filteredOptions.length
          : 0,
      );
    } else if (e.key === 'Home') {
      e.preventDefault();
      setHighlightedIdx(0);
    } else if (e.key === 'End') {
      e.preventDefault();
      setHighlightedIdx(Math.max(0, filteredOptions.length - 1));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const target = filteredOptions[highlightedIdx];
      if (target && !target.disabled) {
        onChange(target.value);
        setOpen(false);
        triggerRef.current?.focus();
      }
    }
  };

  const heightClass = size === 'sm' ? 'h-8 rounded-xl px-2.5 text-[0.72rem]' : 'h-8.5 rounded-2xl px-3 text-[0.75rem]';

  return (
    <>
      <button
        ref={triggerRef}
        type="button"
        role="combobox"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={ariaLabel ?? placeholder}
        disabled={disabled}
        onKeyDown={handleKeyDown}
        onClick={() => !disabled && setOpen((v) => !v)}
        className={`inline-flex items-center justify-between gap-2 border transition-colors disabled:pointer-events-none disabled:opacity-45 ${heightClass} ${
          open
            ? 'border-[var(--md-primary)] bg-[var(--md-surface-container)] text-[var(--md-on-surface)]'
            : 'border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] text-[var(--md-on-surface)] hover:border-[var(--md-outline)] hover:bg-[var(--md-surface-container)]'
        } ${className}`}
      >
        <span className="flex min-w-0 items-center gap-2 truncate font-medium">
          {selectedOption?.icon && <span className="shrink-0">{selectedOption.icon}</span>}
          <span className="truncate">{selectedOption ? selectedOption.label : placeholder}</span>
        </span>
        <ChevronDown
          className={`h-3.5 w-3.5 shrink-0 text-[var(--md-on-surface-variant)] transition-transform duration-150 ${
            open ? 'rotate-180 text-[var(--md-primary)]' : ''
          }`}
        />
      </button>

      {open &&
        typeof document !== 'undefined' &&
        createPortal(
          <div
            ref={menuRef}
            role="listbox"
            aria-label={ariaLabel ?? placeholder}
            onKeyDown={handleKeyDown}
            style={{
              top: menuPos.top,
              left: menuPos.left,
              minWidth: menuPos.minWidth,
              maxHeight: menuPos.maxHeight,
            }}
            className="aura-scroll fixed z-[75] overflow-y-auto rounded-2xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-highest)] p-1.5 shadow-2xl"
          >
            {searchable && (
              <div className="sticky top-0 z-10 mb-1.5 bg-[var(--md-surface-container-highest)] pb-1">
                <div className="relative">
                  <Search className="pointer-events-none absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-[var(--md-on-surface-variant)]" />
                  <input
                    ref={searchRef}
                    type="text"
                    value={query}
                    onChange={(e) => {
                      setQuery(e.target.value);
                      setHighlightedIdx(0);
                    }}
                    placeholder={searchPlaceholder}
                    className="h-7.5 w-full rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] pr-2.5 pl-7.5 text-[0.75rem] text-[var(--md-on-surface)] placeholder:text-[var(--md-on-surface-variant)]/70 focus:border-[var(--md-primary)] focus:outline-none"
                  />
                </div>
              </div>
            )}

            {filteredOptions.length === 0 ? (
              <div className="py-3 text-center text-[0.72rem] text-[var(--md-on-surface-variant)]">
                Ничего не найдено
              </div>
            ) : (
              filteredOptions.map((opt, idx) => {
                const isSelected = opt.value === value;
                const isHi = idx === highlightedIdx;
                return (
                  <button
                    key={opt.value}
                    type="button"
                    role="option"
                    aria-selected={isSelected}
                    disabled={opt.disabled}
                    onMouseEnter={() => setHighlightedIdx(idx)}
                    onClick={() => {
                      if (opt.disabled) return;
                      onChange(opt.value);
                      setOpen(false);
                      triggerRef.current?.focus();
                    }}
                    className={`flex w-full items-center justify-between gap-2.5 rounded-xl px-2.5 py-1.5 text-left text-[0.75rem] transition-colors disabled:opacity-45 ${
                      isSelected
                        ? 'bg-[var(--md-secondary-container)] font-semibold text-[var(--md-on-secondary-container)]'
                        : isHi
                          ? 'bg-[var(--md-surface-container)] text-[var(--md-on-surface)]'
                          : 'text-[var(--md-on-surface)] hover:bg-[var(--md-surface-container)]'
                    }`}
                  >
                    <span className="flex min-w-0 items-center gap-2">
                      {opt.icon && <span className="shrink-0">{opt.icon}</span>}
                      <span className="min-w-0">
                        <span className="block truncate">{opt.label}</span>
                        {opt.description && (
                          <span className="block truncate text-[0.65rem] font-normal text-[var(--md-on-surface-variant)]">
                            {opt.description}
                          </span>
                        )}
                      </span>
                    </span>
                    <span className="flex shrink-0 items-center gap-1.5">
                      {opt.badge !== undefined && (
                        <span className="rounded-full bg-[var(--md-surface-container-low)] px-1.5 py-0.5 text-[0.65rem] text-[var(--md-on-surface-variant)] font-mono-num">
                          {opt.badge}
                        </span>
                      )}
                      {isSelected && <Check className="h-3.5 w-3.5 text-[var(--md-primary)]" />}
                    </span>
                  </button>
                );
              })
            )}
          </div>,
          document.body,
        )}
    </>
  );
}
