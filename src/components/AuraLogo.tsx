import { useId } from 'react';

interface AuraLogoProps {
  variant?: 'mark' | 'monochrome' | 'horizontal';
  className?: string;
}

export function AuraLogo({ variant = 'mark', className = 'h-6 w-6' }: AuraLogoProps) {
  const uid = useId().replace(/:/g, '');

  if (variant === 'monochrome') {
    return (
      <svg viewBox="0 0 512 512" fill="none" className={className} aria-hidden="true">
        <path
          d="M 130.6 376.2 A 166.4 166.4 0 1 1 381.4 376.2"
          stroke="currentColor"
          strokeWidth="27"
          strokeLinecap="round"
          opacity="0.85"
        />
        <path
          d="M 171.5 361 L 256 166.4 L 340.5 361"
          stroke="currentColor"
          strokeWidth="40"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <circle cx="256" cy="309.8" r="25" fill="currentColor" />
      </svg>
    );
  }

  const mark = (
    <svg viewBox="0 0 512 512" fill="none" className={className} aria-hidden="true">
      <defs>
        <linearGradient
          id={`aura-bg-${uid}`}
          x1="56"
          y1="40"
          x2="456"
          y2="472"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0%" stopColor="#1E1B4B" />
          <stop offset="48%" stopColor="#3730A3" />
          <stop offset="100%" stopColor="#0E7490" />
        </linearGradient>
        <linearGradient
          id={`aura-arc-${uid}`}
          x1="108"
          y1="98"
          x2="404"
          y2="404"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0%" stopColor="#C7D2FE" />
          <stop offset="55%" stopColor="#818CF8" />
          <stop offset="100%" stopColor="#67E8F9" />
        </linearGradient>
      </defs>
      <rect x="28" y="28" width="456" height="456" rx="112" fill={`url(#aura-bg-${uid})`} />
      <rect
        x="33"
        y="33"
        width="446"
        height="446"
        rx="108"
        stroke="#FFFFFF"
        strokeOpacity="0.16"
        strokeWidth="3"
      />
      <path
        d="M 130.6 376.2 A 166.4 166.4 0 1 1 381.4 376.2"
        stroke={`url(#aura-arc-${uid})`}
        strokeWidth="25"
        strokeLinecap="round"
      />
      <path
        d="M 171.5 361 L 256 166.4 L 340.5 361"
        stroke="#FFFFFF"
        strokeWidth="37"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="256" cy="309.8" r="24" fill="#67E8F9" />
    </svg>
  );

  if (variant === 'horizontal') {
    return (
      <div className="inline-flex items-center gap-2.5">
        {mark}
        <div className="leading-none">
          <div className="font-display text-sm font-extrabold tracking-tight text-[var(--md-on-surface)]">
            AURA <span className="font-semibold text-[var(--md-primary)]">VPN</span>
          </div>
          <div className="mt-0.5 text-[0.65rem] font-medium text-[var(--md-on-surface-variant)]">
            Xray-core • AmneziaWG • Wintun
          </div>
        </div>
      </div>
    );
  }

  return mark;
}
