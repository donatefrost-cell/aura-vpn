import { Globe } from 'lucide-react';
import type { ReactNode } from 'react';
import { getCountryName } from '../utils/format';

type FlagSize = 'sm' | 'md' | 'lg';

const SIZE_CLASSES: Record<FlagSize, string> = {
  sm: 'h-3.5 w-[19px] rounded-[3px]',
  md: 'h-[18px] w-6 rounded-[4px]',
  lg: 'h-[22px] w-[30px] rounded-[5px]',
};

const h3 = (top: string, mid: string, bot: string) => (
  <>
    <rect width="24" height="6" fill={top} />
    <rect y="6" width="24" height="6" fill={mid} />
    <rect y="12" width="24" height="6" fill={bot} />
  </>
);

const v3 = (left: string, mid: string, right: string) => (
  <>
    <rect width="8" height="18" fill={left} />
    <rect x="8" width="8" height="18" fill={mid} />
    <rect x="16" width="8" height="18" fill={right} />
  </>
);

const h2 = (top: string, bot: string) => (
  <>
    <rect width="24" height="9" fill={top} />
    <rect y="9" width="24" height="9" fill={bot} />
  </>
);

const nordic = (bg: string, cross: string, inner?: string) => (
  <>
    <rect width="24" height="18" fill={bg} />
    <rect x="7" width="4" height="18" fill={cross} />
    <rect y="7" width="24" height="4" fill={cross} />
    {inner && (
      <>
        <rect x="8" width="2" height="18" fill={inner} />
        <rect y="8" width="24" height="2" fill={inner} />
      </>
    )}
  </>
);

function renderFlagSvg(code: string): ReactNode | null {
  switch (code) {
    case 'EU':
      return (
        <>
          <rect width="24" height="18" fill="#003399" />
          {[0, 30, 60, 90, 120, 150, 180, 210, 240, 270, 300, 330].map((deg) => {
            const rad = (deg * Math.PI) / 180;
            const cx = 12 + Math.cos(rad) * 5.2;
            const cy = 9 + Math.sin(rad) * 5.2;
            return <circle key={deg} cx={cx} cy={cy} r="0.85" fill="#FFCC00" />;
          })}
        </>
      );
    case 'NL':
      return h3('#AE1C28', '#FFFFFF', '#21468B');
    case 'DE':
      return h3('#111111', '#DD0000', '#FFCE00');
    case 'RU':
      return h3('#FFFFFF', '#0039A6', '#D52B1E');
    case 'LU':
      return h3('#EA141D', '#FFFFFF', '#51ADDA');
    case 'AT':
      return h3('#ED2939', '#FFFFFF', '#ED2939');
    case 'HU':
      return h3('#CE2939', '#FFFFFF', '#477050');
    case 'BG':
      return h3('#FFFFFF', '#00966E', '#D62612');
    case 'EE':
      return h3('#0072CE', '#111111', '#FFFFFF');
    case 'LT':
      return h3('#FDB913', '#006A44', '#C1272D');
    case 'AM':
      return h3('#D90012', '#0033A0', '#F2A800');
    case 'AR':
      return (
        <>
          {h3('#74ACDF', '#FFFFFF', '#74ACDF')}
          <circle cx="12" cy="9" r="1.8" fill="#F6B40E" />
        </>
      );
    case 'LV':
      return (
        <>
          <rect width="24" height="7" fill="#9E3039" />
          <rect y="7" width="24" height="4" fill="#FFFFFF" />
          <rect y="11" width="24" height="7" fill="#9E3039" />
        </>
      );
    case 'UA':
      return h2('#005BBB', '#FFD500');
    case 'PL':
      return h2('#FFFFFF', '#DC143C');
    case 'ID':
      return h2('#CE1126', '#FFFFFF');
    case 'FR':
      return v3('#002395', '#FFFFFF', '#ED2939');
    case 'IT':
      return v3('#009246', '#FFFFFF', '#CE2B37');
    case 'BE':
      return v3('#111111', '#FAE042', '#ED2939');
    case 'IE':
      return v3('#169B62', '#FFFFFF', '#FF883E');
    case 'RO':
      return v3('#002B7F', '#FCD116', '#CE1126');
    case 'MX':
      return (
        <>
          {v3('#006847', '#FFFFFF', '#CE1126')}
          <circle cx="12" cy="9" r="1.7" fill="#8B5E34" />
        </>
      );
    case 'CA':
      return (
        <>
          <rect width="5.5" height="18" fill="#D80621" />
          <rect x="5.5" width="13" height="18" fill="#FFFFFF" />
          <rect x="18.5" width="5.5" height="18" fill="#D80621" />
          <path
            d="M12 4.2 L13.1 7.2 L15.5 6.8 L14.1 9.2 L15.7 10.6 L12.7 11.4 L12.5 13.8 L11.5 13.8 L11.3 11.4 L8.3 10.6 L9.9 9.2 L8.5 6.8 L10.9 7.2 Z"
            fill="#D80621"
          />
        </>
      );
    case 'FI':
      return nordic('#FFFFFF', '#003580');
    case 'SE':
      return nordic('#006AA7', '#FECC00');
    case 'DK':
      return nordic('#C60C30', '#FFFFFF');
    case 'NO':
      return nordic('#BA0C2F', '#FFFFFF', '#00205B');
    case 'IS':
      return nordic('#02529C', '#FFFFFF', '#DC1E35');
    case 'CH':
      return (
        <>
          <rect width="24" height="18" fill="#D52B1E" />
          <rect x="10.2" y="4" width="3.6" height="10" fill="#FFFFFF" />
          <rect x="7" y="7.2" width="10" height="3.6" fill="#FFFFFF" />
        </>
      );
    case 'US':
      return (
        <>
          <rect width="24" height="18" fill="#FFFFFF" />
          {[0, 2.57, 5.14, 7.71, 10.28, 12.85, 15.42].map((y, idx) => (
            <rect key={idx} y={y} width="24" height="1.35" fill="#B22234" />
          ))}
          <rect width="10.5" height="9.2" fill="#3C3B6E" />
          {[2.2, 5.2, 8.2].map((x) =>
            [2.3, 4.7, 7.1].map((y) => (
              <circle key={`${x}-${y}`} cx={x} cy={y} r="0.65" fill="#FFFFFF" />
            )),
          )}
        </>
      );
    case 'GB':
      return (
        <>
          <rect width="24" height="18" fill="#012169" />
          <path d="M0 0 L24 18 M24 0 L0 18" stroke="#FFFFFF" strokeWidth="3.2" />
          <path d="M0 0 L24 18 M24 0 L0 18" stroke="#C8102E" strokeWidth="1.5" />
          <rect x="9.5" width="5" height="18" fill="#FFFFFF" />
          <rect y="6.5" width="24" height="5" fill="#FFFFFF" />
          <rect x="10.5" width="3" height="18" fill="#C8102E" />
          <rect y="7.5" width="24" height="3" fill="#C8102E" />
        </>
      );
    case 'AU':
      return (
        <>
          <rect width="24" height="18" fill="#00008B" />
          <rect width="11" height="8" fill="#012169" />
          <path d="M0 0 L11 8 M11 0 L0 8" stroke="#FFFFFF" strokeWidth="1.4" />
          <rect x="4.5" width="2" height="8" fill="#FFFFFF" />
          <rect y="3" width="11" height="2" fill="#FFFFFF" />
          <rect x="5" width="1" height="8" fill="#C8102E" />
          <rect y="3.5" width="11" height="1" fill="#C8102E" />
          <circle cx="5.5" cy="13.2" r="1.4" fill="#FFFFFF" />
          <circle cx="17.5" cy="4.5" r="0.9" fill="#FFFFFF" />
          <circle cx="20.2" cy="8.5" r="0.9" fill="#FFFFFF" />
          <circle cx="17.5" cy="13.5" r="0.9" fill="#FFFFFF" />
          <circle cx="14.5" cy="9" r="0.9" fill="#FFFFFF" />
        </>
      );
    case 'ES':
      return (
        <>
          <rect width="24" height="4.5" fill="#AA151B" />
          <rect y="4.5" width="24" height="9" fill="#F1BF00" />
          <rect y="13.5" width="24" height="4.5" fill="#AA151B" />
          <rect x="5.5" y="6.8" width="2.4" height="4.2" rx="0.6" fill="#AA151B" />
        </>
      );
    case 'PT':
      return (
        <>
          <rect width="9" height="18" fill="#006600" />
          <rect x="9" width="15" height="18" fill="#FF0000" />
          <circle cx="9" cy="9" r="2.8" fill="#FFCC00" />
          <rect x="7.8" y="7.7" width="2.4" height="2.6" fill="#FFFFFF" />
        </>
      );
    case 'CZ':
      return (
        <>
          <rect width="24" height="9" fill="#FFFFFF" />
          <rect y="9" width="24" height="9" fill="#D7141A" />
          <polygon points="0,0 11.5,9 0,18" fill="#11457E" />
        </>
      );
    case 'TR':
      return (
        <>
          <rect width="24" height="18" fill="#E30A17" />
          <circle cx="9.6" cy="9" r="4" fill="#FFFFFF" />
          <circle cx="10.8" cy="9" r="3.2" fill="#E30A17" />
          <circle cx="14.6" cy="9" r="1.1" fill="#FFFFFF" />
        </>
      );
    case 'SG':
      return (
        <>
          {h2('#EF3340', '#FFFFFF')}
          <circle cx="5.2" cy="4.5" r="2.7" fill="#FFFFFF" />
          <circle cx="6.2" cy="4.5" r="2.2" fill="#EF3340" />
          <circle cx="7.4" cy="3.1" r="0.45" fill="#FFFFFF" />
          <circle cx="8.8" cy="4.1" r="0.45" fill="#FFFFFF" />
          <circle cx="8.3" cy="5.8" r="0.45" fill="#FFFFFF" />
          <circle cx="6.6" cy="5.8" r="0.45" fill="#FFFFFF" />
        </>
      );
    case 'JP':
      return (
        <>
          <rect width="24" height="18" fill="#FFFFFF" />
          <circle cx="12" cy="9" r="4.6" fill="#BC002D" />
        </>
      );
    case 'HK':
      return (
        <>
          <rect width="24" height="18" fill="#DE2910" />
          <circle cx="12" cy="6.6" r="1.5" fill="#FFFFFF" />
          <circle cx="14.4" cy="8.4" r="1.5" fill="#FFFFFF" />
          <circle cx="13.5" cy="11.1" r="1.5" fill="#FFFFFF" />
          <circle cx="10.5" cy="11.1" r="1.5" fill="#FFFFFF" />
          <circle cx="9.6" cy="8.4" r="1.5" fill="#FFFFFF" />
          <circle cx="12" cy="9" r="1.1" fill="#DE2910" />
        </>
      );
    case 'KR':
      return (
        <>
          <rect width="24" height="18" fill="#FFFFFF" />
          <circle cx="12" cy="9" r="3.8" fill="#CD2E3A" />
          <path d="M8.2 9 A3.8 3.8 0 0 0 15.8 9 A1.9 1.9 0 0 1 12 9 A1.9 1.9 0 0 0 8.2 9 Z" fill="#0047A0" />
          <rect x="4" y="3.5" width="3" height="0.9" transform="rotate(-35 5.5 4)" fill="#111111" />
          <rect x="17" y="3.5" width="3" height="0.9" transform="rotate(35 18.5 4)" fill="#111111" />
          <rect x="4" y="13.5" width="3" height="0.9" transform="rotate(35 5.5 14)" fill="#111111" />
          <rect x="17" y="13.5" width="3" height="0.9" transform="rotate(-35 18.5 14)" fill="#111111" />
        </>
      );
    case 'KZ':
      return (
        <>
          <rect width="24" height="18" fill="#00AFCA" />
          <rect x="1.5" y="1.5" width="1.6" height="15" fill="#FEC50C" />
          <circle cx="13" cy="8.5" r="2.8" fill="#FEC50C" />
          <path d="M9.5 12.2 Q13 14 16.5 12.2" stroke="#FEC50C" strokeWidth="1.2" fill="none" />
        </>
      );
    case 'AE':
      return (
        <>
          <rect x="6.5" width="17.5" height="6" fill="#00732F" />
          <rect x="6.5" y="6" width="17.5" height="6" fill="#FFFFFF" />
          <rect x="6.5" y="12" width="17.5" height="6" fill="#111111" />
          <rect width="6.5" height="18" fill="#FF0000" />
        </>
      );
    case 'IN':
      return (
        <>
          {h3('#FF9933', '#FFFFFF', '#138808')}
          <circle cx="12" cy="9" r="2.1" fill="none" stroke="#000080" strokeWidth="0.8" />
          <circle cx="12" cy="9" r="0.6" fill="#000080" />
        </>
      );
    case 'BR':
      return (
        <>
          <rect width="24" height="18" fill="#009C3B" />
          <polygon points="12,2.5 21,9 12,15.5 3,9" fill="#FFDF00" />
          <circle cx="12" cy="9" r="3.2" fill="#002776" />
          <path d="M9 8.6 Q12 9.8 15 8.8" stroke="#FFFFFF" strokeWidth="0.7" fill="none" />
        </>
      );
    case 'GR':
      return (
        <>
          <rect width="24" height="18" fill="#0D5EAF" />
          {[2, 6, 10, 14].map((y) => (
            <rect key={y} y={y} width="24" height="2" fill="#FFFFFF" />
          ))}
          <rect width="10" height="10" fill="#0D5EAF" />
          <rect x="4" width="2" height="10" fill="#FFFFFF" />
          <rect y="4" width="10" height="2" fill="#FFFFFF" />
        </>
      );
    case 'SK':
      return (
        <>
          {h3('#FFFFFF', '#0B4EA2', '#EE1C25')}
          <rect x="5" y="5.5" width="4.5" height="6" rx="1.2" fill="#EE1C25" stroke="#FFFFFF" strokeWidth="0.6" />
          <rect x="6.9" y="6.5" width="0.7" height="3.8" fill="#FFFFFF" />
          <rect x="5.9" y="7.6" width="2.7" height="0.7" fill="#FFFFFF" />
        </>
      );
    case 'RS':
      return (
        <>
          {h3('#C6363C', '#0C4076', '#FFFFFF')}
          <rect x="5.5" y="5.5" width="3.8" height="5.5" rx="1" fill="#C6363C" stroke="#FFFFFF" strokeWidth="0.6" />
        </>
      );
    case 'MD':
      return (
        <>
          {v3('#0046AE', '#FFD200', '#CC092F')}
          <rect x="10.6" y="6.8" width="2.8" height="4.2" rx="0.5" fill="#7A4B1E" />
        </>
      );
    case 'GE':
      return (
        <>
          <rect width="24" height="18" fill="#FFFFFF" />
          <rect x="10" width="4" height="18" fill="#FF0000" />
          <rect y="7" width="24" height="4" fill="#FF0000" />
          {[
            [5, 3.5],
            [19, 3.5],
            [5, 14.5],
            [19, 14.5],
          ].map(([x, y], idx) => (
            <circle key={idx} cx={x} cy={y} r="1" fill="#FF0000" />
          ))}
        </>
      );
    case 'IL':
      return (
        <>
          <rect width="24" height="18" fill="#FFFFFF" />
          <rect y="2.2" width="24" height="2.4" fill="#0038B8" />
          <rect y="13.4" width="24" height="2.4" fill="#0038B8" />
          <polygon points="12,5.8 14.8,10.6 9.2,10.6" fill="none" stroke="#0038B8" strokeWidth="0.9" />
          <polygon points="12,12.2 14.8,7.4 9.2,7.4" fill="none" stroke="#0038B8" strokeWidth="0.9" />
        </>
      );
    case 'CY':
      return (
        <>
          <rect width="24" height="18" fill="#FFFFFF" />
          <ellipse cx="12" cy="8.5" rx="4.5" ry="2.6" fill="#D57800" />
          <path d="M8 13.5 Q12 15.2 16 13.5" stroke="#4E5B31" strokeWidth="1" fill="none" />
        </>
      );
    case 'TW':
      return (
        <>
          <rect width="24" height="18" fill="#FE0000" />
          <rect width="11.5" height="9" fill="#000095" />
          <circle cx="5.75" cy="4.5" r="2.2" fill="#FFFFFF" />
        </>
      );
    case 'BY':
      return (
        <>
          <rect width="24" height="12" fill="#D22730" />
          <rect y="12" width="24" height="6" fill="#00AF66" />
          <rect width="3.5" height="18" fill="#FFFFFF" />
        </>
      );
    case 'TH':
      return (
        <>
          <rect width="24" height="3" fill="#A51931" />
          <rect y="3" width="24" height="3" fill="#F4F5F8" />
          <rect y="6" width="24" height="6" fill="#2D2A4A" />
          <rect y="12" width="24" height="3" fill="#F4F5F8" />
          <rect y="15" width="24" height="3" fill="#A51931" />
        </>
      );
    case 'VN':
      return (
        <>
          <rect width="24" height="18" fill="#DA251D" />
          <polygon
            points="12,4 13.2,7.8 17.2,7.8 14,10.1 15.2,13.9 12,11.6 8.8,13.9 10,10.1 6.8,7.8 10.8,7.8"
            fill="#FFFF00"
          />
        </>
      );
    default:
      return null;
  }
}

export function CountryBadge({
  code,
  size = 'md',
  className = '',
  tooltip = false,
}: {
  code?: string | null;
  size?: FlagSize;
  className?: string;
  tooltip?: boolean;
}) {
  const upper = code?.trim().toUpperCase();
  const countryName = getCountryName(upper);
  const svgBody = upper ? renderFlagSvg(upper) : null;
  const label = countryName ? `${countryName} (${upper})` : upper || 'Глобальный узел';

  if (svgBody) {
    return (
      <span
        title={tooltip ? label : undefined}
        aria-label={label}
        className={`relative inline-flex shrink-0 overflow-hidden bg-[var(--md-surface-container-high)] shadow-xs ring-1 ring-inset ring-[var(--md-outline-variant)] ${SIZE_CLASSES[size]} ${className}`}
      >
        <svg viewBox="0 0 24 18" className="h-full w-full block" aria-hidden="true">
          {svgBody}
        </svg>
      </span>
    );
  }

  return (
    <span
      title={tooltip ? label : undefined}
      aria-label={label}
      className={`inline-flex shrink-0 items-center justify-center border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-high)] text-[var(--md-on-surface-variant)] ${SIZE_CLASSES[size]} ${className}`}
    >
      <Globe className={size === 'sm' ? 'h-2.5 w-2.5' : 'h-3.5 w-3.5'} />
    </span>
  );
}
