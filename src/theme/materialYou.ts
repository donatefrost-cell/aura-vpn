import type { AccentPreset, AppSettings } from '../types/vpn';

export const ACCENT_PRESET_META: Array<{
  id: AccentPreset;
  label: string;
  hex: string;
}> = [
  { id: 'windows', label: 'Системный Windows', hex: '#4F7CFF' },
  { id: 'indigo', label: 'Индиго', hex: '#5B6EF5' },
  { id: 'blue', label: 'Синий', hex: '#2E7CF6' },
  { id: 'purple', label: 'Фиолетовый', hex: '#865DFF' },
  { id: 'teal', label: 'Бирюзовый', hex: '#0D9488' },
  { id: 'green', label: 'Зелёный', hex: '#16A34A' },
  { id: 'custom', label: 'Свой цвет', hex: '#7C5CFF' },
];

interface Rgb {
  r: number;
  g: number;
  b: number;
}

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

export function normalizeHex(raw?: string | null, fallback = '#5B6EF5'): string {
  if (!raw) return fallback;
  const clean = raw.trim().replace(/^#/, '');
  if (/^[0-9a-fA-F]{6}$/.test(clean)) return `#${clean.toUpperCase()}`;
  return fallback;
}

function hexToRgb(hex: string): Rgb {
  const clean = normalizeHex(hex).slice(1);
  return {
    r: parseInt(clean.slice(0, 2), 16),
    g: parseInt(clean.slice(2, 4), 16),
    b: parseInt(clean.slice(4, 6), 16),
  };
}

function rgbToHex(r: number, g: number, b: number): string {
  return (
    '#' +
    [r, g, b]
      .map((v) => clamp(Math.round(v), 0, 255).toString(16).padStart(2, '0'))
      .join('')
      .toUpperCase()
  );
}

function rgbToHsl(r: number, g: number, b: number): { h: number; s: number; l: number } {
  const rn = r / 255;
  const gn = g / 255;
  const bn = b / 255;
  const max = Math.max(rn, gn, bn);
  const min = Math.min(rn, gn, bn);
  const l = (max + min) / 2;
  let h = 0;
  let s = 0;
  if (max !== min) {
    const d = max - min;
    s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
    switch (max) {
      case rn:
        h = (gn - bn) / d + (gn < bn ? 6 : 0);
        break;
      case gn:
        h = (bn - rn) / d + 2;
        break;
      case bn:
        h = (rn - gn) / d + 4;
        break;
    }
    h *= 60;
  }
  return { h, s: s * 100, l: l * 100 };
}

function hslToHex(h: number, s: number, l: number): string {
  const hue = ((h % 360) + 360) % 360;
  const sat = clamp(s, 0, 100) / 100;
  const light = clamp(l, 0, 100) / 100;
  const c = (1 - Math.abs(2 * light - 1)) * sat;
  const x = c * (1 - Math.abs(((hue / 60) % 2) - 1));
  const m = light - c / 2;
  let rp = 0;
  let gp = 0;
  let bp = 0;
  if (hue < 60) {
    rp = c;
    gp = x;
  } else if (hue < 120) {
    rp = x;
    gp = c;
  } else if (hue < 180) {
    gp = c;
    bp = x;
  } else if (hue < 240) {
    gp = x;
    bp = c;
  } else if (hue < 300) {
    rp = x;
    bp = c;
  } else {
    rp = c;
    bp = x;
  }
  return rgbToHex((rp + m) * 255, (gp + m) * 255, (bp + m) * 255);
}

function hexAlpha(hex: string, alpha: number): string {
  const { r, g, b } = hexToRgb(hex);
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

export function relativeLuminance(hex: string): number {
  const { r, g, b } = hexToRgb(hex);
  const conv = (c: number) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * conv(r) + 0.7152 * conv(g) + 0.0722 * conv(b);
}

export function contrastRatio(hexA: string, hexB: string): number {
  const lumA = relativeLuminance(hexA);
  const lumB = relativeLuminance(hexB);
  const hi = Math.max(lumA, lumB);
  const lo = Math.min(lumA, lumB);
  return (hi + 0.05) / (lo + 0.05);
}

export function ensureMinContrast(
  fgHex: string,
  bgHex: string,
  minRatio = 4.5,
): string {
  if (contrastRatio(fgHex, bgHex) >= minRatio) {
    return normalizeHex(fgHex);
  }
  const { r, g, b } = hexToRgb(fgHex);
  const { h, s, l } = rgbToHsl(r, g, b);
  const bgLum = relativeLuminance(bgHex);
  // Move lightness away from background luminance to reach target contrast cleanly
  const goDarker = bgLum > 0.22;
  let bestHex = fgHex;
  let bestDist = Infinity;

  for (let delta = 2; delta <= 100; delta += 2) {
    const candidates = goDarker
      ? [clamp(l - delta, 4, 96), clamp(l + delta, 4, 96)]
      : [clamp(l + delta, 4, 96), clamp(l - delta, 4, 96)];
    for (const nextL of candidates) {
      const cand = hslToHex(h, s, nextL);
      if (contrastRatio(cand, bgHex) >= minRatio) {
        const dist = Math.abs(nextL - l);
        if (dist < bestDist) {
          bestDist = dist;
          bestHex = cand;
        }
        return bestHex;
      }
    }
  }

  const darkContrast = contrastRatio('#111827', bgHex);
  const lightContrast = contrastRatio('#FFFFFF', bgHex);
  return lightContrast >= darkContrast ? '#FFFFFF' : '#111827';
}

function pickContrastText(bgHex: string, darkHex: string, lightHex: string): string {
  const cDark = contrastRatio(darkHex, bgHex);
  const cLight = contrastRatio(lightHex, bgHex);
  const chosen = cLight >= cDark ? lightHex : darkHex;
  return ensureMinContrast(chosen, bgHex, 4.5);
}

export function resolveSeedColor(
  preset: AccentPreset,
  customHex?: string | null,
  windowsAccentHex?: string | null,
): string {
  if (preset === 'windows' && windowsAccentHex) {
    return normalizeHex(windowsAccentHex, '#5B6EF5');
  }
  if (preset === 'custom') {
    return normalizeHex(customHex, '#5B6EF5');
  }
  const found = ACCENT_PRESET_META.find((p) => p.id === preset);
  return found?.hex ?? '#5B6EF5';
}

export function generateMaterialTokens(
  seedHex: string,
  mode: 'dark' | 'light',
  dynamicColor: boolean,
): Record<string, string> {
  const { r, g, b } = hexToRgb(seedHex);
  const { h, s } = rgbToHsl(r, g, b);
  const primarySat = clamp(s, 45, 88);
  const neutralSat = dynamicColor ? clamp(s * 0.14, 5, 11) : 4;
  const secondaryHue = (h + 22) % 360;
  const tertiaryHue = (h + 58) % 360;

  if (mode === 'dark') {
    const surface = hslToHex(h, neutralSat, 7);
    const surfaceLowest = hslToHex(h, neutralSat, 5);
    const surfaceLow = hslToHex(h, neutralSat, 10);
    const surfaceContainer = hslToHex(h, neutralSat + 1, 13);
    const surfaceHigh = hslToHex(h, neutralSat + 1.5, 16);
    const surfaceHighest = hslToHex(h, neutralSat + 2, 20);

    const primary = ensureMinContrast(
      hslToHex(h, clamp(primarySat, 60, 88), 76),
      surfaceContainer,
      4.5,
    );
    const onPrimary = pickContrastText(primary, hslToHex(h, 55, 14), '#FFFFFF');
    const primaryContainer = hslToHex(h, clamp(primarySat * 0.65, 34, 62), 29);
    const onPrimaryContainer = ensureMinContrast(
      hslToHex(h, clamp(primarySat, 65, 92), 91),
      primaryContainer,
      4.5,
    );

    const secondary = ensureMinContrast(
      hslToHex(secondaryHue, clamp(primarySat * 0.45, 22, 46), 74),
      surfaceContainer,
      4.5,
    );
    const secondaryContainer = hslToHex(secondaryHue, clamp(primarySat * 0.36, 18, 36), 25);
    const onSecondaryContainer = ensureMinContrast(
      hslToHex(secondaryHue, 40, 89),
      secondaryContainer,
      4.5,
    );

    const tertiary = ensureMinContrast(
      hslToHex(tertiaryHue, clamp(primarySat * 0.48, 25, 48), 75),
      surfaceContainer,
      4.5,
    );
    const tertiaryContainer = hslToHex(tertiaryHue, 28, 26);
    const onTertiaryContainer = ensureMinContrast(
      hslToHex(tertiaryHue, 45, 90),
      tertiaryContainer,
      4.5,
    );

    const onSurface = ensureMinContrast(hslToHex(h, 12, 93), surfaceContainer, 7.0);
    const onSurfaceVariant = ensureMinContrast(hslToHex(h, 10, 72), surfaceContainer, 4.5);
    const outline = hslToHex(h, 8, 48);
    const outlineVariant = hexAlpha(onSurface, 0.1);

    const error = '#F28B82';
    const onError = '#490B0E';
    const errorContainer = 'rgba(242, 139, 130, 0.14)';
    const onErrorContainer = '#FAD2CF';

    const success = '#4ADEA0';
    const successContainer = 'rgba(74, 222, 160, 0.14)';
    const onSuccessContainer = '#B8F5D8';

    const warning = '#F5BA4B';
    const warningContainer = 'rgba(245, 186, 75, 0.14)';

    const inverseSurface = '#E6E9F2';
    const inverseOnSurface = '#191C24';
    const inversePrimary = ensureMinContrast(primary, inverseSurface, 4.5);
    const inverseSuccess = ensureMinContrast('#0F7A4D', inverseSurface, 4.5);
    const inverseError = ensureMinContrast('#B3261E', inverseSurface, 4.5);
    const inverseWarning = ensureMinContrast('#8C5200', inverseSurface, 4.5);

    return {
      '--md-primary': primary,
      '--md-on-primary': onPrimary,
      '--md-primary-container': primaryContainer,
      '--md-on-primary-container': onPrimaryContainer,
      '--md-secondary': secondary,
      '--md-secondary-container': secondaryContainer,
      '--md-on-secondary-container': onSecondaryContainer,
      '--md-tertiary': tertiary,
      '--md-tertiary-container': tertiaryContainer,
      '--md-on-tertiary-container': onTertiaryContainer,
      '--md-surface': surface,
      '--md-surface-container-lowest': surfaceLowest,
      '--md-surface-container-low': surfaceLow,
      '--md-surface-container': surfaceContainer,
      '--md-surface-container-high': surfaceHigh,
      '--md-surface-container-highest': surfaceHighest,
      '--md-on-surface': onSurface,
      '--md-on-surface-variant': onSurfaceVariant,
      '--md-outline': outline,
      '--md-outline-variant': outlineVariant,
      '--md-error': error,
      '--md-on-error': onError,
      '--md-error-container': errorContainer,
      '--md-on-error-container': onErrorContainer,
      '--md-success': success,
      '--md-success-container': successContainer,
      '--md-on-success-container': onSuccessContainer,
      '--md-warning': warning,
      '--md-warning-container': warningContainer,
      '--md-inverse-surface': inverseSurface,
      '--md-inverse-on-surface': inverseOnSurface,
      '--md-inverse-primary': inversePrimary,
      '--md-inverse-success': inverseSuccess,
      '--md-inverse-error': inverseError,
      '--md-inverse-warning': inverseWarning,
      '--bg-canvas': surface,
      '--bg-sidebar': surfaceLow,
      '--bg-surface': surfaceContainer,
      '--bg-surface-2': surfaceHigh,
      '--bg-elevated': surfaceHighest,
      '--border-subtle': hexAlpha(onSurface, 0.075),
      '--border-strong': hexAlpha(onSurface, 0.15),
      '--text-primary': onSurface,
      '--text-secondary': onSurfaceVariant,
      '--text-muted': hslToHex(h, 8, 56),
      '--accent-primary': primary,
      '--accent-secondary': tertiary,
      '--accent-soft': hexAlpha(primary, 0.14),
      '--status-connected': success,
      '--status-connected-soft': successContainer,
      '--status-warning': warning,
      '--status-error': error,
      '--status-error-soft': errorContainer,
      '--dial-face': `linear-gradient(155deg, ${surfaceHighest} 0%, ${surfaceContainer} 100%)`,
      '--dial-shadow': '0 14px 36px rgba(0, 0, 0, 0.45), inset 0 1px 0 rgba(255, 255, 255, 0.06)',
    };
  }

  // Light theme (MD3 Tone 40 primary with WCAG AA guarantee >= 4.5:1)
  const surface = hslToHex(h, neutralSat, 97.5);
  const surfaceLowest = '#FFFFFF';
  const surfaceLow = hslToHex(h, neutralSat + 2, 95);
  const surfaceContainer = hslToHex(h, neutralSat + 2, 93);
  const surfaceHigh = hslToHex(h, neutralSat + 2, 90.5);
  const surfaceHighest = hslToHex(h, neutralSat + 2, 87.5);

  const lightPrimaryL = h >= 42 && h <= 195 ? 32 : 41;
  const primary = ensureMinContrast(
    hslToHex(h, clamp(primarySat, 55, 86), lightPrimaryL),
    surfaceContainer,
    4.5,
  );
  const onPrimary = pickContrastText(primary, '#111827', '#FFFFFF');
  const primaryContainer = hslToHex(h, clamp(primarySat, 65, 92), 90);
  const onPrimaryContainer = ensureMinContrast(
    hslToHex(h, clamp(primarySat, 50, 82), 18),
    primaryContainer,
    4.5,
  );

  const secondary = ensureMinContrast(
    hslToHex(secondaryHue, clamp(primarySat * 0.42, 20, 44), 40),
    surfaceContainer,
    4.5,
  );
  const secondaryContainer = hslToHex(secondaryHue, 40, 89);
  const onSecondaryContainer = ensureMinContrast(
    hslToHex(secondaryHue, 40, 19),
    secondaryContainer,
    4.5,
  );

  const tertiary = ensureMinContrast(
    hslToHex(tertiaryHue, clamp(primarySat * 0.45, 22, 46), 41),
    surfaceContainer,
    4.5,
  );
  const tertiaryContainer = hslToHex(tertiaryHue, 40, 90);
  const onTertiaryContainer = ensureMinContrast(
    hslToHex(tertiaryHue, 42, 19),
    tertiaryContainer,
    4.5,
  );

  const onSurface = ensureMinContrast(hslToHex(h, 16, 13), surfaceContainer, 7.0);
  const onSurfaceVariant = ensureMinContrast(hslToHex(h, 12, 34), surfaceContainer, 4.5);
  const outline = hslToHex(h, 10, 52);
  const outlineVariant = hexAlpha(onSurface, 0.11);

  const error = '#BA1A2D';
  const onError = '#FFFFFF';
  const errorContainer = '#FFDAD9';
  const onErrorContainer = '#69000E';

  const success = '#127A4E';
  const successContainer = '#D3F7E5';
  const onSuccessContainer = '#063B24';

  const warning = '#9A5404';
  const warningContainer = '#FCEAD0';

  return {
    '--md-primary': primary,
    '--md-on-primary': onPrimary,
    '--md-primary-container': primaryContainer,
    '--md-on-primary-container': onPrimaryContainer,
    '--md-secondary': secondary,
    '--md-secondary-container': secondaryContainer,
    '--md-on-secondary-container': onSecondaryContainer,
    '--md-tertiary': tertiary,
    '--md-tertiary-container': tertiaryContainer,
    '--md-on-tertiary-container': onTertiaryContainer,
    '--md-surface': surface,
    '--md-surface-container-lowest': surfaceLowest,
    '--md-surface-container-low': surfaceLow,
    '--md-surface-container': surfaceContainer,
    '--md-surface-container-high': surfaceHigh,
    '--md-surface-container-highest': surfaceHighest,
    '--md-on-surface': onSurface,
    '--md-on-surface-variant': onSurfaceVariant,
    '--md-outline': outline,
    '--md-outline-variant': outlineVariant,
    '--md-error': error,
    '--md-on-error': onError,
    '--md-error-container': errorContainer,
    '--md-on-error-container': onErrorContainer,
    '--md-success': success,
    '--md-success-container': successContainer,
    '--md-on-success-container': onSuccessContainer,
    '--md-warning': warning,
    '--md-warning-container': warningContainer,
    '--md-inverse-surface': '#262B36',
    '--md-inverse-on-surface': '#F2F4F8',
    '--md-inverse-primary': ensureMinContrast('#9FB0FF', '#262B36', 4.5),
    '--md-inverse-success': ensureMinContrast('#6EE7B7', '#262B36', 4.5),
    '--md-inverse-error': ensureMinContrast('#FCA5A5', '#262B36', 4.5),
    '--md-inverse-warning': ensureMinContrast('#FCD34D', '#262B36', 4.5),
    '--bg-canvas': surface,
    '--bg-sidebar': surfaceLow,
    '--bg-surface': surfaceLowest,
    '--bg-surface-2': surfaceContainer,
    '--bg-elevated': surfaceHigh,
    '--border-subtle': hexAlpha(onSurface, 0.08),
    '--border-strong': hexAlpha(onSurface, 0.16),
    '--text-primary': onSurface,
    '--text-secondary': onSurfaceVariant,
    '--text-muted': hslToHex(h, 10, 44),
    '--accent-primary': primary,
    '--accent-secondary': tertiary,
    '--accent-soft': hexAlpha(primary, 0.12),
    '--status-connected': success,
    '--status-connected-soft': successContainer,
    '--status-warning': warning,
    '--status-error': error,
    '--status-error-soft': errorContainer,
    '--dial-face': `linear-gradient(155deg, ${surfaceLowest} 0%, ${surfaceLow} 100%)`,
    '--dial-shadow': '0 14px 32px rgba(15, 23, 42, 0.08), inset 0 1px 0 rgba(255, 255, 255, 0.9)',
  };
}

export function applyMaterialTheme(
  root: HTMLElement,
  settings: AppSettings,
  windowsAccentHex: string | null,
  systemPrefersDark: boolean,
): 'dark' | 'light' {
  const resolvedMode: 'dark' | 'light' =
    settings.theme === 'system'
      ? systemPrefersDark
        ? 'dark'
        : 'light'
      : settings.theme;

  root.classList.remove('dark', 'light');
  root.classList.add(resolvedMode);

  const seed = resolveSeedColor(
    settings.accentPreset,
    settings.customAccentHex,
    windowsAccentHex,
  );
  const tokens = generateMaterialTokens(seed, resolvedMode, settings.dynamicColor);
  for (const [k, v] of Object.entries(tokens)) {
    root.style.setProperty(k, v);
  }

  const scale = clamp(settings.uiScale || 100, 90, 120);
  root.style.fontSize = `${scale}%`;
  root.dataset.compact = settings.compactMode ? 'true' : 'false';
  root.dataset.noMotion = settings.animationsEnabled ? 'false' : 'true';
  root.dataset.bgStyle = settings.backgroundStyle ?? 'aura';
  return resolvedMode;
}
