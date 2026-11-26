import { describe, expect, it } from 'vitest';
import {
  contrastRatio,
  ensureMinContrast,
  generateMaterialTokens,
  normalizeHex,
  resolveSeedColor,
} from '../theme/materialYou';

describe('materialYou contrast & tokens', () => {
  const testSeeds = [
    { name: 'indigo', hex: '#5B6EF5' },
    { name: 'teal', hex: '#0D9488' },
    { name: 'yellow', hex: '#FACC15' },
  ];

  it('normalizes valid hex strings and falls back cleanly', () => {
    expect(normalizeHex('facc15')).toBe('#FACC15');
    expect(normalizeHex('invalid', '#5B6EF5')).toBe('#5B6EF5');
    expect(resolveSeedColor('teal')).toBe('#0D9488');
    expect(resolveSeedColor('custom', 'facc15')).toBe('#FACC15');
  });

  for (const seed of testSeeds) {
    for (const mode of ['dark', 'light'] as const) {
      it(`guarantees WCAG AA >= 4.5:1 contrast for ${seed.name} (${seed.hex}) in ${mode} mode`, () => {
        const tokens = generateMaterialTokens(seed.hex, mode, true);
        const surfaceContainer = tokens['--md-surface-container'];
        const primary = tokens['--md-primary'];
        const onPrimary = tokens['--md-on-primary'];
        const primaryContainer = tokens['--md-primary-container'];
        const onPrimaryContainer = tokens['--md-on-primary-container'];
        const onSurface = tokens['--md-on-surface'];
        const onSurfaceVariant = tokens['--md-on-surface-variant'];
        const inverseSurface = tokens['--md-inverse-surface'];
        const inversePrimary = tokens['--md-inverse-primary'];
        const inverseSuccess = tokens['--md-inverse-success'];
        const inverseError = tokens['--md-inverse-error'];

        expect(contrastRatio(primary, surfaceContainer)).toBeGreaterThanOrEqual(4.5);
        expect(contrastRatio(onPrimary, primary)).toBeGreaterThanOrEqual(4.5);
        expect(contrastRatio(onPrimaryContainer, primaryContainer)).toBeGreaterThanOrEqual(4.5);
        expect(contrastRatio(onSurface, surfaceContainer)).toBeGreaterThanOrEqual(7.0);
        expect(contrastRatio(onSurfaceVariant, surfaceContainer)).toBeGreaterThanOrEqual(4.5);
        expect(contrastRatio(inversePrimary, inverseSurface)).toBeGreaterThanOrEqual(4.5);
        expect(contrastRatio(inverseSuccess, inverseSurface)).toBeGreaterThanOrEqual(4.5);
        expect(contrastRatio(inverseError, inverseSurface)).toBeGreaterThanOrEqual(4.5);
      });
    }
  }

  it('adjusts low-contrast foregrounds via ensureMinContrast', () => {
    const adjusted = ensureMinContrast('#FACC15', '#FFFFFF', 4.5);
    expect(contrastRatio(adjusted, '#FFFFFF')).toBeGreaterThanOrEqual(4.5);
  });
});
