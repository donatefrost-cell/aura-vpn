import { describe, expect, it } from 'vitest';
import {
  formatBytes,
  formatDuration,
  formatNodePoolLabel,
  formatProtocolBadge,
  formatServerDisplayName,
  formatSpeed,
  getCountryName,
  getLatencyTone,
  shouldShowCountryInSubtitle,
} from '../utils/format';
import type { ServerProfile } from '../types/vpn';

describe('format utilities', () => {
  it('formats bytes and speeds in Russian units', () => {
    expect(formatBytes(0)).toBe('0 Б');
    expect(formatBytes(-5)).toBe('0 Б');
    expect(formatBytes(1536)).toBe('1.50 КБ');
    expect(formatBytes(15 * 1024 * 1024)).toBe('15.0 МБ');

    expect(formatSpeed(0)).toBe('0 КБ/с');
    expect(formatSpeed(512)).toBe('512 Б/с');
    expect(formatSpeed(2048)).toBe('2.0 КБ/с');
    expect(formatSpeed(2 * 1024 * 1024)).toBe('2.00 МБ/с');
  });

  it('formats durations and Russian plural node pool labels', () => {
    expect(formatDuration(null)).toBe('00:00:00');
    expect(formatDuration(1000, 1000 * 1000 + 3665 * 1000)).toBe('01:01:05');

    expect(formatNodePoolLabel(1)).toBe('1 узел');
    expect(formatNodePoolLabel(3)).toBe('3 узла');
    expect(formatNodePoolLabel(12)).toBe('12 узлов');
    expect(formatNodePoolLabel(21)).toBe('21 узел');
  });

  it('strips regional indicator flag prefixes and deduplicates country names', () => {
    expect(formatServerDisplayName('🇳🇱 Amsterdam-01')).toBe('Amsterdam-01');
    expect(getCountryName('nl')).toBe('Нидерланды');
    expect(shouldShowCountryInSubtitle('Нидерланды VIP', 'Нидерланды')).toBe(false);
    expect(shouldShowCountryInSubtitle('Amsterdam-01', 'Нидерланды')).toBe(true);
    expect(shouldShowCountryInSubtitle('Дубай 01', 'ОАЭ')).toBe(false);
  });

  it('classifies latency tones and protocol badges', () => {
    expect(getLatencyTone(null)).toBe('none');
    expect(getLatencyTone(45)).toBe('good');
    expect(getLatencyTone(120)).toBe('medium');
    expect(getLatencyTone(350)).toBe('poor');

    const vlessProfile: ServerProfile = {
      id: 'p1',
      name: 'NL-1',
      address: '1.1.1.1',
      port: 443,
      protocol: 'vless',
      favorite: false,
      details: {
        kind: 'vless',
        data: {
          uuid: 'u',
          flow: 'xtls-rprx-vision',
          encryption: 'none',
          network: 'tcp',
          security: 'reality',
          allowInsecure: false,
        },
      },
      createdAt: '2026-01-01T00:00:00Z',
    };
    expect(formatProtocolBadge(vlessProfile)).toBe('VLESS Reality');
  });
});
