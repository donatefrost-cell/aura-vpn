import { beforeEach, describe, expect, it } from 'vitest';
import { DEFAULT_SETTINGS } from '../config/defaultSettings';
import { liveStore } from '../stores/liveStore';
import { notificationStore } from '../stores/notificationStore';
import { analyzeProfileDiff, profilesStore } from '../stores/profilesStore';

describe('liveStore O(1) ring buffer & latency meta', () => {
  beforeEach(() => {
    liveStore.resetTraffic();
  });

  it('bounds raw samples to 960 and aggregates 1m/5m/15m/session windows cleanly', () => {
    const startTs = 1_700_000_000_000;
    for (let i = 0; i < 1000; i++) {
      liveStore.pushTraffic(
        {
          rxBytesPerSec: (i + 1) * 100,
          txBytesPerSec: (i + 1) * 10,
          totalRxBytes: i * 1000,
          totalTxBytes: i * 100,
        },
        startTs + i * 1000,
      );
    }

    expect(liveStore.getRawCount()).toBe(960);

    const w1m = liveStore.getTrafficWindow('1m');
    expect(w1m.samples.length).toBe(60);
    expect(w1m.peakRx).toBe(1000 * 100);

    const w5m = liveStore.getTrafficWindow('5m');
    expect(w5m.samples.length).toBe(300);

    const w15m = liveStore.getTrafficWindow('15m');
    expect(w15m.samples.length).toBe(900);

    const wSession = liveStore.getTrafficWindow('session');
    expect(wSession.samples.length).toBeGreaterThan(20);
    expect(wSession.samples.length).toBeLessThanOrEqual(365);
  });

  it('tracks ping history ring per server up to 12 points', () => {
    for (let i = 0; i < 15; i++) {
      liveStore.recordServerLatencies([{ id: 'srv-1', latencyMs: 40 + i }]);
    }
    const meta = liveStore.getSnapshot().serverLatencyMeta['srv-1'];
    expect(meta).toBeDefined();
    expect(meta.history.length).toBe(12);
    expect(meta.history[0]).toBe(43);
    expect(meta.history[11]).toBe(54);
    expect(meta.checkedAt).toBeGreaterThan(0);
  });
});

describe('profilesStore security downgrade & reconnect analysis', () => {
  it('flags reconnect and security downgrades when moving from hardened work profile to daily', () => {
    const state = profilesStore.getSnapshot();
    const work = state.profiles.work;
    const daily = state.profiles.daily;

    const hardenedSettings = {
      ...DEFAULT_SETTINGS,
      connectionMode: work.connectionMode,
      killSwitchEnabled: work.killSwitchEnabled,
      ipv6Enabled: work.ipv6Enabled,
      dns: { ...work.dns },
      routing: {
        ...DEFAULT_SETTINGS.routing,
        profile: work.routingProfile,
        bypassRuDomains: work.bypassRuDomains,
        splitTunnelMode: work.splitTunnelMode,
      },
    };

    const diff = analyzeProfileDiff(hardenedSettings, daily, true);
    expect(diff.requiresReconnect).toBe(true);
    expect(diff.securityDowngrades.length).toBeGreaterThanOrEqual(2);
  });
});

describe('notificationStore mute & unread tracking', () => {
  beforeEach(() => {
    notificationStore.clear();
  });

  it('tracks unread notifications and respects muted categories', () => {
    expect(
      notificationStore.push({
        category: 'import',
        tone: 'success',
        title: 'Импорт выполнен',
      }),
    ).toBe(true);
    expect(notificationStore.getSnapshot().items.length).toBe(1);
    expect(notificationStore.getSnapshot().items[0].read).toBe(false);

    notificationStore.toggleMute('import');
    expect(
      notificationStore.push({
        category: 'import',
        tone: 'info',
        title: 'Должно быть скрыто',
      }),
    ).toBe(false);
    expect(notificationStore.getSnapshot().items.length).toBe(1);

    notificationStore.markAllRead();
    expect(notificationStore.getSnapshot().items[0].read).toBe(true);
  });
});
