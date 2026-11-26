import { describe, expect, it, vi } from 'vitest';
import { liveStore } from '../stores/liveStore';

describe('liveStore', () => {
  it('notifies subscribers and caps logs at 300 and traffic samples at 45', () => {
    liveStore.clearLogs();
    liveStore.resetTraffic();

    const listener = vi.fn();
    const unsub = liveStore.subscribe(listener);

    for (let i = 0; i < 310; i++) {
      liveStore.pushLog({
        id: i,
        timestamp: '12:00:00',
        level: 'info',
        source: 'test',
        message: `msg-${i}`,
      });
    }

    for (let i = 0; i < 50; i++) {
      liveStore.pushTraffic({
        rxBytesPerSec: i * 100,
        txBytesPerSec: i * 50,
        totalRxBytes: i * 1000,
        totalTxBytes: i * 500,
      });
    }

    const snap = liveStore.getSnapshot();
    expect(snap.logs).toHaveLength(300);
    expect(snap.logs[0].message).toBe('msg-10');
    expect(snap.logs[299].message).toBe('msg-309');
    expect(snap.trafficSamples).toHaveLength(45);
    expect(snap.traffic.rxBytesPerSec).toBe(4900);
    expect(listener).toHaveBeenCalledTimes(360);

    unsub();
    liveStore.clearLogs();
    liveStore.resetTraffic();
    expect(listener).toHaveBeenCalledTimes(360);
  });
});
