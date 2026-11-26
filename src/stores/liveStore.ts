import { useSyncExternalStore } from 'react';
import type {
  ConnectionTimelineEvent,
  LogEntry,
  TrafficSample,
  TrafficStats,
  TrafficTimeframe,
} from '../types/vpn';

export interface ServerLatencyMeta {
  checkedAt: number;
  history: number[];
}

export interface LiveSnapshot {
  traffic: TrafficStats;
  trafficSamples: TrafficSample[];
  trafficVersion: number;
  logs: LogEntry[];
  serverLatencyMeta: Record<string, ServerLatencyMeta>;
  connectionTimeline: ConnectionTimelineEvent[];
}

const EMPTY_TRAFFIC: TrafficStats = {
  rxBytesPerSec: 0,
  txBytesPerSec: 0,
  totalRxBytes: 0,
  totalTxBytes: 0,
};

const RAW_CAP = 960; // 16 minutes @ 1 Hz in fixed circular buffer (O(1) memory)
const ONE_HOUR_CAP = 360; // 1 hour = 360 × 10-second buckets
const SESSION_CAP = 360;
const TIMELINE_CAP = 100;
const LATENCY_META_KEY = 'aura-server-latency-meta-v1';

function loadLatencyMeta(): Record<string, ServerLatencyMeta> {
  if (typeof window === 'undefined' || !window.localStorage) return {};
  try {
    const raw = window.localStorage.getItem(LATENCY_META_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as Record<string, ServerLatencyMeta>;
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

function saveLatencyMeta(meta: Record<string, ServerLatencyMeta>) {
  if (typeof window === 'undefined' || !window.localStorage) return;
  try {
    window.localStorage.setItem(LATENCY_META_KEY, JSON.stringify(meta));
  } catch {
    // Ignore storage quota errors
  }
}

export interface TrafficWindowResult {
  samples: TrafficSample[];
  peakRx: number;
  peakTx: number;
  avgRx: number;
  avgTx: number;
}

class LiveStore {
  private rawBuf: Array<TrafficSample | undefined> = new Array(RAW_CAP);
  private rawHead = 0;
  private rawCount = 0;

  private hourBuf: Array<TrafficSample | undefined> = new Array(ONE_HOUR_CAP);
  private hourHead = 0;
  private hourCount = 0;
  private hourAccumCount = 0;
  private hourAccumRx = 0;
  private hourAccumTx = 0;
  private hourAccumTs = 0;

  private sessionBuf: TrafficSample[] = [];
  private sessionBucketSec = 5;
  private accumCount = 0;
  private accumRx = 0;
  private accumTx = 0;
  private accumTs = 0;

  private state: LiveSnapshot = {
    traffic: EMPTY_TRAFFIC,
    trafficSamples: [],
    trafficVersion: 0,
    logs: [],
    serverLatencyMeta: loadLatencyMeta(),
    connectionTimeline: [],
  };

  private listeners = new Set<() => void>();

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  getSnapshot = (): LiveSnapshot => this.state;

  private emit() {
    for (const l of this.listeners) {
      l();
    }
  }

  private pushSampleToRing(sample: TrafficSample) {
    this.rawBuf[this.rawHead] = sample;
    this.rawHead = (this.rawHead + 1) % RAW_CAP;
    if (this.rawCount < RAW_CAP) {
      this.rawCount += 1;
    }

    this.hourAccumRx += sample.rx;
    this.hourAccumTx += sample.tx;
    this.hourAccumTs = sample.ts;
    this.hourAccumCount += 1;
    if (this.hourAccumCount >= 10) {
      this.hourBuf[this.hourHead] = {
        ts: this.hourAccumTs,
        rx: Math.round(this.hourAccumRx / this.hourAccumCount),
        tx: Math.round(this.hourAccumTx / this.hourAccumCount),
      };
      this.hourHead = (this.hourHead + 1) % ONE_HOUR_CAP;
      if (this.hourCount < ONE_HOUR_CAP) {
        this.hourCount += 1;
      }
      this.hourAccumCount = 0;
      this.hourAccumRx = 0;
      this.hourAccumTx = 0;
    }

    this.accumRx += sample.rx;
    this.accumTx += sample.tx;
    this.accumTs = sample.ts;
    this.accumCount += 1;

    if (this.accumCount >= this.sessionBucketSec) {
      this.sessionBuf.push({
        ts: this.accumTs,
        rx: Math.round(this.accumRx / this.accumCount),
        tx: Math.round(this.accumTx / this.accumCount),
      });
      this.accumCount = 0;
      this.accumRx = 0;
      this.accumTx = 0;

      if (this.sessionBuf.length >= SESSION_CAP) {
        const compacted: TrafficSample[] = [];
        for (let i = 0; i + 1 < this.sessionBuf.length; i += 2) {
          const a = this.sessionBuf[i];
          const b = this.sessionBuf[i + 1];
          compacted.push({
            ts: b.ts,
            rx: Math.round((a.rx + b.rx) / 2),
            tx: Math.round((a.tx + b.tx) / 2),
          });
        }
        this.sessionBuf = compacted;
        this.sessionBucketSec = Math.min(300, this.sessionBucketSec * 2);
      }
    }
  }

  private readRecentRaw(maxCount: number): TrafficSample[] {
    const n = Math.min(maxCount, this.rawCount);
    const out: TrafficSample[] = new Array(n);
    const start = (this.rawHead - n + RAW_CAP) % RAW_CAP;
    for (let i = 0; i < n; i++) {
      const s = this.rawBuf[(start + i) % RAW_CAP];
      if (s) out[i] = s;
    }
    return out;
  }

  private readHourRing(): TrafficSample[] {
    const out: TrafficSample[] = new Array(this.hourCount);
    const start = (this.hourHead - this.hourCount + ONE_HOUR_CAP) % ONE_HOUR_CAP;
    for (let i = 0; i < this.hourCount; i++) {
      const s = this.hourBuf[(start + i) % ONE_HOUR_CAP];
      if (s) out[i] = s;
    }
    if (this.hourAccumCount > 0) {
      out.push({
        ts: this.hourAccumTs,
        rx: Math.round(this.hourAccumRx / this.hourAccumCount),
        tx: Math.round(this.hourAccumTx / this.hourAccumCount),
      });
    }
    return out;
  }

  getTrafficWindow(timeframe: TrafficTimeframe): TrafficWindowResult {
    let samples: TrafficSample[];
    if (timeframe === '1m') {
      samples = this.readRecentRaw(60);
    } else if (timeframe === '5m') {
      samples = this.readRecentRaw(300);
    } else if (timeframe === '15m') {
      samples = this.readRecentRaw(900);
    } else if (timeframe === '1h') {
      const hourSamples = this.readHourRing();
      samples = hourSamples.length >= 2 ? hourSamples : this.readRecentRaw(RAW_CAP);
    } else {
      samples =
        this.sessionBuf.length >= 6
          ? [
              ...this.sessionBuf,
              ...(this.accumCount > 0
                ? [
                    {
                      ts: this.accumTs,
                      rx: Math.round(this.accumRx / this.accumCount),
                      tx: Math.round(this.accumTx / this.accumCount),
                    },
                  ]
                : []),
            ]
          : this.readRecentRaw(RAW_CAP);
    }

    let peakRx = 0;
    let peakTx = 0;
    let sumRx = 0;
    let sumTx = 0;
    for (const s of samples) {
      if (s.rx > peakRx) peakRx = s.rx;
      if (s.tx > peakTx) peakTx = s.tx;
      sumRx += s.rx;
      sumTx += s.tx;
    }
    const denom = Math.max(1, samples.length);
    return {
      samples,
      peakRx,
      peakTx,
      avgRx: Math.round(sumRx / denom),
      avgTx: Math.round(sumTx / denom),
    };
  }

  getRawCount(): number {
    return this.rawCount;
  }

  setInitialLogs(logs: LogEntry[]) {
    this.state = {
      ...this.state,
      logs: logs.slice(-300),
    };
    this.emit();
  }

  pushLog(entry: LogEntry) {
    this.state = {
      ...this.state,
      logs: [...this.state.logs.slice(-299), entry],
    };
    this.emit();
  }

  clearLogs() {
    this.state = {
      ...this.state,
      logs: [],
    };
    this.emit();
  }

  setInitialTraffic(traffic: TrafficStats) {
    this.state = {
      ...this.state,
      traffic,
    };
    this.emit();
  }

  pushTraffic(traffic: TrafficStats, ts = Date.now()) {
    this.pushSampleToRing({
      ts,
      rx: traffic.rxBytesPerSec,
      tx: traffic.txBytesPerSec,
    });
    this.state = {
      ...this.state,
      traffic,
      trafficSamples: this.readRecentRaw(45),
      trafficVersion: this.state.trafficVersion + 1,
    };
    this.emit();
  }

  resetTraffic() {
    this.rawBuf = new Array(RAW_CAP);
    this.rawHead = 0;
    this.rawCount = 0;
    this.hourBuf = new Array(ONE_HOUR_CAP);
    this.hourHead = 0;
    this.hourCount = 0;
    this.hourAccumCount = 0;
    this.hourAccumRx = 0;
    this.hourAccumTx = 0;
    this.hourAccumTs = 0;
    this.sessionBuf = [];
    this.sessionBucketSec = 5;
    this.accumCount = 0;
    this.accumRx = 0;
    this.accumTx = 0;
    this.accumTs = 0;
    this.state = {
      ...this.state,
      traffic: EMPTY_TRAFFIC,
      trafficSamples: [],
      trafficVersion: this.state.trafficVersion + 1,
    };
    this.emit();
  }

  seedPreviewTraffic(samples: TrafficSample[]) {
    this.rawBuf = new Array(RAW_CAP);
    this.rawHead = 0;
    this.rawCount = 0;
    this.hourBuf = new Array(ONE_HOUR_CAP);
    this.hourHead = 0;
    this.hourCount = 0;
    this.hourAccumCount = 0;
    this.hourAccumRx = 0;
    this.hourAccumTx = 0;
    this.hourAccumTs = 0;
    this.sessionBuf = [];
    this.sessionBucketSec = 5;
    this.accumCount = 0;
    this.accumRx = 0;
    this.accumTx = 0;
    for (const s of samples.slice(-RAW_CAP)) {
      this.pushSampleToRing(s);
    }
    this.state = {
      ...this.state,
      trafficSamples: this.readRecentRaw(45),
      trafficVersion: this.state.trafficVersion + 1,
    };
    this.emit();
  }

  recordServerLatencies(entries: Array<{ id: string; latencyMs?: number | null }>, checkedAt = Date.now()) {
    const next = { ...this.state.serverLatencyMeta };
    for (const item of entries) {
      const prev = next[item.id];
      const history = prev ? [...prev.history] : [];
      if (typeof item.latencyMs === 'number' && Number.isFinite(item.latencyMs)) {
        history.push(Math.round(item.latencyMs));
      }
      next[item.id] = {
        checkedAt,
        history: history.slice(-12),
      };
    }
    saveLatencyMeta(next);
    this.state = {
      ...this.state,
      serverLatencyMeta: next,
    };
    this.emit();
  }

  setInitialTimeline(events: ConnectionTimelineEvent[]) {
    this.state = {
      ...this.state,
      connectionTimeline: events.slice(0, TIMELINE_CAP),
    };
    this.emit();
  }

  pushTimelineEvent(event: ConnectionTimelineEvent) {
    const next = [event, ...this.state.connectionTimeline.filter((e) => e.id !== event.id)].slice(
      0,
      TIMELINE_CAP,
    );
    this.state = {
      ...this.state,
      connectionTimeline: next,
    };
    this.emit();
  }

  clearTimeline() {
    this.state = {
      ...this.state,
      connectionTimeline: [],
    };
    this.emit();
  }

  clearLatencyMeta() {
    if (typeof window !== 'undefined' && window.localStorage) {
      try {
        window.localStorage.removeItem(LATENCY_META_KEY);
      } catch {
        // ignore
      }
    }
    this.state = {
      ...this.state,
      serverLatencyMeta: {},
    };
    this.emit();
  }
}

export const liveStore = new LiveStore();

export function useConnectionTimeline(): ConnectionTimelineEvent[] {
  return useSyncExternalStore(
    liveStore.subscribe,
    () => liveStore.getSnapshot().connectionTimeline,
    () => liveStore.getSnapshot().connectionTimeline,
  );
}

export function useLiveTraffic(): TrafficStats {
  return useSyncExternalStore(
    liveStore.subscribe,
    () => liveStore.getSnapshot().traffic,
    () => liveStore.getSnapshot().traffic,
  );
}

export function useLiveTrafficSamples(): TrafficSample[] {
  return useSyncExternalStore(
    liveStore.subscribe,
    () => liveStore.getSnapshot().trafficSamples,
    () => liveStore.getSnapshot().trafficSamples,
  );
}

export function useLiveTrafficVersion(): number {
  return useSyncExternalStore(
    liveStore.subscribe,
    () => liveStore.getSnapshot().trafficVersion,
    () => liveStore.getSnapshot().trafficVersion,
  );
}

export function useLiveLogs(): LogEntry[] {
  return useSyncExternalStore(
    liveStore.subscribe,
    () => liveStore.getSnapshot().logs,
    () => liveStore.getSnapshot().logs,
  );
}

export function useServerLatencyMeta(): Record<string, ServerLatencyMeta> {
  return useSyncExternalStore(
    liveStore.subscribe,
    () => liveStore.getSnapshot().serverLatencyMeta,
    () => liveStore.getSnapshot().serverLatencyMeta,
  );
}
