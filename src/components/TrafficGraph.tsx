import { useMemo, useRef, useState, type PointerEvent as ReactPointerEvent } from 'react';
import { liveStore, useLiveTrafficVersion } from '../stores/liveStore';
import type { ConnectionStatus, TrafficSample, TrafficTimeframe } from '../types/vpn';
import { formatSpeed } from '../utils/format';
import { M3SegmentedButton } from './md3';

interface TrafficGraphProps {
  status: ConnectionStatus;
  compact?: boolean;
}

const TIMEFRAME_OPTIONS: Array<{ id: TrafficTimeframe; label: string }> = [
  { id: '1m', label: '1м' },
  { id: '5m', label: '5м' },
  { id: '15m', label: '15м' },
  { id: '1h', label: '1ч' },
  { id: 'session', label: 'Сессия' },
];

function computeNiceCeiling(rawMax: number): number {
  const floorMin = 64 * 1024;
  if (rawMax <= floorMin) return floorMin;
  const exp = Math.pow(10, Math.floor(Math.log10(rawMax)));
  const norm = rawMax / exp;
  const nice = norm <= 1.2 ? 1.2 : norm <= 2 ? 2 : norm <= 3 ? 3 : norm <= 5 ? 5 : 10;
  return Math.max(floorMin, Math.ceil(nice * exp));
}

function formatAxisLabel(bytesPerSec: number): string {
  if (bytesPerSec <= 0) return '0';
  if (bytesPerSec >= 1024 * 1024) {
    const mb = bytesPerSec / (1024 * 1024);
    return `${mb >= 10 ? mb.toFixed(0) : mb.toFixed(1)} МБ/с`;
  }
  return `${Math.round(bytesPerSec / 1024)} КБ/с`;
}

function formatSampleTime(ts: number): string {
  if (!ts || ts < 1_000_000) return '--:--:--';
  const d = new Date(ts);
  return d.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function TrafficGraph({ status, compact = false }: TrafficGraphProps) {
  const [timeframe, setTimeframe] = useState<TrafficTimeframe>('1m');
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  const version = useLiveTrafficVersion();
  const effectiveTimeframe: TrafficTimeframe = compact ? '1m' : timeframe;

  const { padded, rawPeak, avgRx, avgTx, ceiling, hasData } = useMemo(() => {
    void version;
    const win = liveStore.getTrafficWindow(effectiveTimeframe);
    const minPoints = effectiveTimeframe === '1m' ? 45 : 60;
    const list = win.samples;
    const paddedList: TrafficSample[] =
      list.length >= minPoints
        ? list
        : [
            ...Array.from({ length: minPoints - list.length }, (_, i) => ({
              ts: i,
              rx: 0,
              tx: 0,
            })),
            ...list,
          ];
    const maxVal = Math.max(win.peakRx, win.peakTx, ...paddedList.map((s) => Math.max(s.rx, s.tx)));
    return {
      padded: paddedList,
      rawPeak: maxVal,
      avgRx: win.avgRx,
      avgTx: win.avgTx,
      ceiling: computeNiceCeiling(maxVal),
      hasData: list.length > 0,
    };
  }, [effectiveTimeframe, version]);

  const isConnected = status === 'connected';
  const width = 520;
  const height = compact ? 38 : 64;
  const topPad = 5;
  const bottomPad = 5;
  const plotH = height - topPad - bottomPad;
  const count = padded.length;

  const getCoords = (idx: number, val: number) => {
    const x = count > 1 ? (idx / (count - 1)) * width : width / 2;
    const ratio = Math.min(1, Math.max(0, val / ceiling));
    const y = height - bottomPad - ratio * plotH;
    return { x, y };
  };

  const buildPath = (key: 'rx' | 'tx') => {
    const pts = padded.map((s, idx) => {
      const { x, y } = getCoords(idx, s[key]);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    });
    return `M ${pts.join(' L ')}`;
  };

  const rxLine = buildPath('rx');
  const txLine = buildPath('tx');
  const rxArea = `${rxLine} L ${width},${height - bottomPad} L 0,${height - bottomPad} Z`;
  const txArea = `${txLine} L ${width},${height - bottomPad} L 0,${height - bottomPad} Z`;

  const handlePointerMove = (e: ReactPointerEvent<SVGSVGElement>) => {
    if (!isConnected || !svgRef.current) return;
    const rect = svgRef.current.getBoundingClientRect();
    if (rect.width <= 0) return;
    const relX = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
    const idx = Math.round(relX * (count - 1));
    setHoverIdx(idx);
  };

  const hoveredSample = hoverIdx !== null && isConnected ? padded[hoverIdx] ?? null : null;
  const hoveredLeftPct =
    hoverIdx !== null && count > 1 ? Math.min(86, Math.max(14, (hoverIdx / (count - 1)) * 100)) : 50;
  const hoveredRxCoord = hoverIdx !== null && hoveredSample ? getCoords(hoverIdx, hoveredSample.rx) : null;
  const hoveredTxCoord = hoverIdx !== null && hoveredSample ? getCoords(hoverIdx, hoveredSample.tx) : null;

  return (
    <div
      data-testid="traffic-graph"
      className={`rounded-2xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] ${
        compact ? 'px-3 py-2' : 'px-3.5 py-2.5'
      }`}
    >
      <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2 text-[0.6875rem]">
        <div className="flex items-center gap-3">
          <span className="font-medium text-[var(--md-on-surface-variant)]">Сетевая активность</span>
          <span className="inline-flex items-center gap-1 text-[0.65rem] text-[var(--md-on-surface-variant)]">
            <span className="h-1.5 w-1.5 rounded-full bg-[var(--md-success)]" />
            Вход
          </span>
          <span className="inline-flex items-center gap-1 text-[0.65rem] text-[var(--md-on-surface-variant)]">
            <span className="h-1.5 w-1.5 rounded-full bg-[var(--md-primary)]" />
            Исход
          </span>
        </div>

        <div className="flex items-center gap-2.5">
          {isConnected ? (
            <span className="flex items-center gap-2 font-mono-num text-[0.65rem] text-[var(--md-on-surface-variant)]">
              <span>Пик: {formatSpeed(rawPeak)}</span>
              {!compact && <span className="opacity-65">•</span>}
              {!compact && <span>Сред. ↓ {formatSpeed(avgRx)}</span>}
              {!compact && <span className="opacity-65">•</span>}
              {!compact && <span data-testid="traffic-avg-up">Сред. ↑ {formatSpeed(avgTx)}</span>}
            </span>
          ) : (
            <span className="font-mono-num text-[0.65rem] text-[var(--md-on-surface-variant)]">
              Ожидание потока
            </span>
          )}

          {!compact && hasData && (
            <M3SegmentedButton
              size="sm"
              value={timeframe}
              onChange={setTimeframe}
              options={TIMEFRAME_OPTIONS}
            />
          )}
        </div>
      </div>

      <div className="relative">
        {hoveredSample && !compact && (
          <div
            data-testid="traffic-graph-tooltip"
            style={{ left: `${hoveredLeftPct}%` }}
            className="pointer-events-none absolute -top-1 z-20 -translate-x-1/2 -translate-y-full rounded-xl bg-[var(--md-inverse-surface)] px-2.5 py-1 text-[0.65rem] text-[var(--md-inverse-on-surface)] shadow-lg whitespace-nowrap font-mono-num"
          >
            <div className="flex items-center gap-2.5">
              <span className="opacity-75">{formatSampleTime(hoveredSample.ts)}</span>
              <span>↓ {formatSpeed(hoveredSample.rx)}</span>
              <span>↑ {formatSpeed(hoveredSample.tx)}</span>
            </div>
          </div>
        )}

        <div className="flex items-stretch gap-2">
          <svg
            ref={svgRef}
            viewBox={`0 0 ${width} ${height}`}
            preserveAspectRatio="none"
            onPointerMove={handlePointerMove}
            onPointerLeave={() => setHoverIdx(null)}
            className={`${compact ? 'h-[36px]' : 'h-[62px]'} w-full flex-1 overflow-visible cursor-crosshair`}
            aria-label="График сетевой активности"
          >
            <defs>
              <linearGradient id="aura-rx-grad-md3" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--md-success)" stopOpacity="0.28" />
                <stop offset="100%" stopColor="var(--md-success)" stopOpacity="0.0" />
              </linearGradient>
              <linearGradient id="aura-tx-grad-md3" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--md-primary)" stopOpacity="0.16" />
                <stop offset="100%" stopColor="var(--md-primary)" stopOpacity="0.0" />
              </linearGradient>
            </defs>

            <line
              x1="0"
              y1={topPad}
              x2={width}
              y2={topPad}
              stroke="var(--md-outline-variant)"
              strokeDasharray="3 4"
              strokeWidth="1"
            />
            <line
              x1="0"
              y1={topPad + plotH / 2}
              x2={width}
              y2={topPad + plotH / 2}
              stroke="var(--md-outline-variant)"
              strokeDasharray="3 4"
              strokeWidth="1"
            />
            <line
              x1="0"
              y1={height - bottomPad}
              x2={width}
              y2={height - bottomPad}
              stroke="var(--md-outline-variant)"
              strokeWidth="1"
            />

            {isConnected && (
              <>
                <path d={txArea} fill="url(#aura-tx-grad-md3)" />
                <path d={rxArea} fill="url(#aura-rx-grad-md3)" />
                <path
                  d={txLine}
                  fill="none"
                  stroke="var(--md-primary)"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  opacity="0.88"
                />
                <path
                  d={rxLine}
                  fill="none"
                  stroke="var(--md-success)"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />

                {hoverIdx !== null && hoveredRxCoord && hoveredTxCoord && (
                  <>
                    <line
                      x1={hoveredRxCoord.x}
                      y1={topPad}
                      x2={hoveredRxCoord.x}
                      y2={height - bottomPad}
                      stroke="var(--md-on-surface-variant)"
                      strokeDasharray="2 3"
                      strokeWidth="1"
                      opacity="0.7"
                    />
                    <circle
                      cx={hoveredTxCoord.x}
                      cy={hoveredTxCoord.y}
                      r="3.2"
                      fill="var(--md-primary)"
                      stroke="var(--md-surface)"
                      strokeWidth="1.2"
                    />
                    <circle
                      cx={hoveredRxCoord.x}
                      cy={hoveredRxCoord.y}
                      r="3.8"
                      fill="var(--md-success)"
                      stroke="var(--md-surface)"
                      strokeWidth="1.4"
                    />
                  </>
                )}
              </>
            )}
          </svg>

          {!compact && (
            <div className="flex shrink-0 flex-col justify-between py-0.5 text-right text-[0.6rem] text-[var(--md-on-surface-variant)]/80 font-mono-num">
              <span>{formatAxisLabel(ceiling)}</span>
              <span>{formatAxisLabel(Math.round(ceiling / 2))}</span>
              <span>0</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
