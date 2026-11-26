import { Download, Play, Stethoscope } from 'lucide-react';
import { useState } from 'react';
import { api } from '../../services/api';
import type { DoctorCheckSeverity, NetworkDoctorReport } from '../../types/vpn';
import { M3Button, M3StatusBadge, M3SurfaceCard, M3Switch } from '../md3';

interface NetworkDoctorPanelProps {
  onExportDiagnostics?: () => Promise<void>;
  onOpenConnectionInspector?: () => void;
}

const SEV_META: Record<DoctorCheckSeverity, { label: string; tone: 'success' | 'warning' | 'error' | 'neutral' }> = {
  pass: { label: 'OK', tone: 'success' },
  warn: { label: 'Внимание', tone: 'warning' },
  fail: { label: 'Сбой', tone: 'error' },
  info: { label: 'Инфо', tone: 'neutral' },
  skipped: { label: 'Пропущено', tone: 'neutral' },
};

export function NetworkDoctorPanel({
  onExportDiagnostics,
  onOpenConnectionInspector,
}: NetworkDoctorPanelProps) {
  const [report, setReport] = useState<NetworkDoctorReport | null>(null);
  const [running, setRunning] = useState(false);
  const [includeExternal, setIncludeExternal] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const runSuite = async () => {
    setRunning(true);
    setError(null);
    try {
      const res = await api.runNetworkDoctor(includeExternal);
      setReport(res);
    } catch (err) {
      setError(String(err));
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="space-y-3" data-testid="panel-network-doctor">
      <M3SurfaceCard level="default" className="p-3.5 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Stethoscope className="h-4 w-4 text-[var(--md-primary)]" />
            <div>
              <h3 className="text-[0.82rem] font-bold text-[var(--md-on-surface)]">
                Сетевой доктор — 12 комплексных проверок
              </h3>
              <p className="text-[0.7rem] text-[var(--md-on-surface-variant)]">
                Целостность ядер, порты Windows и excludedportrange, TUN/Wintun, Kill Switch, DNS и сквозная проверка туннеля
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {onOpenConnectionInspector && (
              <M3Button size="sm" variant="outlined" onClick={onOpenConnectionInspector}>
                Инспектор туннеля
              </M3Button>
            )}
            {onExportDiagnostics && (
              <M3Button
                size="sm"
                variant="tonal"
                onClick={() => void onExportDiagnostics()}
                leadingIcon={<Download className="h-3.5 w-3.5" />}
              >
                Экспорт (без секретов)
              </M3Button>
            )}
            <M3Button
              size="sm"
              variant="filled"
              loading={running}
              onClick={() => void runSuite()}
              leadingIcon={<Play className="h-3.5 w-3.5" />}
            >
              Запустить проверки
            </M3Button>
          </div>
        </div>

        <div className="flex items-center justify-between rounded-xl bg-[var(--md-surface-container-low)] px-3 py-2 text-[0.7rem]">
          <span>Включать внешние сетевые проверки (DNS, TCP пинг узла, HTTPS 204 через туннель)</span>
          <M3Switch
            checked={includeExternal}
            onChange={setIncludeExternal}
            ariaLabel="Включать внешние сетевые проверки"
          />
        </div>

        {error && (
          <div className="rounded-xl bg-[var(--md-error-container)] px-3 py-2 text-[0.72rem] text-[var(--md-error)]">
            {error}
          </div>
        )}

        {report && (
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2 text-[0.72rem]">
              <M3StatusBadge tone={SEV_META[report.overallStatus].tone}>
                Итог: {SEV_META[report.overallStatus].label}
              </M3StatusBadge>
              <span className="font-mono-num text-[var(--md-success)]">Пройдено: {report.passCount}</span>
              <span className="font-mono-num text-[var(--md-warning)]">Внимание: {report.warnCount}</span>
              <span className="font-mono-num text-[var(--md-error)]">Сбоев: {report.failCount}</span>
            </div>

            <div className="space-y-1.5">
              {report.checks.map((chk) => {
                const meta = SEV_META[chk.severity];
                return (
                  <div
                    key={chk.id}
                    className="rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] p-2.5 text-[0.7rem]"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <M3StatusBadge tone={meta.tone}>{meta.label}</M3StatusBadge>
                        <span className="font-bold text-[var(--md-on-surface)]">{chk.title}</span>
                        <span className="text-[0.625rem] text-[var(--md-on-surface-variant)]">
                          [{chk.category}]
                        </span>
                      </div>
                      <span className="font-mono-num text-[0.65rem] text-[var(--md-on-surface-variant)]">
                        {chk.durationMs} мс
                      </span>
                    </div>
                    <div className="mt-1 font-medium text-[var(--md-on-surface)]">{chk.summary}</div>
                    <div className="text-[0.6875rem] text-[var(--md-on-surface-variant)]">{chk.detail}</div>
                    {chk.recommendedAction && (
                      <div className="mt-1 text-[0.6875rem] font-medium text-[var(--md-primary)]">
                        Рекомендация: {chk.recommendedAction}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </M3SurfaceCard>
    </div>
  );
}
