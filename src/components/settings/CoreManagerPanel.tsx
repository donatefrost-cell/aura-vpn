import { CheckCircle2, Cpu, RefreshCw, ShieldAlert, ShieldCheck } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { DEFAULT_SETTINGS } from '../../config/defaultSettings';
import { api } from '../../services/api';
import type {
  AppSettings,
  CoreInventorySnapshot,
  CoreKind,
  CoreSelectionMode,
  CoreUpdateCheckResult,
} from '../../types/vpn';
import { formatBytes } from '../../utils/format';
import { M3Button, M3SegmentedButton, M3StatusBadge, M3SurfaceCard } from '../md3';
import { SettingMetaRow } from './SettingMetaRow';

interface CoreManagerPanelProps {
  settings: AppSettings;
  onUpdateSettings: (next: AppSettings) => void;
  highlightSettingId?: string | null;
}

export function CoreManagerPanel({
  settings,
  onUpdateSettings,
  highlightSettingId,
}: CoreManagerPanelProps) {
  const [inventory, setInventory] = useState<CoreInventorySnapshot | null>(null);
  const [loading, setLoading] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [checkingKind, setCheckingKind] = useState<CoreKind | null>(null);
  const [updateResults, setUpdateResults] = useState<Partial<Record<CoreKind, CoreUpdateCheckResult>>>({});
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const inv = await api.getCoreInventory();
      setInventory(inv);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const adv = settings.advanced ?? DEFAULT_SETTINGS.advanced!;

  const handleVerifyIntegrity = async () => {
    setVerifying(true);
    setError(null);
    try {
      await api.verifyCoreIntegrity();
      await load();
    } catch (err) {
      setError(String(err));
    } finally {
      setVerifying(false);
    }
  };

  const handleCheckUpdate = async (kind: CoreKind) => {
    setCheckingKind(kind);
    try {
      const res = await api.checkCoreUpdates(kind);
      setUpdateResults((prev) => ({ ...prev, [kind]: res }));
    } catch (err) {
      setError(String(err));
    } finally {
      setCheckingKind(null);
    }
  };

  return (
    <div className="space-y-3" data-testid="panel-core-manager">
      <SettingMetaRow
        id="core-selection"
        level="basic"
        title="Выбор ядра маршрутизации"
        description="Автоматический выбор или явное назначение движка (при несовместимости с протоколом запуск будет безопасно отклонён)"
        defaultLabel="Авто"
        recommendedLabel="Авто"
        impact="Для WireGuard можно переключить между нативным Xray-core и wireproxy-awg; для остальных протоколов выбирается совместимое ядро."
        compatibility="VLESS/VMess/Trojan/Hysteria2 работают в Xray-core; AmneziaWG требует wireproxy-awg"
        requiresReconnect
        modified={adv.coreSelection !== DEFAULT_SETTINGS.advanced!.coreSelection}
        highlighted={highlightSettingId === 'core-selection'}
        onReset={() =>
          onUpdateSettings({
            ...settings,
            advanced: { ...adv, coreSelection: DEFAULT_SETTINGS.advanced!.coreSelection },
          })
        }
        control={
          <M3SegmentedButton<CoreSelectionMode>
            size="sm"
            value={adv.coreSelection}
            onChange={(coreSelection) =>
              onUpdateSettings({
                ...settings,
                advanced: { ...adv, coreSelection },
              })
            }
            options={[
              { id: 'auto', label: 'Авто' },
              { id: 'xray', label: 'Xray-core' },
              { id: 'wireproxy_awg', label: 'wireproxy-awg' },
            ]}
          />
        }
      />

      {/* Action header */}
      <M3SurfaceCard level="default" className="p-3.5 space-y-2.5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Cpu className="h-4 w-4 text-[var(--md-primary)]" />
            <div>
              <h3 className="text-[0.82rem] font-bold text-[var(--md-on-surface)]">
                Установленные ядра и системные компоненты
              </h3>
              <p className="text-[0.7rem] text-[var(--md-on-surface-variant)]">
                Инвентарь, права запуска, проверка SHA-256 по вшитому манифесту сборки и проверка обновлений GitHub Releases
              </p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <M3Button
              size="sm"
              variant="tonal"
              loading={verifying}
              onClick={() => void handleVerifyIntegrity()}
              leadingIcon={<ShieldCheck className="h-3.5 w-3.5" />}
            >
              Проверить SHA-256
            </M3Button>
            <M3Button
              size="sm"
              variant="outlined"
              loading={loading}
              onClick={() => void load()}
              leadingIcon={<RefreshCw className="h-3.5 w-3.5" />}
            >
              Обновить
            </M3Button>
          </div>
        </div>

        {error && (
          <div className="rounded-xl bg-[var(--md-error-container)] px-3 py-2 text-[0.72rem] text-[var(--md-error)]">
            {error}
          </div>
        )}

        {inventory?.singBoxNote && (
          <div className="rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] px-3 py-2 text-[0.7rem] text-[var(--md-on-surface-variant)]">
            <span className="font-semibold text-[var(--md-on-surface)]">О sing-box: </span>
            {inventory.singBoxNote}
          </div>
        )}

        {/* Cores list */}
        <div className="space-y-2">
          {inventory?.cores.map((core) => {
            const upd = updateResults[core.kind];
            return (
              <div
                key={core.id}
                className="rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] p-3 space-y-2"
              >
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[0.8rem] font-bold text-[var(--md-on-surface)]">
                        {core.name}
                      </span>
                      <span className="rounded-md bg-[var(--md-surface-container-highest)] px-1.5 py-0.5 font-mono-num text-[0.65rem] text-[var(--md-on-surface)]">
                        {core.version}
                      </span>
                      <M3StatusBadge tone={core.integrityOk ? 'success' : 'error'}>
                        {core.integrityOk ? 'SHA-256 OK' : 'Нарушена целостность'}
                      </M3StatusBadge>
                      {core.isActive && (
                        <M3StatusBadge tone="primary">Активно</M3StatusBadge>
                      )}
                      <span className="text-[0.65rem] text-[var(--md-on-surface-variant)]">
                        {core.license} • {core.arch} • {formatBytes(core.sizeBytes)}
                      </span>
                    </div>
                    <div className="mt-1 truncate font-mono text-[0.65rem] text-[var(--md-on-surface-variant)]">
                      {core.path}
                    </div>
                    <div className="mt-1 text-[0.6875rem] text-[var(--md-on-surface-variant)]">
                      Источник: {core.sourceOrigin} • {core.permissionsNote}
                    </div>
                    {core.sha256 && (
                      <div className="mt-0.5 truncate font-mono text-[0.625rem] text-[var(--md-on-surface-variant)]">
                        SHA-256: {core.sha256}
                      </div>
                    )}
                  </div>

                  <div className="shrink-0">
                    <M3Button
                      size="sm"
                      variant="outlined"
                      loading={checkingKind === core.kind}
                      onClick={() => void handleCheckUpdate(core.kind)}
                    >
                      Проверить релиз
                    </M3Button>
                  </div>
                </div>

                {upd && (
                  <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg bg-[var(--md-surface-container)] px-2.5 py-1.5 text-[0.6875rem]">
                    <div className="flex items-center gap-1.5">
                      {upd.updateAvailable ? (
                        <ShieldAlert className="h-3.5 w-3.5 text-[var(--md-warning)]" />
                      ) : (
                        <CheckCircle2 className="h-3.5 w-3.5 text-[var(--md-success)]" />
                      )}
                      <span className="text-[var(--md-on-surface)]">{upd.message}</span>
                    </div>
                    {upd.releaseUrl && (
                      <button
                        type="button"
                        onClick={() => void navigator.clipboard?.writeText(upd.releaseUrl ?? '')}
                        title="Скопировать ссылку на релиз"
                        className="font-mono text-[0.625rem] text-[var(--md-primary)] underline-offset-2 hover:underline"
                      >
                        {upd.releaseUrl} (копировать)
                      </button>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </M3SurfaceCard>

      {/* Compatibility Matrix */}
      {inventory && inventory.compatibilityMatrix.length > 0 && (
        <M3SurfaceCard level="default" className="p-3.5 space-y-2">
          <h3 className="text-[0.8rem] font-bold text-[var(--md-on-surface)]">
            Матрица совместимости протоколов и ядер
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[0.6875rem]">
              <thead>
                <tr className="border-b border-[var(--md-outline-variant)] text-[var(--md-on-surface-variant)]">
                  <th className="py-1.5 pr-3">Протокол</th>
                  <th className="py-1.5 pr-3">Ядро</th>
                  <th className="py-1.5 pr-3">Доп. модули</th>
                  <th className="py-1.5">Примечание</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--md-outline-variant)]/50">
                {inventory.compatibilityMatrix.map((row) => (
                  <tr key={row.protocol}>
                    <td className="py-1.5 pr-3 font-semibold text-[var(--md-on-surface)]">
                      {row.protocolLabel}
                    </td>
                    <td className="py-1.5 pr-3 font-mono text-[var(--md-primary)]">
                      {row.supportedCores.join(' / ')}
                    </td>
                    <td className="py-1.5 pr-3 text-[var(--md-on-surface-variant)]">
                      {row.requiredAux ?? '—'}
                    </td>
                    <td className="py-1.5 text-[var(--md-on-surface-variant)]">{row.notes}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </M3SurfaceCard>
      )}
    </div>
  );
}
