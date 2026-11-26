import { KeyRound, Lock, RefreshCw, ShieldCheck, Trash2 } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { DEFAULT_SETTINGS } from '../../config/defaultSettings';
import { api } from '../../services/api';
import type {
  AppSettings,
  PrivacyInventory,
  PrivacyPurgeReport,
  PrivacyPurgeScope,
} from '../../types/vpn';
import { M3Button, M3Checkbox, M3StatusBadge, M3SurfaceCard, M3Switch } from '../md3';
import { SettingMetaRow } from './SettingMetaRow';

interface PrivacyCenterPanelProps {
  settings: AppSettings;
  onUpdateSettings: (next: AppSettings) => void;
  onRefreshBootstrap?: () => Promise<void>;
  highlightSettingId?: string | null;
}

const DEFAULT_SCOPE: PrivacyPurgeScope = {
  clearHistory: true,
  clearOriginalIp: false,
  clearVpnIp: true,
  clearLogs: true,
  clearServerQuality: false,
  clearSubBackups: false,
  clearSyncHistory: false,
  clearProfileEditHistory: false,
};

export function PrivacyCenterPanel({
  settings,
  onUpdateSettings,
  onRefreshBootstrap,
  highlightSettingId,
}: PrivacyCenterPanelProps) {
  const [inv, setInv] = useState<PrivacyInventory | null>(null);
  const [scope, setScope] = useState<PrivacyPurgeScope>(DEFAULT_SCOPE);
  const [purging, setPurging] = useState(false);
  const [purgeReport, setPurgeReport] = useState<PrivacyPurgeReport | null>(null);
  const [rotating, setRotating] = useState(false);

  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const res = await api.getPrivacyInventory();
      setInv(res);
    } catch (err) {
      setError(typeof err === 'string' ? err : String(err));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const handleRotateHwid = async () => {
    setRotating(true);
    setError(null);
    try {
      await api.rotateDeviceHwid();
      await onRefreshBootstrap?.();
      await load();
    } catch (err) {
      setError(typeof err === 'string' ? err : String(err));
    } finally {
      setRotating(false);
    }
  };

  const handlePurge = async () => {
    setPurging(true);
    setError(null);
    try {
      const rep = await api.purgePrivacyData(scope);
      if (scope.clearLogs || scope.clearHistory) {
        const { notificationStore } = await import('../../stores/notificationStore');
        notificationStore.clear();
      }
      if (scope.clearServerQuality || scope.clearHistory) {
        const { liveStore } = await import('../../stores/liveStore');
        liveStore.clearLatencyMeta();
      }
      setPurgeReport(rep);
      await onRefreshBootstrap?.();
      await load();
    } catch (err) {
      setError(typeof err === 'string' ? err : String(err));
    } finally {
      setPurging(false);
    }
  };

  return (
    <div className="space-y-3" data-testid="panel-privacy-center">
      <SettingMetaRow
        id="privacy-hwid"
        level="basic"
        title="Идентификатор устройства (HWID) и история подключений"
        description="Управление отправкой HWID провайдеру подписки и локальной статистикой трафика"
        defaultLabel="HWID Вкл. • История Вкл."
        impact="Выключение HWID повышает приватность, но некоторые панели подписок могут ограничивать число устройств."
        compatibility="Все ключи и токены на диске зашифрованы Windows DPAPI"
        highlighted={highlightSettingId === 'privacy-hwid'}
        modified={
          settings.sendHwid !== DEFAULT_SETTINGS.sendHwid ||
          settings.historyEnabled !== DEFAULT_SETTINGS.historyEnabled
        }
        onReset={() =>
          onUpdateSettings({
            ...settings,
            sendHwid: DEFAULT_SETTINGS.sendHwid,
            historyEnabled: DEFAULT_SETTINGS.historyEnabled,
          })
        }
      >
        <div className="space-y-2.5">
          <div className="flex items-center justify-between rounded-xl bg-[var(--md-surface-container)] px-3 py-2 text-[0.72rem]">
            <span>Передавать HWID устройства (только HTTPS-домену подписки)</span>
            <M3Switch
              checked={settings.sendHwid}
              onChange={(sendHwid) => onUpdateSettings({ ...settings, sendHwid })}
              ariaLabel="Передавать HWID"
            />
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl bg-[var(--md-surface-container)] px-3 py-2 text-[0.72rem]">
            <div>
              <span>Текущий HWID: </span>
              <span className="font-mono font-semibold text-[var(--md-on-surface)]">
                {inv?.hwidMasked ?? '••••'}
              </span>
            </div>
            <M3Button
              size="sm"
              variant="tonal"
              loading={rotating}
              onClick={() => void handleRotateHwid()}
              leadingIcon={<KeyRound className="h-3.5 w-3.5" />}
            >
              Перевыпустить HWID
            </M3Button>
          </div>

          <div className="flex items-center justify-between rounded-xl bg-[var(--md-surface-container)] px-3 py-2 text-[0.72rem]">
            <span>Сохранять историю сессий и статистику трафика</span>
            <M3Switch
              checked={settings.historyEnabled}
              onChange={(historyEnabled) => onUpdateSettings({ ...settings, historyEnabled })}
              ariaLabel="Сохранять историю подключений"
            />
          </div>
        </div>
      </SettingMetaRow>

      {/* DPAPI Inventory & Network Transparency */}
      <M3SurfaceCard level="default" className="p-3.5 space-y-3">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Lock className="h-4 w-4 text-[var(--md-success)]" />
            <h3 className="text-[0.82rem] font-bold text-[var(--md-on-surface)]">
              Инвентарь локальных данных и сетевая прозрачность
            </h3>
          </div>
          <M3Button
            size="sm"
            variant="outlined"
            onClick={() => void load()}
            leadingIcon={<RefreshCw className="h-3.5 w-3.5" />}
          >
            Обновить
          </M3Button>
        </div>

        {inv && (
          <div className="space-y-2.5 text-[0.7rem]">
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              <div className="rounded-xl bg-[var(--md-surface-container-low)] p-2.5 space-y-1">
                <div className="flex items-center gap-1.5 font-semibold text-[var(--md-on-surface)]">
                  <ShieldCheck className="h-3.5 w-3.5 text-[var(--md-success)]" />
                  Зашифровано Windows DPAPI:
                </div>
                <div className="font-mono text-[0.65rem] text-[var(--md-on-surface-variant)]">
                  {inv.dpapiEncryptedFiles.join(', ') || 'нет файлов'}
                </div>
              </div>
              <div className="rounded-xl bg-[var(--md-surface-container-low)] p-2.5 space-y-1">
                <div className="font-semibold text-[var(--md-on-surface)]">Локальные счётчики:</div>
                <div className="text-[var(--md-on-surface-variant)]">
                  История сессий: {inv.historyEntriesCount} • Логи в памяти: {inv.logsCount} • Бэкапы подписок: {inv.subBackupsCount}
                </div>
              </div>
            </div>

            <div className="space-y-1.5">
              <div className="font-semibold text-[var(--md-on-surface)]">
                Какие сетевые запросы может выполнять клиент (без скрытой телеметрии):
              </div>
              {inv.externalNetworkFeatures.map((feat) => (
                <div
                  key={feat.id}
                  className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] px-3 py-2"
                >
                  <div className="min-w-0 flex-1">
                    <div className="font-semibold text-[var(--md-on-surface)]">{feat.title}</div>
                    <div className="text-[0.65rem] text-[var(--md-on-surface-variant)]">
                      Триггер: {feat.trigger} • Назначение: {feat.destination}
                    </div>
                  </div>
                  <M3StatusBadge tone={feat.enabled ? 'primary' : 'neutral'}>
                    {feat.enabled ? 'Разрешено' : 'Вручную'}
                  </M3StatusBadge>
                </div>
              ))}
            </div>
          </div>
        )}
      </M3SurfaceCard>

      {/* Selective Purge */}
      <M3SurfaceCard level="default" className="p-3.5 space-y-2.5">
        <div className="flex items-center gap-2">
          <Trash2 className="h-4 w-4 text-[var(--md-error)]" />
          <h3 className="text-[0.82rem] font-bold text-[var(--md-on-surface)]">
            Выборочная очистка приватных данных
          </h3>
        </div>
        <div className="grid grid-cols-1 gap-2 text-[0.72rem] sm:grid-cols-2">
          {(
            [
              ['clearHistory', 'История подключений'],
              ['clearOriginalIp', 'Сохранённый реальный IP'],
              ['clearVpnIp', 'Кэш выходного VPN IP'],
              ['clearLogs', 'Журнал событий ядра'],
              ['clearServerQuality', 'Метрики качества узлов'],
              ['clearSubBackups', 'Локальные бэкапы подписок'],
              ['clearSyncHistory', 'История синхронизаций подписок'],
              ['clearProfileEditHistory', 'Ревизии Config Studio'],
            ] as Array<[keyof PrivacyPurgeScope, string]>
          ).map(([key, label]) => (
            <label key={key} className="flex items-center gap-2 cursor-pointer">
              <M3Checkbox
                checked={scope[key]}
                onChange={(checked) => setScope((p) => ({ ...p, [key]: checked }))}
                ariaLabel={label}
              />
              <span>{label}</span>
            </label>
          ))}
        </div>

        {error && (
          <div className="rounded-xl bg-[var(--md-error-container)] px-3 py-2 text-[0.72rem] text-[var(--md-error)]">
            {error}
          </div>
        )}

        {purgeReport && (
          <div className="rounded-xl bg-[var(--md-success-container)] px-3 py-2 text-[0.72rem] text-[var(--md-success)]">
            {purgeReport.summary}
          </div>
        )}

        <div className="flex justify-end">
          <M3Button
            size="sm"
            variant="danger"
            loading={purging}
            onClick={() => void handlePurge()}
            leadingIcon={<Trash2 className="h-3.5 w-3.5" />}
          >
            Очистить выбранное
          </M3Button>
        </div>
      </M3SurfaceCard>
    </div>
  );
}
