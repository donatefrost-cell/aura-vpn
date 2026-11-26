import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  Eye,
  EyeOff,
  FileCode2,
  History,
  Layers,
  Play,
  RotateCcw,
  Save,
  ShieldAlert,
  Sparkles,
  X,
} from 'lucide-react';
import { AnimatePresence, motion } from 'motion/react';
import { useCallback, useEffect, useState } from 'react';
import { api } from '../services/api';
import type {
  ConfigStudioView,
  ConfigValidationResult,
  ConnectionMode,
  CoreSelectionMode,
  DnsMode,
  MtuMode,
  ProfileAnalysisReport,
  ProfileOverrides,
  ServerProfile,
} from '../types/vpn';
import { formatProtocolBadge, formatServerDisplayName } from '../utils/format';
import { M3Button, M3IconButton, M3SegmentedButton, M3Select, M3StatusBadge, M3SurfaceCard } from './md3';

type StudioTab = 'overview' | 'inspector' | 'editor' | 'diff' | 'revisions';

interface ConfigStudioModalProps {
  open: boolean;
  server: ServerProfile | null;
  onClose: () => void;
  onAnalyze?: (id: string) => Promise<ProfileAnalysisReport>;
  onApplyOverrides?: (id: string, overrides: ProfileOverrides) => Promise<void>;
  onAfterProfileChange?: () => Promise<void>;
}

export function ConfigStudioModal({
  open,
  server,
  onClose,
  onAnalyze,
  onApplyOverrides,
  onAfterProfileChange,
}: ConfigStudioModalProps) {
  const [tab, setTab] = useState<StudioTab>('overview');
  const [studioView, setStudioView] = useState<ConfigStudioView | null>(null);
  const [analysis, setAnalysis] = useState<ProfileAnalysisReport | null>(null);
  const [revealSecrets, setRevealSecrets] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Overrides form
  const [ovMtuMode, setOvMtuMode] = useState<'default' | MtuMode>('default');
  const [ovMtu, setOvMtu] = useState('');
  const [ovDns, setOvDns] = useState('');
  const [ovDnsMode, setOvDnsMode] = useState<'default' | DnsMode>('default');
  const [ovMode, setOvMode] = useState<'default' | ConnectionMode>('default');
  const [ovCore, setOvCore] = useState<CoreSelectionMode>('auto');
  const [ovTimeout, setOvTimeout] = useState('');
  const [ovMux, setOvMux] = useState<'default' | 'on' | 'off'>('default');
  const [savingOv, setSavingOv] = useState(false);

  // JSON editor
  const [editorJson, setEditorJson] = useState('');
  const [editNote, setEditNote] = useState('');
  const [validation, setValidation] = useState<ConfigValidationResult | null>(null);
  const [validating, setValidating] = useState(false);
  const [savingJson, setSavingJson] = useState(false);
  const [diffLayerChoice, setDiffLayerChoice] = useState<'l1' | 'l2' | 'l4'>('l4');

  const loadStudio = useCallback(async () => {
    if (!server) return;
    setLoading(true);
    setError(null);
    try {
      const [view, rep] = await Promise.all([
        api.getConfigStudioView(server.id, revealSecrets),
        onAnalyze ? onAnalyze(server.id) : api.analyzeServerProfile(server.id),
      ]);
      setStudioView(view);
      setAnalysis(rep);
      setEditorJson(JSON.stringify(view.layer2WithOverrides, null, 2));
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, [server, revealSecrets, onAnalyze]);

  useEffect(() => {
    if (!open || !server) return;
    setTab('overview');
    setValidation(null);
    setEditNote('');
    setOvMtuMode(server.overrides?.mtuMode ?? 'default');
    setOvMtu(server.overrides?.mtu ? String(server.overrides.mtu) : '');
    setOvDns(server.overrides?.customDns ?? '');
    setOvDnsMode(server.overrides?.dnsModeOverride ?? 'default');
    setOvMode(server.overrides?.preferredMode ?? 'default');
    setOvCore(server.overrides?.preferredCore ?? 'auto');
    setOvTimeout(server.overrides?.connectTimeoutSecs ? String(server.overrides.connectTimeoutSecs) : '');
    setOvMux(
      server.overrides?.muxOverride === true
        ? 'on'
        : server.overrides?.muxOverride === false
          ? 'off'
          : 'default',
    );
    void loadStudio();
  }, [open, server?.id, loadStudio]);

  const handleSaveOverrides = async () => {
    if (!server || !onApplyOverrides) return;
    setSavingOv(true);
    setError(null);
    try {
      let parsedMtu: number | null = null;
      if (ovMtu.trim()) {
        const n = Number(ovMtu.trim());
        if (!Number.isInteger(n) || n < 1280 || n > 1500) {
          throw new Error('MTU должен быть целым числом от 1280 до 1500.');
        }
        parsedMtu = n;
      }
      const next: ProfileOverrides = {
        mtuMode: ovMtuMode === 'default' ? null : ovMtuMode,
        mtu: parsedMtu,
        customDns: ovDns.trim() ? ovDns.trim() : null,
        dnsModeOverride: ovDnsMode === 'default' ? null : ovDnsMode,
        preferredMode: ovMode === 'default' ? null : ovMode,
        preferredCore: ovCore === 'auto' ? null : ovCore,
        connectTimeoutSecs: ovTimeout.trim() ? Number(ovTimeout.trim()) : null,
        muxOverride: ovMux === 'default' ? null : ovMux === 'on',
      };
      await onApplyOverrides(server.id, next);
      await loadStudio();
    } catch (err) {
      setError(String(err));
    } finally {
      setSavingOv(false);
    }
  };

  const handleValidateJson = async () => {
    if (!server) return;
    setValidating(true);
    setError(null);
    try {
      const res = await api.validateCustomProfileConfig(server.id, editorJson);
      setValidation(res);
    } catch (err) {
      setError(String(err));
    } finally {
      setValidating(false);
    }
  };

  const handleSaveJson = async () => {
    if (!server) return;
    setSavingJson(true);
    setError(null);
    try {
      await api.saveProfileConfigEdit(server.id, editorJson, editNote.trim() || null);
      await onAfterProfileChange?.();
      await loadStudio();
      setTab('overview');
    } catch (err) {
      setError(String(err));
    } finally {
      setSavingJson(false);
    }
  };

  const handleRollbackRevision = async (revisionId: string) => {
    if (!server) return;
    setLoading(true);
    try {
      await api.rollbackProfileConfig(server.id, revisionId);
      await onAfterProfileChange?.();
      await loadStudio();
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  const handleDuplicate = async () => {
    if (!server) return;
    setLoading(true);
    try {
      await api.duplicateServerProfile(server.id);
      await onAfterProfileChange?.();
      onClose();
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  if (!server) return null;

  const activeJsonPreview =
    diffLayerChoice === 'l1'
      ? studioView?.layer1Imported
      : diffLayerChoice === 'l2'
        ? studioView?.layer2WithOverrides
        : studioView?.layer4FinalSanitized;

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.15 }}
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/65 p-4 backdrop-blur-sm"
          onClick={onClose}
        >
          <motion.div
            role="dialog"
            aria-modal="true"
            aria-label="Config Studio"
            initial={{ opacity: 0, scale: 0.97, y: 8 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.97, y: 8 }}
            transition={{ duration: 0.16, ease: 'easeOut' }}
            onClick={(e) => e.stopPropagation()}
            data-testid="config-studio-modal"
            className="flex max-h-[90vh] w-full max-w-4xl flex-col overflow-hidden rounded-3xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] shadow-2xl"
          >
            {/* Header */}
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--md-outline-variant)] px-5 py-3.5">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <Sparkles className="h-4 w-4 text-[var(--md-primary)]" />
                  <h2 className="truncate font-display text-[0.98rem] font-bold text-[var(--md-on-surface)]">
                    Config Studio — {formatServerDisplayName(server.name, server.countryCode)}
                  </h2>
                  <M3StatusBadge tone="primary" dot={false}>
                    {formatProtocolBadge(server)}
                  </M3StatusBadge>
                  {(server.configRevision ?? 0) > 0 && (
                    <M3StatusBadge tone="neutral" dot={false}>
                      rev #{server.configRevision}
                    </M3StatusBadge>
                  )}
                </div>
                <div className="text-[0.7rem] text-[var(--md-on-surface-variant)]">
                  Инспектор протокола, переопределения, Xray JSON-редактор, 4-уровневый diff и история ревизий
                </div>
              </div>

              <div className="flex items-center gap-2">
                <M3Button
                  size="sm"
                  variant="tonal"
                  onClick={() => void handleDuplicate()}
                  leadingIcon={<Copy className="h-3.5 w-3.5" />}
                >
                  Дублировать
                </M3Button>
                <M3IconButton onClick={onClose} aria-label="Закрыть Config Studio">
                  <X className="h-4 w-4" />
                </M3IconButton>
              </div>
            </div>

            {/* Tabs */}
            <div className="flex flex-wrap items-center gap-2 border-b border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] px-5 py-2">
              <M3SegmentedButton<StudioTab>
                size="sm"
                value={tab}
                onChange={setTab}
                options={[
                  { id: 'overview', label: 'Обзор и Overrides' },
                  { id: 'inspector', label: 'Инспектор протокола' },
                  { id: 'editor', label: 'JSON-редактор' },
                  { id: 'diff', label: '4 слоя и Diff' },
                  { id: 'revisions', label: `Ревизии (${studioView?.revisions.length ?? 0})` },
                ]}
              />
            </div>

            {/* Body */}
            <div className="aura-scroll flex-1 space-y-3.5 overflow-y-auto px-5 py-4">
              {error && (
                <div className="rounded-xl bg-[var(--md-error-container)] px-3 py-2 text-[0.75rem] text-[var(--md-error)]">
                  {error}
                </div>
              )}

              {tab === 'overview' && (
                <div className="space-y-3">
                  {studioView && (
                    <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-4">
                      <M3SurfaceCard level="default" className="p-3 space-y-0.5">
                        <div className="text-[0.65rem] text-[var(--md-on-surface-variant)]">Ядро</div>
                        <div className="text-[0.8rem] font-bold text-[var(--md-on-surface)]">
                          {studioView.effectiveCore}
                        </div>
                      </M3SurfaceCard>
                      <M3SurfaceCard level="default" className="p-3 space-y-0.5">
                        <div className="text-[0.65rem] text-[var(--md-on-surface-variant)]">MTU ({studioView.mtuSource})</div>
                        <div className="font-mono-num text-[0.8rem] font-bold text-[var(--md-on-surface)]">
                          {studioView.effectiveMtu}
                        </div>
                      </M3SurfaceCard>
                      <M3SurfaceCard level="default" className="p-3 space-y-0.5">
                        <div className="text-[0.65rem] text-[var(--md-on-surface-variant)]">DNS ({studioView.dnsSource})</div>
                        <div className="truncate font-mono text-[0.76rem] font-bold text-[var(--md-on-surface)]">
                          {studioView.effectiveDns}
                        </div>
                      </M3SurfaceCard>
                      <M3SurfaceCard level="default" className="p-3 space-y-0.5">
                        <div className="text-[0.65rem] text-[var(--md-on-surface-variant)]">Режим ({studioView.modeSource})</div>
                        <div className="text-[0.8rem] font-bold text-[var(--md-on-surface)]">
                          {studioView.effectiveMode === 'tun' ? 'TUN (весь ПК)' : 'Системный прокси'}
                        </div>
                      </M3SurfaceCard>
                    </div>
                  )}

                  {analysis && analysis.warnings.length > 0 && (
                    <div className="rounded-xl bg-[var(--md-warning-container)]/50 px-3.5 py-2.5 text-[0.72rem] space-y-1">
                      <div className="flex items-center gap-1.5 font-semibold text-[var(--md-warning)]">
                        <AlertTriangle className="h-3.5 w-3.5" />
                        Предупреждения совместимости:
                      </div>
                      {analysis.warnings.map((w, i) => (
                        <div key={i} className="text-[var(--md-on-surface)]">• {w}</div>
                      ))}
                    </div>
                  )}

                  <M3SurfaceCard level="default" className="p-4 space-y-3">
                    <div className="text-[0.82rem] font-bold text-[var(--md-on-surface)]">
                      Индивидуальные переопределения профиля
                    </div>
                    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
                      <div className="space-y-1 text-[0.72rem]">
                        <span className="text-[var(--md-on-surface-variant)]">Ядро запуска</span>
                        <M3Select
                          size="sm"
                          ariaLabel="Ядро профиля"
                          value={ovCore}
                          onChange={(v) => setOvCore(v as CoreSelectionMode)}
                          options={[
                            { value: 'auto', label: 'Как в глобальных (Авто)' },
                            { value: 'xray', label: 'Xray-core' },
                            { value: 'wireproxy_awg', label: 'wireproxy-awg' },
                          ]}
                        />
                      </div>

                      <div className="space-y-1 text-[0.72rem]">
                        <span className="text-[var(--md-on-surface-variant)]">Режим перехвата</span>
                        <M3Select
                          size="sm"
                          ariaLabel="Режим перехвата профиля"
                          value={ovMode}
                          onChange={(v) => setOvMode(v as 'default' | ConnectionMode)}
                          options={[
                            { value: 'default', label: 'Глобальный' },
                            { value: 'system_proxy', label: 'Системный прокси' },
                            { value: 'tun', label: 'TUN (весь ПК)' },
                          ]}
                        />
                      </div>

                      <div className="space-y-1 text-[0.72rem]">
                        <span className="text-[var(--md-on-surface-variant)]">Стратегия MTU</span>
                        <M3Select
                          size="sm"
                          ariaLabel="MTU режим профиля"
                          value={ovMtuMode}
                          onChange={(v) => setOvMtuMode(v as 'default' | MtuMode)}
                          options={[
                            { value: 'default', label: 'Глобальная' },
                            { value: 'auto', label: 'Авто' },
                            { value: 'profile', label: 'Из профиля' },
                            { value: 'manual', label: 'Ручной MTU' },
                          ]}
                        />
                      </div>

                      <label className="space-y-1 text-[0.72rem]">
                        <span className="text-[var(--md-on-surface-variant)]">MTU вручную (1280–1500)</span>
                        <input
                          type="number"
                          min={1280}
                          max={1500}
                          value={ovMtu}
                          onChange={(e) => setOvMtu(e.target.value)}
                          placeholder="По умолчанию"
                          className="w-full rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] px-3 py-1.5 font-mono-num text-[0.72rem]"
                        />
                      </label>

                      <label className="space-y-1 text-[0.72rem]">
                        <span className="text-[var(--md-on-surface-variant)]">DNS профиля (IP / DoH)</span>
                        <input
                          type="text"
                          value={ovDns}
                          onChange={(e) => setOvDns(e.target.value)}
                          placeholder="Глобальный DNS"
                          className="w-full rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] px-3 py-1.5 font-mono text-[0.72rem]"
                        />
                      </label>

                      <div className="space-y-1 text-[0.72rem]">
                        <span className="text-[var(--md-on-surface-variant)]">Мультиплексирование (Mux)</span>
                        <M3Select
                          size="sm"
                          ariaLabel="Mux профиля"
                          value={ovMux}
                          onChange={(v) => setOvMux(v as 'default' | 'on' | 'off')}
                          options={[
                            { value: 'default', label: 'Глобальный' },
                            { value: 'on', label: 'Разрешить (где безопасно)' },
                            { value: 'off', label: 'Запретить' },
                          ]}
                        />
                      </div>
                    </div>

                    <div className="flex justify-end gap-2 pt-1">
                      <M3Button
                        size="sm"
                        variant="filled"
                        loading={savingOv}
                        onClick={() => void handleSaveOverrides()}
                        leadingIcon={<Save className="h-3.5 w-3.5" />}
                      >
                        Применить переопределения
                      </M3Button>
                    </div>
                  </M3SurfaceCard>
                </div>
              )}

              {tab === 'inspector' && (
                <div className="space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="text-[0.75rem] text-[var(--md-on-surface-variant)]">
                      Раскрытие UUID/паролей и приватных ключей выполняется только по кнопке
                    </div>
                    <M3Button
                      size="sm"
                      variant="outlined"
                      onClick={() => setRevealSecrets((v) => !v)}
                      leadingIcon={revealSecrets ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                    >
                      {revealSecrets ? 'Скрыть секреты' : 'Показать секреты'}
                    </M3Button>
                  </div>

                  {analysis && (
                    <M3SurfaceCard level="default" className="p-3.5 grid grid-cols-2 gap-2 text-[0.72rem] sm:grid-cols-3">
                      <div>Транспорт: <span className="font-semibold">{analysis.capabilities.transport}</span></div>
                      <div>Безопасность: <span className="font-semibold">{analysis.capabilities.security}</span></div>
                      <div>UDP: <span className="font-semibold">{analysis.capabilities.requiresUdp ? 'Да' : 'Нет'}</span></div>
                      <div>Узлов / балансир: <span className="font-semibold">{analysis.capabilities.nodeCount} / {analysis.capabilities.hasBalancer ? 'Да' : 'Нет'}</span></div>
                      <div className="col-span-2">Фичи: <span className="font-mono text-[0.68rem]">{analysis.capabilities.features.join(', ') || '—'}</span></div>
                    </M3SurfaceCard>
                  )}

                  {studioView?.awgConfigPreview && (
                    <M3SurfaceCard level="default" className="p-3.5 space-y-1.5">
                      <div className="text-[0.75rem] font-bold">wireproxy-awg конфигурация (INI)</div>
                      <pre className="aura-scroll max-h-60 overflow-auto rounded-xl bg-[var(--md-surface-container-low)] p-3 font-mono text-[0.68rem]">
                        {studioView.awgConfigPreview}
                      </pre>
                    </M3SurfaceCard>
                  )}

                  {studioView && (
                    <M3SurfaceCard level="default" className="p-3.5 space-y-1.5">
                      <div className="text-[0.75rem] font-bold">Layer 1 — Импортированный outbound</div>
                      <pre className="aura-scroll max-h-72 overflow-auto rounded-xl bg-[var(--md-surface-container-low)] p-3 font-mono text-[0.68rem]">
                        {JSON.stringify(studioView.layer1Imported, null, 2)}
                      </pre>
                    </M3SurfaceCard>
                  )}
                </div>
              )}

              {tab === 'editor' && (
                <div className="space-y-3">
                  <div className="rounded-xl bg-[var(--md-surface-container-low)] px-3 py-2 text-[0.7rem] text-[var(--md-on-surface-variant)]">
                    <FileCode2 className="mr-1.5 inline h-3.5 w-3.5 text-[var(--md-primary)]" />
                    Перед сохранением выполняется политика безопасности (удаление опасных полей вроде allowInsecure / masterKeyLog / fs-путей) и проверка конфига через <code className="font-mono">xray -test</code>.
                  </div>

                  <textarea
                    aria-label="JSON конфигурация outbound Xray"
                    value={editorJson}
                    onChange={(e) => setEditorJson(e.target.value)}
                    rows={13}
                    spellCheck={false}
                    className="w-full rounded-2xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] p-3 font-mono text-[0.7rem] text-[var(--md-on-surface)] focus:border-[var(--md-primary)] focus:outline-none"
                  />

                  <div className="flex flex-wrap items-center gap-2">
                    <input
                      type="text"
                      aria-label="Комментарий к ревизии"
                      value={editNote}
                      onChange={(e) => setEditNote(e.target.value)}
                      placeholder="Комментарий к ревизии (необязательно)"
                      className="min-w-[200px] flex-1 rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] px-3 py-1.5 text-[0.72rem]"
                    />
                    <M3Button
                      size="sm"
                      variant="tonal"
                      loading={validating}
                      onClick={() => void handleValidateJson()}
                      leadingIcon={<Play className="h-3.5 w-3.5" />}
                    >
                      Проверить (xray -test)
                    </M3Button>
                    <M3Button
                      size="sm"
                      variant="filled"
                      loading={savingJson}
                      onClick={() => void handleSaveJson()}
                      leadingIcon={<Save className="h-3.5 w-3.5" />}
                    >
                      Сохранить в профиль
                    </M3Button>
                  </div>

                  {validation && (
                    <div
                      className={`rounded-xl border p-3 text-[0.72rem] space-y-1 ${
                        validation.ok
                          ? 'border-[var(--md-success)]/40 bg-[var(--md-success-container)]/40'
                          : 'border-[var(--md-error)]/40 bg-[var(--md-error-container)]/50'
                      }`}
                    >
                      <div className="flex items-center gap-1.5 font-bold">
                        {validation.ok ? (
                          <CheckCircle2 className="h-4 w-4 text-[var(--md-success)]" />
                        ) : (
                          <ShieldAlert className="h-4 w-4 text-[var(--md-error)]" />
                        )}
                        <span>
                          {validation.ok ? 'Проверка пройдена успешно' : 'Найдены ошибки конфигурации'}
                          {validation.coreTested ? ' (проверено xray -test)' : ''}
                        </span>
                      </div>
                      {validation.errors.map((e, i) => (
                        <div key={i} className="text-[var(--md-error)]">• {e}</div>
                      ))}
                      {validation.warnings.map((w, i) => (
                        <div key={i} className="text-[var(--md-warning)]">• {w}</div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {tab === 'diff' && studioView && (
                <div className="space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-1.5 text-[0.78rem] font-bold">
                      <Layers className="h-4 w-4 text-[var(--md-primary)]" />
                      Преобразования от исходного ключа к финальному конфигу Xray
                    </div>
                    <M3SegmentedButton<'l1' | 'l2' | 'l4'>
                      size="sm"
                      value={diffLayerChoice}
                      onChange={setDiffLayerChoice}
                      options={[
                        { id: 'l1', label: 'Layer 1 Импорт' },
                        { id: 'l2', label: 'Layer 2 Overrides' },
                        { id: 'l4', label: 'Layer 4 Финал Xray' },
                      ]}
                    />
                  </div>

                  {studioView.layer3InjectedSummary.length > 0 && (
                    <M3SurfaceCard level="default" className="p-3 space-y-1 text-[0.7rem]">
                      <div className="font-bold text-[var(--md-on-surface)]">Layer 3 — Клиентская логика:</div>
                      {studioView.layer3InjectedSummary.map((line, i) => (
                        <div key={i} className="text-[var(--md-on-surface-variant)]">• {line}</div>
                      ))}
                    </M3SurfaceCard>
                  )}

                  {studioView.diffs.length > 0 && (
                    <M3SurfaceCard level="default" className="p-3 space-y-1.5 text-[0.7rem]">
                      <div className="font-bold text-[var(--md-on-surface)]">
                        Применённые изменения ({studioView.diffs.length}):
                      </div>
                      {studioView.diffs.map((d, i) => (
                        <div key={i} className="rounded-lg bg-[var(--md-surface-container-low)] px-2.5 py-1.5">
                          <div className="font-mono font-semibold text-[var(--md-primary)]">{d.path}</div>
                          <div className="text-[var(--md-on-surface-variant)]">
                            {d.layer} • {d.reason}: {d.before ?? '—'} → {d.after ?? '—'}
                          </div>
                        </div>
                      ))}
                    </M3SurfaceCard>
                  )}

                  {activeJsonPreview && (
                    <pre className="aura-scroll max-h-72 overflow-auto rounded-2xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] p-3 font-mono text-[0.68rem]">
                      {JSON.stringify(activeJsonPreview, null, 2)}
                    </pre>
                  )}
                </div>
              )}

              {tab === 'revisions' && (
                <div className="space-y-2.5">
                  {loading && <div className="text-[0.75rem]">Загрузка...</div>}
                  {studioView && studioView.revisions.length === 0 ? (
                    <M3SurfaceCard level="default" className="p-4 text-[0.75rem] text-[var(--md-on-surface-variant)]">
                      Сохранённых ревизий пока нет — они создаются автоматически при редактировании JSON в Config Studio.
                    </M3SurfaceCard>
                  ) : (
                    studioView?.revisions.map((rev) => (
                      <M3SurfaceCard key={rev.revisionId} level="default" className="flex flex-wrap items-center justify-between gap-2 p-3">
                        <div className="space-y-0.5 text-[0.72rem]">
                          <div className="flex items-center gap-1.5 font-bold text-[var(--md-on-surface)]">
                            <History className="h-3.5 w-3.5 text-[var(--md-primary)]" />
                            <span>{rev.note}</span>
                          </div>
                          <div className="text-[var(--md-on-surface-variant)]">
                            {rev.summary} • {new Date(rev.timestamp).toLocaleString('ru-RU')}
                          </div>
                        </div>
                        <M3Button
                          size="sm"
                          variant="tonal"
                          onClick={() => void handleRollbackRevision(rev.revisionId)}
                          leadingIcon={<RotateCcw className="h-3.5 w-3.5" />}
                        >
                          Откатить
                        </M3Button>
                      </M3SurfaceCard>
                    ))
                  )}
                </div>
              )}
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
