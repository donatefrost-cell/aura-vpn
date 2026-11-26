import { ClipboardPaste, Plus, ShieldCheck, Sparkles } from 'lucide-react';
import { AuraLogo } from './AuraLogo';
import { M3Button, M3Dialog } from './md3';

interface OnboardingModalProps {
  open: boolean;
  onComplete: () => void;
  onOpenImport: () => void;
  onPasteClipboard: () => void;
}

export function OnboardingModal({
  open,
  onComplete,
  onOpenImport,
  onPasteClipboard,
}: OnboardingModalProps) {
  return (
    <M3Dialog
      open={open}
      onClose={onComplete}
      title="Добро пожаловать в AURA VPN"
      description="Современный Windows-клиент на Xray-core и AmneziaWG с приватным хранением ключей и защитой от утечек."
      footer={
        <>
          <M3Button variant="text" onClick={onComplete}>
            Начать позже
          </M3Button>
          <M3Button
            variant="tonal"
            leadingIcon={<Plus className="h-3.5 w-3.5" />}
            onClick={() => {
              onComplete();
              onOpenImport();
            }}
          >
            Добавить вручную
          </M3Button>
          <M3Button
            variant="filled"
            leadingIcon={<ClipboardPaste className="h-3.5 w-3.5" />}
            onClick={() => {
              onComplete();
              onPasteClipboard();
            }}
          >
            Из буфера обмена
          </M3Button>
        </>
      }
    >
      <div className="space-y-3">
        <div className="flex items-center gap-3 rounded-2xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] p-3">
          <AuraLogo variant="mark" className="h-11 w-11 shrink-0" />
          <div className="text-xs leading-relaxed text-[var(--md-on-surface-variant)]">
            <strong className="text-[var(--md-on-surface)]">Быстрый старт за 10 секунд:</strong>{' '}
            вставьте ссылку подписки (
            <code className="rounded bg-[var(--md-surface-container-high)] px-1 py-0.5 font-mono text-[0.7rem] text-[var(--md-on-surface)]">
              https://
            </code>
            ,{' '}
            <code className="rounded bg-[var(--md-surface-container-high)] px-1 py-0.5 font-mono text-[0.7rem] text-[var(--md-on-surface)]">
              happ://
            </code>
            ,{' '}
            <code className="rounded bg-[var(--md-surface-container-high)] px-1 py-0.5 font-mono text-[0.7rem] text-[var(--md-on-surface)]">
              v2raytun://
            </code>
            ) или любой ключ — флаг и протокол определятся автоматически.
          </div>
        </div>

        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 text-xs">
          <div className="rounded-xl bg-[var(--md-surface-container-low)] p-2.5">
            <div className="flex items-center gap-1.5 font-semibold text-[var(--md-on-surface)]">
              <ShieldCheck className="h-3.5 w-3.5 text-[var(--md-success)]" />
              Режимы Прокси и TUN
            </div>
            <p className="mt-1 text-[0.7rem] text-[var(--md-on-surface-variant)]">
              Системный прокси для браузеров или Wintun TUN для всех программ и игр.
            </p>
          </div>
          <div className="rounded-xl bg-[var(--md-surface-container-low)] p-2.5">
            <div className="flex items-center gap-1.5 font-semibold text-[var(--md-on-surface)]">
              <Sparkles className="h-3.5 w-3.5 text-[var(--md-primary)]" />
              РФ сервисы напрямую
            </div>
            <p className="mt-1 text-[0.7rem] text-[var(--md-on-surface-variant)]">
              Банки, Госуслуги и .ru сайты открываются напрямую без отключения VPN.
            </p>
          </div>
        </div>
      </div>
    </M3Dialog>
  );
}
