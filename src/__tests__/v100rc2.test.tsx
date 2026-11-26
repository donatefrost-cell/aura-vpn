// @vitest-environment jsdom
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DEFAULT_SETTINGS } from '../config/defaultSettings';
import { previewApi } from '../services/previewApi';
import type { ConnectionSnapshot, ServerProfile } from '../types/vpn';
import { HomeView } from '../views/HomeView';
import { RoutingView } from '../views/RoutingView';
import { SettingsView } from '../views/SettingsView';

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const TEST_SERVER: ServerProfile = {
  id: 'srv-1',
  name: 'NL Test Server',
  protocol: 'amneziawg',
  address: '198.51.100.10',
  port: 51820,
  countryCode: 'NL',
  favorite: false,
  latencyMs: 42,
  details: {
    kind: 'amneziawg',
    data: {
      secretKey: 'sec',
      address: ['10.8.1.2/32'],
      publicKey: 'pub',
      endpoint: '198.51.100.10:51820',
      dns: ['1.1.1.1'],
    },
  },
  createdAt: '2026-11-26T10:00:00Z',
};

describe('AURA VPN v1.0.0-rc.2 Claude Guard & Always-Admin UI controls', () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    container = document.createElement('div');
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    act(() => {
      root.unmount();
    });
    container.remove();
  });

  it('renders Claude Guard card in RoutingView, toggles Always-VPN, adds extra process, and triggers Always-Admin CTA', async () => {
    const diag = await previewApi.getDiagnostics();
    const onUpdateRouting = vi.fn();
    const onSetAlwaysAdmin = vi.fn(async () => {});
    const settingsWithClaude = {
      ...DEFAULT_SETTINGS,
      routing: {
        ...DEFAULT_SETTINGS.routing,
        claudeGuard: {
          enabled: true,
          blockWithoutVpn: true,
          extraApps: [],
        },
      },
    };
    const conn: ConnectionSnapshot = {
      status: 'disconnected',
      mode: 'system_proxy',
      systemProxyEnabled: false,
      killSwitchEngaged: false,
      claudeGuard: {
        enabled: true,
        blockWithoutVpn: true,
        wfpBlockingActive: false,
        detectedApps: ['C:\\Program Files\\WindowsApps\\Claude\\Claude.exe'],
        blockedIpCount: 6,
        needsElevation: true,
        detail: 'Требуются права администратора (UAC)',
      },
    };

    await act(async () => {
      root.render(
        <RoutingView
          settings={settingsWithClaude}
          connection={conn}
          diagnostics={{ ...diag, isElevated: false }}
          rulepackStatus={null}
          onUpdateRouting={onUpdateRouting}
          onSwitchToTun={vi.fn()}
          onSetAlwaysAdmin={onSetAlwaysAdmin}
          onUpdateRulepack={vi.fn(async () => {})}
          onRollbackRulepack={vi.fn(async () => {})}
          onNotify={vi.fn()}
        />,
      );
      await new Promise((r) => setTimeout(r, 20));
    });

    const card = container.querySelector('[data-testid="claude-guard-card"]');
    expect(card).toBeTruthy();
    expect(card?.textContent).toContain('Защита Claude и Anthropic');
    expect(card?.textContent).toContain('Приложений: 1 • IP: 6');

    const alwaysAdminBtn = Array.from(card?.querySelectorAll('button') ?? []).find((b) =>
      b.textContent?.includes('Права администратора навсегда'),
    ) as HTMLButtonElement;
    expect(alwaysAdminBtn).toBeTruthy();
    await act(async () => {
      alwaysAdminBtn.click();
    });
    expect(onSetAlwaysAdmin).toHaveBeenCalledWith(true, true);

    const extraInput = container.querySelector(
      'input[aria-label="Дополнительный процесс Claude"]',
    ) as HTMLInputElement;
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
    await act(async () => {
      setter?.call(extraInput, 'claude-code.exe');
      extraInput.dispatchEvent(new Event('input', { bubbles: true }));
      extraInput.dispatchEvent(new Event('change', { bubbles: true }));
    });
    await act(async () => {
      extraInput.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    });
    expect(onUpdateRouting).toHaveBeenCalled();
    expect(onUpdateRouting.mock.calls.at(-1)?.[0].claudeGuard?.extraApps).toContain(
      'claude-code.exe',
    );
  });

  it('shows WFP active chip on HomeView and Always-Admin toggle in SettingsView', async () => {
    const diag = await previewApi.getDiagnostics();
    const onToggleClaude = vi.fn();
    const onSetAlwaysAdmin = vi.fn(async () => {});

    const connBlocking: ConnectionSnapshot = {
      status: 'disconnected',
      mode: 'tun',
      systemProxyEnabled: false,
      killSwitchEngaged: false,
      claudeGuard: {
        enabled: true,
        blockWithoutVpn: true,
        wfpBlockingActive: true,
        detectedApps: [],
        blockedIpCount: 4,
        needsElevation: false,
        detail: 'WFP-блокировка активна',
      },
    };

    await act(async () => {
      root.render(
        <HomeView
          profiles={[TEST_SERVER]}
          activeServer={TEST_SERVER}
          connection={connBlocking}
          settings={{
            ...DEFAULT_SETTINGS,
            routing: {
              ...DEFAULT_SETTINGS.routing,
              claudeGuard: { enabled: true, blockWithoutVpn: true, extraApps: [] },
            },
          }}
          isPinging={false}
          isAutoSelecting={false}
          isProbingProxy={false}
          lastProbe={null}
          externalIp={null}
          isFetchingIp={false}
          lastReconnectAt={null}
          dnsStatus="unknown"
          onToggleConnect={vi.fn()}
          onDisengageKillSwitch={vi.fn()}
          onSelectServer={vi.fn()}
          onPingActive={vi.fn()}
          onProbeProxy={vi.fn()}
          onFetchExternalIp={vi.fn()}
          onCopyExternalIp={vi.fn()}
          onAutoSelectFastest={vi.fn()}
          onChangeMode={vi.fn()}
          onToggleRuDirect={vi.fn()}
          onToggleKillSwitch={vi.fn()}
          onToggleClaudeGuard={onToggleClaude}
          onSelectBehaviorProfile={vi.fn()}
          onOpenImport={vi.fn()}
          onPasteClipboard={vi.fn()}
          onOpenDiagnostics={vi.fn()}
        />,
      );
    });

    const chip = Array.from(container.querySelectorAll('button')).find((b) =>
      b.textContent?.includes('Claude: WFP-блок'),
    ) as HTMLButtonElement;
    expect(chip).toBeTruthy();
    await act(async () => {
      chip.click();
    });
    expect(onToggleClaude).toHaveBeenCalledTimes(1);

    await act(async () => {
      root.render(
        <SettingsView
          settings={DEFAULT_SETTINGS}
          diagnostics={{ ...diag, alwaysRunAsAdmin: true, isElevated: true }}
          rulepackStatus={null}
          windowsAccentHex="#4F46E5"
          updateResult={null}
          isCheckingUpdate={false}
          initialSection="general"
          onUpdateSettings={vi.fn()}
          onRelaunchAdmin={vi.fn()}
          onSetAlwaysAdmin={onSetAlwaysAdmin}
          onCheckUpdates={vi.fn()}
          onOpenDiagnostics={vi.fn()}
          onExportDiagnostics={vi.fn(async () => {})}
          onExportSettings={vi.fn(async () => {})}
          onImportSettings={vi.fn(async () => {})}
          onResetSettings={vi.fn(async () => {})}
        />,
      );
      await new Promise((r) => setTimeout(r, 20));
    });

    expect(container.textContent).toContain('Включено навсегда');
    const sw = container.querySelector(
      '[aria-label="Права администратора навсегда"]',
    ) as HTMLButtonElement;
    expect(sw).toBeTruthy();
    await act(async () => {
      sw.click();
    });
    expect(onSetAlwaysAdmin).toHaveBeenCalledWith(false, false);
  });
});
