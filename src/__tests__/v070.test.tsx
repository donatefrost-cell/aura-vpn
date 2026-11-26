// @vitest-environment jsdom
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ProtectionCenterModal } from '../components/ProtectionCenterModal';
import { ConfigStudioModal } from '../components/ConfigStudioModal';
import { DEFAULT_SETTINGS } from '../config/defaultSettings';
import type { ConnectionSnapshot, ServerProfile, Subscription } from '../types/vpn';
import { HomeView } from '../views/HomeView';
import { SubscriptionsView } from '../views/SubscriptionsView';

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const SAMPLE_SERVER: ServerProfile = {
  id: 'srv-nl-1',
  name: 'NL Amsterdam Ultra Fast Reality Node',
  protocol: 'vless',
  address: 'nl1.example.com',
  port: 443,
  countryCode: 'NL',
  favorite: true,
  latencyMs: 38,
  details: {
    kind: 'vless',
    data: {
      uuid: '11111111-1111-1111-1111-111111111111',
      encryption: 'none',
      security: 'reality',
      network: 'tcp',
      flow: 'xtls-rprx-vision',
      sni: 'www.microsoft.com',
      fingerprint: 'chrome',
      alpn: ['h2'],
      allowInsecure: false,
      pqv: 'ml-dsa-65-demo',
    },
  },
  createdAt: '2026-11-24T10:00:00Z',
};

const SAMPLE_CONNECTION: ConnectionSnapshot = {
  status: 'connected',
  activeServerId: SAMPLE_SERVER.id,
  mode: 'system_proxy',
  connectedSince: Math.floor(Date.now() / 1000) - 120,
  systemProxyEnabled: true,
  killSwitchEngaged: false,
  localSocksPort: 10808,
  localHttpPort: 10809,
};

describe('AURA VPN v0.7.0 defaults and UI components', () => {
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

  it('provides safe v0.7.0 defaults for Kill Switch 2.0, BackgroundStyle and Smart Config Engine', () => {
    expect(DEFAULT_SETTINGS.killSwitch?.mode).toBe('off');
    expect(DEFAULT_SETTINGS.killSwitch?.blockIpv6Leaks).toBe(true);
    expect(DEFAULT_SETTINGS.killSwitch?.allowLan).toBe(true);
    expect(DEFAULT_SETTINGS.killSwitch?.persistOnExit).toBe(false);
    expect(DEFAULT_SETTINGS.backgroundStyle).toBe('aura');
    expect(DEFAULT_SETTINGS.configAdaptationMode).toBe('auto');
  });

  it('renders HomeView without duplicate active server cards and includes Protection Center CTA', () => {
    act(() => {
      root.render(
        <HomeView
          profiles={[SAMPLE_SERVER]}
          activeServer={SAMPLE_SERVER}
          connection={SAMPLE_CONNECTION}
          settings={DEFAULT_SETTINGS}
          isPinging={false}
          isAutoSelecting={false}
          isProbingProxy={false}
          lastProbe={null}
          externalIp="203.0.113.45"
          isFetchingIp={false}
          lastReconnectAt={null}
          dnsStatus="ok"
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
          onSelectBehaviorProfile={vi.fn()}
          onOpenImport={vi.fn()}
          onPasteClipboard={vi.fn()}
          onOpenDiagnostics={vi.fn()}
          onOpenProtectionCenter={vi.fn()}
          onInspectServer={vi.fn()}
        />,
      );
    });

    const text = container.textContent ?? '';
    const occurrences = text.split('NL Amsterdam Ultra Fast Reality Node').length - 1;
    expect(occurrences).toBe(1);
    expect(text).toContain('Центр защиты');
    expect(text).toContain('РФ напрямую');
    expect(text).toContain('Kill Switch');
  });

  it('renders SubscriptionsView with <1% quota label, non-empty interval option, and rollback banner', () => {
    const sub: Subscription = {
      id: 'sub-1',
      title: 'FlyVPN — всё летает',
      url: 'https://sub.example.com/profile',
      enabled: true,
      autoUpdate: true,
      updateIntervalHours: 16,
      serverCount: 1,
      errorHistory: [],
      userInfo: {
        uploadBytes: 200_000_000,
        downloadBytes: 300_000_000,
        totalBytes: 1_000_000_000_000,
      },
      updatedAt: new Date().toISOString(),
    };

    act(() => {
      root.render(
        <SubscriptionsView
          subscriptions={[sub]}
          profiles={[SAMPLE_SERVER]}
          refreshingIds={new Set()}
          lastRefreshDiff={{
            subscriptionId: 'sub-1',
            added: 2,
            removed: 1,
            updated: 3,
            unchanged: 15,
            activeServerChanged: false,
            canRollback: true,
            warnings: ['Тестовое предупреждение diff'],
          }}
          onRefresh={vi.fn()}
          onRollback={vi.fn()}
          onRefreshAll={vi.fn()}
          onRename={vi.fn()}
          onToggleEnabled={vi.fn()}
          onUpdateConfig={vi.fn()}
          onDelete={vi.fn()}
          onOpenImport={vi.fn()}
        />,
      );
    });

    const text = container.textContent ?? '';
    expect(text).not.toContain('Выберите');
    expect(text).toContain('<1%');
    expect(text).toContain('Откатить');
    expect(text).toContain('Авто: 16 ч');
  });

  it('renders ConfigStudioModal and ProtectionCenterModal cleanly', async () => {
    await act(async () => {
      root.render(
        <>
          <ConfigStudioModal
            open={true}
            server={SAMPLE_SERVER}
            onClose={vi.fn()}
            onApplyOverrides={vi.fn()}
          />
          <ProtectionCenterModal
            open={true}
            onClose={vi.fn()}
            onCheckIp={vi.fn(async () => {})}
            onSetIpMask={vi.fn(async () => {})}
            onEmergencyRecover={vi.fn(async () => ({
              wfpFiltersRemoved: true,
              legacyNetshRuleRemoved: true,
              systemProxyRestored: true,
              orphanedProcessesKilled: 0,
              staleFilesCleaned: 0,
              needsElevation: false,
              warnings: [],
            }))}
            onDisengageKillSwitch={vi.fn(async () => {})}
            onOpenSecuritySettings={vi.fn()}
          />
        </>,
      );
    });

    for (let i = 0; i < 20; i++) {
      if ((document.body.textContent ?? '').includes('Экстренное восстановление сети')) break;
      await act(async () => {
        await new Promise((r) => setTimeout(r, 30));
      });
    }

    const bodyText = document.body.textContent ?? '';
    expect(bodyText).toContain('Индивидуальные переопределения профиля');
    expect(bodyText).toContain('Центр защиты и контроля утечек');
    expect(bodyText).toContain('Экстренное восстановление сети');
  });
});
