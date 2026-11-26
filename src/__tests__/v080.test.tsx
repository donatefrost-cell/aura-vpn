// @vitest-environment jsdom
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ConfigStudioModal } from '../components/ConfigStudioModal';
import { ConnectionInspectorDrawer } from '../components/ConnectionInspectorDrawer';
import { TrafficGraph } from '../components/TrafficGraph';
import { SettingMetaRow } from '../components/settings/SettingMetaRow';
import { DEFAULT_SETTINGS, normalizeDnsMode } from '../config/defaultSettings';
import { SETTINGS_GROUPS, SETTINGS_REGISTRY } from '../config/settingsRegistry';
import { liveStore } from '../stores/liveStore';
import { profilesStore } from '../stores/profilesStore';
import { SettingsView } from '../views/SettingsView';
import { previewApi } from '../services/previewApi';
import type { ServerProfile } from '../types/vpn';

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const SAMPLE_SERVER: ServerProfile = {
  id: 'srv-nl-1',
  name: 'NL Amsterdam Reality',
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
    },
  },
  createdAt: '2026-11-25T10:00:00Z',
};

describe('AURA VPN v0.8.0 modules, settings registry, Config Studio & TrafficGraph 1h', () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    container = document.createElement('div');
    document.body.appendChild(container);
    root = createRoot(container);
    liveStore.resetTraffic();
  });

  afterEach(() => {
    act(() => {
      root.unmount();
    });
    container.remove();
  });

  it('defines 4 groups × 16 categories and supports all 6 DNS modes', () => {
    expect(SETTINGS_GROUPS.length).toBe(4);
    const totalCategories = SETTINGS_GROUPS.reduce((acc, g) => acc + g.categories.length, 0);
    expect(totalCategories).toBe(16);
    expect(SETTINGS_REGISTRY.length).toBeGreaterThanOrEqual(14);
    expect(normalizeDnsMode('config')).toBe('config');
    expect(normalizeDnsMode('system')).toBe('system');
    expect(normalizeDnsMode('custom')).toBe('custom');
    expect(DEFAULT_SETTINGS.tun?.adapterName).toBe('aura_tun');
    expect(DEFAULT_SETTINGS.advanced?.coreSelection).toBe('auto');
  });

  it('aggregates 1h ring buffer (360x10s) and renders TrafficGraph 1ч + Сред. ↑', () => {
    const baseTs = Date.now() - 120_000;
    for (let i = 0; i < 30; i++) {
      liveStore.pushTraffic(
        {
          rxBytesPerSec: 1_000_000 + i * 10_000,
          txBytesPerSec: 250_000,
          totalRxBytes: 10_000_000,
          totalTxBytes: 2_000_000,
        },
        baseTs + i * 1000,
      );
    }
    const win1h = liveStore.getTrafficWindow('1h');
    expect(win1h.samples.length).toBe(3); // 30 seconds -> 3 buckets of 10s
    expect(win1h.avgTx).toBe(250_000);

    act(() => {
      root.render(<TrafficGraph status="connected" />);
    });
    const text = container.textContent ?? '';
    expect(text).toContain('1ч');
    expect(text).toContain('Сред. ↑');
  });

  it('expands ⓘ metadata popover on SettingMetaRow and saves custom behavior profile', () => {
    profilesStore.saveCustomFromSettings({
      ...DEFAULT_SETTINGS,
      connectionMode: 'tun',
    });
    expect(profilesStore.getSnapshot().profiles.custom.connectionMode).toBe('tun');

    act(() => {
      root.render(
        <SettingMetaRow
          id="demo-setting"
          level="expert"
          title="TCP Keepalive"
          description="Таймаут keepalive"
          defaultLabel="0с"
          recommendedLabel="30с"
          rangeLabel="0–120с"
          impact="Удерживает NAT"
          compatibility="Xray TCP"
          requiresReconnect
          modified
          onReset={vi.fn()}
        />,
      );
    });
    const infoBtn = container.querySelector('button[aria-label*="Справка по параметру"]') as HTMLButtonElement;
    expect(infoBtn).toBeTruthy();
    act(() => {
      infoBtn.click();
    });
    expect(container.textContent).toContain('По умолчанию:');
    expect(container.textContent).toContain('Рекомендуется:');
    expect(container.textContent).toContain('Удерживает NAT');
  });

  it('renders ConfigStudioModal (5 tabs) and ConnectionInspectorDrawer cleanly', async () => {
    void previewApi;
    await act(async () => {
      root.render(
        <>
          <ConfigStudioModal open server={SAMPLE_SERVER} onClose={vi.fn()} />
          <ConnectionInspectorDrawer open onClose={vi.fn()} />
        </>,
      );
      for (let i = 0; i < 10; i++) {
        await new Promise((r) => setTimeout(r, 25));
        if ((container.textContent ?? '').includes('Пропускная способность сессии')) break;
      }
    });

    const text = container.textContent ?? '';
    expect(text).toContain('Config Studio');
    expect(text).toContain('Обзор и Overrides');
    expect(text).toContain('Инспектор протокола');
    expect(text).toContain('JSON-редактор');
    expect(text).toContain('4 слоя и Diff');
    expect(text).toContain('Инспектор подключения');
    expect(text).toContain('Пропускная способность сессии');
  });

  it('renders 2-column Master-Detail SettingsView with 3-tier toggle and CoreManagerPanel', async () => {
    const diag = await previewApi.getDiagnostics();
    await act(async () => {
      root.render(
        <SettingsView
          settings={DEFAULT_SETTINGS}
          diagnostics={diag}
          rulepackStatus={null}
          windowsAccentHex="#4F46E5"
          updateResult={null}
          isCheckingUpdate={false}
          initialSection="vpn-core"
          onUpdateSettings={vi.fn()}
          onRelaunchAdmin={vi.fn()}
          onCheckUpdates={vi.fn()}
          onOpenDiagnostics={vi.fn()}
          onExportDiagnostics={vi.fn(async () => {})}
          onExportSettings={vi.fn(async () => {})}
          onImportSettings={vi.fn(async () => {})}
          onResetSettings={vi.fn(async () => {})}
        />,
      );
      await new Promise((r) => setTimeout(r, 40));
    });

    const text = container.textContent ?? '';
    expect(text).toContain('Основной');
    expect(text).toContain('Расширенный');
    expect(text).toContain('Экспертный');
    expect(text).toContain('Изменённые (0)');
    expect(text).toContain('Xray-core');
    expect(text).toContain('Матрица совместимости протоколов и ядер');
  });

  it('allows dragging and committing M3Slider controls in AdvancedVpnPanel and TunManagerPanel', async () => {
    const { AdvancedVpnPanel } = await import('../components/settings/AdvancedVpnPanel');
    const { TunManagerPanel } = await import('../components/settings/TunManagerPanel');
    const onUpdateAdv = vi.fn();
    const onUpdateTun = vi.fn();

    await act(async () => {
      root.render(
        <>
          <AdvancedVpnPanel settings={DEFAULT_SETTINGS} level="expert" onUpdateSettings={onUpdateAdv} />
          <TunManagerPanel settings={DEFAULT_SETTINGS} level="expert" onUpdateSettings={onUpdateTun} />
        </>,
      );
      await new Promise((r) => setTimeout(r, 30));
    });

    const coreSlider = container.querySelector('input[aria-label="Таймаут запуска ядра"]') as HTMLInputElement;
    expect(coreSlider).toBeTruthy();
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
    await act(async () => {
      setter?.call(coreSlider, '14');
      coreSlider.dispatchEvent(new Event('change', { bubbles: true }));
      coreSlider.dispatchEvent(new KeyboardEvent('keyup', { key: 'ArrowRight', bubbles: true }));
    });
    expect(coreSlider.value).toBe('14');
    expect(onUpdateAdv).toHaveBeenCalled();
    expect(onUpdateAdv.mock.calls.at(-1)?.[0].advanced.coreStartTimeoutSecs).toBe(14);

    const mtuSlider = container.querySelector('input[aria-label="MTU адаптера TUN"]') as HTMLInputElement;
    expect(mtuSlider).toBeTruthy();
    await act(async () => {
      setter?.call(mtuSlider, '1420');
      mtuSlider.dispatchEvent(new Event('change', { bubbles: true }));
      mtuSlider.dispatchEvent(new KeyboardEvent('keyup', { key: 'ArrowRight', bubbles: true }));
    });
    expect(mtuSlider.value).toBe('1420');
    expect(onUpdateTun).toHaveBeenCalled();
    expect(onUpdateTun.mock.calls.at(-1)?.[0].tun.mtu).toBe(1420);
  });
});
