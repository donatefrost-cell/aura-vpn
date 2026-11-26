/// <reference types="vite/client" />
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { readText as readClipboardTauri } from '@tauri-apps/plugin-clipboard-manager';
import type {
  AppSettings,
  AutoSelectResult,
  BackgroundStyle,
  BootstrapState,
  ConfigStudioView,
  ConfigValidationResult,
  ConnectionHistoryResponse,
  ConnectionInspectorSnapshot,
  ConnectionSnapshot,
  ConnectionTimelineEvent,
  CoreDiagnostics,
  CoreInventorySnapshot,
  CoreKind,
  CoreUpdateCheckResult,
  DiagnosticsReport,
  DnsInspectorReport,
  DnsLiveLookupResult,
  DnsRouteCheckResult,
  DnsServerTestResult,
  EmergencyRecoveryOutcome,
  ImportOutcome,
  ImportPreviewResult,
  IpMonitorState,
  IpProviderId,
  KillSwitchConfig,
  KillSwitchSnapshot,
  LogEntry,
  NetworkDoctorReport,
  PrivacyInventory,
  PrivacyPurgeReport,
  PrivacyPurgeScope,
  ProfileAnalysisReport,
  ProfileOverrides,
  ProtectionCenterSnapshot,
  ProxyProbeResult,
  RouteTestResult,
  RulepackStatus,
  ServerProfile,
  SmartImportOutcome,
  SpeedTestResult,
  SubscriptionImportOutcome,
  SubscriptionRefreshOutcome,
  SubscriptionSyncEntry,
  TrafficStats,
  TunManagerSnapshot,
  UpdateCheckResult,
  VirtualAdapterConflict,
  WindowModeState,
} from '../types/vpn';

declare global {
  interface Window {
    __TAURI_INTERNALS__?: unknown;
  }
}

export function isTauriRuntime(): boolean {
  return typeof window !== 'undefined' && Boolean(window.__TAURI_INTERNALS__);
}

export const IS_PREVIEW_BUILD =
  import.meta.env.DEV || import.meta.env.VITE_PREVIEW_MODE === '1';

async function loadPreview() {
  if (!IS_PREVIEW_BUILD) {
    throw new Error('Приложение должно запускаться внутри Tauri (Desktop Runtime).');
  }
  const mod = await import('./previewApi');
  return mod.previewApi;
}

export const api = {
  async getBootstrapState(): Promise<BootstrapState> {
    if (!isTauriRuntime()) return (await loadPreview()).getBootstrapState();
    return invoke<BootstrapState>('get_bootstrap_state');
  },

  async previewImportText(raw: string): Promise<ImportPreviewResult> {
    if (!isTauriRuntime()) return (await loadPreview()).previewImportText(raw);
    return invoke<ImportPreviewResult>('preview_import_text', { raw });
  },

  async importFromText(raw: string, applyAdaptations?: boolean): Promise<ImportOutcome> {
    if (!isTauriRuntime()) return (await loadPreview()).importFromText(raw, applyAdaptations);
    return invoke<ImportOutcome>('import_from_text', {
      raw,
      applyAdaptations: applyAdaptations ?? null,
    });
  },

  async importSubscription(url: string): Promise<SubscriptionImportOutcome> {
    if (!isTauriRuntime()) return (await loadPreview()).importSubscription(url);
    return invoke<SubscriptionImportOutcome>('import_subscription', { url });
  },

  async smartImport(raw: string, applyAdaptations?: boolean): Promise<SmartImportOutcome> {
    if (!isTauriRuntime()) return (await loadPreview()).smartImport(raw, applyAdaptations);
    return invoke<SmartImportOutcome>('smart_import', {
      raw,
      applyAdaptations: applyAdaptations ?? null,
    });
  },

  async refreshSubscription(id: string): Promise<SubscriptionRefreshOutcome> {
    if (!isTauriRuntime()) return (await loadPreview()).refreshSubscription(id);
    return invoke<SubscriptionRefreshOutcome>('refresh_subscription', { id });
  },

  async rollbackSubscription(id: string): Promise<BootstrapState> {
    if (!isTauriRuntime()) return (await loadPreview()).rollbackSubscription(id);
    return invoke<BootstrapState>('rollback_subscription', { id });
  },

  async deleteSubscription(id: string): Promise<BootstrapState> {
    if (!isTauriRuntime()) return (await loadPreview()).deleteSubscription(id);
    return invoke<BootstrapState>('delete_subscription', { id });
  },

  async renameSubscription(id: string, title: string): Promise<BootstrapState> {
    if (!isTauriRuntime()) return (await loadPreview()).renameSubscription(id, title);
    return invoke<BootstrapState>('rename_subscription', { id, title });
  },

  async toggleSubscriptionEnabled(id: string, enabled: boolean): Promise<BootstrapState> {
    if (!isTauriRuntime()) return (await loadPreview()).toggleSubscriptionEnabled(id, enabled);
    return invoke<BootstrapState>('toggle_subscription_enabled', { id, enabled });
  },

  async updateSubscriptionConfig(
    id: string,
    autoUpdate: boolean,
    updateIntervalHours: number | null,
  ): Promise<BootstrapState> {
    if (!isTauriRuntime()) {
      return (await loadPreview()).updateSubscriptionConfig(id, autoUpdate, updateIntervalHours);
    }
    return invoke<BootstrapState>('update_subscription_config', {
      id,
      autoUpdate,
      updateIntervalHours,
    });
  },

  async selectServer(id: string): Promise<BootstrapState> {
    if (!isTauriRuntime()) return (await loadPreview()).selectServer(id);
    return invoke<BootstrapState>('select_server', { id });
  },

  async toggleFavoriteServer(id: string): Promise<BootstrapState> {
    if (!isTauriRuntime()) return (await loadPreview()).toggleFavoriteServer(id);
    return invoke<BootstrapState>('toggle_favorite_server', { id });
  },

  async renameServer(id: string, name: string): Promise<BootstrapState> {
    if (!isTauriRuntime()) return (await loadPreview()).renameServer(id, name);
    return invoke<BootstrapState>('rename_server', { id, name });
  },

  async deleteServer(id: string): Promise<BootstrapState> {
    if (!isTauriRuntime()) return (await loadPreview()).deleteServer(id);
    return invoke<BootstrapState>('delete_server', { id });
  },

  async bulkDeleteServers(ids: string[]): Promise<BootstrapState> {
    if (!isTauriRuntime()) return (await loadPreview()).bulkDeleteServers(ids);
    return invoke<BootstrapState>('bulk_delete_servers', { ids });
  },

  async bulkSetFavoriteServers(ids: string[], favorite: boolean): Promise<BootstrapState> {
    if (!isTauriRuntime()) return (await loadPreview()).bulkSetFavoriteServers(ids, favorite);
    return invoke<BootstrapState>('bulk_set_favorite_servers', { ids, favorite });
  },

  async pingServer(id: string): Promise<number | null> {
    if (!isTauriRuntime()) return (await loadPreview()).pingServer(id);
    return invoke<number | null>('ping_server', { id });
  },

  async pingAllServers(): Promise<ServerProfile[]> {
    if (!isTauriRuntime()) return (await loadPreview()).pingAllServers();
    return invoke<ServerProfile[]>('ping_all_servers');
  },

  async autoSelectFastestServer(): Promise<AutoSelectResult> {
    if (!isTauriRuntime()) return (await loadPreview()).autoSelectFastestServer();
    return invoke<AutoSelectResult>('auto_select_fastest_server');
  },

  async connect(serverId?: string | null): Promise<ConnectionSnapshot> {
    if (!isTauriRuntime()) return (await loadPreview()).connect(serverId);
    return invoke<ConnectionSnapshot>('connect', { serverId: serverId ?? null });
  },

  async disconnect(): Promise<ConnectionSnapshot> {
    if (!isTauriRuntime()) return (await loadPreview()).disconnect();
    return invoke<ConnectionSnapshot>('disconnect');
  },

  async disengageKillSwitch(): Promise<ConnectionSnapshot> {
    if (!isTauriRuntime()) return (await loadPreview()).disengageKillSwitch();
    return invoke<ConnectionSnapshot>('disengage_kill_switch');
  },

  async getKillSwitchStatus(): Promise<KillSwitchSnapshot> {
    if (!isTauriRuntime()) return (await loadPreview()).getKillSwitchStatus();
    return invoke<KillSwitchSnapshot>('get_kill_switch_status');
  },

  async setKillSwitchConfig(config: KillSwitchConfig): Promise<BootstrapState> {
    if (!isTauriRuntime()) return (await loadPreview()).setKillSwitchConfig(config);
    return invoke<BootstrapState>('set_kill_switch_config', { config });
  },

  async emergencyRecoverNetwork(): Promise<EmergencyRecoveryOutcome> {
    if (!isTauriRuntime()) return (await loadPreview()).emergencyRecoverNetwork();
    return invoke<EmergencyRecoveryOutcome>('emergency_recover_network');
  },

  async checkIpMonitor(includeIpv6 = false, provider?: IpProviderId): Promise<IpMonitorState> {
    if (!isTauriRuntime()) return (await loadPreview()).checkIpMonitor(includeIpv6, provider);
    return invoke<IpMonitorState>('check_ip_monitor', {
      includeIpv6,
      provider: provider ?? null,
    });
  },

  async setIpMask(maskIp: boolean): Promise<IpMonitorState> {
    if (!isTauriRuntime()) return (await loadPreview()).setIpMask(maskIp);
    return invoke<IpMonitorState>('set_ip_mask', { maskIp });
  },

  async getProtectionCenter(): Promise<ProtectionCenterSnapshot> {
    if (!isTauriRuntime()) return (await loadPreview()).getProtectionCenter();
    return invoke<ProtectionCenterSnapshot>('get_protection_center');
  },

  async analyzeServerProfile(id: string): Promise<ProfileAnalysisReport> {
    if (!isTauriRuntime()) return (await loadPreview()).analyzeServerProfile(id);
    return invoke<ProfileAnalysisReport>('analyze_server_profile', { id });
  },

  async applyProfileOverrides(id: string, overrides: ProfileOverrides): Promise<BootstrapState> {
    if (!isTauriRuntime()) return (await loadPreview()).applyProfileOverrides(id, overrides);
    return invoke<BootstrapState>('apply_profile_overrides', { id, overrides });
  },

  async setWindowBackgroundStyle(style: BackgroundStyle): Promise<AppSettings> {
    if (!isTauriRuntime()) return (await loadPreview()).setWindowBackgroundStyle(style);
    return invoke<AppSettings>('set_window_background_style', { style });
  },

  async probeActiveConnection(): Promise<ProxyProbeResult> {
    if (!isTauriRuntime()) return (await loadPreview()).probeActiveConnection();
    return invoke<ProxyProbeResult>('probe_active_connection');
  },

  async updateSettings(newSettings: AppSettings): Promise<AppSettings> {
    if (!isTauriRuntime()) return (await loadPreview()).updateSettings(newSettings);
    return invoke<AppSettings>('update_settings', { newSettings });
  },

  async getWindowsAccentColor(): Promise<string | null> {
    if (!isTauriRuntime()) return '#4F46E5';
    return invoke<string | null>('get_windows_accent_color');
  },

  async getRulepackStatus(): Promise<RulepackStatus> {
    if (!isTauriRuntime()) return (await loadPreview()).getRulepackStatus();
    return invoke<RulepackStatus>('get_rulepack_status');
  },

  async updateRulepack(url?: string | null): Promise<RulepackStatus> {
    if (!isTauriRuntime()) return (await loadPreview()).updateRulepack(url);
    return invoke<RulepackStatus>('update_rulepack', { url: url ?? null });
  },

  async rollbackRulepack(): Promise<RulepackStatus> {
    if (!isTauriRuntime()) return (await loadPreview()).rollbackRulepack();
    return invoke<RulepackStatus>('rollback_rulepack');
  },

  async testRoute(query: string, process?: string | null): Promise<RouteTestResult> {
    if (!isTauriRuntime()) return (await loadPreview()).testRoute(query, process);
    return invoke<RouteTestResult>('test_route', { query, process: process || null });
  },

  async dnsLookupRoute(domain: string): Promise<DnsRouteCheckResult> {
    if (!isTauriRuntime()) return (await loadPreview()).dnsLookupRoute(domain);
    return invoke<DnsRouteCheckResult>('dns_lookup_route', { domain });
  },

  async runNetworkDiagnostics(includeExternalIp: boolean): Promise<DiagnosticsReport> {
    if (!isTauriRuntime()) return (await loadPreview()).runNetworkDiagnostics(includeExternalIp);
    return invoke<DiagnosticsReport>('run_network_diagnostics', { includeExternalIp });
  },

  async getConnectionHistory(): Promise<ConnectionHistoryResponse> {
    if (!isTauriRuntime()) return (await loadPreview()).getConnectionHistory();
    return invoke<ConnectionHistoryResponse>('get_connection_history');
  },

  async clearConnectionHistory(): Promise<ConnectionHistoryResponse> {
    if (!isTauriRuntime()) return (await loadPreview()).clearConnectionHistory();
    return invoke<ConnectionHistoryResponse>('clear_connection_history');
  },

  async exportDiagnosticsBundle(): Promise<string> {
    if (!isTauriRuntime()) return (await loadPreview()).exportDiagnosticsBundle();
    return invoke<string>('export_diagnostics_bundle');
  },

  async exportSettingsBackup(): Promise<string> {
    if (!isTauriRuntime()) return (await loadPreview()).exportSettingsBackup();
    return invoke<string>('export_settings_backup');
  },

  async importSettingsBackup(rawJson: string): Promise<AppSettings> {
    if (!isTauriRuntime()) return (await loadPreview()).importSettingsBackup(rawJson);
    return invoke<AppSettings>('import_settings_backup', { rawJson });
  },

  async resetSettingsToDefault(): Promise<BootstrapState> {
    if (!isTauriRuntime()) return (await loadPreview()).resetSettingsToDefault();
    return invoke<BootstrapState>('reset_settings_to_default');
  },

  async getElevationStatus(): Promise<boolean> {
    if (!isTauriRuntime()) return false;
    return invoke<boolean>('get_elevation_status');
  },

  async relaunchAsAdmin(): Promise<void> {
    if (!isTauriRuntime()) return;
    return invoke<void>('relaunch_as_admin');
  },

  async checkForUpdates(): Promise<UpdateCheckResult> {
    if (!isTauriRuntime()) return (await loadPreview()).checkForUpdates();
    return invoke<UpdateCheckResult>('check_for_updates');
  },

  async getLogs(): Promise<LogEntry[]> {
    if (!isTauriRuntime()) return (await loadPreview()).getLogs();
    return invoke<LogEntry[]>('get_logs');
  },

  async clearLogs(): Promise<void> {
    if (!isTauriRuntime()) return;
    return invoke<void>('clear_logs');
  },

  async getDiagnostics(): Promise<CoreDiagnostics> {
    if (!isTauriRuntime()) return (await loadPreview()).getDiagnostics();
    return invoke<CoreDiagnostics>('get_diagnostics');
  },

  async readClipboard(): Promise<string> {
    if (isTauriRuntime()) {
      return (await readClipboardTauri()) ?? '';
    }
    if (navigator.clipboard?.readText) {
      return await navigator.clipboard.readText();
    }
    return '';
  },

  async windowMinimize(): Promise<void> {
    if (!isTauriRuntime()) return;
    return invoke<void>('window_minimize');
  },

  async windowCloseAction(): Promise<void> {
    if (!isTauriRuntime()) return;
    return invoke<void>('window_close_action');
  },

  async getWindowModeState(): Promise<WindowModeState> {
    if (!isTauriRuntime()) return (await loadPreview()).getWindowModeState();
    return invoke<WindowModeState>('get_window_mode_state');
  },

  async setMiniMode(enabled: boolean, alwaysOnTop?: boolean): Promise<WindowModeState> {
    if (!isTauriRuntime()) return (await loadPreview()).setMiniMode(enabled, alwaysOnTop);
    return invoke<WindowModeState>('set_mini_mode', {
      enabled,
      alwaysOnTop: alwaysOnTop ?? null,
    });
  },

  async setAlwaysOnTop(enabled: boolean): Promise<WindowModeState> {
    if (!isTauriRuntime()) return (await loadPreview()).setAlwaysOnTop(enabled);
    return invoke<WindowModeState>('set_always_on_top', { enabled });
  },

  async onConnectionState(cb: (snapshot: ConnectionSnapshot) => void): Promise<UnlistenFn> {
    if (!isTauriRuntime()) return () => {};
    return listen<ConnectionSnapshot>('connection-state', (e) => cb(e.payload));
  },

  async onTrafficStats(cb: (stats: TrafficStats) => void): Promise<UnlistenFn> {
    if (!isTauriRuntime()) return () => {};
    return listen<TrafficStats>('traffic-stats', (e) => cb(e.payload));
  },

  async onLogEntry(cb: (entry: LogEntry) => void): Promise<UnlistenFn> {
    if (!isTauriRuntime()) return () => {};
    return listen<LogEntry>('log-entry', (e) => cb(e.payload));
  },

  async onBootstrapSync(cb: (state: BootstrapState) => void): Promise<UnlistenFn> {
    if (!isTauriRuntime()) return () => {};
    return listen<BootstrapState>('bootstrap-sync', (e) => cb(e.payload));
  },

  async onConnectionTimelineEvent(cb: (event: ConnectionTimelineEvent) => void): Promise<UnlistenFn> {
    if (!isTauriRuntime()) return () => {};
    return listen<ConnectionTimelineEvent>('connection-timeline-event', (e) => cb(e.payload));
  },

  // ===== v0.8.0 Core Manager, DNS, TUN, Inspector, Config Studio, Doctor & Privacy =====

  async getCoreInventory(): Promise<CoreInventorySnapshot> {
    if (!isTauriRuntime()) return (await loadPreview()).getCoreInventory();
    return invoke<CoreInventorySnapshot>('get_core_inventory');
  },

  async verifyCoreIntegrity(): Promise<CoreDiagnostics> {
    if (!isTauriRuntime()) return (await loadPreview()).verifyCoreIntegrity();
    return invoke<CoreDiagnostics>('verify_core_integrity');
  },

  async checkCoreUpdates(kind: CoreKind): Promise<CoreUpdateCheckResult> {
    if (!isTauriRuntime()) return (await loadPreview()).checkCoreUpdates(kind);
    return invoke<CoreUpdateCheckResult>('check_core_updates', { kind });
  },

  async getDnsInspectorReport(): Promise<DnsInspectorReport> {
    if (!isTauriRuntime()) return (await loadPreview()).getDnsInspectorReport();
    return invoke<DnsInspectorReport>('get_dns_inspector_report');
  },

  async testDnsServer(server: string, domain?: string): Promise<DnsServerTestResult> {
    if (!isTauriRuntime()) return (await loadPreview()).testDnsServer(server, domain);
    return invoke<DnsServerTestResult>('test_dns_server', { server, domain: domain ?? null });
  },

  async runDnsInspectorLookup(domain: string): Promise<DnsLiveLookupResult> {
    if (!isTauriRuntime()) return (await loadPreview()).runDnsInspectorLookup(domain);
    return invoke<DnsLiveLookupResult>('run_dns_inspector_lookup', { domain });
  },

  async getTunStatus(): Promise<TunManagerSnapshot> {
    if (!isTauriRuntime()) return (await loadPreview()).getTunStatus();
    return invoke<TunManagerSnapshot>('get_tun_status');
  },

  async detectTunConflicts(): Promise<VirtualAdapterConflict[]> {
    if (!isTauriRuntime()) return (await loadPreview()).detectTunConflicts();
    return invoke<VirtualAdapterConflict[]>('detect_tun_conflicts');
  },

  async getConnectionInspector(): Promise<ConnectionInspectorSnapshot> {
    if (!isTauriRuntime()) return (await loadPreview()).getConnectionInspector();
    return invoke<ConnectionInspectorSnapshot>('get_connection_inspector');
  },

  async getConnectionTimeline(): Promise<ConnectionTimelineEvent[]> {
    if (!isTauriRuntime()) return (await loadPreview()).getConnectionTimeline();
    return invoke<ConnectionTimelineEvent[]>('get_connection_timeline');
  },

  async clearConnectionTimeline(): Promise<ConnectionTimelineEvent[]> {
    if (!isTauriRuntime()) return (await loadPreview()).clearConnectionTimeline();
    return invoke<ConnectionTimelineEvent[]>('clear_connection_timeline');
  },

  async getConfigStudioView(id: string, revealSecrets: boolean): Promise<ConfigStudioView> {
    if (!isTauriRuntime()) return (await loadPreview()).getConfigStudioView(id, revealSecrets);
    return invoke<ConfigStudioView>('get_config_studio_view', { id, revealSecrets });
  },

  async validateCustomProfileConfig(id: string, rawJson: string): Promise<ConfigValidationResult> {
    if (!isTauriRuntime()) return (await loadPreview()).validateCustomProfileConfig(id, rawJson);
    return invoke<ConfigValidationResult>('validate_custom_profile_config', { id, rawJson });
  },

  async saveProfileConfigEdit(id: string, rawJson: string, note?: string | null): Promise<BootstrapState> {
    if (!isTauriRuntime()) return (await loadPreview()).saveProfileConfigEdit(id, rawJson, note);
    return invoke<BootstrapState>('save_profile_config_edit', { id, rawJson, note: note ?? null });
  },

  async rollbackProfileConfig(id: string, revisionId: string): Promise<BootstrapState> {
    if (!isTauriRuntime()) return (await loadPreview()).rollbackProfileConfig(id, revisionId);
    return invoke<BootstrapState>('rollback_profile_config', { id, revisionId });
  },

  async duplicateServerProfile(id: string, customName?: string | null): Promise<BootstrapState> {
    if (!isTauriRuntime()) return (await loadPreview()).duplicateServerProfile(id, customName);
    return invoke<BootstrapState>('duplicate_server_profile', {
      id,
      customName: customName ?? null,
    });
  },

  async runNetworkDoctor(includeExternalProbes: boolean): Promise<NetworkDoctorReport> {
    if (!isTauriRuntime()) return (await loadPreview()).runNetworkDoctor(includeExternalProbes);
    return invoke<NetworkDoctorReport>('run_network_doctor', { includeExternalProbes });
  },

  async getPrivacyInventory(): Promise<PrivacyInventory> {
    if (!isTauriRuntime()) return (await loadPreview()).getPrivacyInventory();
    return invoke<PrivacyInventory>('get_privacy_inventory');
  },

  async rotateDeviceHwid(): Promise<BootstrapState> {
    if (!isTauriRuntime()) return (await loadPreview()).rotateDeviceHwid();
    return invoke<BootstrapState>('rotate_device_hwid');
  },

  async purgePrivacyData(scope: PrivacyPurgeScope): Promise<PrivacyPurgeReport> {
    if (!isTauriRuntime()) return (await loadPreview()).purgePrivacyData(scope);
    return invoke<PrivacyPurgeReport>('purge_privacy_data', { scope });
  },

  async setIpProvider(provider: IpProviderId): Promise<IpMonitorState> {
    if (!isTauriRuntime()) return (await loadPreview()).setIpProvider(provider);
    return invoke<IpMonitorState>('set_ip_provider', { provider });
  },

  async clearOriginalIp(): Promise<IpMonitorState> {
    if (!isTauriRuntime()) return (await loadPreview()).clearOriginalIp();
    return invoke<IpMonitorState>('clear_original_ip');
  },

  async clearIpMonitorCache(): Promise<IpMonitorState> {
    if (!isTauriRuntime()) return (await loadPreview()).clearIpMonitorCache();
    return invoke<IpMonitorState>('clear_ip_monitor_cache');
  },

  async getSubscriptionSyncHistory(id: string): Promise<SubscriptionSyncEntry[]> {
    if (!isTauriRuntime()) return (await loadPreview()).getSubscriptionSyncHistory(id);
    return invoke<SubscriptionSyncEntry[]>('get_subscription_sync_history', { id });
  },

  async runServerSpeedTest(id: string): Promise<SpeedTestResult> {
    if (!isTauriRuntime()) return (await loadPreview()).runServerSpeedTest(id);
    return invoke<SpeedTestResult>('run_server_speed_test', { id });
  },
};
