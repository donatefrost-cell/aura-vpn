export type ProtocolType =
  | 'vless'
  | 'vmess'
  | 'trojan'
  | 'shadowsocks'
  | 'hysteria2'
  | 'wireguard'
  | 'amneziawg'
  | 'rawxray';

export type ConnectionStatus =
  | 'disconnected'
  | 'connecting'
  | 'verifying'
  | 'connected'
  | 'reconnecting'
  | 'switching'
  | 'disconnecting'
  | 'error';

export type ThemeMode = 'dark' | 'light' | 'system';
export type AccentPreset =
  | 'windows'
  | 'indigo'
  | 'blue'
  | 'purple'
  | 'teal'
  | 'green'
  | 'custom';

export type ConnectionMode = 'system_proxy' | 'tun';
export type UpdateChannel = 'stable' | 'beta';
export type KillSwitchMode = 'off' | 'on_drop' | 'always_on' | 'routing_aware';
export type KillSwitchStatus = 'inactive' | 'armed' | 'blocking' | 'degraded' | 'recovery_required';
export type KillSwitchEnforcement = 'none' | 'proxy_guard' | 'wfp_firewall' | 'netsh_fallback';
export type BackgroundStyle = 'standard' | 'aura' | 'minimal' | 'mica';
export type ConfigAdaptationMode = 'auto' | 'profile' | 'manual';
export type ProfileCompatibilityStatus =
  | 'valid'
  | 'valid_with_warnings'
  | 'needs_adaptation'
  | 'incompatible';
export type TunnelHealthState =
  | 'stopped'
  | 'starting'
  | 'port_open'
  | 'tunnel_established'
  | 'verified'
  | 'unstable'
  | 'lost'
  | 'unknown';
export type ProtectionItemStatus = 'verified' | 'issue' | 'limited' | 'unchecked' | 'unavailable';
export type BehaviorProfileId = 'daily' | 'work' | 'gaming' | 'custom';
export type TrafficTimeframe = '1m' | '5m' | '15m' | '1h' | 'session';
export type CoreKind = 'xray' | 'wireproxy_awg' | 'wintun';
export type CoreSelectionMode = 'auto' | 'xray' | 'wireproxy_awg';
export type MtuMode = 'auto' | 'profile' | 'manual';
export type DnsMode = 'auto' | 'config' | 'system' | 'vpn' | 'hybrid' | 'custom';
export type IpProviderId = 'auto' | 'ip_who_is' | 'ip_api_co' | 'ip_info_io' | 'ipify_only';
export type NotificationCategory =
  | 'connection'
  | 'subscription'
  | 'update'
  | 'import'
  | 'duplicate';
export type RoutingProfile =
  | 'all_vpn'
  | 'ru_direct'
  | 'bypass_apps'
  | 'only_apps'
  | 'custom';
export type SplitTunnelMode = 'all_vpn' | 'bypass_apps' | 'only_apps';
export type RuleMatchType = 'domain' | 'ip' | 'process';
export type RuleAction = 'proxy' | 'direct' | 'block';

export type NavTab = 'home' | 'servers' | 'subscriptions' | 'routing' | 'settings';

export interface ProfileOverrides {
  mtu?: number | null;
  customDns?: string | null;
  preferredMode?: ConnectionMode | null;
  preferredCore?: CoreSelectionMode | null;
  mtuMode?: MtuMode | null;
  dnsModeOverride?: DnsMode | null;
  connectTimeoutSecs?: number | null;
  muxOverride?: boolean | null;
}

export interface KillSwitchConfig {
  mode: KillSwitchMode;
  allowLan: boolean;
  blockIpv6Leaks: boolean;
  persistOnExit: boolean;
  reconnectAttempts: number;
}

export interface KillSwitchSnapshot {
  mode: KillSwitchMode;
  status: KillSwitchStatus;
  enforcement: KillSwitchEnforcement;
  blockingActive: boolean;
  needsElevation: boolean;
  allowedExceptions: string[];
  lastReason?: string | null;
  updatedAt?: string | null;
}

export interface EmergencyRecoveryReport {
  wfpFiltersRemoved: boolean;
  legacyNetshRuleRemoved: boolean;
  systemProxyRestored: boolean;
  orphanedProcessesKilled: number;
  staleFilesCleaned: number;
  needsElevation: boolean;
  warnings: string[];
}

export interface TunnelHealthSnapshot {
  state: TunnelHealthState;
  lastCheckedAt?: string | null;
  lastProbeRttMs?: number | null;
  consecutiveFailures: number;
  reason?: string | null;
}

export interface VlessDetails {
  uuid: string;
  encryption: string;
  flow?: string | null;
  network: string;
  security: string;
  sni?: string | null;
  fingerprint?: string | null;
  publicKey?: string | null;
  shortId?: string | null;
  spiderX?: string | null;
  path?: string | null;
  hostHeader?: string | null;
  serviceName?: string | null;
  alpn?: string[] | null;
  allowInsecure: boolean;
  pqv?: string | null;
  grpcAuthority?: string | null;
  grpcMultiMode?: boolean;
  kcpSeed?: string | null;
  wsEarlyData?: number | null;
  wsEarlyDataHeader?: string | null;
}

export interface VmessDetails {
  uuid: string;
  alterId: number;
  cipher: string;
  network: string;
  security: string;
  sni?: string | null;
  fingerprint?: string | null;
  path?: string | null;
  hostHeader?: string | null;
  alpn?: string[] | null;
  allowInsecure: boolean;
  headerType?: string | null;
  serviceName?: string | null;
  grpcAuthority?: string | null;
  grpcMultiMode?: boolean;
  kcpSeed?: string | null;
  xhttpMode?: string | null;
}

export interface TrojanDetails {
  password: string;
  network: string;
  security: string;
  sni?: string | null;
  fingerprint?: string | null;
  publicKey?: string | null;
  shortId?: string | null;
  spiderX?: string | null;
  path?: string | null;
  hostHeader?: string | null;
  serviceName?: string | null;
  alpn?: string[] | null;
  allowInsecure: boolean;
  headerType?: string | null;
  grpcAuthority?: string | null;
  grpcMultiMode?: boolean;
  xhttpMode?: string | null;
}

export interface ShadowsocksDetails {
  method: string;
  password: string;
  uot?: boolean;
  plugin?: string | null;
  pluginOpts?: string | null;
}

export interface Hysteria2Details {
  password: string;
  sni?: string | null;
  obfs?: string | null;
  obfsPassword?: string | null;
  upMbps?: number | null;
  downMbps?: number | null;
  alpn?: string[] | null;
  allowInsecure: boolean;
  mport?: string | null;
  hopIntervalSecs?: number | null;
}

export interface WireguardDetails {
  secretKey: string;
  address: string[];
  publicKey: string;
  presharedKey?: string | null;
  endpoint: string;
  mtu?: number | null;
  dns?: string[];
  reserved?: number[] | null;
  keepalive?: number | null;
}

export interface AmneziaWgDetails {
  secretKey: string;
  address: string[];
  publicKey: string;
  presharedKey?: string | null;
  endpoint: string;
  mtu?: number | null;
  dns?: string[];
  jc?: string | null;
  jmin?: string | null;
  jmax?: string | null;
  s1?: string | null;
  s2?: string | null;
  h1?: string | null;
  h2?: string | null;
  h3?: string | null;
  h4?: string | null;
  extraParams?: Record<string, string>;
  keepalive?: number | null;
}

export interface RawXrayDetails {
  outboundJson: Record<string, unknown>;
  label: string;
  extraOutbounds?: Record<string, unknown>[];
  balancers?: Array<Record<string, unknown>>;
  transportSummary?: string | null;
  nodeCount?: number | null;
}

export type ProtocolDetails =
  | { kind: 'vless'; data: VlessDetails }
  | { kind: 'vmess'; data: VmessDetails }
  | { kind: 'trojan'; data: TrojanDetails }
  | { kind: 'shadowsocks'; data: ShadowsocksDetails }
  | { kind: 'hysteria2'; data: Hysteria2Details }
  | { kind: 'wireguard'; data: WireguardDetails }
  | { kind: 'amneziawg'; data: AmneziaWgDetails }
  | { kind: 'rawxray'; data: RawXrayDetails };

export interface ServerProfile {
  id: string;
  name: string;
  protocol: ProtocolType;
  address: string;
  port: number;
  countryCode?: string | null;
  subscriptionId?: string | null;
  latencyMs?: number | null;
  details: ProtocolDetails;
  createdAt: string;
  favorite: boolean;
  lastUsedAt?: string | null;
  fingerprintKey?: string | null;
  customName?: string | null;
  overrides?: ProfileOverrides | null;
  originalSource?: string | null;
  configRevision?: number;
}

export interface SubscriptionUserInfo {
  uploadBytes?: number | null;
  downloadBytes?: number | null;
  totalBytes?: number | null;
  expireTimestamp?: number | null;
}

export interface SubscriptionErrorEntry {
  timestamp: string;
  message: string;
}

export interface SubscriptionSyncEntry {
  id: string;
  subscriptionId: string;
  timestamp: string;
  status: string;
  added: number;
  removed: number;
  updated: number;
  unchanged: number;
  serverCount: number;
  durationMs: number;
  errorMessage?: string | null;
  backupSnapshotId?: string | null;
}

export interface Subscription {
  id: string;
  title: string;
  url: string;
  updatedAt: string;
  serverCount: number;
  updateIntervalHours?: number | null;
  userInfo?: SubscriptionUserInfo | null;
  lastError?: string | null;
  enabled: boolean;
  autoUpdate: boolean;
  errorHistory: SubscriptionErrorEntry[];
  syncHistory?: SubscriptionSyncEntry[];
}

export interface RoutingRule {
  id: string;
  enabled: boolean;
  matchType: RuleMatchType;
  pattern: string;
  action: RuleAction;
  note?: string | null;
}

export interface RuCategoriesConfig {
  banks: boolean;
  gov: boolean;
  marketplaces: boolean;
  search: boolean;
  social: boolean;
  mail: boolean;
  telecom: boolean;
  education: boolean;
  ruTlds: boolean;
  otherRu: boolean;
}

export interface RoutingConfig {
  profile: RoutingProfile;
  bypassLan: boolean;
  bypassRuDomains: boolean;
  ruCategories: RuCategoriesConfig;
  splitTunnelMode: SplitTunnelMode;
  splitApps: string[];
  customRules: RoutingRule[];
  rulepackUpdateUrl?: string | null;
}

export interface DnsConfig {
  mode: string;
  primaryDns: string;
  fallbackDns?: string | null;
  directDns: string;
  directFallbackDns?: string | null;
  protocolHint?: string;
  disableCache?: boolean;
  disableFallback?: boolean;
  queryStrategy?: string | null;
}

export interface TunSettings {
  adapterName: string;
  mtuMode: MtuMode;
  mtu: number;
  ipv4Address: string;
  ipv6Address: string;
  enableIpv6: boolean;
  strictRoute: boolean;
  bypassLan: boolean;
  autoRoute: boolean;
}

export interface AdvancedVpnSettings {
  coreSelection: CoreSelectionMode;
  coreStartTimeoutSecs: number;
  probeTimeoutSecs: number;
  healthCheckEnabled: boolean;
  healthCheckIntervalSecs: number;
  healthFailureThreshold: number;
  reconnectBaseDelaySecs: number;
  reconnectMaxDelaySecs: number;
  maxParallelPings: number;
  preferredInterface?: string | null;
  tcpKeepaliveIntervalSecs: number;
  tcpFastOpen: boolean;
  tcpNoDelay: boolean;
  dialerDomainStrategy: string;
  muxEnabled: boolean;
  muxConcurrency: number;
  muxXudpConcurrency: number;
  mtuMode: MtuMode;
  manualMtu?: number | null;
  statsApiMode: string;
  statsApiPort?: number | null;
}

export interface AppSettings {
  autostart: boolean;
  startMinimized: boolean;
  minimizeToTray: boolean;
  theme: ThemeMode;
  accentPreset: AccentPreset;
  customAccentHex?: string | null;
  dynamicColor: boolean;
  uiScale: number;
  compactMode: boolean;
  animationsEnabled: boolean;
  sidebarExpanded: boolean;
  connectionMode: ConnectionMode;
  httpPort: number;
  socksPort: number;
  activeServerId?: string | null;
  killSwitchEnabled: boolean;
  killSwitch?: KillSwitchConfig;
  backgroundStyle?: BackgroundStyle;
  configAdaptationMode?: ConfigAdaptationMode;
  autoReconnect: boolean;
  reconnectOnWake: boolean;
  connectTimeoutSecs: number;
  autoConnectOnLaunch: boolean;
  systemNotifications: boolean;
  ipv6Enabled: boolean;
  dns: DnsConfig;
  tun?: TunSettings;
  advanced?: AdvancedVpnSettings;
  preferredIpProvider?: IpProviderId;
  autoCheckIpIntervalSecs?: number;
  autoUpdateRulepack?: boolean;
  keepLocalSubOverrides?: boolean;
  duplicatePolicy?: string;
  logLevel: string;
  autoCheckUpdates: boolean;
  updateFeedUrl?: string | null;
  updateChannel?: UpdateChannel;
  sendHwid: boolean;
  deviceHwid?: string | null;
  historyEnabled: boolean;
  onboardingCompleted: boolean;
  routing: RoutingConfig;
}

export interface ConnectionErrorInfo {
  code: string;
  category: string;
  title: string;
  message: string;
  hint: string;
  action?: 'relaunch_admin' | 'open_settings' | 'disengage_kill_switch' | 'retry' | string | null;
}

export interface ConnectionSnapshot {
  status: ConnectionStatus;
  mode: ConnectionMode;
  activeServerId?: string | null;
  connectedSince?: number | null;
  latencyMs?: number | null;
  errorMessage?: string | null;
  errorInfo?: ConnectionErrorInfo | null;
  systemProxyEnabled: boolean;
  killSwitchEngaged: boolean;
  localHttpPort?: number | null;
  localSocksPort?: number | null;
  health?: TunnelHealthSnapshot;
  killSwitch?: KillSwitchSnapshot;
}

export interface TrafficStats {
  rxBytesPerSec: number;
  txBytesPerSec: number;
  totalRxBytes: number;
  totalTxBytes: number;
}

export interface TrafficSample {
  ts: number;
  rx: number;
  tx: number;
}

export interface LogEntry {
  id: number;
  timestamp: string;
  level: 'info' | 'warn' | 'error';
  source: string;
  message: string;
}

export interface ImportResult {
  importedServers: ServerProfile[];
  skippedLines: number;
  errors: string[];
}

export interface CoreDiagnostics {
  coreName: string;
  coreVersion: string;
  corePath: string;
  coreAvailable: boolean;
  wintunAvailable: boolean;
  awgAvailable: boolean;
  isElevated: boolean;
  killSwitchEngaged: boolean;
  systemProxyActive: boolean;
  activeProxyEndpoint?: string | null;
  configDir: string;
  coreIntegrityOk: boolean;
  awgIntegrityOk: boolean;
  wintunIntegrityOk: boolean;
  integrityNote?: string | null;
}

export interface ServerQualityMetrics {
  lastHttpRttMs?: number | null;
  lastTcpMs?: number | null;
  successCount: number;
  failCount: number;
  consecutiveFailures: number;
  lastSuccessAt?: string | null;
  lastErrorCode?: string | null;
  qualityScore: number;
  qualityLabel: string;
}

export interface ConnectionHistoryEntry {
  id: string;
  serverId?: string | null;
  serverName: string;
  countryCode?: string | null;
  protocol: string;
  mode: ConnectionMode;
  startedAt: string;
  endedAt: string;
  durationSecs: number;
  rxBytes: number;
  txBytes: number;
  endReason: string;
  reconnectCount: number;
}

export interface TrafficAggregateStats {
  todayRxBytes: number;
  todayTxBytes: number;
  weekRxBytes: number;
  weekTxBytes: number;
  monthRxBytes: number;
  monthTxBytes: number;
  totalDurationSecs: number;
  totalSessions: number;
  totalReconnects: number;
}

export interface ConnectionHistoryResponse {
  entries: ConnectionHistoryEntry[];
  aggregates: TrafficAggregateStats;
  serverQuality: Record<string, ServerQualityMetrics>;
}

export interface NetworkCheckItem {
  id: string;
  label: string;
  status: 'ok' | 'warn' | 'fail' | string;
  value: string;
  detail: string;
}

export interface DiagnosticsReport {
  checkedAt: string;
  checks: NetworkCheckItem[];
  externalIp?: string | null;
}

export interface ImportPreviewItem {
  name: string;
  protocol: string;
  address: string;
  port: number;
  countryCode?: string | null;
  isDuplicate: boolean;
}

export interface ConfigAdaptationProposal {
  field: string;
  label: string;
  currentValue: string;
  proposedValue: string;
  reason: string;
  requiresConfirmation: boolean;
  safeToAutoApply: boolean;
}

export interface ProfileCapabilities {
  protocol: string;
  transport: string;
  security: string;
  requiresUdp: boolean;
  supportsSystemProxy: boolean;
  supportsTun: boolean;
  mtu?: number | null;
  dnsServers: string[];
  nodeCount: number;
  hasBalancer: boolean;
  minCoreRequirement: string;
  features: string[];
}

export interface ProfileAnalysisReport {
  serverId?: string | null;
  status: ProfileCompatibilityStatus;
  coreAvailable: boolean;
  protocolSupported: boolean;
  capabilities: ProfileCapabilities;
  warnings: string[];
  unsupportedFields: string[];
  proposals: ConfigAdaptationProposal[];
}

export interface IpEndpointInfo {
  ip: string;
  ipv6?: string | null;
  country?: string | null;
  countryCode?: string | null;
  region?: string | null;
  city?: string | null;
  isp?: string | null;
  org?: string | null;
  asn?: string | null;
  timezone?: string | null;
  networkType?: string | null;
  latencyMs?: number | null;
  checkedAt: string;
  source: string;
  viaVpn: boolean;
  mode: ConnectionMode;
}

export interface IpMonitorState {
  vpnIp?: IpEndpointInfo | null;
  originalIp?: IpEndpointInfo | null;
  ipChanged?: boolean | null;
  ipv6Changed?: boolean | null;
  maskIp: boolean;
  provider?: IpProviderId;
  comparisonNote?: string | null;
}

export interface ProtectionItem {
  id: string;
  label: string;
  status: ProtectionItemStatus;
  value: string;
  detail: string;
  kind: 'config' | 'network' | string;
}

export interface ProtectionCenterSnapshot {
  checkedAt: string;
  items: ProtectionItem[];
  killSwitch: KillSwitchSnapshot;
  ipMonitor: IpMonitorState;
}

export interface SubscriptionRefreshDiff {
  subscriptionId: string;
  added: number;
  removed: number;
  updated: number;
  unchanged: number;
  activeServerChanged: boolean;
  canRollback: boolean;
  warnings: string[];
}

export interface SubscriptionRefreshOutcome {
  diff: SubscriptionRefreshDiff;
  state: BootstrapState;
}

export interface EmergencyRecoveryOutcome {
  report: EmergencyRecoveryReport;
  state: BootstrapState;
}

export interface ImportPreviewResult {
  kind: 'subscription' | 'servers' | string;
  validCount: number;
  duplicateCount: number;
  skippedLines: number;
  errors: string[];
  servers: ImportPreviewItem[];
  warnings?: string[];
  capabilitiesSummary?: string[];
  suggestedAdaptations?: ConfigAdaptationProposal[];
}

export interface BootstrapState {
  profiles: ServerProfile[];
  subscriptions: Subscription[];
  settings: AppSettings;
  connection: ConnectionSnapshot;
  traffic: TrafficStats;
  diagnostics: CoreDiagnostics;
  serverQuality: Record<string, ServerQualityMetrics>;
  needsKillSwitchElevation: boolean;
  killSwitch?: KillSwitchSnapshot;
  ipMonitor?: IpMonitorState;
}

export interface ImportOutcome {
  result: ImportResult;
  state: BootstrapState;
}

export interface SubscriptionImportOutcome {
  subscription: Subscription;
  state: BootstrapState;
}

export interface SmartImportOutcome {
  kind: 'subscription' | 'servers';
  importedCount: number;
  skippedLines: number;
  title?: string | null;
  state: BootstrapState;
}

export interface AutoSelectResult {
  selectedServerId: string;
  serverName: string;
  latencyMs: number;
  state: BootstrapState;
}

export interface WindowModeState {
  miniMode: boolean;
  alwaysOnTop: boolean;
}

export interface BehaviorProfile {
  id: BehaviorProfileId;
  name: string;
  description: string;
  serverId?: string | null;
  connectionMode: ConnectionMode;
  routingProfile: RoutingProfile;
  bypassRuDomains: boolean;
  splitTunnelMode: SplitTunnelMode;
  dns: DnsConfig;
  autoReconnect: boolean;
  reconnectOnWake: boolean;
  killSwitchEnabled: boolean;
  ipv6Enabled: boolean;
}

export interface AppNotification {
  id: string;
  category: NotificationCategory;
  tone: 'success' | 'info' | 'warning' | 'error';
  title: string;
  description?: string;
  createdAt: number;
  read: boolean;
  deepLink?: {
    tab: NavTab;
    settingsSection?: string;
    openDiagnostics?: boolean;
  };
}

export interface UpdateCheckResult {
  currentVersion: string;
  latestVersion?: string | null;
  updateAvailable: boolean;
  status: string;
  message: string;
  releaseUrl?: string | null;
  checkedAt: string;
}

export interface RuCategoryMeta {
  id: string;
  title: string;
  description: string;
  examples: string[];
  domainCount: number;
}

export interface RulepackStatus {
  version: string;
  updatedAt: string;
  source: string;
  totalDomains: number;
  hasBackup: boolean;
  geositePresent: boolean;
  geoipPresent: boolean;
  categories: RuCategoryMeta[];
}

export interface RouteTestResult {
  query: string;
  normalizedHost: string;
  action: 'proxy' | 'direct' | 'block';
  priorityLabel: string;
  matchedRule: string;
  matchedCategory?: string | null;
  explanation: string;
  requiresTunNote: boolean;
  isConfigAnalysis: boolean;
}

export interface DnsRouteCheckResult {
  domain: string;
  resolvedIps: string[];
  error?: string | null;
}

export interface ProxyProbeResult {
  ok: boolean;
  rttMs?: number | null;
  endpoint: string;
  message: string;
}

// ===== v0.8.0 Core Manager, DNS, TUN, Inspector, Config Studio, Doctor & Privacy DTOs =====

export interface CoreCapabilities {
  supportsTun: boolean;
  supportsSystemProxy: boolean;
  supportsDoh: boolean;
  supportsDot: boolean;
  supportsDoq: boolean;
  supportsMux: boolean;
  supportsReality: boolean;
  supportsXhttp: boolean;
  supportsHysteria2: boolean;
  supportsAwg: boolean;
}

export interface CoreHistoryEntry {
  version: string;
  installedAt: string;
  sha256: string;
  path: string;
  canRollback: boolean;
}

export interface InstalledCoreInfo {
  id: string;
  kind: CoreKind;
  name: string;
  license: string;
  version: string;
  availableVersion?: string | null;
  arch: string;
  path: string;
  sizeBytes: number;
  installedAt?: string | null;
  sha256?: string | null;
  expectedSha256?: string | null;
  integrityOk: boolean;
  source: string;
  sourceOrigin: string;
  status: string;
  permissionsNote: string;
  isActive: boolean;
  supportedProtocols: ProtocolType[];
  capabilities: CoreCapabilities;
  history: CoreHistoryEntry[];
}

export interface CoreCompatibilityRow {
  protocol: ProtocolType;
  protocolLabel: string;
  supportedCores: string[];
  requiredAux?: string | null;
  minVersion: string;
  notes: string;
}

export interface CoreInventorySnapshot {
  checkedAt: string;
  cores: InstalledCoreInfo[];
  compatibilityMatrix: CoreCompatibilityRow[];
  singBoxNote: string;
  activeSelection: CoreSelectionMode;
}

export interface CoreUpdateCheckResult {
  coreKind: CoreKind;
  currentVersion: string;
  latestVersion?: string | null;
  updateAvailable: boolean;
  releaseUrl?: string | null;
  assetName?: string | null;
  expectedSha256?: string | null;
  publishedAt?: string | null;
  blockedByActiveConnection: boolean;
  status: string;
  message: string;
}

export interface DnsServerTestResult {
  server: string;
  protocol: string;
  reachable: boolean;
  latencyMs?: number | null;
  resolvedIps: string[];
  error?: string | null;
  viaVpn: boolean;
}

export interface DnsConfigAnalysis {
  effectiveMode: string;
  activeServers: string[];
  directServers: string[];
  directDomainsCount: number;
  tunDnsHijackActive: boolean;
  systemProxyDnsNote: string;
  cacheEnabled: boolean;
  fallbackEnabled: boolean;
  ipv6QueryStrategy: string;
  leakRiskLevel: string;
  warnings: string[];
}

export interface DnsLiveLookupResult {
  domain: string;
  resolverUsed: string;
  resolvedIps: string[];
  latencyMs?: number | null;
  bypassedVpnWarning: boolean;
  error?: string | null;
}

export interface DnsInspectorReport {
  checkedAt: string;
  configAnalysis: DnsConfigAnalysis;
  liveLookup?: DnsLiveLookupResult | null;
}

export interface TunAdapterStatus {
  adapterPresent: boolean;
  adapterName: string;
  interfaceIndex?: number | null;
  status: string;
  mtu?: number | null;
  ipv4Addresses: string[];
  ipv6Addresses: string[];
  dnsServers: string[];
  wintunVersion?: string | null;
  wintunPresent: boolean;
  wintunIntegrityOk: boolean;
  driverStatus: string;
  isElevated: boolean;
}

export interface VirtualAdapterConflict {
  adapterName: string;
  interfaceDescription: string;
  category: string;
  status: string;
  severity: string;
  detail: string;
}

export interface TunManagerSnapshot {
  checkedAt: string;
  settings: TunSettings;
  adapter: TunAdapterStatus;
  conflicts: VirtualAdapterConflict[];
}

export interface ConnectionStageFlags {
  coreProcessRunning: boolean;
  auxProcessRunning?: boolean | null;
  localProxyListening: boolean;
  tunAdapterUp: boolean;
  tunnelEstablished: boolean;
  internetVerified: boolean;
}

export interface ThroughputSummary {
  currentRxBps: number;
  currentTxBps: number;
  avgRxBps: number;
  avgTxBps: number;
  peakRxBps: number;
  peakTxBps: number;
  totalRxBytes: number;
  totalTxBytes: number;
  sampleCount: number;
}

export interface ConnectionTimelineEvent {
  id: number;
  timestamp: string;
  stage: string;
  level: string;
  message: string;
  latencyMs?: number | null;
}

export interface ConnectionInspectorSnapshot {
  status: ConnectionStatus;
  stages: ConnectionStageFlags;
  mode: ConnectionMode;
  activeServerId?: string | null;
  activeServerName?: string | null;
  protocol?: string | null;
  activeCoreName: string;
  activeCoreVersion: string;
  activeAdapterName?: string | null;
  routingProfile: RoutingProfile;
  dnsMode: string;
  tcpLatencyMs?: number | null;
  httpRttMs?: number | null;
  uptimeSecs: number;
  reconnectCount: number;
  killSwitch: KillSwitchSnapshot;
  throughput: ThroughputSummary;
  timeline: ConnectionTimelineEvent[];
}

export interface ConfigDiffEntry {
  path: string;
  layer: string;
  changeType: string;
  before?: string | null;
  after?: string | null;
  reason: string;
}

export interface ProfileEditRevisionMeta {
  revisionId: string;
  timestamp: string;
  note: string;
  summary: string;
}

export interface ConfigValidationResult {
  ok: boolean;
  coreTested: boolean;
  errors: string[];
  warnings: string[];
  strippedFields: string[];
}

export interface ConfigStudioView {
  profileId: string;
  format: string;
  effectiveCore: string;
  effectiveMtu: number;
  mtuSource: string;
  effectiveDns: string;
  dnsSource: string;
  effectiveMode: ConnectionMode;
  modeSource: string;
  layer1Imported: Record<string, unknown>;
  layer2WithOverrides: Record<string, unknown>;
  layer3InjectedSummary: string[];
  layer4FinalSanitized: Record<string, unknown>;
  awgConfigPreview?: string | null;
  strippedGuardrails: ConfigDiffEntry[];
  diffs: ConfigDiffEntry[];
  validationOk?: boolean | null;
  validationError?: string | null;
  revisions: ProfileEditRevisionMeta[];
}

export type DoctorCheckSeverity = 'pass' | 'warn' | 'fail' | 'info' | 'skipped';

export interface DoctorCheckResult {
  id: string;
  category: string;
  title: string;
  severity: DoctorCheckSeverity;
  summary: string;
  detail: string;
  recommendedAction?: string | null;
  durationMs: number;
}

export interface NetworkDoctorReport {
  checkedAt: string;
  overallStatus: DoctorCheckSeverity;
  passCount: number;
  warnCount: number;
  failCount: number;
  checks: DoctorCheckResult[];
}

export interface PrivacyNetworkDisclosure {
  id: string;
  title: string;
  enabled: boolean;
  trigger: string;
  destination: string;
  dataSent: string;
}

export interface PrivacyInventory {
  configDir: string;
  dpapiEncryptedFiles: string[];
  plaintextFiles: string[];
  historyEntriesCount: number;
  savedOriginalIpPresent: boolean;
  savedVpnIpPresent: boolean;
  logsCount: number;
  subBackupsCount: number;
  syncHistoryCount: number;
  sendHwid: boolean;
  hwidMasked?: string | null;
  externalNetworkFeatures: PrivacyNetworkDisclosure[];
}

export interface PrivacyPurgeScope {
  clearHistory: boolean;
  clearOriginalIp: boolean;
  clearVpnIp: boolean;
  clearLogs: boolean;
  clearServerQuality: boolean;
  clearSubBackups: boolean;
  clearSyncHistory: boolean;
  clearProfileEditHistory: boolean;
}

export interface PrivacyPurgeReport {
  itemsRemoved: number;
  summary: string;
}

export interface SpeedTestResult {
  ok: boolean;
  serverId: string;
  bytesDownloaded: number;
  durationMs: number;
  mbps: number;
  viaVpn: boolean;
  note: string;
}
