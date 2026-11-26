use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolType {
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    Hysteria2,
    Wireguard,
    AmneziaWg,
    RawXray,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VlessDetails {
    pub uuid: String,
    pub encryption: String,
    pub flow: Option<String>,
    pub network: String,
    pub security: String,
    pub sni: Option<String>,
    pub fingerprint: Option<String>,
    pub public_key: Option<String>,
    pub short_id: Option<String>,
    pub spider_x: Option<String>,
    pub path: Option<String>,
    pub host_header: Option<String>,
    pub service_name: Option<String>,
    pub alpn: Option<Vec<String>>,
    #[serde(default)]
    pub allow_insecure: bool,
    #[serde(default)]
    pub pinned_cert_sha256: Option<String>,
    #[serde(default)]
    pub verify_peer_cert_by_name: Option<String>,
    #[serde(default)]
    pub header_type: Option<String>,
    #[serde(default)]
    pub xhttp_mode: Option<String>,
    #[serde(default)]
    pub xhttp_extra: Option<serde_json::Value>,
    #[serde(default)]
    pub pqv: Option<String>,
    #[serde(default)]
    pub grpc_authority: Option<String>,
    #[serde(default)]
    pub grpc_multi_mode: bool,
    #[serde(default)]
    pub kcp_seed: Option<String>,
    #[serde(default)]
    pub ws_early_data: Option<u32>,
    #[serde(default)]
    pub ws_early_data_header: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VmessDetails {
    pub uuid: String,
    pub alter_id: u16,
    pub cipher: String,
    pub network: String,
    pub security: String,
    pub sni: Option<String>,
    pub fingerprint: Option<String>,
    pub path: Option<String>,
    pub host_header: Option<String>,
    pub alpn: Option<Vec<String>>,
    #[serde(default)]
    pub allow_insecure: bool,
    #[serde(default)]
    pub pinned_cert_sha256: Option<String>,
    #[serde(default)]
    pub verify_peer_cert_by_name: Option<String>,
    #[serde(default)]
    pub header_type: Option<String>,
    #[serde(default)]
    pub service_name: Option<String>,
    #[serde(default)]
    pub grpc_authority: Option<String>,
    #[serde(default)]
    pub grpc_multi_mode: bool,
    #[serde(default)]
    pub kcp_seed: Option<String>,
    #[serde(default)]
    pub xhttp_mode: Option<String>,
    #[serde(default)]
    pub xhttp_extra: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrojanDetails {
    pub password: String,
    pub network: String,
    pub security: String,
    pub sni: Option<String>,
    pub fingerprint: Option<String>,
    pub public_key: Option<String>,
    pub short_id: Option<String>,
    pub path: Option<String>,
    pub host_header: Option<String>,
    pub service_name: Option<String>,
    pub alpn: Option<Vec<String>>,
    #[serde(default)]
    pub allow_insecure: bool,
    #[serde(default)]
    pub pinned_cert_sha256: Option<String>,
    #[serde(default)]
    pub verify_peer_cert_by_name: Option<String>,
    #[serde(default)]
    pub spider_x: Option<String>,
    #[serde(default)]
    pub header_type: Option<String>,
    #[serde(default)]
    pub grpc_authority: Option<String>,
    #[serde(default)]
    pub grpc_multi_mode: bool,
    #[serde(default)]
    pub xhttp_mode: Option<String>,
    #[serde(default)]
    pub xhttp_extra: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShadowsocksDetails {
    pub method: String,
    pub password: String,
    #[serde(default)]
    pub uot: bool,
    #[serde(default)]
    pub plugin: Option<String>,
    #[serde(default)]
    pub plugin_opts: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hysteria2Details {
    pub password: String,
    pub sni: Option<String>,
    pub obfs: Option<String>,
    pub obfs_password: Option<String>,
    pub up_mbps: Option<u32>,
    pub down_mbps: Option<u32>,
    pub alpn: Option<Vec<String>>,
    #[serde(default)]
    pub allow_insecure: bool,
    #[serde(default)]
    pub pinned_cert_sha256: Option<String>,
    #[serde(default)]
    pub verify_peer_cert_by_name: Option<String>,
    #[serde(default)]
    pub mport: Option<String>,
    #[serde(default)]
    pub hop_interval_secs: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireguardDetails {
    pub secret_key: String,
    pub address: Vec<String>,
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub endpoint: String,
    pub mtu: Option<u16>,
    #[serde(default)]
    pub dns: Vec<String>,
    #[serde(default)]
    pub reserved: Option<Vec<u8>>,
    #[serde(default)]
    pub keepalive: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AmneziaWgDetails {
    pub secret_key: String,
    pub address: Vec<String>,
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub endpoint: String,
    pub mtu: Option<u16>,
    #[serde(default)]
    pub dns: Vec<String>,
    pub jc: Option<String>,
    pub jmin: Option<String>,
    pub jmax: Option<String>,
    pub s1: Option<String>,
    pub s2: Option<String>,
    pub h1: Option<String>,
    pub h2: Option<String>,
    pub h3: Option<String>,
    pub h4: Option<String>,
    #[serde(default)]
    pub extra_params: HashMap<String, String>,
    #[serde(default)]
    pub keepalive: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawXrayDetails {
    pub outbound_json: serde_json::Value,
    pub label: String,
    #[serde(default)]
    pub extra_outbounds: Vec<serde_json::Value>,
    #[serde(default)]
    pub balancers: Vec<serde_json::Value>,
    #[serde(default)]
    pub observatory: Option<serde_json::Value>,
    #[serde(default)]
    pub burst_observatory: Option<serde_json::Value>,
    #[serde(default)]
    pub transport_summary: Option<String>,
    #[serde(default)]
    pub node_count: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "lowercase")]
pub enum ProtocolDetails {
    Vless(VlessDetails),
    Vmess(VmessDetails),
    Trojan(TrojanDetails),
    Shadowsocks(ShadowsocksDetails),
    Hysteria2(Hysteria2Details),
    Wireguard(WireguardDetails),
    AmneziaWg(AmneziaWgDetails),
    RawXray(RawXrayDetails),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CoreKind {
    #[default]
    Xray,
    WireproxyAwg,
    Wintun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CoreSelectionMode {
    #[default]
    Auto,
    Xray,
    WireproxyAwg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MtuMode {
    #[default]
    Auto,
    Profile,
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ProfileOverrides {
    pub mtu: Option<u16>,
    pub custom_dns: Option<String>,
    pub preferred_mode: Option<ConnectionMode>,
    pub preferred_core: Option<CoreSelectionMode>,
    pub mtu_mode: Option<MtuMode>,
    pub dns_mode_override: Option<DnsMode>,
    pub connect_timeout_secs: Option<u64>,
    pub mux_override: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerProfile {
    pub id: String,
    pub name: String,
    pub protocol: ProtocolType,
    pub address: String,
    pub port: u16,
    pub country_code: Option<String>,
    pub subscription_id: Option<String>,
    pub latency_ms: Option<u64>,
    pub details: ProtocolDetails,
    pub created_at: String,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub last_used_at: Option<String>,
    #[serde(default)]
    pub fingerprint_key: Option<String>,
    #[serde(default)]
    pub custom_name: Option<String>,
    #[serde(default)]
    pub overrides: Option<ProfileOverrides>,
    #[serde(default)]
    pub original_source: Option<String>,
    #[serde(default)]
    pub config_revision: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionUserInfo {
    pub upload_bytes: Option<u64>,
    pub download_bytes: Option<u64>,
    pub total_bytes: Option<u64>,
    pub expire_timestamp: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionErrorEntry {
    pub timestamp: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionSyncEntry {
    pub id: String,
    pub subscription_id: String,
    pub timestamp: String,
    pub status: String,
    pub added: usize,
    pub removed: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub server_count: usize,
    pub duration_ms: u64,
    pub error_message: Option<String>,
    pub backup_snapshot_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Subscription {
    pub id: String,
    pub title: String,
    pub url: String,
    pub updated_at: String,
    pub server_count: usize,
    pub update_interval_hours: Option<u32>,
    pub user_info: Option<SubscriptionUserInfo>,
    pub last_error: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub auto_update: bool,
    #[serde(default)]
    pub error_history: Vec<SubscriptionErrorEntry>,
    #[serde(default)]
    pub sync_history: Vec<SubscriptionSyncEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ThemeMode {
    #[default]
    Dark,
    Light,
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AccentPreset {
    Windows,
    #[default]
    Indigo,
    Blue,
    Purple,
    Teal,
    Green,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionMode {
    #[default]
    SystemProxy,
    Tun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RoutingProfile {
    #[default]
    AllVpn,
    RuDirect,
    BypassApps,
    OnlyApps,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SplitTunnelMode {
    #[default]
    AllVpn,
    BypassApps,
    OnlyApps,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleMatchType {
    Domain,
    Ip,
    Process,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Proxy,
    Direct,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutingRule {
    pub id: String,
    pub enabled: bool,
    pub match_type: RuleMatchType,
    pub pattern: String,
    pub action: RuleAction,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RuCategoriesConfig {
    pub banks: bool,
    pub gov: bool,
    pub marketplaces: bool,
    pub search: bool,
    pub social: bool,
    pub mail: bool,
    pub telecom: bool,
    pub education: bool,
    pub ru_tlds: bool,
    pub other_ru: bool,
}

impl Default for RuCategoriesConfig {
    fn default() -> Self {
        Self {
            banks: true,
            gov: true,
            marketplaces: true,
            search: true,
            social: true,
            mail: true,
            telecom: true,
            education: true,
            ru_tlds: true,
            other_ru: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RoutingConfig {
    pub profile: RoutingProfile,
    pub bypass_lan: bool,
    pub bypass_ru_domains: bool,
    pub ru_categories: RuCategoriesConfig,
    pub split_tunnel_mode: SplitTunnelMode,
    pub split_apps: Vec<String>,
    pub custom_rules: Vec<RoutingRule>,
    pub rulepack_update_url: Option<String>,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            profile: RoutingProfile::AllVpn,
            bypass_lan: true,
            bypass_ru_domains: false,
            ru_categories: RuCategoriesConfig::default(),
            split_tunnel_mode: SplitTunnelMode::AllVpn,
            split_apps: Vec::new(),
            custom_rules: Vec::new(),
            rulepack_update_url: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DnsMode {
    Auto,
    Config,
    System,
    Vpn,
    #[default]
    Hybrid,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DnsConfig {
    pub mode: String,
    pub primary_dns: String,
    pub fallback_dns: Option<String>,
    pub direct_dns: String,
    pub direct_fallback_dns: Option<String>,
    pub protocol_hint: String,
    pub disable_cache: bool,
    pub disable_fallback: bool,
    pub query_strategy: Option<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            mode: "hybrid".to_string(),
            primary_dns: "1.1.1.1".to_string(),
            fallback_dns: Some("8.8.8.8".to_string()),
            direct_dns: "77.88.8.8".to_string(),
            direct_fallback_dns: Some("77.88.8.1".to_string()),
            protocol_hint: "plain".to_string(),
            disable_cache: false,
            disable_fallback: false,
            query_strategy: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TunSettings {
    pub adapter_name: String,
    pub mtu_mode: MtuMode,
    pub mtu: u16,
    pub ipv4_address: String,
    pub ipv6_address: String,
    pub enable_ipv6: bool,
    pub strict_route: bool,
    pub bypass_lan: bool,
    pub auto_route: bool,
}

impl Default for TunSettings {
    fn default() -> Self {
        Self {
            adapter_name: "aura_tun".to_string(),
            mtu_mode: MtuMode::Auto,
            mtu: 1500,
            ipv4_address: "10.24.0.1/24".to_string(),
            ipv6_address: "fd00:10:24::1/126".to_string(),
            enable_ipv6: false,
            strict_route: true,
            bypass_lan: true,
            auto_route: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AdvancedVpnSettings {
    pub core_selection: CoreSelectionMode,
    pub core_start_timeout_secs: u64,
    pub probe_timeout_secs: u64,
    pub health_check_enabled: bool,
    pub health_check_interval_secs: u64,
    pub health_failure_threshold: u32,
    pub reconnect_base_delay_secs: u64,
    pub reconnect_max_delay_secs: u64,
    pub max_parallel_pings: usize,
    pub preferred_interface: Option<String>,
    pub tcp_keepalive_interval_secs: u32,
    pub tcp_fast_open: bool,
    pub tcp_no_delay: bool,
    pub dialer_domain_strategy: String,
    pub mux_enabled: bool,
    pub mux_concurrency: i16,
    pub mux_xudp_concurrency: i16,
    pub mtu_mode: MtuMode,
    pub manual_mtu: Option<u16>,
    pub stats_api_mode: String,
    pub stats_api_port: Option<u16>,
}

impl Default for AdvancedVpnSettings {
    fn default() -> Self {
        Self {
            core_selection: CoreSelectionMode::Auto,
            core_start_timeout_secs: 6,
            probe_timeout_secs: 10,
            health_check_enabled: true,
            health_check_interval_secs: 30,
            health_failure_threshold: 2,
            reconnect_base_delay_secs: 2,
            reconnect_max_delay_secs: 15,
            max_parallel_pings: 12,
            preferred_interface: None,
            tcp_keepalive_interval_secs: 0,
            tcp_fast_open: false,
            tcp_no_delay: true,
            dialer_domain_strategy: "AsIs".to_string(),
            mux_enabled: false,
            mux_concurrency: 8,
            mux_xudp_concurrency: 8,
            mtu_mode: MtuMode::Auto,
            manual_mtu: None,
            stats_api_mode: "ephemeral".to_string(),
            stats_api_port: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitchMode {
    #[default]
    Off,
    OnDrop,
    AlwaysOn,
    RoutingAware,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitchStatus {
    #[default]
    Inactive,
    Armed,
    Blocking,
    Degraded,
    RecoveryRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitchEnforcement {
    #[default]
    None,
    ProxyGuard,
    WfpFirewall,
    NetshFallback,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct KillSwitchConfig {
    pub mode: KillSwitchMode,
    pub allow_lan: bool,
    pub block_ipv6_leaks: bool,
    pub persist_on_exit: bool,
    pub reconnect_attempts: u32,
}

impl Default for KillSwitchConfig {
    fn default() -> Self {
        Self {
            mode: KillSwitchMode::Off,
            allow_lan: true,
            block_ipv6_leaks: true,
            persist_on_exit: false,
            reconnect_attempts: 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct KillSwitchSnapshot {
    pub mode: KillSwitchMode,
    pub status: KillSwitchStatus,
    pub enforcement: KillSwitchEnforcement,
    pub blocking_active: bool,
    pub needs_elevation: bool,
    pub allowed_exceptions: Vec<String>,
    pub last_reason: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct EmergencyRecoveryReport {
    pub wfp_filters_removed: bool,
    pub legacy_netsh_rule_removed: bool,
    pub system_proxy_restored: bool,
    pub orphaned_processes_killed: usize,
    pub stale_files_cleaned: usize,
    pub needs_elevation: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BackgroundStyle {
    Standard,
    #[default]
    Aura,
    Minimal,
    Mica,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ConfigAdaptationMode {
    #[default]
    Auto,
    Profile,
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UpdateChannel {
    #[default]
    Stable,
    Beta,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct WindowModeState {
    pub mini_mode: bool,
    pub always_on_top: bool,
}

fn default_true() -> bool {
    true
}

fn default_ui_scale() -> u16 {
    100
}

fn default_connect_timeout() -> u64 {
    10
}

fn default_log_level() -> String {
    "warning".to_string()
}

fn default_duplicate_policy() -> String {
    "merge".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AppSettings {
    pub autostart: bool,
    pub start_minimized: bool,
    pub minimize_to_tray: bool,
    pub theme: ThemeMode,
    #[serde(default)]
    pub accent_preset: AccentPreset,
    #[serde(default)]
    pub custom_accent_hex: Option<String>,
    #[serde(default = "default_true")]
    pub dynamic_color: bool,
    #[serde(default = "default_ui_scale")]
    pub ui_scale: u16,
    #[serde(default)]
    pub compact_mode: bool,
    #[serde(default = "default_true")]
    pub animations_enabled: bool,
    #[serde(default)]
    pub sidebar_expanded: bool,
    pub connection_mode: ConnectionMode,
    pub http_port: u16,
    pub socks_port: u16,
    pub active_server_id: Option<String>,
    pub kill_switch_enabled: bool,
    #[serde(default)]
    pub kill_switch: KillSwitchConfig,
    #[serde(default)]
    pub background_style: BackgroundStyle,
    #[serde(default)]
    pub config_adaptation_mode: ConfigAdaptationMode,
    #[serde(default = "default_true")]
    pub auto_reconnect: bool,
    #[serde(default = "default_true")]
    pub reconnect_on_wake: bool,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
    #[serde(default)]
    pub auto_connect_on_launch: bool,
    #[serde(default = "default_true")]
    pub system_notifications: bool,
    #[serde(default)]
    pub ipv6_enabled: bool,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub tun: TunSettings,
    #[serde(default)]
    pub advanced: AdvancedVpnSettings,
    #[serde(default)]
    pub preferred_ip_provider: IpProviderId,
    #[serde(default)]
    pub auto_check_ip_interval_secs: u64,
    #[serde(default = "default_true")]
    pub auto_update_rulepack: bool,
    #[serde(default = "default_true")]
    pub keep_local_sub_overrides: bool,
    #[serde(default = "default_duplicate_policy")]
    pub duplicate_policy: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    pub auto_check_updates: bool,
    pub update_feed_url: Option<String>,
    #[serde(default)]
    pub update_channel: UpdateChannel,
    #[serde(default = "default_true")]
    pub send_hwid: bool,
    #[serde(default)]
    pub device_hwid: Option<String>,
    #[serde(default = "default_true")]
    pub history_enabled: bool,
    #[serde(default)]
    pub onboarding_completed: bool,
    pub routing: RoutingConfig,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            autostart: false,
            start_minimized: false,
            minimize_to_tray: true,
            theme: ThemeMode::Dark,
            accent_preset: AccentPreset::Indigo,
            custom_accent_hex: None,
            dynamic_color: true,
            ui_scale: 100,
            compact_mode: false,
            animations_enabled: true,
            sidebar_expanded: false,
            connection_mode: ConnectionMode::SystemProxy,
            http_port: 10809,
            socks_port: 10808,
            active_server_id: None,
            kill_switch_enabled: false,
            kill_switch: KillSwitchConfig::default(),
            background_style: BackgroundStyle::Aura,
            config_adaptation_mode: ConfigAdaptationMode::Auto,
            auto_reconnect: true,
            reconnect_on_wake: true,
            connect_timeout_secs: 10,
            auto_connect_on_launch: false,
            system_notifications: true,
            ipv6_enabled: false,
            dns: DnsConfig::default(),
            tun: TunSettings::default(),
            advanced: AdvancedVpnSettings::default(),
            preferred_ip_provider: IpProviderId::Auto,
            auto_check_ip_interval_secs: 0,
            auto_update_rulepack: true,
            keep_local_sub_overrides: true,
            duplicate_policy: "merge".to_string(),
            log_level: "warning".to_string(),
            auto_check_updates: false,
            update_feed_url: None,
            update_channel: UpdateChannel::Stable,
            send_hwid: true,
            device_hwid: None,
            history_enabled: true,
            onboarding_completed: false,
            routing: RoutingConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Verifying,
    Connected,
    Reconnecting,
    Switching,
    Disconnecting,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionErrorInfo {
    pub code: String,
    pub category: String,
    pub title: String,
    pub message: String,
    pub hint: String,
    pub action: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TunnelHealthState {
    #[default]
    Stopped,
    Starting,
    PortOpen,
    TunnelEstablished,
    Verified,
    Unstable,
    Lost,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct TunnelHealthSnapshot {
    pub state: TunnelHealthState,
    pub consecutive_failures: u32,
    pub last_probe_rtt_ms: Option<u64>,
    pub last_checked_at: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionSnapshot {
    pub status: ConnectionStatus,
    pub mode: ConnectionMode,
    pub active_server_id: Option<String>,
    pub connected_since: Option<i64>,
    pub latency_ms: Option<u64>,
    pub error_message: Option<String>,
    #[serde(default)]
    pub error_info: Option<ConnectionErrorInfo>,
    pub system_proxy_enabled: bool,
    pub kill_switch_engaged: bool,
    pub local_http_port: Option<u16>,
    pub local_socks_port: Option<u16>,
    #[serde(default)]
    pub health: TunnelHealthSnapshot,
    #[serde(default)]
    pub kill_switch: KillSwitchSnapshot,
}

impl Default for ConnectionSnapshot {
    fn default() -> Self {
        Self {
            status: ConnectionStatus::Disconnected,
            mode: ConnectionMode::SystemProxy,
            active_server_id: None,
            connected_since: None,
            latency_ms: None,
            error_message: None,
            error_info: None,
            system_proxy_enabled: false,
            kill_switch_engaged: false,
            local_http_port: None,
            local_socks_port: None,
            health: TunnelHealthSnapshot::default(),
            kill_switch: KillSwitchSnapshot::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TrafficStats {
    pub rx_bytes_per_sec: u64,
    pub tx_bytes_per_sec: u64,
    pub total_rx_bytes: u64,
    pub total_tx_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    pub id: u64,
    pub timestamp: String,
    pub level: LogLevel,
    pub source: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub imported_servers: Vec<ServerProfile>,
    pub skipped_lines: usize,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreDiagnostics {
    pub core_name: String,
    pub core_version: String,
    pub core_path: String,
    pub core_available: bool,
    pub wintun_available: bool,
    #[serde(default)]
    pub awg_available: bool,
    pub is_elevated: bool,
    pub kill_switch_engaged: bool,
    pub system_proxy_active: bool,
    pub active_proxy_endpoint: Option<String>,
    pub config_dir: String,
    #[serde(default)]
    pub core_integrity_ok: bool,
    #[serde(default)]
    pub awg_integrity_ok: bool,
    #[serde(default)]
    pub wintun_integrity_ok: bool,
    #[serde(default)]
    pub integrity_note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ServerQualityMetrics {
    pub last_http_rtt_ms: Option<u64>,
    pub last_tcp_ms: Option<u64>,
    pub success_count: u32,
    pub fail_count: u32,
    pub consecutive_failures: u32,
    pub last_success_at: Option<String>,
    pub last_error_code: Option<String>,
    pub quality_score: u8,
    pub quality_label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionHistoryEntry {
    pub id: String,
    pub server_id: Option<String>,
    pub server_name: String,
    pub country_code: Option<String>,
    pub protocol: String,
    pub mode: ConnectionMode,
    pub started_at: String,
    pub ended_at: String,
    pub duration_secs: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub end_reason: String,
    pub reconnect_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct TrafficAggregateStats {
    pub today_rx_bytes: u64,
    pub today_tx_bytes: u64,
    pub week_rx_bytes: u64,
    pub week_tx_bytes: u64,
    pub month_rx_bytes: u64,
    pub month_tx_bytes: u64,
    pub total_duration_secs: u64,
    pub total_sessions: u64,
    pub total_reconnects: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionHistoryResponse {
    pub entries: Vec<ConnectionHistoryEntry>,
    pub aggregates: TrafficAggregateStats,
    pub server_quality: HashMap<String, ServerQualityMetrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkCheckItem {
    pub id: String,
    pub label: String,
    pub status: String,
    pub value: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsReport {
    pub checked_at: String,
    pub checks: Vec<NetworkCheckItem>,
    pub external_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreviewItem {
    pub name: String,
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub country_code: Option<String>,
    pub is_duplicate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreviewResult {
    pub kind: String,
    pub valid_count: usize,
    pub duplicate_count: usize,
    pub skipped_lines: usize,
    pub errors: Vec<String>,
    pub servers: Vec<ImportPreviewItem>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub capabilities_summary: Vec<String>,
    #[serde(default)]
    pub suggested_adaptations: Vec<ConfigAdaptationProposal>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileCompatibilityStatus {
    Valid,
    ValidWithWarnings,
    NeedsAdaptation,
    Incompatible,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigAdaptationProposal {
    pub field: String,
    pub label: String,
    pub current_value: String,
    pub proposed_value: String,
    pub reason: String,
    pub requires_confirmation: bool,
    pub safe_to_auto_apply: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileCapabilities {
    pub protocol: String,
    pub transport: String,
    pub security: String,
    pub requires_udp: bool,
    pub supports_system_proxy: bool,
    pub supports_tun: bool,
    pub mtu: Option<u16>,
    pub dns_servers: Vec<String>,
    pub node_count: usize,
    pub has_balancer: bool,
    pub min_core_requirement: String,
    pub features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileAnalysisReport {
    pub server_id: Option<String>,
    pub status: ProfileCompatibilityStatus,
    pub core_available: bool,
    pub protocol_supported: bool,
    pub capabilities: ProfileCapabilities,
    pub warnings: Vec<String>,
    pub unsupported_fields: Vec<String>,
    pub proposals: Vec<ConfigAdaptationProposal>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum IpProviderId {
    #[default]
    Auto,
    IpWhoIs,
    IpApiCo,
    IpInfoIo,
    IpifyOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpEndpointInfo {
    pub ip: String,
    pub ipv6: Option<String>,
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    #[serde(default)]
    pub org: Option<String>,
    pub asn: Option<String>,
    #[serde(default)]
    pub timezone: Option<String>,
    #[serde(default)]
    pub network_type: Option<String>,
    #[serde(default)]
    pub latency_ms: Option<u64>,
    pub checked_at: String,
    pub source: String,
    pub via_vpn: bool,
    pub mode: ConnectionMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct IpMonitorState {
    pub vpn_ip: Option<IpEndpointInfo>,
    pub original_ip: Option<IpEndpointInfo>,
    pub ip_changed: Option<bool>,
    pub ipv6_changed: Option<bool>,
    pub mask_ip: bool,
    pub provider: IpProviderId,
    pub comparison_note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionItemStatus {
    Verified,
    Issue,
    Limited,
    Unchecked,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectionItem {
    pub id: String,
    pub label: String,
    pub status: ProtectionItemStatus,
    pub value: String,
    pub detail: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectionCenterSnapshot {
    pub checked_at: String,
    pub items: Vec<ProtectionItem>,
    pub kill_switch: KillSwitchSnapshot,
    pub ip_monitor: IpMonitorState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionRefreshDiff {
    pub subscription_id: String,
    pub added: usize,
    pub removed: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub active_server_changed: bool,
    pub can_rollback: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionRefreshOutcome {
    pub diff: SubscriptionRefreshDiff,
    pub state: BootstrapState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapState {
    pub profiles: Vec<ServerProfile>,
    pub subscriptions: Vec<Subscription>,
    pub settings: AppSettings,
    pub connection: ConnectionSnapshot,
    pub traffic: TrafficStats,
    pub diagnostics: CoreDiagnostics,
    #[serde(default)]
    pub server_quality: HashMap<String, ServerQualityMetrics>,
    #[serde(default)]
    pub needs_kill_switch_elevation: bool,
    #[serde(default)]
    pub kill_switch: KillSwitchSnapshot,
    #[serde(default)]
    pub ip_monitor: IpMonitorState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoSelectResult {
    pub selected_server_id: String,
    pub server_name: String,
    pub latency_ms: u64,
    pub state: BootstrapState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCheckResult {
    pub current_version: String,
    pub latest_version: Option<String>,
    pub update_available: bool,
    pub status: String,
    pub message: String,
    pub release_url: Option<String>,
    pub checked_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuCategoryMeta {
    pub id: String,
    pub title: String,
    pub description: String,
    pub examples: Vec<String>,
    pub domain_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RulepackStatus {
    pub version: String,
    pub updated_at: String,
    pub source: String,
    pub total_domains: usize,
    pub has_backup: bool,
    pub geosite_present: bool,
    pub geoip_present: bool,
    pub categories: Vec<RuCategoryMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteTestResult {
    pub query: String,
    pub normalized_host: String,
    pub action: String,
    pub priority_label: String,
    pub matched_rule: String,
    pub matched_category: Option<String>,
    pub explanation: String,
    pub requires_tun_note: bool,
    pub is_config_analysis: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsRouteCheckResult {
    pub domain: String,
    pub resolved_ips: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyProbeResult {
    pub ok: bool,
    pub rtt_ms: Option<u64>,
    pub endpoint: String,
    pub message: String,
}

// ===== v0.8.0 Core Manager, DNS, TUN, Inspector, Config Studio, Doctor & Privacy DTOs =====

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct CoreCapabilities {
    pub supports_tun: bool,
    pub supports_system_proxy: bool,
    pub supports_doh: bool,
    pub supports_dot: bool,
    pub supports_doq: bool,
    pub supports_mux: bool,
    pub supports_reality: bool,
    pub supports_xhttp: bool,
    pub supports_hysteria2: bool,
    pub supports_awg: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreHistoryEntry {
    pub version: String,
    pub installed_at: String,
    pub sha256: String,
    pub path: String,
    pub can_rollback: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledCoreInfo {
    pub id: String,
    pub kind: CoreKind,
    pub name: String,
    pub license: String,
    pub version: String,
    pub available_version: Option<String>,
    pub arch: String,
    pub path: String,
    pub size_bytes: u64,
    pub installed_at: Option<String>,
    pub sha256: Option<String>,
    pub expected_sha256: Option<String>,
    pub integrity_ok: bool,
    pub source: String,
    pub source_origin: String,
    pub status: String,
    pub permissions_note: String,
    pub is_active: bool,
    pub supported_protocols: Vec<ProtocolType>,
    pub capabilities: CoreCapabilities,
    pub history: Vec<CoreHistoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreCompatibilityRow {
    pub protocol: ProtocolType,
    pub protocol_label: String,
    pub supported_cores: Vec<String>,
    pub required_aux: Option<String>,
    pub min_version: String,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreInventorySnapshot {
    pub checked_at: String,
    pub cores: Vec<InstalledCoreInfo>,
    pub compatibility_matrix: Vec<CoreCompatibilityRow>,
    pub sing_box_note: String,
    pub active_selection: CoreSelectionMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreUpdateCheckResult {
    pub core_kind: CoreKind,
    pub current_version: String,
    pub latest_version: Option<String>,
    pub update_available: bool,
    pub release_url: Option<String>,
    pub asset_name: Option<String>,
    pub expected_sha256: Option<String>,
    pub published_at: Option<String>,
    pub blocked_by_active_connection: bool,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsServerTestResult {
    pub server: String,
    pub protocol: String,
    pub reachable: bool,
    pub latency_ms: Option<u64>,
    pub resolved_ips: Vec<String>,
    pub error: Option<String>,
    pub via_vpn: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsConfigAnalysis {
    pub effective_mode: String,
    pub active_servers: Vec<String>,
    pub direct_servers: Vec<String>,
    pub direct_domains_count: usize,
    pub tun_dns_hijack_active: bool,
    pub system_proxy_dns_note: String,
    pub cache_enabled: bool,
    pub fallback_enabled: bool,
    pub ipv6_query_strategy: String,
    pub leak_risk_level: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsLiveLookupResult {
    pub domain: String,
    pub resolver_used: String,
    pub resolved_ips: Vec<String>,
    pub latency_ms: Option<u64>,
    pub bypassed_vpn_warning: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsInspectorReport {
    pub checked_at: String,
    pub config_analysis: DnsConfigAnalysis,
    pub live_lookup: Option<DnsLiveLookupResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunAdapterStatus {
    pub adapter_present: bool,
    pub adapter_name: String,
    pub interface_index: Option<u32>,
    pub status: String,
    pub mtu: Option<u32>,
    pub ipv4_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
    pub dns_servers: Vec<String>,
    pub wintun_version: Option<String>,
    pub wintun_present: bool,
    pub wintun_integrity_ok: bool,
    pub driver_status: String,
    pub is_elevated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VirtualAdapterConflict {
    pub adapter_name: String,
    pub interface_description: String,
    pub category: String,
    pub status: String,
    pub severity: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunManagerSnapshot {
    pub checked_at: String,
    pub settings: TunSettings,
    pub adapter: TunAdapterStatus,
    pub conflicts: Vec<VirtualAdapterConflict>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ConnectionStageFlags {
    pub core_process_running: bool,
    pub aux_process_running: Option<bool>,
    pub local_proxy_listening: bool,
    pub tun_adapter_up: bool,
    pub tunnel_established: bool,
    pub internet_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ThroughputSummary {
    pub current_rx_bps: u64,
    pub current_tx_bps: u64,
    pub avg_rx_bps: u64,
    pub avg_tx_bps: u64,
    pub peak_rx_bps: u64,
    pub peak_tx_bps: u64,
    pub total_rx_bytes: u64,
    pub total_tx_bytes: u64,
    pub sample_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionTimelineEvent {
    pub id: u64,
    pub timestamp: String,
    pub stage: String,
    pub level: String,
    pub message: String,
    pub latency_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionInspectorSnapshot {
    pub status: ConnectionStatus,
    pub stages: ConnectionStageFlags,
    pub mode: ConnectionMode,
    pub active_server_id: Option<String>,
    pub active_server_name: Option<String>,
    pub protocol: Option<String>,
    pub active_core_name: String,
    pub active_core_version: String,
    pub active_adapter_name: Option<String>,
    pub routing_profile: RoutingProfile,
    pub dns_mode: String,
    pub tcp_latency_ms: Option<u64>,
    pub http_rtt_ms: Option<u64>,
    pub uptime_secs: u64,
    pub reconnect_count: u32,
    pub kill_switch: KillSwitchSnapshot,
    pub throughput: ThroughputSummary,
    pub timeline: Vec<ConnectionTimelineEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigDiffEntry {
    pub path: String,
    pub layer: String,
    pub change_type: String,
    pub before: Option<String>,
    pub after: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileEditRevisionMeta {
    pub revision_id: String,
    pub timestamp: String,
    pub note: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigValidationResult {
    pub ok: bool,
    pub core_tested: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub stripped_fields: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigStudioView {
    pub profile_id: String,
    pub format: String,
    pub effective_core: String,
    pub effective_mtu: u16,
    pub mtu_source: String,
    pub effective_dns: String,
    pub dns_source: String,
    pub effective_mode: ConnectionMode,
    pub mode_source: String,
    pub layer1_imported: serde_json::Value,
    pub layer2_with_overrides: serde_json::Value,
    pub layer3_injected_summary: Vec<String>,
    pub layer4_final_sanitized: serde_json::Value,
    pub awg_config_preview: Option<String>,
    pub stripped_guardrails: Vec<ConfigDiffEntry>,
    pub diffs: Vec<ConfigDiffEntry>,
    pub validation_ok: Option<bool>,
    pub validation_error: Option<String>,
    pub revisions: Vec<ProfileEditRevisionMeta>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DoctorCheckSeverity {
    Pass,
    Warn,
    Fail,
    Info,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorCheckResult {
    pub id: String,
    pub category: String,
    pub title: String,
    pub severity: DoctorCheckSeverity,
    pub summary: String,
    pub detail: String,
    pub recommended_action: Option<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkDoctorReport {
    pub checked_at: String,
    pub overall_status: DoctorCheckSeverity,
    pub pass_count: usize,
    pub warn_count: usize,
    pub fail_count: usize,
    pub checks: Vec<DoctorCheckResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyNetworkDisclosure {
    pub id: String,
    pub title: String,
    pub enabled: bool,
    pub trigger: String,
    pub destination: String,
    pub data_sent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyInventory {
    pub config_dir: String,
    pub dpapi_encrypted_files: Vec<String>,
    pub plaintext_files: Vec<String>,
    pub history_entries_count: usize,
    pub saved_original_ip_present: bool,
    pub saved_vpn_ip_present: bool,
    pub logs_count: usize,
    pub sub_backups_count: usize,
    pub sync_history_count: usize,
    pub send_hwid: bool,
    pub hwid_masked: Option<String>,
    pub external_network_features: Vec<PrivacyNetworkDisclosure>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PrivacyPurgeScope {
    pub clear_history: bool,
    pub clear_original_ip: bool,
    pub clear_vpn_ip: bool,
    pub clear_logs: bool,
    pub clear_server_quality: bool,
    pub clear_sub_backups: bool,
    pub clear_sync_history: bool,
    pub clear_profile_edit_history: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PrivacyPurgeReport {
    pub items_removed: usize,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpeedTestResult {
    pub ok: bool,
    pub server_id: String,
    pub bytes_downloaded: u64,
    pub duration_ms: u64,
    pub mbps: f64,
    pub via_vpn: bool,
    pub note: String,
}
