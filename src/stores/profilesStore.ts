import { useSyncExternalStore } from 'react';
import type { AppSettings, BehaviorProfile, BehaviorProfileId } from '../types/vpn';
import { isRuBypassActive } from '../utils/format';

const STORAGE_KEY = 'aura-behavior-profiles-v1';

export interface BehaviorProfilesState {
  activeProfileId: BehaviorProfileId;
  profiles: Record<BehaviorProfileId, BehaviorProfile>;
}

const DEFAULT_PROFILES: Record<BehaviorProfileId, BehaviorProfile> = {
  daily: {
    id: 'daily',
    name: 'Повседневный',
    description: 'Системный прокси, российские сайты напрямую, гибридный DNS',
    connectionMode: 'system_proxy',
    routingProfile: 'ru_direct',
    bypassRuDomains: true,
    splitTunnelMode: 'all_vpn',
    dns: { mode: 'hybrid', primaryDns: '1.1.1.1', directDns: '77.88.8.8' },
    autoReconnect: true,
    reconnectOnWake: true,
    killSwitchEnabled: false,
    ipv6Enabled: false,
  },
  work: {
    id: 'work',
    name: 'Рабочий',
    description: 'TUN + весь трафик через VPN, VPN DNS и Kill Switch',
    connectionMode: 'tun',
    routingProfile: 'all_vpn',
    bypassRuDomains: false,
    splitTunnelMode: 'all_vpn',
    dns: { mode: 'vpn', primaryDns: '1.1.1.1', directDns: '77.88.8.8' },
    autoReconnect: true,
    reconnectOnWake: true,
    killSwitchEnabled: true,
    ipv6Enabled: false,
  },
  gaming: {
    id: 'gaming',
    name: 'Игровой',
    description: 'TUN с обходом выбранных игр и гибридным DNS',
    connectionMode: 'tun',
    routingProfile: 'bypass_apps',
    bypassRuDomains: false,
    splitTunnelMode: 'bypass_apps',
    dns: { mode: 'hybrid', primaryDns: '1.1.1.1', directDns: '77.88.8.8' },
    autoReconnect: true,
    reconnectOnWake: false,
    killSwitchEnabled: false,
    ipv6Enabled: false,
  },
  custom: {
    id: 'custom',
    name: 'Пользовательский',
    description: 'Сохранённая комбинация параметров и выбранного узла',
    connectionMode: 'system_proxy',
    routingProfile: 'ru_direct',
    bypassRuDomains: true,
    splitTunnelMode: 'all_vpn',
    dns: { mode: 'hybrid', primaryDns: '1.1.1.1', directDns: '77.88.8.8' },
    autoReconnect: true,
    reconnectOnWake: true,
    killSwitchEnabled: false,
    ipv6Enabled: false,
  },
};

function loadInitial(): BehaviorProfilesState {
  if (typeof window === 'undefined' || !window.localStorage) {
    return { activeProfileId: 'daily', profiles: { ...DEFAULT_PROFILES } };
  }
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return { activeProfileId: 'daily', profiles: { ...DEFAULT_PROFILES } };
    const parsed = JSON.parse(raw) as Partial<BehaviorProfilesState>;
    return {
      activeProfileId: parsed.activeProfileId ?? 'daily',
      profiles: {
        daily: { ...DEFAULT_PROFILES.daily, ...(parsed.profiles?.daily ?? {}) },
        work: { ...DEFAULT_PROFILES.work, ...(parsed.profiles?.work ?? {}) },
        gaming: { ...DEFAULT_PROFILES.gaming, ...(parsed.profiles?.gaming ?? {}) },
        custom: { ...DEFAULT_PROFILES.custom, ...(parsed.profiles?.custom ?? {}) },
      },
    };
  } catch {
    return { activeProfileId: 'daily', profiles: { ...DEFAULT_PROFILES } };
  }
}

export interface ProfileDiffSummary {
  requiresReconnect: boolean;
  securityDowngrades: string[];
  changesSummary: string[];
}

export function analyzeProfileDiff(
  current: AppSettings,
  target: BehaviorProfile,
  isConnected: boolean,
): ProfileDiffSummary {
  const securityDowngrades: string[] = [];
  const changesSummary: string[] = [];

  if (current.connectionMode !== target.connectionMode) {
    changesSummary.push(
      `Режим: ${target.connectionMode === 'tun' ? 'TUN (весь ПК)' : 'Системный прокси'}`,
    );
  }
  if (current.routing.profile !== target.routingProfile) {
    changesSummary.push(`Маршрутизация: ${target.routingProfile}`);
  }
  if (current.killSwitchEnabled && !target.killSwitchEnabled) {
    securityDowngrades.push('Отключается защита от утечек (Kill Switch)');
  } else if (!current.killSwitchEnabled && target.killSwitchEnabled) {
    changesSummary.push('Kill Switch будет включён');
  }

  if (!current.ipv6Enabled && target.ipv6Enabled) {
    securityDowngrades.push('Включается передача IPv6 в туннель');
  }

  const curRu = isRuBypassActive(current.routing);
  if (!curRu && target.bypassRuDomains) {
    securityDowngrades.push('Российские сервисы и домены .ru пойдут напрямую без VPN');
  }

  if (current.dns.mode === 'vpn' && target.dns.mode === 'direct') {
    securityDowngrades.push('DNS переключится на провайдера (вместо VPN DNS)');
  }

  const tunnelDiff =
    current.connectionMode !== target.connectionMode ||
    current.routing.profile !== target.routingProfile ||
    current.routing.bypassRuDomains !== target.bypassRuDomains ||
    current.routing.splitTunnelMode !== target.splitTunnelMode ||
    current.dns.mode !== target.dns.mode ||
    current.ipv6Enabled !== target.ipv6Enabled ||
    (target.serverId !== undefined &&
      target.serverId !== null &&
      target.serverId !== current.activeServerId);

  return {
    requiresReconnect: isConnected && tunnelDiff,
    securityDowngrades,
    changesSummary,
  };
}

export function applyBehaviorProfileToSettings(
  current: AppSettings,
  profile: BehaviorProfile,
): AppSettings {
  const prevKs = current.killSwitch ?? {
    mode: 'off',
    allowLan: true,
    blockIpv6Leaks: true,
    persistOnExit: false,
    reconnectAttempts: 3,
  };
  const nextMode = profile.killSwitchEnabled
    ? prevKs.mode === 'off'
      ? 'on_drop'
      : prevKs.mode
    : 'off';
  return {
    ...current,
    activeServerId:
      profile.serverId !== undefined && profile.serverId !== null
        ? profile.serverId
        : current.activeServerId,
    connectionMode: profile.connectionMode,
    autoReconnect: profile.autoReconnect,
    reconnectOnWake: profile.reconnectOnWake,
    killSwitchEnabled: profile.killSwitchEnabled,
    killSwitch: {
      ...prevKs,
      mode: nextMode,
    },
    ipv6Enabled: profile.ipv6Enabled,
    dns: { ...profile.dns },
    routing: {
      ...current.routing,
      profile: profile.routingProfile,
      bypassRuDomains: profile.bypassRuDomains,
      splitTunnelMode: profile.splitTunnelMode,
    },
  };
}

class ProfilesStore {
  private state: BehaviorProfilesState = loadInitial();
  private listeners = new Set<() => void>();

  subscribe = (l: () => void) => {
    this.listeners.add(l);
    return () => {
      this.listeners.delete(l);
    };
  };

  getSnapshot = () => this.state;

  private persist(next: BehaviorProfilesState) {
    this.state = next;
    if (typeof window !== 'undefined' && window.localStorage) {
      try {
        window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
      } catch {
        // Ignore quota errors
      }
    }
    for (const l of this.listeners) l();
  }

  setActiveProfileId(id: BehaviorProfileId) {
    this.persist({ ...this.state, activeProfileId: id });
  }

  saveSettingsToProfile(id: BehaviorProfileId, settings: AppSettings) {
    const base = this.state.profiles[id];
    const updated: BehaviorProfile = {
      ...base,
      serverId: id === 'custom' ? settings.activeServerId ?? null : base.serverId,
      connectionMode: settings.connectionMode,
      routingProfile: settings.routing.profile,
      bypassRuDomains: settings.routing.bypassRuDomains,
      splitTunnelMode: settings.routing.splitTunnelMode,
      dns: { ...settings.dns },
      autoReconnect: settings.autoReconnect,
      reconnectOnWake: settings.reconnectOnWake,
      killSwitchEnabled: settings.killSwitchEnabled,
      ipv6Enabled: settings.ipv6Enabled,
    };
    this.persist({
      activeProfileId: id,
      profiles: { ...this.state.profiles, [id]: updated },
    });
  }

  saveCustomFromSettings(settings: AppSettings) {
    this.saveSettingsToProfile('custom', settings);
  }

  resetAll() {
    this.persist({ activeProfileId: 'daily', profiles: { ...DEFAULT_PROFILES } });
  }
}

export const profilesStore = new ProfilesStore();

export function useBehaviorProfiles(): BehaviorProfilesState {
  return useSyncExternalStore(
    profilesStore.subscribe,
    profilesStore.getSnapshot,
    profilesStore.getSnapshot,
  );
}
