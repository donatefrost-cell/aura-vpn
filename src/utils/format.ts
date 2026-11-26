import type { RawXrayDetails, RoutingConfig, ServerProfile } from '../types/vpn';

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 Б';
  const units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
  let val = bytes;
  let idx = 0;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx += 1;
  }
  const decimals = idx === 0 ? 0 : val >= 100 ? 0 : val >= 10 ? 1 : 2;
  return `${val.toFixed(decimals)} ${units[idx]}`;
}

export function formatSpeed(bytesPerSec: number): string {
  if (!Number.isFinite(bytesPerSec) || bytesPerSec <= 0) return '0 КБ/с';
  if (bytesPerSec < 1024) return `${Math.round(bytesPerSec)} Б/с`;
  const kb = bytesPerSec / 1024;
  if (kb < 1024) return `${kb >= 100 ? kb.toFixed(0) : kb.toFixed(1)} КБ/с`;
  const mb = kb / 1024;
  return `${mb >= 100 ? mb.toFixed(0) : mb.toFixed(2)} МБ/с`;
}

export function formatDuration(connectedSinceSec?: number | null, nowMs: number = Date.now()): string {
  if (!connectedSinceSec) return '00:00:00';
  const diff = Math.max(0, Math.floor(nowMs / 1000 - connectedSinceSec));
  const h = Math.floor(diff / 3600);
  const m = Math.floor((diff % 3600) / 60);
  const s = diff % 60;
  return [h, m, s].map((n) => String(n).padStart(2, '0')).join(':');
}

function describeRawXray(d: RawXrayDetails): { badge: string; transport: string } {
  const ob = d.outboundJson ?? {};
  const rawProto = String(ob.protocol ?? '').toLowerCase();
  const stream = (ob.streamSettings as Record<string, unknown> | undefined) ?? {};
  const rawNet = String(
    stream.network ?? (rawProto === 'hysteria' ? 'hysteria' : 'tcp'),
  ).toLowerCase();
  const sec = String(
    stream.security ?? (rawProto === 'hysteria' || rawProto === 'hysteria2' ? 'tls' : 'none'),
  ).toLowerCase();

  let badge = d.label;
  if (!badge || badge === 'VLESS' || badge === 'HYSTERIA' || badge === 'XRAY') {
    if (rawProto === 'vless') {
      badge = sec === 'reality' ? 'VLESS Reality' : sec === 'tls' ? 'VLESS TLS' : 'VLESS';
    } else if (rawProto === 'vmess') {
      badge = sec === 'tls' ? 'VMess TLS' : 'VMess';
    } else if (rawProto === 'trojan') {
      badge = 'Trojan';
    } else if (rawProto === 'shadowsocks') {
      badge = 'Shadowsocks';
    } else if (rawProto === 'hysteria' || rawProto === 'hysteria2') {
      badge = 'Hysteria2';
    } else if (rawProto === 'wireguard') {
      badge = 'WireGuard';
    } else if (rawProto) {
      badge = rawProto.toUpperCase();
    } else {
      badge = 'Xray';
    }
  }

  if (d.transportSummary && d.transportSummary.trim()) {
    return { badge, transport: d.transportSummary };
  }

  const netLabel =
    rawNet === 'raw' || rawNet === 'tcp' || rawNet === ''
      ? 'TCP'
      : rawNet === 'ws'
        ? 'WS'
        : rawNet === 'grpc'
          ? 'gRPC'
          : rawNet === 'xhttp' || rawNet === 'splithttp'
            ? 'XHTTP'
            : rawNet === 'httpupgrade'
              ? 'HTTPUpgrade'
              : rawNet === 'hysteria'
                ? 'QUIC'
                : rawNet === 'kcp' || rawNet === 'mkcp'
                  ? 'mKCP'
                  : rawNet === 'http' || rawNet === 'h2'
                    ? 'H2'
                    : rawNet.toUpperCase();

  const settings = (ob.settings as Record<string, unknown> | undefined) ?? {};
  const vnext = Array.isArray(settings.vnext) ? settings.vnext : [];
  const firstUser =
    vnext[0] && Array.isArray((vnext[0] as Record<string, unknown>).users)
      ? ((vnext[0] as Record<string, unknown>).users as Array<Record<string, unknown>>)[0]
      : undefined;
  const flow = String(firstUser?.flow ?? '').toLowerCase();
  const hasVision = flow.includes('vision');
  const udpmasks = Array.isArray(stream.udpmasks) ? stream.udpmasks : [];
  const hasSalamander = udpmasks.some(
    (m) => String((m as Record<string, unknown>)?.type ?? '').toLowerCase() === 'salamander',
  );

  let transport: string;
  if (rawProto === 'wireguard') {
    transport = 'UDP • Noise';
  } else if (rawProto === 'hysteria' || rawProto === 'hysteria2') {
    transport = hasSalamander ? 'QUIC • Salamander' : 'QUIC • TLS';
  } else if (rawProto === 'shadowsocks') {
    const servers = Array.isArray(settings.servers) ? settings.servers : [];
    const method = (servers[0] as Record<string, unknown> | undefined)?.method;
    transport = method ? String(method) : 'AEAD';
  } else {
    const parts = [netLabel];
    if (sec === 'reality') {
      parts.push(hasVision ? 'Vision' : 'Reality');
    } else if (sec === 'tls') {
      if (hasVision) parts.push('Vision');
      else if (!badge.endsWith('TLS')) parts.push('TLS');
    }
    transport = parts.join(' • ');
  }

  return { badge, transport };
}

export function formatProtocolBadge(profile: ServerProfile): string {
  switch (profile.details.kind) {
    case 'vless': {
      const sec = profile.details.data.security;
      const net = profile.details.data.network;
      if (sec === 'reality') return 'VLESS Reality';
      if (sec === 'tls') return net !== 'tcp' && net !== 'raw' ? `VLESS ${net.toUpperCase()}` : 'VLESS TLS';
      return 'VLESS';
    }
    case 'vmess':
      return profile.details.data.security === 'tls' ? 'VMess TLS' : 'VMess';
    case 'trojan':
      return 'Trojan';
    case 'shadowsocks':
      return 'Shadowsocks';
    case 'hysteria2':
      return 'Hysteria2';
    case 'wireguard':
      return 'WireGuard';
    case 'amneziawg':
      return 'AmneziaWG';
    case 'rawxray':
      return describeRawXray(profile.details.data).badge;
  }
}

export function formatTransportInfo(profile: ServerProfile): string {
  switch (profile.details.kind) {
    case 'vless': {
      const d = profile.details.data;
      const parts = [d.network.toUpperCase()];
      if (d.security !== 'none') parts.push(d.security.toUpperCase());
      if (d.flow) parts.push('Vision');
      return parts.join(' • ');
    }
    case 'vmess': {
      const d = profile.details.data;
      return d.security === 'tls' ? `${d.network.toUpperCase()} • TLS` : d.network.toUpperCase();
    }
    case 'trojan': {
      const d = profile.details.data;
      return `${d.network.toUpperCase()} • ${d.security.toUpperCase()}`;
    }
    case 'shadowsocks':
      return profile.details.data.method;
    case 'hysteria2': {
      const d = profile.details.data;
      return d.obfs ? `QUIC • ${d.obfs}` : 'QUIC • TLS';
    }
    case 'wireguard':
      return 'UDP • Noise';
    case 'amneziawg': {
      const jc = profile.details.data.jc;
      return jc ? `AWG • Jc=${jc}` : 'AmneziaWG • UDP';
    }
    case 'rawxray':
      return describeRawXray(profile.details.data).transport;
  }
}

export function getProfileNodeCount(profile: ServerProfile): number {
  if (profile.details.kind !== 'rawxray') return 1;
  const d = profile.details.data;
  if (typeof d.nodeCount === 'number' && d.nodeCount > 0) return d.nodeCount;
  const extraProxies = (d.extraOutbounds ?? []).filter((ob) => {
    const p = String((ob as Record<string, unknown>)?.protocol ?? '').toLowerCase();
    return p !== '' && p !== 'freedom' && p !== 'blackhole' && p !== 'dns' && p !== 'loopback';
  });
  return 1 + extraProxies.length;
}

export function hasAutoBalancer(profile: ServerProfile): boolean {
  return profile.details.kind === 'rawxray' && (profile.details.data.balancers?.length ?? 0) > 0;
}

export function formatNodePoolLabel(count: number): string {
  const mod100 = count % 100;
  const mod10 = count % 10;
  if (mod100 >= 11 && mod100 <= 19) return `${count} узлов`;
  if (mod10 === 1) return `${count} узел`;
  if (mod10 >= 2 && mod10 <= 4) return `${count} узла`;
  return `${count} узлов`;
}

export const COUNTRY_NAMES: Record<string, string> = {
  EU: 'Европа',
  NL: 'Нидерланды',
  DE: 'Германия',
  FI: 'Финляндия',
  US: 'США',
  GB: 'Великобритания',
  SE: 'Швеция',
  PL: 'Польша',
  FR: 'Франция',
  TR: 'Турция',
  SG: 'Сингапур',
  JP: 'Япония',
  LV: 'Латвия',
  EE: 'Эстония',
  LT: 'Литва',
  AT: 'Австрия',
  CH: 'Швейцария',
  CA: 'Канада',
  KZ: 'Казахстан',
  RU: 'Россия',
  UA: 'Украина',
  IT: 'Италия',
  ES: 'Испания',
  CZ: 'Чехия',
  NO: 'Норвегия',
  HK: 'Гонконг',
  KR: 'Южная Корея',
  AE: 'ОАЭ',
  IN: 'Индия',
  BR: 'Бразилия',
  AU: 'Австралия',
  BE: 'Бельгия',
  DK: 'Дания',
  IE: 'Ирландия',
  PT: 'Португалия',
  GR: 'Греция',
  RO: 'Румыния',
  BG: 'Болгария',
  HU: 'Венгрия',
  SK: 'Словакия',
  MD: 'Молдова',
  AM: 'Армения',
  GE: 'Грузия',
  IL: 'Израиль',
  CY: 'Кипр',
  RS: 'Сербия',
  IS: 'Исландия',
  LU: 'Люксембург',
  TW: 'Тайвань',
  MX: 'Мексика',
  AR: 'Аргентина',
  BY: 'Беларусь',
  TH: 'Таиланд',
  VN: 'Вьетнам',
  ID: 'Индонезия',
};

export function formatServerDisplayName(name: string, _countryCode?: string | null): string {
  // Windows omits color country flags and renders regional indicators as raw "NL"/"DE" letters,
  // which duplicates our SVG CountryBadge. Strip leading regional indicator pairs cleanly.
  return name.replace(/^[\u{1F1E6}-\u{1F1FF}]{2}[\s•|-]*/u, '').trim() || name;
}

export function getCountryName(code?: string | null): string | null {
  if (!code) return null;
  return COUNTRY_NAMES[code.toUpperCase()] ?? code.toUpperCase();
}

export function shouldShowCountryInSubtitle(displayName: string, countryName: string | null): boolean {
  if (!countryName) return false;
  const lowTitle = displayName.toLowerCase();
  const lowCountry = countryName.toLowerCase();
  if (lowTitle.includes(lowCountry)) return false;
  if (lowCountry === 'оаэ' && (lowTitle.includes('эмират') || lowTitle.includes('дуба'))) {
    return false;
  }
  const stem = lowCountry.slice(0, Math.min(5, lowCountry.length));
  if (stem.length >= 4 && lowTitle.includes(stem)) return false;
  return true;
}

export function formatRelativeDate(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return 'недавно';
  return date.toLocaleString('ru-RU', {
    day: '2-digit',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function formatExpireDate(unixSeconds?: number | null): string | null {
  if (!unixSeconds || unixSeconds <= 0) return null;
  const date = new Date(unixSeconds * 1000);
  if (Number.isNaN(date.getTime())) return null;
  return date.toLocaleDateString('ru-RU', {
    day: '2-digit',
    month: 'long',
    year: 'numeric',
  });
}

export function getLatencyTone(ms?: number | null): 'good' | 'medium' | 'poor' | 'none' {
  if (ms === null || ms === undefined) return 'none';
  if (ms <= 90) return 'good';
  if (ms <= 190) return 'medium';
  return 'poor';
}

export function isRuBypassActive(routing: RoutingConfig): boolean {
  if (routing.profile === 'ru_direct') return true;
  if (routing.profile === 'all_vpn') return false;
  return Boolean(routing.bypassRuDomains);
}
