export function splitSubscriptionUrls(raw: string): string[] {
  const lines = raw
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  if (lines.length < 2) return [];
  const allUrls = lines.every(
    (l) =>
      /^https?:\/\/\S+$/i.test(l) ||
      /^(happ|v2raytun|hiddify|streisand|v2box|sing-box|clash|sub):\/\//i.test(l),
  );
  return allUrls ? lines : [];
}

export function looksLikeImportableText(clip: string): boolean {
  const t = clip.trim();
  if (!t) return false;
  return (
    /(vless|vmess|trojan|ss|hysteria2|hy2|hysteria|vpn|wireguard|wg|happ|v2raytun|hiddify|streisand|v2box|sing-box|sub|https?):\/\//i.test(
      t,
    ) ||
    (t.includes('[Interface]') && t.includes('[Peer]')) ||
    (t.startsWith('{') && t.includes('outbounds')) ||
    t.includes('proxies:')
  );
}

export type InputKind =
  | 'empty'
  | 'multi_sub'
  | 'sub'
  | 'amnezia_vpn'
  | 'awg_ini'
  | 'json'
  | 'yaml'
  | 'keys'
  | 'unknown';

export function detectInputKind(raw: string): { kind: InputKind; label: string } {
  const t = raw.trim();
  if (!t) {
    return {
      kind: 'empty',
      label:
        'Поддерживаются VLESS, VMess, Trojan, Shadowsocks, Hysteria2, Amnezia (vpn://), AmneziaWG/WireGuard (.conf), JSON, YAML и подписки (в том числе несколько по одной в строке)',
    };
  }

  const multiSubs = splitSubscriptionUrls(t);
  if (multiSubs.length >= 2) {
    return {
      kind: 'multi_sub',
      label: `Обнаружено несколько ссылок подписок: ${multiSubs.length} — будут загружены по очереди`,
    };
  }

  if (/^vpn:\/\//i.test(t) || t.toLowerCase().includes('vpn://')) {
    return {
      kind: 'amnezia_vpn',
      label: 'Обнаружен контейнер Amnezia (vpn://) — поддерживаются AmneziaWG, Xray и Shadowsocks',
    };
  }

  if (t.includes('[Interface]') && t.includes('[Peer]')) {
    const hasAwg = /\b(Jc|Jmin|Jmax|S1|S2|H1|H2|H3|H4)\s*=/i.test(t);
    return {
      kind: 'awg_ini',
      label: hasAwg
        ? 'Обнаружен конфиг AmneziaWG (.conf) — будет запущен через wireproxy-awg'
        : 'Обнаружен конфиг WireGuard (.conf)',
    };
  }

  if ((t.startsWith('{') || t.startsWith('[')) && t.includes('outbounds')) {
    return {
      kind: 'json',
      label: 'Обнаружен JSON-конфиг Xray — устаревшие флаги совместимости будут очищены автоматически',
    };
  }

  if (t.includes('proxies:')) {
    return {
      kind: 'yaml',
      label: 'Обнаружен YAML-конфиг Clash / Mihomo',
    };
  }

  if (/(vless|vmess|trojan|ss|hysteria2|hy2|hysteria|wireguard|wg):\/\//i.test(t)) {
    const matches =
      t.match(/(vless|vmess|trojan|ss|hysteria2|hy2|hysteria|wireguard|wg):\/\//gi) ?? [];
    return {
      kind: 'keys',
      label:
        matches.length > 1
          ? `Обнаружено VPN-ключей: ${matches.length}`
          : 'Обнаружен VPN-ключ для прямого импорта',
    };
  }

  if (/(happ|v2raytun|hiddify|streisand|v2box|sing-box|clash|sub):\/\//i.test(t)) {
    return {
      kind: 'sub',
      label: 'Обнаружена ссылка из Telegram/панели — подписка будет распакована и загружена',
    };
  }

  if (/https?:\/\/\S+/i.test(t)) {
    return {
      kind: 'sub',
      label: 'Обнаружена ссылка подписки — будут загружены узлы и квота трафика (с поддержкой 302)',
    };
  }

  if (/^[A-Za-z0-9+/=_-]{24,}$/.test(t.replace(/\s+/g, ''))) {
    return {
      kind: 'keys',
      label: 'Похоже на Base64-список ключей — декодируется автоматически',
    };
  }

  return {
    kind: 'unknown',
    label: 'Вставьте ключ, текст сообщения из Telegram, JSON, .conf или ссылки подписок',
  };
}
