import { describe, expect, it } from 'vitest';
import {
  detectInputKind,
  looksLikeImportableText,
  splitSubscriptionUrls,
} from '../utils/importHelpers';

describe('importHelpers', () => {
  it('splits multi-line subscription URLs cleanly', () => {
    const urls = splitSubscriptionUrls('https://a.example/sub\nhttps://b.example/sub');
    expect(urls).toEqual(['https://a.example/sub', 'https://b.example/sub']);
    expect(splitSubscriptionUrls('https://only-one.example/sub')).toEqual([]);
  });

  it('recognizes importable clipboard strings across protocols and containers', () => {
    expect(looksLikeImportableText('vless://uuid@example.com:443#NL')).toBe(true);
    expect(looksLikeImportableText('vpn://AAAA')).toBe(true);
    expect(looksLikeImportableText('[Interface]\nPrivateKey=abc\n[Peer]\nEndpoint=1.2.3.4:51820')).toBe(true);
    expect(looksLikeImportableText('hello world')).toBe(false);
  });

  it('classifies AmneziaWG INI configs vs standard WireGuard and multi-subs', () => {
    expect(detectInputKind('').kind).toBe('empty');
    expect(detectInputKind('https://a.example/1\nhapp://sub.example/2').kind).toBe('multi_sub');
    expect(detectInputKind('vpn://xyz').kind).toBe('amnezia_vpn');
    expect(
      detectInputKind('[Interface]\nPrivateKey=a\nJc = 4\n[Peer]\nEndpoint=1.1.1.1:51820').kind,
    ).toBe('awg_ini');
    expect(detectInputKind('{"outbounds":[]}').kind).toBe('json');
    expect(detectInputKind('proxies:\n  - name: n1').kind).toBe('yaml');
    expect(detectInputKind('vless://1@a:443').kind).toBe('keys');
  });
});
