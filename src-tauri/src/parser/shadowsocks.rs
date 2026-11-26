use super::{clean_host, decode_base64_text, extract_country_code, percent_decode};
use crate::models::{ProtocolDetails, ProtocolType, ServerProfile, ShadowsocksDetails};
use chrono::Utc;
use url::Url;

pub fn parse_shadowsocks(
    uri: &str,
    subscription_id: Option<String>,
) -> Result<ServerProfile, String> {
    let trimmed = uri.trim();
    let without_scheme = trimmed
        .strip_prefix("ss://")
        .or_else(|| trimmed.strip_prefix("SS://"))
        .ok_or_else(|| "Ожидалась схема ss://".to_string())?;

    let (before_hash, fragment) = match without_scheme.split_once('#') {
        Some((a, b)) => (a, Some(percent_decode(b))),
        None => (without_scheme, None),
    };

    // Extract query parameters (?plugin=..., ?uot=...) before splitting userinfo@hostport
    let (main_part, query_part) = match before_hash.split_once('?') {
        Some((m, q)) => (m, Some(q)),
        None => (before_hash, None),
    };
    let (mut uot, mut plugin, mut plugin_opts) = (false, None, None);
    if let Some(qs) = query_part {
        for (k, v) in url::form_urlencoded::parse(qs.as_bytes()) {
            match k.to_ascii_lowercase().as_str() {
                "uot" => uot = v == "1" || v.eq_ignore_ascii_case("true"),
                "plugin" => {
                    let raw_p = v.trim();
                    if !raw_p.is_empty() {
                        if let Some((pname, popts)) = raw_p.split_once(';') {
                            plugin = Some(pname.trim().to_string());
                            if !popts.trim().is_empty() {
                                plugin_opts = Some(popts.trim().to_string());
                            }
                        } else {
                            plugin = Some(raw_p.to_string());
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let (method, password, host, port) =
        if let Some((userinfo, hostport)) = main_part.split_once('@') {
            let decoded_creds = if userinfo.contains(':') {
                percent_decode(userinfo)
            } else {
                decode_base64_text(userinfo)
                    .map_err(|_| "Не удалось декодировать учётные данные Shadowsocks".to_string())?
            };

            let (method, password) = decoded_creds
                .split_once(':')
                .ok_or_else(|| "Неверный формат method:password в Shadowsocks-ключе".to_string())?;

            let fake_url = Url::parse(&format!("http://{hostport}"))
                .map_err(|_| "Некорректный адрес/порт в Shadowsocks-ключе".to_string())?;
            let host = fake_url
                .host_str()
                .map(clean_host)
                .filter(|h| !h.is_empty())
                .ok_or_else(|| "В Shadowsocks-ключе не указан адрес".to_string())?;
            // Ensure explicit `:80` is not dropped by HTTP default port normalization
            let port = if hostport.trim_end().ends_with(":80") {
                Some(80u16)
            } else {
                fake_url.port()
            }
            .filter(|p| *p > 0)
            .ok_or_else(|| "В Shadowsocks-ключе не указан порт".to_string())?;

            (method.trim().to_string(), password.to_string(), host, port)
        } else {
            // Legacy SIP002 / full base64 ss://base64(method:password@host:port)
            let decoded = decode_base64_text(main_part)
                .map_err(|_| "Некорректная структура Shadowsocks-ключа".to_string())?;
            let (creds, hostport) = decoded
                .rsplit_once('@')
                .ok_or_else(|| "Отсутствует @ в Shadowsocks-ключе".to_string())?;
            let (method, password) = creds
                .split_once(':')
                .ok_or_else(|| "Неверный формат method:password в Shadowsocks-ключе".to_string())?;
            let fake_url = Url::parse(&format!("http://{hostport}"))
                .map_err(|_| "Некорректный адрес/порт в Shadowsocks-ключе".to_string())?;
            let host = fake_url
                .host_str()
                .map(clean_host)
                .filter(|h| !h.is_empty())
                .ok_or_else(|| "В Shadowsocks-ключе не указан адрес".to_string())?;
            let port = if hostport.trim_end().ends_with(":80") {
                Some(80u16)
            } else {
                fake_url.port()
            }
            .filter(|p| *p > 0)
            .ok_or_else(|| "В Shadowsocks-ключе не указан порт".to_string())?;

            (method.trim().to_string(), password.to_string(), host, port)
        };

    if method.is_empty() || password.is_empty() {
        return Err("В Shadowsocks-ключе отсутствуют метод шифрования или пароль".to_string());
    }

    let name = fragment
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("{host}:{port}"));
    let country_code = extract_country_code(&name);

    Ok(ServerProfile {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        protocol: ProtocolType::Shadowsocks,
        address: host,
        port,
        country_code,
        subscription_id,
        latency_ms: None,
        details: ProtocolDetails::Shadowsocks(ShadowsocksDetails {
            method,
            password,
            uot,
            plugin,
            plugin_opts,
        }),
        created_at: Utc::now().to_rfc3339(),
        favorite: false,
        last_used_at: None,
        fingerprint_key: None,
        custom_name: None,
        overrides: None,
        original_source: None,
        config_revision: 0,
    })
}
