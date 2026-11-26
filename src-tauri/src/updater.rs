use crate::models::{UpdateChannel, UpdateCheckResult};
use crate::net_fetch::{fetch_https_bytes_safe, same_origin, validate_http_url};
use chrono::Utc;
use serde::Deserialize;
use std::cmp::Ordering;
use std::time::Duration;

const MAX_UPDATER_BYTES: usize = 256 * 1024;

#[derive(Deserialize)]
struct GithubReleasePayload {
    tag_name: String,
    html_url: Option<String>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
}

#[derive(Debug, Eq, PartialEq)]
struct ParsedSemVer {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Option<String>,
}

fn parse_semver(raw: &str) -> Option<ParsedSemVer> {
    let trimmed = raw.trim().trim_start_matches(['v', 'V']);
    if trimmed.is_empty() {
        return None;
    }
    let no_build = trimmed.split('+').next()?;
    let (core, pre) = match no_build.split_once('-') {
        Some((c, p)) if !p.is_empty() => (c, Some(p.to_string())),
        Some((c, _)) => (c, None),
        None => (no_build, None),
    };

    let parts: Vec<&str> = core.split('.').collect();
    if parts.is_empty() || parts.len() > 3 {
        return None;
    }
    let major = parts[0].parse::<u64>().ok()?;
    let minor = parts.get(1).unwrap_or(&"0").parse::<u64>().ok()?;
    let patch = parts.get(2).unwrap_or(&"0").parse::<u64>().ok()?;
    Some(ParsedSemVer {
        major,
        minor,
        patch,
        pre,
    })
}

fn cmp_prerelease(a: Option<&str>, b: Option<&str>) -> Ordering {
    match (a, b) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater, // stable > prerelease
        (Some(_), None) => Ordering::Less,    // prerelease < stable
        (Some(pa), Some(pb)) => {
            let mut ia = pa.split('.');
            let mut ib = pb.split('.');
            loop {
                match (ia.next(), ib.next()) {
                    (None, None) => return Ordering::Equal,
                    (None, Some(_)) => return Ordering::Less,
                    (Some(_), None) => return Ordering::Greater,
                    (Some(sa), Some(sb)) => {
                        let ord = match (sa.parse::<u64>(), sb.parse::<u64>()) {
                            (Ok(na), Ok(nb)) => na.cmp(&nb),
                            (Ok(_), Err(_)) => Ordering::Less,
                            (Err(_), Ok(_)) => Ordering::Greater,
                            (Err(_), Err(_)) => sa.cmp(sb),
                        };
                        if ord != Ordering::Equal {
                            return ord;
                        }
                    }
                }
            }
        }
    }
}

pub fn compare_semver(current: &str, latest: &str) -> Ordering {
    compare_semver_strict(current, latest).unwrap_or(Ordering::Equal)
}

pub fn compare_semver_strict(current: &str, latest: &str) -> Option<Ordering> {
    let c = parse_semver(current)?;
    let l = parse_semver(latest)?;
    Some(
        (c.major, c.minor, c.patch)
            .cmp(&(l.major, l.minor, l.patch))
            .then_with(|| cmp_prerelease(c.pre.as_deref(), l.pre.as_deref())),
    )
}

fn sanitize_release_url(raw: Option<String>, feed_url: Option<&str>) -> Option<String> {
    let raw_url = raw?;
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return None;
    }
    let parsed = validate_http_url(trimmed, true, false).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();

    let is_github_release = (host == "github.com" || host == "www.github.com")
        && parsed
            .path()
            .to_ascii_lowercase()
            .starts_with("/donatefrost-cell/aura-vpn/releases");
    let matches_feed_origin = feed_url
        .and_then(|f| validate_http_url(f, true, false).ok())
        .is_some_and(|feed| same_origin(&parsed, &feed));

    if is_github_release || matches_feed_origin {
        Some(parsed.to_string())
    } else {
        None
    }
}

pub async fn check_for_updates(
    feed_url: Option<&str>,
    channel: UpdateChannel,
) -> UpdateCheckResult {
    let current_version = env!("CARGO_PKG_VERSION").to_string();
    let checked_at = Utc::now().to_rfc3339();

    let Some(raw_url) = feed_url.map(|s| s.trim()).filter(|s| !s.is_empty()) else {
        return UpdateCheckResult {
            current_version: current_version.clone(),
            latest_version: None,
            update_available: false,
            status: "local_build".to_string(),
            message: format!(
                "Источник обновлений не настроен — используется локальная сборка v{current_version}. Автоустановка без криптоподписи (Tauri Ed25519 + Authenticode) не выполняется."
            ),
            release_url: None,
            checked_at,
        };
    };

    let (_final_feed_url, bytes) = match fetch_https_bytes_safe(
        raw_url,
        &format!("AuraVPN/{}", env!("CARGO_PKG_VERSION")),
        MAX_UPDATER_BYTES,
        Duration::from_secs(10),
        "Ответ сервера обновлений превышает допустимый лимит 256 КБ",
        false,
    )
    .await
    {
        Ok(res) => res,
        Err(err) => {
            return UpdateCheckResult {
                current_version,
                latest_version: None,
                update_available: false,
                status: "error".to_string(),
                message: err,
                release_url: None,
                checked_at,
            };
        }
    };

    let payload: GithubReleasePayload = match serde_json::from_slice(&bytes) {
        Ok(p) => p,
        Err(_) => {
            return UpdateCheckResult {
                current_version,
                latest_version: None,
                update_available: false,
                status: "error".to_string(),
                message: "Ответ сервера обновлений не соответствует формату GitHub Release JSON"
                    .to_string(),
                release_url: None,
                checked_at,
            };
        }
    };

    if payload.draft || (payload.prerelease && channel == UpdateChannel::Stable) {
        return UpdateCheckResult {
            current_version: current_version.clone(),
            latest_version: None,
            update_available: false,
            status: "up_to_date".to_string(),
            message: format!(
                "Для канала «Стабильный» установлена актуальная версия v{current_version}"
            ),
            release_url: None,
            checked_at,
        };
    }

    let clean_latest = payload
        .tag_name
        .trim()
        .trim_start_matches(['v', 'V'])
        .to_string();
    let Some(cmp) = compare_semver_strict(&current_version, &clean_latest) else {
        return UpdateCheckResult {
            current_version,
            latest_version: None,
            update_available: false,
            status: "error".to_string(),
            message: "Сервер обновлений вернул некорректную SemVer-версию".to_string(),
            release_url: None,
            checked_at,
        };
    };

    let update_available = cmp == Ordering::Less;
    let safe_release_url = sanitize_release_url(payload.html_url, Some(raw_url));

    let (status, message) = if update_available {
        (
            "update_available".to_string(),
            format!(
                "Доступна новая версия v{clean_latest} (текущая v{current_version}). Загрузите подписанный релиз вручную по проверенной ссылке."
            ),
        )
    } else {
        (
            "up_to_date".to_string(),
            format!("Установлена актуальная версия v{current_version}"),
        )
    };

    UpdateCheckResult {
        current_version,
        latest_version: Some(clean_latest),
        update_available,
        status,
        message,
        release_url: safe_release_url,
        checked_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_semver_versions_accurately() {
        assert_eq!(compare_semver("0.2.0", "v0.3.0"), Ordering::Less);
        assert_eq!(compare_semver("0.2.0", "0.2.0"), Ordering::Equal);
        assert_eq!(compare_semver("0.2.0", "v0.1.9"), Ordering::Greater);
        assert_eq!(compare_semver("0.2.0", "1.0.0-beta.1"), Ordering::Less);
        assert_eq!(compare_semver("1.0.0-alpha.1", "1.0.0"), Ordering::Less);
        assert_eq!(compare_semver_strict("0.5.0", "not-a-version"), None);
    }

    #[test]
    fn rejects_non_https_and_untrusted_release_urls() {
        assert!(sanitize_release_url(Some("javascript:alert(1)".to_string()), None).is_none());
        assert!(sanitize_release_url(Some("http://example.com/rel".to_string()), None).is_none());
        assert!(
            sanitize_release_url(Some("https://evil.example/payload.exe".to_string()), None)
                .is_none()
        );
        assert!(sanitize_release_url(
            Some("https://github.com/evil/repo/releases/tag/v9.9.9".to_string()),
            None
        )
        .is_none());
        assert!(sanitize_release_url(
            Some(
                "https://github.com/donatefrost-cell/aura-vpn/releases/tag/v1.0.0-rc.1".to_string()
            ),
            None
        )
        .is_some());
        assert!(sanitize_release_url(
            Some("https://updates.example.com/aura/v0.6.0.exe".to_string()),
            Some("https://updates.example.com/latest.json")
        )
        .is_some());
    }

    #[tokio::test]
    async fn reports_local_build_when_no_feed_configured() {
        let res = check_for_updates(None, UpdateChannel::Stable).await;
        assert_eq!(res.status, "local_build");
        assert!(!res.update_available);
        assert_eq!(res.current_version, env!("CARGO_PKG_VERSION"));
    }
}
