use crate::models::{
    ConnectionMode, RouteTestResult, RoutingConfig, RoutingProfile, RoutingRule,
    RuCategoriesConfig, RuCategoryMeta, RuleAction, RuleMatchType, RulepackStatus, SplitTunnelMode,
};
use crate::net_fetch::fetch_https_bytes_safe;
use crate::storage::{atomic_copy_file, atomic_write_bytes};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::Duration;
use url::Url;

const MAX_RULEPACK_BYTES: usize = 2 * 1024 * 1024;
const MAX_RULEPACK_DOMAINS: usize = 10_000;
const MAX_RULEPACK_CIDRS: usize = 2_000;
const ALLOWED_RU_TLDS: [&str; 7] = [
    "ru",
    "su",
    "xn--p1ai",
    "moscow",
    "xn--80adxhks",
    "tatar",
    "xn--p1acf",
];

fn parse_numeric_version_tuple(raw: &str) -> Vec<u64> {
    raw.trim()
        .trim_start_matches(['v', 'V'])
        .split(['.', '-', '_'])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse::<u64>().unwrap_or(0)
        })
        .collect()
}

pub fn is_rulepack_downgrade(candidate: &str, current: &str) -> bool {
    let a = parse_numeric_version_tuple(candidate);
    let b = parse_numeric_version_tuple(current);
    let max_len = a.len().max(b.len());
    for i in 0..max_len {
        let av = *a.get(i).unwrap_or(&0);
        let bv = *b.get(i).unwrap_or(&0);
        if av < bv {
            return true;
        }
        if av > bv {
            return false;
        }
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuCategoryId {
    Banks,
    Gov,
    Marketplaces,
    Search,
    Social,
    Mail,
    Telecom,
    Education,
    RuTlds,
    OtherRu,
}

impl RuCategoryId {
    pub fn key(&self) -> &'static str {
        match self {
            Self::Banks => "banks",
            Self::Gov => "gov",
            Self::Marketplaces => "marketplaces",
            Self::Search => "search",
            Self::Social => "social",
            Self::Mail => "mail",
            Self::Telecom => "telecom",
            Self::Education => "education",
            Self::RuTlds => "ru_tlds",
            Self::OtherRu => "other_ru",
        }
    }

    pub fn is_enabled(&self, cfg: &RuCategoriesConfig) -> bool {
        match self {
            Self::Banks => cfg.banks,
            Self::Gov => cfg.gov,
            Self::Marketplaces => cfg.marketplaces,
            Self::Search => cfg.search,
            Self::Social => cfg.social,
            Self::Mail => cfg.mail,
            Self::Telecom => cfg.telecom,
            Self::Education => cfg.education,
            Self::RuTlds => cfg.ru_tlds,
            Self::OtherRu => cfg.other_ru,
        }
    }

    pub fn meta(&self) -> (&'static str, &'static str, &'static [&'static str]) {
        match self {
            Self::Banks => (
                "Российские банки",
                "Онлайн-банкинг, переводы СБП и платёжные системы",
                &["Сбербанк", "Т-Банк", "Альфа-Банк", "ВТБ"],
            ),
            Self::Gov => (
                "Государственные сервисы",
                "Порталы госуслуг, налоговая и официальные ведомства",
                &["Госуслуги", "ФНС", "mos.ru", "ЦБ РФ"],
            ),
            Self::Marketplaces => (
                "Маркетплейсы",
                "Крупные торговые площадки и сервисы доставки",
                &["Ozon", "Wildberries", "Авито", "Мегамаркет"],
            ),
            Self::Search => (
                "Поисковые системы",
                "Российские поисковики, карты и навигация",
                &["Яндекс", "2ГИС", "Rambler"],
            ),
            Self::Social => (
                "Социальные сети и видео",
                "Соцсети, видеоплатформы и медиа-сообщества",
                &["VK", "Rutube", "Дзен", "Хабр"],
            ),
            Self::Mail => (
                "Почтовые сервисы",
                "Российские почтовые веб-клиенты и домены доставки",
                &["Mail.ru", "Яндекс Почта"],
            ),
            Self::Telecom => (
                "Операторы связи",
                "Личные кабинеты мобильных операторов и провайдеров",
                &["МТС", "МегаФон", "Билайн", "T2", "Ростелеком"],
            ),
            Self::Education => (
                "Образовательные платформы",
                "Школьные порталы, вузы и онлайн-курсы",
                &["Сферум", "Учи.ру", "Яндекс Практикум", "Stepik"],
            ),
            Self::RuTlds => (
                "Российские доменные зоны",
                "Национальные домены .ru, .su, .рф, .moscow, .tatar",
                &[".ru", ".рф", ".su", ".moscow"],
            ),
            Self::OtherRu => (
                "Другие российские сервисы",
                "Билеты, кинотеатры, погода, работа и деловые сервисы",
                &["РЖД", "Кинопоиск", "HH.ru", "Авиасейлс"],
            ),
        }
    }

    pub fn all() -> &'static [RuCategoryId] {
        &[
            Self::Banks,
            Self::Gov,
            Self::Marketplaces,
            Self::Search,
            Self::Social,
            Self::Mail,
            Self::Telecom,
            Self::Education,
            Self::RuTlds,
            Self::OtherRu,
        ]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RulepackData {
    pub version: String,
    pub updated_at: String,
    pub source: String,
    pub categories: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub ip_cidrs: Vec<String>,
}

const FORBIDDEN_GLOBAL_CDNS: &[&str] = &[
    "cloudflare.com",
    "cloudflare-dns.com",
    "amazonaws.com",
    "akamai.net",
    "akamaiedge.net",
    "fastly.net",
    "googleapis.com",
    "gstatic.com",
    "google.com",
];

pub fn default_rulepack() -> RulepackData {
    let mut categories: HashMap<String, Vec<String>> = HashMap::new();

    categories.insert(
        "banks".to_string(),
        [
            "sberbank.ru",
            "sber.ru",
            "sberbank.com",
            "sberid.ru",
            "spasibosberbank.ru",
            "tbank.ru",
            "tinkoff.ru",
            "tinkoff.com",
            "t-static.ru",
            "cdn-tinkoff.ru",
            "alfabank.ru",
            "alfa.me",
            "alfaclick.ru",
            "vtb.ru",
            "vtb24.ru",
            "gazprombank.ru",
            "raiffeisen.ru",
            "sovcombank.ru",
            "halvacard.ru",
            "psbank.ru",
            "rshb.ru",
            "pochtabank.ru",
            "nspk.ru",
            "mironline.ru",
            "yoomoney.ru",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    );

    categories.insert(
        "gov".to_string(),
        [
            "gosuslugi.ru",
            "gu-st.ru",
            "xn--80ajghhoc2aj1c8b.xn--p1ai",
            "nalog.gov.ru",
            "nalog.ru",
            "mos.ru",
            "sfr.gov.ru",
            "pfr.gov.ru",
            "pochta.ru",
            "gov.ru",
            "cbr.ru",
            "kremlin.ru",
            "rosreestr.gov.ru",
            "fssp.gov.ru",
            "sudrf.ru",
            "xn--90adear.xn--p1ai",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    );

    categories.insert(
        "marketplaces".to_string(),
        [
            "ozon.ru",
            "ozon.com",
            "ozone.ru",
            "ozonusercontent.com",
            "wildberries.ru",
            "wb.ru",
            "wbbasket.ru",
            "wbstatic.net",
            "avito.ru",
            "avito.st",
            "megamarket.ru",
            "lamoda.ru",
            "dns-shop.ru",
            "mvideo.ru",
            "eldorado.ru",
            "citilink.ru",
            "aliexpress.ru",
            "kuper.ru",
            "sbermarket.ru",
            "samokat.ru",
            "mm.ru",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    );

    categories.insert(
        "search".to_string(),
        [
            "yandex.ru",
            "yandex.com",
            "yandex.net",
            "ya.ru",
            "yastatic.net",
            "yandex.st",
            "2gis.ru",
            "2gis.com",
            "rambler.ru",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    );

    categories.insert(
        "social".to_string(),
        [
            "vk.com",
            "vk.ru",
            "vk.me",
            "vkvideo.ru",
            "vkplay.ru",
            "userapi.com",
            "vk-cdn.net",
            "vkuservideo.net",
            "vkuseraudio.net",
            "mycdn.me",
            "ok.ru",
            "odnoklassniki.ru",
            "dzen.ru",
            "rutube.ru",
            "rtbcdn.ru",
            "habr.com",
            "habrastorage.org",
            "pikabu.ru",
            "livejournal.com",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    );

    categories.insert(
        "mail".to_string(),
        [
            "mail.ru",
            "imgsmail.ru",
            "my.com",
            "mail.yandex.ru",
            "mail.yandex.com",
            "mail.rambler.ru",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    );

    categories.insert(
        "telecom".to_string(),
        [
            "mts.ru",
            "mtsbank.ru",
            "kion.ru",
            "megafon.ru",
            "beeline.ru",
            "t2.ru",
            "tele2.ru",
            "rt.ru",
            "rostelecom.ru",
            "wink.ru",
            "yota.ru",
            "dom.ru",
            "mgts.ru",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    );

    categories.insert(
        "education".to_string(),
        [
            "uchi.ru",
            "yaklass.ru",
            "sferum.ru",
            "foxford.ru",
            "stepik.org",
            "skillbox.ru",
            "netology.ru",
            "practicum.yandex.ru",
            "dnevnik.ru",
            "mes.mos.ru",
            "resh.edu.ru",
            "openedu.ru",
            "litres.ru",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    );

    categories.insert(
        "ru_tlds".to_string(),
        [
            "ru",
            "su",
            "xn--p1ai",
            "moscow",
            "xn--80adxhks",
            "tatar",
            "xn--p1acf",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    );

    categories.insert(
        "other_ru".to_string(),
        [
            "rzd.ru",
            "aeroflot.ru",
            "s7.ru",
            "pobeda.aero",
            "tutu.ru",
            "aviasales.ru",
            "ostrovok.ru",
            "kinopoisk.ru",
            "ivi.ru",
            "ivi.tv",
            "okko.tv",
            "start.ru",
            "premier.one",
            "hh.ru",
            "superjob.ru",
            "cian.ru",
            "domclick.ru",
            "auto.ru",
            "drom.ru",
            "gismeteo.ru",
            "rbc.ru",
            "tass.ru",
            "sports.ru",
            "1c.ru",
            "kontur.ru",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    );

    RulepackData {
        version: "2026.11.1".to_string(),
        updated_at: "2026-11-24T00:00:00Z".to_string(),
        source: "Встроенная база AURA".to_string(),
        categories,
        ip_cidrs: vec![],
    }
}

fn rulepacks_dir(base_dir: &Path) -> PathBuf {
    base_dir.join("rulepacks")
}

fn rulepack_file(base_dir: &Path) -> PathBuf {
    rulepacks_dir(base_dir).join("ru-rules-pack.json")
}

fn rulepack_backup_file(base_dir: &Path) -> PathBuf {
    rulepacks_dir(base_dir).join("ru-rules-pack.json.bak")
}

pub fn is_valid_domain_token(raw: &str) -> bool {
    is_valid_domain_token_for_cat("", raw)
}

fn is_valid_domain_token_for_cat(category_id: &str, raw: &str) -> bool {
    let t = raw.trim().to_ascii_lowercase();
    if t.is_empty() || t.len() > 253 || t.starts_with('.') || t.ends_with('.') {
        return false;
    }
    if category_id == "ru_tlds" {
        return ALLOWED_RU_TLDS.contains(&t.as_str());
    }
    if !t.contains('.') {
        return false;
    }
    for label in t.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || label
                .chars()
                .any(|c| !(c.is_ascii_alphanumeric() || c == '-'))
        {
            return false;
        }
    }
    !FORBIDDEN_GLOBAL_CDNS
        .iter()
        .any(|cdn| t == *cdn || t.ends_with(&format!(".{cdn}")))
}

pub fn validate_rulepack_data(pack: &RulepackData) -> Result<(), String> {
    if pack.version.trim().is_empty() || pack.version.len() > 64 {
        return Err("В базе правил не указана корректная версия".to_string());
    }
    let total_entries: usize = pack.categories.values().map(|v| v.len()).sum();
    if total_entries == 0 {
        return Err("База правил пуста".to_string());
    }
    if total_entries > MAX_RULEPACK_DOMAINS {
        return Err(format!(
            "База правил превышает допустимый лимит {MAX_RULEPACK_DOMAINS} доменов"
        ));
    }
    let valid_keys: HashSet<&str> = RuCategoryId::all().iter().map(|c| c.key()).collect();
    for (cat, list) in &pack.categories {
        if cat.trim().is_empty() || !valid_keys.contains(cat.as_str()) {
            return Err(format!(
                "Неизвестный или пустой идентификатор категории: {cat}"
            ));
        }
        for dom in list {
            if !is_valid_domain_token_for_cat(cat, dom) {
                return Err(format!("Недопустимый домен в базе правил ({cat}): {dom}"));
            }
        }
    }
    if pack.ip_cidrs.len() > MAX_RULEPACK_CIDRS {
        return Err(format!(
            "База правил превышает допустимый лимит {MAX_RULEPACK_CIDRS} IP-подсетей"
        ));
    }
    for cidr in &pack.ip_cidrs {
        if !is_valid_ip_or_cidr(cidr) {
            return Err(format!("Недопустимая IP-подсеть в базе правил: {cidr}"));
        }
    }
    Ok(())
}

pub fn load_rulepack(base_dir: &Path) -> RulepackData {
    let main_path = rulepack_file(base_dir);
    if let Ok(raw) = fs::read_to_string(&main_path) {
        if let Ok(parsed) = serde_json::from_str::<RulepackData>(&raw) {
            if validate_rulepack_data(&parsed).is_ok() {
                return parsed;
            }
        }
    }

    let bak_path = rulepack_backup_file(base_dir);
    if let Ok(raw) = fs::read_to_string(&bak_path) {
        if let Ok(parsed) = serde_json::from_str::<RulepackData>(&raw) {
            if validate_rulepack_data(&parsed).is_ok() {
                let _ = atomic_copy_file(&bak_path, &main_path);
                return parsed;
            }
        }
    }

    default_rulepack()
}

pub fn save_rulepack_atomic_with_backup(
    base_dir: &Path,
    pack: &RulepackData,
) -> Result<(), String> {
    validate_rulepack_data(pack)?;
    let dir = rulepacks_dir(base_dir);
    fs::create_dir_all(&dir).map_err(|e| format!("Не удалось создать папку баз правил: {e}"))?;

    let main_path = rulepack_file(base_dir);
    let bak_path = rulepack_backup_file(base_dir);
    if main_path.exists() {
        atomic_copy_file(&main_path, &bak_path)?;
    }

    let json = serde_json::to_vec_pretty(pack)
        .map_err(|e| format!("Ошибка сериализации базы правил: {e}"))?;
    atomic_write_bytes(&main_path, &json)
}

pub fn rollback_rulepack(base_dir: &Path) -> Result<RulepackData, String> {
    let bak_path = rulepack_backup_file(base_dir);
    if !bak_path.exists() {
        let main_path = rulepack_file(base_dir);
        if main_path.exists() {
            let _ = fs::remove_file(&main_path);
        }
        return Ok(default_rulepack());
    }

    let raw = fs::read_to_string(&bak_path)
        .map_err(|e| format!("Не удалось прочитать резервную базу правил: {e}"))?;
    let parsed: RulepackData = serde_json::from_str(&raw)
        .map_err(|e| format!("Резервная копия базы правил повреждена: {e}"))?;
    validate_rulepack_data(&parsed)?;
    atomic_copy_file(&bak_path, &rulepack_file(base_dir))
        .map_err(|e| format!("Не удалось восстановить базу правил: {e}"))?;
    Ok(parsed)
}

pub async fn update_rulepack_from_url(
    base_dir: &Path,
    raw_url: &str,
) -> Result<RulepackData, String> {
    let (_final_url, bytes) = fetch_https_bytes_safe(
        raw_url,
        &format!("AuraVPN/{}", env!("CARGO_PKG_VERSION")),
        MAX_RULEPACK_BYTES,
        Duration::from_secs(15),
        "Размер базы правил превышает допустимый лимит 2 МБ",
        false,
    )
    .await?;

    let mut pack: RulepackData = serde_json::from_slice(&bytes)
        .map_err(|_| "Загруженный файл не соответствует формату Rulepack JSON".to_string())?;
    validate_rulepack_data(&pack)?;

    // Anti-downgrade guard: reject updates older than current active version (numeric tuple comparison)
    let current = load_rulepack(base_dir);
    if is_rulepack_downgrade(&pack.version, &current.version) {
        return Err(format!(
            "Отклонено понижение версии базы правил ({} < текущая {})",
            pack.version.trim(),
            current.version.trim()
        ));
    }

    if pack.updated_at.trim().is_empty() {
        pack.updated_at = Utc::now().to_rfc3339();
    }
    if pack.source.trim().is_empty() {
        pack.source = "Внешнее обновление (HTTPS)".to_string();
    }
    save_rulepack_atomic_with_backup(base_dir, &pack)?;
    Ok(pack)
}

pub fn build_rulepack_status(base_dir: &Path, xray_dir: Option<&Path>) -> RulepackStatus {
    let pack = load_rulepack(base_dir);
    let mut seen: HashSet<String> = HashSet::new();
    let mut cats = Vec::with_capacity(RuCategoryId::all().len());

    for cat in RuCategoryId::all() {
        let (title, description, examples) = cat.meta();
        let list = pack.categories.get(cat.key());
        let count = list.map(|v| v.len()).unwrap_or(0);
        if let Some(items) = list {
            for item in items {
                seen.insert(item.to_ascii_lowercase());
            }
        }
        cats.push(RuCategoryMeta {
            id: cat.key().to_string(),
            title: title.to_string(),
            description: description.to_string(),
            examples: examples.iter().map(|s| (*s).to_string()).collect(),
            domain_count: count,
        });
    }

    let (geosite_present, geoip_present) = match xray_dir {
        Some(dir) => (
            dir.join("geosite.dat").exists(),
            dir.join("geoip.dat").exists(),
        ),
        None => (false, false),
    };

    RulepackStatus {
        version: pack.version,
        updated_at: pack.updated_at,
        source: pack.source,
        total_domains: seen.len(),
        has_backup: rulepack_backup_file(base_dir).exists(),
        geosite_present,
        geoip_present,
        categories: cats,
    }
}

pub fn is_ru_bypass_active(routing: &RoutingConfig) -> bool {
    match routing.profile {
        RoutingProfile::AllVpn => false,
        RoutingProfile::RuDirect => true,
        RoutingProfile::BypassApps | RoutingProfile::OnlyApps | RoutingProfile::Custom => {
            routing.bypass_ru_domains
        }
    }
}

pub fn effective_split_mode(routing: &RoutingConfig) -> SplitTunnelMode {
    match routing.profile {
        RoutingProfile::BypassApps => SplitTunnelMode::BypassApps,
        RoutingProfile::OnlyApps => SplitTunnelMode::OnlyApps,
        RoutingProfile::AllVpn | RoutingProfile::RuDirect => SplitTunnelMode::AllVpn,
        RoutingProfile::Custom => routing.split_tunnel_mode,
    }
}

pub fn collect_active_ru_domains(routing: &RoutingConfig, pack: &RulepackData) -> Vec<String> {
    if !is_ru_bypass_active(routing) {
        return Vec::new();
    }

    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();

    for cat in RuCategoryId::all() {
        if !cat.is_enabled(&routing.ru_categories) {
            continue;
        }
        if let Some(list) = pack.categories.get(cat.key()) {
            for dom in list {
                let clean = dom.trim().to_ascii_lowercase();
                if clean.is_empty() || !is_valid_domain_token_for_cat(cat.key(), &clean) {
                    continue;
                }
                if seen.insert(clean.clone()) {
                    out.push(format!("domain:{clean}"));
                }
            }
        }
    }

    out
}

pub fn is_valid_ip_or_cidr(raw: &str) -> bool {
    let trimmed = raw.trim();
    if let Some((ip_part, prefix_part)) = trimmed.split_once('/') {
        let Ok(ip) = ip_part.parse::<IpAddr>() else {
            return false;
        };
        let Ok(prefix) = prefix_part.parse::<u8>() else {
            return false;
        };
        match ip {
            IpAddr::V4(_) => prefix <= 32,
            IpAddr::V6(_) => prefix <= 128,
        }
    } else {
        trimmed.parse::<IpAddr>().is_ok()
    }
}

pub fn validate_routing_rule(rule: &RoutingRule) -> Result<(), String> {
    let pattern = rule.pattern.trim();
    if pattern.is_empty() || pattern.len() > 240 {
        return Err(
            "Шаблон правила маршрутизации должен содержать от 1 до 240 символов".to_string(),
        );
    }
    if pattern.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(format!(
            "Шаблон «{pattern}» содержит недопустимые пробелы или символы"
        ));
    }
    match rule.match_type {
        RuleMatchType::Ip => {
            if !is_valid_ip_or_cidr(pattern) {
                return Err(format!(
                    "Некорректный IP или CIDR «{pattern}» (пример: 192.0.2.0/24)"
                ));
            }
        }
        RuleMatchType::Domain => {
            let low = pattern.to_ascii_lowercase();
            if pattern.contains('\\') || pattern.contains('/') {
                return Err(format!(
                    "Шаблон домена «{pattern}» не должен содержать пути файлов"
                ));
            }
            if low.starts_with("ext:") || low.starts_with("geosite:") || low.starts_with("geoip:") {
                return Err(format!(
                    "Внешние файлы ext:/geosite:/geoip: в пользовательских правилах запрещены («{pattern}»)"
                ));
            }
            if let Some((prefix, expr)) = pattern.split_once(':') {
                let p = prefix.to_ascii_lowercase();
                if !matches!(p.as_str(), "domain" | "full" | "keyword" | "regexp")
                    || expr.is_empty()
                {
                    return Err(format!(
                        "Недопустимый префикс правила «{pattern}». Доступны: domain:, full:, keyword:, regexp:"
                    ));
                }
                if p == "regexp" && regex::Regex::new(expr).is_err() {
                    return Err(format!("Некорректное регулярное выражение в «{pattern}»"));
                }
            }
        }
        RuleMatchType::Process => {
            if pattern.len() > 128
                || pattern.contains("..")
                || pattern.contains('/')
                || pattern.contains('\\')
                || pattern.contains(':')
            {
                return Err(format!(
                    "Укажите только имя процесса без пути (например, chrome.exe), а не «{pattern}»"
                ));
            }
        }
    }
    Ok(())
}

fn ip_matches_cidr(ip: IpAddr, rule_pattern: &str) -> bool {
    let trimmed = rule_pattern.trim();
    if let Some((net_str, prefix_str)) = trimmed.split_once('/') {
        let Ok(net_ip) = net_str.parse::<IpAddr>() else {
            return false;
        };
        let Ok(prefix) = prefix_str.parse::<u32>() else {
            return false;
        };
        match (ip, net_ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) if prefix <= 32 => {
                let mask = if prefix == 0 {
                    0u32
                } else {
                    u32::MAX << (32 - prefix)
                };
                (u32::from(a) & mask) == (u32::from(b) & mask)
            }
            (IpAddr::V6(a), IpAddr::V6(b)) if prefix <= 128 => {
                let mask = if prefix == 0 {
                    0u128
                } else {
                    u128::MAX << (128 - prefix)
                };
                (u128::from(a) & mask) == (u128::from(b) & mask)
            }
            _ => false,
        }
    } else {
        trimmed.parse::<IpAddr>().map(|r| r == ip).unwrap_or(false)
    }
}

fn is_lan_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn domain_matches_pattern(host: &str, raw_pattern: &str) -> bool {
    let pat = raw_pattern.trim().to_ascii_lowercase();
    if let Some(full) = pat.strip_prefix("full:") {
        host == full
    } else if let Some(dom) = pat.strip_prefix("domain:") {
        host == dom || host.ends_with(&format!(".{dom}"))
    } else if let Some(kw) = pat.strip_prefix("keyword:") {
        host.contains(kw)
    } else if let Some(rx) = pat.strip_prefix("regexp:") {
        regex::Regex::new(rx)
            .map(|r| r.is_match(host))
            .unwrap_or(false)
    } else {
        host == pat || host.ends_with(&format!(".{pat}"))
    }
}

fn normalize_target_host(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.parse::<Ipv4Addr>().is_ok() || trimmed.parse::<Ipv6Addr>().is_ok() {
        return trimmed.to_string();
    }
    let candidate = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    if let Ok(url) = Url::parse(&candidate) {
        if let Some(host) = url.host_str() {
            return host.trim_matches(['[', ']']).to_ascii_lowercase();
        }
    }
    trimmed
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split(['/', '?', '#', ':'])
        .next()
        .unwrap_or(trimmed)
        .to_ascii_lowercase()
}

fn action_to_str(action: RuleAction) -> &'static str {
    match action {
        RuleAction::Proxy => "proxy",
        RuleAction::Direct => "direct",
        RuleAction::Block => "block",
    }
}

pub fn evaluate_route(
    query: &str,
    process: Option<&str>,
    routing: &RoutingConfig,
    mode: ConnectionMode,
    pack: &RulepackData,
) -> RouteTestResult {
    let host = normalize_target_host(query);
    let ip_opt = host.parse::<IpAddr>().ok();
    let clean_proc = process
        .map(|p| p.trim().to_ascii_lowercase())
        .filter(|p| !p.is_empty());

    // Priority 1: LAN / Loopback bypass
    if routing.bypass_lan && (host == "localhost" || ip_opt.is_some_and(is_lan_ip)) {
        return RouteTestResult {
            query: query.trim().to_string(),
            normalized_host: host,
            action: "direct".to_string(),
            priority_label: "Приоритет 1 • Локальная сеть (LAN)".to_string(),
            matched_rule: "bypass_lan".to_string(),
            matched_category: None,
            explanation:
                "Локальные и приватные адреса всегда направляются напрямую без выхода в VPN."
                    .to_string(),
            requires_tun_note: false,
            is_config_analysis: true,
        };
    }

    // Priority 2: User custom rules (strictly ordered)
    for (idx, rule) in routing.custom_rules.iter().enumerate() {
        if !rule.enabled {
            continue;
        }
        let pat = rule.pattern.trim();
        let matched = match rule.match_type {
            RuleMatchType::Domain => ip_opt.is_none() && domain_matches_pattern(&host, pat),
            RuleMatchType::Ip => ip_opt.is_some_and(|ip| ip_matches_cidr(ip, pat)),
            RuleMatchType::Process => clean_proc
                .as_ref()
                .is_some_and(|p| p.contains(&pat.to_ascii_lowercase())),
        };
        if matched {
            let needs_tun =
                rule.match_type == RuleMatchType::Process && mode == ConnectionMode::SystemProxy;
            let action_str = action_to_str(rule.action).to_string();
            let direct_warn = if rule.action == RuleAction::Direct {
                " Трафик идёт напрямую вне VPN-туннеля."
            } else {
                ""
            };
            let tun_warn = if needs_tun {
                " Примечание: фильтрация по процессам реально действует только в TUN-режиме."
            } else {
                ""
            };
            return RouteTestResult {
                query: query.trim().to_string(),
                normalized_host: host,
                action: action_str,
                priority_label: format!("Приоритет 2 • Пользовательское правило #{}", idx + 1),
                matched_rule: pat.to_string(),
                matched_category: None,
                explanation: format!(
                    "Сработало пользовательское правило ({:?}: {pat}).{direct_warn}{tun_warn}",
                    rule.match_type
                ),
                requires_tun_note: needs_tun,
                is_config_analysis: true,
            };
        }
    }

    // Priority 3: App split tunneling
    let split_mode = effective_split_mode(routing);
    if split_mode != SplitTunnelMode::AllVpn && !routing.split_apps.is_empty() {
        if let Some(ref proc_name) = clean_proc {
            let proc_matched = routing.split_apps.iter().any(|app| {
                !app.trim().is_empty() && proc_name.contains(&app.trim().to_ascii_lowercase())
            });
            let needs_tun = mode == ConnectionMode::SystemProxy;
            let tun_note = if needs_tun {
                " Внимание: в режиме «Системный прокси» исключения приложений не перехватываются по имени процесса — включите TUN."
            } else {
                ""
            };

            if proc_matched && split_mode == SplitTunnelMode::BypassApps {
                return RouteTestResult {
                    query: query.trim().to_string(),
                    normalized_host: host,
                    action: "direct".to_string(),
                    priority_label: "Приоритет 3 • Исключение приложения (Split Tunneling)"
                        .to_string(),
                    matched_rule: proc_name.clone(),
                    matched_category: None,
                    explanation: format!(
                        "Приложение «{proc_name}» добавлено в исключения (напрямую).{tun_note}"
                    ),
                    requires_tun_note: needs_tun,
                    is_config_analysis: true,
                };
            }
            if split_mode == SplitTunnelMode::OnlyApps {
                return RouteTestResult {
                    query: query.trim().to_string(),
                    normalized_host: host,
                    action: if proc_matched { "proxy" } else { "direct" }.to_string(),
                    priority_label: "Приоритет 3 • Профиль «Только выбранные приложения»"
                        .to_string(),
                    matched_rule: if proc_matched {
                        proc_name.clone()
                    } else {
                        "Остальные процессы -> direct".to_string()
                    },
                    matched_category: None,
                    explanation: if proc_matched {
                        format!(
                            "Приложение «{proc_name}» разрешено для работы через VPN.{tun_note}"
                        )
                    } else {
                        format!("Приложение «{proc_name}» не входит в белый список и направляется напрямую.{tun_note}")
                    },
                    requires_tun_note: needs_tun,
                    is_config_analysis: true,
                };
            }
        }
    }

    // Priority 4: Enabled Russian Services categories
    if ip_opt.is_none() && is_ru_bypass_active(routing) {
        for cat in RuCategoryId::all() {
            if !cat.is_enabled(&routing.ru_categories) {
                continue;
            }
            if let Some(domains) = pack.categories.get(cat.key()) {
                if let Some(matched_dom) = domains
                    .iter()
                    .find(|d| host == d.as_str() || host.ends_with(&format!(".{d}")))
                {
                    let (cat_title, _, _) = cat.meta();
                    return RouteTestResult {
                        query: query.trim().to_string(),
                        normalized_host: host,
                        action: "direct".to_string(),
                        priority_label: "Приоритет 4 • Российские сервисы напрямую".to_string(),
                        matched_rule: format!("domain:{matched_dom}"),
                        matched_category: Some(cat_title.to_string()),
                        explanation: format!(
                            "Домен совпал с категорией «{cat_title}» (правило domain:{matched_dom}). Трафик идёт напрямую через обычное интернет-соединение вне VPN."
                        ),
                        requires_tun_note: false,
                        is_config_analysis: true,
                    };
                }
            }
        }
    }

    // Priority 5: Default route
    let default_direct = split_mode == SplitTunnelMode::OnlyApps && !routing.split_apps.is_empty();
    RouteTestResult {
        query: query.trim().to_string(),
        normalized_host: host,
        action: if default_direct { "direct" } else { "proxy" }.to_string(),
        priority_label: "Приоритет 5 • Маршрут по умолчанию".to_string(),
        matched_rule: if default_direct {
            "only_apps_default_direct".to_string()
        } else {
            "default_proxy".to_string()
        },
        matched_category: None,
        explanation: if default_direct {
            "Активен профиль «Только выбранные приложения через VPN» — без указания выбранного приложения трафик идёт напрямую."
                .to_string()
        } else {
            "Специальных исключений не найдено — весь трафик шифруется и направляется через выбранный VPN-сервер."
                .to_string()
        },
        requires_tun_note: false,
        is_config_analysis: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_rulepack_covers_all_10_categories_without_global_cdns() {
        let pack = default_rulepack();
        assert!(validate_rulepack_data(&pack).is_ok());
        for cat in RuCategoryId::all() {
            let list = pack
                .categories
                .get(cat.key())
                .unwrap_or_else(|| panic!("Missing category {}", cat.key()));
            assert!(!list.is_empty(), "Category {} is empty", cat.key());
        }
        for cdn in FORBIDDEN_GLOBAL_CDNS {
            for list in pack.categories.values() {
                assert!(!list.iter().any(|d| d == cdn), "Unexpected CDN {cdn}");
            }
        }
    }

    #[test]
    fn evaluate_route_respects_priority_and_custom_overrides() {
        let pack = default_rulepack();
        let mut routing = RoutingConfig {
            profile: RoutingProfile::RuDirect,
            bypass_ru_domains: true,
            ..Default::default()
        };

        let sber = evaluate_route(
            "https://online.sberbank.ru/auth",
            None,
            &routing,
            ConnectionMode::SystemProxy,
            &pack,
        );
        assert_eq!(sber.action, "direct");
        assert_eq!(sber.matched_category.as_deref(), Some("Российские банки"));

        let gov_rf = evaluate_route(
            "госуслуги.рф",
            None,
            &routing,
            ConnectionMode::SystemProxy,
            &pack,
        );
        assert_eq!(gov_rf.action, "direct");

        // International site goes through VPN
        let intl = evaluate_route(
            "github.com",
            None,
            &routing,
            ConnectionMode::SystemProxy,
            &pack,
        );
        assert_eq!(intl.action, "proxy");

        // User custom rule overrides RU Direct (Priority 2 beats Priority 4)
        routing.custom_rules.push(RoutingRule {
            id: "override-1".to_string(),
            enabled: true,
            match_type: RuleMatchType::Domain,
            pattern: "domain:sberbank.ru".to_string(),
            action: RuleAction::Proxy,
            note: None,
        });
        let sber_overridden = evaluate_route(
            "online.sberbank.ru",
            None,
            &routing,
            ConnectionMode::SystemProxy,
            &pack,
        );
        assert_eq!(sber_overridden.action, "proxy");
    }

    #[test]
    fn rulepack_atomic_save_and_corrupt_rollback() {
        let temp_dir = std::env::temp_dir().join(format!("aura_rp_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();

        let mut p1 = default_rulepack();
        p1.version = "2026.11.1".to_string();
        save_rulepack_atomic_with_backup(&temp_dir, &p1).unwrap();

        let mut p2 = p1.clone();
        p2.version = "2026.11.2".to_string();
        save_rulepack_atomic_with_backup(&temp_dir, &p2).unwrap();
        assert_eq!(load_rulepack(&temp_dir).version, "2026.11.2");

        // Corrupt main file -> load_rulepack automatically falls back to backup p1
        fs::write(rulepack_file(&temp_dir), "{not valid json").unwrap();
        assert_eq!(load_rulepack(&temp_dir).version, "2026.11.1");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn rejects_global_tld_and_ext_rule_injections() {
        let mut bad_pack = default_rulepack();
        bad_pack
            .categories
            .get_mut("other_ru")
            .unwrap()
            .push("com".to_string());
        assert!(validate_rulepack_data(&bad_pack).is_err());

        let ext_rule = RoutingRule {
            id: "r1".to_string(),
            enabled: true,
            match_type: RuleMatchType::Domain,
            pattern: r"ext:\\attacker\share\evil.dat:proxy".to_string(),
            action: RuleAction::Direct,
            note: None,
        };
        assert!(validate_routing_rule(&ext_rule).is_err());

        let proc_path_rule = RoutingRule {
            id: "r2".to_string(),
            enabled: true,
            match_type: RuleMatchType::Process,
            pattern: r"..\evil.exe".to_string(),
            action: RuleAction::Direct,
            note: None,
        };
        assert!(validate_routing_rule(&proc_path_rule).is_err());
    }

    #[test]
    fn emits_ru_tlds_and_compares_versions_numerically() {
        let cfg = RoutingConfig {
            profile: RoutingProfile::RuDirect,
            bypass_ru_domains: true,
            ..Default::default()
        };
        let pack = default_rulepack();
        let active = collect_active_ru_domains(&cfg, &pack);
        assert!(active.iter().any(|d| d == "domain:ru"));
        assert!(active.iter().any(|d| d == "domain:xn--p1ai"));

        assert!(is_rulepack_downgrade("2026.9.1", "2026.11.1"));
        assert!(!is_rulepack_downgrade("2026.11.10", "2026.11.2"));
        assert!(!is_rulepack_downgrade("2026.11.2", "2026.11.2"));
    }
}
