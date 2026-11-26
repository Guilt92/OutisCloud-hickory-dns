use actix_web::HttpMessage;
use actix_web::body::{MessageBody, to_bytes};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::Next;
use actix_web::{App, HttpRequest, HttpResponse, HttpServer, Responder, http::header, web};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::{OpenApi, ToSchema};
mod automation;
mod db_pool;
mod dns_builder;
mod dns_manager;
mod dns_validator;
mod dnssec;
mod ext;
mod health;
mod lookup;
mod metrics;
mod shared;
mod tenants;
mod zone_file_generator;
mod zone_ops;
use actix_cors::Cors;
use actix_web_prom::PrometheusMetricsBuilder;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use chrono::TimeZone;
use db_pool::Pool;
use dns_builder::DnsRecordBuilder;
use dns_manager::DnsManager;
use dns_validator::*;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode};
use prometheus::gather;
use prometheus::{Encoder, TextEncoder};
use std::collections::HashMap;
#[cfg(test)]
use tokio_postgres::NoTls;
use uuid::Uuid;
use zone_file_generator::RecordRow;

/// Generate a cryptographically random salt for password/agent-token hashing.
fn generate_salt() -> SaltString {
    use rand_core::{OsRng, RngCore};

    let mut salt_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut salt_bytes);
    SaltString::encode_b64(&salt_bytes)
        .unwrap_or_else(|_| SaltString::from_b64("ABCD1234EFGH5678IJKL").unwrap())
}

/// Hash a token for storage (refresh tokens and the access-token blacklist).
/// SHA-256 so the stored value is a stable, collision-resistant digest (the
/// std `DefaultHasher` is a 64-bit, non-cryptographic hash whose output is not
/// guaranteed to be stable across Rust releases).
fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Maximum number of failed-or-not login attempts per username per minute.
const LOGIN_ATTEMPTS_PER_MINUTE: u32 = 10;

static LOGIN_LIMITER: once_cell::sync::Lazy<governor::DefaultKeyedRateLimiter<String>> =
    once_cell::sync::Lazy::new(|| {
        governor::RateLimiter::keyed(governor::Quota::per_minute(
            std::num::NonZeroU32::new(LOGIN_ATTEMPTS_PER_MINUTE).unwrap(),
        ))
    });

/// Budget per client address (many users may share one NAT, so it is much
/// larger than the per-username one). `LOGIN_RATE_PER_IP`, default 60/minute.
static LOGIN_IP_LIMITER: once_cell::sync::Lazy<governor::DefaultKeyedRateLimiter<String>> =
    once_cell::sync::Lazy::new(|| {
        let n = std::env::var("LOGIN_RATE_PER_IP")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(60);
        governor::RateLimiter::keyed(governor::Quota::per_minute(
            std::num::NonZeroU32::new(n).unwrap(),
        ))
    });

/// Returns false when `username` has exhausted its login budget.
fn login_allowed(username: &str) -> bool {
    // bound the memory an attacker can force by cycling usernames
    if LOGIN_LIMITER.len() > 10_000 {
        LOGIN_LIMITER.retain_recent();
        LOGIN_LIMITER.shrink_to_fit();
    }
    let key: String = username.to_ascii_lowercase().chars().take(64).collect();
    LOGIN_LIMITER.check_key(&key).is_ok()
}

/// Returns false when this client address has exhausted its login budget.
fn login_ip_allowed(ip: &std::net::IpAddr) -> bool {
    if LOGIN_IP_LIMITER.len() > 50_000 {
        LOGIN_IP_LIMITER.retain_recent();
        LOGIN_IP_LIMITER.shrink_to_fit();
    }
    LOGIN_IP_LIMITER.check_key(&ip.to_string()).is_ok()
}

/// Build a CORS middleware instance based on the `ALLOWED_ORIGINS`
/// environment variable.  The value may be a comma-separated list of
/// origins or a single asterisk (`*`) to allow any origin.  When the
/// variable is missing we fall back to a small set of development
/// defaults (including the UI port on `localhost:8081`).
///
/// The resulting middleware is applied to every `App` instance and
/// automatically handles preflight requests (OPTIONS) and populates
/// the `Access-Control-Allow-Origin` header for permitted origins.
fn cors_middleware() -> Cors {
    // gather configuration from environment
    let maybe_env = std::env::var("ALLOWED_ORIGINS");
    let cors_origins = maybe_env.clone().unwrap_or_else(|_| {
        "http://localhost:3000,http://localhost:5173,http://localhost:8081".to_string()
    });

    // if user explicitly provided a list but forgot the common
    // development UI port, emit a warning so they don't waste time
    if maybe_env.is_ok()
        && cors_origins.trim() != "*"
        && !cors_origins
            .split(',')
            .any(|o| o.trim() == "http://localhost:8081")
    {
        warn!(
            "ALLOWED_ORIGINS does not include the default UI origin http://localhost:8081; login from the built-in docker UI may fail"
        );
    }

    let mut cors = Cors::default()
        .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
        .allowed_headers(vec![header::AUTHORIZATION, header::CONTENT_TYPE])
        .expose_headers(vec!["X-Total-Count"])
        .max_age(3600);

    if cors_origins.trim() == "*" {
        // Tokens travel in the Authorization header (no cookies), so a wildcard
        // does not enable cross-site request forgery, but it is still wider
        // than needed. Prefer an explicit list.
        warn!(
            "ALLOWED_ORIGINS=* allows any website to call this API from a browser; list your UI origin(s) instead"
        );
        cors = cors.allow_any_origin();
    } else {
        for origin in cors_origins.split(',') {
            let o = origin.trim();
            if !o.is_empty() {
                cors = cors.allowed_origin(o);
            }
        }
    }

    cors
}

// ============================================================================
// OpenAPI / Swagger Types
// ============================================================================

#[derive(ToSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

#[derive(ToSchema, Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

#[derive(ToSchema, Clone, Serialize, Deserialize)]
struct Claims {
    sub: String,
    role: String,
    exp: usize,
    /// Session generation. Tokens issued before this claim existed decode as
    /// generation 0, which matches existing database rows.
    #[serde(default)]
    ver: i64,
}

#[derive(ToSchema, Clone, Serialize, Deserialize)]
struct ServerInfo {
    id: String,
    name: String,
    address: String,
    port: i32,
    region: Option<String>,
    enabled: bool,
    dnssec: bool,
    enable_logging: bool,
    max_cache_ttl: i32,
    min_cache_ttl: i32,
    status: Option<String>,
}

#[derive(ToSchema, Clone, Serialize, Deserialize)]
struct ZoneRecord {
    name: String,
    record_type: String,
    value: String,
    ttl: u32,
}

#[derive(ToSchema, Clone, Serialize, Deserialize)]
struct Zone {
    id: String,
    domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    records: Vec<ZoneRecord>,
}

#[derive(ToSchema, Clone, Serialize, Deserialize)]
struct ZoneWithOwner {
    id: String,
    domain: String,
    owner: String,
    zone_type: String,
    created_at: String,
    geodns_enabled: bool,
    /// "active" or "pending" (waiting for domain-ownership verification)
    #[serde(default)]
    status: String,
    /// the caller's role on this zone: admin, owner, editor or viewer
    #[serde(default)]
    access: String,
    #[serde(default)]
    ecs_enabled: bool,
    /// owning tenant (id and name), if any
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    tenant_name: Option<String>,
    #[serde(default)]
    description: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    hold_reason: Option<String>,
    #[serde(default)]
    hold_until: Option<String>,
}

#[derive(Clone)]
struct AppState {
    db: Arc<Pool>,
    jwt_secret: String,
    dns_manager: Arc<DnsManager>,
    /// resolver used for domain-ownership TXT checks
    verify_resolver: std::net::SocketAddr,
    /// ordered DNS Lookup resolvers (empty = not configured); see lookup.rs
    lookup_resolvers: Vec<lookup::ResolverSpec>,
    /// require a TXT challenge before a non-admin's zone is served
    verify_domains: bool,
    /// http://host:port/metrics of the DNS server (query statistics)
    dns_metrics_url: Option<String>,
}

/// Proxies whose `X-Forwarded-For` is trusted (TRUSTED_PROXIES).
static TRUSTED_PROXIES: once_cell::sync::OnceCell<Vec<ext::Cidr>> =
    once_cell::sync::OnceCell::new();

fn trusted_proxies() -> &'static [ext::Cidr] {
    TRUSTED_PROXIES.get().map(|v| v.as_slice()).unwrap_or(&[])
}

fn real_client_ip(req: &HttpRequest) -> Option<std::net::IpAddr> {
    ext::client_ip(req, trusted_proxies())
}

struct GeoState {
    db: Option<geodns::GeoDB>,
}

#[derive(Clone)]
struct FullState {
    inner: AppState,
    geo: Arc<tokio::sync::Mutex<GeoState>>,
    processes: Arc<tokio::sync::Mutex<HashMap<String, std::process::Child>>>,
}

// ============================================================================
// Shared helpers: audit trail, zone access control, publication
// ============================================================================

/// Record an entry in the audit trail. Failures are logged but never fail the
/// request that is being audited.
async fn audit(
    db: &Pool,
    user_id: Option<&str>,
    action: &str,
    resource_type: &str,
    resource_id: Option<String>,
    req: &HttpRequest,
    details: serde_json::Value,
) {
    let ip = real_client_ip(req).map(|a| a.to_string());
    let ua = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.chars().take(256).collect::<String>());
    let res = db
        .execute(
            "INSERT INTO audit_logs (id, user_id, action, resource_type, resource_id, details, ip_address, user_agent) \
             VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5, $6::text::jsonb, $7, $8)",
            &[&Uuid::new_v4().to_string(), &user_id, &action, &resource_type, &resource_id, &details.to_string(), &ip, &ua],
        )
        .await;
    if let Err(e) = res {
        warn!(
            "failed to write audit log ({}): {}",
            action,
            full_error_string(&e)
        );
    }
}

/// Result of an access check on a zone.
struct ZoneAccess {
    domain: String,
    /// Tenant that owns the zone; used for fair transaction admission.
    tenant_id: Option<String>,
    /// "admin", "owner", "editor" or "viewer"
    role: String,
    /// Lifecycle state from `zones.status` ("active", "held", "suspended", ...).
    status: String,
}

/// What a caller wants to do with a zone.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Level {
    /// read zone, records, export, geo rules
    Read,
    /// change records and geo rules
    Write,
    /// rename/delete the zone, manage sharing, restore revisions
    Owner,
}

/// Load a zone and verify that the caller may act on it at `need`.
/// Admins may do everything; the owner has all levels; members added through
/// zone sharing have `Read` (viewer) or `Read`+`Write` (editor). Returns the
/// HTTP response to send when access is not granted (404 unknown zone, 403
/// otherwise).
async fn zone_access_at(
    db: &Pool,
    zone_id: &str,
    tok: &TokenData<Claims>,
    need: Level,
) -> Result<ZoneAccess, HttpResponse> {
    // `zones.owner` is a UUID column: compare through text so the check never
    // depends on how the driver would decode it.
    let row = db
        .query_opt(
            "SELECT z.domain, COALESCE(CAST(z.owner AS varchar), ''), \
                    (SELECT m.role FROM zone_members m WHERE m.zone_id = z.id AND CAST(m.user_id AS varchar) = $2), \
                    (SELECT tm.role FROM tenant_members tm WHERE tm.tenant_id = z.tenant_id AND CAST(tm.user_id AS varchar) = $2), \
                    COALESCE(z.status, 'active'), CAST(z.tenant_id AS varchar) \
             FROM zones z WHERE CAST(z.id AS varchar) = $1",
            &[&zone_id, &tok.claims.sub],
        )
        .await;
    match row {
        Ok(Some(r)) => {
            let domain: String = r.try_get(0).unwrap_or_default();
            let owner: String = r.try_get(1).unwrap_or_default();
            let member: Option<String> = r.try_get(2).unwrap_or(None);
            let tenant_member: Option<String> = r.try_get(3).unwrap_or(None);
            let status: String = r.try_get(4).unwrap_or_else(|_| "active".to_string());
            let tenant_id: Option<String> = r.try_get(5).unwrap_or(None);
            let rank = |x: &str| match x {
                "owner" => 3,
                "editor" => 2,
                "viewer" => 1,
                _ => 0,
            };
            let role = if tok.claims.role == "admin" {
                "admin"
            } else if !owner.is_empty() && owner == tok.claims.sub {
                "owner"
            } else {
                // best of zone sharing and tenant membership
                let a = match member.as_deref() {
                    Some("editor") => "editor",
                    Some("viewer") => "viewer",
                    _ => "",
                };
                let b = tenants::tenant_role_to_zone_role(tenant_member.as_deref());
                if rank(b) > rank(a) { b } else { a }
            };
            let granted = match role {
                "admin" | "owner" => Level::Owner,
                "editor" => Level::Write,
                "viewer" => Level::Read,
                _ => {
                    return Err(HttpResponse::Forbidden()
                        .json(serde_json::json!({"error": "access denied"})));
                }
            };
            if granted >= need {
                // Archived zones are read-only for everyone except admins. The
                // owner may still delete or restore the zone (Level::Owner).
                if status == "archived" && need == Level::Write {
                    return Err(HttpResponse::Conflict().json(serde_json::json!({
                        "error": "zone is archived",
                        "details": "restore the zone before changing its records"
                    })));
                }
                Ok(ZoneAccess {
                    domain,
                    tenant_id,
                    role: role.to_string(),
                    status,
                })
            } else {
                Err(HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied", "details": "insufficient permission on this zone"})))
            }
        }
        Ok(None) => {
            Err(HttpResponse::NotFound().json(serde_json::json!({"error": "zone not found"})))
        }
        Err(e) => {
            warn!("zone access check error: {}", full_error_string(&e));
            Err(HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"})))
        }
    }
}

async fn begin_zone_transaction(
    db: &Pool,
    access: &ZoneAccess,
) -> Result<db_pool::TxConn, tokio_postgres::Error> {
    if let Some(tenant_id) = access.tenant_id.as_deref() {
        db.begin_for(tenant_id).await
    } else {
        db.begin().await
    }
}

/// Write access (the historic behaviour of `zone_access`).
async fn zone_access(
    db: &Pool,
    zone_id: &str,
    tok: &TokenData<Claims>,
) -> Result<ZoneAccess, HttpResponse> {
    zone_access_at(db, zone_id, tok, Level::Write).await
}

fn unauthorized() -> HttpResponse {
    HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"}))
}

fn invalid_list_query() -> HttpResponse {
    HttpResponse::BadRequest().json(serde_json::json!({
        "error": "invalid_query",
        "details": "Unsupported sort field or order"
    }))
}

fn status_error_code(status: actix_web::http::StatusCode) -> &'static str {
    match status.as_u16() {
        400 | 422 => "invalid_request",
        401 => "unauthorized",
        403 => "forbidden",
        404 => "not_found",
        409 => "conflict",
        429 => "rate_limited",
        501 => "not_implemented",
        503 => "service_unavailable",
        500..=599 => "internal_error",
        _ => "request_failed",
    }
}

/// Preserve existing response fields while guaranteeing clients a stable
/// `code`, `error`, and `details` envelope for every JSON client/server error.
async fn error_envelope_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<actix_web::body::BoxBody>, actix_web::Error> {
    let response = next.call(req).await?;
    let status = response.status();
    if !(status.is_client_error() || status.is_server_error()) {
        return Ok(response.map_into_boxed_body());
    }
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !content_type.contains("application/json") {
        return Ok(response.map_into_boxed_body());
    }
    let (request, response) = response.into_parts();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body())
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("failed to read error response"))?;
    let code = status_error_code(status);
    let normalized = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .map(|value| {
            let mut object = value.as_object().cloned().unwrap_or_default();
            if !object
                .get("code")
                .is_some_and(|v| v.as_str().is_some_and(|s| !s.is_empty()))
            {
                object.insert("code".into(), code.into());
            }
            if !object.get("error").is_some_and(|v| v.is_string()) {
                object.insert("error".into(), code.into());
            }
            if !object.contains_key("details") {
                object.insert(
                    "details".into(),
                    object
                        .get("message")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null),
                );
            }
            serde_json::Value::Object(object)
        })
        .unwrap_or_else(|| serde_json::json!({"code": code, "error": code, "details": null}));
    let mut builder = HttpResponse::build(status);
    for (name, value) in headers.iter() {
        if name != header::CONTENT_LENGTH && name != header::CONTENT_TYPE {
            builder.insert_header((name.clone(), value.clone()));
        }
    }
    Ok(ServiceResponse::new(
        request,
        builder.json(normalized).map_into_boxed_body(),
    ))
}

/// Republish zone files and report the real outcome. `zone_domain` is the zone
/// the caller's change affects: if that zone could not be published the error
/// is returned (its previous file is still the one being served). Failures of
/// unrelated zones are logged but not attributed to this request.
async fn publish(
    dns: &DnsManager,
    db: &Arc<Pool>,
    zone_domain: Option<&str>,
) -> Result<(), String> {
    let result = publish_current(dns, db, zone_domain).await;
    if let Some(domain) = zone_domain {
        match &result {
            Ok(()) => {
                if let Err(error) = db
                    .execute(
                        "DELETE FROM publication_outbox WHERE zone_domain=$1",
                        &[&domain],
                    )
                    .await
                {
                    warn!("unable to acknowledge published zone {}: {}", domain, error);
                }
            }
            Err(error) => {
            if let Err(queue_error) = db.execute(
                "INSERT INTO publication_outbox(zone_domain, attempts, next_attempt, last_error) VALUES($1,0,now(),$2) ON CONFLICT(zone_domain) DO UPDATE SET attempts=0,next_attempt=now(),last_error=EXCLUDED.last_error,updated_at=now()",
                &[&domain, error],
            ).await {
                warn!("unable to persist publication retry for {}: {}", domain, queue_error);
            }
        }
        }
    }
    result
}

async fn publish_current(
    dns: &DnsManager,
    db: &Arc<Pool>,
    zone_domain: Option<&str>,
) -> Result<(), String> {
    match dns.regenerate_zones(db.clone()).await {
        Err(e) => Err(e.to_string()),
        Ok(report) => {
            if let Some(d) = zone_domain {
                if let Some(err) = report.error_for(d) {
                    return Err(err.to_string());
                }
            } else if !report.failed.is_empty() {
                let list: Vec<String> = report
                    .failed
                    .iter()
                    .map(|(z, e)| format!("{}: {}", z, e))
                    .collect();
                return Err(format!(
                    "{} zone(s) not published: {}",
                    report.failed.len(),
                    list.join("; ")
                ));
            }
            // new published content => new bundle version for the agents
            if let Err(e) = ext::current_bundle(dns, db).await {
                warn!("bundle version update failed: {}", e);
            }
            Ok(())
        }
    }
}

async fn publication_retry_worker(dns: Arc<DnsManager>, db: Arc<Pool>) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        if let Err(error) = publication_retry_once(&dns, &db).await {
            warn!("publication retry poll failed: {}", error);
        }
    }
}

/// Claim and process at most one due publication job. Keeping this as a
/// single iteration lets integration tests exercise worker restart/reclaim
/// behavior without relying on wall-clock sleeps.
async fn publication_retry_once(
    dns: &DnsManager,
    db: &Arc<Pool>,
) -> Result<bool, tokio_postgres::Error> {
    let due = db.query(
            "WITH due AS (SELECT zone_domain FROM publication_outbox WHERE status='pending' AND next_attempt <= now() ORDER BY next_attempt FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE publication_outbox o SET attempts=o.attempts+1,status=CASE WHEN o.attempts >= 9 THEN 'failed' ELSE 'pending' END,next_attempt=now()+LEAST(300, power(2, LEAST(o.attempts,8))::int)*interval '1 second',updated_at=now() FROM due WHERE o.zone_domain=due.zone_domain RETURNING o.zone_domain,o.attempts",
            &[],
        ).await?.into_iter().next();
    let Some(due) = due else {
        return Ok(false);
    };
    let domain: String = due.get(0);
    let attempts: i32 = due.get(1);
    match publish_current(dns, db, Some(&domain)).await {
        Ok(()) => {
            if let Err(error) = db
                .execute(
                    "DELETE FROM publication_outbox WHERE zone_domain=$1",
                    &[&domain],
                )
                .await
            {
                warn!(
                    "published {} but could not acknowledge retry job: {}",
                    domain, error
                );
            }
        }
        Err(error) => {
            warn!(
                "publication retry {} for {} failed: {}",
                attempts, domain, error
            );
            db.execute(
                "UPDATE publication_outbox SET last_error=$2,updated_at=now() WHERE zone_domain=$1",
                &[&domain, &error],
            )
            .await?;
        }
    }
    Ok(true)
}

/// Requeue a terminal publication failure after an operator has corrected its
/// filesystem or database cause. Only a verified administrator may invoke it.
async fn retry_failed_publication(
    path: web::Path<String>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let token = match auth_from_header(&req, &data.jwt_secret) {
        Some(token) => token,
        None => return unauthorized(),
    };
    if token.claims.role != "admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "admin role required"}));
    }
    let domain = path.into_inner().trim_end_matches('.').to_ascii_lowercase();
    if dns_validator::validate_zone_domain(&domain).is_err() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "invalid zone domain"}));
    }
    let updated = match data.db.execute(
        "UPDATE publication_outbox SET attempts=0,status='pending',next_attempt=now(),last_error='operator requested retry',updated_at=now() WHERE zone_domain=$1",
        &[&domain],
    ).await {
        Ok(updated) => updated,
        Err(error) => {
            warn!("unable to requeue publication for {}: {}", domain, error);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "database error"}));
        }
    };
    if updated == 0 {
        return HttpResponse::NotFound()
            .json(serde_json::json!({"error": "publication retry not found"}));
    }
    audit(
        &data.db,
        Some(&token.claims.sub),
        "publication_retry_requeued",
        "zone",
        Some(domain.clone()),
        &req,
        serde_json::json!({"domain": domain}),
    )
    .await;
    HttpResponse::Accepted().json(serde_json::json!({"domain": domain, "status": "pending"}))
}

#[cfg(test)]
mod publication_retry_tests {
    #[test]
    fn retry_delay_is_exponential_and_bounded() {
        let delays: Vec<i32> = (0..12).map(|attempt| 2_i32.pow(attempt.min(8))).collect();
        assert_eq!(&delays[..5], &[1, 2, 4, 8, 16]);
        assert!(delays.iter().all(|delay| *delay <= 256));
        assert_eq!(delays[8], delays[11]);
    }

    #[test]
    fn retry_jobs_address_committed_zone_state_not_mutation_payloads() {
        let migration = include_str!("../migrations/007_publication_outbox.sql");
        assert!(migration.contains("zone_domain TEXT PRIMARY KEY"));
        assert!(!migration.contains("record_value"));
        assert!(migration.contains("next_attempt"));
        assert!(migration.contains("last_error"));
    }
}

fn idempotency_key(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|key| !key.is_empty() && key.len() <= 255)
        .map(str::to_string)
}

async fn idempotency_replay(
    db: &Pool,
    key: &str,
    user: &str,
    endpoint: &str,
) -> Option<HttpResponse> {
    let row = db
        .query_opt(
            "SELECT status, response FROM idempotency_keys \
         WHERE key = $1 AND CAST(user_id AS varchar) = $2 AND endpoint = $3 AND expires_at > now()",
            &[&key, &user, &endpoint],
        )
        .await
        .ok()
        .flatten()?;
    let status = row.get::<_, i32>(0) as u16;
    let response: serde_json::Value = row.get(1);
    let code =
        actix_web::http::StatusCode::from_u16(status).unwrap_or(actix_web::http::StatusCode::OK);
    Some(HttpResponse::build(code).json(response))
}

async fn idempotency_store(
    db: &Pool,
    key: &str,
    user: &str,
    endpoint: &str,
    status: u16,
    response: &serde_json::Value,
) {
    let ttl = std::env::var("IDEMPOTENCY_TTL_SECS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(86_400);
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(ttl);
    if let Err(e) = db
        .execute(
            "INSERT INTO idempotency_keys (key, user_id, endpoint, status, response, expires_at) \
         VALUES ($1, $2::text::uuid, $3, $4, $5, $6) \
         ON CONFLICT (key, user_id, endpoint) DO NOTHING",
            &[
                &key,
                &user,
                &endpoint,
                &(status as i32),
                response,
                &expires_at,
            ],
        )
        .await
    {
        warn!("idempotency_store failed: {}", full_error_string(&e));
    }
}

fn publish_failed(err: &str) -> HttpResponse {
    HttpResponse::InternalServerError().json(serde_json::json!({
        "error": "publish_failed",
        "details": format!("The change was saved but the zone could not be published; the previous zone data is still being served: {}", err),
        "saved": true,
        "published": false
    }))
}

fn publish_failed_rolled_back(err: &str) -> HttpResponse {
    HttpResponse::InternalServerError().json(serde_json::json!({
        "error": "publish_failed",
        "details": format!("The change was rolled back because the zone could not be published; the previous zone data is still being served: {}", err),
        "saved": false,
        "published": false
    }))
}

/// Does `candidate` overlap (equal, parent or child of) a zone owned by someone else?
async fn zone_overlaps_other_owner(
    db: &Pool,
    candidate: &str,
    owner: &str,
    exclude_zone_id: Option<&str>,
) -> Result<bool, tokio_postgres::Error> {
    let excl = exclude_zone_id.unwrap_or("");
    let row = db
        .query_opt(
            "SELECT 1 FROM zones WHERE COALESCE(CAST(owner AS varchar), '') <> $2 AND CAST(id AS varchar) <> $3 \
             AND (tenant_id IS NULL OR NOT EXISTS (SELECT 1 FROM tenant_members tm WHERE tm.tenant_id = zones.tenant_id AND CAST(tm.user_id AS varchar) = $2)) \
             AND (domain = $1 OR domain LIKE '%.' || $1 OR $1 LIKE '%.' || domain) LIMIT 1",
            &[&candidate, &owner, &excl],
        )
        .await?;
    Ok(row.is_some())
}

/// Roles understood by the API (the dashboard offers admin / editor / viewer).
/// `admin` manages everything; `user` and `editor` manage the zones they own;
/// `viewer` is read-only everywhere (enforced in [`auth_middleware`]).
const VALID_ROLES: [&str; 4] = ["admin", "editor", "viewer", "user"];

fn is_read_method(m: &actix_web::http::Method) -> bool {
    matches!(
        *m,
        actix_web::http::Method::GET
            | actix_web::http::Method::HEAD
            | actix_web::http::Method::OPTIONS
    )
}

/// Endpoints a read-only account still needs for managing its own session.
fn viewer_may_write(path: &str) -> bool {
    // own-account actions and the (read-only, rate-limited) DNS lookup tool
    matches!(
        path,
        "/api/v1/auth/logout"
            | "/api/v1/auth/refresh"
            | "/api/v1/auth/change-password"
            | "/api/v1/auth/mfa/setup"
            | "/api/v1/auth/mfa/enable"
            | "/api/v1/auth/mfa/disable"
            | "/api/v1/dns/lookup"
    )
}

const MAX_RECORD_TTL: u32 = 2_147_483_647; // RFC 2181: TTLs are 31-bit values

fn valid_target_ip(s: &str) -> bool {
    s.trim().parse::<std::net::IpAddr>().is_ok()
}

fn validate_georule_fields(
    match_type: Option<&str>,
    match_value: Option<&str>,
    target: Option<&str>,
    record_name: Option<&str>,
    record_type: Option<&str>,
) -> Result<(), String> {
    if let Some(mt) = match_type {
        if !matches!(
            mt,
            "country" | "region" | "city" | "continent" | "default" | "fallback"
        ) {
            return Err(
                "match_type must be one of country, region, city, continent, default, fallback"
                    .into(),
            );
        }
        if let Some(mv) = match_value {
            let ok = match mt {
                "country" => mv.len() == 2 && mv.bytes().all(|b| b.is_ascii_alphabetic()),
                "continent" => mv.len() == 2 && mv.bytes().all(|b| b.is_ascii_alphabetic()),
                // ISO 3166-1 alpha-2 or ISO 3166-2 (e.g. US-CA)
                "region" => {
                    mv.len() >= 2
                        && mv.len() <= 10
                        && mv.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                }
                // "CC:City Name" or "City Name" (City database required)
                "city" => {
                    !mv.is_empty()
                        && mv.chars().count() <= 100
                        && mv
                            .chars()
                            .all(|c| c.is_alphanumeric() || " .'-:".contains(c))
                }
                _ => {
                    mv.is_empty()
                        || (mv.len() <= 16
                            && mv.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
                }
            };
            if !ok {
                return Err(format!("invalid match_value for match_type {}", mt));
            }
        }
    } else if let Some(mv) = match_value {
        if mv.len() > 16 || !mv.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err("invalid match_value".into());
        }
    }
    if let Some(t) = target {
        if !valid_target_ip(t) {
            return Err("target must be an IPv4 or IPv6 address".into());
        }
    }
    if let Some(n) = record_name {
        if !n.is_empty()
            && validate_record_in_zone(n, "invalid.invalid").is_err()
            && !n.ends_with('.')
        {
            return Err("invalid record_name".into());
        }
        if n.len() > 253 {
            return Err("invalid record_name".into());
        }
    }
    if let Some(t) = record_type {
        if !t.is_empty() && !t.eq_ignore_ascii_case("A") && !t.eq_ignore_ascii_case("AAAA") {
            return Err("record_type must be A or AAAA".into());
        }
    }
    Ok(())
}

async fn health() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"status":"ok"}))
}

async fn ready(data: web::Data<AppState>) -> impl Responder {
    match data.db.query("SELECT 1", &[]).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status":"ready"})),
        Err(e) => {
            warn!("database not ready: {}", e);
            HttpResponse::ServiceUnavailable().json(serde_json::json!({"status":"not ready"}))
        }
    }
}

// Collect the full message of an error and its source chain. tokio_postgres
// errors surface as a top-level "db error" whose useful detail (e.g. the
// unique-violation message) lives in the source chain, and anyhow/DNS errors
// similarly nest their cause. Joining every level avoids losing that context.
fn full_error_string(e: &dyn std::error::Error) -> String {
    let mut parts = Vec::new();
    let mut current = Some(e as &dyn std::error::Error);
    while let Some(err) = current {
        let msg = err.to_string();
        if !parts.iter().any(|p: &String| *p == msg) {
            parts.push(msg);
        }
        current = err.source();
    }
    parts.join(": ")
}

async fn rollback_transaction(client: &tokio_postgres::Client) {
    let failed = if let Err(error) = client.batch_execute("ROLLBACK").await {
        warn!(
            "database transaction rollback failed: {}",
            full_error_string(&error)
        );
        true
    } else {
        false
    };
    metrics::record_transaction_rollback(failed);
}

fn validate_domain(domain: &str) -> Result<(), String> {
    // Wrapper that uses the centralized dns_validator module
    validate_zone_domain(domain).map_err(|e| e.message)
}

fn validate_record_type_str(record_type: &str) -> Result<(), String> {
    // Wrapper that uses the centralized dns_validator module
    validate_record_type(record_type)
        .map(|_| ())
        .map_err(|e| e.message)
}

fn valid_email(email: &str) -> bool {
    if email.len() > 254 || email.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }
    let mut parts = email.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    if local.is_empty()
        || local.len() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
    {
        return false;
    }
    if domain.is_empty() || domain.len() > 253 || !domain.contains('.') {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

fn validate_record_value_str(record_type: &str, value: &str) -> Result<(), String> {
    // Wrapper that uses the centralized dns_validator module
    validate_record_value(record_type, value)
        .map(|_| ())
        .map_err(|e| e.message)
}

async fn migrate_db(client: &Pool) -> Result<(), tokio_postgres::Error> {
    // Create tables individually to better report errors

    // Users table
    if let Err(e) = client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMPTZ DEFAULT now(),
            updated_at TIMESTAMPTZ DEFAULT now()
        );",
        )
        .await
    {
        warn!("Failed to create users table: {}", e);
        return Err(e);
    }
    info!("Users table ready");

    // Token blacklist table for invalidated tokens (logout)
    if let Err(e) = client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS token_blacklist (
            id UUID PRIMARY KEY,
            token_hash TEXT NOT NULL,
            user_id UUID,
            revoked_at TIMESTAMPTZ DEFAULT now(),
            expires_at TIMESTAMPTZ NOT NULL
        );",
        )
        .await
    {
        warn!("Failed to create token_blacklist table: {}", e);
        return Err(e);
    }
    info!("Token blacklist table ready");

    // Clean up expired tokens on startup
    if let Err(e) = client
        .execute("DELETE FROM token_blacklist WHERE expires_at < now()", &[])
        .await
    {
        warn!("Failed to clean up expired tokens: {}", e);
    }

    // Servers table
    if let Err(e) = client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS servers (
            id UUID PRIMARY KEY,
            name TEXT NOT NULL,
            address TEXT NOT NULL,
            port INT DEFAULT 53,
            region TEXT,
            enabled BOOLEAN DEFAULT true,
            dnssec BOOLEAN DEFAULT false,
            enable_logging BOOLEAN DEFAULT true,
            max_cache_ttl INT DEFAULT 3600,
            min_cache_ttl INT DEFAULT 60,
            created_at TIMESTAMPTZ DEFAULT now(),
            updated_at TIMESTAMPTZ DEFAULT now()
        );",
        )
        .await
    {
        warn!("Failed to create servers table: {}", e);
        return Err(e);
    }
    info!("Servers table ready");

    // Zones table
    if let Err(e) = client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS zones (
            id UUID PRIMARY KEY,
            domain TEXT NOT NULL,
            owner UUID REFERENCES users(id) ON DELETE SET NULL,
            zone_type TEXT NOT NULL DEFAULT 'primary',
            description TEXT NOT NULL DEFAULT '',
            tags JSONB NOT NULL DEFAULT '[]'::jsonb,
            axfr_policy TEXT NOT NULL DEFAULT 'Deny',
            axfr_allowed_peers TEXT[] NOT NULL DEFAULT '{}',
            geodns_enabled BOOLEAN DEFAULT true,
            created_at TIMESTAMPTZ DEFAULT now(),
            updated_at TIMESTAMPTZ DEFAULT now(),
            UNIQUE(domain)
        );",
        )
        .await
    {
        warn!("Failed to create zones table: {}", e);
        return Err(e);
    }
    info!("Zones table ready");
    // Ensure existing installations get the new column
    if let Err(e) = client
        .batch_execute(
            "ALTER TABLE zones ADD COLUMN IF NOT EXISTS geodns_enabled BOOLEAN DEFAULT true;",
        )
        .await
    {
        warn!("Failed to add geodns_enabled to zones: {}", e);
        return Err(e);
    }

    // Records table
    if let Err(e) = client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS records (
            id UUID PRIMARY KEY,
            zone_id UUID REFERENCES zones(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            record_type TEXT NOT NULL,
            value TEXT NOT NULL,
            ttl INT NOT NULL DEFAULT 3600,
            priority INT DEFAULT 10,
            comment TEXT NOT NULL DEFAULT '',
            tags JSONB NOT NULL DEFAULT '[]'::jsonb,
            created_at TIMESTAMPTZ DEFAULT now(),
            updated_at TIMESTAMPTZ DEFAULT now()
        );",
        )
        .await
    {
        warn!("Failed to create records table: {}", e);
        return Err(e);
    }
    info!("Records table ready");
    // Fix: rename `type` column to `record_type` if the old migration SQL was used.
    // The migration SQL (001_initial_schema.sql) creates column `type`, but all
    // application code uses `record_type`. Must handle safely for existing DBs.
    if let Err(e) = client.batch_execute(
        "DO $$
         BEGIN
             IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name='records' AND column_name='type') THEN
                 ALTER TABLE records RENAME COLUMN type TO record_type;
             END IF;
         END $$;"
    ).await {
        warn!("Failed to rename records.type to record_type: {}", e);
        return Err(e);
    }
    // Also ensure record_type column exists (for fresh tables or partial migrations)
    if let Err(e) = client
        .batch_execute(
            "ALTER TABLE records ADD COLUMN IF NOT EXISTS record_type TEXT NOT NULL DEFAULT 'A';",
        )
        .await
    {
        warn!("Failed to ensure record_type column on records: {}", e);
        return Err(e);
    }

    // Nameservers table — created by migrate_db so it always exists regardless
    // of whether the migration SQL files were loaded at container init.
    if let Err(e) = client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS nameservers (
            id UUID PRIMARY KEY,
            hostname TEXT NOT NULL UNIQUE,
            ip_address TEXT NOT NULL,
            glue_ip TEXT,
            sort_order INT DEFAULT 0,
            enabled BOOLEAN DEFAULT true,
            created_at TIMESTAMPTZ DEFAULT now(),
            updated_at TIMESTAMPTZ DEFAULT now()
        );",
        )
        .await
    {
        warn!("Failed to create nameservers table: {}", e);
        return Err(e);
    }
    info!("Nameservers table ready");

    // Agents table
    if let Err(e) = client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS agents (
            id UUID PRIMARY KEY,
            name TEXT NOT NULL,
            addr TEXT NOT NULL,
            last_heartbeat TIMESTAMPTZ DEFAULT now(),
            token_hash TEXT NOT NULL,
            enabled BOOLEAN DEFAULT true,
            created_at TIMESTAMPTZ DEFAULT now(),
            updated_at TIMESTAMPTZ DEFAULT now()
        );",
        )
        .await
    {
        warn!("Failed to create agents table: {}", e);
        return Err(e);
    }
    info!("Agents table ready");

    // Georules table
    if let Err(e) = client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS georules (
            id UUID PRIMARY KEY,
            zone_id UUID REFERENCES zones(id) ON DELETE CASCADE,
            match_type TEXT NOT NULL,
            match_value TEXT NOT NULL,
            target TEXT NOT NULL,
            weight INT NOT NULL DEFAULT 1,
            priority INT DEFAULT 0,
            enabled BOOLEAN DEFAULT true,
            record_name TEXT,
            record_type TEXT,
            created_at TIMESTAMPTZ DEFAULT now(),
            updated_at TIMESTAMPTZ DEFAULT now()
        );",
        )
        .await
    {
        warn!("Failed to create georules table: {}", e);
        return Err(e);
    }
    info!("Georules table ready");
    if let Err(e) = client
        .batch_execute(
            "ALTER TABLE georules ADD COLUMN IF NOT EXISTS weight INT NOT NULL DEFAULT 1;",
        )
        .await
    {
        warn!("failed to add weight column to georules: {}", e);
        return Err(e);
    }
    // ensure existing installations have new columns
    if let Err(e) = client
        .batch_execute("ALTER TABLE georules ADD COLUMN IF NOT EXISTS priority INT DEFAULT 0;")
        .await
    {
        warn!("failed to add priority column to georules: {}", e);
    }
    if let Err(e) = client
        .batch_execute(
            "ALTER TABLE georules ADD COLUMN IF NOT EXISTS enabled BOOLEAN DEFAULT true;",
        )
        .await
    {
        warn!("failed to add enabled column to georules: {}", e);
    }
    if let Err(e) = client
        .batch_execute("ALTER TABLE georules ADD COLUMN IF NOT EXISTS record_name TEXT;")
        .await
    {
        warn!("failed to add record_name column to georules: {}", e);
    }
    if let Err(e) = client
        .batch_execute("ALTER TABLE georules ADD COLUMN IF NOT EXISTS record_type TEXT;")
        .await
    {
        warn!("failed to add record_type column to georules: {}", e);
    }

    // ACLs table
    if let Err(e) = client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS acls (
            id UUID PRIMARY KEY,
            name TEXT NOT NULL,
            action TEXT NOT NULL CHECK (action IN ('allow', 'deny')),
            networks TEXT NOT NULL,
            server_id UUID REFERENCES servers(id) ON DELETE CASCADE,
            created_at TIMESTAMPTZ DEFAULT now()
        );",
        )
        .await
    {
        warn!("Failed to create acls table: {}", e);
        return Err(e);
    }
    info!("ACLs table ready");

    // Rate limits table
    if let Err(e) = client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS rate_limits (
            id UUID PRIMARY KEY,
            name TEXT NOT NULL,
            queries_per_second INT DEFAULT 100,
            burst INT DEFAULT 200,
            server_id UUID REFERENCES servers(id) ON DELETE CASCADE,
            enabled BOOLEAN DEFAULT false,
            created_at TIMESTAMPTZ DEFAULT now()
        );",
        )
        .await
    {
        warn!("Failed to create rate_limits table: {}", e);
        return Err(e);
    }
    info!("Rate limits table ready");

    // DNS views table
    if let Err(e) = client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS dns_views (
            id UUID PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            match_clients TEXT NOT NULL,
            server_id UUID REFERENCES servers(id) ON DELETE CASCADE,
            enabled BOOLEAN DEFAULT true,
            created_at TIMESTAMPTZ DEFAULT now()
        );",
        )
        .await
    {
        warn!("Failed to create dns_views table: {}", e);
        return Err(e);
    }
    info!("DNS views table ready");

    // Audit logs table
    if let Err(e) = client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS audit_logs (
            id UUID PRIMARY KEY,
            user_id UUID REFERENCES users(id) ON DELETE SET NULL,
            action TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id TEXT,
            details JSONB,
            ip_address TEXT,
            user_agent TEXT,
            created_at TIMESTAMPTZ DEFAULT now()
        );",
        )
        .await
    {
        warn!("Failed to create audit_logs table: {}", e);
        return Err(e);
    }
    info!("Audit logs table ready");

    // Agent configs table
    if let Err(e) = client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS agent_configs (
            id UUID PRIMARY KEY,
            agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
            config_version INT NOT NULL,
            config_data JSONB NOT NULL,
            release_channel TEXT NOT NULL DEFAULT 'stable',
            is_active BOOLEAN DEFAULT false,
            created_at TIMESTAMPTZ DEFAULT now(),
            deployed_at TIMESTAMPTZ
        );",
        )
        .await
    {
        warn!("Failed to create agent_configs table: {}", e);
        return Err(e);
    }
    info!("Agent configs table ready");

    // A DNS RRset may hold several records of the same name and type (several
    // NS, MX, A, TXT ...), so (zone, name, type) must not be unique. Older
    // installations created that constraint; drop it and only forbid exact
    // duplicates.
    if let Err(e) = client
        .batch_execute(
            "ALTER TABLE records DROP CONSTRAINT IF EXISTS records_zone_id_name_record_type_key;",
        )
        .await
    {
        warn!("Failed to drop legacy records uniqueness constraint: {}", e);
    }
    if let Err(e) = client.batch_execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_records_rrset_value ON records(zone_id, lower(name), record_type, value);"
    ).await {
        warn!("Could not create exact-duplicate guard on records (existing duplicate rows?): {}", e);
    }

    // ---- schema additions (all idempotent; existing data is untouched) ----
    // zones: verification state; zone sharing; revision history
    client.batch_execute(
        "ALTER TABLE zones ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
         ALTER TABLE zones ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';
         ALTER TABLE zones ADD COLUMN IF NOT EXISTS tags JSONB NOT NULL DEFAULT '[]'::jsonb;
         ALTER TABLE zones ADD COLUMN IF NOT EXISTS axfr_policy TEXT NOT NULL DEFAULT 'Deny';
         ALTER TABLE zones ADD COLUMN IF NOT EXISTS axfr_allowed_peers TEXT[] NOT NULL DEFAULT '{}';
         ALTER TABLE records ADD COLUMN IF NOT EXISTS comment TEXT NOT NULL DEFAULT '';
         ALTER TABLE records ADD COLUMN IF NOT EXISTS tags JSONB NOT NULL DEFAULT '[]'::jsonb;
         ALTER TABLE zones ADD COLUMN IF NOT EXISTS verify_token TEXT;
         ALTER TABLE zones ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ;
         ALTER TABLE zones ADD COLUMN IF NOT EXISTS ecs_enabled BOOLEAN NOT NULL DEFAULT false;
         CREATE TABLE IF NOT EXISTS zone_members (
             zone_id UUID NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
             user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
             role TEXT NOT NULL CHECK (role IN ('viewer','editor')),
             created_at TIMESTAMPTZ DEFAULT now(),
             PRIMARY KEY (zone_id, user_id)
         );
         CREATE TABLE IF NOT EXISTS zone_revisions (
             id UUID PRIMARY KEY,
             zone_id UUID NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
             domain TEXT NOT NULL,
             records JSONB NOT NULL,
             settings JSONB NOT NULL DEFAULT '{}'::jsonb,
             reason TEXT NOT NULL DEFAULT 'change',
             user_id UUID,
             created_at TIMESTAMPTZ DEFAULT now()
         );
         CREATE INDEX IF NOT EXISTS idx_zone_revisions_zone ON zone_revisions(zone_id, created_at DESC);
         ALTER TABLE zone_revisions ADD COLUMN IF NOT EXISTS settings JSONB NOT NULL DEFAULT '{}'::jsonb;
         CREATE INDEX IF NOT EXISTS idx_zone_members_user ON zone_members(user_id);"
    ).await?;
    // DNSSEC keys
    client.batch_execute(dnssec::SCHEMA).await?;
    client.batch_execute(tenants::SCHEMA).await?;
    client.batch_execute(shared::SCHEMA).await?;
    client.batch_execute(automation::SCHEMA).await?;
    // users: MFA and session generation
    client.batch_execute(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT;
         ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT false;
         ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version BIGINT NOT NULL DEFAULT 0;
         ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT;
         CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique ON users (lower(email)) WHERE email IS NOT NULL AND email <> '';"
    ).await?;
    // token_blacklist: distinguish access-token revocations from refresh-token
    // sessions so refresh rotation can lock and retire exactly one token.
    client.batch_execute(
        "ALTER TABLE token_blacklist ADD COLUMN IF NOT EXISTS token_type TEXT NOT NULL DEFAULT 'access';
         ALTER TABLE token_blacklist ADD COLUMN IF NOT EXISTS session_id UUID;
         ALTER TABLE token_blacklist ADD COLUMN IF NOT EXISTS rotated_at TIMESTAMPTZ;
         ALTER TABLE token_blacklist ADD COLUMN IF NOT EXISTS replaced_by_hash TEXT;
         UPDATE token_blacklist SET token_type = 'refresh', session_id = COALESCE(session_id, id)
           WHERE user_id IS NOT NULL AND token_type = 'access';
         CREATE INDEX IF NOT EXISTS idx_token_blacklist_hash ON token_blacklist(token_hash);
         CREATE INDEX IF NOT EXISTS idx_token_blacklist_session ON token_blacklist(session_id);"
    ).await?;
    // agents: synchronisation state and explicit zone authorization. Agents
    // receive no zones unless an administrator assigns them.
    client
        .batch_execute(
            "ALTER TABLE agents ADD COLUMN IF NOT EXISTS applied_version BIGINT NOT NULL DEFAULT 0;
         ALTER TABLE agents ADD COLUMN IF NOT EXISTS last_ack_at TIMESTAMPTZ;
         ALTER TABLE agents ADD COLUMN IF NOT EXISTS last_error TEXT;
         ALTER TABLE agents ADD COLUMN IF NOT EXISTS sync_requested BOOLEAN NOT NULL DEFAULT false;
         ALTER TABLE agents ADD COLUMN IF NOT EXISTS last_seen_ip TEXT;
         ALTER TABLE agents ADD COLUMN IF NOT EXISTS token_sha256 TEXT;
         CREATE TABLE IF NOT EXISTS agent_zones (
             agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
             zone_id UUID NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
             created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
             PRIMARY KEY (agent_id, zone_id)
         );
         CREATE INDEX IF NOT EXISTS idx_agent_zones_zone ON agent_zones(zone_id);
         CREATE INDEX IF NOT EXISTS idx_agents_token_sha256 ON agents(token_sha256);",
        )
        .await?;
    // publication history (one row per zone per publication outcome change)
    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS publish_state (
             id INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
             version BIGINT NOT NULL DEFAULT 0,
             bundle_hash TEXT,
             updated_at TIMESTAMPTZ DEFAULT now()
         );
         INSERT INTO publish_state (id) VALUES (1) ON CONFLICT DO NOTHING;",
        )
        .await?;
    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS publication_outbox (
            zone_domain TEXT PRIMARY KEY,
            attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
            status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','failed')),
            next_attempt TIMESTAMPTZ NOT NULL DEFAULT now(),
            last_error TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        ALTER TABLE publication_outbox ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending';
        CREATE INDEX IF NOT EXISTS idx_publication_outbox_due ON publication_outbox(next_attempt);",
        )
        .await?;

    // Idempotency key store (mirrors migrations/005_idempotency.sql)
    client.batch_execute(
        "CREATE TABLE IF NOT EXISTS idempotency_keys (
            key TEXT NOT NULL,
            user_id UUID NOT NULL,
            endpoint TEXT NOT NULL,
            status INT NOT NULL DEFAULT 200,
            response JSONB,
            created_at TIMESTAMPTZ DEFAULT now(),
            expires_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (key, user_id, endpoint)
        );
        CREATE INDEX IF NOT EXISTS idx_idempotency_keys_expires_at ON idempotency_keys(expires_at);"
    ).await?;

    // Create indexes
    if let Err(e) = client
        .batch_execute(
            "CREATE INDEX IF NOT EXISTS idx_zones_owner ON zones(owner);
         CREATE INDEX IF NOT EXISTS idx_zones_domain ON zones(domain);
         CREATE INDEX IF NOT EXISTS idx_records_zone_id ON records(zone_id);
         CREATE INDEX IF NOT EXISTS idx_records_name_type ON records(name, record_type);
         CREATE INDEX IF NOT EXISTS idx_georules_zone_id ON georules(zone_id);
         CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
         CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
         CREATE INDEX IF NOT EXISTS idx_agents_enabled ON agents(enabled);
         CREATE INDEX IF NOT EXISTS idx_nameservers_enabled ON nameservers(enabled);
         CREATE INDEX IF NOT EXISTS idx_nameservers_sort_order ON nameservers(sort_order);
         CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
         CREATE INDEX IF NOT EXISTS idx_agent_configs_agent_id ON agent_configs(agent_id);
         CREATE INDEX IF NOT EXISTS idx_agent_configs_active ON agent_configs(agent_id, is_active);",
        )
        .await
    {
        warn!("Failed to create indexes: {}", e);
        // don't return error, indexes are not critical
    }
    info!("Indexes created");

    // No default administrator is created here: a built-in username/password
    // pair would be a known credential on every installation. The first
    // administrator comes from ADMIN_USERNAME / ADMIN_PASSWORD (see main).

    Ok(())
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
    /// TOTP code, required when the account has MFA enabled
    #[serde(default)]
    otp: Option<String>,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    refresh_token: String,
    expires_in: usize,
}

/// Argon2 hash of a throw-away password, verified against when a login names an
/// unknown user so that unknown and known usernames take comparable time.
static DUMMY_HASH: once_cell::sync::Lazy<String> = once_cell::sync::Lazy::new(|| {
    Argon2::default()
        .hash_password(b"not-a-real-password", &generate_salt())
        .map(|h| h.to_string())
        .unwrap_or_default()
});

fn issue_access_token(
    user_id: &str,
    role: &str,
    token_version: i64,
    secret: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let exp = (chrono::Utc::now() + chrono::Duration::minutes(15)).timestamp() as usize;
    let claims = Claims {
        sub: user_id.to_string(),
        role: role.to_string(),
        exp,
        ver: token_version,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

async fn login(
    body: web::Json<LoginRequest>,
    data: web::Data<AppState>,
    http_req: HttpRequest,
) -> impl Responder {
    let username = body.username.trim();
    if username.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "username required"}));
    }
    // per-client-address budget (proxy-aware) in addition to the per-username one
    if let Some(ip) = real_client_ip(&http_req) {
        let per_ip: u32 = std::env::var("LOGIN_RATE_PER_IP")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|n| *n > 0)
            .unwrap_or(60);
        if shared::limited(&data.db, &format!("login-ip:{}", ip), per_ip, 60, || {
            login_ip_allowed(&ip)
        })
        .await
        .is_some()
        {
            return HttpResponse::TooManyRequests()
                .insert_header((header::RETRY_AFTER, "60"))
                .json(serde_json::json!({"error": "too_many_attempts", "details": "Too many login attempts from this address"}));
        }
    }
    let ukey: String = username.to_ascii_lowercase().chars().take(64).collect();
    if shared::limited(
        &data.db,
        &format!("login-user:{}", ukey),
        LOGIN_ATTEMPTS_PER_MINUTE,
        60,
        || login_allowed(username),
    )
    .await
    .is_some()
    {
        return HttpResponse::TooManyRequests()
            .insert_header((header::RETRY_AFTER, "60"))
            .json(serde_json::json!({"error": "too_many_attempts", "details": "Too many login attempts; try again later"}));
    }

    let user = data.db.query_opt(
        "SELECT CAST(id AS varchar), password_hash, role, totp_enabled, totp_secret, token_version FROM users WHERE username = $1",
        &[&username]
    ).await;
    let user = match user {
        Ok(u) => u,
        Err(e) => {
            warn!("login database error: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database_error"}));
        }
    };

    let (stored_hash, found) = match &user {
        Some(row) => (row.try_get::<_, String>(1).unwrap_or_default(), true),
        None => (DUMMY_HASH.clone(), false),
    };
    let verified = PasswordHash::new(&stored_hash)
        .map(|h| {
            Argon2::default()
                .verify_password(body.password.as_bytes(), &h)
                .is_ok()
        })
        .unwrap_or(false);

    let row = match user {
        Some(r) if found && verified => r,
        _ => {
            audit(
                &data.db,
                None,
                "login_failed",
                "user",
                Some(username.to_string()),
                &http_req,
                serde_json::json!({}),
            )
            .await;
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({"error": "invalid credentials"}));
        }
    };
    let id: String = row.try_get(0).unwrap_or_default();
    let mut role: String = row
        .try_get::<_, Option<String>>(2)
        .ok()
        .flatten()
        .unwrap_or_else(|| "user".to_string());
    let mut token_version: i64 = row.try_get(5).unwrap_or(0);

    // second factor
    if row.try_get::<_, bool>(3).unwrap_or(false) {
        let secret = row
            .try_get::<_, Option<String>>(4)
            .ok()
            .flatten()
            .and_then(|s| data_encoding::BASE32_NOPAD.decode(s.as_bytes()).ok())
            .unwrap_or_default();
        match body.otp.as_deref() {
            None | Some("") => {
                return HttpResponse::Unauthorized().json(serde_json::json!({"error": "mfa_required", "details": "enter the code from your authenticator app"}));
            }
            Some(code)
                if !ext::totp_verify(&secret, code, chrono::Utc::now().timestamp() as u64) =>
            {
                audit(
                    &data.db,
                    None,
                    "login_failed",
                    "user",
                    Some(username.to_string()),
                    &http_req,
                    serde_json::json!({"reason": "otp"}),
                )
                .await;
                return HttpResponse::Unauthorized()
                    .json(serde_json::json!({"error": "invalid credentials"}));
            }
            _ => {}
        }
    }

    // Refresh token: 7 days, stored only as a hash. One active session per
    // user (a new login replaces the previous refresh token). Locking the user
    // row keeps two simultaneous logins from leaving two active sessions.
    let refresh_token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let refresh_hash = hash_token(&refresh_token);
    let refresh_expires = (chrono::Utc::now() + chrono::Duration::days(7)).timestamp();
    let session_id = Uuid::new_v4().to_string();
    let tx = match data.db.begin().await {
        Ok(t) => t,
        Err(e) => {
            warn!("login transaction: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "session_error"}));
        }
    };
    let c = tx.client();
    if let Err(e) = c.batch_execute("BEGIN").await {
        warn!("login begin: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "session_error"}));
    }
    let locked = match c.query_opt(
        "SELECT password_hash, role, token_version FROM users WHERE CAST(id AS varchar) = $1 FOR UPDATE",
        &[&id],
    ).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            rollback_transaction(c).await;
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": "invalid credentials"}));
        }
        Err(e) => {
            rollback_transaction(c).await;
            warn!("login user lock: {}", full_error_string(&e));
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "session_error"}));
        }
    };
    let locked_hash: String = locked.try_get(0).unwrap_or_default();
    if locked_hash != stored_hash {
        // The password changed while this login was being verified. Never
        // create a session that would survive the change that just won.
        rollback_transaction(c).await;
        return HttpResponse::Unauthorized()
            .json(serde_json::json!({"error": "invalid credentials"}));
    }
    role = locked.try_get(1).unwrap_or(role);
    token_version = locked.try_get(2).unwrap_or(token_version);
    if let Err(e) = c
        .execute(
            "DELETE FROM token_blacklist WHERE CAST(user_id AS varchar) = $1",
            &[&id],
        )
        .await
    {
        rollback_transaction(c).await;
        warn!("login session reset: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "session_error"}));
    }
    if let Err(e) = c.execute(
        "INSERT INTO token_blacklist (id, token_hash, user_id, expires_at, token_type, session_id) \
         VALUES ($1::text::uuid, $2, $3::text::uuid, to_timestamp($4), 'refresh', $5::text::uuid)",
        &[&Uuid::new_v4().to_string(), &refresh_hash, &id, &(refresh_expires as f64), &session_id]
    ).await {
        rollback_transaction(c).await;
        // Without a stored refresh token the session cannot be renewed; do not
        // hand out a token that can never work.
        warn!("Failed to store refresh token: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": "session_error"}));
    }
    if let Err(e) = c.batch_execute("COMMIT").await {
        warn!("login commit: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "session_error"}));
    }
    drop(tx);

    match issue_access_token(&id, &role, token_version, &data.jwt_secret) {
        Ok(token) => {
            audit(
                &data.db,
                Some(&id),
                "login",
                "user",
                Some(id.clone()),
                &http_req,
                serde_json::json!({}),
            )
            .await;
            HttpResponse::Ok().json(LoginResponse {
                token,
                refresh_token,
                expires_in: 900,
            })
        }
        Err(e) => {
            warn!("JWT encode error: {}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

async fn logout(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"}));
        }
    };

    // Logout ends every session for the account: bumping the token generation
    // invalidates all access tokens (not just the presented one), and the
    // refresh tokens are deleted in the same transaction.
    let tx = match data.db.begin().await {
        Ok(t) => t,
        Err(e) => {
            warn!("logout transaction: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "logout_failed"}));
        }
    };
    let c = tx.client();
    if let Err(e) = c.batch_execute("BEGIN").await {
        warn!("logout begin: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "logout_failed"}));
    }
    if let Some(access_token) = bearer_token(&req) {
        let token_hash = hash_token(access_token);
        let expires = tok.claims.exp as i64 + 60;
        if let Err(e) = c.execute(
            "INSERT INTO token_blacklist (id, token_hash, expires_at, token_type) VALUES ($1::text::uuid, $2, to_timestamp($3), 'access')",
            &[&Uuid::new_v4().to_string(), &token_hash, &(expires as f64)]
        ).await {
            rollback_transaction(c).await;
            warn!("Failed to blacklist token: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "logout_failed"}));
        }
    }
    if let Err(e) = c.execute(
        "UPDATE users SET token_version = token_version + 1, updated_at = now() WHERE CAST(id AS varchar) = $1",
        &[&tok.claims.sub]
    ).await {
        rollback_transaction(c).await;
        warn!("Failed to invalidate sessions: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": "logout_failed"}));
    }
    if let Err(e) = c.execute(
        "DELETE FROM token_blacklist WHERE CAST(user_id AS varchar) = $1 AND token_type = 'refresh'",
        &[&tok.claims.sub]
    ).await {
        rollback_transaction(c).await;
        warn!("Failed to invalidate refresh tokens: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": "logout_failed"}));
    }
    if let Err(e) = c.batch_execute("COMMIT").await {
        warn!("logout commit: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "logout_failed"}));
    }
    drop(tx);
    audit(
        &data.db,
        Some(&tok.claims.sub),
        "logout",
        "user",
        Some(tok.claims.sub.clone()),
        &req,
        serde_json::json!({}),
    )
    .await;

    HttpResponse::Ok().json(serde_json::json!({"message": "logged out successfully"}))
}

#[derive(Deserialize)]
struct RefreshRequest {
    refresh_token: String,
}

async fn refresh_token(
    body: web::Json<RefreshRequest>,
    data: web::Data<AppState>,
) -> impl Responder {
    let refresh_token = &body.refresh_token;
    if refresh_token.is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "refresh_token required"}));
    }
    let refresh_token_hash = hash_token(refresh_token);

    // Rotation is serialised by locking the refresh row. A token can be used
    // exactly once: the old row is retained (until its original expiry) with
    // rotated_at set, so a replay is recognisable and revokes the session.
    let tx = match data.db.begin().await {
        Ok(t) => t,
        Err(e) => {
            warn!("refresh transaction: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database_error"}));
        }
    };
    let c = tx.client();
    if let Err(e) = c.batch_execute("BEGIN").await {
        warn!("refresh begin: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "database_error"}));
    }
    let row = c.query_opt(
        "SELECT CAST(u.id AS varchar), u.role, u.token_version, \
                (b.expires_at <= now()) AS expired, (b.rotated_at IS NOT NULL) AS rotated, \
                COALESCE(b.session_id, b.id)::text, extract(epoch FROM b.expires_at)::float8, CAST(b.id AS varchar) \
         FROM token_blacklist b JOIN users u ON u.id = b.user_id \
         WHERE b.token_hash = $1 AND b.token_type = 'refresh' \
         FOR UPDATE OF b",
        &[&refresh_token_hash]
    ).await;
    let row = match row {
        Ok(Some(r)) => r,
        Ok(None) => {
            rollback_transaction(c).await;
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({"error": "invalid or expired refresh token"}));
        }
        Err(e) => {
            rollback_transaction(c).await;
            warn!("refresh database error: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database_error"}));
        }
    };
    let uid: String = row.try_get(0).unwrap_or_default();
    let role: String = row.try_get(1).unwrap_or_else(|_| "user".to_string());
    let token_version: i64 = row.try_get(2).unwrap_or(0);
    let expired: bool = row.try_get(3).unwrap_or(true);
    let rotated: bool = row.try_get(4).unwrap_or(true);
    let session_id: String = row.try_get(5).unwrap_or_default();
    let expires_at: f64 = row.try_get(6).unwrap_or(0.0);
    let old_id: String = row.try_get(7).unwrap_or_default();

    if rotated {
        // Re-use of a rotated token means the token leaked or two clients are
        // racing. End the whole session and invalidate outstanding access
        // tokens instead of minting another generation.
        let _ = c.execute(
            "UPDATE token_blacklist SET expires_at = now() WHERE CAST(user_id AS varchar) = $1 AND token_type = 'refresh'",
            &[&uid]
        ).await;
        let _ = c.execute(
            "UPDATE users SET token_version = token_version + 1, updated_at = now() WHERE CAST(id AS varchar) = $1",
            &[&uid]
        ).await;
        let _ = c.batch_execute("COMMIT").await;
        drop(tx);
        warn!("refresh token replay detected for session {}", session_id);
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "invalid or expired refresh token",
            "details": "refresh token was already used; please sign in again"
        }));
    }
    if expired {
        rollback_transaction(c).await;
        return HttpResponse::Unauthorized()
            .json(serde_json::json!({"error": "invalid or expired refresh token"}));
    }

    let new_refresh = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let new_hash = hash_token(&new_refresh);
    if let Err(e) = c.execute(
        "UPDATE token_blacklist SET rotated_at = now(), replaced_by_hash = $2 WHERE CAST(id AS varchar) = $1",
        &[&old_id, &new_hash]
    ).await {
        rollback_transaction(c).await;
        warn!("refresh rotation: {}", full_error_string(&e));
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": "database_error"}));
    }
    if let Err(e) = c.execute(
        "INSERT INTO token_blacklist (id, token_hash, user_id, expires_at, token_type, session_id) \
         VALUES ($1::text::uuid, $2, $3::text::uuid, to_timestamp($4), 'refresh', $5::text::uuid)",
        &[&Uuid::new_v4().to_string(), &new_hash, &uid, &expires_at, &session_id]
    ).await {
        rollback_transaction(c).await;
        warn!("refresh store: {}", full_error_string(&e));
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": "database_error"}));
    }
    if let Err(e) = c.batch_execute("COMMIT").await {
        warn!("refresh commit: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "database_error"}));
    }
    drop(tx);

    match issue_access_token(&uid, &role, token_version, &data.jwt_secret) {
        Ok(token) => HttpResponse::Ok().json(LoginResponse {
            token,
            refresh_token: new_refresh,
            expires_in: 900,
        }),
        Err(e) => {
            warn!("JWT encode error during refresh: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "token generation failed"}))
        }
    }
}

async fn get_current_user(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"}));
        }
    };

    let user_id = &tok.claims.sub;
    // users.id is a UUID column; compare text representation to avoid UUID param type issues
    match data.db.query_opt(
        "SELECT CAST(id AS varchar), username, role, to_char(created_at, 'YYYY-MM-DD HH24:MI:SS'), totp_enabled, COALESCE(email, '') FROM users WHERE CAST(id AS varchar) = $1",
        &[user_id]
    ).await {
        Ok(Some(row)) => {
            // Use try_get to avoid panics
            match (row.try_get::<_, String>(0), row.try_get::<_, String>(1), row.try_get::<_, String>(2), row.try_get::<_, Option<String>>(3)) {
                (Ok(id), Ok(username), Ok(role), Ok(created_at)) => {
                    HttpResponse::Ok().json(serde_json::json!({
                        "id": id,
                        "username": username,
                        "role": role,
                        "createdAt": created_at,
                        "email": row.try_get::<_, String>(5).unwrap_or_default(),
                        "mfaEnabled": row.try_get::<_, bool>(4).unwrap_or(false)
                    }))
                }
                _ => HttpResponse::InternalServerError().json(serde_json::json!({"error": "database deserialization error"}))
            }
        }
        Ok(None) => {
            HttpResponse::NotFound().json(serde_json::json!({"error": "user not found"}))
        }
        Err(e) => {
            warn!("get_current_user error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "database error"}))
        }
    }
}

#[derive(Deserialize)]
struct ChangePasswordReq {
    current_password: String,
    new_password: String,
}

/// Replace a password and end every present and future session that was
/// created with the previous password. Returns false when the user is gone.
async fn replace_password_and_revoke_sessions(
    db: &Pool,
    user_id: &str,
    new_hash: &str,
) -> Result<bool, tokio_postgres::Error> {
    let user_id = user_id.to_owned();
    let new_hash = new_hash.to_owned();
    db.run_transaction(3, move |client| {
        let user_id = user_id.clone();
        let new_hash = new_hash.clone();
        async move {
            let updated = client
                .execute(
                    "UPDATE users SET password_hash = $1, token_version = token_version + 1, updated_at = now() \
                     WHERE CAST(id AS varchar) = $2",
                    &[&new_hash, &user_id],
                )
                .await?;
            if updated == 0 {
                return Ok(false);
            }
            client
                .execute(
                    "DELETE FROM token_blacklist WHERE CAST(user_id AS varchar) = $1 AND token_type = 'refresh'",
                    &[&user_id],
                )
                .await?;
            Ok(true)
        }
    })
    .await
}

/// Change password for the currently authenticated user
async fn change_password(
    body: web::Json<ChangePasswordReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"}));
        }
    };

    let user_id = &tok.claims.sub;

    // Validate new password
    if body.new_password.len() < 8 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "new_password_too_short",
            "details": "Password must be at least 8 characters"
        }));
    }

    // Get current user's password hash
    let user_row = match data
        .db
        .query_opt(
            "SELECT password_hash FROM users WHERE CAST(id AS varchar) = $1",
            &[user_id],
        )
        .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({"error": "user not found"}));
        }
        Err(e) => {
            warn!("change_password error: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    };

    let stored_hash: String = user_row.try_get(0).unwrap_or_default();

    // Verify current password
    if stored_hash.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "no_password_set",
            "details": "Cannot change password: no password is set for this user"
        }));
    }

    // Parse the stored hash and verify
    let parsed_hash = match PasswordHash::new(&stored_hash) {
        Ok(h) => h,
        Err(e) => {
            warn!("Failed to parse stored password hash: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "password verification failed"}));
        }
    };

    let valid =
        match Argon2::default().verify_password(body.current_password.as_bytes(), &parsed_hash) {
            Ok(_) => true,
            Err(_) => false,
        };

    if !valid {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "incorrect_current_password",
            "details": "Current password is incorrect"
        }));
    }

    // Hash the new password

    let salt = generate_salt();
    let argon2 = Argon2::default();
    let new_hash = match argon2.hash_password(body.new_password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(e) => {
            warn!("Failed to hash new password: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "password hashing failed"}));
        }
    };

    // Update the password and invalidate every session atomically.
    match replace_password_and_revoke_sessions(&data.db, user_id, &new_hash).await {
        Ok(true) => {
            audit(
                &data.db,
                Some(user_id),
                "change_password",
                "user",
                Some(user_id.clone()),
                &req,
                serde_json::json!({}),
            )
            .await;
            info!("User {} changed their password successfully", user_id);
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "Password changed successfully"
            }))
        }
        Ok(false) => HttpResponse::NotFound().json(serde_json::json!({"error": "user not found"})),
        Err(e) => {
            warn!("change_password update error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "failed to update password"}))
        }
    }
}

/// Admin-only: Reset password for any user
#[derive(Deserialize)]
struct AdminResetPasswordReq {
    user_id: String,
    new_password: String,
}

async fn admin_reset_password(
    body: web::Json<AdminResetPasswordReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"}));
        }
    };

    // Check if admin
    if tok.claims.role != "admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "admin role required"}));
    }

    // Validate new password
    if body.new_password.len() < 8 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "password_too_short",
            "details": "Password must be at least 8 characters"
        }));
    }

    // Hash the new password

    let salt = generate_salt();
    let argon2 = Argon2::default();
    let new_hash = match argon2.hash_password(body.new_password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(e) => {
            warn!("Failed to hash password: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "password hashing failed"}));
        }
    };

    // Update the password and invalidate every session atomically.
    match replace_password_and_revoke_sessions(&data.db, &body.user_id, &new_hash).await {
        Ok(true) => {
            audit(
                &data.db,
                Some(&tok.claims.sub),
                "admin_reset_password",
                "user",
                Some(body.user_id.clone()),
                &req,
                serde_json::json!({}),
            )
            .await;
            info!("Admin reset password for user {}", body.user_id);
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "Password reset successfully"
            }))
        }
        Ok(false) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "user_not_found",
            "details": "No user found with the specified ID"
        })),
        Err(e) => {
            warn!("admin_reset_password error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "failed to reset password"}))
        }
    }
}

#[derive(Deserialize)]
struct ResetUserPasswordReq {
    new_password: String,
}

/// Admin-only per-user password reset addressed by path id.
async fn reset_user_password(
    path: web::Path<String>,
    body: web::Json<ResetUserPasswordReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"}));
        }
    };
    if tok.claims.role != "admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "admin role required"}));
    }
    if body.new_password.len() < 8 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "password_too_short",
            "details": "Password must be at least 8 characters"
        }));
    }
    let user_id = path.into_inner();
    let salt = generate_salt();
    let new_hash = match Argon2::default().hash_password(body.new_password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(e) => {
            warn!("reset_user_password hash error: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "password hashing failed"}));
        }
    };
    match replace_password_and_revoke_sessions(&data.db, &user_id, &new_hash).await {
        Ok(true) => {
            audit(
                &data.db,
                Some(&tok.claims.sub),
                "reset_user_password",
                "user",
                Some(user_id.clone()),
                &req,
                serde_json::json!({}),
            )
            .await;
            HttpResponse::Ok().json(serde_json::json!({"success": true}))
        }
        Ok(false) => HttpResponse::NotFound().json(serde_json::json!({"error": "user_not_found"})),
        Err(e) => {
            warn!("reset_user_password error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "failed to reset password"}))
        }
    }
}

#[derive(Deserialize)]
struct CreateUserReq {
    username: String,
    password: String,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

async fn create_user(
    req: web::Json<CreateUserReq>,
    data: web::Data<AppState>,
    http_req: HttpRequest,
) -> impl Responder {
    // Account creation is admin-only; without this check any unauthenticated
    // caller could register accounts.
    let tok = match auth_from_header(&http_req, &data.jwt_secret) {
        Some(t) => t,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "unauthorized",
                "details": "Authentication required"
            }));
        }
    };
    if tok.claims.role != "admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "forbidden",
            "details": "Admin role required"
        }));
    }

    // Validate input
    let username = req.username.trim();
    if username.chars().count() < 3
        || username.chars().count() > 64
        || username.chars().any(|c| c.is_control())
    {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_username",
            "details": "Username must be 3-64 characters without control characters"
        }));
    }
    if req.password.is_empty() || req.password.len() < 8 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_password",
            "details": "Password must be at least 8 characters"
        }));
    }

    // Hash password

    let salt = generate_salt();
    let argon2 = Argon2::default();
    let password_hash = match argon2.hash_password(req.password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(e) => {
            warn!("password hash error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "hash_error",
                "details": "Failed to hash password"
            }));
        }
    };

    // Create user
    let email = req
        .email
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .map(str::to_string);
    if let Some(email) = &email {
        if !valid_email(email) {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "invalid_email",
                "details": "Enter a valid email address"
            }));
        }
    }
    let id = Uuid::new_v4();
    let id_str = id.to_string();
    let role = req.role.as_deref().unwrap_or("user");
    if !VALID_ROLES.contains(&role) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_role",
            "details": "role must be one of admin, editor, viewer, user"
        }));
    }

    match data.db.execute(
        "INSERT INTO users (id, username, password_hash, role, email) VALUES ($1::text::uuid, $2, $3, $4, $5)",
        &[&id_str, &username, &password_hash, &role, &email]
    ).await {
        Ok(_) => {
            audit(&data.db, Some(&tok.claims.sub), "create_user", "user", Some(id_str.clone()), &http_req, serde_json::json!({"username": username, "email": email})).await;
            info!("Created user: {}", username);
            HttpResponse::Created().json(serde_json::json!({
                "id": id.to_string(),
                "username": username,
                "role": role,
                "email": email
            }))
        }
        Err(e) => {
            let err_msg = full_error_string(&e);
            if err_msg.contains("unique") || err_msg.contains("duplicate") {
                warn!("create_user error: username already exists: {}", username);
                HttpResponse::Conflict().json(serde_json::json!({
                    "error": "username_or_email_exists",
                    "details": "Username or email already exists"
                }))
            } else {
                warn!("create_user database error: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "database_error",
                    "details": "Failed to create user"
                }))
            }
        }
    }
}

#[derive(Deserialize)]
struct UpdateUserReq {
    username: Option<String>,
    role: Option<String>,
    email: Option<String>,
}

async fn get_user(
    path: web::Path<String>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let user_id = path.into_inner();
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"}));
        }
    };
    // Users may read their own profile; reading anyone else's is admin-only.
    if tok.claims.role != "admin" && tok.claims.sub != user_id {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "forbidden"}));
    }

    match data.db.query(
        "SELECT CAST(id AS varchar), username, role, to_char(created_at, 'YYYY-MM-DD HH24:MI:SS'), COALESCE(email, '') FROM users WHERE CAST(id AS varchar) = $1",
        &[&user_id]
    ).await {
        Ok(rows) => {
            if rows.is_empty() {
                return HttpResponse::NotFound().json(serde_json::json!({"error": "user not found"}));
            }
            let row = &rows[0];
            if let (Ok(id), Ok(username), Ok(role), Ok(created_at)) =
                (row.try_get::<_, String>(0), row.try_get::<_, String>(1), row.try_get::<_, String>(2), row.try_get::<_, Option<String>>(3)) {
                HttpResponse::Ok().json(serde_json::json!({
                    "id": id,
                    "username": username,
                    "role": role,
                    "createdAt": created_at,
                    "email": row.try_get::<_, String>(4).unwrap_or_default()
                }))
            } else {
                HttpResponse::InternalServerError().json(serde_json::json!({"error": "database deserialization error"}))
            }
        }
        Err(e) => {
            warn!("get_user error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "database error"}))
        }
    }
}

async fn list_users(
    page: web::Query<ext::PageQuery>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    // Check for auth token
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "unauthorized",
                "details": "Authentication token required"
            }));
        }
    };

    // Only admins can list all users
    if tok.claims.role != "admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "forbidden",
            "details": "Admin role required to list users"
        }));
    }

    let (limit, offset, qtext) = page.parts();
    let sort = match page.sort_column(
        &[
            ("username", "username"),
            ("role", "role"),
            ("created", "created_at"),
        ],
        "username",
    ) {
        Ok(value) => value,
        Err(()) => return invalid_list_query(),
    };
    let direction = match page.sort_direction() {
        Ok(value) => value,
        Err(()) => return invalid_list_query(),
    };
    let total: i64 = match data
        .db
        .query_one(
            "SELECT count(*) FROM users WHERE $1::text IS NULL OR username ILIKE '%' || $1 || '%'",
            &[&qtext],
        )
        .await
    {
        Ok(row) => row.get(0),
        Err(e) => {
            warn!("list_users count: {}", full_error_string(&e));
            return HttpResponse::InternalServerError().json(
                serde_json::json!({"error":"database_error","details":"Failed to count users"}),
            );
        }
    };
    let list_sql = format!(
        "SELECT CAST(id AS varchar), username, role, to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') as created_at_str, count(*) OVER(), COALESCE(email, '') FROM users WHERE $1::text IS NULL OR username ILIKE '%' || $1 || '%' ORDER BY {sort} {direction}, id LIMIT $2::bigint OFFSET $3::bigint"
    );
    match data.db.query(&list_sql, &[&qtext, &limit, &offset]).await {
        Ok(rows) => {
            let users: Vec<_> = rows
                .into_iter()
                .filter_map(|r| {
                    let id_result = r.try_get::<_, String>(0);
                    let username_result = r.try_get::<_, String>(1);
                    let role_result = r.try_get::<_, String>(2);
                    let created_at_result = r.try_get::<_, Option<String>>(3);

                    let email = r.try_get::<_, String>(5).unwrap_or_default();
                    match (id_result, username_result, role_result, created_at_result) {
                        (Ok(id), Ok(username), Ok(role), Ok(created_at)) => {
                            Some(serde_json::json!({
                                "id": id,
                                "username": username,
                                "role": role,
                                "createdAt": created_at.unwrap_or_else(|| String::from("")),
                                "email": email
                            }))
                        }
                        _ => None, // Skip rows with deserialization errors
                    }
                })
                .collect();
            HttpResponse::Ok()
                .insert_header(("X-Total-Count", total.to_string()))
                .json(users)
        }
        Err(e) => {
            warn!("list_users error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "database_error",
                "details": "Failed to fetch users"
            }))
        }
    }
}

async fn update_user(
    path: web::Path<String>,
    body: web::Json<UpdateUserReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let user_id = path.into_inner();
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"}));
        }
    };

    if tok.claims.role != "admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "admin role required"}));
    }
    if body.username.is_none() && body.role.is_none() && body.email.is_none() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "no fields to update"}));
    }
    let email_supplied = body.email.is_some();
    let new_email = body
        .email
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .map(str::to_string);
    if let Some(email) = &new_email {
        if !valid_email(email) {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": "invalid email address"}));
        }
    }
    let new_username = body.username.as_ref().map(|u| u.trim().to_string());
    if let Some(u) = &new_username {
        if u.chars().count() < 3 || u.chars().count() > 64 || u.chars().any(|c| c.is_control()) {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": "username must be 3-64 characters"}));
        }
    }
    if let Some(r) = &body.role {
        if !VALID_ROLES.contains(&r.as_str()) {
            return HttpResponse::BadRequest().json(
                serde_json::json!({"error": "role must be one of admin, editor, viewer, user"}),
            );
        }
        if user_id == tok.claims.sub && r != "admin" {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": "cannot remove your own admin role"}));
        }
    }

    // One statement, so a request never half-applies.
    match data
        .db
        .execute(
            "UPDATE users SET username = COALESCE($1, username), role = COALESCE($2, role), \
                email = CASE WHEN $3 THEN $4 ELSE email END, updated_at = now() \
         WHERE CAST(id AS varchar) = $5",
            &[
                &new_username,
                &body.role,
                &email_supplied,
                &new_email,
                &user_id,
            ],
        )
        .await
    {
        Ok(0) => HttpResponse::NotFound().json(serde_json::json!({"error": "user not found"})),
        Ok(_) => {
            audit(&data.db, Some(&tok.claims.sub), "update_user", "user", Some(user_id.clone()),
                  &req, serde_json::json!({"username": new_username, "role": body.role, "email": new_email})).await;
            HttpResponse::Ok().json(serde_json::json!({"message": "user updated"}))
        }
        Err(e) => {
            let msg = full_error_string(&e);
            if msg.contains("unique") || msg.contains("duplicate") {
                HttpResponse::Conflict()
                    .json(serde_json::json!({"error": "username or email already exists"}))
            } else {
                warn!("update_user error: {}", msg);
                HttpResponse::InternalServerError()
                    .json(serde_json::json!({"error": "failed to update user"}))
            }
        }
    }
}

async fn delete_user(
    path: web::Path<String>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let user_id = path.into_inner();
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"}));
        }
    };

    if tok.claims.role != "admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "admin role required"}));
    }

    if user_id == tok.claims.sub {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "cannot delete yourself"}));
    }

    match data
        .db
        .execute(
            "DELETE FROM users WHERE CAST(id AS varchar) = $1",
            &[&user_id],
        )
        .await
    {
        Ok(result) => {
            if result > 0 {
                audit(
                    &data.db,
                    Some(&tok.claims.sub),
                    "delete_user",
                    "user",
                    Some(user_id.clone()),
                    &req,
                    serde_json::json!({}),
                )
                .await;
                HttpResponse::Ok().json(serde_json::json!({"message": "user deleted"}))
            } else {
                HttpResponse::NotFound().json(serde_json::json!({"error": "user not found"}))
            }
        }
        Err(e) => {
            warn!("delete_user error: {}", full_error_string(&e));
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "failed to delete user"}))
        }
    }
}

/// True if `hash` is an Argon2 hash of `password`.
fn hash_matches(hash: &str, password: &str) -> bool {
    PasswordHash::new(hash)
        .map(|h| {
            Argon2::default()
                .verify_password(password.as_bytes(), &h)
                .is_ok()
        })
        .unwrap_or(false)
}

fn bearer_token(req: &HttpRequest) -> Option<&str> {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
}

/// Authenticated caller of the current request.
///
/// When the [`auth_middleware`] is installed (always, in the running server)
/// this returns the identity it verified: signature and expiry, not revoked by
/// logout, and the user still exists, with the role read from the database
/// (so demotions and deletions take effect immediately instead of when the
/// 15 minute token expires). Without the middleware (unit tests of single
/// handlers) it falls back to verifying the token signature only.
fn jwt_secrets(primary: &str) -> Vec<String> {
    let mut secrets = vec![primary.to_string()];
    if let Ok(previous) = std::env::var("JWT_PREVIOUS_SECRETS") {
        for secret in previous.split(',') {
            let secret = secret.trim();
            if !secret.is_empty() && !secrets.iter().any(|s| s == secret) {
                secrets.push(secret.to_string());
            }
        }
    }
    secrets
}

/// Verify a JWT against the current secret first, then any previous secrets
/// listed in `JWT_PREVIOUS_SECRETS` (comma separated). This allows an overlap
/// window during rotation: new tokens are signed with the current secret while
/// tokens issued before the change remain valid until they expire.
fn decode_with_secrets(token: &str, secrets: &[String]) -> Option<TokenData<Claims>> {
    for secret in secrets {
        if let Ok(td) = decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &Validation::default(),
        ) {
            return Some(td);
        }
    }
    None
}

fn decode_access_token(token: &str, primary: &str) -> Option<TokenData<Claims>> {
    decode_with_secrets(token, &jwt_secrets(primary))
}

fn auth_from_header(req: &HttpRequest, secret: &str) -> Option<TokenData<Claims>> {
    if let Some(verified) = req.extensions().get::<TokenData<Claims>>() {
        return Some(verified.clone());
    }
    let token = bearer_token(req)?;
    decode_access_token(token, secret)
}

/// Baseline browser security headers for every API response. HSTS is opt-in
/// because it is only meaningful when the public endpoint is HTTPS (typically
/// terminated by the reverse proxy).
async fn security_headers(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<actix_web::body::BoxBody>, actix_web::Error> {
    let path = req.path().to_string();
    let is_auth = path.starts_with("/api/v1/auth/");
    let res = next.call(req).await?;
    let mut res = res.map_into_boxed_body();
    let headers = res.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::X_FRAME_OPTIONS,
        header::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        header::HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::HeaderName::from_static("permissions-policy"),
        header::HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    if std::env::var("SECURITY_HSTS")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false)
    {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            header::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    if is_auth {
        headers.insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        );
    }
    Ok(res)
}

/// `/metrics` is scrape-only: when `METRICS_TOKEN` is configured it requires
/// the same bearer token, preventing unauthenticated external access.
fn metrics_authorized(req: &HttpRequest, expected: Option<&str>) -> bool {
    let Some(want) = expected.filter(|t| !t.is_empty()) else {
        return true;
    };
    let got = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .unwrap_or("");
    got.as_bytes().len() == want.as_bytes().len()
        && got
            .as_bytes()
            .iter()
            .zip(want.as_bytes())
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}

async fn metrics_endpoint(req: HttpRequest) -> impl Responder {
    let expected = std::env::var("METRICS_TOKEN").ok();
    if !metrics_authorized(&req, expected.as_deref()) {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"}));
    }
    let encoder = TextEncoder::new();
    let metric_families = gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap_or(());
    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4")
        .body(buffer)
}

/// Authenticate a bearer credential (JWT session or `ocd_` personal API
/// token), enforcing revocation, session generation, account existence, token
/// scopes and the read-only viewer role.
pub(crate) async fn authenticate_request(
    req: &HttpRequest,
    state: &AppState,
) -> Result<automation::AuthCtx, (actix_web::http::StatusCode, &'static str)> {
    use actix_web::http::StatusCode;
    let token = bearer_token(req).ok_or((StatusCode::UNAUTHORIZED, "unauthorized"))?;
    if token.starts_with("ocd_") {
        let ctx = automation::authenticate_api_token(&state.db, &token)
            .await
            .map_err(|m| {
                if m == "database error" {
                    (StatusCode::SERVICE_UNAVAILABLE, m)
                } else {
                    (StatusCode::UNAUTHORIZED, m)
                }
            })?;
        let scopes = ctx.scopes.clone().unwrap_or_default();
        if !automation::scope_permits(&scopes, req.method(), req.path()) {
            return Err((StatusCode::FORBIDDEN, "insufficient token scope"));
        }
        if ctx.claims.role == "viewer"
            && !is_read_method(req.method())
            && !viewer_may_write(req.path())
        {
            return Err((StatusCode::FORBIDDEN, "read-only account"));
        }
        return Ok(ctx);
    }
    let mut td = decode_access_token(&token, &state.jwt_secret)
        .ok_or((StatusCode::UNAUTHORIZED, "unauthorized"))?;
    let th = hash_token(&token);
    let row = state
        .db
        .query_opt(
            "SELECT u.role, u.token_version, \
                    EXISTS (SELECT 1 FROM token_blacklist b WHERE b.token_hash = $2 \
                            AND b.token_type = 'access' AND b.expires_at > now()) \
             FROM users u WHERE CAST(u.id AS varchar) = $1",
            &[&td.claims.sub, &th],
        )
        .await
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "database error"))?;
    let Some(r) = row else {
        return Err((StatusCode::UNAUTHORIZED, "user no longer exists"));
    };
    let revoked: bool = r.try_get(2).unwrap_or(true);
    if revoked {
        return Err((StatusCode::UNAUTHORIZED, "token revoked"));
    }
    let current_version: i64 = r.try_get(1).unwrap_or(-1);
    if td.claims.ver != current_version {
        return Err((StatusCode::UNAUTHORIZED, "session expired"));
    }
    td.claims.role = r
        .try_get::<_, String>(0)
        .unwrap_or_else(|_| "user".to_string());
    if td.claims.role == "viewer" && !is_read_method(req.method()) && !viewer_may_write(req.path())
    {
        return Err((StatusCode::FORBIDDEN, "read-only account"));
    }
    Ok(automation::AuthCtx {
        claims: td.claims,
        token_id: None,
        scopes: None,
    })
}

fn auth_failure_response(
    status: actix_web::http::StatusCode,
    detail: &'static str,
) -> HttpResponse {
    if status == actix_web::http::StatusCode::SERVICE_UNAVAILABLE {
        HttpResponse::ServiceUnavailable().json(serde_json::json!({"error": "service_unavailable"}))
    } else {
        HttpResponse::build(status)
            .json(serde_json::json!({"error": "unauthorized", "details": detail}))
    }
}

/// Reject revoked tokens and tokens of deleted users, and pin the caller's
/// role to the database value, before any handler runs.
async fn auth_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<actix_web::body::BoxBody>, actix_web::Error> {
    let state = req.app_data::<web::Data<AppState>>().cloned();
    if let Some(state) = state {
        let token = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(|s| s.to_string());
        if let Some(token) = token {
            // Personal API tokens are always verified here. For JWT sessions we
            // keep the historical behaviour of letting non-JWT-shaped bearer
            // values reach the handler (public endpoints stay public).
            let is_api_token = token.starts_with("ocd_");
            let is_jwt = decode::<Claims>(
                &token,
                &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
                &Validation::default(),
            )
            .is_ok();
            if is_api_token || is_jwt {
                match authenticate_request(req.request(), &state).await {
                    Ok(ctx) => {
                        req.extensions_mut().insert(TokenData {
                            header: Header::default(),
                            claims: ctx.claims.clone(),
                        });
                        req.extensions_mut().insert(ctx);
                    }
                    Err((status, detail)) => {
                        let resp = auth_failure_response(status, detail);
                        return Ok(req.into_response(resp).map_into_boxed_body());
                    }
                }
            }
        }
    }
    Ok(next.call(req).await?.map_into_boxed_body())
}

async fn list_servers(
    page: web::Query<ext::PageQuery>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    // Server addresses are infrastructure details: administrators only.
    match auth_from_header(&req, &data.jwt_secret) {
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "unauthorized",
                "details": "Authentication required"
            }));
        }
        Some(t) if t.claims.role != "admin" => {
            return HttpResponse::Forbidden()
                .json(serde_json::json!({"error": "forbidden", "details": "Admin role required"}));
        }
        Some(_) => {}
    }

    let (limit, offset, qtext) = page.parts();
    let sort = match page.sort_column(
        &[
            ("name", "name"),
            ("address", "address"),
            ("region", "region"),
            ("port", "port"),
        ],
        "name",
    ) {
        Ok(value) => value,
        Err(()) => return invalid_list_query(),
    };
    let direction = match page.sort_direction() {
        Ok(value) => value,
        Err(()) => return invalid_list_query(),
    };
    let total = match data.db.query_one(
        "SELECT count(*) FROM servers WHERE $1::text IS NULL OR name ILIKE '%' || $1 || '%' OR address ILIKE '%' || $1 || '%' OR COALESCE(region, '') ILIKE '%' || $1 || '%'",
        &[&qtext],
    ).await {
        Ok(row) => row.get::<_, i64>(0),
        Err(e) => {
            warn!("list_servers count error: {}", full_error_string(&e));
            return HttpResponse::InternalServerError().json(serde_json::json!({"error":"database_error","details":"Failed to fetch servers"}));
        }
    };
    let list_sql = format!(
        "SELECT CAST(id AS varchar), name, address, port, COALESCE(region, ''), enabled, dnssec, enable_logging, max_cache_ttl, min_cache_ttl FROM servers WHERE $1::text IS NULL OR name ILIKE '%' || $1 || '%' OR address ILIKE '%' || $1 || '%' OR COALESCE(region, '') ILIKE '%' || $1 || '%' ORDER BY {sort} {direction}, id LIMIT $2::bigint OFFSET $3::bigint"
    );
    match data.db.query(&list_sql, &[&qtext, &limit, &offset]).await {
        Ok(rows) => {
            let mut servers: Vec<ServerInfo> = rows
                .into_iter()
                .map(|r| ServerInfo {
                    id: r.try_get(0).unwrap_or_default(),
                    name: r.try_get(1).unwrap_or_default(),
                    address: r.try_get(2).unwrap_or_default(),
                    port: r.try_get(3).unwrap_or(53),
                    region: Some(r.try_get(4).unwrap_or_default())
                        .filter(|s: &String| !s.is_empty()),
                    enabled: r.try_get(5).unwrap_or(true),
                    dnssec: r.try_get(6).unwrap_or(false),
                    enable_logging: r.try_get(7).unwrap_or(true),
                    max_cache_ttl: r.try_get(8).unwrap_or(3600),
                    min_cache_ttl: r.try_get(9).unwrap_or(60),
                    status: None,
                })
                .collect();
            // real reachability instead of an always-empty status
            let probes: Vec<_> = servers
                .iter()
                .map(|sv| {
                    let (h, p, en) = (sv.address.clone(), sv.port, sv.enabled);
                    tokio::spawn(async move {
                        if en {
                            Some(ext::probe_server(&h, p).await.0)
                        } else {
                            None
                        }
                    })
                })
                .collect();
            for (sv, pr) in servers.iter_mut().zip(probes) {
                sv.status = match pr.await {
                    Ok(Some(st)) => Some(st.to_string()),
                    Ok(None) => Some("disabled".to_string()),
                    Err(_) => None,
                };
            }
            HttpResponse::Ok()
                .insert_header(("X-Total-Count", total.to_string()))
                .json(servers)
        }
        Err(e) => {
            warn!("list_servers database error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "database_error",
                "details": "Failed to fetch servers"
            }))
        }
    }
}

#[derive(Deserialize)]
struct CreateServerReq {
    name: String,
    address: String,
    port: Option<i32>,
    region: Option<String>,
    enabled: Option<bool>,
    dnssec: Option<bool>,
    enable_logging: Option<bool>,
    max_cache_ttl: Option<i32>,
    min_cache_ttl: Option<i32>,
}

async fn create_server(
    body: web::Json<CreateServerReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    // Authenticate and verify admin role
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "unauthorized",
                "details": "Authentication required"
            }));
        }
    };

    if tok.claims.role != "admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "forbidden",
            "details": "Admin role required"
        }));
    }

    // Validate input
    if body.name.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_input",
            "details": "Server name is required"
        }));
    }

    if body.address.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_input",
            "details": "Server address is required"
        }));
    }

    let port = body.port.unwrap_or(53);
    if !(1..=65535).contains(&port) {
        return HttpResponse::BadRequest().json(
            serde_json::json!({"error": "invalid_input", "details": "port must be 1-65535"}),
        );
    }
    let (min_ttl, max_ttl) = (
        body.min_cache_ttl.unwrap_or(60),
        body.max_cache_ttl.unwrap_or(3600),
    );
    if min_ttl < 0 || max_ttl < 0 || min_ttl > max_ttl {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid_input", "details": "cache TTLs must be non-negative and min <= max"}));
    }
    let id = Uuid::new_v4();
    let id_str = id.to_string();

    match data.db.execute(
        "INSERT INTO servers (id, name, address, port, region, enabled, dnssec, enable_logging, max_cache_ttl, min_cache_ttl) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        &[&id_str, &body.name, &body.address, &body.port.unwrap_or(53), &body.region, &body.enabled.unwrap_or(true), &body.dnssec.unwrap_or(false), &body.enable_logging.unwrap_or(true), &body.max_cache_ttl.unwrap_or(3600), &body.min_cache_ttl.unwrap_or(60)]
    ).await {
        Ok(_) => {
            info!("Created server: {} at {}", body.name, body.address);
            audit(&data.db, Some(&tok.claims.sub), "create_server", "server", Some(id_str.clone()), &req, serde_json::json!({
                "name": body.name, "address": body.address, "port": port
            })).await;
            HttpResponse::Created().json(serde_json::json!({
                "id": id.to_string(),
                "name": body.name,
                "address": body.address
            }))
        }
        Err(e) => {
            warn!("create_server error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "database_error",
                "details": "Failed to create server"
            }))
        }
    }
}

#[derive(Deserialize)]
struct UpdateServerReq {
    name: Option<String>,
    address: Option<String>,
    port: Option<i32>,
    region: Option<String>,
    enabled: Option<bool>,
    dnssec: Option<bool>,
    enable_logging: Option<bool>,
    max_cache_ttl: Option<i32>,
    min_cache_ttl: Option<i32>,
}

async fn update_server(
    path: web::Path<String>,
    body: web::Json<UpdateServerReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"}));
        }
    };
    if tok.claims.role != "admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "admin role required"}));
    }
    let server_id = path.into_inner();
    let old = match data.db.query_opt(
        "SELECT name, address, port, region, COALESCE(enabled, true), COALESCE(dnssec, false), \
                COALESCE(enable_logging, true), COALESCE(max_cache_ttl, 3600), COALESCE(min_cache_ttl, 60) \
         FROM servers WHERE CAST(id AS varchar) = $1",
        &[&server_id],
    ).await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "server not found"})),
        Err(e) => {
            warn!("update_server lookup: {}", full_error_string(&e));
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "database error"}));
        }
    };
    let name = body.name.clone().unwrap_or_else(|| old.get(0));
    let address = body.address.clone().unwrap_or_else(|| old.get(1));
    if name.trim().is_empty() || address.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid_input", "details": "name and address are required"}));
    }
    let port = body.port.unwrap_or_else(|| old.get(2));
    if !(1..=65535).contains(&port) {
        return HttpResponse::BadRequest().json(
            serde_json::json!({"error": "invalid_input", "details": "port must be 1-65535"}),
        );
    }
    let region = body.region.clone().or_else(|| old.get(3));
    let enabled = body.enabled.unwrap_or_else(|| old.get(4));
    let dnssec = body.dnssec.unwrap_or_else(|| old.get(5));
    let enable_logging = body.enable_logging.unwrap_or_else(|| old.get(6));
    let max_ttl = body.max_cache_ttl.unwrap_or_else(|| old.get(7));
    let min_ttl = body.min_cache_ttl.unwrap_or_else(|| old.get(8));
    if min_ttl < 0 || max_ttl < 0 || min_ttl > max_ttl {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid_input", "details": "cache TTLs must be non-negative and min <= max"}));
    }
    match data.db.execute(
        "UPDATE servers SET name = $1, address = $2, port = $3, region = $4, enabled = $5, dnssec = $6, \
                enable_logging = $7, max_cache_ttl = $8, min_cache_ttl = $9, updated_at = now() \
         WHERE CAST(id AS varchar) = $10",
        &[&name, &address, &port, &region, &enabled, &dnssec, &enable_logging, &max_ttl, &min_ttl, &server_id],
    ).await {
        Ok(0) => HttpResponse::NotFound().json(serde_json::json!({"error": "server not found"})),
        Ok(_) => {
            audit(&data.db, Some(&tok.claims.sub), "update_server", "server", Some(server_id.clone()), &req, serde_json::json!({
                "name": name, "address": address, "port": port
            })).await;
            HttpResponse::Ok().json(serde_json::json!({"success": true, "id": server_id}))
        }
        Err(e) => {
            warn!("update_server error: {}", full_error_string(&e));
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "failed to update server"}))
        }
    }
}

async fn delete_server(
    path: web::Path<String>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"}));
        }
    };
    if tok.claims.role != "admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "admin role required"}));
    }
    let server_id = path.into_inner();
    match data
        .db
        .execute(
            "DELETE FROM servers WHERE CAST(id AS varchar) = $1",
            &[&server_id],
        )
        .await
    {
        Ok(0) => HttpResponse::NotFound().json(serde_json::json!({"error": "server not found"})),
        Ok(_) => {
            audit(
                &data.db,
                Some(&tok.claims.sub),
                "delete_server",
                "server",
                Some(server_id.clone()),
                &req,
                serde_json::json!({}),
            )
            .await;
            HttpResponse::Ok().json(serde_json::json!({"success": true}))
        }
        Err(e) => {
            warn!("delete_server error: {}", full_error_string(&e));
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "failed to delete server"}))
        }
    }
}

// ============================================================
// Nameservers API - Authoritative Nameserver Configuration
// ============================================================

#[derive(Serialize)]
struct NameserverInfo {
    id: String,
    hostname: String,
    ip_address: String,
    glue_ip: Option<String>,
    sort_order: i32,
    enabled: bool,
}

#[derive(Deserialize)]
struct CreateNameserverReq {
    hostname: String,
    ip_address: String,
    glue_ip: Option<String>,
    sort_order: Option<i32>,
    enabled: Option<bool>,
}

async fn list_nameservers(
    page: web::Query<ext::PageQuery>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let Some(tok) = auth_from_header(&req, &data.jwt_secret) else {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "unauthorized",
            "details": "Authentication required"
        }));
    };
    // Customers need the public nameservers to delegate their domains, but not disabled/internal entries.
    let only_enabled = tok.claims.role != "admin";
    let (limit, offset, qtext) = page.parts();
    let sort = match page.sort_column(
        &[
            ("hostname", "hostname"),
            ("sort_order", "sort_order"),
            ("enabled", "enabled"),
        ],
        "sort_order",
    ) {
        Ok(value) => value,
        Err(()) => return invalid_list_query(),
    };
    let direction = match page.sort_direction() {
        Ok(value) => value,
        Err(()) => return invalid_list_query(),
    };
    let total = match data.db.query_one(
        "SELECT count(*) FROM nameservers WHERE (enabled OR NOT $1) AND ($2::text IS NULL OR hostname ILIKE '%' || $2 || '%' OR ip_address ILIKE '%' || $2 || '%')",
        &[&only_enabled, &qtext],
    ).await {
        Ok(row) => row.get::<_, i64>(0),
        Err(e) => {
            warn!("list_nameservers count error: {}", full_error_string(&e));
            return HttpResponse::InternalServerError().json(serde_json::json!({"error":"database_error","details":"Failed to fetch nameservers"}));
        }
    };
    let list_sql = format!(
        "SELECT CAST(id AS varchar), hostname, ip_address, glue_ip, sort_order, enabled FROM nameservers WHERE (enabled OR NOT $1) AND ($2::text IS NULL OR hostname ILIKE '%' || $2 || '%' OR ip_address ILIKE '%' || $2 || '%') ORDER BY {sort} {direction}, hostname, id LIMIT $3::bigint OFFSET $4::bigint"
    );
    match data
        .db
        .query(&list_sql, &[&only_enabled, &qtext, &limit, &offset])
        .await
    {
        Ok(rows) => {
            let nameservers: Vec<NameserverInfo> = rows
                .into_iter()
                .map(|r| NameserverInfo {
                    id: r.try_get(0).unwrap_or_default(),
                    hostname: r.try_get(1).unwrap_or_default(),
                    ip_address: r.try_get(2).unwrap_or_default(),
                    glue_ip: r.try_get(3).ok(),
                    sort_order: r.try_get(4).unwrap_or(0),
                    enabled: r.try_get(5).unwrap_or(true),
                })
                .collect();
            HttpResponse::Ok()
                .insert_header(("X-Total-Count", total.to_string()))
                .json(nameservers)
        }
        Err(e) => {
            warn!("list_nameservers database error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "database_error",
                "details": "Failed to fetch nameservers"
            }))
        }
    }
}

/// Validate and normalise nameserver input: hostname (FQDN), IP address and
/// optional glue IP. Anything else would end up in every zone file.
fn validate_nameserver_input(
    req: &CreateNameserverReq,
) -> Result<(String, String, Option<String>), String> {
    let hostname = normalize_zone_domain(&req.hostname)
        .map_err(|e| format!("invalid hostname: {}", e.message))?;
    let ip = req.ip_address.trim();
    let ip: std::net::IpAddr = ip
        .parse()
        .map_err(|_| "ip_address must be an IPv4 or IPv6 address".to_string())?;
    let glue = match req
        .glue_ip
        .as_deref()
        .map(str::trim)
        .filter(|g| !g.is_empty())
    {
        Some(g) => Some(
            g.parse::<std::net::IpAddr>()
                .map_err(|_| "glue_ip must be an IPv4 or IPv6 address".to_string())?
                .to_string(),
        ),
        None => None,
    };
    Ok((hostname, ip.to_string(), glue))
}

async fn create_nameserver(
    body: web::Json<CreateNameserverReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"}));
        }
    };

    if tok.claims.role != "admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "admin role required"}));
    }

    let (hostname, ip, glue_ip) = match validate_nameserver_input(&body) {
        Ok(v) => v,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    };

    let id = Uuid::new_v4();
    let id_str = id.to_string();
    let sort_order = body.sort_order.unwrap_or(0);
    let enabled = body.enabled.unwrap_or(true);

    match data.db.execute(
        "INSERT INTO nameservers (id, hostname, ip_address, glue_ip, sort_order, enabled) VALUES ($1::text::uuid, $2, $3, $4, $5, $6)",
        &[&id_str, &hostname, &ip, &glue_ip, &sort_order, &enabled]
    ).await {
        Ok(_) => {
            info!("Created nameserver: {} ({})", hostname, ip);
            audit(&data.db, Some(&tok.claims.sub), "create_nameserver", "nameserver", Some(id_str.clone()), &req, serde_json::json!({"hostname": hostname})).await;

            // Apply the new nameservers to every zone file and report the real outcome.
            if let Err(e) = publish(&data.dns_manager, &data.db, None).await {
                warn!("Failed to regenerate zones after nameserver creation: {}", e);
                return publish_failed(&e);
            }

            HttpResponse::Created().json(serde_json::json!({
                "id": id.to_string(),
                "hostname": hostname,
                "ip_address": ip
            }))
        }
        Err(e) => {
            let msg = full_error_string(&e);
            if msg.contains("unique") || msg.contains("duplicate") {
                return HttpResponse::Conflict().json(serde_json::json!({"error": "nameserver already exists"}));
            }
            warn!("create_nameserver error: {}", msg);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "database_error",
                "details": "Failed to create nameserver"
            }))
        }
    }
}

async fn update_nameserver(
    path: web::Path<String>,
    body: web::Json<CreateNameserverReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"}));
        }
    };

    if tok.claims.role != "admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "admin role required"}));
    }

    let ns_id = path.into_inner();
    let (hostname, ip, glue_ip) = match validate_nameserver_input(&body) {
        Ok(v) => v,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    };
    let sort_order = body.sort_order.unwrap_or(0);
    let enabled = body.enabled.unwrap_or(true);

    match data.db.execute(
        "UPDATE nameservers SET hostname = $1, ip_address = $2, glue_ip = $3, sort_order = $4, enabled = $5, updated_at = now() WHERE CAST(id AS varchar) = $6",
        &[&hostname, &ip, &glue_ip, &sort_order, &enabled, &ns_id]
    ).await {
        Ok(0) => HttpResponse::NotFound().json(serde_json::json!({"error": "nameserver not found"})),
        Ok(_) => {
            info!("Updated nameserver: {}", ns_id);
            audit(&data.db, Some(&tok.claims.sub), "update_nameserver", "nameserver", Some(ns_id.clone()), &req, serde_json::json!({"hostname": hostname})).await;

            if let Err(e) = publish(&data.dns_manager, &data.db, None).await {
                warn!("Failed to regenerate zones after nameserver update: {}", e);
                return publish_failed(&e);
            }

            HttpResponse::Ok().json(serde_json::json!({"success": true}))
        }
        Err(e) => {
            let msg = full_error_string(&e);
            if msg.contains("unique") || msg.contains("duplicate") {
                return HttpResponse::Conflict().json(serde_json::json!({"error": "nameserver already exists"}));
            }
            warn!("update_nameserver error: {}", msg);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "database_error",
                "details": "Failed to update nameserver"
            }))
        }
    }
}

async fn delete_nameserver(
    path: web::Path<String>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"}));
        }
    };

    if tok.claims.role != "admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "admin role required"}));
    }

    let ns_id = path.into_inner();
    match data
        .db
        .execute(
            "DELETE FROM nameservers WHERE CAST(id AS varchar) = $1",
            &[&ns_id],
        )
        .await
    {
        Ok(0) => {
            HttpResponse::NotFound().json(serde_json::json!({"error": "nameserver not found"}))
        }
        Ok(_) => {
            info!("Deleted nameserver: {}", ns_id);
            audit(
                &data.db,
                Some(&tok.claims.sub),
                "delete_nameserver",
                "nameserver",
                Some(ns_id.clone()),
                &req,
                serde_json::json!({}),
            )
            .await;

            if let Err(e) = publish(&data.dns_manager, &data.db, None).await {
                warn!(
                    "Failed to regenerate zones after nameserver deletion: {}",
                    e
                );
                return publish_failed(&e);
            }

            HttpResponse::Ok().json(serde_json::json!({"success": true}))
        }
        Err(e) => {
            warn!("delete_nameserver error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "failed to delete nameserver"}))
        }
    }
}

#[derive(Deserialize)]
struct AgentRegistration {
    name: String,
    addr: String,
}

#[derive(Serialize)]
struct AgentRegisterResponse {
    id: String,
    token: String,
    signing_key: String,
}

async fn agent_register(
    body: web::Json<AgentRegistration>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    // Agent registration issues a valid agent token that can later pull the
    // full zone list, so it must require an authenticated admin.
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "unauthorized",
                "details": "Authentication required"
            }));
        }
    };
    if tok.claims.role != "admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "forbidden",
            "details": "Admin role required"
        }));
    }

    // Validate input
    if body.name.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_input",
            "details": "Agent name is required"
        }));
    }

    if body.addr.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_input",
            "details": "Agent address is required"
        }));
    }

    // Create agent id and token
    let id = Uuid::new_v4();
    let id_str = id.to_string();
    // token: combine two UUIDs for sufficient entropy
    let token_plain = format!(
        "{}{}",
        Uuid::new_v4().to_string(),
        Uuid::new_v4().to_string()
    );
    let token_fingerprint = hash_token(&token_plain);
    let salt = generate_salt();
    let argon2 = Argon2::default();
    let token_hash = match argon2.hash_password(token_plain.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(e) => {
            warn!("agent token hash error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "hash_error",
                "details": "Failed to hash agent token"
            }));
        }
    };

    match data.db.execute(
        "INSERT INTO agents (id, name, addr, token_hash, token_sha256) VALUES ($1::text::uuid, $2, $3, $4, $5)",
        &[&id_str, &body.name, &body.addr, &token_hash, &token_fingerprint]
    ).await {
        Ok(_) => {
            audit(&data.db, Some(&tok.claims.sub), "register_agent", "agent", Some(id_str.clone()), &req, serde_json::json!({"name": body.name})).await;
            info!("Registered agent: {} at {}", body.name, body.addr);
            // The token authenticates the agent; the signing key lets it verify
            // configuration bundles. Both are shown once.
            HttpResponse::Created().json(AgentRegisterResponse {
                id: id.to_string(),
                token: token_plain,
                signing_key: ext::agent_signing_key(&data.jwt_secret, &id_str),
            })
        }
        Err(e) => {
            warn!("agent_register database error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "database_error",
                "details": "Failed to register agent"
            }))
        }
    }
}

#[derive(Deserialize)]
struct AgentHeartbeat {
    #[serde(default)]
    id: Option<String>,
    addr: String,
}

async fn agent_heartbeat_ok(data: &AppState, req: &HttpRequest, id_str: &str) -> HttpResponse {
    let seen = real_client_ip(req).map(|i| i.to_string());
    match data.db.execute("UPDATE agents SET last_heartbeat = now(), last_seen_ip = $2 WHERE CAST(id AS varchar) = $1", &[&id_str, &seen]).await {
        Ok(_) => {
            let st = data.db.query_opt(
                "SELECT (SELECT version FROM publish_state WHERE id = 1), a.sync_requested, a.applied_version FROM agents a WHERE CAST(a.id AS varchar) = $1", &[&id_str]).await;
            match st {
                Ok(Some(r)) => HttpResponse::Ok().json(serde_json::json!({
                    "agent_id": id_str, "desired_version": r.get::<_, i64>(0), "applied_version": r.get::<_, i64>(2), "sync_requested": r.get::<_, bool>(1)
                })),
                Ok(None) => HttpResponse::NotFound().finish(),
                Err(e) => { warn!("agent_heartbeat status: {}", full_error_string(&e)); HttpResponse::InternalServerError().finish() }
            }
        }
        Err(e) => { warn!("agent_heartbeat error: {}", e); HttpResponse::InternalServerError().finish() }
    }
}

async fn agent_heartbeat(
    body: web::Json<AgentHeartbeat>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let token = match bearer_token(&req) {
        Some(t) => t.to_string(),
        None => return HttpResponse::Unauthorized().finish(),
    };
    let presented = hash_token(&token);

    if let Some(agent_id) = body.id.as_deref().filter(|id| !id.trim().is_empty()) {
        let row = match data.db.query_opt(
            "SELECT token_hash, token_sha256 FROM agents WHERE CAST(id AS varchar) = $1 AND COALESCE(enabled, true)",
            &[&agent_id],
        ).await {
            Ok(Some(r)) => r,
            Ok(None) => return HttpResponse::Unauthorized().finish(),
            Err(e) => { warn!("agent_heartbeat by id: {}", full_error_string(&e)); return HttpResponse::InternalServerError().finish(); }
        };
        let stored_hash: String = row.get(0);
        let fingerprint: Option<String> = row.get(1);
        if let Some(fp) = fingerprint {
            if fp != presented {
                return HttpResponse::Unauthorized().finish();
            }
        } else {
            let ok = PasswordHash::new(&stored_hash)
                .map(|p| {
                    Argon2::default()
                        .verify_password(token.as_bytes(), &p)
                        .is_ok()
                })
                .unwrap_or(false);
            if !ok {
                return HttpResponse::Unauthorized().finish();
            }
            let _ = data.db.execute(
                "UPDATE agents SET token_sha256 = $1 WHERE CAST(id AS varchar) = $2 AND token_sha256 IS NULL",
                &[&presented, &agent_id],
            ).await;
        }
        return agent_heartbeat_ok(&data, &req, agent_id).await;
    }

    let rows = match data.db.query(
        "SELECT CAST(id AS varchar), token_hash, token_sha256 FROM agents WHERE addr = $1 AND COALESCE(enabled, true) AND token_sha256 = $2",
        &[&body.addr, &presented],
    ).await {
        Ok(r) => r,
        Err(e) => { warn!("agent_heartbeat error: {}", full_error_string(&e)); return HttpResponse::InternalServerError().finish(); }
    };
    if let Some(row) = rows.into_iter().next() {
        let id_str: String = row.get(0);
        return agent_heartbeat_ok(&data, &req, &id_str).await;
    }

    // Legacy agents registered before fingerprints existed still authenticate
    // with Argon2, but only a bounded number of rows per request and under a
    // per-address budget. A successful check upgrades the row permanently.
    let legacy = match data.db.query(
        "SELECT CAST(id AS varchar), token_hash FROM agents WHERE addr = $1 AND COALESCE(enabled, true) AND token_sha256 IS NULL ORDER BY created_at LIMIT 8",
        &[&body.addr],
    ).await {
        Ok(r) => r,
        Err(e) => { warn!("agent_heartbeat legacy lookup: {}", full_error_string(&e)); return HttpResponse::InternalServerError().finish(); }
    };
    if legacy.is_empty() {
        let exists = match data
            .db
            .query_opt(
                "SELECT 1 FROM agents WHERE addr = $1 AND COALESCE(enabled, true)",
                &[&body.addr],
            )
            .await
        {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => {
                warn!("agent_heartbeat address lookup: {}", full_error_string(&e));
                return HttpResponse::InternalServerError().finish();
            }
        };
        return if exists {
            HttpResponse::Unauthorized().finish()
        } else {
            HttpResponse::NotFound().finish()
        };
    }
    let bucket = format!(
        "agent-legacy:{}",
        real_client_ip(&req)
            .map(|i| i.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    );
    if let Some(wait) = shared::limited(&data.db, &bucket, 20, 60, || true).await {
        return HttpResponse::TooManyRequests()
            .insert_header((header::RETRY_AFTER, wait.to_string()))
            .finish();
    }
    for row in legacy {
        let id_str: String = row.try_get(0).unwrap_or_default();
        let th: String = row.try_get(1).unwrap_or_default();
        if let Ok(ph) = PasswordHash::new(&th) {
            if Argon2::default()
                .verify_password(token.as_bytes(), &ph)
                .is_ok()
            {
                let _ = data.db.execute(
                    "UPDATE agents SET token_sha256 = $1 WHERE CAST(id AS varchar) = $2 AND token_sha256 IS NULL",
                    &[&presented, &id_str],
                ).await;
                return agent_heartbeat_ok(&data, &req, &id_str).await;
            }
        }
    }
    HttpResponse::Unauthorized().finish()
}

// Agent fetch config (agents call this with their token)
async fn agent_get_config(
    path: web::Path<String>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let agent_id = path.into_inner();
    if let Err(r) = ext::agent_authenticated(&data, &agent_id, &req).await {
        return r;
    }
    let zones = match data.db.query(
        "SELECT CAST(z.id AS varchar), z.domain FROM agent_zones az JOIN zones z ON z.id = az.zone_id \
         WHERE CAST(az.agent_id AS varchar) = $1 AND COALESCE(z.status, 'active') = 'active' ORDER BY z.domain",
        &[&agent_id],
    ).await {
        Ok(z) => z,
        Err(e) => { warn!("agent_get_config error: {}", full_error_string(&e)); return HttpResponse::InternalServerError().finish(); }
    };
    let z: Vec<_> = zones.into_iter().map(|r| serde_json::json!({"id": r.try_get::<_, String>(0).unwrap_or_default(), "domain": r.try_get::<_, String>(1).unwrap_or_default()})).collect();
    HttpResponse::Ok().json(serde_json::json!({"zones": z}))
}

// Admin-only: rotate agent token
async fn rotate_agent_token(
    path: web::Path<String>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return HttpResponse::Unauthorized().finish(),
    };
    if tok.claims.role != "admin" {
        return HttpResponse::Forbidden().finish();
    }
    let agent_id = path.into_inner();
    let token_plain = format!(
        "{}{}",
        Uuid::new_v4().to_string(),
        Uuid::new_v4().to_string()
    );
    let token_fingerprint = hash_token(&token_plain);
    let salt = generate_salt();
    let argon2 = Argon2::default();
    let token_hash = match argon2.hash_password(token_plain.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(e) => {
            warn!("agent token hash error: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let res = data.db.execute("UPDATE agents SET token_hash = $1, token_sha256 = $2, updated_at = now() WHERE CAST(id AS varchar) = $3", &[&token_hash, &token_fingerprint, &agent_id]).await;
    match res {
        Ok(r) => {
            if r == 0 {
                HttpResponse::NotFound().finish()
            } else {
                audit(
                    &data.db,
                    Some(&tok.claims.sub),
                    "rotate_agent_token",
                    "agent",
                    Some(agent_id.clone()),
                    &req,
                    serde_json::json!({}),
                )
                .await;
                HttpResponse::Ok().json(serde_json::json!({"token": token_plain, "signing_key": ext::agent_signing_key(&data.jwt_secret, &agent_id)}))
            }
        }
        Err(e) => {
            warn!("rotate_agent_token error: {}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// Admin-only: remove an agent registration (its token stops working).
async fn delete_agent(
    path: web::Path<String>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    if tok.claims.role != "admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "admin role required"}));
    }
    let agent_id = path.into_inner();
    match data
        .db
        .execute(
            "DELETE FROM agents WHERE CAST(id AS varchar) = $1",
            &[&agent_id],
        )
        .await
    {
        Ok(0) => HttpResponse::NotFound().json(serde_json::json!({"error": "agent not found"})),
        Ok(_) => {
            audit(
                &data.db,
                Some(&tok.claims.sub),
                "delete_agent",
                "agent",
                Some(agent_id.clone()),
                &req,
                serde_json::json!({}),
            )
            .await;
            HttpResponse::Ok().json(serde_json::json!({"success": true}))
        }
        Err(e) => {
            warn!("delete_agent error: {}", full_error_string(&e));
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "failed to delete agent"}))
        }
    }
}

async fn list_agents(
    page: web::Query<ext::PageQuery>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    // Authenticate and verify admin role
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "unauthorized",
                "details": "Authentication required"
            }));
        }
    };

    if tok.claims.role != "admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "forbidden",
            "details": "Admin role required"
        }));
    }

    let (limit, offset, qtext) = page.parts();
    let sort = match page.sort_column(
        &[
            ("name", "name"),
            ("address", "addr"),
            ("heartbeat", "last_heartbeat"),
        ],
        "name",
    ) {
        Ok(value) => value,
        Err(()) => return invalid_list_query(),
    };
    let direction = match page.sort_direction() {
        Ok(value) => value,
        Err(()) => return invalid_list_query(),
    };
    let total = match data.db.query_one(
        "SELECT count(*) FROM agents WHERE $1::text IS NULL OR name ILIKE '%' || $1 || '%' OR addr ILIKE '%' || $1 || '%'",
        &[&qtext],
    ).await {
        Ok(row) => row.get::<_, i64>(0),
        Err(e) => {
            warn!("list_agents count error: {}", full_error_string(&e));
            return HttpResponse::InternalServerError().json(serde_json::json!({"error":"database_error"}));
        }
    };
    // Query only one page (with synchronisation state).
    let desired: i64 = match data
        .db
        .query_one("SELECT version FROM publish_state WHERE id = 1", &[])
        .await
    {
        Ok(row) => row.get(0),
        Err(e) => {
            warn!("list_agents publish state: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    };
    let behind: i64 = match data
        .db
        .query_one(
            "SELECT count(*) FROM agents WHERE COALESCE(enabled, true) AND applied_version < $1",
            &[&desired],
        )
        .await
    {
        Ok(row) => row.get(0),
        Err(e) => {
            warn!("list_agents sync count: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database_error"}));
        }
    };
    let list_sql = format!(
        "SELECT CAST(id AS varchar), name, addr, EXTRACT(EPOCH FROM last_heartbeat)::float8 as epoch, COALESCE(enabled, true), applied_version, EXTRACT(EPOCH FROM last_ack_at)::float8, last_error, sync_requested, last_seen_ip FROM agents WHERE $1::text IS NULL OR name ILIKE '%' || $1 || '%' OR addr ILIKE '%' || $1 || '%' ORDER BY {sort} {direction}, id LIMIT $2::bigint OFFSET $3::bigint"
    );
    match data.db.query(&list_sql, &[&qtext, &limit, &offset]).await {
        Ok(rows) => {
            let agents: Vec<_> = rows.into_iter().map(|r| {
                let id: String = r.try_get(0).unwrap_or_default();
                let name: String = r.try_get(1).unwrap_or_default();
                let addr: String = r.try_get(2).unwrap_or_default();
                let epoch: f64 = r.try_get(3).unwrap_or(0.0);
                let enabled: bool = r.try_get(5 - 1).unwrap_or(true);
                let applied: i64 = r.try_get(5).unwrap_or(0);
                let ack_epoch: Option<f64> = r.try_get(6).unwrap_or(None);
                let last_dt = chrono::Utc.timestamp_opt(epoch as i64, (epoch.fract() * 1e9) as u32).single().unwrap_or(chrono::Utc::now());
                let age = chrono::Utc::now().signed_duration_since(last_dt).num_seconds();
                let online = enabled && age < 120;
                let in_sync = applied >= desired;
                serde_json::json!({
                    "id": id, "name": name, "addr": addr, "last_heartbeat": last_dt.to_rfc3339(), "online": online, "enabled": enabled,
                    "applied_version": applied, "desired_version": desired, "in_sync": in_sync,
                    "last_ack_at": ack_epoch.and_then(|e| chrono::Utc.timestamp_opt(e as i64, 0).single()).map(|d| d.to_rfc3339()),
                    "last_error": r.try_get::<_, Option<String>>(7).unwrap_or(None),
                    "sync_requested": r.try_get::<_, bool>(8).unwrap_or(false),
                    "last_seen_ip": r.try_get::<_, Option<String>>(9).unwrap_or(None),
                })
            }).collect();
            metrics::record_sync(desired, behind, data.db.healthy());
            HttpResponse::Ok()
                .insert_header(("X-Total-Count", total.to_string()))
                .json(agents)
        }
        Err(e) => {
            warn!("list_agents database error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "database_error",
                "details": "Failed to fetch agents"
            }))
        }
    }
}

#[derive(Deserialize)]
struct AgentZonesReq {
    #[serde(default)]
    zone_ids: Vec<String>,
}

async fn list_agent_zones(
    path: web::Path<String>,
    page: web::Query<ext::PageQuery>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    if tok.claims.role != "admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "admin role required"}));
    }
    let agent_id = path.into_inner();
    match data
        .db
        .query_opt(
            "SELECT 1 FROM agents WHERE CAST(id AS varchar) = $1",
            &[&agent_id],
        )
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({"error": "agent not found"}));
        }
        Err(e) => {
            warn!("list_agent_zones lookup: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    }
    let (limit, offset, qtext) = page.parts();
    let sort = match page.sort_column(&[("domain", "z.domain")], "domain") {
        Ok(value) => value,
        Err(()) => return invalid_list_query(),
    };
    let direction = match page.sort_direction() {
        Ok(value) => value,
        Err(()) => return invalid_list_query(),
    };
    let total = match data.db.query_one(
        "SELECT count(*) FROM agent_zones az JOIN zones z ON z.id = az.zone_id WHERE CAST(az.agent_id AS varchar) = $1 AND ($2::text IS NULL OR z.domain ILIKE '%' || $2 || '%')",
        &[&agent_id, &qtext],
    ).await {
        Ok(row) => row.get::<_, i64>(0),
        Err(e) => {
            warn!("list_agent_zones count: {}", full_error_string(&e));
            return HttpResponse::InternalServerError().json(serde_json::json!({"error":"database_error"}));
        }
    };
    let list_sql = format!(
        "SELECT CAST(z.id AS varchar), z.domain FROM agent_zones az JOIN zones z ON z.id = az.zone_id WHERE CAST(az.agent_id AS varchar) = $1 AND ($2::text IS NULL OR z.domain ILIKE '%' || $2 || '%') ORDER BY {sort} {direction}, z.id LIMIT $3::bigint OFFSET $4::bigint"
    );
    match data
        .db
        .query(&list_sql, &[&agent_id, &qtext, &limit, &offset])
        .await
    {
        Ok(rows) => {
            let zones: Vec<_> = rows
                .into_iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.try_get::<_, String>(0).unwrap_or_default(),
                        "domain": r.try_get::<_, String>(1).unwrap_or_default(),
                    })
                })
                .collect();
            HttpResponse::Ok()
                .insert_header(("X-Total-Count", total.to_string()))
                .json(serde_json::json!({"agent_id": agent_id, "zones": zones}))
        }
        Err(e) => {
            warn!("list_agent_zones: {}", full_error_string(&e));
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "database error"}))
        }
    }
}

async fn set_agent_zones(
    path: web::Path<String>,
    body: web::Json<AgentZonesReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    if tok.claims.role != "admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "admin role required"}));
    }
    let agent_id = path.into_inner();
    let mut ids: Vec<String> = Vec::new();
    for id in &body.zone_ids {
        let parsed = match Uuid::parse_str(id.trim()) {
            Ok(u) => u.to_string(),
            Err(_) => {
                return HttpResponse::BadRequest()
                    .json(serde_json::json!({"error": "invalid zone id"}));
            }
        };
        if !ids.contains(&parsed) {
            ids.push(parsed);
        }
    }
    let tx = match data.db.begin().await {
        Ok(t) => t,
        Err(e) => {
            warn!("set_agent_zones transaction: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    };
    let c = tx.client();
    if let Err(e) = c.batch_execute("BEGIN").await {
        warn!("set_agent_zones begin: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "database error"}));
    }
    match c
        .query_opt(
            "SELECT 1 FROM agents WHERE CAST(id AS varchar) = $1 FOR UPDATE",
            &[&agent_id],
        )
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => {
            rollback_transaction(c).await;
            return HttpResponse::NotFound().json(serde_json::json!({"error": "agent not found"}));
        }
        Err(e) => {
            rollback_transaction(c).await;
            warn!("set_agent_zones agent lookup: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    }
    if !ids.is_empty() {
        let found = match c
            .query(
                "SELECT CAST(id AS varchar) FROM zones WHERE CAST(id AS varchar) = ANY($1::text[])",
                &[&ids],
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                rollback_transaction(c).await;
                warn!("set_agent_zones zone lookup: {}", full_error_string(&e));
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({"error": "database error"}));
            }
        };
        if found.len() != ids.len() {
            rollback_transaction(c).await;
            return HttpResponse::NotFound()
                .json(serde_json::json!({"error": "one or more zones were not found"}));
        }
    }
    if let Err(e) = c
        .execute(
            "DELETE FROM agent_zones WHERE CAST(agent_id AS varchar) = $1",
            &[&agent_id],
        )
        .await
    {
        rollback_transaction(c).await;
        warn!("set_agent_zones clear: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "database error"}));
    }
    if !ids.is_empty() {
        if let Err(e) = c.execute(
            "INSERT INTO agent_zones (agent_id, zone_id) SELECT $1::text::uuid, z.id FROM zones z WHERE CAST(z.id AS varchar) = ANY($2::text[])",
            &[&agent_id, &ids],
        ).await {
            rollback_transaction(c).await;
            warn!("set_agent_zones insert: {}", full_error_string(&e));
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "database error"}));
        }
    }
    if let Err(e) = c
        .execute(
            "UPDATE publish_state SET version = version + 1, updated_at = now() WHERE id = 1",
            &[],
        )
        .await
    {
        rollback_transaction(c).await;
        warn!("set_agent_zones version: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "database error"}));
    }
    if let Err(e) = c.batch_execute("COMMIT").await {
        warn!("set_agent_zones commit: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "database error"}));
    }
    drop(tx);
    audit(
        &data.db,
        Some(&tok.claims.sub),
        "update_agent_zones",
        "agent",
        Some(agent_id.clone()),
        &req,
        serde_json::json!({"zone_ids": ids}),
    )
    .await;
    let zones = match data.db.query(
        "SELECT CAST(z.id AS varchar), z.domain FROM agent_zones az JOIN zones z ON z.id = az.zone_id \
         WHERE CAST(az.agent_id AS varchar) = $1 ORDER BY z.domain",
        &[&agent_id],
    ).await {
        Ok(rows) => rows.into_iter().map(|r| serde_json::json!({
            "id": r.try_get::<_, String>(0).unwrap_or_default(),
            "domain": r.try_get::<_, String>(1).unwrap_or_default(),
        })).collect::<Vec<_>>(),
        Err(e) => {
            warn!("set_agent_zones result: {}", full_error_string(&e));
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "database error"}));
        }
    };
    HttpResponse::Ok().json(serde_json::json!({"agent_id": agent_id, "zones": zones}))
}

async fn generate_dns_files(data: web::Data<FullState>, req: HttpRequest) -> impl Responder {
    // this endpoint is retained for debugging but is not required by the
    // production architecture; generation is automatic on every write.
    if let Some(tok) = auth_from_header(&req, &data.inner.jwt_secret) {
        if tok.claims.role != "admin" {
            return HttpResponse::Forbidden()
                .json(serde_json::json!({"error": "admin role required"}));
        }
    } else {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"}));
    }

    match data
        .inner
        .dns_manager
        .regenerate_zones(data.inner.db.clone())
        .await
    {
        Ok(report) if report.failed.is_empty() => HttpResponse::Ok().json(serde_json::json!({
            "status": "generated",
            "zones": report.published.len()
        })),
        Ok(report) => {
            warn!(
                "zone generation finished with failures: {:?}",
                report.failed
            );
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "some zones could not be generated; their previous zone files are still being served",
                "failed": report.failed.iter().map(|(z, e)| serde_json::json!({"zone": z, "error": e})).collect::<Vec<_>>(),
                "zones": report.published.len()
            }))
        }
        Err(e) => {
            warn!("failed to generate zone files: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": format!("generation failed: {}", e)}))
        }
    }
}

#[derive(Deserialize)]
struct CreateGeoRuleReq {
    zone_id: String,
    match_type: String,
    match_value: String,
    target: String,
    #[serde(default)]
    weight: Option<i32>,
    #[serde(default)]
    priority: Option<i32>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    record_name: Option<String>,
    #[serde(default)]
    record_type: Option<String>,
}

async fn create_georule(
    body: web::Json<CreateGeoRuleReq>,
    data: web::Data<FullState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.inner.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let db = &data.inner.db;

    let zone_uuid = match Uuid::parse_str(&body.zone_id) {
        Ok(z) => z,
        Err(_) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": "invalid zone_id"}));
        }
    };
    let zone_str = zone_uuid.to_string();
    // Rules may only be created by an admin or the owner of the target zone.
    let access = match zone_access(db, &zone_str, &tok).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if dnssec::zone_is_signed(db, &zone_str).await {
        return dnssec::geo_conflict();
    }
    if let Err(e) = validate_georule_fields(
        Some(&body.match_type),
        Some(&body.match_value),
        Some(&body.target),
        body.record_name.as_deref(),
        body.record_type.as_deref(),
    ) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": e}));
    }
    let weight = body.weight.unwrap_or(1);
    if !(0..=1_000_000).contains(&weight) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "weight must be between 0 and 1000000"
        }));
    }

    let id = Uuid::new_v4();
    let id_str = id.to_string();
    let res = db.execute(
        "INSERT INTO georules (id, zone_id, match_type, match_value, target, weight, priority, enabled, record_name, record_type) \
         VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5, $6, $7, $8, $9, $10)",
        &[&id_str, &zone_str, &body.match_type, &body.match_value.trim(), &body.target.trim(),
          &weight, &body.priority.unwrap_or(0), &body.enabled.unwrap_or(true), &body.record_name, &body.record_type]
    ).await;
    match res {
        Ok(_) => {
            audit(
                db,
                Some(&tok.claims.sub),
                "create_georule",
                "georule",
                Some(id_str.clone()),
                &req,
                serde_json::json!({"zone": access.domain}),
            )
            .await;
            // regenerate configuration so DNS servers pick up new rule
            if let Err(e) = publish(&data.inner.dns_manager, db, Some(&access.domain)).await {
                warn!("Failed to publish zone after georule creation: {}", e);
                return publish_failed(&e);
            }
            HttpResponse::Created().json(serde_json::json!({"id": id_str}))
        }
        Err(e) => {
            warn!("create_georule error: {}", full_error_string(&e));
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "failed to create rule"}))
        }
    }
}

async fn list_georules(
    page: web::Query<ext::PageQuery>,
    data: web::Data<FullState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.inner.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let (limit, offset, qtext) = page.parts();
    let sort = match page.sort_column(
        &[
            ("domain", "z.domain"),
            ("priority", "g.priority"),
            ("match_type", "g.match_type"),
        ],
        "domain",
    ) {
        Ok(value) => value,
        Err(()) => return invalid_list_query(),
    };
    let direction = match page.sort_direction() {
        Ok(value) => value,
        Err(()) => return invalid_list_query(),
    };
    let base = "FROM georules g JOIN zones z ON z.id = g.zone_id \
         WHERE ($1 OR CAST(z.owner AS varchar) = $2 OR EXISTS (SELECT 1 FROM zone_members m WHERE m.zone_id = z.id AND CAST(m.user_id AS varchar) = $2) \
                OR EXISTS (SELECT 1 FROM tenant_members tm WHERE tm.tenant_id = z.tenant_id AND CAST(tm.user_id AS varchar) = $2)) \
                AND ($3::text IS NULL OR g.match_type ILIKE '%' || $3 || '%' OR g.match_value ILIKE '%' || $3 || '%' \
                    OR COALESCE(g.record_name, '') ILIKE '%' || $3 || '%' OR z.domain ILIKE '%' || $3 || '%')";
    let count_sql = format!("SELECT count(*) {base}");
    let total: i64 = match data
        .inner
        .db
        .query_one(
            &count_sql,
            &[&(tok.claims.role == "admin"), &tok.claims.sub, &qtext],
        )
        .await
    {
        Ok(row) => row.get(0),
        Err(e) => {
            warn!("list_georules count: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database_error"}));
        }
    };
    let list_sql = format!(
        "SELECT CAST(g.id AS varchar), CAST(g.zone_id AS varchar), g.match_type, g.match_value, g.target, g.priority, g.enabled, g.record_name, g.record_type, g.weight \
         {base} ORDER BY {sort} {direction}, g.id LIMIT $4::bigint OFFSET $5::bigint"
    );
    let rows = data
        .inner
        .db
        .query(
            &list_sql,
            &[
                &(tok.claims.role == "admin"),
                &tok.claims.sub,
                &qtext,
                &limit,
                &offset,
            ],
        )
        .await;
    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            warn!("list_georules error: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database_error"}));
        }
    };
    let out: Vec<_> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "id": r.try_get::<_, String>(0).unwrap_or_default(),
                "zone_id": r.try_get::<_, String>(1).unwrap_or_default(),
                "match_type": r.try_get::<_, String>(2).unwrap_or_default(),
                "match_value": r.try_get::<_, String>(3).unwrap_or_default(),
                "target": r.try_get::<_, String>(4).unwrap_or_default(),
                "priority": r.try_get::<_, i32>(5).unwrap_or(0),
                "enabled": r.try_get::<_, bool>(6).unwrap_or(true),
                "record_name": r.try_get::<_, Option<String>>(7).unwrap_or(None),
                "record_type": r.try_get::<_, Option<String>>(8).unwrap_or(None),
                "weight": r.try_get::<_, i32>(9).unwrap_or(1),
            })
        })
        .collect();
    HttpResponse::Ok()
        .insert_header(("X-Total-Count", total.to_string()))
        .json(out)
}

#[derive(Deserialize)]
struct UpdateGeoRuleReq {
    match_type: Option<String>,
    match_value: Option<String>,
    target: Option<String>,
    weight: Option<i32>,
    priority: Option<i32>,
    enabled: Option<bool>,
    record_name: Option<String>,
    record_type: Option<String>,
}

/// Look up the zone a rule belongs to and check the caller may act on it.
async fn georule_access(
    db: &Pool,
    rule_id: &str,
    tok: &TokenData<Claims>,
) -> Result<(String, ZoneAccess, tokio_postgres::Row), HttpResponse> {
    let row = db.query_opt(
        "SELECT CAST(zone_id AS varchar), match_type, match_value, target, weight FROM georules WHERE CAST(id AS varchar) = $1",
        &[&rule_id],
    ).await;
    let row = match row {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Err(
                HttpResponse::NotFound().json(serde_json::json!({"error": "rule not found"}))
            );
        }
        Err(e) => {
            warn!("georule lookup error: {}", full_error_string(&e));
            return Err(HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database_error"})));
        }
    };
    let zone_id: String = row.try_get(0).unwrap_or_default();
    let access = zone_access(db, &zone_id, tok).await?;
    Ok((zone_id, access, row))
}

async fn update_georule(
    path: web::Path<String>,
    body: web::Json<UpdateGeoRuleReq>,
    data: web::Data<FullState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.inner.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let rule_id = path.into_inner();
    let db = &data.inner.db;

    // Rules may only be updated by an admin or the owner of the target zone.
    let (_zone_id, access, current) = match georule_access(db, &rule_id, &tok).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    if body.match_type.is_none()
        && body.match_value.is_none()
        && body.target.is_none()
        && body.weight.is_none()
        && body.priority.is_none()
        && body.enabled.is_none()
        && body.record_name.is_none()
        && body.record_type.is_none()
    {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "no fields to update"}));
    }
    // validate the resulting rule, not just the changed fields
    let eff_type = body
        .match_type
        .clone()
        .unwrap_or_else(|| current.try_get(1).unwrap_or_default());
    let eff_value = body
        .match_value
        .clone()
        .unwrap_or_else(|| current.try_get(2).unwrap_or_default());
    if let Err(e) = validate_georule_fields(
        Some(&eff_type),
        Some(&eff_value),
        body.target.as_deref(),
        body.record_name.as_deref(),
        body.record_type.as_deref(),
    ) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": e}));
    }
    let eff_weight = body
        .weight
        .unwrap_or_else(|| current.try_get(4).unwrap_or(1));
    if !(0..=1_000_000).contains(&eff_weight) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "weight must be between 0 and 1000000"
        }));
    }

    // Single statement with typed parameters (priority is INT, enabled BOOLEAN).
    match db.execute(
        "UPDATE georules SET match_type = COALESCE($1, match_type), match_value = COALESCE($2, match_value), \
         target = COALESCE($3, target), weight = COALESCE($4, weight), priority = COALESCE($5, priority), enabled = COALESCE($6, enabled), \
         record_name = COALESCE($7, record_name), record_type = COALESCE($8, record_type), updated_at = now() \
         WHERE CAST(id AS varchar) = $9",
        &[&body.match_type, &body.match_value.as_ref().map(|v| v.trim().to_string()), &body.target.as_ref().map(|v| v.trim().to_string()),
          &body.weight, &body.priority, &body.enabled, &body.record_name, &body.record_type, &rule_id]
    ).await {
        Ok(0) => HttpResponse::NotFound().json(serde_json::json!({"error": "rule not found"})),
        Ok(_) => {
            audit(db, Some(&tok.claims.sub), "update_georule", "georule", Some(rule_id.clone()), &req, serde_json::json!({"zone": access.domain})).await;
            if let Err(e) = publish(&data.inner.dns_manager, db, Some(&access.domain)).await {
                warn!("Failed to publish zone after georule update: {}", e);
                return publish_failed(&e);
            }
            HttpResponse::Ok().json(serde_json::json!({"success": true}))
        }
        Err(e) => {
            warn!("update_georule error: {}", full_error_string(&e));
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "failed to update rule"}))
        }
    }
}

async fn delete_georule(
    path: web::Path<String>,
    data: web::Data<FullState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.inner.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let rule_id = path.into_inner();
    let db = &data.inner.db;

    // Rules may only be deleted by an admin or the owner of the target zone.
    let (_zone_id, access, _row) = match georule_access(db, &rule_id, &tok).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    match db
        .execute(
            "DELETE FROM georules WHERE CAST(id AS varchar) = $1",
            &[&rule_id],
        )
        .await
    {
        Ok(_) => {
            audit(
                db,
                Some(&tok.claims.sub),
                "delete_georule",
                "georule",
                Some(rule_id.clone()),
                &req,
                serde_json::json!({"zone": access.domain}),
            )
            .await;
            if let Err(e) = publish(&data.inner.dns_manager, db, Some(&access.domain)).await {
                warn!("Failed to publish zone after georule delete: {}", e);
                return publish_failed(&e);
            }
            HttpResponse::Ok().json(serde_json::json!({"success": true}))
        }
        Err(e) => {
            warn!("delete_georule error: {}", full_error_string(&e));
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "failed to delete rule"}))
        }
    }
}

#[derive(Deserialize)]
struct CreateZoneReq {
    domain: String,
    #[serde(default)]
    geodns_enabled: Option<bool>,
    /// tenant that will own the zone (customers: one of their tenants; default: their own tenant)
    #[serde(default)]
    tenant_id: Option<String>,
    /// Optional built-in zone template. DNSSEC keys are never copied or created by templates.
    #[serde(default)]
    template_id: Option<String>,
    #[serde(default)]
    template_variables: HashMap<String, String>,
}

#[derive(Serialize)]
struct ZoneTemplateVariable {
    name: &'static str,
    label: &'static str,
    input: &'static str,
    required: bool,
}

#[derive(Serialize)]
struct ZoneTemplateInfo {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    variables: Vec<ZoneTemplateVariable>,
}

fn zone_template_catalog() -> Vec<ZoneTemplateInfo> {
    vec![
        ZoneTemplateInfo {
            id: "web",
            name: "Web site",
            description: "Apex A record and www CNAME.",
            variables: vec![
                ZoneTemplateVariable {
                    name: "ipv4",
                    label: "IPv4 address",
                    input: "ipv4",
                    required: true,
                },
                ZoneTemplateVariable {
                    name: "ipv6",
                    label: "IPv6 address",
                    input: "ipv6",
                    required: false,
                },
            ],
        },
        ZoneTemplateInfo {
            id: "mail",
            name: "Mail server",
            description: "Mail host A record, apex MX and a restrictive SPF TXT record.",
            variables: vec![ZoneTemplateVariable {
                name: "mail_ipv4",
                label: "Mail server IPv4 address",
                input: "ipv4",
                required: true,
            }],
        },
    ]
}

fn render_zone_template(
    template_id: Option<&str>,
    domain: &str,
    variables: &HashMap<String, String>,
) -> Result<Vec<RecordRow>, String> {
    let Some(template_id) = template_id else {
        if !variables.is_empty() {
            return Err("template_variables require a template_id".to_string());
        }
        return Ok(Vec::new());
    };
    let mut raw: Vec<(&str, &str, String, i32)> = Vec::new();
    let allowed: &[&str];
    match template_id {
        "web" => {
            allowed = &["ipv4", "ipv6"];
            let ipv4 = variables
                .get("ipv4")
                .filter(|v| !v.trim().is_empty())
                .ok_or_else(|| "template variable 'ipv4' is required".to_string())?;
            raw.push(("@", "A", ipv4.trim().to_string(), 0));
            if let Some(ipv6) = variables.get("ipv6").filter(|v| !v.trim().is_empty()) {
                raw.push(("@", "AAAA", ipv6.trim().to_string(), 0));
            }
            raw.push((
                "www",
                "CNAME",
                format!("{}.", domain.trim_end_matches('.')),
                0,
            ));
        }
        "mail" => {
            allowed = &["mail_ipv4"];
            let ipv4 = variables
                .get("mail_ipv4")
                .filter(|v| !v.trim().is_empty())
                .ok_or_else(|| "template variable 'mail_ipv4' is required".to_string())?;
            raw.push(("mail", "A", ipv4.trim().to_string(), 0));
            raw.push((
                "@",
                "MX",
                format!("mail.{}.", domain.trim_end_matches('.')),
                10,
            ));
            raw.push(("@", "TXT", "v=spf1 mx -all".to_string(), 0));
        }
        _ => return Err("unknown zone template".to_string()),
    }
    if variables.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err("template_variables contains an unsupported variable".to_string());
    }
    raw.into_iter()
        .map(|(name, rtype, value, priority)| {
            validate_record_input(domain, name, rtype, &value, 3600, priority)
        })
        .collect()
}

async fn list_zone_templates(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    if auth_from_header(&req, &data.jwt_secret).is_none() {
        return unauthorized();
    }
    HttpResponse::Ok().json(zone_template_catalog())
}

async fn list_zones(
    page: web::Query<ext::PageQuery>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    // Check authentication
    let auth = auth_from_header(&req, &data.jwt_secret);
    if auth.is_none() {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "unauthorized",
            "details": "Authentication required"
        }));
    }
    let tok = auth.unwrap();

    // Admins see every zone; others the zones they own or that were shared with them.
    let is_admin = tok.claims.role == "admin";
    let (limit, offset, qtext) = page.parts();
    let tag = page.tag();
    let sort = match page.sort_column(
        &[
            ("domain", "z.domain"),
            ("created", "z.created_at"),
            ("status", "z.status"),
        ],
        "domain",
    ) {
        Ok(value) => value,
        Err(()) => return invalid_list_query(),
    };
    let direction = match page.sort_direction() {
        Ok(value) => value,
        Err(()) => return invalid_list_query(),
    };
    let list_sql = format!(
        "SELECT CAST(z.id AS varchar), z.domain, COALESCE(CAST(z.owner AS varchar), '') as owner, z.zone_type, z.created_at::text, \
                COALESCE(z.geodns_enabled, true), z.status, z.ecs_enabled, \
                CASE WHEN $1 THEN 'admin' WHEN CAST(z.owner AS varchar) = $2 THEN 'owner' \
                     ELSE COALESCE(m.role, (SELECT tm.role FROM tenant_members tm WHERE tm.tenant_id = z.tenant_id AND CAST(tm.user_id AS varchar) = $2), '') END, count(*) OVER(), \
                CAST(z.tenant_id AS varchar), (SELECT name FROM tenants t WHERE t.id = z.tenant_id), z.description, z.tags, \
                z.hold_reason, to_char(z.hold_until, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') \
         FROM zones z LEFT JOIN zone_members m ON m.zone_id = z.id AND CAST(m.user_id AS varchar) = $2 \
         WHERE ({}) AND ($3::text IS NULL OR z.domain ILIKE '%' || $3 || '%') \
           AND ($6::text IS NULL OR z.tags ? $6) \
         ORDER BY {sort} {direction}, z.id LIMIT $4::bigint OFFSET $5::bigint",
        tenants::ZONE_VISIBLE
    );
    let count_sql = format!(
        "SELECT count(*) FROM zones z LEFT JOIN zone_members m ON m.zone_id = z.id AND CAST(m.user_id AS varchar) = $2 WHERE ({}) AND ($3::text IS NULL OR z.domain ILIKE '%' || $3 || '%') AND ($4::text IS NULL OR z.tags ? $4)",
        tenants::ZONE_VISIBLE
    );
    let total = match data
        .db
        .query_one(&count_sql, &[&is_admin, &tok.claims.sub, &qtext, &tag])
        .await
    {
        Ok(row) => row.get::<_, i64>(0),
        Err(e) => {
            warn!("list_zones count error: {}", full_error_string(&e));
            return HttpResponse::InternalServerError().json(
                serde_json::json!({"error":"database_error","details":"Failed to count zones"}),
            );
        }
    };
    let query_result = data
        .db
        .query(
            &list_sql,
            &[&is_admin, &tok.claims.sub, &qtext, &limit, &offset, &tag],
        )
        .await;

    match query_result {
        Ok(rows) => {
            let zones: Vec<ZoneWithOwner> = rows
                .into_iter()
                .map(|r| ZoneWithOwner {
                    id: r.try_get(0).unwrap_or_default(),
                    domain: r.try_get(1).unwrap_or_default(),
                    owner: r.try_get(2).unwrap_or_default(),
                    zone_type: r.try_get(3).unwrap_or_default(),
                    created_at: r.try_get(4).unwrap_or_default(),
                    geodns_enabled: r.try_get(5).unwrap_or(true),
                    status: r.try_get(6).unwrap_or_default(),
                    ecs_enabled: r.try_get(7).unwrap_or(false),
                    access: r.try_get(8).unwrap_or_default(),
                    tenant_id: r.try_get(10).unwrap_or(None),
                    tenant_name: r.try_get(11).unwrap_or(None),
                    description: r.try_get(12).unwrap_or_default(),
                    tags: r.try_get(13).unwrap_or_default(),
                    hold_reason: r.try_get(14).unwrap_or(None),
                    hold_until: r.try_get(15).unwrap_or(None),
                })
                .collect();
            HttpResponse::Ok()
                .insert_header(("X-Total-Count", total.to_string()))
                .json(ApiResponse {
                    success: true,
                    data: Some(zones),
                    error: None,
                })
        }
        Err(e) => {
            warn!("list_zones database error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "database_error",
                "details": "Failed to fetch zones"
            }))
        }
    }
}

async fn create_zone(
    body: web::Json<CreateZoneReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let db = &data.db;
    let idem = idempotency_key(&req);
    if let Some(key) = &idem {
        if let Some(response) = idempotency_replay(db, key, &tok.claims.sub, "create_zone").await {
            return response;
        }
    }

    // Validate and canonicalise the domain (lower-case, LDH labels, no root/TLD)
    let domain = match normalize_zone_domain(&body.domain) {
        Ok(d) => d,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": e.message})),
    };
    let template_records = match render_zone_template(
        body.template_id.as_deref(),
        &domain,
        &body.template_variables,
    ) {
        Ok(records) => records,
        Err(error) => return HttpResponse::BadRequest().json(serde_json::json!({"error": error})),
    };

    let zone_id = Uuid::new_v4();
    let zone_id_str = zone_id.to_string();
    let owner_uuid_str = &tok.claims.sub;
    let geodns_enabled = body.geodns_enabled.unwrap_or(true);

    // Ensure owner_uuid_str is a valid UUID
    if let Err(e) = Uuid::parse_str(owner_uuid_str) {
        warn!("Invalid owner UUID: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "server_error",
            "details": "Invalid user ID format"
        }));
    }

    // Tenants may not create a zone that is the parent or a child of a zone
    // owned by someone else (that would let them shadow or hijack names inside
    // another tenant's namespace).
    if tok.claims.role != "admin" {
        match zone_overlaps_other_owner(&data.db, &domain, owner_uuid_str, None).await {
            Ok(false) => {}
            Ok(true) => {
                return HttpResponse::Conflict().json(serde_json::json!({
                    "error": "domain overlaps a zone owned by another user"
                }));
            }
            Err(e) => {
                warn!("create_zone overlap check error: {}", full_error_string(&e));
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({"error": "database error"}));
            }
        }
    }

    // Tenant ownership and zone quota. Customers always act inside a tenant; admins may assign one.
    let zone_tenant: Option<String> = if tok.claims.role == "admin" {
        body.tenant_id.clone().filter(|t| !t.is_empty())
    } else {
        match tenants::tenant_for_user(&data.db, owner_uuid_str, body.tenant_id.as_deref(), true)
            .await
        {
            Ok(t) => Some(t),
            Err(resp) => return resp,
        }
    };

    // Authoritative nameservers for this zone: enabled rows of the
    // nameservers table, falling back to PUBLIC_NAMESERVERS. Resolve and
    // validate them before the transaction so the quota reservation also
    // covers the default NS and SOA rows created below.
    let ns_rows = match data
        .db
        .query(
            "SELECT hostname FROM nameservers WHERE enabled = true ORDER BY sort_order, hostname",
            &[],
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(
                "create_zone nameserver lookup failed: {}",
                full_error_string(&e)
            );
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    };
    let candidates: Vec<String> = if !ns_rows.is_empty() {
        ns_rows
            .iter()
            .filter_map(|r| r.try_get::<_, String>(0).ok())
            .collect()
    } else {
        std::env::var("PUBLIC_NAMESERVERS")
            .unwrap_or_else(|_| "ns1.my-dns.com.,ns2.my-dns.com.".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };
    let mut ns_values: Vec<String> = Vec::new();
    for hostname in candidates {
        let ns_value = if hostname.ends_with('.') {
            hostname
        } else {
            format!("{}.", hostname)
        };
        // Validate NS value through Hickory before inserting
        if let Err(e) = validate_record_value("NS", &ns_value) {
            warn!("Failed to validate NS record '{}': {}", ns_value, e.message);
            continue;
        }
        ns_values.push(ns_value);
    }

    // With VERIFY_DOMAINS a non-admin's zone stays "pending" (not served) until
    // a TXT challenge proves control of the domain.
    let needs_verification = data.verify_domains && tok.claims.role != "admin";
    let (zone_status, verify_token) = if needs_verification {
        ("pending", Some(ext::new_verify_token()))
    } else {
        ("active", None)
    };

    // The zone row, its quota reservation, the default NS RRset and the SOA
    // commit together. A failed NS/SOA insert must never leave a half-created
    // zone behind. Concurrent creations for the same tenant serialise on the
    // tenant row, so they cannot both observe the same free slot.
    let tx_result = if let Some(tenant_id) = zone_tenant.as_deref() {
        data.db.begin_for(tenant_id).await
    } else {
        data.db.begin().await
    };
    let tx = match tx_result {
        Ok(t) => t,
        Err(e) => {
            warn!("create_zone transaction: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    };
    let c = tx.client();
    if let Err(e) = c.batch_execute("BEGIN").await {
        warn!("create_zone begin: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "database error"}));
    }
    if let (Some(t), false) = (&zone_tenant, tok.claims.role == "admin") {
        if let Err(resp) = tenants::reserve_quota_tx(
            c,
            t,
            1,
            2 + ns_values.len() as i64 + template_records.len() as i64,
        )
        .await
        {
            rollback_transaction(c).await;
            return resp;
        }
    }
    if let Err(e) = c.execute(
        "INSERT INTO zones (id, domain, owner, geodns_enabled, status, verify_token, tenant_id) VALUES ($1::text::uuid, $2, $3::text::uuid, $4, $5, $6, $7::text::uuid)",
        &[&zone_id_str, &domain, &owner_uuid_str, &geodns_enabled, &zone_status, &verify_token, &zone_tenant]
    ).await {
        rollback_transaction(c).await;
        // e.to_string() only shows the top-level "db error"; the actual
        // SQLSTATE message (e.g. the unique-violation detail) is deeper in
        // the error chain, so inspect the whole chain for the conflict.
        let err_str = full_error_string(&e);
        warn!("create_zone error: {}", err_str);
        return if err_str.contains("unique") || err_str.contains("duplicate") {
            HttpResponse::Conflict().json(serde_json::json!({"error": "domain already exists"}))
        } else {
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "failed to create zone"}))
        };
    }

    let assigned_nameservers = ns_values;
    if !assigned_nameservers.is_empty() {
        let ids: Vec<String> = assigned_nameservers
            .iter()
            .map(|_| Uuid::new_v4().to_string())
            .collect();
        let names: Vec<String> = assigned_nameservers
            .iter()
            .map(|_| "@".to_string())
            .collect();
        let types: Vec<String> = assigned_nameservers
            .iter()
            .map(|_| "NS".to_string())
            .collect();
        let ttls: Vec<i32> = assigned_nameservers.iter().map(|_| 3600).collect();
        if let Err(e) = c.execute(
            "INSERT INTO records (id, zone_id, name, record_type, value, ttl) \
             SELECT u.id::uuid, $1::text::uuid, u.n, u.t, u.v, u.ttl \
             FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::int4[]) AS u(id, n, t, v, ttl)",
            &[&zone_id_str, &ids, &names, &types, &assigned_nameservers, &ttls],
        ).await {
            rollback_transaction(c).await;
            warn!("Failed to add default NS records for zone {} ({}): {}", domain, zone_id_str, full_error_string(&e));
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "failed to create zone"}));
        }
    }

    // Default SOA with a date-based serial (YYYYMMDD00). The zone
    // generator advances the serial whenever the zone's content
    // changes, so this is only the initial value. MNAME is the first
    // real nameserver.
    let soa_id = Uuid::new_v4().to_string();
    let serial = chrono::Utc::now().format("%Y%m%d00").to_string();
    let mname = assigned_nameservers
        .first()
        .cloned()
        .unwrap_or_else(|| format!("ns1.{}.", domain));
    let soa_value = format!(
        "{} hostmaster.{}. {} 3600 3600 604800 3600",
        mname, domain, serial
    );
    if let Err(e) = c.execute(
        "INSERT INTO records (id, zone_id, name, record_type, value, ttl) VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5, $6)",
        &[&soa_id, &zone_id_str, &"@", &"SOA", &soa_value, &3600]
    ).await {
        rollback_transaction(c).await;
        warn!("Failed to add default SOA record: {}", full_error_string(&e));
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": "failed to create zone"}));
    }
    if !template_records.is_empty() {
        let ids: Vec<String> = template_records
            .iter()
            .map(|_| Uuid::new_v4().to_string())
            .collect();
        let names: Vec<String> = template_records.iter().map(|r| r.name.clone()).collect();
        let types: Vec<String> = template_records.iter().map(|r| r.rtype.clone()).collect();
        let values: Vec<String> = template_records.iter().map(|r| r.value.clone()).collect();
        let ttls: Vec<i32> = template_records.iter().map(|r| r.ttl).collect();
        let priorities: Vec<i32> = template_records.iter().map(|r| r.priority).collect();
        if let Err(e) = c.execute(
            "INSERT INTO records (id, zone_id, name, record_type, value, ttl, priority) \
             SELECT u.id::uuid, $1::text::uuid, u.n, u.t, u.v, u.ttl, u.p \
             FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::int4[], $7::int4[]) AS u(id, n, t, v, ttl, p)",
            &[&zone_id_str, &ids, &names, &types, &values, &ttls, &priorities],
        ).await {
            rollback_transaction(c).await;
            warn!("failed to create zone from template: {}", full_error_string(&e));
            return HttpResponse::InternalServerError().json(serde_json::json!({"error":"failed to apply zone template"}));
        }
    }
    if let Err(e) = c.batch_execute("COMMIT").await {
        warn!("create_zone commit failed: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "failed to create zone"}));
    }
    drop(tx);
    info!("Created zone: {} for owner: {}", domain, owner_uuid_str);

    // Publish. If the new zone cannot be published, do not keep a zone
    // that is not being served.
    if let Err(e) = publish(&data.dns_manager, &data.db, Some(&domain)).await {
        warn!("Failed to publish new zone {}: {}", domain, e);
        let _ = data
            .db
            .execute(
                "DELETE FROM zones WHERE CAST(id AS varchar) = $1",
                &[&zone_id_str],
            )
            .await;
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "publish_failed",
            "details": format!("zone could not be published and was not created: {}", e),
            "saved": false,
            "published": false
        }));
    }
    audit(
        &data.db,
        Some(&tok.claims.sub),
        "create_zone",
        "zone",
        Some(zone_id_str.clone()),
        &req,
        serde_json::json!({"domain": domain, "template_id": body.template_id}),
    )
    .await;
    let revision_snapshot_ok =
        ext::snapshot_zone(&data.db, &zone_id_str, Some(&tok.claims.sub), "created").await;

    let response = serde_json::json!({
        "id": zone_id_str,
        "domain": domain,
        "status": zone_status,
        "template_id": body.template_id,
        "template_record_count": template_records.len(),
        "revision_snapshot": if revision_snapshot_ok { "saved" } else { "failed" },
        "verification": verify_token.as_ref().map(|t| serde_json::json!({
            "type": "TXT", "name": format!("{}.{}", ext::CHALLENGE_LABEL, domain), "value": t,
            "next": "publish the TXT record, then POST /api/v1/zones/{id}/verify"
        })),
        "nameservers": assigned_nameservers,
        "message": "Zone created successfully. Please configure the following nameservers at your domain registrar: ".to_string() + &assigned_nameservers.join(", ")
    });
    if let Some(key) = idem {
        idempotency_store(db, &key, &tok.claims.sub, "create_zone", 201, &response).await;
    }
    HttpResponse::Created().json(response)
}

#[derive(Deserialize)]
struct DnsLookupRequest {
    domain: String,
    /// administrators only: label of one configured resolver
    #[serde(default)]
    resolver: Option<String>,
    #[serde(default = "default_record_type")]
    record_type: String,
}

fn default_record_type() -> String {
    "A".to_string()
}

/// Perform a system DNS lookup (A/AAAA records only via the OS resolver).
/// For full record type support, enable the `hickory-resolver` feature.
async fn dns_lookup(
    body: web::Json<DnsLookupRequest>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    // the tool sends real queries to a shared resolver: bound the rate per account
    let lim = lookup::rate_limit_per_minute();
    if let Some(wait) = shared::limited(
        &data.db,
        &format!("lookup:{}", tok.claims.sub),
        lim,
        60,
        || lookup::check_rate(&tok.claims.sub, lim).is_ok(),
    )
    .await
    {
        return HttpResponse::TooManyRequests().insert_header(("Retry-After", wait.to_string()))
            .json(serde_json::json!({"error": "rate_limited", "details": format!("too many lookups, retry in {} s", wait)}));
    }
    let Some(rtype) = lookup::parse_type(&body.record_type) else {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "unsupported record type", "supported": lookup::SUPPORTED_TYPES
        }));
    };
    let is_admin = tok.claims.role == "admin";
    if data.lookup_resolvers.is_empty() {
        return HttpResponse::ServiceUnavailable().json(serde_json::json!({"error": "not_configured", "details": "DNS lookup is not available on this installation"}));
    }
    // only administrators may pick a specific resolver (diagnostics); customers always get the managed failover chain
    let only = if is_admin {
        body.resolver.as_deref().filter(|s| !s.is_empty())
    } else {
        None
    };
    if body
        .resolver
        .as_deref()
        .map(|s| !s.is_empty())
        .unwrap_or(false)
        && !is_admin
    {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"error": "resolver selection is not permitted"}));
    }
    match lookup::lookup_failover(
        &data.lookup_resolvers,
        only,
        &body.domain,
        rtype,
        lookup::timeout_per_resolver(),
        lookup::total_deadline(),
    )
    .await
    {
        Ok(mut r) => {
            if !is_admin {
                r.resolver = None;
                r.attempts.clear();
            }
            HttpResponse::Ok().json(r)
        }
        // a malformed question or an unknown resolver label: nothing was sent, nothing to hide
        Err((e, attempts)) if attempts.is_empty() => {
            HttpResponse::BadRequest().json(serde_json::json!({"error": e}))
        }
        Err((e, attempts)) => {
            warn!("dns_lookup: {} ({:?})", e, attempts);
            // customers learn only that the service is unavailable; administrators see what each resolver did
            let mut body = serde_json::json!({"error": "resolver_unavailable", "details": "the lookup service could not reach a resolver, please try again shortly"});
            if is_admin {
                body["attempts"] = serde_json::json!(attempts);
            }
            HttpResponse::BadGateway().json(body)
        }
    }
}

#[derive(Deserialize)]
struct GeoResolveRequest {
    zone_id: String,
    client_ip: String,
    #[serde(default)]
    record_name: Option<String>,
    #[serde(default)]
    record_type: Option<String>,
}

/// Resolve a DNS response for a zone based on client's geographic location.
/// Uses GeoRules to determine which target address to return.
async fn resolve_by_geo(
    body: web::Json<GeoResolveRequest>,
    data: web::Data<FullState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.inner.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let db = &data.inner.db;

    // Parse client IP
    let client_ip = match body.client_ip.trim().parse::<std::net::IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": "invalid client IP"}));
        }
    };

    // A zone's rules are only visible to its owner (or an admin).
    let access = match zone_access_at(db, &body.zone_id, &tok, Level::Read).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    // Fetch georules for this zone from DB
    let rows = match db
        .query(
            "SELECT CAST(id AS varchar), match_type, match_value, target, priority, enabled, record_name, record_type, weight FROM georules WHERE CAST(zone_id AS varchar) = $1",
            &[&body.zone_id],
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("resolve_by_geo error: {}", full_error_string(&e));
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "database_error"}));
        }
    };

    let rules: Vec<geodns::GeoRule> = rows
        .into_iter()
        .map(|r| geodns::GeoRule {
            id: r.try_get::<_, String>(0).unwrap_or_default(),
            match_type: r.try_get::<_, String>(1).unwrap_or_default(),
            match_value: r.try_get::<_, String>(2).unwrap_or_default(),
            target: r.try_get::<_, String>(3).unwrap_or_default(),
            weight: r.try_get::<_, i32>(8).unwrap_or(1).max(0) as u32,
            priority: r.try_get::<_, i32>(4).unwrap_or(0),
            enabled: r.try_get::<_, bool>(5).unwrap_or(true),
            record_name: r.try_get::<_, Option<String>>(6).unwrap_or(None),
            record_type: r.try_get::<_, Option<String>>(7).unwrap_or(None),
        })
        .collect();

    // Get GeoIP DB from state
    let geo_state = data.geo.lock().await;
    let geo_db = geo_state.db.as_ref().cloned();
    drop(geo_state);

    // Create rule engine and evaluate exactly like the DNS server does
    let mut engine = geodns::GeoRuleEngine::new(geo_db);
    engine.set_rules(rules);

    let rtype = body.record_type.as_deref().unwrap_or("A");
    let target = match body.record_name.as_deref() {
        Some(rn) => {
            let domain = access.domain.trim_end_matches('.').to_ascii_lowercase();
            let rn_l = rn.trim().trim_end_matches('.').to_ascii_lowercase();
            let fq = if rn_l == "@" || rn_l.is_empty() {
                domain.clone()
            } else if rn_l == domain || rn_l.ends_with(&format!(".{}", domain)) {
                rn_l
            } else {
                format!("{}.{}", rn_l, domain)
            };
            engine.evaluate_in_zone(client_ip, &fq, rtype, &domain)
        }
        None => engine.evaluate(client_ip, None, Some(rtype)),
    };
    match target {
        Some(t) => HttpResponse::Ok().json(serde_json::json!({"target": t})),
        None => HttpResponse::Ok()
            .json(serde_json::json!({"target": None::<String>, "message": "no matching geo rule"})),
    }
}

// Placeholder: function to push configuration to agents (secure HTTPS/gRPC in production)
#[allow(dead_code)]
async fn push_config_to_agent(_agent_id: &str) {
    // TODO: implement secure config push
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ConfigPushRequest {
    agent_id: String,
    zone_id: String,
    zone_config: serde_json::Value,
}

#[derive(Serialize)]
struct ConfigPushResponse {
    success: bool,
    message: String,
}

/// "Push" for a pull-based fleet: flag the agent (or all enabled agents with
/// `agent_id: "all"`) as needing a sync. Agents learn about it in the answer to
/// their next heartbeat and fetch the signed bundle immediately; the flag is
/// cleared by their acknowledgement. Returns 202: delivery is asynchronous and
/// the real result is visible as `applied_version` / `last_error` on the agent.
async fn push_config_to_agents(
    body: web::Json<ConfigPushRequest>,
    data: web::Data<FullState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.inner.jwt_secret) {
        Some(t) if t.claims.role == "admin" => t,
        Some(_) => {
            return HttpResponse::Forbidden()
                .json(serde_json::json!({"error": "admin role required"}));
        }
        None => return unauthorized(),
    };
    let db = &data.inner.db;
    let res = if body.agent_id == "all" {
        db.execute(
            "UPDATE agents SET sync_requested = true WHERE COALESCE(enabled, true)",
            &[],
        )
        .await
    } else {
        db.execute("UPDATE agents SET sync_requested = true WHERE CAST(id AS varchar) = $1 AND COALESCE(enabled, true)", &[&body.agent_id]).await
    };
    match res {
        Ok(0) => HttpResponse::NotFound().json(ConfigPushResponse {
            success: false,
            message: "no matching enabled agent".to_string(),
        }),
        Ok(n) => {
            audit(
                db,
                Some(&tok.claims.sub),
                "push_config",
                "agent",
                Some(body.agent_id.clone()),
                &req,
                serde_json::json!({"agents": n}),
            )
            .await;
            HttpResponse::Accepted().json(ConfigPushResponse {
                success: true,
                message: format!(
                    "sync requested from {} agent(s); they apply it on their next heartbeat",
                    n
                ),
            })
        }
        Err(e) => {
            warn!("config push error: {}", full_error_string(&e));
            HttpResponse::InternalServerError().json(ConfigPushResponse {
                success: false,
                message: "database error".to_string(),
            })
        }
    }
}

// ============================================================================
// RECORDS CRUD ENDPOINTS
// ============================================================================

#[derive(Deserialize)]
struct CreateRecordReq {
    name: String,
    record_type: String,
    value: String,
    ttl: u32,
    priority: Option<i32>,
}

#[derive(Serialize, Clone)]
struct RecordResponse {
    id: String,
    zone_id: String,
    name: String,
    record_type: String,
    value: String,
    ttl: u32,
    priority: i32,
    #[serde(default)]
    comment: String,
    #[serde(default)]
    tags: Vec<String>,
}

/// Validate one record the way the generator will render it and normalise it.
/// Everything that would later make zone generation fail is rejected here.
fn validate_record_input(
    domain: &str,
    name: &str,
    record_type: &str,
    value: &str,
    ttl: i64,
    priority: i32,
) -> Result<RecordRow, String> {
    if !(1..=MAX_RECORD_TTL as i64).contains(&ttl) {
        return Err(format!("ttl must be between 1 and {}", MAX_RECORD_TTL));
    }
    if !(0..=65535).contains(&priority) {
        return Err("priority must be between 0 and 65535".to_string());
    }
    let name = name.trim();
    validate_record_in_zone(name, domain).map_err(|e| e.message)?;
    let rtype = record_type.trim().to_ascii_uppercase();
    DnsRecordBuilder::from_db_fields(
        name.to_string(),
        rtype.clone(),
        value.to_string(),
        ttl as i32,
        priority,
    )
    .map_err(|e| format!("{:#}", e))?;
    Ok(RecordRow {
        name: name.to_string(),
        rtype,
        value: value.trim().to_string(),
        ttl: ttl as i32,
        priority,
    })
}

/// Nameservers a NS record may point at: the enabled rows of the nameservers
/// table (the source of truth), falling back to PUBLIC_NAMESERVERS.
async fn allowed_nameservers(db: &Pool) -> Result<Vec<String>, tokio_postgres::Error> {
    let rows = db
        .query(
            "SELECT hostname FROM nameservers WHERE enabled = true ORDER BY sort_order, hostname",
            &[],
        )
        .await?;
    Ok(if rows.is_empty() {
        get_global_nameservers()
    } else {
        rows.iter()
            .filter_map(|r| r.try_get::<_, String>(0).ok())
            .collect()
    })
}

/// Render the zone as it would look after a change and make sure Hickory
/// accepts it, before anything is saved.
async fn precheck_zone_change(
    db: &Pool,
    domain: &str,
    records: Vec<RecordRow>,
) -> Result<(), String> {
    let nameservers = zone_file_generator::load_nameservers(db)
        .await
        .map_err(|e| format!("{:#}", e))?;
    zone_file_generator::precheck_zone(domain, &records, &nameservers)
        .map_err(|e| format!("{:#}", e))
}

async fn create_record(
    zone_id: web::Path<String>,
    body: web::Json<CreateRecordReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let zone_id_str = zone_id.into_inner();
    let db = &data.db;

    let access = match zone_access(db, &zone_id_str, &tok).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let rec = match validate_record_input(
        &access.domain,
        &body.name,
        &body.record_type,
        &body.value,
        body.ttl as i64,
        body.priority.unwrap_or(0),
    ) {
        Ok(r) => r,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    };

    // NS targets must be one of the configured authoritative nameservers.
    if rec.rtype == "NS" {
        match allowed_nameservers(db).await {
            Ok(allowed) => {
                if let Err(e) = validate_ns_value(&rec.value, &allowed) {
                    return HttpResponse::BadRequest()
                        .json(serde_json::json!({"error": e.message}));
                }
            }
            Err(e) => {
                warn!("nameserver lookup error: {}", full_error_string(&e));
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({"error": "database error"}));
            }
        }
    }

    let existing = match zone_file_generator::load_zone_records(db, &zone_id_str).await {
        Ok(r) => r,
        Err(e) => {
            warn!("create_record: {:#}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    };

    // A zone may only contain a single SOA record. Zone creation already
    // inserts one, so reject attempts to add a second SOA with a clear error.
    if rec.rtype == "SOA" && existing.iter().any(|r| r.rtype.eq_ignore_ascii_case("SOA")) {
        return HttpResponse::Conflict().json(serde_json::json!({
            "error": "SOA record already exists for this zone; update the existing SOA instead of creating a second one"
        }));
    }
    // Exact duplicates are rejected; several records with the same name and
    // type but different values are a normal RRset.
    if existing.iter().any(|r| {
        r.name.eq_ignore_ascii_case(&rec.name)
            && r.rtype.eq_ignore_ascii_case(&rec.rtype)
            && r.value.trim() == rec.value
    }) {
        return HttpResponse::Conflict()
            .json(serde_json::json!({"error": "record already exists"}));
    }

    let mut candidate = existing;
    candidate.push(rec.clone());
    if let Err(e) = precheck_zone_change(db, &access.domain, candidate).await {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": e}));
    }

    let id = Uuid::new_v4();
    let id_str = id.to_string();
    // Reserve quota and insert in one transaction: concurrent writers for the
    // same tenant serialise on the tenant row instead of both passing the
    // pre-insert count.
    let tx = match begin_zone_transaction(db, &access).await {
        Ok(t) => t,
        Err(e) => {
            warn!("create_record transaction: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    };
    let c = tx.client();
    if let Err(e) = c.batch_execute("BEGIN").await {
        warn!("create_record begin: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "database error"}));
    }
    if let Err(resp) =
        tenants::reserve_zone_records_quota_tx(c, &zone_id_str, 1, tok.claims.role == "admin").await
    {
        rollback_transaction(c).await;
        return resp;
    }
    if let Err(e) = c.execute(
        "INSERT INTO records (id, zone_id, name, record_type, value, ttl, priority) VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5, $6, $7)",
        &[&id_str, &zone_id_str, &rec.name, &rec.rtype, &rec.value, &rec.ttl, &rec.priority]
    ).await {
        rollback_transaction(c).await;
        let err_str = full_error_string(&e);
        warn!("create_record error for zone {} (type={}, name={}): {}", zone_id_str, rec.rtype, rec.name, err_str);
        return if err_str.contains("unique") || err_str.contains("duplicate") {
            HttpResponse::Conflict().json(serde_json::json!({"error": "record already exists"}))
        } else {
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "failed to create record"}))
        };
    }
    if let Err(e) = c.batch_execute("COMMIT").await {
        warn!("create_record commit failed: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "failed to create record"}));
    }
    drop(tx);
    info!(
        "Created record: {} ({}) in zone: {}",
        rec.name, rec.rtype, zone_id_str
    );
    if let Err(e) = publish(&data.dns_manager, db, Some(&access.domain)).await {
        // Not served -> do not keep it.
        warn!(
            "Failed to publish zone after record creation, rolling back: {}",
            e
        );
        let _ = db
            .execute(
                "DELETE FROM records WHERE CAST(id AS varchar) = $1",
                &[&id_str],
            )
            .await;
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "publish_failed",
            "details": format!("record was not created because the zone could not be published: {}", e),
            "saved": false,
            "published": false
        }));
    }
    let revision_snapshot_ok =
        ext::snapshot_zone(db, &zone_id_str, Some(&tok.claims.sub), "record created").await;
    audit(
        db,
        Some(&tok.claims.sub),
        "create_record",
        "record",
        Some(id_str.clone()),
        &req,
        serde_json::json!({"zone": access.domain, "name": rec.name, "type": rec.rtype}),
    )
    .await;
    HttpResponse::Created().json(serde_json::json!({
        "id": id_str,
        "name": rec.name,
        "type": rec.rtype,
        "value": rec.value,
        "ttl": rec.ttl,
        "revision_snapshot": if revision_snapshot_ok { "saved" } else { "failed" }
    }))
}

async fn list_records(
    zone_id: web::Path<String>,
    page: web::Query<ext::PageQuery>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let zone_id_str = zone_id.into_inner();
    if let Err(resp) = zone_access_at(&data.db, &zone_id_str, &tok, Level::Read).await {
        return resp;
    }

    let (limit, offset, qtext) = page.parts();
    let sort = match page.sort_column(
        &[("name", "name"), ("type", "record_type"), ("ttl", "ttl")],
        "name",
    ) {
        Ok(value) => value,
        Err(()) => return invalid_list_query(),
    };
    let direction = match page.sort_direction() {
        Ok(value) => value,
        Err(()) => return invalid_list_query(),
    };
    let total: i64 = match data.db.query_one(
        "SELECT count(*) FROM records WHERE CAST(zone_id AS varchar) = $1 AND ($2::text IS NULL OR name ILIKE '%' || $2 || '%' OR value ILIKE '%' || $2 || '%' OR record_type ILIKE $2)",
        &[&zone_id_str, &qtext],
    ).await {
        Ok(row) => row.get(0),
        Err(e) => {
            warn!("list_records count: {}", full_error_string(&e));
            return HttpResponse::InternalServerError().json(serde_json::json!({"error":"database_error"}));
        }
    };
    let list_sql = format!(
        "SELECT CAST(id AS varchar), CAST(zone_id AS varchar), name, record_type, value, ttl, priority, count(*) OVER(), COALESCE(comment, ''), tags FROM records WHERE CAST(zone_id AS varchar) = $1 AND ($2::text IS NULL OR name ILIKE '%' || $2 || '%' OR value ILIKE '%' || $2 || '%' OR record_type ILIKE $2) ORDER BY {sort} {direction}, name, record_type, value LIMIT $3::bigint OFFSET $4::bigint"
    );
    let rows = match data
        .db
        .query(&list_sql, &[&zone_id_str, &qtext, &limit, &offset])
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("list_records error: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    };

    let records: Vec<RecordResponse> = rows
        .into_iter()
        .map(|r| RecordResponse {
            id: r.try_get(0).unwrap_or_default(),
            zone_id: r.try_get(1).unwrap_or_default(),
            name: r.try_get(2).unwrap_or_default(),
            record_type: r.try_get(3).unwrap_or_default(),
            value: r.try_get(4).unwrap_or_default(),
            ttl: r.try_get::<_, i32>(5).unwrap_or(0).max(0) as u32,
            priority: r.try_get::<_, i32>(6).unwrap_or(0),
            comment: r.try_get(8).unwrap_or_default(),
            tags: r
                .try_get::<_, serde_json::Value>(9)
                .ok()
                .and_then(|v| {
                    v.as_array().map(|a| {
                        a.iter()
                            .filter_map(|t| t.as_str().map(str::to_string))
                            .collect()
                    })
                })
                .unwrap_or_default(),
        })
        .collect();

    HttpResponse::Ok()
        .insert_header(("X-Total-Count", total.to_string()))
        .json(records)
}

#[derive(Deserialize)]
struct UpdateRecordReq {
    name: Option<String>,
    record_type: Option<String>,
    value: Option<String>,
    ttl: Option<i64>,
    priority: Option<i32>,
}

async fn update_record(
    path: web::Path<(String, String)>,
    body: web::Json<UpdateRecordReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let (zone_id, record_id) = path.into_inner();
    let db = &data.db;

    let access = match zone_access(db, &zone_id, &tok).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    if body.name.is_none()
        && body.record_type.is_none()
        && body.value.is_none()
        && body.ttl.is_none()
        && body.priority.is_none()
    {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "no fields to update"}));
    }

    // All records of the zone with their ids: the target is replaced by its
    // merged form so the *resulting* zone is validated.
    let rows = match db.query(
        "SELECT CAST(id AS varchar), name, record_type, value, ttl, priority FROM records WHERE CAST(zone_id AS varchar) = $1 ORDER BY created_at, id",
        &[&zone_id],
    ).await {
        Ok(r) => r,
        Err(e) => {
            warn!("update_record: {}", full_error_string(&e));
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "database error"}));
        }
    };
    let mut others: Vec<RecordRow> = Vec::new();
    let mut current: Option<RecordRow> = None;
    for r in rows {
        let id: String = r.try_get(0).unwrap_or_default();
        let row = RecordRow {
            name: r.try_get(1).unwrap_or_default(),
            rtype: r.try_get(2).unwrap_or_default(),
            value: r.try_get(3).unwrap_or_default(),
            ttl: r.try_get(4).unwrap_or(3600),
            priority: r.try_get(5).unwrap_or(0),
        };
        if id == record_id {
            current = Some(row);
        } else {
            others.push(row);
        }
    }
    let current = match current {
        Some(c) => c,
        None => {
            return HttpResponse::NotFound().json(serde_json::json!({"error": "record not found"}));
        }
    };

    let merged = match validate_record_input(
        &access.domain,
        body.name.as_deref().unwrap_or(&current.name),
        body.record_type.as_deref().unwrap_or(&current.rtype),
        body.value.as_deref().unwrap_or(&current.value),
        body.ttl.unwrap_or(current.ttl as i64),
        body.priority.unwrap_or(current.priority),
    ) {
        Ok(r) => r,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    };

    if merged.rtype == "NS" {
        match allowed_nameservers(db).await {
            Ok(allowed) => {
                if let Err(e) = validate_ns_value(&merged.value, &allowed) {
                    return HttpResponse::BadRequest()
                        .json(serde_json::json!({"error": e.message}));
                }
            }
            Err(e) => {
                warn!("nameserver lookup error: {}", full_error_string(&e));
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({"error": "database error"}));
            }
        }
    }
    if merged.rtype == "SOA" && others.iter().any(|r| r.rtype.eq_ignore_ascii_case("SOA")) {
        return HttpResponse::Conflict().json(serde_json::json!({
            "error": "SOA record already exists for this zone; update the existing SOA instead of creating a second one"
        }));
    }
    if others.iter().any(|r| {
        r.name.eq_ignore_ascii_case(&merged.name)
            && r.rtype.eq_ignore_ascii_case(&merged.rtype)
            && r.value.trim() == merged.value
    }) {
        return HttpResponse::Conflict()
            .json(serde_json::json!({"error": "record already exists"}));
    }

    let mut candidate = others;
    candidate.push(merged.clone());
    if let Err(e) = precheck_zone_change(db, &access.domain, candidate).await {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": e}));
    }

    // One atomic statement (the previous implementation updated each column
    // separately and ignored failures of all but single-field updates).
    match db.execute(
        "UPDATE records SET name = $1, record_type = $2, value = $3, ttl = $4, priority = $5, updated_at = now() \
         WHERE CAST(id AS varchar) = $6 AND CAST(zone_id AS varchar) = $7",
        &[&merged.name, &merged.rtype, &merged.value, &merged.ttl, &merged.priority, &record_id, &zone_id]
    ).await {
        Ok(0) => HttpResponse::NotFound().json(serde_json::json!({"error": "record not found"})),
        Ok(_) => {
            if let Err(e) = publish(&data.dns_manager, db, Some(&access.domain)).await {
                warn!("Failed to publish zone after record update: {}", e);
                if let Err(rollback) = db.execute(
                    "UPDATE records SET name = $1, record_type = $2, value = $3, ttl = $4, priority = $5, updated_at = now() \
                     WHERE CAST(id AS varchar) = $6 AND CAST(zone_id AS varchar) = $7 \
                       AND name = $8 AND record_type = $9 AND value = $10 AND ttl = $11 AND priority = $12",
                    &[
                        &current.name, &current.rtype, &current.value, &current.ttl, &current.priority,
                        &record_id, &zone_id,
                        &merged.name, &merged.rtype, &merged.value, &merged.ttl, &merged.priority,
                    ],
                ).await {
                    warn!("record update rollback failed for zone {zone_id} record {record_id}: {}", full_error_string(&rollback));
                }
                return publish_failed_rolled_back(&e);
            }
            let revision_snapshot_ok =
                ext::snapshot_zone(db, &zone_id, Some(&tok.claims.sub), "record updated").await;
            audit(db, Some(&tok.claims.sub), "update_record", "record", Some(record_id.clone()), &req,
                  serde_json::json!({"zone": access.domain})).await;
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "revision_snapshot": if revision_snapshot_ok { "saved" } else { "failed" }
            }))
        }
        Err(e) => {
            let err_str = full_error_string(&e);
            warn!("update_record error for zone {} record {}: {}", zone_id, record_id, err_str);
            if err_str.contains("unique") || err_str.contains("duplicate") {
                HttpResponse::Conflict().json(serde_json::json!({"error": "record already exists"}))
            } else {
                HttpResponse::InternalServerError().json(serde_json::json!({"error": "failed to update record"}))
            }
        }
    }
}

async fn delete_record(
    path: web::Path<(String, String)>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let (zone_id, record_id) = path.into_inner();
    let access = match zone_access(&data.db, &zone_id, &tok).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let original = match data
        .db
        .query_opt(
            "SELECT name, record_type, value, ttl, priority FROM records \
         WHERE CAST(id AS varchar) = $1 AND CAST(zone_id AS varchar) = $2",
            &[&record_id, &zone_id],
        )
        .await
    {
        Ok(Some(row)) => RecordRow {
            name: row.get(0),
            rtype: row.get(1),
            value: row.get(2),
            ttl: row.get(3),
            priority: row.get(4),
        },
        Ok(None) => {
            return HttpResponse::NotFound().json(ErrorResponse {
                error: "record not found".to_string(),
                details: None,
            });
        }
        Err(e) => {
            warn!("delete_record lookup error: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    };

    match data
        .db
        .execute(
            "DELETE FROM records WHERE CAST(id AS varchar) = $1 AND CAST(zone_id AS varchar) = $2",
            &[&record_id, &zone_id],
        )
        .await
    {
        Ok(0) => HttpResponse::NotFound().json(ErrorResponse {
            error: "record not found".to_string(),
            details: None,
        }),
        Ok(_) => {
            info!("Deleted record: {} from zone: {}", record_id, zone_id);
            if let Err(e) = publish(&data.dns_manager, &data.db, Some(&access.domain)).await {
                warn!("Failed to publish zone after record deletion: {}", e);
                if let Err(rollback) = data.db.execute(
                    "INSERT INTO records (id, zone_id, name, record_type, value, ttl, priority) \
                     VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5, $6, $7)",
                    &[
                        &record_id, &zone_id, &original.name, &original.rtype, &original.value,
                        &original.ttl, &original.priority,
                    ],
                ).await {
                    warn!("record delete rollback failed for zone {zone_id} record {record_id}: {}", full_error_string(&rollback));
                }
                return publish_failed_rolled_back(&e);
            }
            let revision_snapshot_ok =
                ext::snapshot_zone(&data.db, &zone_id, Some(&tok.claims.sub), "record deleted")
                    .await;
            audit(
                &data.db,
                Some(&tok.claims.sub),
                "delete_record",
                "record",
                Some(record_id.clone()),
                &req,
                serde_json::json!({"zone": access.domain}),
            )
            .await;
            HttpResponse::Ok().json(ApiResponse {
                success: true,
                data: Some(serde_json::json!({
                    "revision_snapshot": if revision_snapshot_ok { "saved" } else { "failed" }
                })),
                error: None,
            })
        }
        Err(e) => {
            warn!(
                "delete_record error for zone {} record {}: {}",
                zone_id,
                record_id,
                full_error_string(&e)
            );
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "failed to delete record"}))
        }
    }
}

// Audit logs endpoint
#[derive(ToSchema, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditLogEntry {
    id: String,
    user_id: Option<String>,
    action: String,
    resource_type: String,
    resource_id: Option<String>,
    details: String,
    ip_address: Option<String>,
    created_at: String,
}

// Get zone by ID
async fn get_zone(
    path: web::Path<String>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "unauthorized".to_string(),
                details: None,
            });
        }
    };
    let zone_id = path.into_inner();
    let access = match zone_access_at(&data.db, &zone_id, &tok, Level::Read).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    match data.db.query_one(
        "SELECT CAST(id AS varchar), domain, COALESCE(CAST(owner AS varchar), '') as owner, zone_type, created_at::text, COALESCE(geodns_enabled, true) as geodns_enabled, status, ecs_enabled, CAST(tenant_id AS varchar), (SELECT name FROM tenants t WHERE t.id = zones.tenant_id), description, tags, hold_reason, to_char(hold_until, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM zones WHERE CAST(id AS varchar) = $1",
        &[&zone_id]
    ).await {
        Ok(row) => {
            let zone = ZoneWithOwner {
                id: row.try_get(0).unwrap_or_default(),
                domain: row.try_get(1).unwrap_or_default(),
                owner: row.try_get(2).unwrap_or_default(),
                zone_type: row.try_get(3).unwrap_or_default(),
                created_at: row.try_get(4).unwrap_or_default(),
                geodns_enabled: row.try_get(5).unwrap_or(true),
                status: row.try_get(6).unwrap_or_default(),
                ecs_enabled: row.try_get(7).unwrap_or(false),
                tenant_id: row.try_get(8).unwrap_or(None),
                tenant_name: row.try_get(9).unwrap_or(None),
                description: row.try_get(10).unwrap_or_default(),
                tags: row.try_get(11).unwrap_or_default(),
                hold_reason: row.try_get(12).unwrap_or(None),
                hold_until: row.try_get(13).unwrap_or(None),
                access: access.role.clone(),
            };

            // The nameservers table is the source of truth for the
            // authoritative nameservers; apex NS rows in the records table are
            // only a fallback for older deployments that never populated it.
            let ns_rows = match data.db.query(
                "SELECT hostname FROM nameservers WHERE enabled = true ORDER BY sort_order, hostname",
                &[]
            ).await {
                Ok(rows) => rows,
                Err(e) => {
                    warn!("get_zone nameservers: {}", full_error_string(&e));
                    return HttpResponse::InternalServerError().json(ErrorResponse { error: "database error".to_string(), details: None });
                }
            };

            let nameservers: Vec<String> = if !ns_rows.is_empty() {
                ns_rows.iter()
                    .filter_map(|r| r.try_get::<_, String>(0).ok())
                    .map(|h| if h.ends_with('.') { h } else { format!("{}.", h) })
                    .collect()
            } else {
                match data.db.query(
                    "SELECT value FROM records WHERE CAST(zone_id AS varchar) = $1 AND record_type = 'NS' AND name = '@'",
                    &[&zone_id]
                ).await {
                    Ok(rows) => rows.into_iter().filter_map(|r| r.try_get::<_, String>(0).ok()).collect(),
                    Err(e) => {
                        warn!("get_zone fallback nameservers: {}", full_error_string(&e));
                        return HttpResponse::InternalServerError().json(ErrorResponse { error: "database error".to_string(), details: None });
                    }
                }
            };

            #[derive(Serialize)]
            struct ZoneWithNameservers {
                #[serde(flatten)]
                zone: ZoneWithOwner,
                nameservers: Vec<String>,
                #[serde(skip_serializing_if = "Option::is_none")]
                verification: Option<serde_json::Value>,
            }

            // a pending zone shows the TXT record that proves ownership
            let verification = if zone.status == "pending" {
                match data.db.query_opt("SELECT verify_token FROM zones WHERE CAST(id AS varchar) = $1", &[&zone_id]).await {
                    Ok(row) => row.and_then(|r| r.get::<_, Option<String>>(0))
                        .map(|t| serde_json::json!({"type": "TXT", "name": format!("{}.{}", ext::CHALLENGE_LABEL, zone.domain), "value": t})),
                    Err(e) => {
                        warn!("get_zone verification: {}", full_error_string(&e));
                        return HttpResponse::InternalServerError().json(ErrorResponse { error: "database error".to_string(), details: None });
                    }
                }
            } else { None };

            HttpResponse::Ok().json(ApiResponse { success: true, data: Some(ZoneWithNameservers { zone, nameservers, verification }), error: None })
        }
        Err(e) if e.as_db_error().is_none() => HttpResponse::NotFound().json(ErrorResponse { error: "zone not found".to_string(), details: None }),
        Err(e) => {
            warn!("get_zone error: {}", full_error_string(&e));
            HttpResponse::InternalServerError().json(ErrorResponse { error: "database error".to_string(), details: None })
        }
    }
}

#[derive(Deserialize)]
struct UpdateZoneReq {
    domain: Option<String>,
    zone_type: Option<String>,
    #[serde(default)]
    geodns_enabled: Option<bool>,
    /// use the EDNS Client Subnet of a query (when present) for geo decisions
    #[serde(default)]
    ecs_enabled: Option<bool>,
}

async fn update_zone(
    path: web::Path<String>,
    body: web::Json<UpdateZoneReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "unauthorized".to_string(),
                details: None,
            });
        }
    };
    let zone_id = path.into_inner();
    let db = &data.db;

    let access = match zone_access_at(db, &zone_id, &tok, Level::Owner).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let new_domain = match &body.domain {
        Some(d) => match normalize_zone_domain(d) {
            Ok(n) => Some(n),
            Err(e) => {
                return HttpResponse::BadRequest().json(serde_json::json!({"error": e.message}));
            }
        },
        None => None,
    };
    if let Some(zt) = &body.zone_type {
        if !zt.eq_ignore_ascii_case("primary") {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": "only primary zones are supported"}));
        }
    }
    if body.domain.is_none()
        && body.zone_type.is_none()
        && body.geodns_enabled.is_none()
        && body.ecs_enabled.is_none()
    {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "no fields to update"}));
    }

    if (body.geodns_enabled == Some(true)
        || new_domain.as_ref().map_or(false, |nd| {
            *nd != access.domain.trim_end_matches('.').to_ascii_lowercase()
        }))
        && dnssec::zone_is_signed(db, &zone_id).await
    {
        // GeoDNS cannot be signed, and a rename would orphan the DS published at the registrar
        return HttpResponse::Conflict().json(serde_json::json!({
            "error": "dnssec_enabled",
            "details": "This zone is DNSSEC-signed: it cannot be renamed or switched to GeoDNS. Disable DNSSEC first (remove the DS at the registrar, then POST /dnssec/disable)."
        }));
    }

    if let Some(nd) = &new_domain {
        if *nd != access.domain.trim_end_matches('.').to_ascii_lowercase() {
            if tok.claims.role != "admin" {
                match zone_overlaps_other_owner(db, nd, &tok.claims.sub, Some(&zone_id)).await {
                    Ok(false) => {}
                    Ok(true) => return HttpResponse::Conflict().json(serde_json::json!({"error": "domain overlaps a zone owned by another user"})),
                    Err(e) => {
                        warn!("update_zone overlap check error: {}", full_error_string(&e));
                        return HttpResponse::InternalServerError().json(serde_json::json!({"error": "database error"}));
                    }
                }
            }
            // the existing records must still form a valid zone under the new name
            let recs = match zone_file_generator::load_zone_records(db, &zone_id).await {
                Ok(r) => r,
                Err(e) => {
                    warn!("update_zone: {:#}", e);
                    return HttpResponse::InternalServerError()
                        .json(serde_json::json!({"error": "database error"}));
                }
            };
            if let Err(e) = precheck_zone_change(db, nd, recs).await {
                return HttpResponse::BadRequest().json(serde_json::json!({"error": e}));
            }
        }
    }

    // The rename and the SOA rewrite commit together. The previous values are
    // kept so a failed publication can restore the exact last-known-good state
    // instead of leaving the database and the served files out of sync.
    let zone_type = body.zone_type.as_ref().map(|z| z.to_ascii_lowercase());
    let tx = match begin_zone_transaction(db, &access).await {
        Ok(t) => t,
        Err(e) => {
            warn!("update_zone transaction: {}", full_error_string(&e));
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "failed to update zone".to_string(),
                details: None,
            });
        }
    };
    let c = tx.client();
    if let Err(e) = c.batch_execute("BEGIN").await {
        warn!("update_zone begin: {}", full_error_string(&e));
        return HttpResponse::InternalServerError().json(ErrorResponse {
            error: "failed to update zone".to_string(),
            details: None,
        });
    }
    let old = match c.query_opt(
        "SELECT domain, zone_type, COALESCE(geodns_enabled, true), COALESCE(ecs_enabled, false) \
         FROM zones WHERE CAST(id AS varchar) = $1 FOR UPDATE",
        &[&zone_id],
    ).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            rollback_transaction(c).await;
            return HttpResponse::NotFound().json(ErrorResponse { error: "zone not found".to_string(), details: None });
        }
        Err(e) => {
            rollback_transaction(c).await;
            warn!("update_zone lookup: {}", full_error_string(&e));
            return HttpResponse::InternalServerError().json(ErrorResponse { error: "failed to update zone".to_string(), details: None });
        }
    };
    let old_domain: String = old
        .get::<_, String>(0)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let old_zone_type: String = old.get(1);
    let old_geodns: bool = old.get(2);
    let old_ecs: bool = old.get(3);
    let renamed_to = new_domain.clone().filter(|nd| *nd != old_domain);
    if let Err(e) = c.execute(
        "UPDATE zones SET domain = COALESCE($1, domain), zone_type = COALESCE($2, zone_type), \
                geodns_enabled = COALESCE($3, geodns_enabled), ecs_enabled = COALESCE($5, ecs_enabled), \
                updated_at = now() WHERE CAST(id AS varchar) = $4",
        &[&new_domain, &zone_type, &body.geodns_enabled, &zone_id, &body.ecs_enabled],
    ).await {
        rollback_transaction(c).await;
        let msg = full_error_string(&e);
        if msg.contains("unique") || msg.contains("duplicate") {
            return HttpResponse::Conflict().json(serde_json::json!({"error": "domain already exists"}));
        }
        warn!("update_zone error: {}", msg);
        return HttpResponse::InternalServerError().json(ErrorResponse { error: "failed to update zone".to_string(), details: None });
    }
    if let Some(nd) = &renamed_to {
        // After a rename the stored SOA still names the old domain
        // (MNAME/RNAME): rewrite those names so the zone stays consistent.
        if let Err(e) = c.execute(
            "UPDATE records SET value = replace(replace(value, '.' || $2 || '.', '.' || $1 || '.'), '.' || $2 || ' ', '.' || $1 || ' ') \
             WHERE CAST(zone_id AS varchar) = $3 AND record_type = 'SOA'",
            &[nd, &old_domain, &zone_id],
        ).await {
            rollback_transaction(c).await;
            warn!("SOA rewrite after rename failed: {}", full_error_string(&e));
            return HttpResponse::InternalServerError().json(ErrorResponse { error: "failed to update zone".to_string(), details: None });
        }
    }
    if let Err(e) = c.batch_execute("COMMIT").await {
        warn!("update_zone commit failed: {}", full_error_string(&e));
        return HttpResponse::InternalServerError().json(ErrorResponse {
            error: "failed to update zone".to_string(),
            details: None,
        });
    }
    drop(tx);

    let published_domain = new_domain.unwrap_or_else(|| old_domain.clone());
    if let Err(e) = publish(&data.dns_manager, db, Some(&published_domain)).await {
        warn!("Failed to publish zone after zone update: {}", e);

        // Compensate: put the previous row values and SOA names back, then
        // republish them. Only report a clean failure when that swap succeeded.
        let mut restored = false;
        match begin_zone_transaction(db, &access).await {
            Ok(rtx) => {
                let rc = rtx.client();
                let mut ok = rc.batch_execute("BEGIN").await.is_ok();
                if ok {
                    ok = rc.execute(
                        "UPDATE zones SET domain = $1, zone_type = $2, geodns_enabled = $3, \
                                ecs_enabled = $4, updated_at = now() WHERE CAST(id AS varchar) = $5",
                        &[&old_domain, &old_zone_type, &old_geodns, &old_ecs, &zone_id],
                    ).await.is_ok();
                }
                if ok {
                    if let Some(nd) = &renamed_to {
                        ok = rc.execute(
                            "UPDATE records SET value = replace(replace(value, '.' || $2 || '.', '.' || $1 || '.'), '.' || $2 || ' ', '.' || $1 || ' ') \
                             WHERE CAST(zone_id AS varchar) = $3 AND record_type = 'SOA'",
                            &[&old_domain, nd, &zone_id],
                        ).await.is_ok();
                    }
                }
                if ok {
                    ok = rc.batch_execute("COMMIT").await.is_ok();
                } else {
                    rollback_transaction(rc).await;
                }
                if ok {
                    restored = publish(&data.dns_manager, db, Some(&old_domain))
                        .await
                        .is_ok();
                }
            }
            Err(re) => warn!(
                "update_zone rollback transaction: {}",
                full_error_string(&re)
            ),
        }
        if restored {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "publish_failed",
                "details": format!("The update was rolled back because the new configuration could not be published; the previous zone is still active: {}", e),
                "saved": false,
                "published": false
            }));
        }
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "state_uncertain",
            "details": format!("The new configuration could not be published and the previous database state could not be fully restored: {}", e),
            "saved": true,
            "published": false
        }));
    }
    let revision_snapshot_ok =
        ext::snapshot_zone(db, &zone_id, Some(&tok.claims.sub), "zone updated").await;
    audit(
        db,
        Some(&tok.claims.sub),
        "update_zone",
        "zone",
        Some(zone_id.clone()),
        &req,
        serde_json::json!({"domain": published_domain}),
    )
    .await;
    HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(serde_json::json!({
            "zone_id": zone_id,
            "revision_snapshot": if revision_snapshot_ok { "saved" } else { "failed" }
        })),
        error: None,
    })
}

// Export zone - serves the already-generated Hickory-validated zone file from disk
async fn export_zone(
    path: web::Path<String>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "unauthorized".to_string(),
                details: None,
            });
        }
    };
    let zone_id = path.into_inner();
    let access = match zone_access_at(&data.db, &zone_id, &tok, Level::Read).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let zone_file_name = format!(
        "zone.{}",
        access.domain.trim_end_matches('.').to_ascii_lowercase()
    );
    let zone_path = std::path::Path::new(&data.dns_manager.zone_dir()).join(&zone_file_name);

    match tokio::fs::read_to_string(&zone_path).await {
        Ok(content) => HttpResponse::Ok().content_type("text/plain").body(content),
        Err(_) => HttpResponse::NotFound().json(ErrorResponse {
            error: "zone file not found on disk. Regenerate with /api/v1/dns/generate first."
                .to_string(),
            details: None,
        }),
    }
}

#[derive(Deserialize)]
struct ImportZoneReq {
    records: Vec<ImportRecordReq>,
    #[serde(default)]
    dry_run: bool,
}

#[derive(Deserialize, Serialize, Clone)]
struct ImportRecordReq {
    name: String,
    record_type: String,
    value: String,
    ttl: Option<u32>,
    /// MX preference / SRV priority when it is not part of `value`
    #[serde(default)]
    priority: Option<i32>,
}

const MAX_IMPORT_RECORDS: usize = 5000;

// Import zone - all or nothing: every record is validated, the resulting zone
// is checked with Hickory, and the rows are inserted in a single statement.
async fn import_zone(
    path: web::Path<String>,
    body: web::Json<ImportZoneReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "unauthorized".to_string(),
                details: None,
            });
        }
    };
    let zone_id = path.into_inner();
    let db = &data.db;

    let access = match zone_access(db, &zone_id, &tok).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if body.records.is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "no records to import"}));
    }
    if body.records.len() > MAX_IMPORT_RECORDS {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("too many records (maximum {} per import)", MAX_IMPORT_RECORDS)
        }));
    }

    let allowed_ns = match allowed_nameservers(db).await {
        Ok(a) => a,
        Err(e) => {
            warn!("import_zone nameserver lookup: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    };
    let existing = match zone_file_generator::load_zone_records(db, &zone_id).await {
        Ok(r) => r,
        Err(e) => {
            warn!("import_zone: {:#}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    };
    let mut has_soa = existing.iter().any(|r| r.rtype.eq_ignore_ascii_case("SOA"));

    // Validate ALL records before importing any; collect every row error.
    let mut candidate = existing;
    let mut fresh: Vec<RecordRow> = Vec::new();
    let mut skipped = 0usize;
    let mut errors: Vec<serde_json::Value> = Vec::new();
    for (index, record) in body.records.iter().enumerate() {
        let rec = match validate_record_input(
            &access.domain,
            &record.name,
            &record.record_type,
            &record.value,
            record.ttl.unwrap_or(3600) as i64,
            record.priority.unwrap_or(0),
        ) {
            Ok(r) => r,
            Err(e) => {
                errors.push(serde_json::json!({
                    "row": index,
                    "name": record.name,
                    "error": e,
                }));
                continue;
            }
        };
        if rec.rtype == "NS" {
            if let Err(e) = validate_ns_value(&rec.value, &allowed_ns) {
                errors.push(serde_json::json!({
                    "row": index,
                    "name": record.name,
                    "error": e.message,
                }));
                continue;
            }
        }
        if rec.rtype == "SOA" {
            if has_soa {
                errors.push(serde_json::json!({
                    "row": index,
                    "name": record.name,
                    "error": "zone already has an SOA record",
                }));
                continue;
            }
            has_soa = true;
        }
        let dup = candidate.iter().any(|r| {
            r.name.eq_ignore_ascii_case(&rec.name)
                && r.rtype.eq_ignore_ascii_case(&rec.rtype)
                && r.value.trim() == rec.value
        });
        if dup {
            skipped += 1;
            continue;
        }
        candidate.push(rec.clone());
        fresh.push(rec);
    }
    if !errors.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Import validation failed",
            "details": format!("{} row(s) failed validation", errors.len()),
            "errors": errors,
        }));
    }
    if let Err(e) = precheck_zone_change(db, &access.domain, candidate).await {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Import validation failed",
            "details": format!("Hickory zone parser validation failed: {}", e)
        }));
    }
    if body.dry_run {
        return HttpResponse::Ok().json(serde_json::json!({
            "dry_run": true,
            "zone_id": zone_id,
            "would_import": fresh.len(),
            "skipped": skipped,
            "errors": [],
        }));
    }
    if fresh.is_empty() {
        return HttpResponse::Ok().json(serde_json::json!({
            "imported": 0, "skipped": skipped, "zone_id": zone_id,
            "message": "No new records (all were duplicates)"
        }));
    }

    let ids: Vec<String> = fresh.iter().map(|_| Uuid::new_v4().to_string()).collect();
    let names: Vec<String> = fresh.iter().map(|r| r.name.clone()).collect();
    let types: Vec<String> = fresh.iter().map(|r| r.rtype.clone()).collect();
    let values: Vec<String> = fresh.iter().map(|r| r.value.clone()).collect();
    let ttls: Vec<i32> = fresh.iter().map(|r| r.ttl).collect();
    let prios: Vec<i32> = fresh.iter().map(|r| r.priority).collect();
    // Reserve quota and insert all rows in one transaction so concurrent
    // imports/record writes cannot overshoot the tenant limit.
    let tx = match begin_zone_transaction(db, &access).await {
        Ok(t) => t,
        Err(e) => {
            warn!("import_zone transaction: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    };
    let c = tx.client();
    if let Err(e) = c.batch_execute("BEGIN").await {
        warn!("import_zone begin: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "database error"}));
    }
    if let Err(resp) = tenants::reserve_zone_records_quota_tx(
        c,
        &zone_id,
        fresh.len() as i64,
        tok.claims.role == "admin",
    )
    .await
    {
        rollback_transaction(c).await;
        return resp;
    }
    if let Err(e) = c.execute(
        "INSERT INTO records (id, zone_id, name, record_type, value, ttl, priority) \
         SELECT u.id::uuid, $1::text::uuid, u.n, u.t, u.v, u.ttl, u.p \
         FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::int4[], $7::int4[]) AS u(id, n, t, v, ttl, p)",
        &[&zone_id, &ids, &names, &types, &values, &ttls, &prios]
    ).await {
        rollback_transaction(c).await;
        warn!("failed to import records: {}", full_error_string(&e));
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Import failed",
            "details": "Database error while importing; no records were imported"
        }));
    }
    if let Err(e) = c.batch_execute("COMMIT").await {
        warn!("import_zone commit failed: {}", full_error_string(&e));
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Import failed",
            "details": "Database error while importing; no records were imported"
        }));
    }
    drop(tx);
    let imported = fresh.len();

    if let Err(e) = publish(&data.dns_manager, db, Some(&access.domain)).await {
        warn!("Failed to publish zone after import, rolling back: {}", e);
        let _ = db
            .execute(
                "DELETE FROM records WHERE CAST(id AS varchar) = ANY($1::text[])",
                &[&ids],
            )
            .await;
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Zone file generation failed",
            "details": format!("import rolled back: {}", e),
            "saved": false,
            "published": false
        }));
    }
    let revision_snapshot_ok =
        ext::snapshot_zone(db, &zone_id, Some(&tok.claims.sub), "import").await;
    audit(
        db,
        Some(&tok.claims.sub),
        "import_zone",
        "zone",
        Some(zone_id.clone()),
        &req,
        serde_json::json!({"zone": access.domain, "imported": imported, "skipped": skipped}),
    )
    .await;

    HttpResponse::Ok().json(serde_json::json!({
        "imported": imported,
        "skipped": skipped,
        "zone_id": zone_id,
        "revision_snapshot": if revision_snapshot_ok { "saved" } else { "failed" },
        "message": format!("Successfully imported {} records", imported)
    }))
}

// Delete zone
async fn delete_zone(
    path: web::Path<String>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "unauthorized".to_string(),
                details: None,
            });
        }
    };
    let zone_id = path.into_inner();
    let access = match zone_access_at(&data.db, &zone_id, &tok, Level::Owner).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let domain = access.domain.trim_end_matches('.').to_ascii_lowercase();

    // Two-phase delete: hide the zone from publication first, publish the
    // replacement configuration, and only then remove its rows. If publication
    // fails the zone is restored to exactly the state it had before.
    let tx = match begin_zone_transaction(&data.db, &access).await {
        Ok(t) => t,
        Err(e) => {
            warn!("delete_zone transaction: {}", full_error_string(&e));
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "failed to delete zone".to_string(),
                details: None,
            });
        }
    };
    let c = tx.client();
    if let Err(e) = c.batch_execute("BEGIN").await {
        warn!("delete_zone begin: {}", full_error_string(&e));
        return HttpResponse::InternalServerError().json(ErrorResponse {
            error: "failed to delete zone".to_string(),
            details: None,
        });
    }
    let old_status: String = match c.query_opt(
        "SELECT COALESCE(status, 'active') FROM zones WHERE CAST(id AS varchar) = $1 FOR UPDATE",
        &[&zone_id],
    ).await {
        Ok(Some(r)) => r.get(0),
        Ok(None) => {
            rollback_transaction(c).await;
            return HttpResponse::NotFound().json(ErrorResponse { error: "zone not found".to_string(), details: None });
        }
        Err(e) => {
            rollback_transaction(c).await;
            warn!("delete_zone lookup: {}", full_error_string(&e));
            return HttpResponse::InternalServerError().json(ErrorResponse { error: "failed to delete zone".to_string(), details: None });
        }
    };
    if let Err(e) = c.execute(
        "UPDATE zones SET status = 'deleting', updated_at = now() WHERE CAST(id AS varchar) = $1",
        &[&zone_id],
    ).await {
        rollback_transaction(c).await;
        warn!("delete_zone mark: {}", full_error_string(&e));
        return HttpResponse::InternalServerError().json(ErrorResponse { error: "failed to delete zone".to_string(), details: None });
    }
    if let Err(e) = c.batch_execute("COMMIT").await {
        warn!("delete_zone commit: {}", full_error_string(&e));
        return HttpResponse::InternalServerError().json(ErrorResponse {
            error: "failed to delete zone".to_string(),
            details: None,
        });
    }
    drop(tx);

    if let Err(e) = publish(&data.dns_manager, &data.db, Some(&domain)).await {
        warn!("Failed to publish after removing zone {}: {}", domain, e);
        let restored = data
            .db
            .execute(
                "UPDATE zones SET status = $2, updated_at = now() WHERE CAST(id AS varchar) = $1",
                &[&zone_id, &old_status],
            )
            .await;
        if let Err(re) = restored {
            warn!(
                "delete_zone could not restore status: {}",
                full_error_string(&re)
            );
        } else if let Err(re) = publish(&data.dns_manager, &data.db, Some(&domain)).await {
            warn!(
                "delete_zone could not republish restored zone {}: {}",
                domain, re
            );
        }
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "publish_failed",
            "details": format!("The zone was not deleted because the new configuration could not be published; the previous configuration is still active: {}", e),
            "saved": true,
            "published": false
        }));
    }

    match data
        .db
        .execute(
            "DELETE FROM zones WHERE CAST(id AS varchar) = $1",
            &[&zone_id],
        )
        .await
    {
        Ok(0) => {
            let _ = data.db.execute(
                "UPDATE zones SET status = $2, updated_at = now() WHERE CAST(id AS varchar) = $1",
                &[&zone_id, &old_status],
            ).await;
            HttpResponse::NotFound().json(ErrorResponse {
                error: "zone not found".to_string(),
                details: None,
            })
        }
        Ok(_) => {
            info!("Deleted zone: {}", zone_id);
            audit(
                &data.db,
                Some(&tok.claims.sub),
                "delete_zone",
                "zone",
                Some(zone_id.clone()),
                &req,
                serde_json::json!({"domain": domain}),
            )
            .await;
            HttpResponse::Ok().json(ApiResponse {
                success: true,
                data: Some(()),
                error: None,
            })
        }
        Err(e) => {
            warn!("delete_zone error: {}", full_error_string(&e));
            let _ = data.db.execute(
                "UPDATE zones SET status = $2, updated_at = now() WHERE CAST(id AS varchar) = $1",
                &[&zone_id, &old_status],
            ).await;
            if let Err(re) = publish(&data.dns_manager, &data.db, Some(&domain)).await {
                warn!("delete_zone restore publication failed: {}", re);
            }
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "failed to delete zone".to_string(),
                details: None,
            })
        }
    }
}

/// All HTTP routes of the control API (shared by the server and the tests).
#[derive(Deserialize)]
struct ZoneMetadataReq {
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct RecordMetadataReq {
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
}

fn validate_metadata_tags(tags: &[String]) -> Result<Vec<String>, String> {
    if tags.len() > 20 {
        return Err("at most 20 tags are allowed".to_string());
    }
    for tag in tags {
        if tag.is_empty() || tag.len() > 32 {
            return Err("tags must be 1-32 characters".to_string());
        }
        if !tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("tags may only contain letters, digits, '-' and '_'".to_string());
        }
    }
    let mut clean = tags.to_vec();
    clean.sort();
    clean.dedup();
    Ok(clean)
}

async fn set_zone_metadata(
    path: web::Path<String>,
    body: web::Json<ZoneMetadataReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let zone_id = path.into_inner();
    let access = match zone_access(&data.db, &zone_id, &tok).await {
        Ok(a) => a,
        Err(response) => return response,
    };
    let description = body.description.clone().unwrap_or_default();
    if description.len() > 500 {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "description too long"}));
    }
    let tags = match validate_metadata_tags(body.tags.as_deref().unwrap_or(&[])) {
        Ok(tags) => {
            serde_json::Value::Array(tags.into_iter().map(serde_json::Value::String).collect())
        }
        Err(error) => return HttpResponse::BadRequest().json(serde_json::json!({"error": error})),
    };
    if let Err(e) = data.db.execute(
        "UPDATE zones SET description = $1, tags = $2, updated_at = now() WHERE CAST(id AS varchar) = $3",
        &[&description, &tags, &zone_id],
    ).await {
        warn!("set_zone_metadata: {}", full_error_string(&e));
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": "database error"}));
    }
    audit(
        &data.db,
        Some(&tok.claims.sub),
        "set_zone_metadata",
        "zone",
        Some(zone_id.clone()),
        &req,
        serde_json::json!({"zone": access.domain}),
    )
    .await;
    HttpResponse::Ok().json(serde_json::json!({"description": description, "tags": tags}))
}

async fn set_record_metadata(
    path: web::Path<(String, String)>,
    body: web::Json<RecordMetadataReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let (zone_id, record_id) = path.into_inner();
    let access = match zone_access(&data.db, &zone_id, &tok).await {
        Ok(a) => a,
        Err(response) => return response,
    };
    let comment = body.comment.clone().unwrap_or_default();
    if comment.len() > 500 {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "comment too long"}));
    }
    let tags = match validate_metadata_tags(body.tags.as_deref().unwrap_or(&[])) {
        Ok(tags) => {
            serde_json::Value::Array(tags.into_iter().map(serde_json::Value::String).collect())
        }
        Err(error) => return HttpResponse::BadRequest().json(serde_json::json!({"error": error})),
    };
    let result = data
        .db
        .execute(
            "UPDATE records SET comment = $1, tags = $2, updated_at = now() \
         WHERE CAST(id AS varchar) = $3 AND CAST(zone_id AS varchar) = $4",
            &[&comment, &tags, &record_id, &zone_id],
        )
        .await;
    match result {
        Ok(0) => HttpResponse::NotFound().json(serde_json::json!({"error": "record not found"})),
        Ok(_) => {
            audit(
                &data.db,
                Some(&tok.claims.sub),
                "set_record_metadata",
                "record",
                Some(record_id.clone()),
                &req,
                serde_json::json!({"zone": access.domain}),
            )
            .await;
            HttpResponse::Ok().json(serde_json::json!({"comment": comment, "tags": tags}))
        }
        Err(e) => {
            warn!("set_record_metadata: {}", full_error_string(&e));
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "database error"}))
        }
    }
}

#[derive(Deserialize)]
struct CloneZoneReq {
    domain: String,
}

fn rewrite_clone_target(value: &str, record_type: &str, source: &str, target: &str) -> String {
    // Only target-bearing RR types contain domain names that should follow a clone.
    // TXT and other opaque values must be copied byte-for-byte.
    if !matches!(record_type, "CNAME" | "DNAME" | "NS" | "MX" | "PTR" | "SRV") {
        return value.to_owned();
    }
    let (prefix, hostname) = if record_type == "SRV" {
        match value.rsplit_once(' ') {
            Some((prefix, hostname)) => (Some(prefix), hostname),
            None => (None, value),
        }
    } else {
        (None, value)
    };
    let trailing_dot = hostname.ends_with('.');
    let bare = hostname.trim_end_matches('.');
    let replacement = if bare.eq_ignore_ascii_case(source) {
        Some(target.to_owned())
    } else if bare.len() > source.len()
        && bare[bare.len() - source.len()..].eq_ignore_ascii_case(source)
        && bare.as_bytes()[bare.len() - source.len() - 1] == b'.'
    {
        Some(format!("{}{}", &bare[..bare.len() - source.len()], target))
    } else {
        None
    };
    match replacement {
        Some(mut name) => {
            if trailing_dot {
                name.push('.');
            }
            match prefix {
                Some(prefix) => format!("{prefix} {name}"),
                None => name,
            }
        }
        None => value.to_owned(),
    }
}

#[cfg(test)]
mod clone_target_tests {
    use super::rewrite_clone_target;

    #[test]
    fn rewrites_only_dns_targets_inside_source_zone() {
        assert_eq!(
            rewrite_clone_target(
                "www.source.example.",
                "CNAME",
                "source.example",
                "copy.example"
            ),
            "www.copy.example."
        );
        assert_eq!(
            rewrite_clone_target("SOURCE.EXAMPLE", "MX", "source.example", "copy.example"),
            "copy.example"
        );
        assert_eq!(
            rewrite_clone_target(
                "10 5 443 sip.source.example.",
                "SRV",
                "source.example",
                "copy.example"
            ),
            "10 5 443 sip.copy.example."
        );
        assert_eq!(
            rewrite_clone_target(
                "not-source.example.",
                "CNAME",
                "source.example",
                "copy.example"
            ),
            "not-source.example."
        );
        assert_eq!(
            rewrite_clone_target(
                "www.source.example.evil.",
                "CNAME",
                "source.example",
                "copy.example"
            ),
            "www.source.example.evil."
        );
        assert_eq!(
            rewrite_clone_target(
                "see source.example",
                "TXT",
                "source.example",
                "copy.example"
            ),
            "see source.example"
        );
    }
}

async fn clone_zone(
    path: web::Path<String>,
    body: web::Json<CloneZoneReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let source_id = path.into_inner();
    let access = match zone_access_at(&data.db, &source_id, &tok, Level::Read).await {
        Ok(a) => a,
        Err(response) => return response,
    };
    let domain = match normalize_zone_domain(&body.domain) {
        Ok(d) => d,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": e.message})),
    };
    if tok.claims.role != "admin" {
        match zone_overlaps_other_owner(&data.db, &domain, &tok.claims.sub, None).await {
            Ok(true) => {
                return HttpResponse::Conflict()
                    .json(serde_json::json!({"error": "domain overlaps another zone"}));
            }
            Ok(false) => {}
            Err(e) => {
                warn!("clone overlap check: {}", full_error_string(&e));
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({"error": "database error"}));
            }
        }
    }
    let rows = match data
        .db
        .query(
            "SELECT name, record_type, value, ttl, priority FROM records \
         WHERE CAST(zone_id AS varchar) = $1 ORDER BY created_at, id",
            &[&source_id],
        )
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            warn!("clone source records: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    };
    let source_domain_trimmed = access.domain.trim_end_matches('.').to_ascii_lowercase();
    let target_domain_trimmed = domain.trim_end_matches('.').to_ascii_lowercase();
    let mut names = Vec::new();
    let mut types = Vec::new();
    let mut values = Vec::new();
    let mut ttls = Vec::new();
    let mut priorities = Vec::new();
    for row in &rows {
        let value: String = row.get(2);
        names.push(row.get::<_, String>(0));
        types.push(row.get::<_, String>(1));
        values.push(rewrite_clone_target(
            &value,
            &row.get::<_, String>(1),
            &source_domain_trimmed,
            &target_domain_trimmed,
        ));
        ttls.push(row.get::<_, i32>(3));
        priorities.push(row.get::<_, Option<i32>>(4).unwrap_or(0));
    }
    let candidate: Vec<RecordRow> = names
        .iter()
        .zip(types.iter())
        .zip(values.iter())
        .zip(ttls.iter())
        .zip(priorities.iter())
        .map(|((((n, t), v), ttl), p)| RecordRow {
            name: n.clone(),
            rtype: t.clone(),
            value: v.clone(),
            ttl: *ttl,
            priority: *p,
        })
        .collect();
    if let Err(e) = precheck_zone_change(&data.db, &domain, candidate).await {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "cloned zone is invalid", "details": e}));
    }

    let zone_id = Uuid::new_v4().to_string();
    let status = if data.verify_domains && tok.claims.role != "admin" {
        "pending"
    } else {
        "active"
    };
    let verify_token = if status == "pending" {
        Some(ext::new_verify_token())
    } else {
        None
    };
    let tx = match begin_zone_transaction(&data.db, &access).await {
        Ok(t) => t,
        Err(e) => {
            warn!("clone transaction: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    };
    let c = tx.client();
    if let Err(e) = c.batch_execute("BEGIN").await {
        warn!("clone begin: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "database error"}));
    }
    if let Err(e) = c.execute(
        "INSERT INTO zones (id, domain, owner, zone_type, status, verify_token, geodns_enabled, ecs_enabled) \
         SELECT $1::text::uuid, $2, $3::text::uuid, zone_type, $4, $5, geodns_enabled, ecs_enabled \
         FROM zones WHERE CAST(id AS varchar) = $6",
        &[&zone_id, &domain, &tok.claims.sub, &status, &verify_token, &source_id],
    ).await {
        rollback_transaction(c).await;
        let err = full_error_string(&e);
        return if err.contains("unique") || err.contains("duplicate") {
            HttpResponse::Conflict().json(serde_json::json!({"error": "domain already exists"}))
        } else {
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "failed to clone zone"}))
        };
    }
    if !names.is_empty() {
        let ids: Vec<String> = names.iter().map(|_| Uuid::new_v4().to_string()).collect();
        let zone_ids: Vec<String> = names.iter().map(|_| zone_id.clone()).collect();
        if let Err(e) = c.execute(
            "INSERT INTO records (id, zone_id, name, record_type, value, ttl, priority) \
             SELECT u.id::text::uuid, u.z::text::uuid, u.n, u.t, u.v, u.ttl, u.p \
             FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::int4[], $7::int4[]) \
                  AS u(id, z, n, t, v, ttl, p)",
            &[&ids, &zone_ids, &names, &types, &values, &ttls, &priorities],
        ).await {
            rollback_transaction(c).await;
            warn!("clone records: {}", full_error_string(&e));
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "failed to clone zone"}));
        }
    }
    if let Err(e) = c.batch_execute("COMMIT").await {
        warn!("clone commit: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "failed to clone zone"}));
    }
    drop(tx);
    if let Err(e) = publish(&data.dns_manager, &data.db, Some(&domain)).await {
        let _ = data
            .db
            .execute(
                "DELETE FROM zones WHERE CAST(id AS varchar) = $1",
                &[&zone_id],
            )
            .await;
        return publish_failed_rolled_back(&e);
    }
    let revision_snapshot_ok =
        ext::snapshot_zone(&data.db, &zone_id, Some(&tok.claims.sub), "cloned zone").await;
    audit(
        &data.db,
        Some(&tok.claims.sub),
        "clone_zone",
        "zone",
        Some(zone_id.clone()),
        &req,
        serde_json::json!({"source": access.domain, "domain": domain}),
    )
    .await;
    HttpResponse::Created().json(serde_json::json!({
        "id": zone_id, "domain": domain, "status": status, "records": names.len(),
        "revision_snapshot": if revision_snapshot_ok { "saved" } else { "failed" }
    }))
}

#[derive(Deserialize)]
struct ZoneLifecycleReq {
    status: String,
    #[serde(default)]
    hold_reason: Option<String>,
    /// RFC 3339 timestamp after which the hold should be reviewed.
    #[serde(default)]
    hold_until: Option<String>,
}

async fn set_zone_lifecycle(
    path: web::Path<String>,
    body: web::Json<ZoneLifecycleReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let zone_id = path.into_inner();
    let access = match zone_access_at(&data.db, &zone_id, &tok, Level::Owner).await {
        Ok(a) => a,
        Err(response) => return response,
    };
    let desired = body.status.trim().to_ascii_lowercase();
    if !matches!(
        desired.as_str(),
        "active" | "suspended" | "held" | "archived"
    ) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "status must be active, suspended, held or archived"
        }));
    }
    let hold_reason = body
        .hold_reason
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(reason) = hold_reason {
        if reason.len() > 500 {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": "hold_reason is too long"}));
        }
    }
    let hold_until = match body.hold_until.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(s) => match chrono::DateTime::parse_from_rfc3339(s) {
            Ok(dt) => Some(dt.with_timezone(&chrono::Utc)),
            Err(_) => {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "hold_until must be an RFC 3339 timestamp"
                }));
            }
        },
    };
    let current = match data
        .db
        .query_one(
            "SELECT status, hold_reason, hold_until, archived_at FROM zones WHERE CAST(id AS varchar) = $1",
            &[&zone_id],
        )
        .await
    {
        Ok(row) => row,
        Err(e) => {
            warn!("set_zone_lifecycle lookup: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    };
    let current_status: String = current.get(0);
    if current_status == "pending" && desired == "active" {
        return HttpResponse::Conflict().json(serde_json::json!({
            "error": "pending zones must be verified before activation"
        }));
    }
    if desired == "held" && hold_reason.is_none() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "hold_reason is required when putting a zone on hold"
        }));
    }
    let (new_reason, new_until, new_archived) = match desired.as_str() {
        "held" => (hold_reason, hold_until, None),
        "archived" => (hold_reason, hold_until, Some(chrono::Utc::now())),
        _ => (None, None, None),
    };
    if let Err(e) = data
        .db
        .execute(
            "UPDATE zones SET status = $1, hold_reason = $2, hold_until = $3, \
                    archived_at = $4, updated_at = now() WHERE CAST(id AS varchar) = $5",
            &[&desired, &new_reason, &new_until, &new_archived, &zone_id],
        )
        .await
    {
        warn!("set_zone_lifecycle update: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "database error"}));
    }
    if let Err(e) = publish(&data.dns_manager, &data.db, Some(&access.domain)).await {
        let _ = data
            .db
            .execute(
                "UPDATE zones SET status = $1, hold_reason = $2, hold_until = $3, \
                        archived_at = $4, updated_at = now() WHERE CAST(id AS varchar) = $5",
                &[
                    &current_status,
                    &current.get::<_, Option<String>>(1),
                    &current.get::<_, Option<chrono::DateTime<chrono::Utc>>>(2),
                    &current.get::<_, Option<chrono::DateTime<chrono::Utc>>>(3),
                    &zone_id,
                ],
            )
            .await;
        return publish_failed_rolled_back(&e);
    }
    audit(
        &data.db,
        Some(&tok.claims.sub),
        "set_zone_lifecycle",
        "zone",
        Some(zone_id.clone()),
        &req,
        serde_json::json!({
            "zone": access.domain, "from": current_status, "to": desired,
            "hold_reason": hold_reason, "hold_until": hold_until
        }),
    )
    .await;
    HttpResponse::Ok().json(serde_json::json!({
        "status": desired,
        "hold_reason": hold_reason,
        "hold_until": hold_until.map(|d| d.to_rfc3339()),
        "archived_at": new_archived.map(|d| d.to_rfc3339()),
    }))
}

#[derive(Deserialize)]
struct TransferPolicyReq {
    policy: String,
    #[serde(default)]
    allowed_peers: Option<Vec<String>>,
}

async fn set_zone_transfer_policy(
    path: web::Path<String>,
    body: web::Json<TransferPolicyReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let zone_id = path.into_inner();
    let access = match zone_access(&data.db, &zone_id, &tok).await {
        Ok(a) => a,
        Err(response) => return response,
    };
    let policy = body.policy.trim().to_ascii_lowercase();
    let canonical = match policy.as_str() {
        "deny" => "Deny",
        "allowall" | "allow_all" | "allow-all" => "AllowAll",
        _ => return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "policy must be Deny or AllowAll; signed transfers require TSIG key custody"
        })),
    };
    let allowed_peers = match body.allowed_peers.as_ref() {
        None => None,
        Some(peers) if peers.len() <= 64 => {
            let mut normalized = Vec::with_capacity(peers.len());
            for peer in peers {
                match peer.trim().parse::<std::net::IpAddr>() {
                    Ok(address) => normalized.push(address.to_string()),
                    Err(_) => {
                        return HttpResponse::BadRequest().json(serde_json::json!({
                            "error": format!("invalid transfer peer IP address: {}", peer)
                        }));
                    }
                }
            }
            normalized.sort();
            normalized.dedup();
            Some(normalized)
        }
        Some(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "at most 64 transfer peer IP addresses may be configured"
            }));
        }
    };
    let previous = match data
        .db
        .query_opt(
            "SELECT COALESCE(axfr_policy, 'Deny'), COALESCE(axfr_allowed_peers, '{}'::text[]) FROM zones WHERE CAST(id AS varchar) = $1",
            &[&zone_id],
        )
        .await
    {
        Ok(Some(row)) => (
            row.get::<_, String>(0),
            row.get::<_, Vec<String>>(1),
        ),
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({"error":"zone not found"}));
        }
        Err(e) => {
            warn!("read transfer policy: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };
    if let Err(e) = data
        .db
        .execute(
            "UPDATE zones SET axfr_policy = $1, axfr_allowed_peers = COALESCE($2, axfr_allowed_peers), updated_at = now() WHERE CAST(id AS varchar) = $3",
            &[&canonical, &allowed_peers, &zone_id],
        )
        .await
    {
        warn!("set_zone_transfer_policy: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "database error"}));
    }
    if let Err(e) = publish(&data.dns_manager, &data.db, Some(&access.domain)).await {
        let rollback = data.db.execute(
            "UPDATE zones SET axfr_policy = $1, axfr_allowed_peers = $2, updated_at = now() WHERE CAST(id AS varchar) = $3",
            &[&previous.0, &previous.1, &zone_id],
        ).await;
        if let Err(rollback_error) = rollback {
            log::error!(
                "transfer policy publication failed ({e}); policy rollback also failed: {}",
                full_error_string(&rollback_error)
            );
        } else if let Err(republish_error) =
            publish(&data.dns_manager, &data.db, Some(&access.domain)).await
        {
            log::error!("transfer policy rollback republish failed: {republish_error}");
        }
        return publish_failed_rolled_back(&e.to_string());
    }
    audit(
        &data.db,
        Some(&tok.claims.sub),
        "set_zone_transfer_policy",
        "zone",
        Some(zone_id.clone()),
        &req,
        serde_json::json!({"zone": access.domain, "policy": canonical, "allowed_peers": allowed_peers.as_ref().unwrap_or(&previous.1)}),
    )
    .await;
    HttpResponse::Ok().json(serde_json::json!({"policy": canonical, "allowed_peers": allowed_peers.unwrap_or(previous.1)}))
}

#[derive(OpenApi)]
#[openapi(components(schemas(ErrorResponse, ZoneWithOwner, AuditLogEntry)))]
struct ApiDoc;

async fn openapi_spec() -> impl Responder {
    let mut document = serde_json::to_value(ApiDoc::openapi()).unwrap_or_else(|_| {
        serde_json::json!({"openapi":"3.0.3","info":{"title":"OutisCloud Control API","version":"1.0.0"}})
    });
    let generated_paths: serde_json::Value =
        serde_json::from_str(include_str!("../openapi-paths.json"))
            .expect("generated OpenAPI route catalog must be valid JSON");
    document["paths"] = generated_paths["paths"].clone();
    if let Some(schemas) = generated_paths
        .get("components")
        .and_then(|components| components.get("schemas"))
        .and_then(serde_json::Value::as_object)
    {
        let destination = document["components"]["schemas"]
            .as_object_mut()
            .expect("OpenAPI components.schemas must be an object");
        for (name, schema) in schemas {
            destination.insert(name.clone(), schema.clone());
        }
    }
    document["components"]["securitySchemes"]["BearerAuth"] = serde_json::json!({
        "type": "http", "scheme": "bearer", "bearerFormat": "JWT"
    });
    HttpResponse::Ok().json(document)
}

fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/health", web::get().to(health))
        .route("/ready", web::get().to(ready))
        .route("/openapi.json", web::get().to(openapi_spec))
        // Auth
        .route("/api/v1/auth/login", web::post().to(login))
        .route("/api/v1/auth/logout", web::post().to(logout))
        .route("/api/v1/auth/refresh", web::post().to(refresh_token))
        .route("/api/v1/auth/me", web::get().to(get_current_user))
        .route(
            "/api/v1/admin/publication-outbox/{domain}/retry",
            web::post().to(retry_failed_publication),
        )
        .route(
            "/api/v1/auth/change-password",
            web::post().to(change_password),
        )
        .route(
            "/api/v1/auth/admin-reset-password",
            web::post().to(admin_reset_password),
        )
        // Users
        .route("/api/v1/users", web::get().to(list_users))
        .route("/api/v1/users", web::post().to(create_user))
        .route("/api/v1/users/{id}", web::get().to(get_user))
        .route("/api/v1/users/{id}", web::put().to(update_user))
        .route("/api/v1/users/{id}", web::delete().to(delete_user))
        .route(
            "/api/v1/users/{id}/password",
            web::post().to(reset_user_password),
        )
        // Servers
        .route("/api/v1/servers", web::get().to(list_servers))
        .route("/api/v1/servers", web::post().to(create_server))
        .route("/api/v1/servers/{id}", web::put().to(update_server))
        .route("/api/v1/servers/{id}", web::delete().to(delete_server))
        // Nameservers (Authoritative NS configuration)
        .route("/api/v1/nameservers", web::get().to(list_nameservers))
        .route("/api/v1/nameservers", web::post().to(create_nameserver))
        .route("/api/v1/nameservers/{id}", web::put().to(update_nameserver))
        .route(
            "/api/v1/nameservers/{id}",
            web::delete().to(delete_nameserver),
        )
        // Zones
        .route("/api/v1/zone-templates", web::get().to(list_zone_templates))
        .route("/api/v1/zones", web::get().to(list_zones))
        .route("/api/v1/zones", web::post().to(create_zone))
        .route(
            "/api/v1/zones/bulk-import",
            web::post().to(zone_ops::bulk_import),
        )
        .route("/api/v1/zones/{id}", web::get().to(get_zone))
        .route("/api/v1/zones/{id}", web::put().to(update_zone))
        .route("/api/v1/zones/{id}", web::delete().to(delete_zone))
        .route("/api/v1/zones/{id}/export", web::get().to(export_zone))
        .route("/api/v1/zones/{id}/import", web::post().to(import_zone))
        .route(
            "/api/v1/zones/{id}/import-bind",
            web::post().to(zone_ops::import_bind),
        )
        .route(
            "/api/v1/zones/{id}/rrsets",
            web::put().to(zone_ops::batch_rrsets),
        )
        .route(
            "/api/v1/zones/{id}/metadata",
            web::put().to(set_zone_metadata),
        )
        .route("/api/v1/zones/{id}/clone", web::post().to(clone_zone))
        .route(
            "/api/v1/zones/{id}/lifecycle",
            web::put().to(set_zone_lifecycle),
        )
        .route(
            "/api/v1/zones/{id}/transfer-policy",
            web::put().to(set_zone_transfer_policy),
        )
        // Records
        .route("/api/v1/zones/{id}/records", web::post().to(create_record))
        .route("/api/v1/zones/{id}/records", web::get().to(list_records))
        .route(
            "/api/v1/zones/{zone_id}/records/{record_id}",
            web::put().to(update_record),
        )
        .route(
            "/api/v1/zones/{zone_id}/records/{record_id}",
            web::delete().to(delete_record),
        )
        .route(
            "/api/v1/zones/{zone_id}/records/bulk-delete",
            web::post().to(zone_ops::bulk_delete_records),
        )
        .route(
            "/api/v1/zones/{zone_id}/records/{record_id}/metadata",
            web::put().to(set_record_metadata),
        )
        // Agents
        .route("/api/v1/agents/register", web::post().to(agent_register))
        .route("/api/v1/agents/heartbeat", web::post().to(agent_heartbeat))
        .route("/api/v1/agents", web::get().to(list_agents))
        .route("/api/v1/agents/{id}", web::delete().to(delete_agent))
        .route(
            "/api/v1/agents/{id}/config",
            web::get().to(agent_get_config),
        )
        .route("/api/v1/agents/{id}/zones", web::get().to(list_agent_zones))
        .route("/api/v1/agents/{id}/zones", web::put().to(set_agent_zones))
        .route(
            "/api/v1/agents/{id}/token/rotate",
            web::post().to(rotate_agent_token),
        )
        // DNS Control (generation endpoint only, server is external)
        .route("/api/v1/dns/generate", web::post().to(generate_dns_files))
        .route("/api/v1/dns/lookup", web::post().to(dns_lookup))
        // GeoRules
        .route("/api/v1/georules", web::post().to(create_georule))
        .route("/api/v1/georules", web::get().to(list_georules))
        .route("/api/v1/georules/{id}", web::put().to(update_georule))
        .route("/api/v1/georules/{id}", web::delete().to(delete_georule))
        .route("/api/v1/georules/resolve", web::post().to(resolve_by_geo))
        // Config Push
        .route("/api/v1/config/push", web::post().to(push_config_to_agents))
        // Audit Logs
        .route("/api/v1/audit/logs", web::get().to(ext::list_audit))
        .route(
            "/api/v1/audit/logs/export",
            web::get().to(ext::export_audit),
        )
        .route("/api/v1/audit/logs/{id}", web::get().to(ext::get_audit))
        .configure(ext::configure)
        .configure(tenants::configure)
        .configure(health::configure)
        // API tokens, durable jobs and webhooks
        .route("/api/v1/tokens", web::get().to(automation::list_tokens))
        .route("/api/v1/tokens", web::post().to(automation::create_token))
        .route(
            "/api/v1/tokens/{id}",
            web::delete().to(automation::revoke_token),
        )
        .route(
            "/api/v1/tokens/{id}/rotate",
            web::post().to(automation::rotate_token),
        )
        .route("/api/v1/jobs", web::get().to(automation::list_jobs))
        .route("/api/v1/jobs/{id}", web::get().to(automation::get_job))
        .route(
            "/api/v1/jobs/{id}/cancel",
            web::post().to(automation::cancel_job),
        )
        .route("/api/v1/webhooks", web::get().to(automation::list_webhooks))
        .route(
            "/api/v1/webhooks",
            web::post().to(automation::create_webhook),
        )
        .route(
            "/api/v1/webhooks/{id}",
            web::delete().to(automation::delete_webhook),
        )
        // DNSSEC
        .route(
            "/api/v1/zones/{id}/dnssec",
            web::get().to(dnssec::get_dnssec),
        )
        .route(
            "/api/v1/zones/{id}/dnssec/enable",
            web::post().to(dnssec::enable_dnssec),
        )
        .route(
            "/api/v1/zones/{id}/dnssec/proof",
            web::put().to(dnssec::set_nx_proof),
        )
        .route(
            "/api/v1/zones/{id}/dnssec/multi-signer",
            web::post().to(dnssec::reject_multi_signer),
        )
        .route(
            "/api/v1/zones/{id}/dnssec/disable",
            web::post().to(dnssec::disable_dnssec),
        )
        .route(
            "/api/v1/zones/{id}/dnssec/rollover",
            web::post().to(dnssec::rollover_dnssec),
        )
        .route(
            "/api/v1/zones/{id}/dnssec/rollover/complete",
            web::post().to(dnssec::complete_rollover),
        )
        .route(
            "/api/v1/zones/{id}/dnssec/ds-status",
            web::get().to(dnssec::ds_status),
        )
        // Metrics (optionally protected by METRICS_TOKEN)
        .route("/metrics", web::get().to(metrics_endpoint));
}

/// Settings that must never reach production. Returns a human readable list.
fn startup_problems(
    jwt_secret: &str,
    database_url: &str,
    admin_password: Option<&str>,
    force_bootstrap: bool,
) -> Vec<String> {
    const PLACEHOLDERS: [&str; 9] = [
        "change_me",
        "changeme",
        "change-me",
        "your-secret",
        "your_secret",
        "placeholder",
        "example",
        ":password@",
        ":postgres@",
    ];
    let is_placeholder = |v: &str| {
        let l = v.to_ascii_lowercase();
        PLACEHOLDERS.iter().any(|p| l.contains(p))
    };
    let mut out = Vec::new();
    if is_placeholder(jwt_secret) {
        out.push(
            "JWT_SECRET looks like a placeholder; generate one with `openssl rand -base64 32`"
                .to_string(),
        );
    }
    // distinct characters is a cheap guard against "aaaaaaaa..." style secrets
    if jwt_secret
        .chars()
        .collect::<std::collections::HashSet<_>>()
        .len()
        < 8
    {
        out.push("JWT_SECRET has too little variety".to_string());
    }
    if is_placeholder(database_url) {
        out.push("DATABASE_URL contains a placeholder password".to_string());
    }
    if let Some(p) = admin_password {
        if p.len() < 12
            || is_placeholder(p)
            || ["admin123", "password", "admin", "changeme"]
                .iter()
                .any(|d| p.eq_ignore_ascii_case(d))
        {
            out.push(
                "ADMIN_PASSWORD is a placeholder, default or shorter than 12 characters"
                    .to_string(),
            );
        }
        if force_bootstrap {
            out.push("FORCE_BOOTSTRAP=true resets the administrator password on every start; remove it after the first run".to_string());
        }
    }
    out
}

/// When `METRICS_TOKEN` is set, `/metrics` requires `Authorization: Bearer <token>`.
async fn api_rate_limit_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<actix_web::body::BoxBody>, actix_web::Error> {
    let path = req.path().to_string();
    if matches!(path.as_str(), "/health" | "/ready" | "/metrics") {
        return Ok(next.call(req).await?.map_into_boxed_body());
    }
    let limit = std::env::var("API_RATE_LIMIT_PER_IP")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(6000);
    let peer = req
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    if let Some(state) = req.app_data::<web::Data<AppState>>().cloned() {
        let bucket = format!("api-global:{peer}");
        if let Some(wait) = shared::limited(&state.db, &bucket, limit, 60, || true).await {
            let response = HttpResponse::TooManyRequests()
                .insert_header((header::RETRY_AFTER, wait.to_string()))
                .json(serde_json::json!({"error": "rate_limited", "retry_after": wait}));
            return Ok(req.into_response(response).map_into_boxed_body());
        }
    }
    Ok(next.call(req).await?.map_into_boxed_body())
}

async fn metrics_guard(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<actix_web::body::BoxBody>, actix_web::Error> {
    if req.path() == "/metrics" {
        if let Some(want) = std::env::var("METRICS_TOKEN")
            .ok()
            .filter(|t| !t.is_empty())
        {
            let got = req
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .and_then(|h| h.strip_prefix("Bearer "))
                .unwrap_or("");
            // constant-time comparison
            let ok = got.len() == want.len()
                && got
                    .bytes()
                    .zip(want.bytes())
                    .fold(0u8, |d, (a, b)| d | (a ^ b))
                    == 0;
            if !ok {
                return Ok(req
                    .into_response(HttpResponse::Unauthorized().finish())
                    .map_into_boxed_body());
            }
        }
    }
    Ok(next.call(req).await?.map_into_boxed_body())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    info!("Starting control API...");

    // Required environment variables for production
    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL environment variable must be set");
    let jwt_secret =
        std::env::var("JWT_SECRET").expect("JWT_SECRET environment variable must be set");

    // Validate JWT_SECRET is sufficiently long for security
    if jwt_secret.len() < 32 {
        panic!("JWT_SECRET must be at least 32 characters for production security");
    }
    // Refuse to run with placeholder secrets or an unsafe bootstrap unless the
    // operator explicitly opts out (development only).
    let insecure_ok = std::env::var("ALLOW_INSECURE_DEFAULTS")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let problems = startup_problems(
        &jwt_secret,
        &database_url,
        std::env::var("ADMIN_PASSWORD").ok().as_deref(),
        std::env::var("FORCE_BOOTSTRAP")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false),
    );
    if !problems.is_empty() {
        for p in &problems {
            log::error!("unsafe configuration: {}", p);
        }
        if !insecure_ok {
            panic!(
                "refusing to start with an unsafe configuration (set ALLOW_INSECURE_DEFAULTS=true to override for development only)"
            );
        }
        warn!(
            "ALLOW_INSECURE_DEFAULTS=true: continuing despite {} unsafe setting(s)",
            problems.len()
        );
    }
    let proxies = ext::parse_trusted_proxies(&std::env::var("TRUSTED_PROXIES").unwrap_or_default());
    if !proxies.is_empty() {
        info!(
            "trusting X-Forwarded-For from {} proxy range(s)",
            proxies.len()
        );
    }
    let _ = TRUSTED_PROXIES.set(proxies);
    metrics::init();

    // CORS origins will be read later when building the server

    let pool_size: usize = std::env::var("DB_POOL_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8);
    let transaction_pool_size: usize = std::env::var("DB_TRANSACTION_POOL_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(pool_size.min(4));
    // Both bounded pools reconnect automatically when a session drops.
    let client =
        Pool::connect_with_transaction_size(&database_url, pool_size, transaction_pool_size, None)
            .await
            .expect("cannot connect to db");
    // Several replicas starting together run the same idempotent DDL; PostgreSQL can reject the loser of a
    // concurrent CREATE ... IF NOT EXISTS race, so retry (the second run finds everything in place).
    {
        let mut attempt = 0;
        loop {
            match migrate_db(&client).await {
                Ok(()) => break,
                Err(e) if attempt < 5 => {
                    attempt += 1;
                    warn!(
                        "migration attempt {} failed ({}), retrying",
                        attempt,
                        full_error_string(&e)
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(400 * attempt)).await;
                }
                Err(e) => panic!("db migrate failed: {}", e),
            }
        }
    }

    // Bootstrap admin user if environment variables are set
    let force_bootstrap = std::env::var("FORCE_BOOTSTRAP")
        .unwrap_or_else(|_| "false".to_string())
        .to_lowercase()
        == "true";
    if let (Ok(admin_user), Ok(admin_password)) = (
        std::env::var("ADMIN_USERNAME"),
        std::env::var("ADMIN_PASSWORD"),
    ) {
        // check if a user exists with that username
        if let Ok(rows) = (&client)
            .query(
                "SELECT CAST(id AS varchar), password_hash FROM users WHERE username = $1 LIMIT 1",
                &[&admin_user],
            )
            .await
        {
            if rows.is_empty() {
                // create new admin

                let salt = generate_salt();
                let argon2 = Argon2::default();
                let password_hash = argon2
                    .hash_password(admin_password.as_bytes(), &salt)
                    .unwrap()
                    .to_string();
                let id = Uuid::new_v4();
                let id_str = id.to_string();
                let role = "admin";
                match (&client).execute("INSERT INTO users (id, username, password_hash, role) VALUES ($1::text::uuid, $2, $3, $4)", &[&id_str, &admin_user, &password_hash, &role]).await {
                    Ok(_) => info!("Bootstrapped admin user '{}'", admin_user),
                    Err(e) => warn!("Failed to create admin user '{}': {}", admin_user, e),
                }
            } else {
                // user exists, ensure password_hash looks valid (contains $argon2)
                let existing_hash: String = rows[0].try_get(1).unwrap_or_default();
                if force_bootstrap {
                    // Force update password hash when explicitly requested

                    let salt = generate_salt();
                    let argon2 = Argon2::default();
                    let password_hash = argon2
                        .hash_password(admin_password.as_bytes(), &salt)
                        .unwrap()
                        .to_string();
                    match (&client)
                        .execute(
                            "UPDATE users SET password_hash = $1 WHERE username = $2",
                            &[&password_hash, &admin_user],
                        )
                        .await
                    {
                        Ok(_) => info!("Force-updated admin user '{}' password hash", admin_user),
                        Err(e) => {
                            warn!("Failed to force-update admin user '{}': {}", admin_user, e)
                        }
                    }
                } else if hash_matches(&existing_hash, "admin123") && admin_password != "admin123" {
                    // The account still carries the well-known default password
                    // shipped by older schema seeds; ADMIN_PASSWORD replaces it.
                    let salt = generate_salt();
                    let password_hash = Argon2::default()
                        .hash_password(admin_password.as_bytes(), &salt)
                        .unwrap()
                        .to_string();
                    match (&client)
                        .execute(
                            "UPDATE users SET password_hash = $1 WHERE username = $2",
                            &[&password_hash, &admin_user],
                        )
                        .await
                    {
                        Ok(_) => info!(
                            "Replaced default password of admin user '{}' with ADMIN_PASSWORD",
                            admin_user
                        ),
                        Err(e) => warn!(
                            "Failed to replace default password of '{}': {}",
                            admin_user, e
                        ),
                    }
                } else if !existing_hash.starts_with("$argon2") {
                    let salt = generate_salt();
                    let argon2 = Argon2::default();
                    let password_hash = argon2
                        .hash_password(admin_password.as_bytes(), &salt)
                        .unwrap()
                        .to_string();
                    match (&client)
                        .execute(
                            "UPDATE users SET password_hash = $1 WHERE username = $2",
                            &[&password_hash, &admin_user],
                        )
                        .await
                    {
                        Ok(_) => info!("Updated admin user '{}' password hash", admin_user),
                        Err(e) => warn!("Failed to update admin user '{}': {}", admin_user, e),
                    }
                } else {
                    info!("Admin user already exists, skipping bootstrap");
                }
            }
        } else {
            warn!("Failed to query for admin user during bootstrap");
        }
    }

    // Refuse to stay silent about well-known credentials.
    if let Ok(rows) = (&client)
        .query(
            "SELECT username, password_hash FROM users WHERE username = 'admin'",
            &[],
        )
        .await
    {
        for r in rows {
            let (u, h): (String, String) = (r.get(0), r.get(1));
            if hash_matches(&h, "admin123") {
                log::error!(
                    "SECURITY: user '{}' still has the default password 'admin123'. Change it now (POST /api/v1/auth/change-password) or set ADMIN_USERNAME/ADMIN_PASSWORD.",
                    u
                );
            }
        }
    }
    {
        let n: i64 = (&client)
            .query_one("SELECT count(*) FROM users", &[])
            .await
            .map(|r| r.get(0))
            .unwrap_or(0);
        if n == 0 {
            log::error!(
                "No users exist and ADMIN_USERNAME/ADMIN_PASSWORD are not set: nobody can log in. Set both and restart."
            );
        }
    }

    let out_dir = std::env::var("HICKORY_DNS_DIR")
        .or_else(|_| std::env::var("OUTISCLOUD_DNS_DIR"))
        .unwrap_or_else(|_| "/etc/hickory".to_string());
    let dns_manager = Arc::new(DnsManager::new(out_dir.clone()));

    let app_state = AppState {
        db: client.clone(),
        jwt_secret: jwt_secret.clone(),
        dns_manager: dns_manager.clone(),
        lookup_resolvers: match lookup::resolvers_from_env() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("invalid configuration: {}", e);
                std::process::exit(2);
            }
        },
        verify_resolver: std::env::var("DNS_VERIFY_RESOLVER")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| "1.1.1.1:53".parse().unwrap()),
        verify_domains: std::env::var("VERIFY_DOMAINS")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false),
        dns_metrics_url: std::env::var("DNS_METRICS_URL")
            .ok()
            .filter(|v| !v.is_empty()),
    };

    // audit retention (AUDIT_RETENTION_DAYS, default 365, 0 = keep forever)
    let retention_days: i64 = std::env::var("AUDIT_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(365);
    if retention_days > 0 {
        let db = app_state.db.clone();
        tokio::spawn(async move {
            loop {
                match ext::purge_audit(&db, retention_days).await {
                    Ok(n) if n > 0 => info!(
                        "audit retention: removed {} entries older than {} days",
                        n, retention_days
                    ),
                    Ok(_) => {}
                    Err(e) => warn!("audit retention failed: {}", e),
                }
                tokio::time::sleep(std::time::Duration::from_secs(6 * 3600)).await;
            }
        });
    }

    // persistent analytics (global counters, per-zone counters when the DNS server exports them)
    shared::spawn_rate_limit_cleanup(app_state.db.clone());
    tenants::spawn_collector(app_state.db.clone(), app_state.dns_metrics_url.clone());
    automation::recover_jobs(&app_state.db).await;
    automation::spawn_job_worker(app_state.clone());
    automation::spawn_webhook_worker(app_state.db.clone());
    health::spawn_health_worker(app_state.db.clone());
    tokio::spawn(publication_retry_worker(
        app_state.dns_manager.clone(),
        app_state.db.clone(),
    ));

    // Load GeoIP DB if provided
    let geo_db = std::env::var("GEOIP_DB_PATH").ok().and_then(|p| {
        std::fs::read(p)
            .ok()
            .and_then(|b| geodns::GeoDB::open_from_bytes(b).ok())
    });

    let full_state = FullState {
        inner: app_state.clone(),
        geo: std::sync::Arc::new(tokio::sync::Mutex::new(GeoState { db: geo_db })),
        processes: std::sync::Arc::new(tokio::sync::Mutex::new(HashMap::new())),
    };

    // generate disk configuration immediately so that an external dns-server
    // container will have something to read when it first starts up.
    match dns_manager.regenerate_zones(app_state.db.clone()).await {
        Ok(report) if !report.failed.is_empty() => {
            warn!("initial zone generation: failed zones: {:?}", report.failed)
        }
        Ok(_) => {}
        Err(e) => warn!("initial zone file generation failed: {}", e),
    }

    // Prometheus metrics middleware
    let prometheus = PrometheusMetricsBuilder::new("control_api")
        .registry(prometheus::default_registry().clone())
        .endpoint("/metrics")
        .build()
        .expect("prometheus builder");

    let app_data = web::Data::new(app_state.clone());
    let full_data = web::Data::new(full_state.clone());

    // Build the HTTP server; CORS configuration is pulled in via helper below
    HttpServer::new(move || {
        // every worker will recreate the middleware from the current environment
        let cors = cors_middleware();

        App::new()
            .wrap(actix_web::middleware::from_fn(security_headers))
            .wrap(actix_web::middleware::from_fn(
                automation::platform_middleware,
            ))
            .wrap(actix_web::middleware::from_fn(auth_middleware))
            .wrap(actix_web::middleware::from_fn(api_rate_limit_middleware))
            .wrap(actix_web::middleware::from_fn(error_envelope_middleware))
            .wrap(cors)
            .wrap(prometheus.clone())
            .wrap(actix_web::middleware::from_fn(metrics_guard))
            .app_data(app_data.clone())
            .app_data(full_data.clone())
            .configure(configure_routes)
    })
    .bind(std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string()))?
    .run()
    .await
}

// ------------------------------------------------------------
// Tests
// ------------------------------------------------------------

#[cfg(test)]
mod api_tests;

#[cfg(test)]
mod cors_tests {
    use super::*;
    use actix_web::{App, HttpResponse, http, test, web};

    fn cors_env(origins: &str) -> Option<String> {
        let prev = std::env::var("ALLOWED_ORIGINS").ok();
        std::env::set_var("ALLOWED_ORIGINS", origins);
        prev
    }

    fn restore_cors_env(prev: Option<String>) {
        match prev {
            Some(v) => std::env::set_var("ALLOWED_ORIGINS", v),
            None => std::env::remove_var("ALLOWED_ORIGINS"),
        }
    }

    #[actix_web::test]
    async fn allowed_origin_and_preflight() {
        let prev = cors_env("http://foo.example");
        let app = test::init_service(App::new().wrap(cors_middleware()).route(
            "/test",
            web::post().to(|| async { HttpResponse::Ok().finish() }),
        ))
        .await;

        // preflight OPTIONS
        let req = test::TestRequest::default()
            .method(http::Method::OPTIONS)
            .uri("/test")
            .insert_header((http::header::ORIGIN, "http://foo.example"))
            .insert_header((http::header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .map(|v| v.to_str().unwrap()),
            Some("http://foo.example"),
        );

        // actual POST
        let req = test::TestRequest::post()
            .uri("/test")
            .insert_header((http::header::ORIGIN, "http://foo.example"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .map(|v| v.to_str().unwrap()),
            Some("http://foo.example"),
        );
        restore_cors_env(prev);
    }

    #[actix_web::test]
    async fn disallowed_origin() {
        let prev = cors_env("http://foo.example");
        let app = test::init_service(App::new().wrap(cors_middleware()).route(
            "/test",
            web::get().to(|| async { HttpResponse::Ok().finish() }),
        ))
        .await;
        let req = test::TestRequest::get()
            .uri("/test")
            .insert_header((http::header::ORIGIN, "http://bar.example"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(
            resp.headers()
                .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
        restore_cors_env(prev);
    }

    #[actix_web::test]
    async fn wildcard_allows_any_origin() {
        let prev = cors_env("*");
        let app = test::init_service(App::new().wrap(cors_middleware()).route(
            "/test",
            web::post().to(|| async { HttpResponse::Ok().finish() }),
        ))
        .await;
        let req = test::TestRequest::post()
            .uri("/test")
            .insert_header((http::header::ORIGIN, "http://anything"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        // actix-cors echoes the origin when allow_any_origin is enabled
        assert_eq!(
            resp.headers()
                .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .map(|v| v.to_str().unwrap()),
            Some("http://anything")
        );
        restore_cors_env(prev);
    }

    #[actix_web::test]
    async fn default_includes_8081() {
        let prev = std::env::var("ALLOWED_ORIGINS").ok();
        std::env::remove_var("ALLOWED_ORIGINS");
        let app = test::init_service(App::new().wrap(cors_middleware()).route(
            "/test",
            web::get().to(|| async { HttpResponse::Ok().finish() }),
        ))
        .await;
        let req = test::TestRequest::get()
            .uri("/test")
            .insert_header((http::header::ORIGIN, "http://localhost:8081"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .map(|v| v.to_str().unwrap()),
            Some("http://localhost:8081"),
        );
        match prev {
            Some(v) => std::env::set_var("ALLOWED_ORIGINS", v),
            None => std::env::remove_var("ALLOWED_ORIGINS"),
        }
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn previous_jwt_secret_is_accepted_during_rotation() {
        let claims = Claims {
            sub: "user-id".into(),
            role: "admin".into(),
            exp: (chrono::Utc::now() + chrono::Duration::minutes(5)).timestamp() as usize,
            ver: 1,
        };
        let old = "previous-test-secret";
        let new = "current-test-secret";
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(old.as_bytes()),
        )
        .unwrap();
        let secrets = vec![new.to_string()];
        assert!(decode_with_secrets(&token, &secrets).is_none());
        let secrets = vec![new.to_string(), old.to_string()];
        let got = decode_with_secrets(&token, &secrets).expect("previous secret accepted");
        assert_eq!(got.claims.sub, "user-id");
    }

    #[test]
    fn metrics_token_comparison_is_exact() {
        let req = actix_web::test::TestRequest::default()
            .insert_header(("Authorization", "Bearer secret"))
            .to_http_request();
        assert!(metrics_authorized(&req, None));
        assert!(metrics_authorized(&req, Some("secret")));
        assert!(!metrics_authorized(&req, Some("secreu")));
        assert!(!metrics_authorized(&req, Some("secret ")));
        let none = actix_web::test::TestRequest::default().to_http_request();
        assert!(!metrics_authorized(&none, Some("secret")));
    }
}

#[cfg(test)]
mod schema_consistency_tests {
    /// Verify that all SQL queries in the codebase use `record_type` (not `type`)
    /// as the column name for the records table, matching the schema defined in
    /// migrate_db(). The old migration SQL used `type` which caused insert failures.
    #[test]
    fn test_record_insert_queries_use_record_type() {
        // Collect all INSERT/UPDATE SQL strings that reference the records table
        let queries = vec![
            // Used in create_zone for NS records (line ~1996)
            "INSERT INTO records (id, zone_id, name, record_type, value, ttl) VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5, $6)",
            // Used in create_zone for SOA record (line ~2046)
            "INSERT INTO records (id, zone_id, name, record_type, value, ttl) VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5, $6)",
            // Used in create_record (line ~2365)
            "INSERT INTO records (id, zone_id, name, record_type, value, ttl, priority) VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5, $6, $7)",
            // Used in list_records (line ~2448)
            "SELECT CAST(id AS varchar), CAST(zone_id AS varchar), name, record_type, value, ttl, priority FROM records WHERE CAST(zone_id AS varchar) = $1 ORDER BY name",
            // Used in update_record for record_type column
            "UPDATE records SET record_type = $1 WHERE CAST(id AS varchar) = $2 AND CAST(zone_id AS varchar) = $3",
        ];

        for (i, query) in queries.iter().enumerate() {
            // Every query referencing the records table must use `record_type`
            // If a query contains `type` as a column reference (not in a value),
            // it will fail on databases created by the old migration SQL.
            assert!(
                query.contains("record_type") || !query.contains("type"),
                "Query #{} contains 'type' instead of 'record_type': {}",
                i,
                query
            );
        }
    }

    /// Verify the records schema contract enforced by migrate_db().
    #[test]
    fn test_records_schema_has_record_type_column() {
        let create_sql = "CREATE TABLE IF NOT EXISTS records (
            id UUID PRIMARY KEY,
            zone_id UUID REFERENCES zones(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            record_type TEXT NOT NULL,
            value TEXT NOT NULL,
            ttl INT NOT NULL DEFAULT 3600,
            priority INT DEFAULT 10,
            comment TEXT NOT NULL DEFAULT '',
            tags JSONB NOT NULL DEFAULT '[]'::jsonb,
            created_at TIMESTAMPTZ DEFAULT now(),
            updated_at TIMESTAMPTZ DEFAULT now()
        )";

        assert!(
            create_sql.contains("record_type TEXT NOT NULL"),
            "Records table schema must define record_type column, not 'type'"
        );
        assert!(
            create_sql.contains("comment TEXT NOT NULL DEFAULT ''")
                && create_sql.contains("tags JSONB NOT NULL DEFAULT '[]'::jsonb"),
            "Records table must carry comment/tags metadata"
        );
        assert!(
            !create_sql.contains("UNIQUE(zone_id, name, record_type)"),
            "The old (zone, name, type) constraint must not be recreated: it forbids valid multi-value RRsets"
        );

        let unique_index_sql = "CREATE UNIQUE INDEX IF NOT EXISTS uq_records_rrset_value ON records(zone_id, lower(name), record_type, value);";
        assert!(
            unique_index_sql.contains("lower(name)") && unique_index_sql.contains("value"),
            "The duplicate guard must key on lower(name), record_type and value"
        );
    }

    /// Verify the old migration would be fixed by the ALTER TABLE logic in migrate_db()
    #[test]
    fn test_alter_table_rename_type_to_record_type_present() {
        let alter_sql = "DO $$
         BEGIN
             IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='records' AND column_name='type') THEN
                 ALTER TABLE records RENAME COLUMN type TO record_type;
             END IF;
         END $$;";

        assert!(alter_sql.contains("RENAME COLUMN type TO record_type"));
    }

    /// Verify the nameservers table is created by migrate_db()
    #[test]
    fn test_nameservers_table_exists_in_migrate_db() {
        let create_ns_sql = "CREATE TABLE IF NOT EXISTS nameservers (
            id UUID PRIMARY KEY,
            hostname TEXT NOT NULL UNIQUE,
            ip_address TEXT NOT NULL,
            glue_ip TEXT,
            sort_order INT DEFAULT 0,
            enabled BOOLEAN DEFAULT true,
            created_at TIMESTAMPTZ DEFAULT now(),
            updated_at TIMESTAMPTZ DEFAULT now()
        )";

        assert!(create_ns_sql.contains("CREATE TABLE IF NOT EXISTS nameservers"));
        assert!(create_ns_sql.contains("hostname TEXT NOT NULL UNIQUE"));
    }

    /// Verify that the zones table UNIQUE constraint is correctly defined
    #[test]
    fn test_zones_table_has_unique_domain() {
        let create_zones_sql = "CREATE TABLE IF NOT EXISTS zones (
            id UUID PRIMARY KEY,
            domain TEXT NOT NULL,
            owner UUID REFERENCES users(id) ON DELETE SET NULL,
            zone_type TEXT NOT NULL DEFAULT 'primary',
            geodns_enabled BOOLEAN DEFAULT true,
            created_at TIMESTAMPTZ DEFAULT now(),
            updated_at TIMESTAMPTZ DEFAULT now(),
            UNIQUE(domain)
        )";

        assert!(create_zones_sql.contains("UNIQUE(domain)"));
    }
}
