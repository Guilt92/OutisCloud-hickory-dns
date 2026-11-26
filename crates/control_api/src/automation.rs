//! Platform automation: scoped API tokens, API-wide/tenant rate limiting,
//! idempotency middleware, durable jobs, signed webhooks and background workers.

use super::*;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

pub const SCHEMA: &str = "
ALTER TABLE zones ADD COLUMN IF NOT EXISTS hold_reason TEXT;
ALTER TABLE zones ADD COLUMN IF NOT EXISTS hold_until TIMESTAMPTZ;
ALTER TABLE zones ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;
ALTER TABLE zones ADD COLUMN IF NOT EXISTS verified_via TEXT;
ALTER TABLE zones ADD COLUMN IF NOT EXISTS last_verified_at TIMESTAMPTZ;
CREATE TABLE IF NOT EXISTS api_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    prefix TEXT NOT NULL,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id);
CREATE TABLE IF NOT EXISTS jobs (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    progress INT NOT NULL DEFAULT 0,
    total INT NOT NULL DEFAULT 0,
    input JSONB,
    result JSONB,
    error TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),
    completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_jobs_user_created ON jobs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE TABLE IF NOT EXISTS webhooks (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    events JSONB NOT NULL DEFAULT '[]'::jsonb,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_webhooks_user ON webhooks(user_id);
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id UUID PRIMARY KEY,
    webhook_id UUID NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event TEXT NOT NULL,
    payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ DEFAULT now(),
    response_status INT,
    error TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    delivered_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_pending ON webhook_deliveries(status, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook ON webhook_deliveries(webhook_id);
CREATE TABLE IF NOT EXISTS health_checks (
    id UUID PRIMARY KEY,
    zone_id UUID REFERENCES zones(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    record_name TEXT NOT NULL,
    record_type TEXT NOT NULL,
    target TEXT NOT NULL,
    port INT NOT NULL DEFAULT 53,
    interval_secs INT NOT NULL DEFAULT 30,
    timeout_ms INT NOT NULL DEFAULT 3000,
    failure_threshold INT NOT NULL DEFAULT 3,
    success_threshold INT NOT NULL DEFAULT 2,
    enabled BOOLEAN NOT NULL DEFAULT true,
    status TEXT NOT NULL DEFAULT 'unknown',
    consecutive_failures INT NOT NULL DEFAULT 0,
    consecutive_successes INT NOT NULL DEFAULT 0,
    last_checked_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_health_checks_zone ON health_checks(zone_id);
CREATE TABLE IF NOT EXISTS health_check_results (
    id UUID PRIMARY KEY,
    check_id UUID NOT NULL REFERENCES health_checks(id) ON DELETE CASCADE,
    ok BOOLEAN NOT NULL,
    latency_ms INT,
    error TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_health_check_results_check ON health_check_results(check_id, created_at DESC);
ALTER TABLE zones ADD COLUMN IF NOT EXISTS primary_addr TEXT;
ALTER TABLE zones ADD COLUMN IF NOT EXISTS last_transfer_at TIMESTAMPTZ;
ALTER TABLE zones ADD COLUMN IF NOT EXISTS last_transfer_serial BIGINT;
ALTER TABLE zones ADD COLUMN IF NOT EXISTS last_transfer_error TEXT;
ALTER TABLE zones ADD COLUMN IF NOT EXISTS transfer_serial BIGINT;
CREATE TABLE IF NOT EXISTS tsig_keys (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    algorithm TEXT NOT NULL DEFAULT 'hmac-sha256',
    secret TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    rotated_at TIMESTAMPTZ
);
";

/// Scope vocabulary accepted by personal API tokens.
pub const KNOWN_SCOPES: [&str; 15] = [
    "*",
    "admin",
    "read",
    "write",
    "zones:read",
    "zones:write",
    "records:read",
    "records:write",
    "analytics:read",
    "audit:read",
    "agents:read",
    "agents:write",
    "jobs:manage",
    "webhooks:manage",
    "tokens:manage",
];

fn scope_list(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn token_prefix(token: &str) -> String {
    token.chars().take(12).collect()
}

fn new_api_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!("ocd_{}", data_encoding::BASE64URL_NOPAD.encode(&bytes))
}

fn token_hash(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

pub(crate) fn scope_permits(
    scopes: &[String],
    method: &actix_web::http::Method,
    path: &str,
) -> bool {
    if scopes.iter().any(|s| s == "*" || s == "admin") {
        return true;
    }
    let admin_only = [
        "/api/v1/users",
        "/api/v1/servers",
        "/api/v1/nameservers",
        "/api/v1/tenants",
        "/api/v1/audit",
        "/api/v1/overview",
        "/api/v1/analytics/global",
    ];
    if admin_only.iter().any(|p| path.starts_with(p)) {
        return false;
    }
    if path.starts_with("/api/v1/tokens") || path.starts_with("/api/v1/webhooks") {
        return scopes
            .iter()
            .any(|s| s == "tokens:manage" || s == "webhooks:manage");
    }
    let write = !is_read_method(method);
    let resource = path
        .strip_prefix("/api/v1/")
        .and_then(|p| p.split('/').next())
        .unwrap_or("");
    let resource = match resource {
        "zones" => {
            if path.contains("/records") {
                "records"
            } else {
                "zones"
            }
        }
        "georules" => "zones",
        "config" => "agents",
        "dns" => "zones",
        "analytics" => "analytics",
        "audit" => "audit",
        "agents" => "agents",
        other => other,
    };
    let specific = format!("{}:{}", resource, if write { "write" } else { "read" });
    scopes.iter().any(|s| {
        s == &specific
            || s == if write { "write" } else { "read" }
            || (write && s == &format!("{}:write", resource))
    })
}

/// The authenticated principal attached to a request by `auth_middleware`.
#[derive(Clone)]
pub struct AuthCtx {
    pub claims: Claims,
    /// Present when the request used a personal API token rather than a JWT.
    pub token_id: Option<String>,
    pub scopes: Option<Vec<String>>,
}

/// Verify a personal API token (`ocd_...`). Returns the same principal shape as
/// the JWT middleware so every existing handler works unchanged.
pub(crate) async fn authenticate_api_token(
    db: &Pool,
    token: &str,
) -> Result<AuthCtx, &'static str> {
    let hash = token_hash(token);
    let row = db
        .query_opt(
            "SELECT CAST(t.id AS varchar), CAST(t.user_id AS varchar), t.scopes, t.expires_at, \
                    t.revoked_at, u.role \
             FROM api_tokens t JOIN users u ON u.id = t.user_id \
             WHERE t.token_hash = $1",
            &[&hash],
        )
        .await
        .map_err(|_| "database error")?;
    let Some(r) = row else {
        return Err("unauthorized");
    };
    let revoked_at: Option<chrono::DateTime<chrono::Utc>> = r.get(4);
    if revoked_at.is_some() {
        return Err("token revoked");
    }
    let expires_at: Option<chrono::DateTime<chrono::Utc>> = r.get(3);
    if expires_at.map(|e| e <= chrono::Utc::now()).unwrap_or(false) {
        return Err("token expired");
    }
    let token_id: String = r.get(0);
    let user_id: String = r.get(1);
    let scopes: serde_json::Value = r.get(2);
    let role: String = r.get(5);
    let _ = db
        .execute(
            "UPDATE api_tokens SET last_used_at = now() WHERE id = $1::text::uuid \
             AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')",
            &[&token_id],
        )
        .await;
    Ok(AuthCtx {
        claims: Claims {
            sub: user_id,
            role,
            exp: 0,
            ver: 0,
        },
        token_id: Some(token_id),
        scopes: Some(scope_list(&scopes)),
    })
}

#[derive(Deserialize)]
pub struct CreateTokenReq {
    pub name: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub expires_in_days: Option<i64>,
}

fn token_row_to_json(r: &tokio_postgres::Row) -> serde_json::Value {
    let scopes: serde_json::Value = r.get(4);
    serde_json::json!({
        "id": r.get::<_, String>(0),
        "name": r.get::<_, String>(1),
        "prefix": r.get::<_, String>(2),
        "scopes": scope_list(&scopes),
        "expires_at": r.get::<_, Option<String>>(3),
        "last_used_at": r.get::<_, Option<String>>(5),
        "revoked_at": r.get::<_, Option<String>>(6),
        "created_at": r.get::<_, String>(7),
    })
}

pub async fn create_token(
    body: web::Json<CreateTokenReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let name = body.name.trim();
    if name.is_empty() || name.len() > 100 {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "name must be 1-100 characters"}));
    }
    let mut scopes = body.scopes.clone();
    scopes.sort();
    scopes.dedup();
    if scopes.is_empty() {
        scopes.push("read".to_string());
    }
    for s in &scopes {
        if !KNOWN_SCOPES.contains(&s.as_str()) {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": format!("unknown scope {s}")}));
        }
        if s == "admin" && tok.claims.role != "admin" {
            return HttpResponse::Forbidden()
                .json(serde_json::json!({"error": "only administrators may create admin tokens"}));
        }
    }
    let days = body.expires_in_days.unwrap_or(90);
    if !(1..=365).contains(&days) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "expires_in_days must be between 1 and 365"}));
    }
    let token = new_api_token();
    let hash = token_hash(&token);
    let id = Uuid::new_v4().to_string();
    let scopes_json = serde_json::Value::Array(
        scopes
            .iter()
            .cloned()
            .map(serde_json::Value::String)
            .collect(),
    );
    let expires = chrono::Utc::now() + chrono::Duration::days(days);
    if let Err(e) = data
        .db
        .execute(
            "INSERT INTO api_tokens (id, user_id, name, token_hash, prefix, scopes, expires_at) \
             VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5, $6, $7)",
            &[
                &id,
                &tok.claims.sub,
                &name,
                &hash,
                &token_prefix(&token),
                &scopes_json,
                &expires,
            ],
        )
        .await
    {
        warn!("create_token: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "database error"}));
    }
    audit(
        &data.db,
        Some(&tok.claims.sub),
        "create_api_token",
        "api_token",
        Some(id.clone()),
        &req,
        serde_json::json!({"name": name, "scopes": scopes}),
    )
    .await;
    HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "name": name,
        "token": token,
        "prefix": token_prefix(&token),
        "scopes": scopes,
        "expires_at": expires.to_rfc3339(),
        "warning": "this is the only time the token is shown; store it securely"
    }))
}

pub async fn list_tokens(
    page: web::Query<ext::PageQuery>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let (limit, offset, qtext) = page.parts();
    let sort = match page.sort_column(
        &[("created", "created_at"), ("expires", "expires_at"), ("name", "name")],
        "created",
    ) {
        Ok(value) => value,
        Err(()) => return HttpResponse::BadRequest().json(serde_json::json!({"error":"invalid_query","details":"Unsupported sort field or order"})),
    };
    let direction = match page.sort_direction_or("desc") {
        Ok(value) => value,
        Err(()) => return HttpResponse::BadRequest().json(serde_json::json!({"error":"invalid_query","details":"Unsupported sort field or order"})),
    };
    let total: i64 = match data.db.query_one(
        "SELECT count(*) FROM api_tokens WHERE CAST(user_id AS varchar) = $1 AND ($2::text IS NULL OR name ILIKE '%' || $2 || '%' OR prefix ILIKE '%' || $2 || '%')",
        &[&tok.claims.sub, &qtext],
    ).await {
        Ok(row) => row.get(0),
        Err(e) => {
            warn!("list_tokens count: {}", full_error_string(&e));
            return HttpResponse::InternalServerError().json(serde_json::json!({"error":"database_error"}));
        }
    };
    let sql = format!(
        "SELECT CAST(id AS varchar), name, prefix, to_char(expires_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), scopes, to_char(last_used_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), to_char(revoked_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), to_char(created_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM api_tokens WHERE CAST(user_id AS varchar) = $1 AND ($2::text IS NULL OR name ILIKE '%' || $2 || '%' OR prefix ILIKE '%' || $2 || '%') ORDER BY {sort} {direction}, id LIMIT $3::bigint OFFSET $4::bigint"
    );
    match data
        .db
        .query(&sql, &[&tok.claims.sub, &qtext, &limit, &offset])
        .await
    {
        Ok(rows) => {
            let mut out = Vec::new();
            for r in &rows {
                out.push(token_row_to_json(r));
            }
            HttpResponse::Ok()
                .insert_header(("X-Total-Count", total.to_string()))
                .json(serde_json::json!({"tokens": out}))
        }
        Err(e) => {
            warn!("list_tokens: {}", full_error_string(&e));
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "database error"}))
        }
    }
}

pub async fn revoke_token(
    path: web::Path<String>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let id = path.into_inner();
    match data
        .db
        .execute(
            "UPDATE api_tokens SET revoked_at = now() WHERE CAST(id AS varchar) = $1 \
             AND CAST(user_id AS varchar) = $2 AND revoked_at IS NULL",
            &[&id, &tok.claims.sub],
        )
        .await
    {
        Ok(0) => HttpResponse::NotFound().json(serde_json::json!({"error": "token not found"})),
        Ok(_) => {
            audit(
                &data.db,
                Some(&tok.claims.sub),
                "revoke_api_token",
                "api_token",
                Some(id.clone()),
                &req,
                serde_json::json!({}),
            )
            .await;
            HttpResponse::Ok().json(serde_json::json!({"revoked": true}))
        }
        Err(e) => {
            warn!("revoke_token: {}", full_error_string(&e));
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "database error"}))
        }
    }
}

pub async fn rotate_token(
    path: web::Path<String>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let id = path.into_inner();
    let row = match data
        .db
        .query_opt(
            "SELECT name, scopes FROM api_tokens WHERE CAST(id AS varchar) = $1 \
             AND CAST(user_id AS varchar) = $2 AND revoked_at IS NULL",
            &[&id, &tok.claims.sub],
        )
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({"error": "token not found"}));
        }
        Err(e) => {
            warn!("rotate_token lookup: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    };
    let name: String = row.get(0);
    let scopes: serde_json::Value = row.get(1);
    let token = new_api_token();
    let new_id = Uuid::new_v4().to_string();
    let expires = chrono::Utc::now() + chrono::Duration::days(90);
    let tx = match data.db.begin().await {
        Ok(t) => t,
        Err(e) => {
            warn!("rotate_token transaction: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    };
    let c = tx.client();
    let ok = async {
        c.batch_execute("BEGIN").await?;
        c.execute(
            "UPDATE api_tokens SET revoked_at = now() WHERE CAST(id AS varchar) = $1",
            &[&id],
        )
        .await?;
        c.execute(
            "INSERT INTO api_tokens (id, user_id, name, token_hash, prefix, scopes, expires_at) \
             VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5, $6, $7)",
            &[
                &new_id,
                &tok.claims.sub,
                &name,
                &token_hash(&token),
                &token_prefix(&token),
                &scopes,
                &expires,
            ],
        )
        .await?;
        c.batch_execute("COMMIT").await
    }
    .await;
    drop(tx);
    if let Err(e) = ok {
        warn!("rotate_token: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "database error"}));
    }
    audit(
        &data.db,
        Some(&tok.claims.sub),
        "rotate_api_token",
        "api_token",
        Some(new_id.clone()),
        &req,
        serde_json::json!({"rotated_from": id}),
    )
    .await;
    HttpResponse::Created().json(serde_json::json!({
        "id": new_id, "name": name, "token": token, "prefix": token_prefix(&token),
        "scopes": scope_list(&scopes), "expires_at": expires.to_rfc3339(),
        "warning": "this is the only time the new token is shown"
    }))
}

// ---------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct JobQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub status: Option<String>,
    pub sort: Option<String>,
    pub order: Option<String>,
}

pub async fn list_jobs(
    q: web::Query<JobQuery>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = q.offset.unwrap_or(0).max(0);
    let admin = tok.claims.role == "admin";
    let sort = match q.sort.as_deref().unwrap_or("created") {
        "created" => "created_at",
        "updated" => "updated_at",
        "kind" => "kind",
        "status" => "status",
        _ => {
            return HttpResponse::BadRequest().json(
                serde_json::json!({"error":"invalid_query","details":"Unsupported sort field"}),
            );
        }
    };
    let direction =
        match q.order.as_deref().unwrap_or("desc") {
            "asc" => "ASC",
            "desc" => "DESC",
            _ => return HttpResponse::BadRequest().json(
                serde_json::json!({"error":"invalid_query","details":"Order must be asc or desc"}),
            ),
        };
    let total: i64 = match data.db.query_one(
        "SELECT count(*) FROM jobs WHERE ($1 OR CAST(user_id AS varchar) = $2) AND ($3::text IS NULL OR status = $3)",
        &[&admin, &tok.claims.sub, &q.status],
    ).await {
        Ok(row) => row.get(0),
        Err(e) => {
            warn!("list_jobs count: {}", full_error_string(&e));
            return HttpResponse::InternalServerError().json(serde_json::json!({"error":"database_error"}));
        }
    };
    let sql = format!(
        "SELECT CAST(id AS varchar), kind, status, progress, total, result, error, \
                      to_char(created_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
                      to_char(updated_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') \
               FROM jobs WHERE ($1 OR CAST(user_id AS varchar) = $2) \
                 AND ($3::text IS NULL OR status = $3) \
               ORDER BY {sort} {direction}, id LIMIT $4 OFFSET $5"
    );
    match data
        .db
        .query(&sql, &[&admin, &tok.claims.sub, &q.status, &limit, &offset])
        .await
    {
        Ok(rows) => HttpResponse::Ok()
            .insert_header(("X-Total-Count", total.to_string()))
            .json(serde_json::json!({
                "jobs": rows.iter().map(|r| serde_json::json!({
                    "id": r.get::<_, String>(0), "kind": r.get::<_, String>(1),
                    "status": r.get::<_, String>(2), "progress": r.get::<_, i32>(3),
                    "total": r.get::<_, i32>(4), "result": r.get::<_, Option<serde_json::Value>>(5),
                    "error": r.get::<_, Option<String>>(6), "created_at": r.get::<_, String>(7),
                    "updated_at": r.get::<_, String>(8),
                })).collect::<Vec<_>>()
            })),
        Err(e) => {
            warn!("list_jobs: {}", full_error_string(&e));
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "database error"}))
        }
    }
}

pub async fn get_job(
    path: web::Path<String>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let id = path.into_inner();
    let admin = tok.claims.role == "admin";
    match data.db.query_opt(
        "SELECT CAST(id AS varchar), kind, status, progress, total, input, result, error, \
                to_char(created_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
                to_char(updated_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
                to_char(completed_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') \
         FROM jobs WHERE CAST(id AS varchar) = $1 AND ($2 OR CAST(user_id AS varchar) = $3)",
        &[&id, &admin, &tok.claims.sub],
    ).await {
        Ok(Some(r)) => HttpResponse::Ok().json(serde_json::json!({
            "id": r.get::<_, String>(0), "kind": r.get::<_, String>(1),
            "status": r.get::<_, String>(2), "progress": r.get::<_, i32>(3),
            "total": r.get::<_, i32>(4), "input": r.get::<_, Option<serde_json::Value>>(5),
            "result": r.get::<_, Option<serde_json::Value>>(6), "error": r.get::<_, Option<String>>(7),
            "created_at": r.get::<_, String>(8), "updated_at": r.get::<_, String>(9),
            "completed_at": r.get::<_, Option<String>>(10),
        })),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "job not found"})),
        Err(e) => {
            warn!("get_job: {}", full_error_string(&e));
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "database error"}))
        }
    }
}

pub async fn cancel_job(
    path: web::Path<String>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let id = path.into_inner();
    let admin = tok.claims.role == "admin";
    match data
        .db
        .execute(
            "UPDATE jobs SET status = 'cancelled', updated_at = now(), completed_at = now() \
         WHERE CAST(id AS varchar) = $1 AND ($2 OR CAST(user_id AS varchar) = $3) \
           AND status IN ('queued','running')",
            &[&id, &admin, &tok.claims.sub],
        )
        .await
    {
        Ok(0) => {
            HttpResponse::Conflict().json(serde_json::json!({"error": "job is not cancellable"}))
        }
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "cancelled"})),
        Err(e) => {
            warn!("cancel_job: {}", full_error_string(&e));
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "database error"}))
        }
    }
}

pub async fn job_status(db: &Pool, job_id: &str) -> Option<String> {
    db.query_opt(
        "SELECT status FROM jobs WHERE CAST(id AS varchar) = $1",
        &[&job_id],
    )
    .await
    .ok()
    .flatten()
    .map(|r| r.get(0))
}

pub async fn job_progress(db: &Pool, job_id: &str, progress: i32) {
    let _ = db
        .execute(
            "UPDATE jobs SET progress = $2, updated_at = now() WHERE CAST(id AS varchar) = $1",
            &[&job_id, &progress],
        )
        .await;
}

pub async fn job_finish(
    db: &Pool,
    job_id: &str,
    status: &str,
    result: Option<&serde_json::Value>,
    error: Option<&str>,
) {
    let _ = db
        .execute(
            "UPDATE jobs SET status = $2, result = $3, error = $4, progress = total, \
                    updated_at = now(), completed_at = now() WHERE CAST(id AS varchar) = $1",
            &[&job_id, &status, &result, &error],
        )
        .await;
}

/// Requeue jobs that were running when the process died.
pub async fn recover_jobs(db: &Pool) {
    match db
        .execute(
            "UPDATE jobs SET status = 'queued', updated_at = now() \
             WHERE status = 'running' AND updated_at < now() - interval '10 minutes'",
            &[],
        )
        .await
    {
        Ok(n) if n > 0 => info!("requeued {} interrupted job(s)", n),
        Ok(_) => {}
        Err(e) => warn!("job recovery: {}", full_error_string(&e)),
    }
}

/// Claim and execute queued jobs. The worker is safe to run on several replicas:
/// `FOR UPDATE SKIP LOCKED` gives each job to exactly one worker.
pub fn spawn_job_worker(state: AppState) {
    tokio::spawn(async move {
        loop {
            let claimed = state
                .db
                .query_opt(
                    "UPDATE jobs SET status = 'running', updated_at = now() \
                     WHERE id = (SELECT id FROM jobs WHERE status = 'queued' \
                                 ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) \
                     RETURNING CAST(id AS varchar), kind, input, CAST(user_id AS varchar)",
                    &[],
                )
                .await;
            match claimed {
                Ok(Some(row)) => {
                    let id: String = row.get(0);
                    let kind: String = row.get(1);
                    let input: Option<serde_json::Value> = row.get(2);
                    let user_id: String = row.get(3);
                    let result = match kind.as_str() {
                        "bulk_import" => {
                            crate::zone_ops::run_bulk_import_job(&state, &id, &user_id, input).await
                        }
                        other => Err(format!("unknown job kind {other}")),
                    };
                    match result {
                        Ok(v) => {
                            job_finish(&state.db, &id, "completed", Some(&v), None).await;
                        }
                        Err(e) => {
                            if job_status(&state.db, &id).await.as_deref() == Some("cancelled") {
                                continue;
                            }
                            warn!("job {} failed: {}", id, e);
                            job_finish(&state.db, &id, "failed", None, Some(&e)).await;
                        }
                    }
                }
                Ok(None) => {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                Err(e) => {
                    warn!("job worker: {}", full_error_string(&e));
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Webhooks
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct WebhookReq {
    pub url: String,
    #[serde(default)]
    pub events: Vec<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

pub(crate) fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                || o[0] == 100 && (o[1] & 0xc0) == 64
                || o[0] == 192 && o[1] == 0 && o[2] == 0
                || o[0] == 198 && (o[1] & 0xfe) == 18
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// Reject webhook URLs that would let a tenant reach the platform's own network.
pub async fn validate_webhook_url(raw: &str) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(raw).map_err(|e| format!("invalid URL: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("webhook URL must use http or https".into());
    }
    let host = url.host_str().ok_or("webhook URL has no host")?.to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    if std::env::var("WEBHOOK_ALLOW_PRIVATE")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return Ok(url);
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !is_public_ip(ip) {
            return Err("webhook URL points to a private or reserved address".into());
        }
        return Ok(url);
    }
    let addrs = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|e| format!("cannot resolve webhook host: {e}"))?;
    let mut any = false;
    for a in addrs {
        any = true;
        if !is_public_ip(a.ip()) {
            return Err("webhook URL resolves to a private or reserved address".into());
        }
    }
    if !any {
        return Err("webhook host did not resolve".into());
    }
    Ok(url)
}

pub async fn create_webhook(
    body: web::Json<WebhookReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    if let Err(e) = validate_webhook_url(&body.url).await {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": e}));
    }
    if body.events.len() > 50 {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "at most 50 events are allowed"}));
    }
    let secret = {
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        data_encoding::HEXLOWER.encode(&b)
    };
    let id = Uuid::new_v4().to_string();
    let events = serde_json::Value::Array(
        body.events
            .iter()
            .cloned()
            .map(serde_json::Value::String)
            .collect(),
    );
    if let Err(e) = data
        .db
        .execute(
            "INSERT INTO webhooks (id, user_id, url, secret, events, enabled) \
             VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5, $6)",
            &[
                &id,
                &tok.claims.sub,
                &body.url,
                &secret,
                &events,
                &body.enabled.unwrap_or(true),
            ],
        )
        .await
    {
        warn!("create_webhook: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "database error"}));
    }
    audit(
        &data.db,
        Some(&tok.claims.sub),
        "create_webhook",
        "webhook",
        Some(id.clone()),
        &req,
        serde_json::json!({"url": body.url, "events": body.events}),
    )
    .await;
    HttpResponse::Created().json(serde_json::json!({
        "id": id, "url": body.url, "events": body.events, "secret": secret,
        "warning": "store the signing secret; it is shown once"
    }))
}

pub async fn list_webhooks(
    page: web::Query<ext::PageQuery>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let (limit, offset, qtext) = page.parts();
    let sort = match page.sort_column(&[("created", "created_at"), ("url", "url")], "created") {
        Ok(value) => value,
        Err(()) => return HttpResponse::BadRequest().json(serde_json::json!({"error":"invalid_query","details":"Unsupported sort field or order"})),
    };
    let direction = match page.sort_direction_or("desc") {
        Ok(value) => value,
        Err(()) => return HttpResponse::BadRequest().json(serde_json::json!({"error":"invalid_query","details":"Unsupported sort field or order"})),
    };
    let admin = tok.claims.role == "admin";
    let total: i64 = match data.db.query_one(
        "SELECT count(*) FROM webhooks WHERE ($1 OR CAST(user_id AS varchar) = $2) AND ($3::text IS NULL OR url ILIKE '%' || $3 || '%')",
        &[&admin, &tok.claims.sub, &qtext],
    ).await {
        Ok(row) => row.get(0),
        Err(e) => {
            warn!("list_webhooks count: {}", full_error_string(&e));
            return HttpResponse::InternalServerError().json(serde_json::json!({"error":"database_error"}));
        }
    };
    let sql = format!(
        "SELECT CAST(id AS varchar), url, events, enabled, to_char(created_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM webhooks WHERE ($1 OR CAST(user_id AS varchar) = $2) AND ($3::text IS NULL OR url ILIKE '%' || $3 || '%') ORDER BY {sort} {direction}, id LIMIT $4::bigint OFFSET $5::bigint"
    );
    match data
        .db
        .query(&sql, &[&admin, &tok.claims.sub, &qtext, &limit, &offset])
        .await
    {
        Ok(rows) => HttpResponse::Ok()
            .insert_header(("X-Total-Count", total.to_string()))
            .json(serde_json::json!({
                "webhooks": rows.iter().map(|r| serde_json::json!({
                    "id": r.get::<_, String>(0), "url": r.get::<_, String>(1),
                    "events": scope_list(&r.get::<_, serde_json::Value>(2)),
                    "enabled": r.get::<_, bool>(3), "created_at": r.get::<_, String>(4),
                })).collect::<Vec<_>>()
            })),
        Err(e) => {
            warn!("list_webhooks: {}", full_error_string(&e));
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "database error"}))
        }
    }
}

pub async fn delete_webhook(
    path: web::Path<String>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let id = path.into_inner();
    let admin = tok.claims.role == "admin";
    match data.db.execute(
        "DELETE FROM webhooks WHERE CAST(id AS varchar) = $1 AND ($2 OR CAST(user_id AS varchar) = $3)",
        &[&id, &admin, &tok.claims.sub],
    ).await {
        Ok(0) => HttpResponse::NotFound().json(serde_json::json!({"error": "webhook not found"})),
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"deleted": true})),
        Err(e) => {
            warn!("delete_webhook: {}", full_error_string(&e));
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "database error"}))
        }
    }
}

/// Enqueue a signed webhook event for every matching subscription.
pub async fn dispatch_event(
    db: &Pool,
    event: &str,
    resource_type: &str,
    resource_id: Option<&str>,
    details: &serde_json::Value,
) {
    let payload = serde_json::json!({
        "event": event,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "data": details,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    let rows = match db
        .query(
            "SELECT CAST(id AS varchar) FROM webhooks WHERE enabled AND (events ? '*' OR events ? $1)",
            &[&event],
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("webhook dispatch lookup: {}", full_error_string(&e));
            return;
        }
    };
    for r in rows {
        let webhook_id: String = r.get(0);
        let _ = db
            .execute(
                "INSERT INTO webhook_deliveries (id, webhook_id, event, payload) \
                 VALUES ($1::text::uuid, $2::text::uuid, $3, $4)",
                &[&Uuid::new_v4().to_string(), &webhook_id, &event, &payload],
            )
            .await;
    }
}

fn sign(secret: &str, timestamp: i64, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    data_encoding::HEXLOWER.encode(&mac.finalize().into_bytes())
}

async fn deliver_one(
    client: &reqwest::Client,
    url: &str,
    secret: &str,
    event: &str,
    payload: &serde_json::Value,
) -> Result<u16, String> {
    let body = serde_json::to_vec(payload).map_err(|e| e.to_string())?;
    let ts = chrono::Utc::now().timestamp();
    let sig = sign(secret, ts, &body);
    let resp = client
        .post(url)
        .header("content-type", "application/json")
        .header("user-agent", "outiscloud-webhooks/1")
        .header("x-outis-event", event)
        .header("x-outis-signature", format!("t={ts},v1={sig}"))
        .body(body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    Ok(resp.status().as_u16())
}

pub fn spawn_webhook_worker(db: Arc<Pool>) {
    tokio::spawn(async move {
        let client = match reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                warn!("webhook client: {}", e);
                return;
            }
        };
        loop {
            let rows = db
                .query(
                    "SELECT CAST(d.id AS varchar), d.event, d.payload, d.attempts, w.url, w.secret \
                     FROM webhook_deliveries d JOIN webhooks w ON w.id = d.webhook_id \
                     WHERE d.status = 'pending' AND d.next_attempt_at <= now() \
                       AND w.enabled ORDER BY d.next_attempt_at LIMIT 10",
                    &[],
                )
                .await
                .unwrap_or_default();
            for r in rows {
                let id: String = r.get(0);
                let event: String = r.get(1);
                let payload: serde_json::Value = r.get(2);
                let attempts: i32 = r.get(3);
                let url: String = r.get(4);
                let secret: String = r.get(5);
                let outcome = deliver_one(&client, &url, &secret, &event, &payload).await;
                match outcome {
                    Ok(status) if (200..300).contains(&status) => {
                        let _ = db
                            .execute(
                                "UPDATE webhook_deliveries SET status = 'delivered', attempts = attempts + 1, \
                                 response_status = $2, delivered_at = now(), error = NULL WHERE CAST(id AS varchar) = $1",
                                &[&id, &(status as i32)],
                            )
                            .await;
                    }
                    other => {
                        let attempts = attempts + 1;
                        let err = match other {
                            Ok(status) => format!("HTTP {status}"),
                            Err(e) => e,
                        };
                        let (status, delay) = if attempts >= 8 {
                            ("dead_letter", 0)
                        } else {
                            ("pending", 5 * 2i64.pow((attempts - 1).min(6) as u32))
                        };
                        let _ = db
                            .execute(
                                "UPDATE webhook_deliveries SET status = $2, attempts = $3, error = $4, \
                                 next_attempt_at = now() + make_interval(secs => $5) WHERE CAST(id AS varchar) = $1",
                                &[&id, &status, &attempts, &err, &(delay as f64)],
                            )
                            .await;
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    });
}

// ---------------------------------------------------------------------------
// API-wide / per-tenant rate limiting
// ---------------------------------------------------------------------------

/// Combined tenant budget and idempotent replay middleware. It authenticates
/// on its own so it does not depend on middleware registration order.
pub async fn platform_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<actix_web::body::BoxBody>, actix_web::Error> {
    let state = req.app_data::<web::Data<AppState>>().cloned();
    let Some(state) = state else {
        return Ok(next.call(req).await?.map_into_boxed_body());
    };
    let path = req.path().to_string();
    if matches!(
        path.as_str(),
        "/health" | "/ready" | "/metrics" | "/openapi.json"
    ) {
        return Ok(next.call(req).await?.map_into_boxed_body());
    }
    // auth_middleware runs first and attaches the verified principal.
    let ctx = req.extensions().get::<AuthCtx>().cloned();
    if let Some(ctx) = ctx {
        // Tenant-level budget. A caller can select one of their tenants with
        // X-Tenant-Id; otherwise the user's first membership is used.
        if let Some(tenant) = req
            .headers()
            .get("x-tenant-id")
            .and_then(|h| h.to_str().ok())
            .map(str::to_string)
            .or_else(|| {
                None // resolved below
            })
        {
            let bucket = format!("api-tenant:{tenant}");
            let limit = tenant_rate_limit();
            if let Some(wait) = shared::limited(&state.db, &bucket, limit, 60, || true).await {
                let response = HttpResponse::TooManyRequests()
                    .insert_header((header::RETRY_AFTER, wait.to_string()))
                    .json(serde_json::json!({"error": "tenant_rate_limited", "retry_after": wait}));
                return Ok(req.into_response(response).map_into_boxed_body());
            }
        } else if let Ok(Some(row)) = state
            .db
            .query_opt(
                "SELECT CAST(tenant_id AS varchar) FROM tenant_members \
                 WHERE CAST(user_id AS varchar) = $1 ORDER BY created_at LIMIT 1",
                &[&ctx.claims.sub],
            )
            .await
        {
            let tenant: String = row.get(0);
            let bucket = format!("api-tenant:{tenant}");
            let limit = tenant_rate_limit();
            if let Some(wait) = shared::limited(&state.db, &bucket, limit, 60, || true).await {
                let response = HttpResponse::TooManyRequests()
                    .insert_header((header::RETRY_AFTER, wait.to_string()))
                    .json(serde_json::json!({"error": "tenant_rate_limited", "retry_after": wait}));
                return Ok(req.into_response(response).map_into_boxed_body());
            }
        }

        // Idempotent replay/store for every mutating request.
        if !is_read_method(req.method()) {
            if let Some(key) = idempotency_key(req.request()) {
                let endpoint = format!("{} {}", req.method(), path);
                if let Some(response) =
                    idempotency_replay(&state.db, &key, &ctx.claims.sub, &endpoint).await
                {
                    return Ok(req.into_response(response).map_into_boxed_body());
                }
                let res = next.call(req).await?;
                let (req2, res2) = res.into_parts();
                let status = res2.status();
                let content_type = res2
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let body = actix_web::body::to_bytes(res2.into_body())
                    .await
                    .map_err(|_| actix_web::error::ErrorInternalServerError("response body"))?;
                if content_type.contains("application/json") && status.as_u16() < 500 {
                    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body) {
                        idempotency_store(
                            &state.db,
                            &key,
                            &ctx.claims.sub,
                            &endpoint,
                            status.as_u16(),
                            &json,
                        )
                        .await;
                    }
                }
                let response = HttpResponse::build(status)
                    .insert_header((header::CONTENT_TYPE, content_type))
                    .body(body);
                return Ok(ServiceResponse::new(req2, response).map_into_boxed_body());
            }
        }
    }
    Ok(next.call(req).await?.map_into_boxed_body())
}

fn tenant_rate_limit() -> u32 {
    std::env::var("API_RATE_LIMIT_PER_TENANT")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(3000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_enforcement_is_least_privilege() {
        let read = vec!["zones:read".to_string()];
        let write = vec!["zones:write".to_string()];
        let admin = vec!["admin".to_string()];
        assert!(scope_permits(
            &read,
            &actix_web::http::Method::GET,
            "/api/v1/zones"
        ));
        assert!(!scope_permits(
            &read,
            &actix_web::http::Method::POST,
            "/api/v1/zones"
        ));
        assert!(scope_permits(
            &write,
            &actix_web::http::Method::POST,
            "/api/v1/zones"
        ));
        assert!(!scope_permits(
            &read,
            &actix_web::http::Method::GET,
            "/api/v1/users"
        ));
        assert!(scope_permits(
            &admin,
            &actix_web::http::Method::GET,
            "/api/v1/users"
        ));
    }

    #[test]
    fn private_webhook_targets_are_rejected() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.1",
            "169.254.1.1",
            "::1",
            "fd00::1",
        ] {
            assert!(!is_public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(is_public_ip(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn generated_tokens_are_prefixed_and_unique() {
        let a = new_api_token();
        let b = new_api_token();
        assert!(a.starts_with("ocd_"));
        assert_ne!(a, b);
        assert_eq!(token_hash(&a).len(), 64);
    }
}
