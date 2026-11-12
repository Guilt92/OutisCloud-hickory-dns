//! Tenants (organisations), quotas, the aggregated overview and persistent analytics.
//!
//! Model: a tenant owns zones (`zones.tenant_id`). Users belong to tenants through
//! `tenant_members` with the roles `owner` (manage members and zones), `editor` (change records)
//! and `viewer` (read). The historic `zones.owner` and `zone_members` sharing keep working; tenant
//! membership is an additional way to get access. Platform administrators are not limited by
//! quotas. Quotas are `NULL` (= unlimited) or a number.

use super::*;
use std::time::Duration;

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    max_zones INTEGER CHECK (max_zones IS NULL OR max_zones >= 0),
    max_records INTEGER CHECK (max_records IS NULL OR max_records >= 0),
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS tenant_members (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner','editor','viewer')),
    created_at TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_tenant_members_user ON tenant_members(user_id);
ALTER TABLE zones ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_zones_tenant ON zones(tenant_id);
CREATE INDEX IF NOT EXISTS idx_zones_owner ON zones(owner);
-- persistent analytics: deltas per sampling interval (no foreign keys: history must survive zone deletion)
CREATE TABLE IF NOT EXISTS analytics_samples (
    ts TIMESTAMPTZ PRIMARY KEY,
    requests BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS zone_query_samples (
    ts TIMESTAMPTZ NOT NULL,
    tenant_id UUID,
    domain TEXT NOT NULL,
    queries BIGINT NOT NULL,
    failed BIGINT NOT NULL,
    PRIMARY KEY (domain, ts)
);
CREATE INDEX IF NOT EXISTS idx_zqs_tenant_ts ON zone_query_samples(tenant_id, ts);
CREATE INDEX IF NOT EXISTS idx_zqs_ts ON zone_query_samples(ts);
CREATE TABLE IF NOT EXISTS tenant_usage_samples (
    ts TIMESTAMPTZ NOT NULL,
    tenant_id UUID NOT NULL,
    zones INTEGER NOT NULL,
    records INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, ts)
);
-- Non-destructive backfill: every non-admin user gets a personal tenant (unlimited) that owns the
-- zones the user owned. Nothing is removed or changed in users/zones except zones.tenant_id.
INSERT INTO tenants (id, name)
SELECT CAST(md5('personal:' || CAST(u.id AS text)) AS uuid), 'personal-' || u.username
FROM users u
WHERE u.role <> 'admin' AND NOT EXISTS (SELECT 1 FROM tenant_members tm WHERE tm.user_id = u.id)
ON CONFLICT DO NOTHING;
INSERT INTO tenant_members (tenant_id, user_id, role)
SELECT CAST(md5('personal:' || CAST(u.id AS text)) AS uuid), u.id, 'owner'
FROM users u
WHERE u.role <> 'admin' AND EXISTS (SELECT 1 FROM tenants t WHERE t.id = CAST(md5('personal:' || CAST(u.id AS text)) AS uuid))
  AND NOT EXISTS (SELECT 1 FROM tenant_members tm WHERE tm.user_id = u.id)
ON CONFLICT DO NOTHING;
UPDATE zones z SET tenant_id = CAST(md5('personal:' || CAST(z.owner AS text)) AS uuid)
WHERE z.tenant_id IS NULL AND z.owner IS NOT NULL
  AND EXISTS (SELECT 1 FROM tenant_members tm WHERE tm.tenant_id = CAST(md5('personal:' || CAST(z.owner AS text)) AS uuid));
";

/// SQL fragment (needs `$1` = is_admin, `$2` = user id as text and the alias `z` for zones):
/// the zone is visible to the caller through ownership, sharing or tenant membership.
pub const ZONE_VISIBLE: &str = "($1 OR z.id IN (\
    SELECT id FROM zones WHERE owner = CAST($2 AS text)::uuid \
    UNION SELECT zone_id FROM zone_members WHERE user_id = CAST($2 AS text)::uuid \
    UNION SELECT id FROM zones WHERE tenant_id IN (SELECT tenant_id FROM tenant_members WHERE user_id = CAST($2 AS text)::uuid)))";

fn forbidden(msg: &str) -> HttpResponse {
    HttpResponse::Forbidden().json(serde_json::json!({"error": msg}))
}
fn db_error(ctx: &str, e: &dyn std::error::Error) -> HttpResponse {
    warn!("{}: {}", ctx, full_error_string(e));
    HttpResponse::InternalServerError().json(serde_json::json!({"error": "database error"}))
}

fn env_quota(name: &str) -> Option<i32> {
    std::env::var(name).ok().and_then(|v| v.trim().parse::<i32>().ok()).filter(|v| *v >= 0)
}

/// The tenant a (non-admin) user acts in; a personal tenant is created on first use.
/// `requested` selects one of several memberships.
pub async fn tenant_for_user(db: &tokio_postgres::Client, user_id: &str, requested: Option<&str>, need_write: bool) -> Result<String, HttpResponse> {
    if let Some(t) = requested {
        let row = db.query_opt(
            "SELECT role FROM tenant_members WHERE CAST(tenant_id AS varchar) = $1 AND CAST(user_id AS varchar) = $2", &[&t, &user_id]
        ).await.map_err(|e| db_error("tenant_for_user", &e))?;
        return match row.map(|r| r.get::<_, String>(0)) {
            Some(r) if r != "viewer" || !need_write => Ok(t.to_string()),
            _ => Err(forbidden("not allowed to create zones in this tenant")),
        };
    }
    let rows = db.query(
        "SELECT CAST(tenant_id AS varchar), role FROM tenant_members WHERE CAST(user_id AS varchar) = $1 ORDER BY (role = 'owner') DESC, created_at", &[&user_id]
    ).await.map_err(|e| db_error("tenant_for_user", &e))?;
    if let Some(r) = rows.iter().find(|r| r.get::<_, String>(1) != "viewer") {
        return Ok(r.get(0));
    }
    if !rows.is_empty() && need_write { return Err(forbidden("viewers cannot create zones")); }
    // no membership yet: personal tenant with the configured default quotas
    let name_row = db.query_opt("SELECT username FROM users WHERE CAST(id AS varchar) = $1", &[&user_id])
        .await.map_err(|e| db_error("tenant_for_user", &e))?;
    let Some(name_row) = name_row else { return Err(unauthorized()) };
    let username: String = name_row.get(0);
    let tid = Uuid::new_v4().to_string();
    let (mz, mr) = (env_quota("DEFAULT_TENANT_MAX_ZONES"), env_quota("DEFAULT_TENANT_MAX_RECORDS"));
    let tname = format!("personal-{}", username);
    db.execute("INSERT INTO tenants (id, name, max_zones, max_records) VALUES ($1::text::uuid, $2, $3, $4) ON CONFLICT (name) DO NOTHING", &[&tid, &tname, &mz, &mr])
        .await.map_err(|e| db_error("tenant_for_user", &e))?;
    let id_row = db.query_one("SELECT CAST(id AS varchar) FROM tenants WHERE name = $1", &[&tname]).await.map_err(|e| db_error("tenant_for_user", &e))?;
    let id: String = id_row.get(0);
    db.execute("INSERT INTO tenant_members (tenant_id, user_id, role) VALUES ($1::text::uuid, $2::text::uuid, 'owner') ON CONFLICT DO NOTHING", &[&id, &user_id])
        .await.map_err(|e| db_error("tenant_for_user", &e))?;
    Ok(id)
}

#[derive(Serialize, Clone)]
pub struct Usage { pub zones: i64, pub records: i64, pub max_zones: Option<i32>, pub max_records: Option<i32> }

pub async fn usage(db: &tokio_postgres::Client, tenant_id: &str) -> Result<Option<Usage>, tokio_postgres::Error> {
    let row = db.query_opt(
        "SELECT t.max_zones, t.max_records, \
                (SELECT count(*) FROM zones z WHERE z.tenant_id = t.id), \
                (SELECT count(*) FROM records r JOIN zones z ON z.id = r.zone_id WHERE z.tenant_id = t.id) \
         FROM tenants t WHERE CAST(t.id AS varchar) = $1", &[&tenant_id]).await?;
    Ok(row.map(|r| Usage { max_zones: r.get(0), max_records: r.get(1), zones: r.get(2), records: r.get(3) }))
}

fn quota_exceeded(what: &str, limit: i32, used: i64, adding: i64) -> HttpResponse {
    HttpResponse::Forbidden().json(serde_json::json!({
        "error": "quota_exceeded", "quota": what, "limit": limit, "used": used, "requested": adding,
        "details": format!("the tenant's {} quota ({}) would be exceeded", what, limit)
    }))
}

/// Refuse when adding `adding_zones` / `adding_records` would exceed the tenant's quota.
pub async fn check_quota(db: &tokio_postgres::Client, tenant_id: &str, adding_zones: i64, adding_records: i64) -> Result<(), HttpResponse> {
    let u = usage(db, tenant_id).await.map_err(|e| db_error("check_quota", &e))?;
    let Some(u) = u else { return Ok(()) };
    if let Some(l) = u.max_zones { if adding_zones > 0 && u.zones + adding_zones > l as i64 { return Err(quota_exceeded("zones", l, u.zones, adding_zones)); } }
    if let Some(l) = u.max_records { if adding_records > 0 && u.records + adding_records > l as i64 { return Err(quota_exceeded("records", l, u.records, adding_records)); } }
    Ok(())
}

/// Quota check for a change inside a zone (no-op for platform-owned zones without tenant).
pub async fn check_zone_records_quota(db: &tokio_postgres::Client, zone_id: &str, adding: i64, tok: &TokenData<Claims>) -> Result<(), HttpResponse> {
    if tok.claims.role == "admin" || adding <= 0 { return Ok(()); }
    let row = db.query_opt("SELECT CAST(tenant_id AS varchar) FROM zones WHERE CAST(id AS varchar) = $1", &[&zone_id]).await.map_err(|e| db_error("quota", &e))?;
    match row.and_then(|r| r.get::<_, Option<String>>(0)) {
        Some(t) => check_quota(db, &t, 0, adding).await,
        None => Ok(()),
    }
}

/// Role of `user_id` in the tenant of `zone` (None = no tenant access).
pub fn tenant_role_to_zone_role(r: Option<&str>) -> &'static str {
    match r { Some("owner") => "owner", Some("editor") => "editor", Some("viewer") => "viewer", _ => "" }
}

// ---------------------------------------------------------------------------
// Tenant API
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct TenantReq { name: String, max_zones: Option<i32>, max_records: Option<i32> }

fn valid_quota(q: Option<i32>) -> bool { q.map(|v| v >= 0).unwrap_or(true) }
fn valid_tenant_name(n: &str) -> bool {
    let n = n.trim();
    !n.is_empty() && n.len() <= 64 && n.chars().all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | ' '))
}

async fn tenant_role(db: &tokio_postgres::Client, tenant_id: &str, tok: &TokenData<Claims>) -> Result<Option<String>, HttpResponse> {
    if tok.claims.role == "admin" { return Ok(Some("owner".into())); }
    let row = db.query_opt("SELECT role FROM tenant_members WHERE CAST(tenant_id AS varchar) = $1 AND CAST(user_id AS varchar) = $2", &[&tenant_id, &tok.claims.sub])
        .await.map_err(|e| db_error("tenant_role", &e))?;
    Ok(row.map(|r| r.get(0)))
}

pub async fn list_tenants(data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) { Some(t) => t, None => return unauthorized() };
    let is_admin = tok.claims.role == "admin";
    if !is_admin {
        // make sure a customer who never created a zone still sees (and has) their tenant
        let _ = tenant_for_user(&data.db, &tok.claims.sub, None, false).await;
    }
    let rows = (&*data.db).query(
        "SELECT CAST(t.id AS varchar), t.name, t.max_zones, t.max_records, t.created_at::text, \
                (SELECT count(*) FROM zones z WHERE z.tenant_id = t.id), \
                (SELECT count(*) FROM records r JOIN zones z ON z.id = r.zone_id WHERE z.tenant_id = t.id), \
                (SELECT count(*) FROM tenant_members x WHERE x.tenant_id = t.id), \
                COALESCE(m.role, CASE WHEN $1 THEN 'admin' ELSE '' END) \
         FROM tenants t LEFT JOIN tenant_members m ON m.tenant_id = t.id AND CAST(m.user_id AS varchar) = $2 \
         WHERE $1 OR m.user_id IS NOT NULL ORDER BY t.name", &[&is_admin, &tok.claims.sub]).await;
    match rows {
        Ok(rows) => HttpResponse::Ok().json(rows.iter().map(|r| serde_json::json!({
            "id": r.get::<_, String>(0), "name": r.get::<_, String>(1), "max_zones": r.get::<_, Option<i32>>(2), "max_records": r.get::<_, Option<i32>>(3),
            "created_at": r.get::<_, String>(4), "zones": r.get::<_, i64>(5), "records": r.get::<_, i64>(6), "members": r.get::<_, i64>(7), "role": r.get::<_, String>(8),
        })).collect::<Vec<_>>()),
        Err(e) => db_error("list_tenants", &e),
    }
}

pub async fn create_tenant(body: web::Json<TenantReq>, data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) { Some(t) => t, None => return unauthorized() };
    if tok.claims.role != "admin" { return forbidden("admin role required"); }
    if !valid_tenant_name(&body.name) || !valid_quota(body.max_zones) || !valid_quota(body.max_records) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid name or quota"}));
    }
    let id = Uuid::new_v4().to_string();
    match (&*data.db).execute("INSERT INTO tenants (id, name, max_zones, max_records) VALUES ($1::text::uuid, $2, $3, $4)", &[&id, &body.name.trim(), &body.max_zones, &body.max_records]).await {
        Ok(_) => {
            audit(&data.db, Some(&tok.claims.sub), "tenant.create", "tenant", Some(id.clone()), &req, serde_json::json!({"name": body.name})).await;
            HttpResponse::Created().json(serde_json::json!({"id": id, "name": body.name.trim(), "max_zones": body.max_zones, "max_records": body.max_records}))
        }
        Err(e) if e.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) =>
            HttpResponse::Conflict().json(serde_json::json!({"error": "a tenant with this name exists"})),
        Err(e) => db_error("create_tenant", &e),
    }
}

/// Replaces name and quotas (`null` quota = unlimited).
pub async fn update_tenant(path: web::Path<String>, body: web::Json<TenantReq>, data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) { Some(t) => t, None => return unauthorized() };
    if tok.claims.role != "admin" { return forbidden("admin role required"); }
    if !valid_tenant_name(&body.name) || !valid_quota(body.max_zones) || !valid_quota(body.max_records) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid name or quota"}));
    }
    let id = path.into_inner();
    match (&*data.db).execute("UPDATE tenants SET name = $2, max_zones = $3, max_records = $4 WHERE CAST(id AS varchar) = $1", &[&id, &body.name.trim(), &body.max_zones, &body.max_records]).await {
        Ok(0) => HttpResponse::NotFound().json(serde_json::json!({"error": "tenant not found"})),
        Ok(_) => {
            audit(&data.db, Some(&tok.claims.sub), "tenant.update", "tenant", Some(id), &req, serde_json::json!({"name": body.name, "max_zones": body.max_zones, "max_records": body.max_records})).await;
            HttpResponse::Ok().json(serde_json::json!({"success": true}))
        }
        Err(e) if e.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) =>
            HttpResponse::Conflict().json(serde_json::json!({"error": "a tenant with this name exists"})),
        Err(e) => db_error("update_tenant", &e),
    }
}

pub async fn delete_tenant(path: web::Path<String>, data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) { Some(t) => t, None => return unauthorized() };
    if tok.claims.role != "admin" { return forbidden("admin role required"); }
    let id = path.into_inner();
    let n: i64 = match (&*data.db).query_one("SELECT count(*) FROM zones WHERE CAST(tenant_id AS varchar) = $1", &[&id]).await { Ok(r) => r.get(0), Err(e) => return db_error("delete_tenant", &e) };
    if n > 0 { return HttpResponse::Conflict().json(serde_json::json!({"error": "tenant still owns zones", "zones": n})); }
    let _ = (&*data.db).execute("DELETE FROM zone_query_samples WHERE CAST(tenant_id AS varchar) = $1", &[&id]).await;
    let _ = (&*data.db).execute("DELETE FROM tenant_usage_samples WHERE CAST(tenant_id AS varchar) = $1", &[&id]).await;
    match (&*data.db).execute("DELETE FROM tenants WHERE CAST(id AS varchar) = $1", &[&id]).await {
        Ok(0) => HttpResponse::NotFound().json(serde_json::json!({"error": "tenant not found"})),
        Ok(_) => { audit(&data.db, Some(&tok.claims.sub), "tenant.delete", "tenant", Some(id), &req, serde_json::json!({})).await; HttpResponse::Ok().json(serde_json::json!({"success": true})) }
        Err(e) => db_error("delete_tenant", &e),
    }
}

pub async fn list_tenant_members(path: web::Path<String>, data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) { Some(t) => t, None => return unauthorized() };
    let id = path.into_inner();
    match tenant_role(&data.db, &id, &tok).await { Ok(Some(_)) => {}, Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "tenant not found"})), Err(r) => return r }
    match (&*data.db).query("SELECT CAST(u.id AS varchar), u.username, m.role FROM tenant_members m JOIN users u ON u.id = m.user_id WHERE CAST(m.tenant_id AS varchar) = $1 ORDER BY u.username", &[&id]).await {
        Ok(rows) => HttpResponse::Ok().json(rows.iter().map(|r| serde_json::json!({"user_id": r.get::<_, String>(0), "username": r.get::<_, String>(1), "role": r.get::<_, String>(2)})).collect::<Vec<_>>()),
        Err(e) => db_error("list_tenant_members", &e),
    }
}

#[derive(Deserialize)]
pub struct MemberReq { username: Option<String>, user_id: Option<String>, role: String }

pub async fn put_tenant_member(path: web::Path<String>, body: web::Json<MemberReq>, data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) { Some(t) => t, None => return unauthorized() };
    let id = path.into_inner();
    match tenant_role(&data.db, &id, &tok).await {
        Ok(Some(r)) if r == "owner" => {}
        Ok(Some(_)) => return forbidden("tenant owner role required"),
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "tenant not found"})),
        Err(r) => return r,
    }
    if !["owner", "editor", "viewer"].contains(&body.role.as_str()) { return HttpResponse::BadRequest().json(serde_json::json!({"error": "role must be owner, editor or viewer"})); }
    let uid: Option<String> = if let Some(u) = &body.user_id { Some(u.clone()) } else if let Some(n) = &body.username {
        match (&*data.db).query_opt("SELECT CAST(id AS varchar) FROM users WHERE username = $1", &[&n.trim()]).await { Ok(r) => r.map(|r| r.get(0)), Err(e) => return db_error("put_tenant_member", &e) }
    } else { None };
    let Some(uid) = uid else { return HttpResponse::NotFound().json(serde_json::json!({"error": "user not found"})) };
    if Uuid::parse_str(&uid).is_err() { return HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid user id"})); }
    // admins are platform operators, not tenant members; a downgrade must keep one owner
    if body.role != "owner" {
        let owners: i64 = match (&*data.db).query_one("SELECT count(*) FROM tenant_members WHERE CAST(tenant_id AS varchar) = $1 AND role = 'owner' AND CAST(user_id AS varchar) <> $2", &[&id, &uid]).await { Ok(r) => r.get(0), Err(e) => return db_error("put_tenant_member", &e) };
        let was_owner = (&*data.db).query_opt("SELECT 1 FROM tenant_members WHERE CAST(tenant_id AS varchar) = $1 AND role = 'owner' AND CAST(user_id AS varchar) = $2", &[&id, &uid]).await.ok().flatten().is_some();
        if was_owner && owners == 0 { return HttpResponse::Conflict().json(serde_json::json!({"error": "a tenant needs at least one owner"})); }
    }
    match (&*data.db).execute("INSERT INTO tenant_members (tenant_id, user_id, role) VALUES ($1::text::uuid, $2::text::uuid, $3) ON CONFLICT (tenant_id, user_id) DO UPDATE SET role = EXCLUDED.role", &[&id, &uid, &body.role]).await {
        Ok(_) => { audit(&data.db, Some(&tok.claims.sub), "tenant.member.set", "tenant", Some(id), &req, serde_json::json!({"user": uid, "role": body.role})).await; HttpResponse::Ok().json(serde_json::json!({"success": true})) }
        Err(e) if e.code() == Some(&tokio_postgres::error::SqlState::FOREIGN_KEY_VIOLATION) => HttpResponse::NotFound().json(serde_json::json!({"error": "user not found"})),
        Err(e) => db_error("put_tenant_member", &e),
    }
}

pub async fn delete_tenant_member(path: web::Path<(String, String)>, data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) { Some(t) => t, None => return unauthorized() };
    let (id, uid) = path.into_inner();
    match tenant_role(&data.db, &id, &tok).await {
        Ok(Some(r)) if r == "owner" => {}
        Ok(Some(_)) => return forbidden("tenant owner role required"),
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "tenant not found"})),
        Err(r) => return r,
    }
    let others: i64 = match (&*data.db).query_one("SELECT count(*) FROM tenant_members WHERE CAST(tenant_id AS varchar) = $1 AND role = 'owner' AND CAST(user_id AS varchar) <> $2", &[&id, &uid]).await { Ok(r) => r.get(0), Err(e) => return db_error("delete_tenant_member", &e) };
    let is_owner = (&*data.db).query_opt("SELECT 1 FROM tenant_members WHERE CAST(tenant_id AS varchar) = $1 AND role = 'owner' AND CAST(user_id AS varchar) = $2", &[&id, &uid]).await.ok().flatten().is_some();
    if is_owner && others == 0 { return HttpResponse::Conflict().json(serde_json::json!({"error": "a tenant needs at least one owner"})); }
    match (&*data.db).execute("DELETE FROM tenant_members WHERE CAST(tenant_id AS varchar) = $1 AND CAST(user_id AS varchar) = $2", &[&id, &uid]).await {
        Ok(0) => HttpResponse::NotFound().json(serde_json::json!({"error": "member not found"})),
        Ok(_) => { audit(&data.db, Some(&tok.claims.sub), "tenant.member.remove", "tenant", Some(id), &req, serde_json::json!({"user": uid})).await; HttpResponse::Ok().json(serde_json::json!({"success": true})) }
        Err(e) => db_error("delete_tenant_member", &e),
    }
}

#[derive(Deserialize)]
pub struct MoveZoneReq { tenant_id: Option<String> }

/// Admin: assign a zone to a tenant (or detach it with `null`). The target tenant's zone quota applies.
pub async fn move_zone(path: web::Path<String>, body: web::Json<MoveZoneReq>, data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) { Some(t) => t, None => return unauthorized() };
    if tok.claims.role != "admin" { return forbidden("admin role required"); }
    let zid = path.into_inner();
    let recs: i64 = match (&*data.db).query_opt("SELECT (SELECT count(*) FROM records r WHERE r.zone_id = z.id) FROM zones z WHERE CAST(z.id AS varchar) = $1", &[&zid]).await {
        Ok(Some(r)) => r.get(0), Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "zone not found"})), Err(e) => return db_error("move_zone", &e) };
    if let Some(t) = &body.tenant_id {
        if let Err(r) = check_quota(&data.db, t, 1, recs).await { return r; }
    }
    match (&*data.db).execute("UPDATE zones SET tenant_id = $2::text::uuid WHERE CAST(id AS varchar) = $1", &[&zid, &body.tenant_id]).await {
        Ok(_) => { audit(&data.db, Some(&tok.claims.sub), "zone.move", "zone", Some(zid), &req, serde_json::json!({"tenant_id": body.tenant_id})).await; HttpResponse::Ok().json(serde_json::json!({"success": true})) }
        Err(e) if e.code() == Some(&tokio_postgres::error::SqlState::FOREIGN_KEY_VIOLATION) => HttpResponse::NotFound().json(serde_json::json!({"error": "tenant not found"})),
        Err(e) => db_error("move_zone", &e),
    }
}

// ---------------------------------------------------------------------------
// Aggregated overview (replaces one /records request per zone)
// ---------------------------------------------------------------------------

/// Everything the overview pages need about zones in ONE query: tenant-scoped, with accurate record counts.
#[derive(Deserialize, Default)]
pub struct OverviewQuery { limit: Option<usize> }

pub async fn overview(q: web::Query<OverviewQuery>, data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) { Some(t) => t, None => return unauthorized() };
    let is_admin = tok.claims.role == "admin";
    let sql = format!(
        "SELECT CAST(z.id AS varchar), z.domain, z.status, COALESCE(z.geodns_enabled, true), CAST(z.tenant_id AS varchar), \
                CASE WHEN $1 THEN 'admin' WHEN CAST(z.owner AS varchar) = $2 THEN 'owner' ELSE COALESCE(\
                    (SELECT m.role FROM zone_members m WHERE m.zone_id = z.id AND CAST(m.user_id AS varchar) = $2), \
                    (SELECT CASE tm.role WHEN 'owner' THEN 'owner' ELSE tm.role END FROM tenant_members tm WHERE tm.tenant_id = z.tenant_id AND CAST(tm.user_id AS varchar) = $2), '') END, \
                COALESCE(c.n, 0), COALESCE(c.by_type, '{{}}'::jsonb)::text \
         FROM zones z \
         LEFT JOIN LATERAL (SELECT sum(cnt)::bigint AS n, jsonb_object_agg(record_type, cnt) AS by_type FROM \
                      (SELECT record_type, count(*) AS cnt FROM records r WHERE r.zone_id = z.id GROUP BY record_type) t) c ON true \
         WHERE {} ORDER BY z.domain", ZONE_VISIBLE);
    let rows = match (&*data.db).query(&sql, &[&is_admin, &tok.claims.sub]).await { Ok(r) => r, Err(e) => return db_error("overview", &e) };
    let mut total_records = 0i64;
    let mut by_type: std::collections::BTreeMap<String, i64> = Default::default();
    let zones: Vec<serde_json::Value> = rows.iter().map(|r| {
        let n: i64 = r.get(6);
        total_records += n;
        let bt: serde_json::Value = serde_json::from_str(&r.get::<_, String>(7)).unwrap_or_default();
        if let Some(o) = bt.as_object() { for (k, v) in o { *by_type.entry(k.clone()).or_insert(0) += v.as_i64().unwrap_or(0); } }
        serde_json::json!({"id": r.get::<_, String>(0), "domain": r.get::<_, String>(1), "status": r.get::<_, String>(2), "geodns_enabled": r.get::<_, bool>(3),
            "tenant_id": r.get::<_, Option<String>>(4), "access": r.get::<_, String>(5), "records": n, "records_by_type": bt})
    }).collect();
    // quota usage of the caller's tenants
    let tenants = if is_admin { vec![] } else {
        match (&*data.db).query(
            "SELECT CAST(t.id AS varchar), t.name, t.max_zones, t.max_records, m.role, \
                    (SELECT count(*) FROM zones z WHERE z.tenant_id = t.id), \
                    (SELECT count(*) FROM records r JOIN zones z ON z.id = r.zone_id WHERE z.tenant_id = t.id) \
             FROM tenants t JOIN tenant_members m ON m.tenant_id = t.id WHERE CAST(m.user_id AS varchar) = $1 ORDER BY t.name", &[&tok.claims.sub]).await {
            Ok(rs) => rs.iter().map(|r| serde_json::json!({"id": r.get::<_, String>(0), "name": r.get::<_, String>(1), "max_zones": r.get::<_, Option<i32>>(2), "max_records": r.get::<_, Option<i32>>(3),
                "role": r.get::<_, String>(4), "zones": r.get::<_, i64>(5), "records": r.get::<_, i64>(6)})).collect(),
            Err(e) => return db_error("overview", &e),
        }
    };
    let pending = zones.iter().filter(|z| z["status"] == "pending").count();
    let zones_total = zones.len();
    // `limit` only shortens the returned list; all totals always cover every visible zone
    let zones: Vec<_> = match q.limit { Some(l) => zones.into_iter().take(l).collect(), None => zones };
    HttpResponse::Ok().json(serde_json::json!({
        "zones_total": zones_total, "zones_pending": pending, "records_total": total_records, "records_by_type": by_type, "zones": zones, "tenants": tenants,
    }))
}

// ---------------------------------------------------------------------------
// Analytics: collection, retention and queries
// ---------------------------------------------------------------------------

pub fn retention_days() -> i64 {
    std::env::var("ANALYTICS_RETENTION_DAYS").ok().and_then(|v| v.parse().ok()).filter(|v: &i64| *v > 0).unwrap_or(90)
}

/// Previous counter values, to turn cumulative Prometheus counters into per-interval deltas.
#[derive(Default)]
pub struct Prev { initialized: bool, total: Option<f64>, zones: std::collections::HashMap<String, (f64, f64)> }

fn label_value(labels: &str, key: &str) -> Option<String> {
    let pat = format!("{}=\"", key);
    let i = labels.find(&pat)? + pat.len();
    let j = labels[i..].find('"')?;
    Some(labels[i..i + j].to_string())
}

fn delta(cur: f64, prev: Option<f64>) -> i64 {
    match prev { Some(p) if cur >= p => (cur - p) as i64, Some(_) => cur as i64 /* counter reset */, None => 0 }
}

/// Store one sampling interval computed from a Prometheus text exposition. Returns (global delta, zones written).
pub async fn ingest(db: &tokio_postgres::Client, text: &str, prev: &mut Prev, now: i64) -> Result<(i64, usize), tokio_postgres::Error> {
    let samples = ext::parse_prometheus(text);
    let total: f64 = samples.iter().filter(|(n, _, _)| n.starts_with("hickory_") && n.contains("request") && n.ends_with("_total")).map(|(_, _, v)| *v).sum();
    let g = delta(total, prev.total);
    prev.total = Some(total);
    if prev.total.is_some() && g >= 0 {
        db.execute("INSERT INTO analytics_samples (ts, requests) VALUES (to_timestamp($1::bigint), $2) ON CONFLICT (ts) DO UPDATE SET requests = analytics_samples.requests + EXCLUDED.requests", &[&now, &g]).await?;
    }
    // per-zone counters exist only when the DNS server runs with DNS_ZONE_QUERY_METRICS=true
    let mut cur: std::collections::HashMap<String, (f64, f64)> = Default::default();
    for (n, l, v) in samples.iter().filter(|(n, _, _)| n == "hickory_zone_queries_total") {
        let Some(zone) = label_value(l, "zone") else { continue };
        let e = cur.entry(zone.trim_end_matches('.').to_ascii_lowercase()).or_insert((0.0, 0.0));
        e.0 += v;
        if label_value(l, "result").as_deref() == Some("error") { e.1 += v; }
        let _ = n;
    }
    let mut written = 0;
    for (domain, (q, f)) in &cur {
        // a zone seen for the first time AFTER the baseline scrape started counting since the last scrape
        let (dq, df) = match prev.zones.get(domain) {
            Some((pq, pf)) => (delta(*q, Some(*pq)), delta(*f, Some(*pf))),
            None if prev.initialized => (*q as i64, *f as i64),
            None => (0, 0),
        };
        if dq == 0 && df == 0 { continue; }
        db.execute(
            "INSERT INTO zone_query_samples (ts, tenant_id, domain, queries, failed) \
             VALUES (to_timestamp($1::bigint), (SELECT tenant_id FROM zones WHERE domain = $2 LIMIT 1), $2, $3, $4) \
             ON CONFLICT (domain, ts) DO UPDATE SET queries = zone_query_samples.queries + EXCLUDED.queries, failed = zone_query_samples.failed + EXCLUDED.failed",
            &[&now, domain, &dq, &df]).await?;
        written += 1;
    }
    prev.zones = cur;
    prev.initialized = true;
    Ok((g, written))
}

/// Hourly snapshot of zones/records per tenant (the "usage" series).
pub async fn snapshot_usage(db: &tokio_postgres::Client, now: i64) -> Result<u64, tokio_postgres::Error> {
    let hour = now - now.rem_euclid(3600);
    db.execute(
        "INSERT INTO tenant_usage_samples (ts, tenant_id, zones, records) \
         SELECT to_timestamp($1::bigint), t.id, (SELECT count(*) FROM zones z WHERE z.tenant_id = t.id)::int, \
                (SELECT count(*) FROM records r JOIN zones z ON z.id = r.zone_id WHERE z.tenant_id = t.id)::int FROM tenants t \
         ON CONFLICT (tenant_id, ts) DO UPDATE SET zones = EXCLUDED.zones, records = EXCLUDED.records", &[&hour]).await
}

pub async fn purge_analytics(db: &tokio_postgres::Client, days: i64) -> Result<u64, tokio_postgres::Error> {
    let mut n = 0;
    for t in ["analytics_samples", "zone_query_samples", "tenant_usage_samples"] {
        n += db.execute(&format!("DELETE FROM {} WHERE ts < now() - make_interval(days => $1::int)", t), &[&(days as i32)]).await?;
    }
    Ok(n)
}

/// Background collector. `ANALYTICS_SAMPLE_SECS` (default 60, 0 = off).
pub fn spawn_collector(db: Arc<Pool>, metrics_url: Option<String>) {
    let secs: u64 = std::env::var("ANALYTICS_SAMPLE_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(60);
    if secs == 0 { info!("analytics collector disabled (ANALYTICS_SAMPLE_SECS=0)"); return; }
    tokio::spawn(async move {
        let mut prev = Prev::default();
        let mut tick = 0u64;
        loop {
            tokio::time::sleep(Duration::from_secs(secs)).await;
            tick += 1;
            let now = chrono::Utc::now().timestamp();
            if let Some(url) = &metrics_url {
                match ext::http_get(url).await {
                    Ok(text) => if let Err(e) = ingest(&db, &text, &mut prev, now).await { warn!("analytics ingest: {}", full_error_string(&e)); },
                    Err(e) => warn!("analytics: DNS metrics endpoint unreachable: {}", e),
                }
            }
            if (tick * secs) % 3600 < secs || tick == 1 {
                if let Err(e) = snapshot_usage(&db, now).await { warn!("usage snapshot: {}", full_error_string(&e)); }
            }
            if (tick * secs) % 86400 < secs {
                match purge_analytics(&db, retention_days()).await { Ok(n) if n > 0 => info!("analytics retention removed {} rows", n), Ok(_) => {}, Err(e) => warn!("analytics purge: {}", full_error_string(&e)) }
            }
        }
    });
}

/// range -> (window, bucket seconds)
fn range_params(r: Option<&str>) -> (i64, i64) {
    match r.unwrap_or("24h") { "1h" => (3600, 60), "6h" => (6 * 3600, 300), "7d" => (7 * 86400, 3600), "30d" => (30 * 86400, 6 * 3600), "90d" => (90 * 86400, 86400), _ => (86400, 900) }
}

#[derive(Deserialize)]
pub struct AnalyticsQuery { range: Option<String>, tenant_id: Option<String>, zone: Option<String> }

pub async fn global_analytics(q: web::Query<AnalyticsQuery>, data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) { Some(t) => t, None => return unauthorized() };
    if tok.claims.role != "admin" { return forbidden("admin role required"); }
    let (win, bucket) = range_params(q.range.as_deref());
    let series = (&*data.db).query(
        "SELECT to_char(to_timestamp(floor(extract(epoch from ts) / $2::double precision) * $2::double precision) AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), sum(requests)::bigint \
         FROM analytics_samples WHERE ts >= now() - make_interval(secs => $1::double precision) GROUP BY 1 ORDER BY 1", &[&(win as f64), &(bucket as f64)]).await;
    let top = (&*data.db).query(
        "SELECT domain, sum(queries)::bigint, sum(failed)::bigint FROM zone_query_samples WHERE ts >= now() - make_interval(secs => $1::double precision) GROUP BY domain ORDER BY 2 DESC LIMIT 10", &[&(win as f64)]).await;
    match (series, top) {
        (Ok(s), Ok(t)) => HttpResponse::Ok().json(serde_json::json!({
            "range": q.range.clone().unwrap_or("24h".into()), "bucket_seconds": bucket, "retention_days": retention_days(),
            "series": s.iter().map(|r| serde_json::json!({"ts": r.get::<_, String>(0), "requests": r.get::<_, i64>(1)})).collect::<Vec<_>>(),
            "total": s.iter().map(|r| r.get::<_, i64>(1)).sum::<i64>(),
            "top_zones": t.iter().map(|r| serde_json::json!({"domain": r.get::<_, String>(0), "queries": r.get::<_, i64>(1), "failed": r.get::<_, i64>(2)})).collect::<Vec<_>>(),
            "per_zone_available": !t.is_empty(),
        })),
        (Err(e), _) | (_, Err(e)) => db_error("global_analytics", &e),
    }
}

/// Tenant analytics. Customers can only read tenants they belong to; admins any tenant (or all, without `tenant_id`).
pub async fn tenant_analytics(q: web::Query<AnalyticsQuery>, data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) { Some(t) => t, None => return unauthorized() };
    let is_admin = tok.claims.role == "admin";
    let tenant = match (&q.tenant_id, is_admin) {
        (Some(t), _) => {
            if Uuid::parse_str(t).is_err() { return HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid tenant id"})); }
            match tenant_role(&data.db, t, &tok).await { Ok(Some(_)) => Some(t.clone()), Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "tenant not found"})), Err(r) => return r }
        }
        (None, true) => None,
        (None, false) => match tenant_for_user(&data.db, &tok.claims.sub, None, false).await { Ok(t) => Some(t), Err(r) => return r },
    };
    let (win, bucket) = range_params(q.range.as_deref());
    let zone = q.zone.as_ref().map(|z| z.trim().trim_end_matches('.').to_ascii_lowercase());
    let series = (&*data.db).query(
        "SELECT to_char(to_timestamp(floor(extract(epoch from ts) / $2::double precision) * $2::double precision) AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), sum(queries)::bigint, sum(failed)::bigint \
         FROM zone_query_samples WHERE ts >= now() - make_interval(secs => $1::double precision) \
           AND ($3::text IS NULL OR CAST(tenant_id AS varchar) = $3) AND ($4::text IS NULL OR domain = $4) GROUP BY 1 ORDER BY 1",
        &[&(win as f64), &(bucket as f64), &tenant, &zone]).await;
    let zones = (&*data.db).query(
        "SELECT domain, sum(queries)::bigint, sum(failed)::bigint FROM zone_query_samples WHERE ts >= now() - make_interval(secs => $1::double precision) \
           AND ($2::text IS NULL OR CAST(tenant_id AS varchar) = $2) GROUP BY domain ORDER BY 2 DESC LIMIT 50", &[&(win as f64), &tenant]).await;
    let usage_series = (&*data.db).query(
        "SELECT to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), sum(zones)::bigint, sum(records)::bigint FROM tenant_usage_samples \
         WHERE ts >= now() - make_interval(secs => $1::double precision) AND ($2::text IS NULL OR CAST(tenant_id AS varchar) = $2) GROUP BY ts ORDER BY ts", &[&(win as f64), &tenant]).await;
    match (series, zones, usage_series) {
        (Ok(s), Ok(z), Ok(u)) => HttpResponse::Ok().json(serde_json::json!({
            "tenant_id": tenant, "range": q.range.clone().unwrap_or("24h".into()), "bucket_seconds": bucket, "retention_days": retention_days(),
            "series": s.iter().map(|r| serde_json::json!({"ts": r.get::<_, String>(0), "queries": r.get::<_, i64>(1), "failed": r.get::<_, i64>(2)})).collect::<Vec<_>>(),
            "total_queries": s.iter().map(|r| r.get::<_, i64>(1)).sum::<i64>(),
            "zones": z.iter().map(|r| serde_json::json!({"domain": r.get::<_, String>(0), "queries": r.get::<_, i64>(1), "failed": r.get::<_, i64>(2)})).collect::<Vec<_>>(),
            "usage": u.iter().map(|r| serde_json::json!({"ts": r.get::<_, String>(0), "zones": r.get::<_, i64>(1), "records": r.get::<_, i64>(2)})).collect::<Vec<_>>(),
        })),
        (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => db_error("tenant_analytics", &e),
    }
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/v1/tenants", web::get().to(list_tenants))
        .route("/api/v1/tenants", web::post().to(create_tenant))
        .route("/api/v1/tenants/{id}", web::put().to(update_tenant))
        .route("/api/v1/tenants/{id}", web::delete().to(delete_tenant))
        .route("/api/v1/tenants/{id}/members", web::get().to(list_tenant_members))
        .route("/api/v1/tenants/{id}/members", web::put().to(put_tenant_member))
        .route("/api/v1/tenants/{id}/members/{user_id}", web::delete().to(delete_tenant_member))
        .route("/api/v1/zones/{id}/tenant", web::put().to(move_zone))
        .route("/api/v1/overview", web::get().to(overview))
        .route("/api/v1/analytics/global", web::get().to(global_analytics))
        .route("/api/v1/analytics/tenant", web::get().to(tenant_analytics));
}
