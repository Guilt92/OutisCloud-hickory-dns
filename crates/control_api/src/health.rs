//! Active DNS health monitors (HLTH-001/HLTH-002): SSRF-safe targets,
//! interval/timeout/threshold state machine, persisted result history and
//! operator APIs.

use super::*;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::{Duration, Instant};

const MAX_CHECKS_PER_REQUEST: i64 = 100;
const RESULT_RETENTION_DAYS: i64 = 7;

#[derive(Deserialize)]
pub struct HealthCheckReq {
    #[serde(default)]
    pub zone_id: Option<String>,
    pub name: String,
    pub record_name: String,
    pub record_type: String,
    pub target: String,
    #[serde(default)]
    pub port: Option<i32>,
    #[serde(default)]
    pub interval_secs: Option<i32>,
    #[serde(default)]
    pub timeout_ms: Option<i32>,
    #[serde(default)]
    pub failure_threshold: Option<i32>,
    #[serde(default)]
    pub success_threshold: Option<i32>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Deserialize)]
pub struct HealthListQuery {
    #[serde(default)]
    pub zone_id: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

fn valid_rtype(rtype: &str) -> Result<(), String> {
    match rtype.to_ascii_uppercase().as_str() {
        "A" | "AAAA" | "CNAME" | "NS" | "TXT" | "MX" | "SRV" | "SOA" => Ok(()),
        _ => Err("unsupported record_type for a DNS health check".to_string()),
    }
}

fn normalize_target(target: &str) -> Result<String, String> {
    let ip: IpAddr = target
        .trim()
        .parse()
        .map_err(|_| "target must be a public IP address literal".to_string())?;
    if !automation::is_public_ip(ip) {
        return Err("target must be a public IP address".to_string());
    }
    Ok(ip.to_string())
}

fn normalize_check_name(name: &str, zone_domain: Option<&str>) -> Result<String, String> {
    use hickory_proto::rr::domain::Name;
    let n = name.trim();
    if n.is_empty() || n.len() > 253 {
        return Err("record_name must be 1-253 characters".to_string());
    }
    let fqdn = if n == "@" {
        match zone_domain {
            Some(domain) => format!("{}.", domain.trim_end_matches('.')),
            None => return Err("record_name @ requires a zone".to_string()),
        }
    } else if n.ends_with('.') {
        n.to_string()
    } else if let Some(domain) = zone_domain {
        format!("{}.{}.", n, domain.trim_end_matches('.'))
    } else {
        format!("{}.", n)
    };
    let parsed = Name::from_utf8(&fqdn).map_err(|e| e.to_string())?;
    Ok(parsed.to_ascii().trim_end_matches('.').to_ascii_lowercase())
}

async fn zone_domain_for(db: &Pool, zone_id: &str) -> Result<Option<String>, String> {
    db.query_opt(
        "SELECT domain FROM zones WHERE CAST(id AS varchar) = $1",
        &[&zone_id],
    )
    .await
    .map_err(|e| full_error_string(&e))
    .map(|r| r.map(|row| row.get(0)))
}

async fn authorize_zone(
    db: &Pool,
    tok: &TokenData<Claims>,
    zone_id: Option<&str>,
    level: Level,
) -> Result<(), HttpResponse> {
    match zone_id {
        Some(z) => zone_access_at(db, z, tok, level).await.map(|_| ()),
        None => {
            if tok.claims.role == "admin" {
                Ok(())
            } else {
                Err(HttpResponse::Forbidden()
                    .json(serde_json::json!({"error": "admin role required for global checks"})))
            }
        }
    }
}

fn row_json(r: &tokio_postgres::Row) -> serde_json::Value {
    serde_json::json!({
        "id": r.get::<_, String>(0),
        "zone_id": r.get::<_, Option<String>>(1),
        "name": r.get::<_, String>(2),
        "record_name": r.get::<_, String>(3),
        "record_type": r.get::<_, String>(4),
        "target": r.get::<_, String>(5),
        "port": r.get::<_, i32>(6),
        "interval_secs": r.get::<_, i32>(7),
        "timeout_ms": r.get::<_, i32>(8),
        "failure_threshold": r.get::<_, i32>(9),
        "success_threshold": r.get::<_, i32>(10),
        "enabled": r.get::<_, bool>(11),
        "status": r.get::<_, String>(12),
        "consecutive_failures": r.get::<_, i32>(13),
        "consecutive_successes": r.get::<_, i32>(14),
        "last_checked_at": r.get::<_, Option<String>>(15),
        "last_error": r.get::<_, Option<String>>(16),
        "created_at": r.get::<_, Option<String>>(17),
        "updated_at": r.get::<_, Option<String>>(18),
    })
}

const HEALTH_COLUMNS: &str = "CAST(h.id AS varchar), CAST(h.zone_id AS varchar), h.name, h.record_name, \
    h.record_type, h.target, h.port, h.interval_secs, h.timeout_ms, h.failure_threshold, \
    h.success_threshold, h.enabled, h.status, h.consecutive_failures, h.consecutive_successes, \
    to_char(h.last_checked_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), h.last_error, \
    to_char(h.created_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
    to_char(h.updated_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')";

pub async fn create_check(
    body: web::Json<HealthCheckReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let zone_id = body.zone_id.as_deref().filter(|z| !z.is_empty());
    if let Err(resp) = authorize_zone(&data.db, &tok, zone_id, Level::Write).await {
        return resp;
    }
    let name = body.name.trim();
    if name.is_empty() || name.len() > 100 {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "name must be 1-100 characters"}));
    }
    let rtype = body.record_type.trim().to_ascii_uppercase();
    if let Err(e) = valid_rtype(&rtype) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": e}));
    }
    let target = match normalize_target(&body.target) {
        Ok(t) => t,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    };
    let zone_domain = match zone_id {
        Some(z) => match zone_domain_for(&data.db, z).await {
            Ok(Some(d)) => Some(d),
            Ok(None) => {
                return HttpResponse::NotFound()
                    .json(serde_json::json!({"error": "zone not found"}));
            }
            Err(e) => {
                warn!("health check zone lookup: {}", e);
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({"error": "database error"}));
            }
        },
        None => None,
    };
    let record_name = match normalize_check_name(&body.record_name, zone_domain.as_deref()) {
        Ok(n) => n,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    };
    let port = body.port.unwrap_or(53);
    if !(1..=65535).contains(&port) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid port"}));
    }
    let interval = body.interval_secs.unwrap_or(30);
    if !(5..=86_400).contains(&interval) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "interval_secs must be 5-86400"}));
    }
    let timeout = body.timeout_ms.unwrap_or(3000);
    if !(100..=30_000).contains(&timeout) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "timeout_ms must be 100-30000"}));
    }
    let failures = body.failure_threshold.unwrap_or(3);
    let successes = body.success_threshold.unwrap_or(2);
    if !(1..=20).contains(&failures) || !(1..=20).contains(&successes) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "failure_threshold and success_threshold must be 1-20"
        }));
    }
    let id = Uuid::new_v4().to_string();
    let enabled = body.enabled.unwrap_or(true);
    if let Err(e) = data
        .db
        .execute(
            "INSERT INTO health_checks (id, zone_id, name, record_name, record_type, target, port, \
                    interval_secs, timeout_ms, failure_threshold, success_threshold, enabled) \
             VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            &[
                &id,
                &zone_id,
                &name,
                &record_name,
                &rtype,
                &target,
                &port,
                &interval,
                &timeout,
                &failures,
                &successes,
                &enabled,
            ],
        )
        .await
    {
        warn!("create health check: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "database error"}));
    }
    audit(
        &data.db,
        Some(&tok.claims.sub),
        "create_health_check",
        "health_check",
        Some(id.clone()),
        &req,
        serde_json::json!({"name": name, "target": target, "record_name": record_name}),
    )
    .await;
    HttpResponse::Created().json(serde_json::json!({"id": id, "status": "unknown"}))
}

pub async fn list_checks(
    query: web::Query<HealthListQuery>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let zone_filter = query.zone_id.as_deref().filter(|z| !z.is_empty());
    if let Some(z) = zone_filter {
        if let Err(resp) = authorize_zone(&data.db, &tok, Some(z), Level::Read).await {
            return resp;
        }
    }
    let is_admin = tok.claims.role == "admin";
    let limit = query.limit.unwrap_or(100).clamp(1, MAX_CHECKS_PER_REQUEST);
    let offset = query.offset.unwrap_or(0).max(0);
    let sql = format!(
        "SELECT {HEALTH_COLUMNS}, count(*) OVER() FROM health_checks h \
         LEFT JOIN zones z ON z.id = h.zone_id \
         WHERE ($1::text IS NULL OR CAST(h.zone_id AS varchar) = $1) \
           AND ($2 OR (h.zone_id IS NOT NULL AND ( \
                 CAST(z.owner AS varchar) = $3 \
                 OR EXISTS (SELECT 1 FROM zone_members m WHERE m.zone_id = z.id AND CAST(m.user_id AS varchar) = $3) \
                 OR EXISTS (SELECT 1 FROM tenant_members tm WHERE tm.tenant_id = z.tenant_id AND CAST(tm.user_id AS varchar) = $3)))) \
         ORDER BY h.created_at DESC LIMIT $4::bigint OFFSET $5::bigint"
    );
    match data
        .db
        .query(
            &sql,
            &[&zone_filter, &is_admin, &tok.claims.sub, &limit, &offset],
        )
        .await
    {
        Ok(rows) => {
            let total: i64 = rows.first().and_then(|r| r.try_get(19).ok()).unwrap_or(0);
            let out: Vec<serde_json::Value> = rows.iter().map(row_json).collect();
            HttpResponse::Ok()
                .insert_header(("X-Total-Count", total.to_string()))
                .json(serde_json::json!({"checks": out}))
        }
        Err(e) => {
            warn!("list health checks: {}", full_error_string(&e));
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "database error"}))
        }
    }
}

async fn load_check(db: &Pool, id: &str) -> Result<Option<tokio_postgres::Row>, String> {
    db.query_opt(
        &format!("SELECT {HEALTH_COLUMNS} FROM health_checks h WHERE CAST(h.id AS varchar) = $1"),
        &[&id],
    )
    .await
    .map_err(|e| full_error_string(&e))
}

async fn check_zone_id(row: &tokio_postgres::Row) -> Option<String> {
    row.get::<_, Option<String>>(1)
}

pub async fn get_check(
    path: web::Path<String>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let id = path.into_inner();
    let row = match load_check(&data.db, &id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({"error": "health check not found"}));
        }
        Err(e) => {
            warn!("get health check: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    };
    let zone_id = check_zone_id(&row).await;
    if let Err(resp) = authorize_zone(&data.db, &tok, zone_id.as_deref(), Level::Read).await {
        return resp;
    }
    let results = data
        .db
        .query(
            "SELECT to_char(created_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), ok, latency_ms, error \
             FROM health_check_results WHERE CAST(check_id AS varchar) = $1 \
             ORDER BY created_at DESC LIMIT 100",
            &[&id],
        )
        .await
        .unwrap_or_default();
    let history: Vec<serde_json::Value> = results
        .iter()
        .map(|r| {
            serde_json::json!({
                "at": r.get::<_, String>(0),
                "ok": r.get::<_, bool>(1),
                "latency_ms": r.get::<_, Option<i32>>(2),
                "error": r.get::<_, Option<String>>(3),
            })
        })
        .collect();
    let mut body = row_json(&row);
    body["history"] = serde_json::Value::Array(history);
    HttpResponse::Ok().json(body)
}

pub async fn update_check(
    path: web::Path<String>,
    body: web::Json<HealthCheckReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let id = path.into_inner();
    let existing = match load_check(&data.db, &id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({"error": "health check not found"}));
        }
        Err(e) => {
            warn!("update health check: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    };
    let current_zone = check_zone_id(&existing).await;
    if let Err(resp) = authorize_zone(&data.db, &tok, current_zone.as_deref(), Level::Write).await {
        return resp;
    }
    let target_zone = body.zone_id.as_deref().filter(|z| !z.is_empty());
    if target_zone != current_zone.as_deref() {
        if let Err(resp) = authorize_zone(&data.db, &tok, target_zone, Level::Write).await {
            return resp;
        }
    }
    let name = body.name.trim();
    if name.is_empty() || name.len() > 100 {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "name must be 1-100 characters"}));
    }
    let rtype = body.record_type.trim().to_ascii_uppercase();
    if let Err(e) = valid_rtype(&rtype) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": e}));
    }
    let target = match normalize_target(&body.target) {
        Ok(t) => t,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    };
    let zone_domain = match target_zone {
        Some(z) => match zone_domain_for(&data.db, z).await {
            Ok(d) => d,
            Err(e) => {
                warn!("update health check zone lookup: {}", e);
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({"error": "database error"}));
            }
        },
        None => None,
    };
    let record_name = match normalize_check_name(&body.record_name, zone_domain.as_deref()) {
        Ok(n) => n,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    };
    let port = body.port.unwrap_or(53);
    let interval = body.interval_secs.unwrap_or(30);
    let timeout = body.timeout_ms.unwrap_or(3000);
    let failures = body.failure_threshold.unwrap_or(3);
    let successes = body.success_threshold.unwrap_or(2);
    if !(1..=65535).contains(&port)
        || !(5..=86_400).contains(&interval)
        || !(100..=30_000).contains(&timeout)
        || !(1..=20).contains(&failures)
        || !(1..=20).contains(&successes)
    {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "invalid port/interval/timeout/threshold"}));
    }
    let enabled = body.enabled.unwrap_or(true);
    if let Err(e) = data
        .db
        .execute(
            "UPDATE health_checks SET zone_id = $2::text::uuid, name = $3, record_name = $4, \
                    record_type = $5, target = $6, port = $7, interval_secs = $8, timeout_ms = $9, \
                    failure_threshold = $10, success_threshold = $11, enabled = $12, updated_at = now() \
             WHERE CAST(id AS varchar) = $1",
            &[
                &id,
                &target_zone,
                &name,
                &record_name,
                &rtype,
                &target,
                &port,
                &interval,
                &timeout,
                &failures,
                &successes,
                &enabled,
            ],
        )
        .await
    {
        warn!("update health check: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "database error"}));
    }
    audit(
        &data.db,
        Some(&tok.claims.sub),
        "update_health_check",
        "health_check",
        Some(id.clone()),
        &req,
        serde_json::json!({"name": name, "target": target, "enabled": enabled}),
    )
    .await;
    HttpResponse::Ok().json(serde_json::json!({"updated": true}))
}

pub async fn delete_check(
    path: web::Path<String>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let id = path.into_inner();
    let existing = match load_check(&data.db, &id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({"error": "health check not found"}));
        }
        Err(e) => {
            warn!("delete health check: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    };
    let zone_id = check_zone_id(&existing).await;
    if let Err(resp) = authorize_zone(&data.db, &tok, zone_id.as_deref(), Level::Owner).await {
        return resp;
    }
    match data
        .db
        .execute(
            "DELETE FROM health_checks WHERE CAST(id AS varchar) = $1",
            &[&id],
        )
        .await
    {
        Ok(0) => {
            HttpResponse::NotFound().json(serde_json::json!({"error": "health check not found"}))
        }
        Ok(_) => {
            audit(
                &data.db,
                Some(&tok.claims.sub),
                "delete_health_check",
                "health_check",
                Some(id.clone()),
                &req,
                serde_json::json!({}),
            )
            .await;
            HttpResponse::Ok().json(serde_json::json!({"deleted": true}))
        }
        Err(e) => {
            warn!("delete health check: {}", full_error_string(&e));
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "database error"}))
        }
    }
}

pub async fn run_check_now(
    path: web::Path<String>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let id = path.into_inner();
    let existing = match load_check(&data.db, &id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({"error": "health check not found"}));
        }
        Err(e) => {
            warn!("run health check: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    };
    let zone_id = check_zone_id(&existing).await;
    if let Err(resp) = authorize_zone(&data.db, &tok, zone_id.as_deref(), Level::Write).await {
        return resp;
    }
    match execute_check(&data.db, &id).await {
        Ok((ok, latency, error, status)) => HttpResponse::Ok().json(serde_json::json!({
            "ok": ok,
            "latency_ms": latency,
            "error": error,
            "status": status,
        })),
        Err(e) => {
            warn!("run health check {}: {}", id, e);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": e}))
        }
    }
}

/// Run one probe and persist the result/state transition. Returns
/// `(ok, latency_ms, error, status_after)`.
pub async fn execute_check(
    db: &Pool,
    id: &str,
) -> Result<(bool, Option<i64>, Option<String>, String), String> {
    let row = db
        .query_opt(
            "SELECT record_name, record_type, target, port, timeout_ms, failure_threshold, \
                    success_threshold, status, consecutive_failures, consecutive_successes, \
                    CAST(zone_id AS varchar), name \
             FROM health_checks WHERE CAST(id AS varchar) = $1",
            &[&id],
        )
        .await
        .map_err(|e| full_error_string(&e))?;
    let Some(r) = row else {
        return Err("health check not found".into());
    };
    let record_name: String = r.get(0);
    let record_type: String = r.get(1);
    let target: String = r.get(2);
    let port: i32 = r.get(3);
    let timeout_ms: i32 = r.get(4);
    let failure_threshold: i32 = r.get(5);
    let success_threshold: i32 = r.get(6);
    let prior_status: String = r.get(7);
    let prior_failures: i32 = r.get(8);
    let prior_successes: i32 = r.get(9);
    let zone_id: Option<String> = r.get(10);
    let check_name: String = r.get(11);

    let probe = probe_dns(
        &target,
        port as u16,
        &record_name,
        &record_type,
        timeout_ms as u64,
    )
    .await;
    let (ok, latency, error) = match probe {
        Ok(ms) => (true, Some(ms), None),
        Err(e) => (false, None, Some(e)),
    };
    let (failures, successes) = if ok {
        (0, prior_successes + 1)
    } else {
        (prior_failures + 1, 0)
    };
    let status = if ok {
        if prior_status == "up" || successes >= success_threshold {
            "up"
        } else {
            prior_status.as_str()
        }
    } else if prior_status == "down" || failures >= failure_threshold {
        "down"
    } else {
        prior_status.as_str()
    };
    let _ = db
        .execute(
            "INSERT INTO health_check_results (id, check_id, ok, latency_ms, error) \
             VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5)",
            &[
                &Uuid::new_v4().to_string(),
                &id,
                &ok,
                &latency.map(|v| v as i32),
                &error,
            ],
        )
        .await;
    db.execute(
        "UPDATE health_checks SET status = $2, consecutive_failures = $3, consecutive_successes = $4, \
                last_checked_at = now(), last_error = $5, updated_at = now() \
         WHERE CAST(id AS varchar) = $1",
        &[&id, &status, &failures, &successes, &error],
    )
    .await
    .map_err(|e| full_error_string(&e))?;

    if status != prior_status && matches!(status, "up" | "down") {
        let event = format!("health_check.{status}");
        let details = serde_json::json!({
            "check_id": id, "name": check_name, "status": status,
            "record_name": record_name, "record_type": record_type,
            "target": target, "error": error, "latency_ms": latency
        });
        automation::dispatch_event(db, &event, "health_check", Some(id), &details).await;
        let _ = db
            .execute(
                "INSERT INTO audit_logs (id, user_id, action, resource_type, resource_id, details) \
                 VALUES ($1::text::uuid, NULL, $2, 'health_check', $3, $4::text::jsonb)",
                &[
                    &Uuid::new_v4().to_string(),
                    &event,
                    &id,
                    &details.to_string(),
                ],
            )
            .await;
    }
    let _ = zone_id;
    Ok((ok, latency, error, status.to_string()))
}

async fn probe_dns(
    target: &str,
    port: u16,
    name: &str,
    rtype: &str,
    timeout_ms: u64,
) -> Result<i64, String> {
    use hickory_proto::op::{Message, Query, ResponseCode};
    use hickory_proto::rr::{Name, RecordType};
    let ip: IpAddr = target
        .parse()
        .map_err(|_| "target is not an IP address".to_string())?;
    if !automation::is_public_ip(ip) {
        return Err("target is not a public address".into());
    }
    let rtype = RecordType::from_str(rtype).map_err(|e| e.to_string())?;
    let qname =
        Name::from_utf8(format!("{}.", name.trim_end_matches('.'))).map_err(|e| e.to_string())?;
    let mut msg = Message::query();
    msg.set_recursion_desired(false);
    msg.add_query(Query::query(qname.clone(), rtype));
    let wire = msg.to_vec().map_err(|e| e.to_string())?;
    let sock = tokio::net::UdpSocket::bind(if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
        .await
        .map_err(|e| e.to_string())?;
    let dest = std::net::SocketAddr::new(ip, port);
    let started = Instant::now();
    sock.send_to(&wire, dest).await.map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 4096];
    let (n, from) =
        tokio::time::timeout(Duration::from_millis(timeout_ms), sock.recv_from(&mut buf))
            .await
            .map_err(|_| "query timed out".to_string())?
            .map_err(|e| e.to_string())?;
    if from.ip() != ip {
        return Err("answer from unexpected address".into());
    }
    let resp = Message::from_vec(&buf[..n]).map_err(|e| e.to_string())?;
    if resp.id() != msg.id() {
        return Err("mismatched transaction id".into());
    }
    if resp.response_code() != ResponseCode::NoError {
        return Err(format!("server answered {}", resp.response_code()));
    }
    if !resp
        .answers()
        .iter()
        .any(|r| r.name() == &qname && r.record_type() == rtype)
    {
        return Err("no matching answer".into());
    }
    Ok(started.elapsed().as_millis() as i64)
}

/// Background worker: probes due checks and prunes old result rows.
pub fn spawn_health_worker(db: Arc<Pool>) {
    tokio::spawn(async move {
        loop {
            let due = db
                .query(
                    "SELECT CAST(id AS varchar) FROM health_checks \
                     WHERE enabled AND (last_checked_at IS NULL \
                         OR last_checked_at < now() - make_interval(secs => interval_secs)) \
                     ORDER BY last_checked_at NULLS FIRST LIMIT 20",
                    &[],
                )
                .await
                .unwrap_or_default();
            for r in due {
                let id: String = r.get(0);
                if let Err(e) = execute_check(&db, &id).await {
                    warn!("health check {}: {}", id, e);
                }
            }
            let _ = db
                .execute(
                    "DELETE FROM health_check_results WHERE created_at < now() - make_interval(days => $1)",
                    &[&RESULT_RETENTION_DAYS],
                )
                .await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/v1/health-checks", web::get().to(list_checks))
        .route("/api/v1/health-checks", web::post().to(create_check))
        .route("/api/v1/health-checks/{id}", web::get().to(get_check))
        .route("/api/v1/health-checks/{id}", web::put().to(update_check))
        .route("/api/v1/health-checks/{id}", web::delete().to(delete_check))
        .route(
            "/api/v1/health-checks/{id}/run",
            web::post().to(run_check_now),
        );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_targets_are_rejected() {
        assert!(normalize_target("127.0.0.1").is_err());
        assert!(normalize_target("10.0.0.1").is_err());
        assert!(normalize_target("::1").is_err());
        assert!(normalize_target("not-an-ip").is_err());
        assert_eq!(normalize_target("192.0.2.1").unwrap(), "192.0.2.1");
    }

    #[test]
    fn check_names_become_fqdn_relative_to_the_zone() {
        assert_eq!(
            normalize_check_name("www", Some("example.com")).unwrap(),
            "www.example.com"
        );
        assert_eq!(
            normalize_check_name("@", Some("example.com")).unwrap(),
            "example.com"
        );
        assert_eq!(
            normalize_check_name("ns1.example.com.", None).unwrap(),
            "ns1.example.com"
        );
    }
}
