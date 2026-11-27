//! Control-plane features added after the audit: zone sharing, zone history,
//! domain-ownership verification, MFA, agent bundles/acks, publication and
//! server status, audit pagination and retention, proxy-aware client IPs.

use super::*;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Proxy-aware client address
// ---------------------------------------------------------------------------

/// A trusted proxy: single address or CIDR block.
#[derive(Clone, Debug, PartialEq)]
pub struct Cidr {
    addr: IpAddr,
    bits: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Cidr> {
        let s = s.trim();
        let (a, b) = match s.split_once('/') {
            Some((a, b)) => (a, Some(b)),
            None => (s, None),
        };
        let addr: IpAddr = a.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let bits = match b {
            Some(b) => b.parse::<u8>().ok().filter(|n| *n <= max)?,
            None => max,
        };
        Some(Cidr { addr, bits })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        fn bits_of(ip: IpAddr) -> u128 {
            match ip {
                IpAddr::V4(v) => u32::from(v) as u128,
                IpAddr::V6(v) => u128::from(v),
            }
        }
        match (self.addr, ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) => {
                let shift = 32 - self.bits as u32;
                shift >= 32 && self.bits == 0
                    || (bits_of(self.addr) >> shift) == (bits_of(ip) >> shift)
            }
            (IpAddr::V6(_), IpAddr::V6(_)) => {
                let shift = 128 - self.bits as u32;
                (shift >= 128 && self.bits == 0)
                    || (bits_of(self.addr) >> shift) == (bits_of(ip) >> shift)
            }
            _ => false,
        }
    }
}

pub fn parse_trusted_proxies(v: &str) -> Vec<Cidr> {
    v.split(',')
        .filter(|s| !s.trim().is_empty())
        .filter_map(|s| {
            let c = Cidr::parse(s);
            if c.is_none() {
                warn!("ignoring invalid TRUSTED_PROXIES entry {:?}", s);
            }
            c
        })
        .collect()
}

/// The address of the real client. `X-Forwarded-For` is only honoured when the
/// direct peer is a configured trusted proxy; the right-most entry that is not
/// itself a trusted proxy is used (the left-most ones are client-controlled).
pub fn client_ip(req: &HttpRequest, trusted: &[Cidr]) -> Option<IpAddr> {
    let peer = req.peer_addr().map(|a| a.ip())?;
    if trusted.is_empty() || !trusted.iter().any(|c| c.contains(peer)) {
        return Some(peer);
    }
    let xff = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    for part in xff.rsplit(',') {
        if let Ok(ip) = part.trim().parse::<IpAddr>() {
            if !trusted.iter().any(|c| c.contains(ip)) {
                return Some(ip);
            }
        }
    }
    Some(peer)
}

// ---------------------------------------------------------------------------
// Zone sharing
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct MemberReq {
    username: String,
    role: String,
}

pub async fn list_members(
    path: web::Path<String>,
    page: web::Query<PageQuery>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let zone_id = path.into_inner();
    if let Err(r) = zone_access_at(&data.db, &zone_id, &tok, Level::Read).await {
        return r;
    }
    let (limit, offset, qtext) = page.parts();
    let sort = match page.sort_column(
        &[("username", "u.username"), ("role", "m.role")],
        "username",
    ) {
        Ok(value) => value,
        Err(()) => {
            return HttpResponse::BadRequest().json(
                serde_json::json!({"error":"invalid_query","details":"Unsupported sort field"}),
            );
        }
    };
    let direction =
        match page.sort_direction() {
            Ok(value) => value,
            Err(()) => return HttpResponse::BadRequest().json(
                serde_json::json!({"error":"invalid_query","details":"Order must be asc or desc"}),
            ),
        };
    let total: i64 = match data.db.query_one(
        "SELECT count(*) FROM zone_members m JOIN users u ON u.id = m.user_id WHERE CAST(m.zone_id AS varchar) = $1 AND ($2::text IS NULL OR u.username ILIKE '%' || $2 || '%')",
        &[&zone_id, &qtext],
    ).await {
        Ok(row) => row.get(0),
        Err(e) => {
            warn!("list_members count: {}", full_error_string(&e));
            return HttpResponse::InternalServerError().json(serde_json::json!({"error":"database_error"}));
        }
    };
    let sql = format!(
        "SELECT CAST(m.user_id AS varchar), u.username, m.role FROM zone_members m JOIN users u ON u.id = m.user_id WHERE CAST(m.zone_id AS varchar) = $1 AND ($2::text IS NULL OR u.username ILIKE '%' || $2 || '%') ORDER BY {sort} {direction}, u.id LIMIT $3::bigint OFFSET $4::bigint"
    );
    match data.db.query(&sql, &[&zone_id, &qtext, &limit, &offset]).await {
        Ok(rows) => HttpResponse::Ok().insert_header(("X-Total-Count", total.to_string())).json(rows.iter().map(|r| serde_json::json!({
            "user_id": r.get::<_, String>(0), "username": r.get::<_, String>(1), "role": r.get::<_, String>(2)
        })).collect::<Vec<_>>()),
        Err(e) => { warn!("list_members: {}", full_error_string(&e)); HttpResponse::InternalServerError().json(serde_json::json!({"error":"database error"})) }
    }
}

pub async fn put_member(
    path: web::Path<String>,
    body: web::Json<MemberReq>,
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
        Err(r) => return r,
    };
    if body.role != "viewer" && body.role != "editor" {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "role must be 'viewer' or 'editor'"}));
    }
    let user = match data.db.query_opt("SELECT CAST(id AS varchar), CAST((SELECT owner FROM zones WHERE CAST(id AS varchar) = $2) AS varchar) FROM users WHERE username = $1",
        &[&body.username.trim(), &zone_id]).await {
        Ok(Some(r)) => r, Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "user not found"})),
        Err(e) => { warn!("put_member: {}", full_error_string(&e)); return HttpResponse::InternalServerError().json(serde_json::json!({"error":"database error"})) }
    };
    let uid: String = user.get(0);
    let owner: Option<String> = user.get(1);
    if owner.as_deref() == Some(uid.as_str()) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "the owner already has full access"}));
    }
    match data.db.execute(
        "INSERT INTO zone_members (zone_id, user_id, role) VALUES ($1::text::uuid, $2::text::uuid, $3) \
         ON CONFLICT (zone_id, user_id) DO UPDATE SET role = EXCLUDED.role", &[&zone_id, &uid, &body.role]).await {
        Ok(_) => {
            audit(&data.db, Some(&tok.claims.sub), "share_zone", "zone", Some(zone_id.clone()), &req,
                  serde_json::json!({"zone": access.domain, "user": body.username, "role": body.role})).await;
            HttpResponse::Ok().json(serde_json::json!({"user_id": uid, "username": body.username.trim(), "role": body.role}))
        }
        Err(e) => { warn!("put_member: {}", full_error_string(&e)); HttpResponse::InternalServerError().json(serde_json::json!({"error":"database error"})) }
    }
}

pub async fn delete_member(
    path: web::Path<(String, String)>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let (zone_id, uid) = path.into_inner();
    let access = match zone_access_at(&data.db, &zone_id, &tok, Level::Owner).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    match data.db.execute("DELETE FROM zone_members WHERE CAST(zone_id AS varchar) = $1 AND CAST(user_id AS varchar) = $2", &[&zone_id, &uid]).await {
        Ok(0) => HttpResponse::NotFound().json(serde_json::json!({"error": "member not found"})),
        Ok(_) => {
            audit(&data.db, Some(&tok.claims.sub), "unshare_zone", "zone", Some(zone_id), &req, serde_json::json!({"zone": access.domain, "user_id": uid})).await;
            HttpResponse::Ok().json(serde_json::json!({"success": true}))
        }
        Err(e) => { warn!("delete_member: {}", full_error_string(&e)); HttpResponse::InternalServerError().json(serde_json::json!({"error":"database error"})) }
    }
}

// ---------------------------------------------------------------------------
// Zone history and rollback
// ---------------------------------------------------------------------------

const DEFAULT_REVISIONS_PER_ZONE: i64 = 50;

fn parse_revision_retention(value: Option<&str>) -> i64 {
    value
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| (1..=1000).contains(v))
        .unwrap_or(DEFAULT_REVISIONS_PER_ZONE)
}

fn revision_retention() -> i64 {
    parse_revision_retention(std::env::var("ZONE_REVISION_RETENTION").ok().as_deref())
}

#[cfg(test)]
mod revision_retention_tests {
    use super::parse_revision_retention;

    #[test]
    fn retention_is_bounded_and_defaults_safely() {
        assert_eq!(parse_revision_retention(None), 50);
        assert_eq!(parse_revision_retention(Some("200")), 200);
        assert_eq!(parse_revision_retention(Some("0")), 50);
        assert_eq!(parse_revision_retention(Some("1001")), 50);
        assert_eq!(parse_revision_retention(Some("invalid")), 50);
    }
}

/// Record the zone's current records and publishable settings as a revision.
/// Duplicate snapshots are skipped. Returns false and increments a metric when
/// persistence fails so the mutation response can report the missing history.
pub async fn snapshot_zone(db: &Pool, zone_id: &str, user: Option<&str>, reason: &str) -> bool {
    snapshot_zone_with_retention(db, zone_id, user, reason, revision_retention()).await
}

pub(crate) async fn snapshot_zone_with_retention(
    db: &Pool,
    zone_id: &str,
    user: Option<&str>,
    reason: &str,
    retention: i64,
) -> bool {
    let res = async {
        let zone = db.query_one(
            "SELECT domain, zone_type, COALESCE(geodns_enabled, true), COALESCE(ecs_enabled, false), description, tags, axfr_policy \
             FROM zones WHERE CAST(id AS varchar) = $1", &[&zone_id]).await?;
        let domain: String = zone.get(0);
        let settings = serde_json::json!({
            "zone_type": zone.get::<_, String>(1),
            "geodns_enabled": zone.get::<_, bool>(2),
            "ecs_enabled": zone.get::<_, bool>(3),
            "description": zone.get::<_, String>(4),
            "tags": zone.get::<_, serde_json::Value>(5),
            "axfr_policy": zone.get::<_, String>(6),
        });
        let rows = db.query(
            "SELECT name, record_type, value, ttl, priority FROM records WHERE CAST(zone_id AS varchar) = $1 ORDER BY name, record_type, value",
            &[&zone_id]).await?;
        let recs: Vec<serde_json::Value> = rows.iter().map(|r| serde_json::json!({
            "name": r.get::<_, String>(0), "record_type": r.get::<_, String>(1), "value": r.get::<_, String>(2),
            "ttl": r.get::<_, i32>(3), "priority": r.get::<_, Option<i32>>(4).unwrap_or(0)
        })).collect();
        let json = serde_json::Value::Array(recs).to_string();
        let same = db.query_opt(
            "SELECT 1 FROM (SELECT records::text AS r, domain, settings::text AS s FROM zone_revisions WHERE CAST(zone_id AS varchar) = $1 ORDER BY created_at DESC LIMIT 1) l \
             WHERE l.r = ($2::text::jsonb)::text AND l.domain = $3 AND l.s = ($4::text::jsonb)::text", &[&zone_id, &json, &domain, &settings.to_string()]).await?;
        if same.is_none() {
            db.execute(
                "INSERT INTO zone_revisions (id, zone_id, domain, records, settings, reason, user_id) VALUES ($1::text::uuid, $2::text::uuid, $3, $4::text::jsonb, $5::text::jsonb, $6, $7::text::uuid)",
                &[&Uuid::new_v4().to_string(), &zone_id, &domain, &json, &settings.to_string(), &reason, &user]).await?;
            db.execute(
                "DELETE FROM zone_revisions WHERE CAST(zone_id AS varchar) = $1 AND id NOT IN \
                 (SELECT id FROM zone_revisions WHERE CAST(zone_id AS varchar) = $1 ORDER BY created_at DESC LIMIT $2)",
                &[&zone_id, &retention]).await?;
        }
        Ok::<(), tokio_postgres::Error>(())
    }.await;
    let succeeded = res.is_ok();
    if let Err(e) = res {
        crate::metrics::record_snapshot_failure();
        warn!(
            "zone snapshot failed for {}: {}",
            zone_id,
            full_error_string(&e)
        );
    }
    succeeded
}

pub async fn list_revisions(
    path: web::Path<String>,
    page: web::Query<PageQuery>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let zone_id = path.into_inner();
    if let Err(r) = zone_access_at(&data.db, &zone_id, &tok, Level::Read).await {
        return r;
    }
    let (limit, offset, qtext) = page.parts();
    let sort = match page.sort_column(
        &[("created", "r.created_at"), ("reason", "r.reason")],
        "created",
    ) {
        Ok(value) => value,
        Err(()) => {
            return HttpResponse::BadRequest().json(
                serde_json::json!({"error":"invalid_query","details":"Unsupported sort field"}),
            );
        }
    };
    let direction =
        match page.sort_direction_or("desc") {
            Ok(value) => value,
            Err(()) => return HttpResponse::BadRequest().json(
                serde_json::json!({"error":"invalid_query","details":"Order must be asc or desc"}),
            ),
        };
    let total: i64 = match data.db.query_one(
        "SELECT count(*) FROM zone_revisions r WHERE CAST(r.zone_id AS varchar) = $1 AND ($2::text IS NULL OR r.reason ILIKE '%' || $2 || '%')",
        &[&zone_id, &qtext],
    ).await {
        Ok(row) => row.get(0),
        Err(e) => {
            warn!("list_revisions count: {}", full_error_string(&e));
            return HttpResponse::InternalServerError().json(serde_json::json!({"error":"database_error"}));
        }
    };
    let sql = format!(
        "SELECT CAST(r.id AS varchar), r.domain, r.reason, COALESCE(u.username, ''), r.created_at::text, jsonb_array_length(r.records) FROM zone_revisions r LEFT JOIN users u ON u.id = r.user_id WHERE CAST(r.zone_id AS varchar) = $1 AND ($2::text IS NULL OR r.reason ILIKE '%' || $2 || '%') ORDER BY {sort} {direction}, r.id LIMIT $3::bigint OFFSET $4::bigint"
    );
    match data.db.query(&sql, &[&zone_id, &qtext, &limit, &offset]).await {
        Ok(rows) => HttpResponse::Ok().insert_header(("X-Total-Count", total.to_string())).json(rows.iter().map(|r| serde_json::json!({
            "id": r.get::<_, String>(0), "domain": r.get::<_, String>(1), "reason": r.get::<_, String>(2),
            "user": r.get::<_, String>(3), "created_at": r.get::<_, String>(4), "record_count": r.get::<_, i32>(5)
        })).collect::<Vec<_>>()),
        Err(e) => { warn!("list_revisions: {}", full_error_string(&e)); HttpResponse::InternalServerError().json(serde_json::json!({"error":"database error"})) }
    }
}

/// Compare a stored revision with the zone's current records.
pub async fn diff_revision(
    path: web::Path<(String, String)>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let (zone_id, revision_id) = path.into_inner();
    if let Err(response) = zone_access_at(&data.db, &zone_id, &tok, Level::Read).await {
        return response;
    }

    let (stored, prior_settings) = match data
        .db
        .query_opt(
            "SELECT records, settings, domain FROM zone_revisions \
         WHERE CAST(id AS varchar) = $1 AND CAST(zone_id AS varchar) = $2",
            &[&revision_id, &zone_id],
        )
        .await
    {
        Ok(Some(row)) => match row.get::<_, serde_json::Value>(0).as_array().cloned() {
            Some(records) => {
                let mut settings = row.get::<_, serde_json::Value>(1);
                let has_settings = settings
                    .as_object()
                    .is_some_and(|object| !object.is_empty());
                if has_settings {
                    if let Some(object) = settings.as_object_mut() {
                        object.insert("domain".to_string(), row.get::<_, String>(2).into());
                    }
                    (records, Some(settings))
                } else {
                    (records, None)
                }
            }
            None => {
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({"error":"invalid revision"}));
            }
        },
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({"error":"revision not found"}));
        }
        Err(e) => {
            warn!("diff_revision lookup: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };

    let rows = match data
        .db
        .query(
            "SELECT name, record_type, value, ttl, priority FROM records \
         WHERE CAST(zone_id AS varchar) = $1 ORDER BY name, record_type, value",
            &[&zone_id],
        )
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            warn!("diff_revision current records: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };
    let current: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.get::<_, String>(0),
                "record_type": r.get::<_, String>(1),
                "value": r.get::<_, String>(2),
                "ttl": r.get::<_, i32>(3),
                "priority": r.get::<_, Option<i32>>(4).unwrap_or(0),
            })
        })
        .collect();

    let zone = match data.db.query_opt(
        "SELECT domain, zone_type, COALESCE(geodns_enabled, true), COALESCE(ecs_enabled, false), description, tags, axfr_policy \
         FROM zones WHERE CAST(id AS varchar) = $1",
        &[&zone_id],
    ).await {
        Ok(Some(row)) => row,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error":"zone not found"})),
        Err(e) => {
            warn!("diff_revision zone settings: {}", full_error_string(&e));
            return HttpResponse::InternalServerError().json(serde_json::json!({"error":"database error"}));
        }
    };
    let current_settings = serde_json::json!({
        "domain": zone.get::<_, String>(0),
        "zone_type": zone.get::<_, String>(1),
        "geodns_enabled": zone.get::<_, bool>(2),
        "ecs_enabled": zone.get::<_, bool>(3),
        "description": zone.get::<_, String>(4),
        "tags": zone.get::<_, serde_json::Value>(5),
        "axfr_policy": zone.get::<_, String>(6),
    });
    let settings_changed = prior_settings
        .filter(|prior| *prior != current_settings)
        .map(|prior| {
            serde_json::json!({
                "from": prior,
                "to": current_settings,
            })
        });

    let key = |r: &serde_json::Value| -> String {
        format!(
            "{}|{}|{}",
            r["name"].as_str().unwrap_or_default().to_ascii_lowercase(),
            r["record_type"]
                .as_str()
                .unwrap_or_default()
                .to_ascii_uppercase(),
            r["value"].as_str().unwrap_or_default()
        )
    };
    let detail = |r: &serde_json::Value| -> serde_json::Value {
        serde_json::json!({
            "name": r["name"],
            "record_type": r["record_type"],
            "value": r["value"],
            "ttl": r["ttl"],
            "priority": r["priority"],
        })
    };
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    for record in &current {
        if !stored.iter().any(|r| key(r) == key(record)) {
            added.push(detail(record));
        }
    }
    for record in &stored {
        if !current.iter().any(|r| key(r) == key(record)) {
            removed.push(detail(record));
        }
    }
    for record in &current {
        if let Some(old) = stored.iter().find(|r| key(r) == key(record)) {
            if old["ttl"] != record["ttl"] || old["priority"] != record["priority"] {
                changed.push(serde_json::json!({"from": detail(old), "to": detail(record)}));
            }
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "revision_id": revision_id,
        "added": added,
        "removed": removed,
        "changed": changed,
        "settings_changed": settings_changed,
    }))
}

pub async fn restore_revision(
    path: web::Path<(String, String)>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let (zone_id, rev) = path.into_inner();
    let access = match zone_access_at(&data.db, &zone_id, &tok, Level::Owner).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let row = match data.db.query_opt("SELECT records::text, settings, domain FROM zone_revisions WHERE CAST(id AS varchar) = $1 AND CAST(zone_id AS varchar) = $2", &[&rev, &zone_id]).await {
        Ok(Some(r)) => r, Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "revision not found"})),
        Err(e) => { warn!("restore: {}", full_error_string(&e)); return HttpResponse::InternalServerError().json(serde_json::json!({"error":"database error"})) }
    };
    let text: String = row.get(0);
    let settings: serde_json::Value = row.get(1);
    let restored_domain: String = row.get(2);
    if let Err(error) = validate_domain(&restored_domain) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "revision contains an invalid domain",
            "details": error
        }));
    }
    if restored_domain != access.domain {
        match data
            .db
            .query_opt(
                "SELECT 1 FROM zones WHERE domain=$1 AND CAST(id AS varchar)<>$2",
                &[&restored_domain, &zone_id],
            )
            .await
        {
            Ok(Some(_)) => return HttpResponse::Conflict().json(
                serde_json::json!({"error":"revision domain is already assigned to another zone"}),
            ),
            Ok(None) => {}
            Err(e) => {
                warn!("restore domain conflict check: {}", full_error_string(&e));
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({"error":"database error"}));
            }
        }
    }
    let recs: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap_or_default();
    let rows: Vec<RecordRow> = recs
        .iter()
        .map(|v| RecordRow {
            name: v["name"].as_str().unwrap_or("").to_string(),
            rtype: v["record_type"].as_str().unwrap_or("").to_string(),
            value: v["value"].as_str().unwrap_or("").to_string(),
            ttl: v["ttl"].as_i64().unwrap_or(3600) as i32,
            priority: v["priority"].as_i64().unwrap_or(0) as i32,
        })
        .collect();
    // the restored zone must be valid *now* (nameservers/validation rules may have changed)
    if let Err(e) = precheck_zone_change(&data.db, &restored_domain, rows.clone()).await {
        return HttpResponse::BadRequest().json(
            serde_json::json!({"error": "revision can no longer be published", "details": e}),
        );
    }
    // a restore must not be a way around the tenant's record quota (only growth counts)
    let cur: i64 = data
        .db
        .query_one(
            "SELECT count(*) FROM records WHERE CAST(zone_id AS varchar) = $1",
            &[&zone_id],
        )
        .await
        .map(|r| r.get(0))
        .unwrap_or(0);
    if let Err(resp) =
        tenants::check_zone_records_quota(&data.db, &zone_id, rows.len() as i64 - cur, &tok).await
    {
        return resp;
    }
    if !snapshot_zone(&data.db, &zone_id, Some(&tok.claims.sub), "before restore").await {
        return HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "restore not started because the current zone could not be snapshotted",
            "revision_snapshot": "failed"
        }));
    }
    let ids: Vec<String> = rows.iter().map(|_| Uuid::new_v4().to_string()).collect();
    let names: Vec<String> = rows.iter().map(|r| r.name.clone()).collect();
    let types: Vec<String> = rows.iter().map(|r| r.rtype.clone()).collect();
    let values: Vec<String> = rows.iter().map(|r| r.value.clone()).collect();
    let ttls: Vec<i32> = rows.iter().map(|r| r.ttl).collect();
    let prios: Vec<i32> = rows.iter().map(|r| r.priority).collect();
    // replace the records in one real transaction so the swap is atomic
    enum RestoreSwapError {
        Db(tokio_postgres::Error),
        Quota(HttpResponse),
    }
    let swap = async {
        let tx = data.db.begin().await.map_err(RestoreSwapError::Db)?;
        let c = tx.client();
        c.batch_execute("BEGIN").await.map_err(RestoreSwapError::Db)?;
        let r: Result<(), RestoreSwapError> = async {
            // Re-check the record quota under the same locks as the swap: the
            // earlier check is only a fast path and can race with other writes.
            let zone_row = c
                .query_opt(
                    "SELECT CAST(tenant_id AS varchar) FROM zones WHERE CAST(id AS varchar) = $1 FOR UPDATE",
                    &[&zone_id],
                )
                .await
                .map_err(RestoreSwapError::Db)?;
            let cur_tx: i64 = c
                .query_one("SELECT count(*) FROM records WHERE CAST(zone_id AS varchar) = $1", &[&zone_id])
                .await
                .map_err(RestoreSwapError::Db)?
                .get(0);
            let growth = rows.len() as i64 - cur_tx;
            if growth > 0 && tok.claims.role != "admin" {
                if let Some(t) = zone_row.and_then(|r| r.get::<_, Option<String>>(0)) {
                    tenants::reserve_quota_tx(c, &t, 0, growth)
                        .await
                        .map_err(RestoreSwapError::Quota)?;
                }
            }
            c.execute("DELETE FROM records WHERE CAST(zone_id AS varchar) = $1", &[&zone_id]).await.map_err(RestoreSwapError::Db)?;
            c.execute(
                "INSERT INTO records (id, zone_id, name, record_type, value, ttl, priority) \
                 SELECT u.id::uuid, $1::text::uuid, u.n, u.t, u.v, u.ttl, u.p \
                 FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::int4[], $7::int4[]) AS u(id, n, t, v, ttl, p)",
                &[&zone_id, &ids, &names, &types, &values, &ttls, &prios]).await.map_err(RestoreSwapError::Db)?;
            c.execute(
                "UPDATE zones SET domain=$1, updated_at=now() WHERE CAST(id AS varchar)=$2",
                &[&restored_domain, &zone_id],
            ).await.map_err(RestoreSwapError::Db)?;
            // Revisions from before settings snapshots contain `{}` and retain
            // the current configuration. New snapshots restore the publishable
            // zone policy in the same transaction as the RRset replacement.
            if settings.as_object().is_some_and(|s| !s.is_empty()) {
                let zone_type = settings.get("zone_type").and_then(serde_json::Value::as_str);
                let geodns = settings.get("geodns_enabled").and_then(serde_json::Value::as_bool);
                let ecs = settings.get("ecs_enabled").and_then(serde_json::Value::as_bool);
                let description = settings.get("description").and_then(serde_json::Value::as_str);
                let tags = settings.get("tags").map(serde_json::Value::to_string);
                let axfr_policy = settings.get("axfr_policy").and_then(serde_json::Value::as_str);
                c.execute(
                    "UPDATE zones SET zone_type = COALESCE($1, zone_type), geodns_enabled = COALESCE($2, geodns_enabled), \
                     ecs_enabled = COALESCE($3, ecs_enabled), description = COALESCE($4, description), \
                     tags = COALESCE($5::text::jsonb, tags), axfr_policy = COALESCE($6, axfr_policy), updated_at = now() \
                     WHERE CAST(id AS varchar) = $7",
                    &[&zone_type, &geodns, &ecs, &description, &tags, &axfr_policy, &zone_id],
                ).await.map_err(RestoreSwapError::Db)?;
            }
            c.batch_execute("COMMIT").await.map_err(RestoreSwapError::Db)?;
            Ok(())
        }.await;
        if r.is_err() { let _ = c.batch_execute("ROLLBACK").await; }
        r
    }.await;
    match swap {
        Ok(()) => {}
        Err(RestoreSwapError::Quota(resp)) => return resp,
        Err(RestoreSwapError::Db(e)) => {
            warn!("restore failed: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "restore failed; zone unchanged"}));
        }
    }
    if let Err(e) = publish(&data.dns_manager, &data.db, Some(&restored_domain)).await {
        return publish_failed(&e);
    }
    let revision_snapshot_ok =
        snapshot_zone(&data.db, &zone_id, Some(&tok.claims.sub), "restore").await;
    audit(
        &data.db,
        Some(&tok.claims.sub),
        "restore_revision",
        "zone",
        Some(zone_id),
        &req,
        serde_json::json!({"revision": rev, "zone": restored_domain}),
    )
    .await;
    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "records": rows.len(),
        "revision_snapshot": if revision_snapshot_ok { "saved" } else { "failed" }
    }))
}

// ---------------------------------------------------------------------------
// Domain-ownership verification
// ---------------------------------------------------------------------------

pub const CHALLENGE_LABEL: &str = "_outis-challenge";

pub fn new_verify_token() -> String {
    format!("outis-verify={}", Uuid::new_v4().simple())
}

/// TXT lookup of `name` against one resolver over UDP.
pub async fn txt_lookup(resolver: SocketAddr, name: &str) -> Result<Vec<String>, String> {
    lookup_records(resolver, name, hickory_proto::rr::RecordType::TXT).await
}

/// Look up one record type against a single resolver over UDP. The response
/// must come from the configured resolver and carry the matching transaction
/// id; TXT values are joined into one string per record, NS names are returned
/// lower-case without the trailing dot.
async fn query_message(
    resolver: SocketAddr,
    name: &str,
    rtype: hickory_proto::rr::RecordType,
) -> Result<hickory_proto::op::Message, String> {
    use hickory_proto::op::{Message, Query, ResponseCode};
    use hickory_proto::rr::Name;
    let mut msg = Message::query();
    msg.set_recursion_desired(true);
    msg.add_query(Query::query(
        Name::from_utf8(format!("{}.", name.trim_end_matches('.'))).map_err(|e| e.to_string())?,
        rtype,
    ));
    let wire = msg.to_vec().map_err(|e| e.to_string())?;
    let bind: SocketAddr = if resolver.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = tokio::net::UdpSocket::bind(bind)
        .await
        .map_err(|e| e.to_string())?;
    sock.send_to(&wire, resolver)
        .await
        .map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 4096];
    let (n, from) = tokio::time::timeout(Duration::from_secs(4), sock.recv_from(&mut buf))
        .await
        .map_err(|_| "resolver timed out".to_string())?
        .map_err(|e| e.to_string())?;
    if from.ip() != resolver.ip() {
        return Err("answer from unexpected address".into());
    }
    let resp = Message::from_vec(&buf[..n]).map_err(|e| e.to_string())?;
    if resp.id() != msg.id() {
        return Err("mismatched transaction id".into());
    }
    if resp.response_code() == ResponseCode::NXDomain {
        return Ok(resp);
    }
    if resp.response_code() != ResponseCode::NoError {
        return Err(format!("resolver answered {}", resp.response_code()));
    }
    Ok(resp)
}

pub async fn lookup_records(
    resolver: SocketAddr,
    name: &str,
    rtype: hickory_proto::rr::RecordType,
) -> Result<Vec<String>, String> {
    use hickory_proto::rr::RData;
    let resp = query_message(resolver, name, rtype).await?;
    Ok(resp
        .answers()
        .iter()
        .filter_map(|r| match r.data() {
            RData::TXT(t) => Some(
                t.txt_data()
                    .iter()
                    .map(|b| String::from_utf8_lossy(b).to_string())
                    .collect::<Vec<_>>()
                    .join(""),
            ),
            RData::NS(ns) => Some(ns.to_ascii().trim_end_matches('.').to_ascii_lowercase()),
            other => Some(other.to_string()),
        })
        .collect())
}

/// Query DS records at `name` (the parent side of a DNSSEC delegation).
pub async fn lookup_ds(resolver: SocketAddr, name: &str) -> Result<Vec<serde_json::Value>, String> {
    use hickory_proto::dnssec::rdata::DNSSECRData;
    use hickory_proto::rr::{RData, RecordType};
    let resp = query_message(resolver, name, RecordType::DS).await?;
    Ok(resp
        .answers()
        .iter()
        .filter_map(|r| match r.data() {
            RData::DNSSEC(DNSSECRData::DS(ds)) => Some(serde_json::json!({
                "key_tag": ds.key_tag(),
                "algorithm": u8::from(ds.algorithm()),
                "digest_type": u8::from(ds.digest_type()),
                "digest": data_encoding::HEXLOWER.encode(ds.digest()),
            })),
            _ => None,
        })
        .collect())
}

#[derive(Deserialize)]
pub struct VerifyQuery {
    /// `txt` (default) or `ns`.
    #[serde(default)]
    pub method: Option<String>,
}

pub async fn verify_zone(
    path: web::Path<String>,
    query: web::Query<VerifyQuery>,
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
        Err(r) => return r,
    };
    let row = match data
        .db
        .query_one(
            "SELECT status, verify_token FROM zones WHERE CAST(id AS varchar) = $1",
            &[&zone_id],
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("verify: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };
    let status: String = row.get(0);
    let token: Option<String> = row.get(1);
    if status == "active" {
        return HttpResponse::Ok()
            .json(serde_json::json!({"status": "active", "message": "zone is already active"}));
    }
    let token = match token {
        Some(t) => t,
        None => {
            return HttpResponse::Conflict()
                .json(serde_json::json!({"error": "zone has no verification token"}));
        }
    };
    let bucket = format!("zone-verify:{}:{}", tok.claims.sub, zone_id);
    if let Some(wait) = crate::shared::limited(&data.db, &bucket, 10, 60, || true).await {
        return HttpResponse::TooManyRequests().json(
            serde_json::json!({"error": "too many verification attempts", "retry_after": wait}),
        );
    }

    let method = query
        .method
        .as_deref()
        .unwrap_or("txt")
        .trim()
        .to_ascii_lowercase();
    let (lookup_name, rtype, challenge) = match method.as_str() {
        "txt" => (
            format!("{}.{}", CHALLENGE_LABEL, access.domain),
            hickory_proto::rr::RecordType::TXT,
            format!(
                "publish a TXT record at {}.{} with the value {}",
                CHALLENGE_LABEL, access.domain, token
            ),
        ),
        "ns" => (
            access.domain.clone(),
            hickory_proto::rr::RecordType::NS,
            "point the domain's NS records at the configured authoritative nameservers".to_string(),
        ),
        _ => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": "method must be txt or ns"}));
        }
    };
    let mut last_error = String::new();
    let mut found = Vec::new();
    for attempt in 0..3u32 {
        match lookup_records(data.verify_resolver, &lookup_name, rtype).await {
            Ok(values) => {
                found = values;
                last_error.clear();
                break;
            }
            Err(error) => {
                last_error = error;
                if attempt + 1 < 3 {
                    tokio::time::sleep(Duration::from_millis(300 * u64::from(attempt + 1))).await;
                }
            }
        }
    }
    if !last_error.is_empty() {
        return HttpResponse::BadGateway().json(
            serde_json::json!({"error": "verification lookup failed", "details": last_error}),
        );
    }
    let matched = if method == "ns" {
        let allowed = match crate::allowed_nameservers(&data.db).await {
            Ok(v) => v,
            Err(e) => {
                warn!("verify ns nameservers: {}", full_error_string(&e));
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({"error": "database error"}));
            }
        };
        let allowed: Vec<String> = allowed
            .iter()
            .map(|n| n.trim_end_matches('.').to_ascii_lowercase())
            .collect();
        !found.is_empty()
            && found.iter().all(|n| {
                let n = n.trim_end_matches('.').to_ascii_lowercase();
                allowed.contains(&n)
            })
    } else {
        found.iter().any(|t| t.trim() == token)
    };
    if !matched {
        return HttpResponse::UnprocessableEntity().json(serde_json::json!({
            "error": "verification challenge not satisfied",
            "details": challenge,
            "method": method,
            "found": found
        }));
    }
    if let Err(e) = data.db.execute(
        "UPDATE zones SET status = 'active', verified_at = now(), verified_via = $2, last_verified_at = now() WHERE CAST(id AS varchar) = $1",
        &[&zone_id, &method],
    ).await {
        warn!("verify: {}", full_error_string(&e));
        return HttpResponse::InternalServerError().json(serde_json::json!({"error":"database error"}));
    }
    if let Err(e) = publish(&data.dns_manager, &data.db, Some(&access.domain)).await {
        return publish_failed(&e);
    }
    audit(
        &data.db,
        Some(&tok.claims.sub),
        "verify_zone",
        "zone",
        Some(zone_id),
        &req,
        serde_json::json!({"zone": access.domain}),
    )
    .await;
    HttpResponse::Ok().json(serde_json::json!({"status": "active", "method": method}))
}

// ---------------------------------------------------------------------------
// MFA (TOTP, RFC 6238: HMAC-SHA1, 6 digits, 30 s)
// ---------------------------------------------------------------------------

fn hotp(secret: &[u8], counter: u64) -> u32 {
    use hmac::Mac as _;
    let mut mac = <Hmac<sha1::Sha1> as hmac::Mac>::new_from_slice(secret).expect("hmac key");
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[19] & 0x0f) as usize;
    let bin = ((h[off] as u32 & 0x7f) << 24)
        | ((h[off + 1] as u32) << 16)
        | ((h[off + 2] as u32) << 8)
        | h[off + 3] as u32;
    bin % 1_000_000
}

/// Verify a 6-digit code allowing one step of clock drift either way.
pub fn totp_verify(secret: &[u8], code: &str, now_secs: u64) -> bool {
    let code = code.trim();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let want: u32 = code.parse().unwrap_or(u32::MAX);
    let step = now_secs / 30;
    (step.saturating_sub(1)..=step + 1).any(|c| hotp(secret, c) == want)
}

pub fn totp_now(secret: &[u8]) -> String {
    let now = chrono::Utc::now().timestamp() as u64;
    format!("{:06}", hotp(secret, now / 30))
}

fn b32(bytes: &[u8]) -> String {
    data_encoding::BASE32_NOPAD.encode(bytes)
}

#[derive(Deserialize)]
pub struct CodeReq {
    code: String,
    #[serde(default)]
    password: Option<String>,
}

pub async fn mfa_setup(data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let secret: Vec<u8> = (0..20).map(|_| rand::random::<u8>()).collect();
    let s32 = b32(&secret);
    let row = data
        .db
        .query_opt(
            "SELECT username, totp_enabled FROM users WHERE CAST(id AS varchar) = $1",
            &[&tok.claims.sub],
        )
        .await;
    let (username, enabled): (String, bool) = match row {
        Ok(Some(r)) => (r.get(0), r.get(1)),
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({"error":"user not found"}));
        }
        Err(e) => {
            warn!("mfa_setup lookup: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };
    if enabled {
        return HttpResponse::Conflict()
            .json(serde_json::json!({"error": "MFA is already enabled; disable it first"}));
    }
    if let Err(e) = data
        .db
        .execute(
            "UPDATE users SET totp_secret = $1 WHERE CAST(id AS varchar) = $2",
            &[&s32, &tok.claims.sub],
        )
        .await
    {
        warn!("mfa_setup: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error":"database error"}));
    }
    HttpResponse::Ok().json(serde_json::json!({
        "secret": s32,
        "otpauth_url": format!("otpauth://totp/OutisCloud:{}?secret={}&issuer=OutisCloud&digits=6&period=30", username, s32)
    }))
}

pub async fn mfa_enable(
    body: web::Json<CodeReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let row = data
        .db
        .query_opt(
            "SELECT totp_secret, totp_enabled FROM users WHERE CAST(id AS varchar) = $1",
            &[&tok.claims.sub],
        )
        .await;
    let secret: Option<String> = match row {
        Ok(Some(r)) => {
            if r.get::<_, bool>(1) {
                return HttpResponse::Conflict()
                    .json(serde_json::json!({"error":"already enabled"}));
            }
            r.get(0)
        }
        Ok(None) => None,
        Err(e) => {
            warn!("mfa_enable lookup: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };
    let Some(secret) = secret.and_then(|s| data_encoding::BASE32_NOPAD.decode(s.as_bytes()).ok())
    else {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "run /auth/mfa/setup first"}));
    };
    if !totp_verify(&secret, &body.code, chrono::Utc::now().timestamp() as u64) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid code"}));
    }
    let tx = match data.db.begin().await {
        Ok(t) => t,
        Err(e) => {
            warn!("mfa_enable transaction: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };
    let c = tx.client();
    if let Err(e) = c.batch_execute("BEGIN").await {
        warn!("mfa_enable begin: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error":"database error"}));
    }
    let updated = match c.execute(
        "UPDATE users SET totp_enabled = true, token_version = token_version + 1, updated_at = now() \
         WHERE CAST(id AS varchar) = $1",
        &[&tok.claims.sub],
    ).await {
        Ok(n) => n,
        Err(e) => {
            let _ = c.batch_execute("ROLLBACK").await;
            warn!("mfa_enable: {}", full_error_string(&e));
            return HttpResponse::InternalServerError().json(serde_json::json!({"error":"database error"}));
        }
    };
    if updated == 0 {
        let _ = c.batch_execute("ROLLBACK").await;
        return HttpResponse::NotFound().json(serde_json::json!({"error":"user not found"}));
    }
    if let Err(e) = c.execute(
        "DELETE FROM token_blacklist WHERE CAST(user_id AS varchar) = $1 AND token_type = 'refresh'",
        &[&tok.claims.sub],
    ).await {
        let _ = c.batch_execute("ROLLBACK").await;
        warn!("mfa_enable sessions: {}", full_error_string(&e));
        return HttpResponse::InternalServerError().json(serde_json::json!({"error":"database error"}));
    }
    if let Err(e) = c.batch_execute("COMMIT").await {
        warn!("mfa_enable commit: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error":"database error"}));
    }
    drop(tx);
    audit(
        &data.db,
        Some(&tok.claims.sub),
        "mfa_enable",
        "user",
        Some(tok.claims.sub.clone()),
        &req,
        serde_json::json!({}),
    )
    .await;
    HttpResponse::Ok().json(serde_json::json!({"mfa": "enabled"}))
}

pub async fn mfa_disable(
    body: web::Json<CodeReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let row = data.db.query_opt("SELECT password_hash, totp_secret, totp_enabled FROM users WHERE CAST(id AS varchar) = $1", &[&tok.claims.sub]).await;
    let (hash, secret, enabled): (String, Option<String>, bool) = match row {
        Ok(Some(r)) => (r.get(0), r.get(1), r.get(2)),
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({"error":"user not found"}));
        }
        Err(e) => {
            warn!("mfa_disable lookup: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };
    if !enabled {
        return HttpResponse::Conflict().json(serde_json::json!({"error": "MFA is not enabled"}));
    }
    // both factors are required to turn MFA off
    if !hash_matches(&hash, body.password.as_deref().unwrap_or("")) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "password required"}));
    }
    let secret = secret
        .and_then(|s| data_encoding::BASE32_NOPAD.decode(s.as_bytes()).ok())
        .unwrap_or_default();
    if !totp_verify(&secret, &body.code, chrono::Utc::now().timestamp() as u64) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "invalid code"}));
    }
    let tx = match data.db.begin().await {
        Ok(t) => t,
        Err(e) => {
            warn!("mfa_disable transaction: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };
    let c = tx.client();
    if let Err(e) = c.batch_execute("BEGIN").await {
        warn!("mfa_disable begin: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error":"database error"}));
    }
    let updated = match c
        .execute(
            "UPDATE users SET totp_enabled = false, totp_secret = NULL, \
                token_version = token_version + 1, updated_at = now() \
         WHERE CAST(id AS varchar) = $1",
            &[&tok.claims.sub],
        )
        .await
    {
        Ok(n) => n,
        Err(e) => {
            let _ = c.batch_execute("ROLLBACK").await;
            warn!("mfa_disable: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };
    if updated == 0 {
        let _ = c.batch_execute("ROLLBACK").await;
        return HttpResponse::NotFound().json(serde_json::json!({"error":"user not found"}));
    }
    if let Err(e) = c.execute(
        "DELETE FROM token_blacklist WHERE CAST(user_id AS varchar) = $1 AND token_type = 'refresh'",
        &[&tok.claims.sub],
    ).await {
        let _ = c.batch_execute("ROLLBACK").await;
        warn!("mfa_disable sessions: {}", full_error_string(&e));
        return HttpResponse::InternalServerError().json(serde_json::json!({"error":"database error"}));
    }
    if let Err(e) = c.batch_execute("COMMIT").await {
        warn!("mfa_disable commit: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error":"database error"}));
    }
    drop(tx);
    audit(
        &data.db,
        Some(&tok.claims.sub),
        "mfa_disable",
        "user",
        Some(tok.claims.sub.clone()),
        &req,
        serde_json::json!({}),
    )
    .await;
    HttpResponse::Ok().json(serde_json::json!({"mfa": "disabled"}))
}

// ---------------------------------------------------------------------------
// Agents: enable/disable, signed + versioned bundles, acknowledgements
// ---------------------------------------------------------------------------

/// Per-agent signing key: HMAC(master, "agent-bundle|<agent id>"). Handed to
/// the agent at registration / token rotation, never stored.
pub fn agent_signing_key(master: &str, agent_id: &str) -> String {
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(master.as_bytes()).expect("hmac key");
    mac.update(format!("agent-bundle|{}", agent_id).as_bytes());
    hex(&mac.finalize().into_bytes())
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// Sign the canonical bundle body.
pub fn sign_bundle(key_hex: &str, version: i64, hash: &str, files: &[(String, String)]) -> String {
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(key_hex.as_bytes()).expect("hmac key");
    mac.update(format!("v1|{}|{}|", version, hash).as_bytes());
    for (n, c) in files {
        mac.update(format!("{}:{}|", n.len(), n).as_bytes());
        mac.update(format!("{}:", c.len()).as_bytes());
        mac.update(c.as_bytes());
    }
    hex(&mac.finalize().into_bytes())
}

pub fn bundle_hash(files: &[(String, String)]) -> String {
    let mut h = Sha256::new();
    for (n, c) in files {
        h.update((n.len() as u64).to_be_bytes());
        h.update(n.as_bytes());
        h.update((c.len() as u64).to_be_bytes());
        h.update(c.as_bytes());
    }
    hex(&h.finalize())
}

pub const ZONE_DIR_TOKEN: &str = "@ZONE_DIR@";

/// Snapshot of what is published: `named.toml` (with the local directory
/// replaced by a placeholder the agent substitutes) and every referenced zone
/// file, read while holding the publish lock so it is internally consistent.
pub async fn read_bundle_files(dns: &DnsManager) -> std::io::Result<Vec<(String, String)>> {
    let _g = dns.lock().await;
    let dir = std::path::PathBuf::from(dns.zone_dir());
    let toml = tokio::fs::read_to_string(dir.join("named.toml")).await?;
    let base = dir.to_string_lossy().trim_end_matches('/').to_string();
    let mut files = vec![(
        "named.toml".to_string(),
        toml.replace(&format!("{}/", base), &format!("{}/", ZONE_DIR_TOKEN)),
    )];
    let mut names: Vec<String> = Vec::new();
    let mut rd = tokio::fs::read_dir(&dir).await?;
    while let Some(e) = rd.next_entry().await? {
        let n = e.file_name().to_string_lossy().to_string();
        if n.starts_with("zone.") && !n.ends_with(".tmp") && e.file_type().await?.is_file() {
            names.push(n);
        }
    }
    names.sort();
    for n in names {
        let c = tokio::fs::read_to_string(dir.join(&n)).await?;
        files.push((n, c));
    }
    Ok(files)
}

/// Restrict a published bundle snapshot to an explicit set of zone domains.
/// The named.toml copy is parsed rather than string-spliced so unknown content
/// cannot smuggle an unauthorized zone into an agent's configuration.
pub fn filter_bundle_files(
    files: Vec<(String, String)>,
    allowed: &HashSet<String>,
) -> Result<Vec<(String, String)>, String> {
    let allowed: HashSet<String> = allowed
        .iter()
        .map(|d| d.trim_end_matches('.').to_ascii_lowercase())
        .collect();
    let mut out = Vec::with_capacity(files.len());
    for (name, content) in files {
        if name == "named.toml" {
            let mut doc: toml::Value = toml::from_str(&content)
                .map_err(|e| format!("published named.toml is invalid: {e}"))?;
            if let Some(zones) = doc.get_mut("zones").and_then(toml::Value::as_array_mut) {
                zones.retain(|entry| {
                    entry
                        .get("zone")
                        .and_then(toml::Value::as_str)
                        .map(|d| {
                            allowed.contains(d.trim_end_matches('.').to_ascii_lowercase().as_str())
                        })
                        .unwrap_or(false)
                });
            }
            let filtered = toml::to_string(&doc)
                .map_err(|e| format!("failed to serialize filtered named.toml: {e}"))?;
            out.push((name, filtered));
        } else if let Some(domain) = name.strip_prefix("zone.") {
            if allowed.contains(domain.trim_end_matches('.').to_ascii_lowercase().as_str()) {
                out.push((name, content));
            }
        }
    }
    Ok(out)
}

/// Make the stored bundle version match the published content: the version
/// is bumped exactly when the content hash changes.
pub async fn current_bundle(
    dns: &DnsManager,
    db: &Pool,
) -> Result<(i64, String, Vec<(String, String)>), String> {
    let files = read_bundle_files(dns)
        .await
        .map_err(|e| format!("cannot read published files: {}", e))?;
    let hash = bundle_hash(&files);
    let row = db.query_one(
        "UPDATE publish_state SET version = version + 1, bundle_hash = $1, updated_at = now() WHERE bundle_hash IS DISTINCT FROM $1 RETURNING version",
        &[&hash]).await;
    let version: i64 = match row {
        Ok(r) => r.get(0),
        Err(_) => db
            .query_one("SELECT version FROM publish_state WHERE id = 1", &[])
            .await
            .map_err(|e| e.to_string())?
            .get(0),
    };
    Ok((version, hash, files))
}

/// Authenticate an agent by id + bearer token. New registrations carry a
/// SHA-256 token fingerprint, so the common path never runs Argon2. Legacy
/// agents are verified once and then upgraded in place.
pub(crate) async fn agent_authenticated(
    data: &AppState,
    agent_id: &str,
    req: &HttpRequest,
) -> Result<(), HttpResponse> {
    let token = match bearer_token(req) {
        Some(t) => t.to_string(),
        None => return Err(HttpResponse::Unauthorized().finish()),
    };
    let row = data.db.query_opt("SELECT token_hash, token_sha256 FROM agents WHERE CAST(id AS varchar) = $1 AND COALESCE(enabled, true)", &[&agent_id]).await;
    match row {
        Ok(Some(r)) => {
            let th: String = r.get(0);
            let fingerprint: Option<String> = r.get(1);
            let presented = hash_token(&token);
            if fingerprint.as_deref() == Some(presented.as_str()) {
                return Ok(());
            }
            if fingerprint.is_some() {
                return Err(HttpResponse::Unauthorized().finish());
            }
            let ok = PasswordHash::new(&th)
                .map(|p| {
                    Argon2::default()
                        .verify_password(token.as_bytes(), &p)
                        .is_ok()
                })
                .unwrap_or(false);
            if !ok {
                return Err(HttpResponse::Unauthorized().finish());
            }
            let _ = data.db.execute("UPDATE agents SET token_sha256 = $1 WHERE CAST(id AS varchar) = $2 AND token_sha256 IS NULL", &[&presented, &agent_id]).await;
            Ok(())
        }
        Ok(None) => Err(HttpResponse::Unauthorized().finish()),
        Err(e) => {
            warn!("agent auth: {}", full_error_string(&e));
            Err(HttpResponse::InternalServerError().finish())
        }
    }
}

/// Zones an agent is explicitly allowed to serve. An unassigned agent gets an
/// empty set, never the platform-wide zone list.
pub async fn agent_authorized_domains(
    db: &Pool,
    agent_id: &str,
) -> Result<HashSet<String>, tokio_postgres::Error> {
    let rows = db
        .query(
            "SELECT z.domain FROM agent_zones az JOIN zones z ON z.id = az.zone_id \
             WHERE CAST(az.agent_id AS varchar) = $1 AND COALESCE(z.status, 'active') = 'active'",
            &[&agent_id],
        )
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            r.get::<_, String>(0)
                .trim_end_matches('.')
                .to_ascii_lowercase()
        })
        .collect())
}

pub async fn agent_bundle(
    path: web::Path<String>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let agent_id = path.into_inner();
    if let Err(r) = agent_authenticated(&data, &agent_id, &req).await {
        return r;
    }
    let allowed = match agent_authorized_domains(&data.db, &agent_id).await {
        Ok(a) => a,
        Err(e) => {
            warn!("agent bundle authorization: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "bundle unavailable"}));
        }
    };
    let (version, _, files) = match current_bundle(&data.dns_manager, &data.db).await {
        Ok(v) => v,
        Err(e) => {
            warn!("bundle: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "bundle unavailable"}));
        }
    };
    let files = match filter_bundle_files(files, &allowed) {
        Ok(f) => f,
        Err(e) => {
            warn!("agent bundle filtering: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "bundle unavailable"}));
        }
    };
    let hash = bundle_hash(&files);
    let key_version: i16 = match data
        .db
        .query_opt(
            "SELECT signing_key_version FROM agents WHERE CAST(id AS varchar) = $1",
            &[&agent_id],
        )
        .await
    {
        Ok(Some(row)) => row.get(0),
        _ => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"bundle unavailable"}));
        }
    };
    let master = if key_version == 1 {
        &data.jwt_secret
    } else {
        &data.agent_signing_secret
    };
    let key = agent_signing_key(master, &agent_id);
    let signature = sign_bundle(&key, version, &hash, &files);
    HttpResponse::Ok().json(serde_json::json!({
        "version": version, "hash": hash, "signature": signature, "zone_dir_token": ZONE_DIR_TOKEN,
        "files": files.iter().map(|(n, c)| serde_json::json!({"name": n, "content": c})).collect::<Vec<_>>()
    }))
}

#[derive(Deserialize)]
pub struct AckReq {
    version: i64,
    #[serde(default)]
    ok: Option<bool>,
    #[serde(default)]
    error: Option<String>,
}

pub async fn agent_ack(
    path: web::Path<String>,
    body: web::Json<AckReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let agent_id = path.into_inner();
    if let Err(r) = agent_authenticated(&data, &agent_id, &req).await {
        return r;
    }
    let ok = body.ok.unwrap_or(true);
    let err: Option<String> = if ok {
        None
    } else {
        Some(
            body.error
                .clone()
                .unwrap_or_else(|| "unknown error".into())
                .chars()
                .take(500)
                .collect(),
        )
    };
    let res = if ok {
        data.db.execute(
            "UPDATE agents SET applied_version = GREATEST(applied_version, $1), last_ack_at = now(), last_error = NULL, sync_requested = false WHERE CAST(id AS varchar) = $2",
            &[&body.version, &agent_id]).await
    } else {
        data.db.execute("UPDATE agents SET last_error = $1, last_ack_at = now() WHERE CAST(id AS varchar) = $2", &[&err, &agent_id]).await
    };
    match res {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"recorded": true})),
        Err(e) => {
            warn!("agent_ack: {}", full_error_string(&e));
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[derive(Deserialize)]
pub struct AgentEnableReq {
    enabled: bool,
}

pub async fn set_agent_enabled(
    path: web::Path<String>,
    body: web::Json<AgentEnableReq>,
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
    let id = path.into_inner();
    match data
        .db
        .execute(
            "UPDATE agents SET enabled = $1, updated_at = now() WHERE CAST(id AS varchar) = $2",
            &[&body.enabled, &id],
        )
        .await
    {
        Ok(0) => HttpResponse::NotFound().json(serde_json::json!({"error": "agent not found"})),
        Ok(_) => {
            audit(
                &data.db,
                Some(&tok.claims.sub),
                if body.enabled {
                    "enable_agent"
                } else {
                    "disable_agent"
                },
                "agent",
                Some(id),
                &req,
                serde_json::json!({}),
            )
            .await;
            HttpResponse::Ok().json(serde_json::json!({"enabled": body.enabled}))
        }
        Err(e) => {
            warn!("set_agent_enabled: {}", full_error_string(&e));
            HttpResponse::InternalServerError().json(serde_json::json!({"error":"database error"}))
        }
    }
}

// ---------------------------------------------------------------------------
// Publication status, server health, DNS query metrics
// ---------------------------------------------------------------------------

pub async fn dns_status(data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    if tok.claims.role != "admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "admin role required"}));
    }
    let last = data.dns_manager.last_publish();
    let (version, hash): (i64, Option<String>) = match data
        .db
        .query_one(
            "SELECT version, bundle_hash FROM publish_state WHERE id = 1",
            &[],
        )
        .await
    {
        Ok(r) => (r.get(0), r.get(1)),
        Err(_) => (0, None),
    };
    HttpResponse::Ok().json(serde_json::json!({
        "bundle_version": version, "bundle_hash": hash,
        "last_publish": last.map(|l| serde_json::json!({
            "at": l.at.to_rfc3339(), "ok": l.failed.is_empty() && l.error.is_none(),
            "published": l.published, "failed": l.failed.iter().map(|(z, e)| serde_json::json!({"zone": z, "error": e})).collect::<Vec<_>>(),
            "error": l.error
        })),
        "db_connections": {"healthy": data.db.healthy(), "size": data.db.size()}
    }))
}

/// TCP reachability of a DNS server (authoritative servers listen on TCP too).
pub async fn probe_server(host: &str, port: i32) -> (&'static str, Option<u128>) {
    let started = std::time::Instant::now();
    let addr = format!("{}:{}", host.trim(), port);
    match tokio::time::timeout(
        Duration::from_millis(1500),
        tokio::net::TcpStream::connect(addr),
    )
    .await
    {
        Ok(Ok(_)) => ("running", Some(started.elapsed().as_millis())),
        _ => ("unreachable", None),
    }
}

pub async fn server_status(
    path: web::Path<String>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    // infrastructure detail (and a TCP probe from the control plane): administrators only
    match auth_from_header(&req, &data.jwt_secret) {
        None => return unauthorized(),
        Some(t) if t.claims.role != "admin" => {
            return HttpResponse::Forbidden()
                .json(serde_json::json!({"error": "admin role required"}));
        }
        Some(_) => {}
    }
    let id = path.into_inner();
    match data
        .db
        .query_opt(
            "SELECT address, port FROM servers WHERE CAST(id AS varchar) = $1",
            &[&id],
        )
        .await
    {
        Ok(Some(r)) => {
            let (host, port): (String, i32) = (r.get(0), r.get(1));
            let (status, ms) = probe_server(&host, port).await;
            HttpResponse::Ok()
                .json(serde_json::json!({"id": id, "status": status, "latency_ms": ms}))
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "server not found"})),
        Err(e) => {
            warn!("server_status: {}", full_error_string(&e));
            HttpResponse::InternalServerError().json(serde_json::json!({"error":"database error"}))
        }
    }
}

/// Plain HTTP GET (the DNS server's Prometheus endpoint is plain HTTP).
pub async fn http_get(url: &str) -> Result<String, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let rest = url
        .strip_prefix("http://")
        .ok_or("only http:// metrics URLs are supported")?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let mut s = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::TcpStream::connect(hostport),
    )
    .await
    .map_err(|_| "metrics endpoint timed out")?
    .map_err(|e| e.to_string())?;
    s.write_all(
        format!(
            "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
            path, hostport
        )
        .as_bytes(),
    )
    .await
    .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(5),
        s.take(4 * 1024 * 1024).read_to_end(&mut out),
    )
    .await
    .map_err(|_| "metrics read timed out")?
    .map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&out).to_string();
    Ok(text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or(text))
}

/// Parse Prometheus text exposition: `name{labels} value`.
pub fn parse_prometheus(text: &str) -> Vec<(String, String, f64)> {
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let (lhs, val) = l.rsplit_once(' ')?;
            let val: f64 = val.parse().ok()?;
            let (name, labels) = match lhs.find('{') {
                Some(i) => (&lhs[..i], lhs[i..].to_string()),
                None => (lhs, String::new()),
            };
            Some((name.to_string(), labels, val))
        })
        .collect()
}

pub async fn query_metrics(data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    if tok.claims.role != "admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "admin role required"}));
    }
    let Some(url) = data.dns_metrics_url.clone() else {
        return HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "not_configured", "details": "set DNS_METRICS_URL to the DNS server's Prometheus endpoint (http://host:port/metrics)"
        }));
    };
    match http_get(&url).await {
        Ok(text) => {
            let samples = parse_prometheus(&text);
            let mut total = 0.0;
            let mut by_name: std::collections::BTreeMap<String, f64> = Default::default();
            for (n, _l, v) in samples.iter().filter(|(n, _, _)| {
                n.starts_with("hickory_")
                    && (n.contains("request") || n.contains("lookup") || n.contains("response"))
            }) {
                *by_name.entry(n.clone()).or_insert(0.0) += v;
                if n.contains("request") && n.ends_with("_total") {
                    total += v;
                }
            }
            HttpResponse::Ok().json(
                serde_json::json!({"requests_total": total, "counters": by_name, "source": url}),
            )
        }
        Err(e) => HttpResponse::BadGateway()
            .json(serde_json::json!({"error": "metrics endpoint unreachable", "details": e})),
    }
}

// ---------------------------------------------------------------------------
// Audit pagination, filters and retention
// ---------------------------------------------------------------------------

/// Pagination for list endpoints: `limit` defaults to 100 and is capped at
/// 1000; `X-Total-Count` always carries the full match count.
#[derive(Deserialize, Default)]
pub struct PageQuery {
    limit: Option<i64>,
    offset: Option<i64>,
    q: Option<String>,
    tag: Option<String>,
    sort: Option<String>,
    order: Option<String>,
    cursor: Option<String>,
}
impl PageQuery {
    /// (limit, offset, search text)
    pub fn parts(&self) -> (Option<i64>, i64, Option<String>) {
        (
            Some(self.limit.unwrap_or(100).clamp(1, 1000)),
            self.offset.unwrap_or(0).max(0),
            self.q
                .as_ref()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        )
    }

    /// Optional exact tag filter for list endpoints backed by `tags JSONB`.
    pub fn tag(&self) -> Option<String> {
        self.tag
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    /// Opaque endpoint-specific keyset cursor, if supplied.
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref().filter(|value| !value.is_empty())
    }

    /// Resolve the requested sort field through an endpoint-owned allowlist.
    /// The returned SQL identifier is always a static string from that list.
    pub fn sort_column(
        &self,
        allowed: &[(&'static str, &'static str)],
        default: &str,
    ) -> Result<&'static str, ()> {
        let requested = self.sort.as_deref().unwrap_or(default);
        allowed
            .iter()
            .find(|(name, _)| *name == requested)
            .map(|(_, column)| *column)
            .ok_or(())
    }

    /// Resolve `order=asc|desc`; default ordering is ascending.
    pub fn sort_direction(&self) -> Result<&'static str, ()> {
        self.sort_direction_or("asc")
    }

    /// Resolve `order=asc|desc` while preserving an endpoint's historical default.
    pub fn sort_direction_or(&self, default: &'static str) -> Result<&'static str, ()> {
        match self.order.as_deref().unwrap_or(default) {
            "asc" => Ok("ASC"),
            "desc" => Ok("DESC"),
            _ => Err(()),
        }
    }
}

#[derive(Deserialize)]
pub struct AuditQuery {
    limit: Option<i64>,
    offset: Option<i64>,
    action: Option<String>,
    user_id: Option<String>,
    resource_type: Option<String>,
    since: Option<String>,
    sort: Option<String>,
    order: Option<String>,
    q: Option<String>,
}

fn audit_filters(q: &AuditQuery) -> Result<(Option<String>, Option<String>), HttpResponse> {
    let since = match q.since.as_deref() {
        Some(value) => Some(chrono::DateTime::parse_from_rfc3339(value).map_err(|_| {
            HttpResponse::BadRequest().json(serde_json::json!({"error":"invalid_query","details":"since must be RFC 3339"}))
        })?.with_timezone(&chrono::Utc).to_rfc3339()),
        None => None,
    };
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty());
    if search.is_some_and(|s| s.chars().count() > 200) {
        return Err(HttpResponse::BadRequest().json(
            serde_json::json!({"error":"invalid_query","details":"q exceeds 200 characters"}),
        ));
    }
    Ok((since, search.map(str::to_string)))
}

pub async fn list_audit(
    q: web::Query<AuditQuery>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    if tok.claims.role != "admin" {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"error": "admin access required"}));
    }
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let offset = q.offset.unwrap_or(0).max(0);
    let sort = match q.sort.as_deref().unwrap_or("created") {
        "created" => "created_at",
        "action" => "action",
        "user_id" => "user_id",
        "resource_type" => "resource_type",
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
    let (since, search) = match audit_filters(&q) {
        Ok(filters) => filters,
        Err(response) => return response,
    };
    let where_sql = "($1::text IS NULL OR action = $1) AND ($2::text IS NULL OR CAST(user_id AS varchar) = $2) \
                     AND ($3::text IS NULL OR resource_type = $3) AND ($4::text IS NULL OR created_at >= $4::text::timestamptz) \
                     AND ($5::text IS NULL OR strpos(lower(concat_ws(' ', action, resource_type, resource_id, details::text)), lower($5)) > 0)";
    let total: i64 = match data
        .db
        .query_one(
            &format!("SELECT count(*) FROM audit_logs WHERE {}", where_sql),
            &[&q.action, &q.user_id, &q.resource_type, &since, &search],
        )
        .await
    {
        Ok(r) => r.get(0),
        Err(e) => {
            warn!("audit count: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error":"database error"}));
        }
    };
    let rows = match data.db.query(&format!(
        "SELECT CAST(id AS varchar), COALESCE(CAST(user_id AS varchar), ''), action, resource_type, COALESCE(resource_id, ''), COALESCE(details::text, ''), COALESCE(ip_address, ''), created_at::text \
         FROM audit_logs WHERE {} ORDER BY {} {}, id LIMIT $6 OFFSET $7", where_sql, sort, direction),
        &[&q.action, &q.user_id, &q.resource_type, &since, &search, &limit, &offset]).await {
        Ok(r) => r, Err(e) => { warn!("audit list: {}", full_error_string(&e)); return HttpResponse::InternalServerError().json(serde_json::json!({"error":"database error"})) }
    };
    let logs: Vec<AuditLogEntry> = rows
        .into_iter()
        .map(|r| AuditLogEntry {
            id: r.get(0),
            user_id: Some(r.get::<_, String>(1)).filter(|s| !s.is_empty()),
            action: r.get(2),
            resource_type: r.get(3),
            resource_id: Some(r.get::<_, String>(4)).filter(|s| !s.is_empty()),
            details: r.get(5),
            ip_address: Some(r.get::<_, String>(6)).filter(|s| !s.is_empty()),
            created_at: r.get(7),
        })
        .collect();
    HttpResponse::Ok()
        .insert_header(("X-Total-Count", total.to_string()))
        .json(ApiResponse {
            success: true,
            data: Some(logs),
            error: None,
        })
}

pub async fn get_audit(
    path: web::Path<String>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    if tok.claims.role != "admin" {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"error": "admin access required"}));
    }
    let id = path.into_inner();
    match data.db.query_opt(
        "SELECT CAST(id AS varchar), COALESCE(CAST(user_id AS varchar), ''), action, resource_type, \
         COALESCE(resource_id, ''), COALESCE(details::text, ''), COALESCE(ip_address, ''), \
         COALESCE(user_agent, ''), created_at::text FROM audit_logs WHERE CAST(id AS varchar) = $1",
        &[&id],
    ).await {
        Ok(Some(row)) => HttpResponse::Ok().json(ApiResponse {
            success: true,
            data: Some(AuditLogEntry {
                id: row.get(0),
                user_id: Some(row.get::<_, String>(1)).filter(|s| !s.is_empty()),
                action: row.get(2),
                resource_type: row.get(3),
                resource_id: Some(row.get::<_, String>(4)).filter(|s| !s.is_empty()),
                details: row.get(5),
                ip_address: Some(row.get::<_, String>(6)).filter(|s| !s.is_empty()),
                created_at: row.get(8),
            }),
            error: None,
        }),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "audit entry not found"})),
        Err(e) => {
            warn!("audit detail: {}", full_error_string(&e));
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "database error"}))
        }
    }
}

fn csv_field(value: &str) -> String {
    // Spreadsheet applications evaluate cells beginning with these characters
    // even when the CSV value is quoted. Audit details can contain user input.
    let unsafe_prefix = value
        .trim_start_matches(|ch: char| ch.is_whitespace() || ch == '\u{feff}')
        .chars()
        .next()
        .is_some_and(|ch| matches!(ch, '=' | '+' | '-' | '@' | '\t' | '\r'));
    let safe = if unsafe_prefix {
        format!("'{value}")
    } else {
        value.to_string()
    };
    if unsafe_prefix || safe.contains(',') || safe.contains('"') || safe.contains('\n') {
        format!("\"{}\"", safe.replace('"', "\"\""))
    } else {
        safe
    }
}

#[cfg(test)]
mod csv_security_tests {
    use super::csv_field;

    #[test]
    fn audit_export_neutralizes_spreadsheet_formulas_and_quotes() {
        assert_eq!(csv_field("=1+1"), "\"'=1+1\"");
        assert_eq!(csv_field("  @SUM(A1)"), "\"'  @SUM(A1)\"");
        assert_eq!(csv_field("\t+cmd"), "\"'\t+cmd\"");
        assert_eq!(csv_field("\u{feff}=1+1"), "\"'\u{feff}=1+1\"");
        assert_eq!(csv_field("\u{2003}-1+1"), "\"'\u{2003}-1+1\"");
        assert_eq!(csv_field("hello,\"world\""), "\"hello,\"\"world\"\"\"");
        assert_eq!(csv_field("normal"), "normal");
    }
}

pub async fn export_audit(
    q: web::Query<AuditQuery>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    if tok.claims.role != "admin" {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"error": "admin access required"}));
    }
    let limit = q.limit.unwrap_or(1000).clamp(1, 10_000);
    let (since, search) = match audit_filters(&q) {
        Ok(filters) => filters,
        Err(response) => return response,
    };
    let where_sql = "($1::text IS NULL OR action = $1) AND ($2::text IS NULL OR CAST(user_id AS varchar) = $2) \
                     AND ($3::text IS NULL OR resource_type = $3) AND ($4::text IS NULL OR created_at >= $4::text::timestamptz) \
                     AND ($5::text IS NULL OR strpos(lower(concat_ws(' ', action, resource_type, resource_id, details::text)), lower($5)) > 0)";
    let sql = format!(
        "SELECT CAST(id AS varchar), COALESCE(CAST(user_id AS varchar), ''), action, resource_type, \
         COALESCE(resource_id, ''), COALESCE(details::text, ''), COALESCE(ip_address, ''), created_at::text \
         FROM audit_logs WHERE {} ORDER BY created_at DESC, id DESC LIMIT $6 OFFSET $7",
        where_sql
    );
    let state = Some((
        data.db.clone(),
        q.action.clone(),
        q.user_id.clone(),
        q.resource_type.clone(),
        since,
        search,
        limit,
        0i64,
        false,
    ));
    let stream = futures_util::stream::unfold(state, move |state| {
        let sql = sql.clone();
        async move {
            let Some((
                db,
                action,
                user_id,
                resource_type,
                since,
                search,
                remaining,
                offset,
                header_sent,
            )) = state
            else {
                return None;
            };
            if !header_sent {
                let header =
                    "id,user_id,action,resource_type,resource_id,details,ip_address,created_at\n";
                return Some((
                    Ok::<_, actix_web::Error>(web::Bytes::from_static(header.as_bytes())),
                    Some((
                        db,
                        action,
                        user_id,
                        resource_type,
                        since,
                        search,
                        remaining,
                        offset,
                        true,
                    )),
                ));
            }
            if remaining == 0 {
                return None;
            }
            let batch = remaining.min(250);
            let rows = match db
                .query(
                    &sql,
                    &[
                        &action,
                        &user_id,
                        &resource_type,
                        &since,
                        &search,
                        &batch,
                        &offset,
                    ],
                )
                .await
            {
                Ok(rows) => rows,
                Err(error) => {
                    warn!("audit export: {}", full_error_string(&error));
                    return Some((
                        Err(actix_web::error::ErrorInternalServerError(
                            "audit export failed",
                        )),
                        None,
                    ));
                }
            };
            if rows.is_empty() {
                return None;
            }
            let count = rows.len() as i64;
            let mut csv = String::new();
            for row in rows {
                let fields: Vec<String> = (0..8)
                    .map(|i| csv_field(&row.get::<_, String>(i)))
                    .collect();
                csv.push_str(&fields.join(","));
                csv.push('\n');
            }
            Some((
                Ok(web::Bytes::from(csv)),
                Some((
                    db,
                    action,
                    user_id,
                    resource_type,
                    since,
                    search,
                    remaining - count,
                    offset + count,
                    true,
                )),
            ))
        }
    });
    HttpResponse::Ok()
        .content_type("text/csv; charset=utf-8")
        .insert_header((
            "Content-Disposition",
            "attachment; filename=audit-export.csv",
        ))
        .streaming(stream)
}

/// Delete audit rows older than `days`; returns the number removed.
pub async fn purge_audit(db: &Pool, days: i64) -> Result<u64, tokio_postgres::Error> {
    db.execute(
        "DELETE FROM audit_logs WHERE created_at < now() - ($1::bigint * interval '1 day')",
        &[&days],
    )
    .await
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/v1/zones/{id}/members", web::get().to(list_members))
        .route("/api/v1/zones/{id}/members", web::put().to(put_member))
        .route(
            "/api/v1/zones/{id}/members/{user_id}",
            web::delete().to(delete_member),
        )
        .route(
            "/api/v1/zones/{id}/revisions",
            web::get().to(list_revisions),
        )
        .route(
            "/api/v1/zones/{id}/revisions/{rev}/restore",
            web::post().to(restore_revision),
        )
        .route(
            "/api/v1/zones/{id}/revisions/{rev}/diff",
            web::get().to(diff_revision),
        )
        .route("/api/v1/zones/{id}/verify", web::post().to(verify_zone))
        .route("/api/v1/auth/mfa/setup", web::post().to(mfa_setup))
        .route("/api/v1/auth/mfa/enable", web::post().to(mfa_enable))
        .route("/api/v1/auth/mfa/disable", web::post().to(mfa_disable))
        .route("/api/v1/agents/{id}", web::put().to(set_agent_enabled))
        .route("/api/v1/agents/{id}/bundle", web::get().to(agent_bundle))
        .route("/api/v1/agents/{id}/ack", web::post().to(agent_ack))
        .route("/api/v1/dns/status", web::get().to(dns_status))
        .route("/api/v1/servers/{id}/status", web::get().to(server_status))
        .route("/api/v1/metrics/queries", web::get().to(query_metrics));
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn page_query_is_bounded() {
        let default = PageQuery::default().parts();
        assert_eq!(default.0, Some(100));
        assert_eq!(default.1, 0);
        let bounded = PageQuery {
            limit: Some(1000000),
            offset: Some(-5),
            q: None,
            ..Default::default()
        }
        .parts();
        assert_eq!((bounded.0, bounded.1), (Some(1000), 0));
        let tiny = PageQuery {
            limit: Some(0),
            offset: None,
            q: None,
            ..Default::default()
        }
        .parts();
        assert_eq!(tiny.0, Some(1));
    }

    #[test]
    fn page_sort_is_allowlisted_and_direction_is_closed() {
        let allowed = [("name", "name"), ("created", "created_at")];
        let query = PageQuery {
            sort: Some("created".into()),
            order: Some("desc".into()),
            ..Default::default()
        };
        assert_eq!(query.sort_column(&allowed, "name"), Ok("created_at"));
        assert_eq!(query.sort_direction(), Ok("DESC"));

        let bad_column = PageQuery {
            sort: Some("name DESC".into()),
            ..Default::default()
        };
        assert_eq!(bad_column.sort_column(&allowed, "name"), Err(()));
        let bad_direction = PageQuery {
            order: Some("sideways".into()),
            ..Default::default()
        };
        assert_eq!(bad_direction.sort_direction(), Err(()));
    }

    #[test]
    fn cidr_matching() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains("10.200.1.1".parse().unwrap()));
        assert!(!c.contains("11.0.0.1".parse().unwrap()));
        assert!(!c.contains("::1".parse().unwrap()));
        assert!(
            Cidr::parse("192.0.2.7")
                .unwrap()
                .contains("192.0.2.7".parse().unwrap())
        );
        assert!(
            !Cidr::parse("192.0.2.7")
                .unwrap()
                .contains("192.0.2.8".parse().unwrap())
        );
        assert!(
            Cidr::parse("fd00::/8")
                .unwrap()
                .contains("fd12::1".parse().unwrap())
        );
        assert!(
            Cidr::parse("0.0.0.0/0")
                .unwrap()
                .contains("8.8.8.8".parse().unwrap())
        );
        assert!(Cidr::parse("10.0.0.0/33").is_none());
        assert!(Cidr::parse("nope").is_none());
    }

    #[test]
    fn totp_rfc6238_vectors() {
        // RFC 6238 appendix B, SHA1, secret "12345678901234567890"
        let k = b"12345678901234567890";
        assert_eq!(hotp(k, 59 / 30) % 1_000_000, 287082);
        assert_eq!(hotp(k, 1111111109 / 30), 81804);
        assert_eq!(hotp(k, 2000000000 / 30), 279037);
        assert!(totp_verify(k, "287082", 59));
        assert!(
            totp_verify(k, "287082", 59 + 30),
            "one step of drift is tolerated"
        );
        assert!(!totp_verify(k, "287082", 59 + 120));
        assert!(!totp_verify(k, "12345", 59));
        assert!(!totp_verify(k, "abcdef", 59));
    }

    #[test]
    fn bundle_signature_binds_content_and_version() {
        let files = vec![
            ("named.toml".to_string(), "x".to_string()),
            ("zone.a.com".to_string(), "y".to_string()),
        ];
        let h = bundle_hash(&files);
        let k = agent_signing_key("master-secret", "agent-1");
        let sig = sign_bundle(&k, 7, &h, &files);
        assert_eq!(sig, sign_bundle(&k, 7, &h, &files));
        assert_ne!(sig, sign_bundle(&k, 8, &h, &files), "version is signed");
        let mut tampered = files.clone();
        tampered[1].1 = "z".into();
        assert_ne!(sig, sign_bundle(&k, 7, &h, &tampered), "content is signed");
        assert_ne!(
            sig,
            sign_bundle(
                &agent_signing_key("master-secret", "agent-2"),
                7,
                &h,
                &files
            ),
            "key is per agent"
        );
        // framing: moving bytes between name and content changes the signature
        let a = vec![("ab".to_string(), "c".to_string())];
        let b = vec![("a".to_string(), "bc".to_string())];
        assert_ne!(sign_bundle(&k, 1, "h", &a), sign_bundle(&k, 1, "h", &b));
    }

    #[test]
    fn agent_vector() {
        // identical vector is asserted by the agent crate; both must agree on the framing
        let files = vec![
            ("named.toml".to_string(), "x".to_string()),
            ("zone.a.com".to_string(), "y".to_string()),
        ];
        let h = bundle_hash(&files);
        assert_eq!(
            h,
            "f21cd528f1ea6cec069650ce232d115707c5380f25699b0e11f8e43f50971c07"
        );
        assert_eq!(
            sign_bundle("k", 7, &h, &files),
            "7831a7e229049aab306a0414d7fc5dd327dcf16b39d118b196d00e4fa38c3213"
        );
    }

    #[test]
    fn prometheus_text_is_parsed() {
        let t = "# HELP x\nhickory_request_total{protocol=\"udp\"} 12\nhickory_request_total{protocol=\"tcp\"} 3\nother 1.5\nbroken line\n";
        let s = parse_prometheus(t);
        assert_eq!(s.len(), 3);
        assert_eq!(s[0].0, "hickory_request_total");
        assert_eq!(s[2], ("other".to_string(), String::new(), 1.5));
    }
}
