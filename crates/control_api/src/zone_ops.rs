//! Zone operations added for the migration-grade roadmap: BIND import,
//! multi-zone bulk import jobs, RRset batch mutation and extended lifecycle.

use super::*;

pub const MAX_BIND_IMPORT_BYTES: usize = 1024 * 1024;
pub const MAX_BULK_ZONES: usize = 100;
pub const MAX_BULK_RECORDS_PER_ZONE: usize = 5000;

#[derive(Deserialize)]
pub struct BindImportReq {
    pub zone_text: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Deserialize, Serialize)]
pub struct BulkImportReq {
    pub zones: Vec<BulkZone>,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub tenant_id: Option<String>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct BulkZone {
    pub domain: String,
    #[serde(default)]
    pub records: Vec<super::ImportRecordReq>,
}

#[derive(Deserialize)]
pub struct RrsetBatchReq {
    pub rrsets: Vec<RrsetSpec>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Deserialize, Clone)]
pub struct RrsetSpec {
    pub name: String,
    pub record_type: String,
    #[serde(default)]
    pub ttl: Option<u32>,
    pub values: Vec<RrsetValue>,
}

#[derive(Deserialize, Clone)]
pub struct RrsetValue {
    pub value: String,
    #[serde(default)]
    pub priority: Option<i32>,
}

fn relative_name(
    name: &hickory_proto::rr::Name,
    origin: &hickory_proto::rr::Name,
) -> Option<String> {
    let n = name.to_ascii().to_ascii_lowercase();
    let o = origin.to_ascii().to_ascii_lowercase();
    let nb = n.trim_end_matches('.');
    let ob = o.trim_end_matches('.');
    if nb == ob {
        Some("@".to_string())
    } else if let Some(prefix) = nb.strip_suffix(&format!(".{ob}")) {
        Some(prefix.to_string())
    } else {
        None
    }
}

fn first_priority(rtype: &str, value: &str) -> i32 {
    if matches!(rtype, "MX" | "SRV") {
        value
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<i32>().ok())
            .filter(|v| (0..=65535).contains(v))
            .unwrap_or(0)
    } else {
        0
    }
}

/// Parse a BIND-style zone file into API import rows using Hickory's parser so
/// quoted/escaped character strings, `$ORIGIN`, `$TTL`, parentheses and
/// comments behave exactly as they do for served zones.
pub fn parse_bind_zone(
    domain: &str,
    text: &str,
) -> Result<Vec<super::ImportRecordReq>, Vec<serde_json::Value>> {
    use hickory_proto::rr::domain::Name;
    use hickory_proto::serialize::txt::Parser;
    use std::str::FromStr;

    if text.len() > MAX_BIND_IMPORT_BYTES {
        return Err(vec![serde_json::json!({
            "row": 0, "error": format!("zone file exceeds {} bytes", MAX_BIND_IMPORT_BYTES)
        })]);
    }
    let origin = match Name::from_str(&format!("{}.", domain.trim_end_matches('.'))) {
        Ok(n) => n,
        Err(e) => {
            return Err(vec![serde_json::json!({"row": 0, "error": e.to_string()})]);
        }
    };
    let parsed = Parser::new(text.to_string(), None, Some(origin.clone())).parse();
    let (_origin, sets) = match parsed {
        Ok(v) => v,
        Err(e) => {
            return Err(vec![serde_json::json!({
                "row": 0, "error": format!("BIND parse error: {e}")
            })]);
        }
    };
    let mut out = Vec::new();
    let mut errors = Vec::new();
    let mut row = 0usize;
    for (_key, set) in sets {
        for record in set.records_without_rrsigs() {
            row += 1;
            let Some(name) = relative_name(record.name(), &origin) else {
                errors.push(serde_json::json!({
                    "row": row, "name": record.name().to_string(),
                    "error": "record name is outside the zone"
                }));
                continue;
            };
            let rtype = record.record_type().to_string().to_ascii_uppercase();
            let value = record.data().to_string();
            let ttl = record.ttl().max(1);
            out.push(super::ImportRecordReq {
                name,
                record_type: rtype.clone(),
                value: value.clone(),
                ttl: Some(ttl),
                priority: Some(first_priority(&rtype, &value)),
            });
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    if out.is_empty() {
        return Err(vec![serde_json::json!({
            "row": 0, "error": "zone file contains no records"
        })]);
    }
    Ok(out)
}

/// Validate and insert an import into an existing zone. All-or-nothing.
pub async fn import_records(
    data: &AppState,
    zone_id: &str,
    domain: &str,
    user_id: &str,
    request: &HttpRequest,
    records: &[super::ImportRecordReq],
    dry_run: bool,
    reason: &str,
) -> HttpResponse {
    let db = &data.db;
    if records.is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "no records to import"}));
    }
    if records.len() > MAX_BULK_RECORDS_PER_ZONE {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("too many records (maximum {} per import)", MAX_BULK_RECORDS_PER_ZONE)
        }));
    }
    let allowed_ns = match super::allowed_nameservers(db).await {
        Ok(a) => a,
        Err(e) => {
            warn!(
                "import_records nameserver lookup: {}",
                full_error_string(&e)
            );
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    };
    let existing = match zone_file_generator::load_zone_records(db, zone_id).await {
        Ok(r) => r,
        Err(e) => {
            warn!("import_records: {:#}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    };
    let mut has_soa = existing.iter().any(|r| r.rtype.eq_ignore_ascii_case("SOA"));
    let mut candidate = existing;
    let mut fresh: Vec<RecordRow> = Vec::new();
    let mut skipped = 0usize;
    let mut errors: Vec<serde_json::Value> = Vec::new();
    for (index, record) in records.iter().enumerate() {
        let rec = match super::validate_record_input(
            domain,
            &record.name,
            &record.record_type,
            &record.value,
            record.ttl.unwrap_or(3600) as i64,
            record.priority.unwrap_or(0),
        ) {
            Ok(r) => r,
            Err(e) => {
                errors.push(serde_json::json!({"row": index, "name": record.name, "error": e}));
                continue;
            }
        };
        if rec.rtype == "NS" {
            if let Err(e) = super::validate_ns_value(&rec.value, &allowed_ns) {
                errors.push(
                    serde_json::json!({"row": index, "name": record.name, "error": e.message}),
                );
                continue;
            }
        }
        if rec.rtype == "SOA" {
            if has_soa {
                errors.push(serde_json::json!({
                    "row": index, "name": record.name, "error": "zone already has an SOA record"
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
    if let Err(e) = super::precheck_zone_change(db, domain, candidate).await {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Import validation failed",
            "details": format!("Hickory zone parser validation failed: {}", e)
        }));
    }
    if dry_run {
        return HttpResponse::Ok().json(serde_json::json!({
            "dry_run": true, "zone_id": zone_id, "would_import": fresh.len(),
            "skipped": skipped, "errors": [],
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
    let tx = match db.begin().await {
        Ok(t) => t,
        Err(e) => {
            warn!("import_records transaction: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    };
    let c = tx.client();
    if let Err(e) = c.batch_execute("BEGIN").await {
        warn!("import_records begin: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "database error"}));
    }
    if let Err(resp) =
        tenants::reserve_zone_records_quota_tx(c, zone_id, fresh.len() as i64, false).await
    {
        let _ = c.batch_execute("ROLLBACK").await;
        return resp;
    }
    if let Err(e) = c.execute(
        "INSERT INTO records (id, zone_id, name, record_type, value, ttl, priority) \
         SELECT u.id::uuid, $1::text::uuid, u.n, u.t, u.v, u.ttl, u.p \
         FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::int4[], $7::int4[]) AS u(id, n, t, v, ttl, p)",
        &[&zone_id, &ids, &names, &types, &values, &ttls, &prios]
    ).await {
        let _ = c.batch_execute("ROLLBACK").await;
        warn!("failed to import records: {}", full_error_string(&e));
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Import failed",
            "details": "Database error while importing; no records were imported"
        }));
    }
    if let Err(e) = c.batch_execute("COMMIT").await {
        warn!("import_records commit failed: {}", full_error_string(&e));
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Import failed",
            "details": "Database error while importing; no records were imported"
        }));
    }
    drop(tx);
    let imported = fresh.len();
    if let Err(e) = super::publish(&data.dns_manager, db, Some(domain)).await {
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
            "saved": false, "published": false
        }));
    }
    ext::snapshot_zone(db, zone_id, Some(user_id), reason).await;
    audit(
        db,
        Some(user_id),
        "import_zone",
        "zone",
        Some(zone_id.to_string()),
        request,
        serde_json::json!({"zone": domain, "imported": imported, "skipped": skipped, "source": reason}),
    )
    .await;
    let _ = automation::dispatch_event(
        db,
        "zone.imported",
        "zone",
        Some(zone_id),
        &serde_json::json!({"zone": domain, "imported": imported, "skipped": skipped}),
    )
    .await;
    HttpResponse::Ok().json(serde_json::json!({
        "imported": imported, "skipped": skipped, "zone_id": zone_id,
        "message": format!("Successfully imported {} records", imported)
    }))
}

pub async fn import_bind(
    path: web::Path<String>,
    body: web::Json<BindImportReq>,
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
    let records = match parse_bind_zone(&access.domain, &body.zone_text) {
        Ok(r) => r,
        Err(errors) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "BIND import validation failed",
                "errors": errors,
            }));
        }
    };
    import_records(
        &data,
        &zone_id,
        &access.domain,
        &tok.claims.sub,
        &req,
        &records,
        body.dry_run,
        "bind import",
    )
    .await
}

pub async fn bulk_import(
    body: web::Json<BulkImportReq>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return unauthorized(),
    };
    if body.zones.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "no zones supplied"}));
    }
    if body.zones.len() > MAX_BULK_ZONES {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("at most {} zones per bulk import", MAX_BULK_ZONES)
        }));
    }
    let mut total_records = 0usize;
    for z in &body.zones {
        if z.records.len() > MAX_BULK_RECORDS_PER_ZONE {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("zone {} exceeds {} records", z.domain, MAX_BULK_RECORDS_PER_ZONE)
            }));
        }
        total_records += z.records.len();
    }
    if total_records > 100_000 {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "at most 100000 records per bulk import"}));
    }
    if body.dry_run {
        let preview = dry_run_bulk(&data, &tok, &body).await;
        return match preview {
            Ok(v) => HttpResponse::Ok().json(v),
            Err(r) => r,
        };
    }
    let job_id = Uuid::new_v4().to_string();
    let input = match serde_json::to_value(&body.0) {
        Ok(v) => v,
        Err(e) => {
            return HttpResponse::BadRequest().json(serde_json::json!({"error": e.to_string()}));
        }
    };
    if let Err(e) = data
        .db
        .execute(
            "INSERT INTO jobs (id, user_id, kind, total, input) \
             VALUES ($1::text::uuid, $2::text::uuid, 'bulk_import', $3, $4)",
            &[&job_id, &tok.claims.sub, &(body.zones.len() as i32), &input],
        )
        .await
    {
        warn!("bulk_import job: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "database error"}));
    }
    audit(
        &data.db,
        Some(&tok.claims.sub),
        "bulk_import",
        "job",
        Some(job_id.clone()),
        &req,
        serde_json::json!({"zones": body.zones.len(), "records": total_records}),
    )
    .await;
    HttpResponse::Accepted().json(serde_json::json!({
        "job_id": job_id,
        "status": "queued",
        "zones": body.zones.len(),
        "records": total_records,
        "poll": format!("/api/v1/jobs/{}", job_id),
    }))
}

async fn dry_run_bulk(
    data: &AppState,
    tok: &TokenData<Claims>,
    body: &BulkImportReq,
) -> Result<serde_json::Value, HttpResponse> {
    let mut zones = Vec::new();
    let mut ok = true;
    for z in &body.zones {
        let domain = match normalize_zone_domain(&z.domain) {
            Ok(d) => d,
            Err(e) => {
                ok = false;
                zones.push(
                    serde_json::json!({"domain": z.domain, "valid": false, "error": e.message}),
                );
                continue;
            }
        };
        if tok.claims.role != "admin" {
            match zone_overlaps_other_owner(&data.db, &domain, &tok.claims.sub, None).await {
                Ok(true) => {
                    ok = false;
                    zones.push(serde_json::json!({
                        "domain": domain, "valid": false, "error": "domain overlaps another zone"
                    }));
                    continue;
                }
                Ok(false) => {}
                Err(e) => {
                    warn!("bulk dry run: {}", full_error_string(&e));
                    return Err(HttpResponse::InternalServerError()
                        .json(serde_json::json!({"error": "database error"})));
                }
            }
        }
        let mut errors = Vec::new();
        for (i, r) in z.records.iter().enumerate() {
            if let Err(e) = validate_record_input(
                &domain,
                &r.name,
                &r.record_type,
                &r.value,
                r.ttl.unwrap_or(3600) as i64,
                r.priority.unwrap_or(0),
            ) {
                errors.push(serde_json::json!({"row": i, "name": r.name, "error": e}));
            }
        }
        if !errors.is_empty() {
            ok = false;
        }
        zones.push(serde_json::json!({
            "domain": domain, "valid": errors.is_empty(),
            "records": z.records.len(), "errors": errors
        }));
    }
    Ok(serde_json::json!({"dry_run": true, "valid": ok, "zones": zones}))
}

/// Execute a queued bulk import. Called by the durable job worker.
pub async fn run_bulk_import_job(
    state: &AppState,
    job_id: &str,
    user_id: &str,
    input: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let input = input.ok_or("job has no input")?;
    let req: BulkImportReq = serde_json::from_value(input).map_err(|e| e.to_string())?;
    let role: String = state
        .db
        .query_opt(
            "SELECT role FROM users WHERE CAST(id AS varchar) = $1",
            &[&user_id],
        )
        .await
        .map_err(|e| full_error_string(&e))?
        .map(|r| r.get(0))
        .unwrap_or_else(|| "user".to_string());
    let is_admin = role == "admin";
    let mut results = Vec::new();
    let total = req.zones.len();
    for (index, z) in req.zones.iter().enumerate() {
        if automation::job_status(&state.db, job_id).await.as_deref() == Some("cancelled") {
            return Ok(serde_json::json!({"cancelled": true, "results": results}));
        }
        let result = import_one_zone(state, user_id, is_admin, z, req.tenant_id.as_deref()).await;
        results.push(match result {
            Ok(v) => v,
            Err(e) => serde_json::json!({"domain": z.domain, "status": "failed", "error": e}),
        });
        automation::job_progress(&state.db, job_id, (index + 1) as i32).await;
    }
    let succeeded = results
        .iter()
        .filter(|v| v["status"] == "created" || v["status"] == "updated")
        .count();
    let _ = total;
    Ok(serde_json::json!({
        "zones_total": results.len(),
        "zones_succeeded": succeeded,
        "zones_failed": results.len() - succeeded,
        "results": results,
    }))
}

async fn import_one_zone(
    state: &AppState,
    user_id: &str,
    is_admin: bool,
    z: &BulkZone,
    tenant_id: Option<&str>,
) -> Result<serde_json::Value, String> {
    let db = &state.db;
    let domain = normalize_zone_domain(&z.domain).map_err(|e| e.message)?;
    if !is_admin {
        if zone_overlaps_other_owner(db, &domain, user_id, None)
            .await
            .map_err(|e| full_error_string(&e))?
        {
            return Err("domain overlaps a zone owned by another user".into());
        }
    }
    let existing = db
        .query_opt(
            "SELECT CAST(id AS varchar) FROM zones WHERE domain = $1",
            &[&domain],
        )
        .await
        .map_err(|e| full_error_string(&e))?;
    if let Some(row) = existing {
        let zone_id: String = row.get(0);
        let access = zone_access_at(
            db,
            &zone_id,
            &TokenData {
                header: Header::default(),
                claims: Claims {
                    sub: user_id.to_string(),
                    role: if is_admin {
                        "admin".into()
                    } else {
                        "user".into()
                    },
                    exp: 0,
                    ver: 0,
                },
            },
            Level::Write,
        )
        .await
        .map_err(|_| "access denied to existing zone".to_string())?;
        let existing_rows = zone_file_generator::load_zone_records(db, &zone_id)
            .await
            .map_err(|e| format!("{:#}", e))?;
        let mut candidate = existing_rows;
        let mut fresh = Vec::new();
        let mut skipped = 0usize;
        for r in &z.records {
            let rec = validate_record_input(
                &domain,
                &r.name,
                &r.record_type,
                &r.value,
                r.ttl.unwrap_or(3600) as i64,
                r.priority.unwrap_or(0),
            )?;
            if candidate.iter().any(|e| {
                e.name.eq_ignore_ascii_case(&rec.name)
                    && e.rtype.eq_ignore_ascii_case(&rec.rtype)
                    && e.value.trim() == rec.value
            }) {
                skipped += 1;
                continue;
            }
            candidate.push(rec.clone());
            fresh.push(rec);
        }
        precheck_zone_change(db, &access.domain, candidate).await?;
        if !fresh.is_empty() {
            let ids: Vec<String> = fresh.iter().map(|_| Uuid::new_v4().to_string()).collect();
            let names: Vec<String> = fresh.iter().map(|r| r.name.clone()).collect();
            let types: Vec<String> = fresh.iter().map(|r| r.rtype.clone()).collect();
            let values: Vec<String> = fresh.iter().map(|r| r.value.clone()).collect();
            let ttls: Vec<i32> = fresh.iter().map(|r| r.ttl).collect();
            let prios: Vec<i32> = fresh.iter().map(|r| r.priority).collect();
            db.execute(
                "INSERT INTO records (id, zone_id, name, record_type, value, ttl, priority) \
                 SELECT u.id::uuid, $1::text::uuid, u.n, u.t, u.v, u.ttl, u.p \
                 FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::int4[], $7::int4[]) AS u(id, n, t, v, ttl, p)",
                &[&zone_id, &ids, &names, &types, &values, &ttls, &prios],
            )
            .await
            .map_err(|e| full_error_string(&e))?;
            if let Err(e) = publish(&state.dns_manager, db, Some(&domain)).await {
                let _ = db
                    .execute(
                        "DELETE FROM records WHERE CAST(id AS varchar) = ANY($1::text[])",
                        &[&ids],
                    )
                    .await;
                return Err(format!("publication failed: {e}"));
            }
        }
        return Ok(serde_json::json!({
            "domain": domain, "zone_id": zone_id, "status": "updated",
            "imported": fresh.len(), "skipped": skipped
        }));
    }

    // Create a new zone. Tenant selection mirrors POST /zones.
    let zone_tenant: Option<String> = if is_admin {
        tenant_id.map(str::to_string).filter(|t| !t.is_empty())
    } else {
        Some(
            tenants::tenant_for_user(db, user_id, tenant_id, true)
                .await
                .map_err(|_| "tenant access denied".to_string())?,
        )
    };
    let mut rows = Vec::new();
    for r in &z.records {
        rows.push(validate_record_input(
            &domain,
            &r.name,
            &r.record_type,
            &r.value,
            r.ttl.unwrap_or(3600) as i64,
            r.priority.unwrap_or(0),
        )?);
    }
    precheck_zone_change(db, &domain, rows.clone()).await?;
    let zone_id = Uuid::new_v4().to_string();
    let status = "active";
    let tx = db.begin().await.map_err(|e| full_error_string(&e))?;
    let c = tx.client();
    c.batch_execute("BEGIN")
        .await
        .map_err(|e| full_error_string(&e))?;
    if let (Some(t), false) = (&zone_tenant, is_admin) {
        let quota_status = tenants::reserve_quota_tx(c, t, 1, rows.len() as i64)
            .await
            .err()
            .map(|r| r.status());
        if let Some(status) = quota_status {
            let _ = c.batch_execute("ROLLBACK").await;
            return Err(format!("tenant quota exceeded (HTTP {})", status.as_u16()));
        }
    }
    c.execute(
        "INSERT INTO zones (id, domain, owner, status, tenant_id) VALUES ($1::text::uuid, $2, $3::text::uuid, $4, $5::text::uuid)",
        &[&zone_id, &domain, &user_id, &status, &zone_tenant],
    )
    .await
    .map_err(|e| full_error_string(&e))?;
    if !rows.is_empty() {
        let ids: Vec<String> = rows.iter().map(|_| Uuid::new_v4().to_string()).collect();
        let names: Vec<String> = rows.iter().map(|r| r.name.clone()).collect();
        let types: Vec<String> = rows.iter().map(|r| r.rtype.clone()).collect();
        let values: Vec<String> = rows.iter().map(|r| r.value.clone()).collect();
        let ttls: Vec<i32> = rows.iter().map(|r| r.ttl).collect();
        let prios: Vec<i32> = rows.iter().map(|r| r.priority).collect();
        c.execute(
            "INSERT INTO records (id, zone_id, name, record_type, value, ttl, priority) \
             SELECT u.id::uuid, $1::text::uuid, u.n, u.t, u.v, u.ttl, u.p \
             FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::int4[], $7::int4[]) AS u(id, n, t, v, ttl, p)",
            &[&zone_id, &ids, &names, &types, &values, &ttls, &prios],
        )
        .await
        .map_err(|e| full_error_string(&e))?;
    }
    c.batch_execute("COMMIT")
        .await
        .map_err(|e| full_error_string(&e))?;
    drop(tx);
    if let Err(e) = publish(&state.dns_manager, db, Some(&domain)).await {
        let _ = db
            .execute(
                "DELETE FROM zones WHERE CAST(id AS varchar) = $1",
                &[&zone_id],
            )
            .await;
        return Err(format!("publication failed: {e}"));
    }
    ext::snapshot_zone(db, &zone_id, Some(user_id), "bulk import").await;
    Ok(serde_json::json!({
        "domain": domain, "zone_id": zone_id, "status": "created", "imported": rows.len()
    }))
}

// ---------------------------------------------------------------------------
// RRset batch mutation
// ---------------------------------------------------------------------------

pub async fn batch_rrsets(
    path: web::Path<String>,
    body: web::Json<RrsetBatchReq>,
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
    if body.rrsets.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "no rrsets supplied"}));
    }
    if body.rrsets.len() > 1000 {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "at most 1000 rrsets per request"}));
    }
    let existing = match zone_file_generator::load_zone_records(&data.db, &zone_id).await {
        Ok(r) => r,
        Err(e) => {
            warn!("batch_rrsets: {:#}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    };
    // Validate the whole batch before touching the database.
    let mut errors = Vec::new();
    let mut replace: Vec<(String, String)> = Vec::new();
    let mut new_rows: Vec<RecordRow> = Vec::new();
    for (i, spec) in body.rrsets.iter().enumerate() {
        let rtype = spec.record_type.trim().to_ascii_uppercase();
        if let Err(e) = validate_record_type_str(&rtype) {
            errors.push(serde_json::json!({"rrset": i, "error": e}));
            continue;
        }
        if spec.values.is_empty() {
            errors.push(
                serde_json::json!({"rrset": i, "error": "an RRset must have at least one value"}),
            );
            continue;
        }
        if spec.values.len() > 500 {
            errors.push(serde_json::json!({"rrset": i, "error": "at most 500 values per RRset"}));
            continue;
        }
        let name = spec.name.trim().to_string();
        if let Err(e) = validate_record_in_zone(&name, &access.domain) {
            errors.push(serde_json::json!({"rrset": i, "error": e.message}));
            continue;
        }
        let key = (name.to_ascii_lowercase(), rtype.clone());
        if replace.contains(&key) {
            errors.push(serde_json::json!({"rrset": i, "error": "duplicate RRset in request"}));
            continue;
        }
        replace.push(key);
        let ttl = spec.ttl.unwrap_or(3600);
        for (j, v) in spec.values.iter().enumerate() {
            match validate_record_input(
                &access.domain,
                &name,
                &rtype,
                &v.value,
                ttl as i64,
                v.priority.unwrap_or(0),
            ) {
                Ok(r) => new_rows.push(r),
                Err(e) => errors.push(serde_json::json!({"rrset": i, "value": j, "error": e})),
            }
        }
    }
    if !errors.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "RRset validation failed", "errors": errors
        }));
    }
    let mut candidate: Vec<RecordRow> = existing
        .iter()
        .filter(|r| {
            !replace
                .iter()
                .any(|(n, t)| r.name.eq_ignore_ascii_case(n) && r.rtype.eq_ignore_ascii_case(t))
        })
        .cloned()
        .collect();
    let removed = existing.len() - candidate.len();
    candidate.extend(new_rows.iter().cloned());
    if let Err(e) = precheck_zone_change(&data.db, &access.domain, candidate).await {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "RRset validation failed", "details": e}));
    }
    if body.dry_run {
        return HttpResponse::Ok().json(serde_json::json!({
            "dry_run": true,
            "rrsets": body.rrsets.len(),
            "records_removed": removed,
            "records_added": new_rows.len(),
        }));
    }
    let old: Vec<RecordRow> = existing
        .iter()
        .filter(|r| {
            replace
                .iter()
                .any(|(n, t)| r.name.eq_ignore_ascii_case(n) && r.rtype.eq_ignore_ascii_case(t))
        })
        .cloned()
        .collect();
    let tx = match data.db.begin().await {
        Ok(t) => t,
        Err(e) => {
            warn!("batch_rrsets transaction: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    };
    let c = tx.client();
    if let Err(e) = c.batch_execute("BEGIN").await {
        warn!("batch_rrsets begin: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "database error"}));
    }
    for (name, rtype) in &replace {
        if let Err(e) = c
            .execute(
                "DELETE FROM records WHERE CAST(zone_id AS varchar) = $1 AND lower(name) = lower($2) AND record_type = $3",
                &[&zone_id, name, rtype],
            )
            .await
        {
            let _ = c.batch_execute("ROLLBACK").await;
            warn!("batch_rrsets delete: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    }
    if !new_rows.is_empty() {
        let ids: Vec<String> = new_rows
            .iter()
            .map(|_| Uuid::new_v4().to_string())
            .collect();
        let names: Vec<String> = new_rows.iter().map(|r| r.name.clone()).collect();
        let types: Vec<String> = new_rows.iter().map(|r| r.rtype.clone()).collect();
        let values: Vec<String> = new_rows.iter().map(|r| r.value.clone()).collect();
        let ttls: Vec<i32> = new_rows.iter().map(|r| r.ttl).collect();
        let prios: Vec<i32> = new_rows.iter().map(|r| r.priority).collect();
        if let Err(e) = c.execute(
            "INSERT INTO records (id, zone_id, name, record_type, value, ttl, priority) \
             SELECT u.id::uuid, $1::text::uuid, u.n, u.t, u.v, u.ttl, u.p \
             FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::int4[], $7::int4[]) AS u(id, n, t, v, ttl, p)",
            &[&zone_id, &ids, &names, &types, &values, &ttls, &prios],
        ).await {
            let _ = c.batch_execute("ROLLBACK").await;
            warn!("batch_rrsets insert: {}", full_error_string(&e));
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "database error"}));
        }
    }
    if let Err(e) = c.batch_execute("COMMIT").await {
        warn!("batch_rrsets commit: {}", full_error_string(&e));
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "database error"}));
    }
    drop(tx);
    if let Err(e) = publish(&data.dns_manager, &data.db, Some(&access.domain)).await {
        // Restore the previous rows.
        let tx = data.db.begin().await.ok();
        if let Some(tx) = tx {
            let c = tx.client();
            let _ = c.batch_execute("BEGIN").await;
            for (name, rtype) in &replace {
                let _ = c
                    .execute(
                        "DELETE FROM records WHERE CAST(zone_id AS varchar) = $1 AND lower(name) = lower($2) AND record_type = $3",
                        &[&zone_id, name, rtype],
                    )
                    .await;
            }
            if !old.is_empty() {
                let ids: Vec<String> = old.iter().map(|_| Uuid::new_v4().to_string()).collect();
                let names: Vec<String> = old.iter().map(|r| r.name.clone()).collect();
                let types: Vec<String> = old.iter().map(|r| r.rtype.clone()).collect();
                let values: Vec<String> = old.iter().map(|r| r.value.clone()).collect();
                let ttls: Vec<i32> = old.iter().map(|r| r.ttl).collect();
                let prios: Vec<i32> = old.iter().map(|r| r.priority).collect();
                let _ = c.execute(
                    "INSERT INTO records (id, zone_id, name, record_type, value, ttl, priority) \
                     SELECT u.id::uuid, $1::text::uuid, u.n, u.t, u.v, u.ttl, u.p \
                     FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::int4[], $7::int4[]) AS u(id, n, t, v, ttl, p)",
                    &[&zone_id, &ids, &names, &types, &values, &ttls, &prios],
                ).await;
            }
            let _ = c.batch_execute("COMMIT").await;
        }
        let _ = publish(&data.dns_manager, &data.db, Some(&access.domain)).await;
        return publish_failed_rolled_back(&e);
    }
    ext::snapshot_zone(&data.db, &zone_id, Some(&tok.claims.sub), "rrset batch").await;
    audit(
        &data.db,
        Some(&tok.claims.sub),
        "batch_rrsets",
        "zone",
        Some(zone_id.clone()),
        &req,
        serde_json::json!({"zone": access.domain, "rrsets": body.rrsets.len(), "added": new_rows.len(), "removed": removed}),
    )
    .await;
    let _ = automation::dispatch_event(
        &data.db,
        "zone.records_changed",
        "zone",
        Some(&zone_id),
        &serde_json::json!({"zone": access.domain, "rrsets": body.rrsets.len()}),
    )
    .await;
    HttpResponse::Ok().json(serde_json::json!({
        "rrsets": body.rrsets.len(),
        "records_added": new_rows.len(),
        "records_removed": removed,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_parser_handles_quoted_txt_and_relative_names() {
        let text = r#"
$ORIGIN example.com.
$TTL 300
@ IN SOA ns1.example.com. hostmaster.example.com. (
  2026010101 3600 600 604800 300 )
@ IN NS ns1.example.com.
www 300 IN A 192.0.2.10
txt 300 IN TXT "hello \"world\"" "second"
"#;
        let rows = parse_bind_zone("example.com", text).expect("parse");
        assert!(rows.iter().any(|r| r.name == "www" && r.record_type == "A"));
        let txt = rows.iter().find(|r| r.record_type == "TXT").unwrap();
        assert!(txt.value.contains("hello"));
        assert!(rows.iter().any(|r| r.name == "@" && r.record_type == "SOA"));
    }

    #[test]
    fn bind_parser_rejects_records_outside_the_zone() {
        let text = "evil.other.org. 300 IN A 192.0.2.1\n";
        assert!(parse_bind_zone("example.com", text).is_err());
    }
}
