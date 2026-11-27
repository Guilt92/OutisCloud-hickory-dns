//! End-to-end tests of the HTTP API against a real PostgreSQL and real zone
//! files on disk.
//!
//! They need a database: set `TEST_DATABASE_URL` (for example
//! `postgres://postgres:pw@127.0.0.1:5432/postgres`). Every test works in its
//! own throw-away schema. Without the variable the tests print `SKIPPED` and
//! return, they do **not** exercise anything.

use super::*;
use actix_web::{App, dev::Service, test};

struct Env {
    state: AppState,
    full: FullState,
    dir: tempfile::TempDir,
    schema: String,
    admin: String,
}

async fn setup() -> Option<Env> {
    let url = match std::env::var("TEST_DATABASE_URL") {
        Ok(u) => u,
        Err(_) => {
            eprintln!("SKIPPED: TEST_DATABASE_URL not set");
            return None;
        }
    };
    let schema = format!("t_{}", Uuid::new_v4().simple());
    {
        let (c, conn) = tokio_postgres::connect(&url, NoTls)
            .await
            .expect("connect test db");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        c.batch_execute(&format!("CREATE SCHEMA {}", schema))
            .await
            .unwrap();
    }
    // every pooled connection uses the isolated schema
    let client = Pool::connect(&url, 4, Some(&schema)).await.expect("pool");
    migrate_db(&client).await.expect("migrate");
    let dir = tempfile::tempdir().unwrap();
    let state = AppState {
        db: client.clone(),
        jwt_secret: "unit-test-secret-unit-test-secret-1234".to_string(),
        agent_signing_secret: "agent-test-secret-agent-test-secret-1234".to_string(),
        dns_manager: Arc::new(DnsManager::new(dir.path().to_string_lossy().to_string())),
        verify_resolver: "127.0.0.1:9".parse().unwrap(),
        verify_domains: false,
        dns_metrics_url: None,
        lookup_resolvers: vec![],
    };
    let geo = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/dns/GeoLite2-Country.mmdb"
    ))
    .ok()
    .and_then(|b| geodns::GeoDB::open_from_bytes(b).ok());
    let full = FullState {
        inner: state.clone(),
        geo: Arc::new(tokio::sync::Mutex::new(GeoState { db: geo })),
        processes: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
    };
    let admin = add_user(&state, "root", "root-password-1", "admin").await;
    Some(Env {
        state,
        full,
        dir,
        schema,
        admin,
    })
}

#[actix_web::test]
async fn publication_outbox_persists_retries_and_serializes_concurrent_workers() {
    let Some(env) = setup().await else { return };
    let domain = "outbox.example";
    env.state.db.execute(
        "INSERT INTO publication_outbox(zone_domain, attempts, next_attempt, last_error) VALUES($1,0,now(),'first failure') ON CONFLICT(zone_domain) DO UPDATE SET attempts=0,next_attempt=now(),last_error=EXCLUDED.last_error",
        &[&domain],
    ).await.unwrap();

    // A duplicate enqueue coalesces to the latest desired committed zone state.
    env.state.db.execute(
        "INSERT INTO publication_outbox(zone_domain, attempts, next_attempt, last_error) VALUES($1,0,now(),'second failure') ON CONFLICT(zone_domain) DO UPDATE SET attempts=0,next_attempt=now(),last_error=EXCLUDED.last_error",
        &[&domain],
    ).await.unwrap();
    let row = env
        .state
        .db
        .query_one(
            "SELECT attempts,status,last_error FROM publication_outbox WHERE zone_domain=$1",
            &[&domain],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i32>(0), 0);
    assert_eq!(row.get::<_, String>(1), "pending");
    assert_eq!(row.get::<_, String>(2), "second failure");

    // Separate pooled connections emulate competing workers. SKIP LOCKED in the
    // claim/update statement allows only one to obtain this due zone job.
    let claim = |db: Arc<Pool>| async move {
        db.query("WITH due AS (SELECT zone_domain FROM publication_outbox WHERE status='pending' AND next_attempt <= now() ORDER BY next_attempt FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE publication_outbox o SET attempts=o.attempts+1,next_attempt=now()+interval '1 minute' FROM due WHERE o.zone_domain=due.zone_domain RETURNING o.zone_domain", &[]).await.unwrap()
    };
    let (left, right) = tokio::join!(claim(env.state.db.clone()), claim(env.state.db.clone()));
    assert_eq!(left.len() + right.len(), 1);

    // A rolled-back record value is never carried by an outbox job. The job
    // contains only the zone key and retry metadata.
    let columns = env.state.db.query("SELECT column_name FROM information_schema.columns WHERE table_schema=$1 AND table_name='publication_outbox'", &[&env.schema]).await.unwrap();
    assert!(
        columns
            .iter()
            .any(|row| row.get::<_, String>(0) == "zone_domain")
    );
    assert!(
        !columns
            .iter()
            .any(|row| row.get::<_, String>(0).contains("record_value"))
    );
    env.cleanup().await;
}

#[actix_web::test]
async fn serializable_transactions_retry_only_retryable_database_conflicts() {
    let Some(env) = setup().await else { return };
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = attempts.clone();
    let value = env
        .state
        .db
        .run_transaction(3, move |client| {
            let attempt = seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move {
                if attempt == 0 {
                    client
                        .batch_execute(
                            "DO $$ BEGIN RAISE EXCEPTION 'retry test' USING ERRCODE='40001'; END $$",
                        )
                        .await?;
                }
                let row = client.query_one("SELECT 42::integer", &[]).await?;
                Ok(row.get::<_, i32>(0))
            }
        })
        .await
        .expect("serialization failure retries and commits the next attempt");
    assert_eq!(value, 42);
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 2);

    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = attempts.clone();
    let result = env
        .state
        .db
        .run_transaction(4, move |client| {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move { client.batch_execute("SELECT 1/0").await }
        })
        .await;
    assert!(result.is_err());
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);

    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = attempts.clone();
    let result = env
        .state
        .db
        .run_transaction(2, move |client| {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move {
                client
                    .batch_execute(
                        "DO $$ BEGIN RAISE EXCEPTION 'bounded retry test' USING ERRCODE='40001'; END $$",
                    )
                    .await
            }
        })
        .await;
    assert!(result.is_err());
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 2);
    env.cleanup().await;
}

#[actix_web::test]
async fn tenant_transaction_gate_isolates_bursts_without_blocking_other_tenants() {
    let Some(env) = setup().await else { return };
    let first = env.state.db.begin_for("tenant-a").await.unwrap();
    let pool = env.state.db.clone();
    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    let queued = tokio::spawn(async move {
        let _ = started_tx.send(());
        pool.begin_for("tenant-a").await.unwrap()
    });
    let mut queued = Box::pin(queued);
    started_rx.recv().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    // A different tenant can still claim a separate session while tenant A's
    // second request waits behind its first transaction.
    let other_tenant = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        env.state.db.begin_for("tenant-b"),
    )
    .await
    .expect("tenant B must not wait for tenant A")
    .unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(25), &mut queued)
            .await
            .is_err()
    );

    drop(first);
    let second = tokio::time::timeout(std::time::Duration::from_secs(1), &mut queued)
        .await
        .expect("tenant A proceeds after its current transaction releases")
        .unwrap();
    drop(other_tenant);
    drop(second);
    env.cleanup().await;
}

#[actix_web::test]
async fn failed_publication_retries_latest_database_state_after_restart() {
    let Some(env) = setup().await else { return };
    let zone_id = Uuid::new_v4().to_string();
    env.state
        .db
        .execute(
            "INSERT INTO zones(id,domain) VALUES($1::text::uuid,$2)",
            &[&zone_id, &"retry-state.example"],
        )
        .await
        .unwrap();
    env.state.db.execute(
        "INSERT INTO records(id,zone_id,name,record_type,value,ttl) VALUES($1::text::uuid,$2::text::uuid,'www','A','192.0.2.10',300)",
        &[&Uuid::new_v4().to_string(), &zone_id],
    ).await.unwrap();
    publish_current(
        &env.state.dns_manager,
        &env.state.db,
        Some("retry-state.example"),
    )
    .await
    .unwrap();
    let original = std::fs::read_to_string(env.zone_file("retry-state.example")).unwrap();
    assert!(original.contains("192.0.2.10"));

    let obstructed_path = env.dir.path().join("not-a-directory");
    std::fs::write(&obstructed_path, "block mkdir").unwrap();
    let failing_dns = DnsManager::new(obstructed_path.to_string_lossy().to_string());
    let error = publish(&failing_dns, &env.state.db, Some("retry-state.example"))
        .await
        .unwrap_err();
    assert!(!error.is_empty());
    let queued = env
        .state
        .db
        .query_one(
            "SELECT status,attempts FROM publication_outbox WHERE zone_domain=$1",
            &[&"retry-state.example"],
        )
        .await
        .unwrap();
    assert_eq!(queued.get::<_, String>(0), "pending");
    assert_eq!(queued.get::<_, i32>(1), 0);
    assert_eq!(
        std::fs::read_to_string(env.zone_file("retry-state.example")).unwrap(),
        original
    );

    let tx = env.state.db.begin().await.unwrap();
    tx.client().batch_execute("BEGIN").await.unwrap();
    let updated = tx
        .client()
        .execute(
            "UPDATE records SET value='192.0.2.99' WHERE zone_id=$1::text::uuid",
            &[&zone_id],
        )
        .await
        .unwrap();
    assert_eq!(updated, 1);
    tx.client().batch_execute("ROLLBACK").await.unwrap();
    drop(tx);

    // Run the retry worker in a separate test process after the enqueueing
    // process has persisted the job and exited. The child gets only the
    // isolated schema and zone directory, not a mutation payload.
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "--ignored",
            "api_tests::publication_worker_restart_child_claims_persisted_job",
            "--nocapture",
        ])
        .env("PUBLICATION_RESTART_SCHEMA", &env.schema)
        .env("PUBLICATION_RESTART_ZONE_DIR", env.dir.path())
        .output()
        .expect("start a fresh process for durable publication recovery");
    assert!(
        child.status.success(),
        "restart worker failed:\n{}\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    assert!(
        String::from_utf8_lossy(&child.stdout)
            .contains("publication_worker_restart_child_claims_persisted_job ... ok"),
        "the new process must actually execute its worker test:\n{}",
        String::from_utf8_lossy(&child.stdout)
    );
    let latest = std::fs::read_to_string(env.zone_file("retry-state.example")).unwrap();
    assert!(latest.contains("192.0.2.10"));
    assert!(!latest.contains("192.0.2.99"));
    env.state
        .db
        .execute(
            "DELETE FROM publication_outbox WHERE zone_domain=$1",
            &[&"retry-state.example"],
        )
        .await
        .unwrap();
    let remaining = env
        .state
        .db
        .query(
            "SELECT 1 FROM publication_outbox WHERE zone_domain=$1",
            &[&"retry-state.example"],
        )
        .await
        .unwrap();
    assert!(remaining.is_empty());
    env.cleanup().await;
}

#[actix_web::test]
#[ignore = "launched as a separate process by failed_publication_retries_latest_database_state_after_restart"]
async fn publication_worker_restart_child_claims_persisted_job() {
    let schema = std::env::var("PUBLICATION_RESTART_SCHEMA")
        .expect("restart child requires its isolated schema");
    let zone_dir = std::env::var("PUBLICATION_RESTART_ZONE_DIR")
        .expect("restart child requires its isolated zone directory");
    let url = std::env::var("TEST_DATABASE_URL").expect("restart child requires TEST_DATABASE_URL");
    let pool = Pool::connect(&url, 2, Some(&schema))
        .await
        .expect("connect restarted worker to the persisted schema");
    let dns = DnsManager::new(zone_dir);
    assert!(
        publication_retry_once(&dns, &pool)
            .await
            .expect("restarted publication worker claims and publishes the durable job")
    );
}

#[actix_web::test]
async fn publication_worker_recovers_persisted_jobs_and_stops_after_ten_attempts() {
    let Some(env) = setup().await else { return };
    let domain = "worker-restart.example";
    env.state
        .db
        .execute(
            "INSERT INTO zones(id,domain) VALUES($1::text::uuid,$2)",
            &[&Uuid::new_v4().to_string(), &domain],
        )
        .await
        .unwrap();
    env.state.db.execute(
        "INSERT INTO publication_outbox(zone_domain,attempts,next_attempt,last_error) VALUES($1,0,now(),'restart test')",
        &[&domain],
    ).await.unwrap();

    // A newly-created pool represents a worker process starting after the
    // enqueueing process has exited; the persisted due row remains claimable.
    let restarted = Pool::connect(
        &std::env::var("TEST_DATABASE_URL").unwrap(),
        2,
        Some(&env.schema),
    )
    .await
    .unwrap();
    let bad_dir = env.dir.path().join("worker-not-a-directory");
    std::fs::write(&bad_dir, "block mkdir").unwrap();
    let bad_dns = DnsManager::new(bad_dir.to_string_lossy().to_string());
    assert!(publication_retry_once(&bad_dns, &restarted).await.unwrap());
    let row = restarted
        .query_one(
            "SELECT attempts,status,last_error FROM publication_outbox WHERE zone_domain=$1",
            &[&domain],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i32>(0), 1);
    assert_eq!(row.get::<_, String>(1), "pending");
    assert!(!row.get::<_, String>(2).is_empty());

    restarted.execute(
        "UPDATE publication_outbox SET attempts=9,next_attempt=now(),status='pending' WHERE zone_domain=$1",
        &[&domain],
    ).await.unwrap();
    assert!(publication_retry_once(&bad_dns, &restarted).await.unwrap());
    let terminal = restarted
        .query_one(
            "SELECT attempts,status FROM publication_outbox WHERE zone_domain=$1",
            &[&domain],
        )
        .await
        .unwrap();
    assert_eq!(terminal.get::<_, i32>(0), 10);
    assert_eq!(terminal.get::<_, String>(1), "failed");
    assert!(!publication_retry_once(&bad_dns, &restarted).await.unwrap());

    // A database outage is temporary: a failed claim leaves the due job
    // durable and the pool reconnect supervisor restores worker access.
    let url = std::env::var("TEST_DATABASE_URL").unwrap();
    let marked_url = if url.contains('?') {
        format!("{url}&application_name=publication-outage-test")
    } else {
        format!("{url}?application_name=publication-outage-test")
    };
    restarted.execute(
        "UPDATE publication_outbox SET attempts=0,status='pending',next_attempt=now() WHERE zone_domain=$1",
        &[&domain],
    ).await.unwrap();
    let outage_pool = Pool::connect(&marked_url, 1, Some(&env.schema))
        .await
        .unwrap();
    let (admin, admin_conn) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = admin_conn.await;
    });
    let killed = admin.execute(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='publication-outage-test'",
        &[],
    ).await.unwrap();
    assert_eq!(killed, 2);
    assert!(
        publication_retry_once(&bad_dns, &outage_pool)
            .await
            .is_err()
    );
    let mut reconnected = false;
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        if outage_pool.healthy() == 1
            && outage_pool.healthy_transactions() == 1
            && outage_pool.query_one("SELECT 1", &[]).await.is_ok()
        {
            reconnected = true;
            break;
        }
    }
    assert!(
        reconnected,
        "database sessions should recover after transient connection loss"
    );
    assert!(
        publication_retry_once(&bad_dns, &outage_pool)
            .await
            .unwrap()
    );
    let after_db_recovery = restarted
        .query_one(
            "SELECT attempts,status FROM publication_outbox WHERE zone_domain=$1",
            &[&domain],
        )
        .await
        .unwrap();
    assert_eq!(after_db_recovery.get::<_, i32>(0), 1);
    assert_eq!(after_db_recovery.get::<_, String>(1), "pending");
    env.cleanup().await;
}

#[actix_web::test]
async fn publication_retry_requeue_requires_admin_and_resets_terminal_job() {
    let Some(env) = setup().await else { return };
    env.state.db.execute(
        "INSERT INTO publication_outbox(zone_domain,attempts,status,next_attempt,last_error) VALUES('requeue.example',10,'failed',now(),'terminal failure')",
        &[],
    ).await.unwrap();
    let viewer = add_user(&env.state, "requeue-viewer", "viewer-password-1", "user").await;
    let viewer_token = env.token(&viewer, "user");
    let app = test::init_service(
        App::new()
            .wrap(actix_web::middleware::from_fn(security_headers))
            .wrap(actix_web::middleware::from_fn(auth_middleware))
            .app_data(web::Data::new(env.state.clone()))
            .app_data(web::Data::new(env.full.clone()))
            .configure(configure_routes),
    )
    .await;
    let viewer_response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/api/v1/admin/publication-outbox/requeue.example/retry")
            .insert_header(("Authorization", format!("Bearer {viewer_token}")))
            .to_request(),
    )
    .await;
    assert_eq!(viewer_response.status().as_u16(), 403);
    let admin_token = env.token(&env.admin, "admin");
    let admin_response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/api/v1/admin/publication-outbox/requeue.example/retry")
            .insert_header(("Authorization", format!("Bearer {admin_token}")))
            .to_request(),
    )
    .await;
    assert_eq!(admin_response.status().as_u16(), 202);
    let row = env.state.db.query_one(
        "SELECT attempts,status,last_error FROM publication_outbox WHERE zone_domain='requeue.example'",
        &[],
    ).await.unwrap();
    assert_eq!(row.get::<_, i32>(0), 0);
    assert_eq!(row.get::<_, String>(1), "pending");
    assert_eq!(row.get::<_, String>(2), "operator requested retry");
    env.cleanup().await;
}

#[actix_web::test]
async fn publication_outbox_upgrade_adds_missing_status_column_idempotently() {
    let Some(env) = setup().await else { return };
    env.state
        .db
        .batch_execute("ALTER TABLE publication_outbox DROP COLUMN status")
        .await
        .unwrap();
    migrate_db(&env.state.db).await.unwrap();
    migrate_db(&env.state.db).await.unwrap();
    let status_column = env.state.db.query_opt(
        "SELECT 1 FROM information_schema.columns WHERE table_schema=$1 AND table_name='publication_outbox' AND column_name='status'",
        &[&env.schema],
    ).await.unwrap();
    assert!(status_column.is_some());
    env.cleanup().await;
}

async fn add_user(state: &AppState, name: &str, pw: &str, role: &str) -> String {
    let id = Uuid::new_v4().to_string();
    let hash = Argon2::default()
        .hash_password(pw.as_bytes(), &generate_salt())
        .unwrap()
        .to_string();
    state
        .db
        .execute(
            "INSERT INTO users (id, username, password_hash, role) VALUES ($1::text::uuid, $2, $3, $4)",
            &[&id, &name, &hash, &role],
        )
        .await
        .unwrap();
    id
}

impl Env {
    async fn cleanup(self) {
        let _ = self
            .state
            .db
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await;
    }
    fn zone_file(&self, domain: &str) -> std::path::PathBuf {
        self.dir.path().join(format!("zone.{}", domain))
    }
    fn token(&self, id: &str, role: &str) -> String {
        self.token_with_version(id, role, 0)
    }
    fn token_with_version(&self, id: &str, role: &str, token_version: i64) -> String {
        issue_access_token(id, role, token_version, &self.state.jwt_secret).unwrap()
    }
}

macro_rules! app {
    ($env:expr) => {
        test::init_service(
            App::new()
                .wrap(actix_web::middleware::from_fn(security_headers))
                .wrap(actix_web::middleware::from_fn(auth_middleware))
                .wrap(actix_web::middleware::from_fn(error_envelope_middleware))
                .app_data(web::Data::new($env.state.clone()))
                .app_data(web::Data::new($env.full.clone()))
                .configure(configure_routes),
        )
        .await
    };
}

/// Perform a request and return (status, parsed JSON or Null, raw body).
macro_rules! call {
    ($app:expr, $method:ident, $uri:expr, $tok:expr, $body:expr) => {{
        let mut r = test::TestRequest::$method().uri($uri);
        if let Some(t) = $tok {
            r = r.insert_header(("Authorization", format!("Bearer {}", t)));
        }
        let body: Option<serde_json::Value> = $body;
        if let Some(b) = body {
            r = r.set_json(b);
        }
        let resp = test::call_service(&$app, r.to_request()).await;
        let status = resp.status().as_u16();
        let bytes = test::read_body(resp).await;
        let json: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json, String::from_utf8_lossy(&bytes).to_string())
    }};
}

fn j(v: serde_json::Value) -> Option<serde_json::Value> {
    Some(v)
}

async fn make_zone(
    env: &Env,
    app: &impl Service<
        actix_http::Request,
        Response = ServiceResponse<actix_web::body::BoxBody>,
        Error = actix_web::Error,
    >,
    tok: &str,
    domain: &str,
) -> String {
    let (st, body, raw) = call!(
        app,
        post,
        "/api/v1/zones",
        Some(tok),
        j(serde_json::json!({"domain": domain}))
    );
    assert_eq!(st, 201, "create zone {domain}: {raw}");
    assert!(
        env.zone_file(domain).is_file(),
        "zone file must exist after creation"
    );
    body["id"].as_str().unwrap().to_string()
}

fn soa_serial(path: &std::path::Path) -> u32 {
    let text = std::fs::read_to_string(path).unwrap();
    super::zone_file_generator::__soa_serial_for_tests(&text).expect("zone has SOA")
}

// ---------------------------------------------------------------------------

#[actix_web::test]
async fn session_lifecycle_and_no_default_credentials() {
    let Some(env) = setup().await else { return };
    let app = app!(env);

    // there is no built-in admin/admin123 account
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/auth/login",
        None::<&str>,
        j(serde_json::json!({"username":"admin","password":"admin123"}))
    );
    assert_eq!(st, 401);

    let (st, body, _) = call!(
        app,
        post,
        "/api/v1/auth/login",
        None::<&str>,
        j(serde_json::json!({"username":"root","password":"root-password-1"}))
    );
    assert_eq!(st, 200);
    let access = body["token"].as_str().unwrap().to_string();
    let refresh = body["refresh_token"].as_str().unwrap().to_string();

    // refresh yields a working access token
    let (st, body, _) = call!(
        app,
        post,
        "/api/v1/auth/refresh",
        None::<&str>,
        j(serde_json::json!({"refresh_token": refresh}))
    );
    assert_eq!(st, 200, "refresh must work: {body}");
    let access2 = body["token"].as_str().unwrap().to_string();
    let (st, _, _) = call!(app, get, "/api/v1/auth/me", Some(&access2), None);
    assert_eq!(st, 200);

    // bogus refresh token
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/auth/refresh",
        None::<&str>,
        j(serde_json::json!({"refresh_token": "nope"}))
    );
    assert_eq!(st, 401);

    // logout revokes the access token and the refresh token
    let (st, _, _) = call!(app, post, "/api/v1/auth/logout", Some(&access), None);
    assert_eq!(st, 200);
    let (st, _, _) = call!(app, get, "/api/v1/auth/me", Some(&access), None);
    assert_eq!(st, 401, "revoked access token must be rejected");
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/auth/refresh",
        None::<&str>,
        j(serde_json::json!({"refresh_token": refresh}))
    );
    assert_eq!(st, 401, "refresh token must die with the session");

    // wrong password / unknown user are indistinguishable
    let (s1, b1, _) = call!(
        app,
        post,
        "/api/v1/auth/login",
        None::<&str>,
        j(serde_json::json!({"username":"root","password":"bad"}))
    );
    let (s2, b2, _) = call!(
        app,
        post,
        "/api/v1/auth/login",
        None::<&str>,
        j(serde_json::json!({"username":"ghost","password":"bad"}))
    );
    assert_eq!((s1, &b1), (s2, &b2));
    env.cleanup().await;
}

#[actix_web::test]
async fn refresh_rotation_replay_revokes_the_whole_session() {
    let Some(env) = setup().await else { return };
    let app = app!(env);

    let (st, body, _) = call!(
        app,
        post,
        "/api/v1/auth/login",
        None::<&str>,
        j(serde_json::json!({"username":"root","password":"root-password-1"}))
    );
    assert_eq!(st, 200);
    let access = body["token"].as_str().unwrap().to_string();
    let refresh = body["refresh_token"].as_str().unwrap().to_string();

    let (st, body, raw) = call!(
        app,
        post,
        "/api/v1/auth/refresh",
        None::<&str>,
        j(serde_json::json!({"refresh_token": refresh}))
    );
    assert_eq!(st, 200, "first refresh: {raw}");
    let rotated_access = body["token"].as_str().unwrap().to_string();
    let rotated_refresh = body["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(rotated_refresh, refresh, "refresh token must rotate");

    // Replaying the old token is detected and ends the session.
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/auth/refresh",
        None::<&str>,
        j(serde_json::json!({"refresh_token": refresh}))
    );
    assert_eq!(st, 401, "rotated refresh token must not be reusable");
    let (st, _, _) = call!(app, get, "/api/v1/auth/me", Some(&rotated_access), None);
    assert_eq!(st, 401, "replay detection must invalidate access tokens");
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/auth/refresh",
        None::<&str>,
        j(serde_json::json!({"refresh_token": rotated_refresh}))
    );
    assert_eq!(
        st, 401,
        "replay detection must invalidate the live refresh token too"
    );
    let (st, _, _) = call!(app, get, "/api/v1/auth/me", Some(&access), None);
    assert_eq!(st, 401);
    env.cleanup().await;
}

#[actix_web::test]
async fn password_change_and_admin_reset_revoke_access_and_refresh_tokens() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let uid = add_user(&env.state, "pwuser", "old-password-1", "user").await;

    let login = |pw: &str| j(serde_json::json!({"username":"pwuser","password":pw}));
    let (st, body, _) = call!(
        app,
        post,
        "/api/v1/auth/login",
        None::<&str>,
        login("old-password-1")
    );
    assert_eq!(st, 200);
    let old_access = body["token"].as_str().unwrap().to_string();
    let old_refresh = body["refresh_token"].as_str().unwrap().to_string();

    let (st, _, raw) = call!(
        app,
        post,
        "/api/v1/auth/change-password",
        Some(&old_access),
        j(serde_json::json!({"current_password":"old-password-1","new_password":"new-password-1"}))
    );
    assert_eq!(st, 200, "{raw}");
    let (st, _, _) = call!(app, get, "/api/v1/auth/me", Some(&old_access), None);
    assert_eq!(
        st, 401,
        "password change must invalidate existing access tokens"
    );
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/auth/refresh",
        None::<&str>,
        j(serde_json::json!({"refresh_token": old_refresh}))
    );
    assert_eq!(st, 401, "password change must invalidate refresh tokens");
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/auth/login",
        None::<&str>,
        login("old-password-1")
    );
    assert_eq!(st, 401);
    let (st, body, _) = call!(
        app,
        post,
        "/api/v1/auth/login",
        None::<&str>,
        login("new-password-1")
    );
    assert_eq!(st, 200);
    let reset_access = body["token"].as_str().unwrap().to_string();
    let reset_refresh = body["refresh_token"].as_str().unwrap().to_string();

    let admin = env.token(&env.admin, "admin");
    let (st, _, raw) = call!(
        app,
        post,
        "/api/v1/auth/admin-reset-password",
        Some(&admin),
        j(serde_json::json!({"user_id": uid, "new_password":"admin-set-password-1"}))
    );
    assert_eq!(st, 200, "{raw}");
    let (st, _, _) = call!(app, get, "/api/v1/auth/me", Some(&reset_access), None);
    assert_eq!(
        st, 401,
        "admin reset must invalidate existing access tokens"
    );
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/auth/refresh",
        None::<&str>,
        j(serde_json::json!({"refresh_token": reset_refresh}))
    );
    assert_eq!(st, 401, "admin reset must invalidate refresh tokens");
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/auth/login",
        None::<&str>,
        login("admin-set-password-1")
    );
    assert_eq!(st, 200);
    env.cleanup().await;
}

#[actix_web::test]
async fn logout_invalidates_every_session_for_the_user() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let login = j(serde_json::json!({"username":"root","password":"root-password-1"}));

    let (_, first, _) = call!(app, post, "/api/v1/auth/login", None::<&str>, login.clone());
    let first_access = first["token"].as_str().unwrap().to_string();
    let (_, second, _) = call!(app, post, "/api/v1/auth/login", None::<&str>, login);
    let second_access = second["token"].as_str().unwrap().to_string();
    let second_refresh = second["refresh_token"].as_str().unwrap().to_string();

    let (st, _, _) = call!(app, post, "/api/v1/auth/logout", Some(&second_access), None);
    assert_eq!(st, 200);
    for token in [&first_access, &second_access] {
        let (st, _, _) = call!(app, get, "/api/v1/auth/me", Some(token), None);
        assert_eq!(
            st, 401,
            "logout must invalidate every access token for the account"
        );
    }
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/auth/refresh",
        None::<&str>,
        j(serde_json::json!({"refresh_token": second_refresh}))
    );
    assert_eq!(st, 401);
    env.cleanup().await;
}

#[actix_web::test]
async fn deleted_user_and_demoted_admin_lose_access_immediately() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let mallory = add_user(&env.state, "mallory", "mallory-pass-1", "admin").await;
    let tok = env.token(&mallory, "admin");
    let (st, _, _) = call!(app, get, "/api/v1/users", Some(&tok), None);
    assert_eq!(st, 200);

    // demote in the database: the (still valid) JWT claims "admin" but must not be honoured
    env.state
        .db
        .execute("UPDATE users SET role='user' WHERE username='mallory'", &[])
        .await
        .unwrap();
    let (st, _, _) = call!(app, get, "/api/v1/users", Some(&tok), None);
    assert_eq!(st, 403, "role must come from the database, not the token");

    env.state
        .db
        .execute("DELETE FROM users WHERE username='mallory'", &[])
        .await
        .unwrap();
    let (st, _, _) = call!(app, get, "/api/v1/auth/me", Some(&tok), None);
    assert_eq!(st, 401, "tokens of deleted users must stop working");
    env.cleanup().await;
}

#[actix_web::test]
async fn login_is_rate_limited_per_username() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let name = format!("victim-{}", Uuid::new_v4().simple());
    let mut last = 0;
    // The budget refills continuously (1 token per 60/N s) and a debug-build login takes a while
    // under parallel test load, so keep trying until the limiter trips instead of assuming a speed.
    for _ in 0..(LOGIN_ATTEMPTS_PER_MINUTE * 6) {
        let (st, _, _) = call!(
            app,
            post,
            "/api/v1/auth/login",
            None::<&str>,
            j(serde_json::json!({"username": name, "password":"x"}))
        );
        last = st;
        if st == 429 {
            break;
        }
    }
    assert_eq!(last, 429);
    env.cleanup().await;
}

#[actix_web::test]
async fn tenants_cannot_touch_each_others_zones() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let alice = add_user(&env.state, "alice", "alice-pass-1", "user").await;
    let bob = add_user(&env.state, "bob", "bob-pass-123", "user").await;
    let (ta, tb, tadmin) = (
        env.token(&alice, "user"),
        env.token(&bob, "user"),
        env.token(&env.admin, "admin"),
    );

    let zid = make_zone(&env, &app, &ta, "alice.example").await;
    let (st, rec, _) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/records"),
        Some(&ta),
        j(serde_json::json!({"name":"www","record_type":"A","value":"192.0.2.10","ttl":300}))
    );
    assert_eq!(st, 201);
    let rid = rec["id"].as_str().unwrap().to_string();
    let (st, gr, _) = call!(
        app,
        post,
        "/api/v1/georules",
        Some(&ta),
        j(
            serde_json::json!({"zone_id": zid, "match_type":"country","match_value":"US","target":"192.0.2.77"})
        )
    );
    assert_eq!(st, 201);
    let gid = gr["id"].as_str().unwrap().to_string();

    // bob: every read and write is refused
    for (m, uri, body) in [
        ("get", format!("/api/v1/zones/{zid}"), None),
        ("get", format!("/api/v1/zones/{zid}/records"), None),
        ("get", format!("/api/v1/zones/{zid}/export"), None),
        (
            "post",
            format!("/api/v1/zones/{zid}/records"),
            j(serde_json::json!({"name":"evil","record_type":"A","value":"6.6.6.6","ttl":60})),
        ),
        (
            "post",
            format!("/api/v1/zones/{zid}/import"),
            j(serde_json::json!({"records":[{"name":"evil","record_type":"A","value":"6.6.6.6"}]})),
        ),
        (
            "put",
            format!("/api/v1/zones/{zid}/records/{rid}"),
            j(serde_json::json!({"value":"6.6.6.6"})),
        ),
        ("delete", format!("/api/v1/zones/{zid}/records/{rid}"), None),
        (
            "put",
            format!("/api/v1/zones/{zid}"),
            j(serde_json::json!({"geodns_enabled": false})),
        ),
        ("delete", format!("/api/v1/zones/{zid}"), None),
        (
            "put",
            format!("/api/v1/georules/{gid}"),
            j(serde_json::json!({"target":"6.6.6.6"})),
        ),
        ("delete", format!("/api/v1/georules/{gid}"), None),
        (
            "post",
            "/api/v1/georules".to_string(),
            j(
                serde_json::json!({"zone_id": zid,"match_type":"default","match_value":"","target":"6.6.6.6"}),
            ),
        ),
        (
            "post",
            "/api/v1/georules/resolve".to_string(),
            j(serde_json::json!({"zone_id": zid,"client_ip":"8.8.8.8"})),
        ),
    ] {
        let (st, _, raw) = match m {
            "get" => call!(app, get, &uri, Some(&tb), body),
            "post" => call!(app, post, &uri, Some(&tb), body),
            "put" => call!(app, put, &uri, Some(&tb), body),
            _ => call!(app, delete, &uri, Some(&tb), body),
        };
        assert_eq!(st, 403, "bob {m} {uri} must be forbidden, got {st}: {raw}");
    }
    let (_, list, _) = call!(app, get, "/api/v1/georules", Some(&tb), None);
    assert_eq!(
        list.as_array().unwrap().len(),
        0,
        "bob must not see alice's geo rules"
    );
    let (_, zl, _) = call!(app, get, "/api/v1/zones", Some(&tb), None);
    assert_eq!(zl["data"].as_array().unwrap().len(), 0);
    // bob may not read alice's profile either
    let (st, _, _) = call!(app, get, &format!("/api/v1/users/{alice}"), Some(&tb), None);
    assert_eq!(st, 403);
    // ...nor create a zone inside her namespace
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/zones",
        Some(&tb),
        j(serde_json::json!({"domain":"shop.alice.example"}))
    );
    assert_eq!(st, 409);
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/zones",
        Some(&tb),
        j(serde_json::json!({"domain":"example"}))
    );
    assert_eq!(st, 400);

    // nothing of bob's attempts reached the zone
    let text = std::fs::read_to_string(env.zone_file("alice.example")).unwrap();
    assert!(!text.contains("6.6.6.6"), "{text}");

    // alice (owner) and the admin can do everything
    let (st, _, _) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zid}/records/{rid}"),
        Some(&ta),
        j(serde_json::json!({"ttl": 600}))
    );
    assert_eq!(st, 200, "owner must be able to update own record");
    let (st, _, _) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zid}"),
        Some(&ta),
        j(serde_json::json!({"geodns_enabled": false}))
    );
    assert_eq!(st, 200);
    let (st, _, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{zid}/export"),
        Some(&tadmin),
        None
    );
    assert_eq!(st, 200);
    let (st, _, _) = call!(
        app,
        delete,
        &format!("/api/v1/zones/{zid}/records/{rid}"),
        Some(&ta),
        None
    );
    assert_eq!(st, 200, "owner must be able to delete own record");
    let (st, _, _) = call!(
        app,
        delete,
        &format!("/api/v1/zones/{zid}"),
        Some(&ta),
        None
    );
    assert_eq!(st, 200);
    assert!(
        !env.zone_file("alice.example").exists(),
        "deleted zone must stop being served"
    );
    env.cleanup().await;
}

#[actix_web::test]
async fn zone_domain_validation() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let tadmin = env.token(&env.admin, "admin");
    for bad in [
        ".",
        "",
        "com",
        "a/b.com",
        "q\"x.com",
        "a b.com",
        "-a.com",
        "a..com",
        "ü.com",
        "../../etc/x.com",
    ] {
        let (st, _, raw) = call!(
            app,
            post,
            "/api/v1/zones",
            Some(&tadmin),
            j(serde_json::json!({"domain": bad}))
        );
        assert_eq!(st, 400, "{bad:?} must be rejected: {raw}");
    }
    let (st, body, _) = call!(
        app,
        post,
        "/api/v1/zones",
        Some(&tadmin),
        j(serde_json::json!({"domain": "Mixed.Example."}))
    );
    assert_eq!(st, 201);
    assert_eq!(
        body["domain"], "mixed.example",
        "domains are stored lower-case without trailing dot"
    );
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/zones",
        Some(&tadmin),
        j(serde_json::json!({"domain": "MIXED.example"}))
    );
    assert_eq!(st, 409, "case variants are the same zone");
    env.cleanup().await;
}

#[actix_web::test]
async fn zone_templates_are_authenticated_validated_and_persist_defaults_and_records() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let admin = env.token(&env.admin, "admin");

    let (status, _, _) = call!(app, get, "/api/v1/zone-templates", None::<&str>, None);
    assert_eq!(status, 401, "template catalog must require authentication");
    let (status, catalog, raw) = call!(app, get, "/api/v1/zone-templates", Some(&admin), None);
    assert_eq!(status, 200, "{raw}");
    assert_eq!(catalog.as_array().unwrap().len(), 2);
    assert!(catalog.as_array().unwrap().iter().any(|t| t["id"] == "web"));

    for (domain, template_id, variables, expected_count) in [
        (
            "web-template.example",
            "web",
            serde_json::json!({"ipv4":"192.0.2.4", "ipv6":"2001:db8::4"}),
            3,
        ),
        (
            "mail-template.example",
            "mail",
            serde_json::json!({"mail_ipv4":"192.0.2.25"}),
            3,
        ),
    ] {
        let (status, body, raw) = call!(
            app,
            post,
            "/api/v1/zones",
            Some(&admin),
            j(serde_json::json!({
                "domain": domain,
                "template_id": template_id,
                "template_variables": variables
            }))
        );
        assert_eq!(status, 201, "{raw}");
        assert_eq!(body["template_record_count"], expected_count);
        let zone_id = body["id"].as_str().unwrap();
        let rows = env.state.db.query(
            "SELECT name,record_type,value,COALESCE(priority,0) FROM records WHERE CAST(zone_id AS varchar)=$1 ORDER BY record_type,name",
            &[&zone_id],
        ).await.unwrap();
        let records: Vec<(String, String, String, i32)> = rows
            .iter()
            .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
            .collect();
        assert!(
            records.iter().any(|r| r.1 == "SOA"),
            "default SOA preserved"
        );
        assert!(records.iter().any(|r| r.1 == "NS"), "default NS preserved");
        if template_id == "web" {
            assert!(records.iter().any(|r| r.1 == "A" && r.2 == "192.0.2.4"));
            assert!(
                records
                    .iter()
                    .any(|r| r.1 == "AAAA" && r.2 == "2001:db8::4")
            );
            assert!(
                records
                    .iter()
                    .any(|r| r.1 == "CNAME" && r.2 == "web-template.example.")
            );
        } else {
            assert!(
                records
                    .iter()
                    .any(|r| r.1 == "A" && r.0 == "mail" && r.2 == "192.0.2.25")
            );
            assert!(
                records
                    .iter()
                    .any(|r| r.1 == "MX" && r.3 == 10 && r.2 == "mail.mail-template.example.")
            );
            assert!(
                records
                    .iter()
                    .any(|r| r.1 == "TXT" && r.2.contains("v=spf1 mx -all"))
            );
        }
        let dnssec = env
            .state
            .db
            .query_one(
                "SELECT dnssec_enabled FROM zones WHERE CAST(id AS varchar)=$1",
                &[&zone_id],
            )
            .await
            .unwrap();
        assert!(
            !dnssec.get::<_, bool>(0),
            "templates must not implicitly enable DNSSEC"
        );
    }

    for (domain, template_id, variables) in [
        ("missing-template.example", "web", serde_json::json!({})),
        (
            "invalid-template.example",
            "web",
            serde_json::json!({"ipv4":"not-an-ip"}),
        ),
        ("unknown-template.example", "bogus", serde_json::json!({})),
    ] {
        let (status, _, raw) = call!(
            app,
            post,
            "/api/v1/zones",
            Some(&admin),
            j(serde_json::json!({
                "domain": domain, "template_id": template_id, "template_variables": variables
            }))
        );
        assert_eq!(status, 400, "{domain}: {raw}");
        let count = env
            .state
            .db
            .query_one("SELECT count(*) FROM zones WHERE domain=$1", &[&domain])
            .await
            .unwrap()
            .get::<_, i64>(0);
        assert_eq!(
            count, 0,
            "invalid template request must not leave a partial zone"
        );
    }
    env.cleanup().await;
}

#[actix_web::test]
async fn record_validation_rrsets_and_atomic_update() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let zid = make_zone(&env, &app, &t, "rr.example").await;
    let rec = |name: &str, ty: &str, val: &str, ttl: u64| {
        j(serde_json::json!({"name":name,"record_type":ty,"value":val,"ttl":ttl}))
    };
    let url = format!("/api/v1/zones/{zid}/records");

    // out of range TTLs used to be stored as negative numbers and broke every zone
    for ttl in [0u64, 2_147_483_648, 4_294_967_295] {
        let (st, _, _) = call!(app, post, &url, Some(&t), rec("x", "A", "192.0.2.1", ttl));
        assert_eq!(st, 400, "ttl {ttl}");
    }
    // names outside the zone
    let (st, _, _) = call!(
        app,
        post,
        &url,
        Some(&t),
        rec("www.victim.org.", "A", "192.0.2.1", 300)
    );
    assert_eq!(st, 400);
    // a round-robin RRset is legal
    for ip in ["192.0.2.1", "192.0.2.2", "192.0.2.3"] {
        let (st, _, raw) = call!(app, post, &url, Some(&t), rec("www", "A", ip, 300));
        assert_eq!(st, 201, "{raw}");
    }
    let (st, _, _) = call!(app, post, &url, Some(&t), rec("www", "A", "192.0.2.1", 300));
    assert_eq!(st, 409, "exact duplicate");
    for (pri, mx) in [(10, "mx1.rr.example."), (20, "mx2.rr.example.")] {
        let (st, _, raw) = call!(
            app,
            post,
            &url,
            Some(&t),
            j(
                serde_json::json!({"name":"@","record_type":"MX","value":mx,"ttl":300,"priority":pri})
            )
        );
        assert_eq!(st, 201, "{raw}");
    }
    let zone = std::fs::read_to_string(env.zone_file("rr.example")).unwrap();
    assert_eq!(zone.matches("192.0.2.").count(), 3, "{zone}");
    assert_eq!(zone.matches(" MX ").count(), 2, "{zone}");

    // CNAME may not share a name with other data, nor sit at the apex
    let (st, _, _) = call!(
        app,
        post,
        &url,
        Some(&t),
        rec("www", "CNAME", "other.rr.example.", 300)
    );
    assert_eq!(st, 400, "CNAME + A");
    let (st, _, _) = call!(
        app,
        post,
        &url,
        Some(&t),
        rec("@", "CNAME", "other.rr.example.", 300)
    );
    assert_eq!(st, 400, "apex CNAME");
    let (st, _, _) = call!(
        app,
        post,
        &url,
        Some(&t),
        rec("alias", "CNAME", "www.rr.example.", 300)
    );
    assert_eq!(st, 201);
    let (st, _, _) = call!(
        app,
        post,
        &url,
        Some(&t),
        rec("alias", "A", "192.0.2.9", 300)
    );
    assert_eq!(st, 400, "A next to CNAME");
    // failed requests left the stored zone untouched and valid
    assert!(
        !std::fs::read_to_string(env.zone_file("rr.example"))
            .unwrap()
            .contains("192.0.2.9")
    );

    // a second SOA is refused
    let (st, _, _) = call!(
        app,
        post,
        &url,
        Some(&t),
        rec(
            "@",
            "SOA",
            "ns1.rr.example. h.rr.example. 1 3600 3600 604800 3600",
            300
        )
    );
    assert_eq!(st, 409);

    // updates are validated as a whole and applied atomically
    let (_, list, _) = call!(app, get, &url, Some(&t), None);
    let a_id = list
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["value"] == "192.0.2.3")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (st, _, _) = call!(
        app,
        put,
        &format!("{url}/{a_id}"),
        Some(&t),
        j(serde_json::json!({"value":"192.0.2.33","ttl":120}))
    );
    assert_eq!(st, 200);
    let (st, _, _) = call!(
        app,
        put,
        &format!("{url}/{a_id}"),
        Some(&t),
        j(serde_json::json!({"value":"not-an-ip","ttl":999}))
    );
    assert_eq!(st, 400);
    let (_, list, _) = call!(app, get, &url, Some(&t), None);
    let r = list
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == a_id.as_str())
        .unwrap()
        .clone();
    assert_eq!(
        (r["value"].as_str().unwrap(), r["ttl"].as_u64().unwrap()),
        ("192.0.2.33", 120),
        "rejected update must change nothing"
    );
    let (st, _, _) = call!(
        app,
        put,
        &format!("{url}/{}", Uuid::new_v4()),
        Some(&t),
        j(serde_json::json!({"ttl": 10}))
    );
    assert_eq!(st, 404);
    // changing the type to something the value does not fit is refused
    let (st, _, _) = call!(
        app,
        put,
        &format!("{url}/{a_id}"),
        Some(&t),
        j(serde_json::json!({"record_type":"AAAA"}))
    );
    assert_eq!(st, 400);
    env.cleanup().await;
}

#[actix_web::test]
async fn import_is_all_or_nothing_and_never_partial() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let zid = make_zone(&env, &app, &t, "imp.example").await;
    let url = format!("/api/v1/zones/{zid}/import");
    let before = std::fs::read_to_string(env.zone_file("imp.example")).unwrap();

    let (st, _, _) = call!(
        app,
        post,
        &url,
        Some(&t),
        j(serde_json::json!({"records":[
        {"name":"a","record_type":"A","value":"192.0.2.1"},
        {"name":"b","record_type":"A","value":"999.0.2.1"}]}))
    );
    assert_eq!(st, 400);
    let (_, list, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{zid}/records"),
        Some(&t),
        None
    );
    assert!(
        list.as_array().unwrap().iter().all(|r| r["name"] != "a"),
        "first record of a failed import must not remain"
    );
    assert_eq!(
        std::fs::read_to_string(env.zone_file("imp.example")).unwrap(),
        before
    );

    let (st, body, raw) = call!(
        app,
        post,
        &url,
        Some(&t),
        j(serde_json::json!({"records":[
        {"name":"a","record_type":"A","value":"192.0.2.1"},
        {"name":"a","record_type":"A","value":"192.0.2.1"},
        {"name":"b","record_type":"TXT","value":"v=spf1 -all","ttl":300}]}))
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(body["imported"], 2);
    assert_eq!(body["skipped"], 1);
    let zone = std::fs::read_to_string(env.zone_file("imp.example")).unwrap();
    assert!(
        zone.contains("192.0.2.1") && zone.contains("spf1"),
        "{zone}"
    );
    env.cleanup().await;
}

#[actix_web::test]
async fn georule_update_and_input_validation() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let zid = make_zone(&env, &app, &t, "geo.example").await;
    let (st, gr, raw) = call!(
        app,
        post,
        "/api/v1/georules",
        Some(&t),
        j(
            serde_json::json!({"zone_id": zid,"match_type":"country","match_value":"US","target":"192.0.2.77","priority":5,"weight":7})
        )
    );
    assert_eq!(st, 201, "{raw}");
    let gid = gr["id"].as_str().unwrap().to_string();

    // used to answer 500: priority/enabled were bound as text
    let (st, _, raw) = call!(
        app,
        put,
        &format!("/api/v1/georules/{gid}"),
        Some(&t),
        j(serde_json::json!({"priority": 9, "enabled": false, "weight": 3}))
    );
    assert_eq!(st, 200, "{raw}");
    let (_, list, _) = call!(app, get, "/api/v1/georules", Some(&t), None);
    let r = &list.as_array().unwrap()[0];
    assert_eq!(
        (r["priority"].as_i64(), r["enabled"].as_bool()),
        (Some(9), Some(false))
    );
    assert_eq!(r["weight"].as_i64(), Some(3));
    let named = std::fs::read_to_string(env.dir.path().join("named.toml")).unwrap();
    assert!(
        named.contains("weight = 3"),
        "weight must be published: {named}"
    );

    // injection attempts and nonsense are refused, nothing reaches named.toml
    for body in [
        serde_json::json!({"zone_id": zid,"match_type":"country","match_value":"US\"\n[[zones]]\nzone=\"pwn\"\n#","target":"192.0.2.1"}),
        serde_json::json!({"zone_id": zid,"match_type":"country","match_value":"US","target":"x\"\n[[zones]]"}),
        serde_json::json!({"zone_id": zid,"match_type":"galaxy","match_value":"US","target":"192.0.2.1"}),
        serde_json::json!({"zone_id": zid,"match_type":"country","match_value":"USA1","target":"192.0.2.1"}),
        serde_json::json!({"zone_id": zid,"match_type":"country","match_value":"US","target":"www.example.com"}),
        serde_json::json!({"zone_id": zid,"match_type":"country","match_value":"US","target":"192.0.2.1","weight":1000001}),
        serde_json::json!({"zone_id": "not-a-uuid","match_type":"country","match_value":"US","target":"192.0.2.1"}),
    ] {
        let (st, _, raw) = call!(app, post, "/api/v1/georules", Some(&t), j(body.clone()));
        assert_eq!(st, 400, "{body} -> {raw}");
    }
    let named = std::fs::read_to_string(env.dir.path().join("named.toml")).unwrap();
    assert!(!named.contains("pwn"), "{named}");
    assert_eq!(named.matches("[[zones]]").count(), 1, "{named}");

    // resolve uses the real GeoIP data
    call!(
        app,
        put,
        &format!("/api/v1/georules/{gid}"),
        Some(&t),
        j(serde_json::json!({"enabled": true}))
    );
    let (_, us, _) = call!(
        app,
        post,
        "/api/v1/georules/resolve",
        Some(&t),
        j(serde_json::json!({"zone_id": zid,"client_ip":"8.8.8.8"}))
    );
    assert_eq!(us["target"], "192.0.2.77");
    let (_, de, _) = call!(
        app,
        post,
        "/api/v1/georules/resolve",
        Some(&t),
        j(serde_json::json!({"zone_id": zid,"client_ip":"5.9.0.1"}))
    );
    assert!(de["target"].is_null());
    env.cleanup().await;
}

#[actix_web::test]
async fn nameserver_input_is_validated_and_applied() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    for body in [
        serde_json::json!({"hostname":"","ip_address":"192.0.2.1"}),
        serde_json::json!({"hostname":"ns1.example.com","ip_address":"not-an-ip"}),
        serde_json::json!({"hostname":"ns 1.example.com","ip_address":"192.0.2.1"}),
        serde_json::json!({"hostname":"ns1.example.com","ip_address":"192.0.2.1","glue_ip":"zzz"}),
    ] {
        let (st, _, raw) = call!(app, post, "/api/v1/nameservers", Some(&t), j(body.clone()));
        assert_eq!(st, 400, "{body}: {raw}");
    }
    let (st, ns, raw) = call!(
        app,
        post,
        "/api/v1/nameservers",
        Some(&t),
        j(serde_json::json!({"hostname":"ns1.glue.example","ip_address":"192.0.2.53"}))
    );
    assert_eq!(st, 201, "{raw}");
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/nameservers",
        Some(&t),
        j(serde_json::json!({"hostname":"NS1.glue.example.","ip_address":"192.0.2.54"}))
    );
    assert_eq!(st, 409);
    make_zone(&env, &app, &t, "glue.example").await;
    let zone = std::fs::read_to_string(env.zone_file("glue.example")).unwrap();
    assert!(zone.contains("IN NS ns1.glue.example."), "{zone}");
    assert!(
        zone.contains("ns1.glue.example. 3600 IN A 192.0.2.53"),
        "glue A: {zone}"
    );
    let (st, _, _) = call!(
        app,
        put,
        &format!("/api/v1/nameservers/{}", Uuid::new_v4()),
        Some(&t),
        j(serde_json::json!({"hostname":"ns9.glue.example","ip_address":"192.0.2.9"}))
    );
    assert_eq!(st, 404);
    let (st, _, _) = call!(
        app,
        delete,
        &format!("/api/v1/nameservers/{}", ns["id"].as_str().unwrap()),
        Some(&t),
        None
    );
    assert_eq!(st, 200);
    env.cleanup().await;
}

#[actix_web::test]
async fn soa_serial_increases_only_when_content_changes() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let zid = make_zone(&env, &app, &t, "serial.example").await;
    let path = env.zone_file("serial.example");
    let s0 = soa_serial(&path);

    // regenerating identical data neither changes the serial nor rewrites the file
    let mtime0 = std::fs::metadata(&path).unwrap().modified().unwrap();
    env.state
        .dns_manager
        .regenerate_zones(env.state.db.clone())
        .await
        .unwrap();
    assert_eq!(soa_serial(&path), s0);
    assert_eq!(
        std::fs::metadata(&path).unwrap().modified().unwrap(),
        mtime0,
        "unchanged zone must not be rewritten"
    );

    let mut prev = s0;
    for i in 0..5 {
        let (st, _, _) = call!(
            app,
            post,
            &format!("/api/v1/zones/{zid}/records"),
            Some(&t),
            j(
                serde_json::json!({"name": format!("h{i}"),"record_type":"A","value":"192.0.2.1","ttl":300})
            )
        );
        assert_eq!(st, 201);
        let s = soa_serial(&path);
        assert!(s > prev, "serial must grow on every change ({prev} -> {s})");
        prev = s;
    }
    env.cleanup().await;
}

#[actix_web::test]
async fn concurrent_writes_all_end_up_published() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let zid = make_zone(&env, &app, &t, "race.example").await;
    let url = format!("/api/v1/zones/{zid}/records");
    let reqs = (0..16).map(|i| {
        let r = test::TestRequest::post()
            .uri(&url)
            .insert_header(("Authorization", format!("Bearer {t}")))
            .set_json(serde_json::json!({"name": format!("n{i}"),"record_type":"A","value":format!("192.0.2.{}", i + 1),"ttl":300}))
            .to_request();
        test::call_service(&app, r)
    });
    for resp in futures_util::future::join_all(reqs).await {
        assert_eq!(resp.status().as_u16(), 201);
    }
    let zone = std::fs::read_to_string(env.zone_file("race.example")).unwrap();
    for i in 0..16 {
        assert!(
            zone.contains(&format!("192.0.2.{} ", i + 1))
                || zone.contains(&format!("192.0.2.{}\n", i + 1)),
            "record {i} missing (stale zone): {zone}"
        );
    }
    assert!(!env.dir.path().join("zone.race.example.tmp").exists());
    env.cleanup().await;
}

#[actix_web::test]
async fn one_broken_zone_never_blocks_or_replaces_others() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let good = make_zone(&env, &app, &t, "good.example").await;
    let bad = make_zone(&env, &app, &t, "bad.example").await;
    let bad_before = std::fs::read_to_string(env.zone_file("bad.example")).unwrap();

    // corrupt data written behind the API's back (e.g. an old bug or manual SQL)
    env.state.db.execute(
        "INSERT INTO records (id, zone_id, name, record_type, value, ttl) VALUES ($1::text::uuid, $2::text::uuid, 'x', 'A', '192.0.2.1', -1)",
        &[&Uuid::new_v4().to_string(), &bad]).await.unwrap();

    // the healthy zone is still published and the broken zone keeps its last known-good file
    let (st, _, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{good}/records"),
        Some(&t),
        j(serde_json::json!({"name":"www","record_type":"A","value":"192.0.2.55","ttl":300}))
    );
    assert_eq!(
        st, 201,
        "healthy zone must not be blocked by another zone's bad data: {raw}"
    );
    assert!(
        std::fs::read_to_string(env.zone_file("good.example"))
            .unwrap()
            .contains("192.0.2.55")
    );
    assert_eq!(
        std::fs::read_to_string(env.zone_file("bad.example")).unwrap(),
        bad_before
    );
    let named = std::fs::read_to_string(env.dir.path().join("named.toml")).unwrap();
    assert!(
        named.contains("bad.example"),
        "last known-good zone must stay configured"
    );

    // and a change to the broken zone is reported honestly, not as success
    let (st, _, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{bad}/records"),
        Some(&t),
        j(serde_json::json!({"name":"www","record_type":"A","value":"192.0.2.66","ttl":300}))
    );
    assert_eq!(st, 400, "{raw}");
    env.cleanup().await;
}

#[actix_web::test]
async fn generate_all_uses_bounded_database_queries() {
    let Some(env) = setup().await else { return };
    for i in 0..25 {
        let zid = Uuid::new_v4().to_string();
        env.state
            .db
            .execute(
                "INSERT INTO zones (id, domain, owner) VALUES ($1::text::uuid, $2, $3::text::uuid)",
                &[&zid, &format!("bulk{i}.example"), &env.admin],
            )
            .await
            .unwrap();
        env.state.db.execute(
            "INSERT INTO records (id, zone_id, name, record_type, value, ttl) VALUES ($1::text::uuid, $2::text::uuid, 'www', 'A', '192.0.2.10', 300)",
            &[&Uuid::new_v4().to_string(), &zid],
        ).await.unwrap();
        env.state.db.execute(
            "INSERT INTO georules (id, zone_id, match_type, match_value, target, priority, enabled) VALUES ($1::text::uuid, $2::text::uuid, 'country', 'US', '192.0.2.11', 1, true)",
            &[&Uuid::new_v4().to_string(), &zid],
        ).await.unwrap();
    }
    let before = env.state.db.query_count();
    let report =
        zone_file_generator::generate_all(env.dir.path().to_str().unwrap(), env.state.db.clone())
            .await
            .unwrap();
    let queries = env.state.db.query_count() - before;
    assert!(report.failed.is_empty(), "{:?}", report.failed);
    assert_eq!(report.published.len(), 25);
    assert!(
        queries <= 8,
        "generate_all must not issue per-zone queries; used {queries} for 25 zones"
    );
    env.cleanup().await;
}

#[actix_web::test]
async fn database_failure_never_wipes_published_zones() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    make_zone(&env, &app, &t, "keep.example").await;
    let before = std::fs::read_to_string(env.zone_file("keep.example")).unwrap();
    let named_before = std::fs::read_to_string(env.dir.path().join("named.toml")).unwrap();

    // make one of the generator's queries fail
    env.state
        .db
        .batch_execute("ALTER TABLE georules RENAME TO georules_gone")
        .await
        .unwrap();
    let res = env
        .state
        .dns_manager
        .regenerate_zones(env.state.db.clone())
        .await;
    assert!(
        res.is_err(),
        "a failing database read must abort publication"
    );
    assert_eq!(
        std::fs::read_to_string(env.zone_file("keep.example")).unwrap(),
        before
    );
    assert_eq!(
        std::fs::read_to_string(env.dir.path().join("named.toml")).unwrap(),
        named_before
    );
    env.state
        .db
        .batch_execute("ALTER TABLE georules_gone RENAME TO georules")
        .await
        .unwrap();
    env.cleanup().await;
}

#[actix_web::test]
async fn agent_lifecycle_register_heartbeat_bundle_ack_push_disable() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    make_zone(&env, &app, &t, "agent.example").await;
    let (st, reg, _) = call!(
        app,
        post,
        "/api/v1/agents/register",
        Some(&t),
        j(serde_json::json!({"name":"a1","addr":"10.0.0.5:5353"}))
    );
    assert_eq!(st, 201);
    let (id, tokn, key) = (
        reg["id"].as_str().unwrap().to_string(),
        reg["token"].as_str().unwrap().to_string(),
        reg["signing_key"].as_str().unwrap().to_string(),
    );
    assert_eq!(
        key,
        ext::agent_signing_key(&env.state.agent_signing_secret, &id)
    );
    assert_ne!(key, ext::agent_signing_key(&env.state.jwt_secret, &id));
    let zid = env
        .state
        .db
        .query_one(
            "SELECT CAST(id AS varchar) FROM zones WHERE domain='agent.example'",
            &[],
        )
        .await
        .unwrap()
        .get::<_, String>(0);
    let (st, _, raw) = call!(
        app,
        put,
        &format!("/api/v1/agents/{id}/zones"),
        Some(&t),
        j(serde_json::json!({"zone_ids":[zid]}))
    );
    assert_eq!(st, 200, "{raw}");

    // heartbeat needs the agent's own token and returns the desired version
    let hb = || serde_json::json!({"name":"a1","addr":"10.0.0.5:5353"});
    let (st, body, _) = call!(app, post, "/api/v1/agents/heartbeat", Some(&tokn), j(hb()));
    assert_eq!(st, 200);
    assert!(body["desired_version"].as_i64().unwrap() >= 1);
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/agents/heartbeat",
        Some("wrong"),
        j(hb())
    );
    assert_eq!(st, 401);

    // signed, versioned bundle; wrong token refused
    let (st, _, _) = call!(
        app,
        get,
        &format!("/api/v1/agents/{id}/bundle"),
        Some("wrong"),
        None
    );
    assert_eq!(st, 401);
    let (st, b1, raw) = call!(
        app,
        get,
        &format!("/api/v1/agents/{id}/bundle"),
        Some(&tokn),
        None
    );
    assert_eq!(st, 200, "{raw}");
    let files: Vec<(String, String)> = b1["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["name"].as_str().unwrap().into(),
                f["content"].as_str().unwrap().into(),
            )
        })
        .collect();
    let v1 = b1["version"].as_i64().unwrap();
    assert!(
        files
            .iter()
            .any(|(n, c)| n == "named.toml" && c.contains("@ZONE_DIR@/zone.agent.example")),
        "paths are templated"
    );
    assert!(files.iter().any(|(n, _)| n == "zone.agent.example"));
    assert_eq!(b1["hash"], ext::bundle_hash(&files));
    assert_eq!(
        b1["signature"],
        ext::sign_bundle(&key, v1, b1["hash"].as_str().unwrap(), &files),
        "agent can verify with its key"
    );

    // a change publishes a new version; unchanged content keeps the version
    let (_, b1b, _) = call!(
        app,
        get,
        &format!("/api/v1/agents/{id}/bundle"),
        Some(&tokn),
        None
    );
    assert_eq!(b1b["version"], b1["version"]);
    call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/records"),
        Some(&t),
        j(serde_json::json!({"name":"w","record_type":"A","value":"192.0.2.1","ttl":60}))
    );
    let (_, b2, _) = call!(
        app,
        get,
        &format!("/api/v1/agents/{id}/bundle"),
        Some(&tokn),
        None
    );
    assert!(b2["version"].as_i64().unwrap() > v1);

    // status before ack: behind; after ack: in sync; failed ack is visible
    let (_, list, _) = call!(app, get, "/api/v1/agents", Some(&t), None);
    assert_eq!(list[0]["in_sync"], false);
    let (st, _, _) = call!(
        app,
        post,
        &format!("/api/v1/agents/{id}/ack"),
        Some(&tokn),
        j(serde_json::json!({"version": b2["version"], "ok": true}))
    );
    assert_eq!(st, 200);
    let (_, list, _) = call!(app, get, "/api/v1/agents", Some(&t), None);
    assert_eq!(
        (
            list[0]["in_sync"].clone(),
            list[0]["applied_version"].clone()
        ),
        (serde_json::json!(true), b2["version"].clone())
    );
    call!(
        app,
        post,
        &format!("/api/v1/agents/{id}/ack"),
        Some(&tokn),
        j(serde_json::json!({"version": 99, "ok": false, "error": "disk full"}))
    );
    let (_, list, _) = call!(app, get, "/api/v1/agents", Some(&t), None);
    assert_eq!(list[0]["last_error"], "disk full");
    assert_eq!(
        list[0]["applied_version"], b2["version"],
        "a failed apply never advances the applied version"
    );

    // push = sync request delivered through the next heartbeat, cleared by the ack
    let (st, body, _) = call!(
        app,
        post,
        "/api/v1/config/push",
        Some(&t),
        j(serde_json::json!({"agent_id": id, "zone_id": "", "zone_config": {}}))
    );
    assert_eq!(
        (st, body["success"].clone()),
        (202, serde_json::json!(true))
    );
    let (_, hbb, _) = call!(app, post, "/api/v1/agents/heartbeat", Some(&tokn), j(hb()));
    assert_eq!(hbb["sync_requested"], true);
    call!(
        app,
        post,
        &format!("/api/v1/agents/{id}/ack"),
        Some(&tokn),
        j(serde_json::json!({"version": b2["version"]}))
    );
    let (_, hbb, _) = call!(app, post, "/api/v1/agents/heartbeat", Some(&tokn), j(hb()));
    assert_eq!(hbb["sync_requested"], false);
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/config/push",
        Some(&t),
        j(
            serde_json::json!({"agent_id": Uuid::new_v4().to_string(), "zone_id": "", "zone_config": {}})
        )
    );
    assert_eq!(st, 404);

    // disabling revokes access to heartbeat, bundle and ack; re-enabling restores it
    let (st, _, _) = call!(
        app,
        put,
        &format!("/api/v1/agents/{id}"),
        Some(&t),
        j(serde_json::json!({"enabled": false}))
    );
    assert_eq!(st, 200);
    for uri in [format!("/api/v1/agents/{id}/bundle")] {
        let (st, _, _) = call!(app, get, &uri, Some(&tokn), None);
        assert_eq!(st, 401, "disabled agent must be refused");
    }
    let (st, _, _) = call!(app, post, "/api/v1/agents/heartbeat", Some(&tokn), j(hb()));
    assert_eq!(st, 404);
    let (_, list, _) = call!(app, get, "/api/v1/agents", Some(&t), None);
    assert_eq!(
        (list[0]["enabled"].clone(), list[0]["online"].clone()),
        (serde_json::json!(false), serde_json::json!(false))
    );
    call!(
        app,
        put,
        &format!("/api/v1/agents/{id}"),
        Some(&t),
        j(serde_json::json!({"enabled": true}))
    );
    let (st, _, _) = call!(
        app,
        get,
        &format!("/api/v1/agents/{id}/bundle"),
        Some(&tokn),
        None
    );
    assert_eq!(st, 200);
    // a non-admin cannot toggle agents
    let u = add_user(&env.state, "plain", "plain-pass-12", "user").await;
    let (st, _, _) = call!(
        app,
        put,
        &format!("/api/v1/agents/{id}"),
        Some(&env.token(&u, "user")),
        j(serde_json::json!({"enabled": false}))
    );
    assert_eq!(st, 403);
    env.cleanup().await;
}

#[actix_web::test]
async fn audit_trail_records_mutations() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    make_zone(&env, &app, &t, "audit.example").await;
    let (st, body, _) = call!(app, get, "/api/v1/audit/logs", Some(&t), None);
    assert_eq!(st, 200);
    let actions: Vec<String> = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap().to_string())
        .collect();
    assert!(actions.contains(&"create_zone".to_string()), "{actions:?}");
    let entry = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["action"] == "create_zone")
        .unwrap();
    // The audit UI reads camelCase fields; keep the JSON contract aligned.
    for field in [
        "id",
        "userId",
        "resourceType",
        "resourceId",
        "details",
        "ipAddress",
        "createdAt",
    ] {
        assert!(
            entry.get(field).is_some(),
            "audit entry is missing {field}: {entry}"
        );
    }
    assert_eq!(entry["resourceType"], "zone");
    env.cleanup().await;
}

#[actix_web::test]
async fn roles_viewer_is_read_only_and_create_user_honours_role() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let tadmin = env.token(&env.admin, "admin");

    // roles offered by the dashboard are accepted on create; junk is not
    let (st, body, raw) = call!(
        app,
        post,
        "/api/v1/users",
        Some(&tadmin),
        j(
            serde_json::json!({"username":"vera","password":"viewer-pass-1","role":"viewer","email":"vera@example.com"})
        )
    );
    assert_eq!(st, 201, "{raw}");
    assert_eq!(body["role"], "viewer");
    assert_eq!(body["email"], "vera@example.com");
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/users",
        Some(&tadmin),
        j(
            serde_json::json!({"username":"bademail","password":"viewer-pass-1","email":"not-an-email"})
        )
    );
    assert_eq!(st, 400, "invalid email must be rejected");
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/users",
        Some(&tadmin),
        j(
            serde_json::json!({"username":"othermail","password":"viewer-pass-1","email":"VERA@example.com"})
        )
    );
    assert_eq!(st, 409, "email uniqueness must ignore case");
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/users",
        Some(&tadmin),
        j(serde_json::json!({"username":"zed","password":"zed-pass-1234","role":"superuser"}))
    );
    assert_eq!(st, 400);
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/users",
        Some(&tadmin),
        j(serde_json::json!({"username":"ed","password":"editor-pass-1","role":"editor"}))
    );
    assert_eq!(st, 400, "username too short");
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/users",
        Some(&tadmin),
        j(serde_json::json!({"username":"edie","password":"editor-pass-1","role":"editor"}))
    );
    assert_eq!(st, 201);
    // default role stays "user"
    let (_, body, _) = call!(
        app,
        post,
        "/api/v1/users",
        Some(&tadmin),
        j(serde_json::json!({"username":"plain","password":"plain-pass-12"}))
    );
    assert_eq!(body["role"], "user");

    // an admin may edit username and role in one request, but not demote themselves
    let (_, list, _) = call!(app, get, "/api/v1/users", Some(&tadmin), None);
    let vera = list
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == "vera")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (st, _, _) = call!(
        app,
        put,
        &format!("/api/v1/users/{vera}"),
        Some(&tadmin),
        j(serde_json::json!({"username":"vera2","role":"viewer","email":"vera2@example.com"}))
    );
    assert_eq!(st, 200);
    let (_, me, _) = call!(
        app,
        get,
        &format!("/api/v1/users/{vera}"),
        Some(&tadmin),
        None
    );
    assert_eq!(me["username"], "vera2");
    assert_eq!(me["email"], "vera2@example.com");
    let (_, list, _) = call!(app, get, "/api/v1/users", Some(&tadmin), None);
    let listed = list
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == "vera2")
        .unwrap();
    assert_eq!(listed["email"], "vera2@example.com");
    assert!(
        !listed["createdAt"].as_str().unwrap_or("").is_empty(),
        "the Users page reads createdAt: {listed}"
    );
    assert!(listed.get("role").is_some() && listed.get("id").is_some());
    let (st, _, _) = call!(
        app,
        put,
        &format!("/api/v1/users/{}", env.admin),
        Some(&tadmin),
        j(serde_json::json!({"role":"viewer"}))
    );
    assert_eq!(st, 400);

    // viewer: reads fine, every write refused (even on a zone it owns)
    let tv = env.token(&vera, "viewer");
    let owned = Uuid::new_v4().to_string();
    env.state.db.execute("INSERT INTO zones (id, domain, owner) VALUES ($1::text::uuid, 'viewer.example', $2::text::uuid)", &[&owned, &vera]).await.unwrap();
    let (st, _, _) = call!(app, get, "/api/v1/zones", Some(&tv), None);
    assert_eq!(st, 200);
    let (st, _, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{owned}/records"),
        Some(&tv),
        None
    );
    assert_eq!(st, 200);
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/zones",
        Some(&tv),
        j(serde_json::json!({"domain":"mine.example"}))
    );
    assert_eq!(st, 403);
    let (st, _, _) = call!(
        app,
        post,
        &format!("/api/v1/zones/{owned}/records"),
        Some(&tv),
        j(serde_json::json!({"name":"w","record_type":"A","value":"192.0.2.1","ttl":60}))
    );
    assert_eq!(st, 403);
    let (st, _, _) = call!(
        app,
        delete,
        &format!("/api/v1/zones/{owned}"),
        Some(&tv),
        None
    );
    assert_eq!(st, 403);
    // ...but it can still manage its own session
    let (st, _, _) = call!(app, post, "/api/v1/auth/logout", Some(&tv), None);
    assert_eq!(st, 200);
    env.cleanup().await;
}

#[actix_web::test]
async fn agents_can_be_deleted_and_import_accepts_priority() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let (_, reg, _) = call!(
        app,
        post,
        "/api/v1/agents/register",
        Some(&t),
        j(serde_json::json!({"name":"a","addr":"10.0.0.9:1"}))
    );
    let id = reg["id"].as_str().unwrap().to_string();
    let (st, _, _) = call!(app, delete, &format!("/api/v1/agents/{id}"), Some(&t), None);
    assert_eq!(st, 200);
    let (st, _, _) = call!(app, delete, &format!("/api/v1/agents/{id}"), Some(&t), None);
    assert_eq!(st, 404);
    let token = reg["token"].as_str().unwrap().to_string();
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/agents/heartbeat",
        Some(&token),
        j(serde_json::json!({"name":"a","addr":"10.0.0.9:1"}))
    );
    assert_eq!(st, 404, "a deleted agent can no longer check in");

    let zid = make_zone(&env, &app, &t, "prio.example").await;
    let (st, body, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/import"),
        Some(&t),
        j(
            serde_json::json!({"records":[{"name":"@","record_type":"MX","value":"mail.prio.example.","ttl":300,"priority":10}]})
        )
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(body["imported"], 1);
    assert!(
        std::fs::read_to_string(env.zone_file("prio.example"))
            .unwrap()
            .contains(" MX 10 mail.prio.example.")
    );
    env.cleanup().await;
}

#[actix_web::test]
async fn zone_sharing_levels() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let alice = add_user(&env.state, "alice", "alice-pass-1", "user").await;
    let bob = add_user(&env.state, "bob", "bob-pass-123", "user").await;
    let carol = add_user(&env.state, "carol", "carol-pass-1", "user").await;
    let (ta, tb, tc) = (
        env.token(&alice, "user"),
        env.token(&bob, "user"),
        env.token(&carol, "user"),
    );
    let zid = make_zone(&env, &app, &ta, "shared.example").await;
    let rec = j(serde_json::json!({"name":"w","record_type":"A","value":"192.0.2.1","ttl":60}));

    // nobody but the owner has access yet
    let (st, _, _) = call!(app, get, &format!("/api/v1/zones/{zid}"), Some(&tb), None);
    assert_eq!(st, 403);
    // owner shares: bob = editor, carol = viewer
    for (u, r) in [("bob", "editor"), ("carol", "viewer")] {
        let (st, _, raw) = call!(
            app,
            put,
            &format!("/api/v1/zones/{zid}/members"),
            Some(&ta),
            j(serde_json::json!({"username": u, "role": r}))
        );
        assert_eq!(st, 200, "{raw}");
    }
    // sharing with the owner / bogus role / unknown user
    let (st, _, _) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zid}/members"),
        Some(&ta),
        j(serde_json::json!({"username": "alice", "role": "editor"}))
    );
    assert_eq!(st, 400);
    let (st, _, _) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zid}/members"),
        Some(&ta),
        j(serde_json::json!({"username": "bob", "role": "owner"}))
    );
    assert_eq!(st, 400);
    let (st, _, _) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zid}/members"),
        Some(&ta),
        j(serde_json::json!({"username": "ghost", "role": "viewer"}))
    );
    assert_eq!(st, 404);

    // listing shows the shared zone with the caller's role
    let (_, zl, _) = call!(app, get, "/api/v1/zones", Some(&tb), None);
    assert_eq!(
        (
            zl["data"][0]["domain"].clone(),
            zl["data"][0]["access"].clone()
        ),
        (
            serde_json::json!("shared.example"),
            serde_json::json!("editor")
        )
    );
    let (_, zl, _) = call!(app, get, "/api/v1/zones", Some(&tc), None);
    assert_eq!(zl["data"][0]["access"], "viewer");

    // editor: read + write records and geo rules, but not rename/delete/share
    let (st, r, _) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/records"),
        Some(&tb),
        rec.clone()
    );
    assert_eq!(st, 201);
    let rid = r["id"].as_str().unwrap().to_string();
    let (st, _, _) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zid}/records/{rid}"),
        Some(&tb),
        j(serde_json::json!({"ttl": 120}))
    );
    assert_eq!(st, 200);
    let (st, _, _) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zid}"),
        Some(&tb),
        j(serde_json::json!({"domain": "renamed.example"}))
    );
    assert_eq!(st, 403);
    let (st, _, _) = call!(
        app,
        delete,
        &format!("/api/v1/zones/{zid}"),
        Some(&tb),
        None
    );
    assert_eq!(st, 403);
    let (st, _, _) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zid}/members"),
        Some(&tb),
        j(serde_json::json!({"username": "carol", "role": "editor"}))
    );
    assert_eq!(st, 403);
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/georules",
        Some(&tb),
        j(
            serde_json::json!({"zone_id": zid,"match_type":"default","match_value":"","target":"192.0.2.9"})
        )
    );
    assert_eq!(st, 201);
    let (_, gl, _) = call!(app, get, "/api/v1/georules", Some(&tb), None);
    assert_eq!(
        gl.as_array().unwrap().len(),
        1,
        "shared zone's rules are listed for members"
    );

    // viewer: read only
    let (st, _, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{zid}/records"),
        Some(&tc),
        None
    );
    assert_eq!(st, 200);
    let (st, _, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{zid}/export"),
        Some(&tc),
        None
    );
    assert_eq!(st, 200);
    let (st, _, _) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/records"),
        Some(&tc),
        rec.clone()
    );
    assert_eq!(st, 403);
    let (st, _, _) = call!(
        app,
        delete,
        &format!("/api/v1/zones/{zid}/records/{rid}"),
        Some(&tc),
        None
    );
    assert_eq!(st, 403);
    let (st, _, _) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/import"),
        Some(&tc),
        j(serde_json::json!({"records":[{"name":"x","record_type":"A","value":"192.0.2.3"}]}))
    );
    assert_eq!(st, 403);

    // members list is visible to members; unshare takes effect immediately
    let (_, ml, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{zid}/members"),
        Some(&tc),
        None
    );
    assert_eq!(ml.as_array().unwrap().len(), 2);
    let member_page = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/api/v1/zones/{zid}/members?limit=1&q=bob&sort=username&order=desc"
            ))
            .insert_header(("Authorization", format!("Bearer {tc}")))
            .to_request(),
    )
    .await;
    assert_eq!(member_page.status(), 200);
    assert_eq!(member_page.headers().get("X-Total-Count").unwrap(), "1");
    let member_page_body: serde_json::Value = test::read_body_json(member_page).await;
    assert_eq!(member_page_body.as_array().unwrap()[0]["username"], "bob");
    let (st, _, _) = call!(
        app,
        delete,
        &format!("/api/v1/zones/{zid}/members/{bob}"),
        Some(&ta),
        None
    );
    assert_eq!(st, 200);
    let (st, _, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{zid}/records"),
        Some(&tb),
        None
    );
    assert_eq!(st, 403);
    env.cleanup().await;
}

#[actix_web::test]
async fn zone_history_and_rollback() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let zid = make_zone(&env, &app, &t, "hist.example").await;
    let url = format!("/api/v1/zones/{zid}/records");
    let (_, r1, _) = call!(
        app,
        post,
        &url,
        Some(&t),
        j(serde_json::json!({"name":"www","record_type":"A","value":"192.0.2.1","ttl":60}))
    );
    let (_, revs, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{zid}/revisions"),
        Some(&t),
        None
    );
    let good = revs[0]["id"].as_str().unwrap().to_string();
    assert_eq!(revs[0]["record_count"], 4, "2 NS + SOA + the new A");
    // a bad edit, then rollback
    call!(
        app,
        delete,
        &format!("{url}/{}", r1["id"].as_str().unwrap()),
        Some(&t),
        None
    );
    call!(
        app,
        post,
        &url,
        Some(&t),
        j(serde_json::json!({"name":"oops","record_type":"A","value":"192.0.2.66","ttl":60}))
    );
    assert!(
        std::fs::read_to_string(env.zone_file("hist.example"))
            .unwrap()
            .contains("192.0.2.66")
    );
    let (st, _, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/revisions/{good}/restore"),
        Some(&t),
        None
    );
    assert_eq!(st, 200, "{raw}");
    let zone = std::fs::read_to_string(env.zone_file("hist.example")).unwrap();
    assert!(
        zone.contains("192.0.2.1") && !zone.contains("192.0.2.66"),
        "{zone}"
    );
    let (_, revs2, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{zid}/revisions"),
        Some(&t),
        None
    );
    assert!(
        revs2.as_array().unwrap().len() > revs.as_array().unwrap().len(),
        "restore is itself recorded (and undoable)"
    );
    // unknown revision, other tenant
    let (st, _, _) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/revisions/{}/restore", Uuid::new_v4()),
        Some(&t),
        None
    );
    assert_eq!(st, 404);
    let bob = add_user(&env.state, "bob", "bob-pass-123", "user").await;
    let (st, _, _) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/revisions/{good}/restore"),
        Some(&env.token(&bob, "user")),
        None
    );
    assert_eq!(st, 403);
    let (st, _, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{zid}/revisions"),
        Some(&env.token(&bob, "user")),
        None
    );
    assert_eq!(st, 403);
    env.cleanup().await;
}

#[actix_web::test]
async fn revision_restore_restores_renamed_domain_and_reports_snapshot_failures() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let token = env.token(&env.admin, "admin");
    let zone_id = make_zone(&env, &app, &token, "restore-old.example").await;
    let record_url = format!("/api/v1/zones/{zone_id}/records");
    let (status, record, raw) = call!(
        app,
        post,
        &record_url,
        Some(&token),
        j(serde_json::json!({"name":"www","record_type":"A","value":"192.0.2.77","ttl":300}))
    );
    assert_eq!(status, 201, "{raw}");
    assert_eq!(record["revision_snapshot"], "saved");
    let (_, revisions, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{zone_id}/revisions"),
        Some(&token),
        None
    );
    let target = revisions
        .as_array()
        .unwrap()
        .iter()
        .find(|revision| {
            revision["domain"] == "restore-old.example" && revision["record_count"] == 4
        })
        .expect("revision containing the added record under the old domain")["id"]
        .as_str()
        .unwrap()
        .to_string();

    let (status, _, raw) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zone_id}"),
        Some(&token),
        j(serde_json::json!({"domain":"restore-new.example"}))
    );
    assert_eq!(status, 200, "{raw}");
    let (status, restored, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zone_id}/revisions/{target}/restore"),
        Some(&token),
        None
    );
    assert_eq!(status, 200, "{raw}");
    assert_eq!(restored["revision_snapshot"], "saved");
    let (_, current, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{zone_id}"),
        Some(&token),
        None
    );
    assert_eq!(current["data"]["domain"], "restore-old.example");
    assert!(env.zone_file("restore-old.example").exists());
    assert!(!env.zone_file("restore-new.example").exists());

    env.state.db.batch_execute(
        "CREATE FUNCTION reject_revision_snapshot() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'simulated snapshot failure'; END $$; \
         CREATE TRIGGER reject_revision_snapshot BEFORE INSERT ON zone_revisions FOR EACH ROW EXECUTE FUNCTION reject_revision_snapshot();"
    ).await.unwrap();
    let (status, response, raw) = call!(
        app,
        post,
        &record_url,
        Some(&token),
        j(
            serde_json::json!({"name":"failure-visible","record_type":"A","value":"192.0.2.88","ttl":300})
        )
    );
    assert_eq!(
        status, 201,
        "record publication succeeds although history write failed: {raw}"
    );
    assert_eq!(
        response["revision_snapshot"], "failed",
        "the mutation caller must see the lost history snapshot"
    );
    let count: i64 = env.state.db.query_one(
        "SELECT count(*) FROM records WHERE CAST(zone_id AS varchar)=$1 AND name='failure-visible'", &[&zone_id]
    ).await.unwrap().get(0);
    assert_eq!(
        count, 1,
        "snapshot failure does not roll back an already published mutation"
    );
    let (status, response, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zone_id}/revisions/{target}/restore"),
        Some(&token),
        None
    );
    assert_eq!(
        status, 503,
        "restore must stop when its recovery snapshot fails: {raw}"
    );
    assert_eq!(response["revision_snapshot"], "failed");
    let unchanged: i64 = env.state.db.query_one(
        "SELECT count(*) FROM records WHERE CAST(zone_id AS varchar)=$1 AND name='failure-visible'", &[&zone_id]
    ).await.unwrap().get(0);
    assert_eq!(
        unchanged, 1,
        "failed pre-restore snapshot must leave the zone untouched"
    );
    env.cleanup().await;
}

/// Minimal UDP resolver that answers TXT queries with a fixed value.
async fn fake_txt_resolver(txt: &'static str) -> std::net::SocketAddr {
    use hickory_proto::op::Message;
    use hickory_proto::rr::{RData, Record, rdata::TXT};
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let Ok(q) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            let mut r = Message::response(q.id(), q.op_code());
            for qq in q.queries() {
                r.add_query(qq.clone());
                r.add_answer(Record::from_rdata(
                    qq.name().clone(),
                    60,
                    RData::TXT(TXT::new(vec![txt.to_string()])),
                ));
            }
            let _ = sock.send_to(&r.to_vec().unwrap(), from).await;
        }
    });
    addr
}

#[actix_web::test]
async fn domain_verification_gates_publication() {
    let Some(mut env) = setup().await else { return };
    env.state.verify_domains = true;
    env.full.inner = env.state.clone();
    let alice = add_user(&env.state, "alice", "alice-pass-1", "user").await;
    let ta = env.token(&alice, "user");
    let tadmin = env.token(&env.admin, "admin");

    // non-admin zones are pending: created, not served
    let app = app!(env);
    let (st, z, raw) = call!(
        app,
        post,
        "/api/v1/zones",
        Some(&ta),
        j(serde_json::json!({"domain":"pending.example"}))
    );
    assert_eq!(st, 201, "{raw}");
    assert_eq!(z["status"], "pending");
    let token = z["verification"]["value"].as_str().unwrap().to_string();
    assert_eq!(
        z["verification"]["name"],
        "_outis-challenge.pending.example"
    );
    assert!(
        !env.zone_file("pending.example").exists(),
        "unverified zone must not be served"
    );
    let zid = z["id"].as_str().unwrap().to_string();
    // admins are trusted
    let (_, az, _) = call!(
        app,
        post,
        "/api/v1/zones",
        Some(&tadmin),
        j(serde_json::json!({"domain":"admin.example"}))
    );
    assert_eq!(az["status"], "active");
    assert!(env.zone_file("admin.example").is_file());

    // wrong token published -> refused, still not served
    let resolver_bad = fake_txt_resolver("outis-verify=nope").await;
    env.state.verify_resolver = resolver_bad;
    env.full.inner = env.state.clone();
    let app = app!(env);
    let (st, _, _) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/verify"),
        Some(&ta),
        None
    );
    assert_eq!(st, 422);
    assert!(!env.zone_file("pending.example").exists());
    // correct token -> activated and published; someone else cannot trigger it
    let leaked: &'static str = Box::leak(token.into_boxed_str());
    env.state.verify_resolver = fake_txt_resolver(leaked).await;
    env.full.inner = env.state.clone();
    let app = app!(env);
    let bob = add_user(&env.state, "bob", "bob-pass-123", "user").await;
    let (st, _, _) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/verify"),
        Some(&env.token(&bob, "user")),
        None
    );
    assert_eq!(st, 403);
    let (st, body, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/verify"),
        Some(&ta),
        None
    );
    assert_eq!(
        (st, body["status"].clone()),
        (200, serde_json::json!("active")),
        "{raw}"
    );
    assert!(env.zone_file("pending.example").is_file());
    env.cleanup().await;
}

#[actix_web::test]
async fn mfa_enrol_login_and_disable() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let name = format!("mfa-{}", Uuid::new_v4().simple());
    let uid = add_user(&env.state, &name, "mfa-password-1", "user").await;
    let tok = env.token(&uid, "user");
    let login = |otp: Option<&str>| {
        let mut b = serde_json::json!({"username": name, "password": "mfa-password-1"});
        if let Some(o) = otp {
            b["otp"] = serde_json::json!(o);
        }
        j(b)
    };
    let (st, _, _) = call!(app, post, "/api/v1/auth/login", None::<&str>, login(None));
    assert_eq!(st, 200, "no MFA yet");

    let (st, setup, _) = call!(app, post, "/api/v1/auth/mfa/setup", Some(&tok), None);
    assert_eq!(st, 200);
    let secret = data_encoding::BASE32_NOPAD
        .decode(setup["secret"].as_str().unwrap().as_bytes())
        .unwrap();
    assert!(
        setup["otpauth_url"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/")
    );
    // not active until a valid code proves the app works
    let (st, _, _) = call!(app, post, "/api/v1/auth/login", None::<&str>, login(None));
    assert_eq!(st, 200);
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/auth/mfa/enable",
        Some(&tok),
        j(serde_json::json!({"code": "000000"}))
    );
    assert_eq!(st, 400);
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/auth/mfa/enable",
        Some(&tok),
        j(serde_json::json!({"code": ext::totp_now(&secret)}))
    );
    assert_eq!(st, 200);

    // now a password alone is not enough
    let (st, b, _) = call!(app, post, "/api/v1/auth/login", None::<&str>, login(None));
    assert_eq!(
        (st, b["error"].clone()),
        (401, serde_json::json!("mfa_required"))
    );
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/auth/login",
        None::<&str>,
        login(Some("123456"))
    );
    assert_eq!(st, 401);
    let (st, b, _) = call!(
        app,
        post,
        "/api/v1/auth/login",
        None::<&str>,
        login(Some(&ext::totp_now(&secret)))
    );
    assert_eq!(st, 200);
    assert!(b["token"].is_string());
    let tok_after_enable = b["token"].as_str().unwrap().to_string();

    // enabling MFA invalidated the session that existed before it
    let (st, _, _) = call!(app, get, "/api/v1/auth/me", Some(&tok), None);
    assert_eq!(
        st, 401,
        "pre-MFA access token must not survive MFA enablement"
    );

    // turning it off needs password AND code
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/auth/mfa/disable",
        Some(&tok_after_enable),
        j(serde_json::json!({"code": ext::totp_now(&secret), "password": "wrong"}))
    );
    assert_eq!(st, 403);
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/auth/mfa/disable",
        Some(&tok_after_enable),
        j(serde_json::json!({"code": ext::totp_now(&secret), "password": "mfa-password-1"}))
    );
    assert_eq!(st, 200);
    let (st, _, _) = call!(app, get, "/api/v1/auth/me", Some(&tok_after_enable), None);
    assert_eq!(
        st, 401,
        "disabling MFA must invalidate the pre-change session"
    );
    let (st, _, _) = call!(app, post, "/api/v1/auth/login", None::<&str>, login(None));
    assert_eq!(st, 200);
    env.cleanup().await;
}

#[actix_web::test]
async fn database_errors_do_not_look_like_missing_zones_or_agents() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let zid = make_zone(&env, &app, &t, "db-error.example").await;
    let (st, reg, raw) = call!(
        app,
        post,
        "/api/v1/agents/register",
        Some(&t),
        j(serde_json::json!({"name":"db-error","addr":"10.0.0.44:5353"}))
    );
    assert_eq!(st, 201, "{raw}");
    let (aid, atok) = (
        reg["id"].as_str().unwrap().to_string(),
        reg["token"].as_str().unwrap().to_string(),
    );
    let hb = || serde_json::json!({"id": aid, "addr": "10.0.0.44:5353"});

    env.state
        .db
        .batch_execute("ALTER TABLE nameservers RENAME TO nameservers_gone")
        .await
        .unwrap();
    let (st, _, raw) = call!(app, get, &format!("/api/v1/zones/{zid}"), Some(&t), None);
    assert_eq!(
        st, 500,
        "a nameserver read failure is not a missing zone: {raw}"
    );
    env.state
        .db
        .batch_execute("ALTER TABLE nameservers_gone RENAME TO nameservers")
        .await
        .unwrap();

    env.state
        .db
        .batch_execute("ALTER TABLE agents RENAME TO agents_gone")
        .await
        .unwrap();
    let (st, _, raw) = call!(app, post, "/api/v1/agents/heartbeat", Some(&atok), j(hb()));
    assert_eq!(
        st, 500,
        "an agent read failure is not an authentication failure: {raw}"
    );
    env.state
        .db
        .batch_execute("ALTER TABLE agents_gone RENAME TO agents")
        .await
        .unwrap();

    assert_eq!(
        call!(app, get, &format!("/api/v1/zones/{zid}"), Some(&t), None).0,
        200
    );
    assert_eq!(
        call!(app, post, "/api/v1/agents/heartbeat", Some(&atok), j(hb())).0,
        200
    );
    env.cleanup().await;
}

#[actix_web::test]
async fn audit_pagination_filters_and_retention() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    for i in 0..7 {
        env.state.db.execute("INSERT INTO audit_logs (id, action, resource_type, created_at) VALUES ($1::text::uuid, $2, 'test', now() - ($3::int * interval '1 day'))",
            &[&Uuid::new_v4().to_string(), &if i % 2 == 0 { "even" } else { "odd" }, &(i * 100)]).await.unwrap();
    }
    let page = |q: &str| {
        let uri = format!("/api/v1/audit/logs?{q}");
        uri
    };
    let (st, b, _) = call!(
        app,
        get,
        &page("limit=3&offset=0&resource_type=test"),
        Some(&t),
        None
    );
    assert_eq!(st, 200);
    assert_eq!(b["data"].as_array().unwrap().len(), 3);
    let (_, b2, _) = call!(
        app,
        get,
        &page("limit=3&offset=3&resource_type=test"),
        Some(&t),
        None
    );
    assert_ne!(b["data"][0]["id"], b2["data"][0]["id"], "pages differ");
    let (_, even, _) = call!(
        app,
        get,
        &page("action=even&resource_type=test"),
        Some(&t),
        None
    );
    assert_eq!(even["data"].as_array().unwrap().len(), 4);
    // total count header
    let r = test::TestRequest::get()
        .uri(&page("limit=1&resource_type=test"))
        .insert_header(("Authorization", format!("Bearer {t}")))
        .to_request();
    let resp = test::call_service(&app, r).await;
    assert_eq!(resp.headers().get("X-Total-Count").unwrap(), "7");
    // limit is clamped, non-admins refused
    let (_, big, _) = call!(
        app,
        get,
        &page("limit=100000&resource_type=test"),
        Some(&t),
        None
    );
    assert_eq!(big["data"].as_array().unwrap().len(), 7);
    let u = add_user(&env.state, "plain", "plain-pass-12", "user").await;
    let (st, _, _) = call!(
        app,
        get,
        "/api/v1/audit/logs",
        Some(&env.token(&u, "user")),
        None
    );
    assert_eq!(st, 403);
    // retention removes only what is older than the window
    let removed = ext::purge_audit(&env.state.db, 250).await.unwrap();
    assert_eq!(removed, 4, "entries at 300, 400, 500, 600 days");
    env.cleanup().await;
}

#[actix_web::test]
async fn zone_rename_rewrites_soa_and_ecs_flag() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let zid = make_zone(&env, &app, &t, "old.example").await;
    let (st, _, raw) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zid}"),
        Some(&t),
        j(serde_json::json!({"domain": "new.example", "ecs_enabled": true}))
    );
    assert_eq!(st, 200, "{raw}");
    let soa: String = env
        .state
        .db
        .query_one("SELECT value FROM records WHERE record_type='SOA'", &[])
        .await
        .unwrap()
        .get(0);
    assert!(
        !soa.contains("old.example") && soa.contains("hostmaster.new.example"),
        "{soa}"
    );
    let zone = std::fs::read_to_string(env.zone_file("new.example")).unwrap();
    assert!(
        zone.contains("hostmaster.new.example.") && !zone.contains("old.example"),
        "{zone}"
    );
    assert!(!env.zone_file("old.example").exists());
    let (_, g, _) = call!(app, get, &format!("/api/v1/zones/{zid}"), Some(&t), None);
    assert_eq!(g["data"]["ecs_enabled"], true);
    env.cleanup().await;
}

#[actix_web::test]
async fn zone_creation_rolls_back_when_default_records_fail() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    env.state.db.batch_execute(
        "CREATE FUNCTION reject_soa() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN IF NEW.record_type = 'SOA' THEN RAISE EXCEPTION 'simulated SOA insert failure'; END IF; RETURN NEW; END $$; \
         CREATE TRIGGER reject_soa BEFORE INSERT ON records FOR EACH ROW EXECUTE FUNCTION reject_soa();",
    ).await.unwrap();

    let (st, _, raw) = call!(
        app,
        post,
        "/api/v1/zones",
        Some(&t),
        j(serde_json::json!({"domain":"rollback.example"}))
    );
    assert_eq!(st, 500, "{raw}");
    let zones: i64 = env
        .state
        .db
        .query_one("SELECT count(*) FROM zones", &[])
        .await
        .unwrap()
        .get(0);
    let records: i64 = env
        .state
        .db
        .query_one("SELECT count(*) FROM records", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        zones, 0,
        "a failed default-record insert must not leave a zone behind"
    );
    assert_eq!(records, 0, "the NS insert must roll back with the zone");

    env.state
        .db
        .batch_execute("DROP TRIGGER reject_soa ON records; DROP FUNCTION reject_soa();")
        .await
        .unwrap();
    let (st, _, raw) = call!(
        app,
        post,
        "/api/v1/zones",
        Some(&t),
        j(serde_json::json!({"domain":"rollback.example"}))
    );
    assert_eq!(st, 201, "{raw}");
    env.cleanup().await;
}

#[actix_web::test]
async fn failed_zone_delete_publication_restores_the_zone() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let zid = make_zone(&env, &app, &t, "keepme.example").await;

    std::fs::remove_dir_all(env.dir.path()).unwrap();
    std::fs::write(env.dir.path(), b"not a directory").unwrap();
    let (st, body, raw) = call!(app, delete, &format!("/api/v1/zones/{zid}"), Some(&t), None);
    assert_eq!(st, 500, "{raw}");
    assert_eq!(body["error"], "publish_failed");
    let status: String = env
        .state
        .db
        .query_one(
            "SELECT status FROM zones WHERE CAST(id AS varchar) = $1",
            &[&zid],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        status, "active",
        "a failed delete must restore the previous status"
    );

    std::fs::remove_file(env.dir.path()).unwrap();
    std::fs::create_dir_all(env.dir.path()).unwrap();
    env.cleanup().await;
}

#[actix_web::test]
async fn dnssec_publication_fails_closed_when_a_key_file_is_missing() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let zid = make_zone(&env, &app, &t, "failclosed.example").await;
    let (st, key, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/dnssec/enable"),
        Some(&t),
        j(serde_json::json!({}))
    );
    assert_eq!(st, 201, "{raw}");
    let tag = key["keys"][0]["key_tag"].as_i64().unwrap();
    let key_file = env
        .dir
        .path()
        .join("dnssec-keys")
        .join(format!("failclosed.example.{tag}.pem"));
    assert!(key_file.is_file());
    let named_before = std::fs::read_to_string(env.dir.path().join("named.toml")).unwrap();
    let zone_before = std::fs::read_to_string(env.zone_file("failclosed.example")).unwrap();

    std::fs::remove_file(&key_file).unwrap();
    env.state.db.execute("UPDATE records SET value = '192.0.2.99' WHERE record_type = 'A' AND CAST(zone_id AS varchar) = $1", &[&zid]).await.unwrap();
    let (st, _, raw) = call!(app, post, "/api/v1/dns/generate", Some(&t), None);
    assert_eq!(
        st, 500,
        "publication must fail instead of serving the signed zone unsigned: {raw}"
    );
    assert_eq!(
        std::fs::read_to_string(env.dir.path().join("named.toml")).unwrap(),
        named_before
    );
    assert_eq!(
        std::fs::read_to_string(env.zone_file("failclosed.example")).unwrap(),
        zone_before
    );
    env.cleanup().await;
}

#[actix_web::test]
async fn agents_are_default_denied_and_only_receive_assigned_zones() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let admin = env.token(&env.admin, "admin");
    let z1 = make_zone(&env, &app, &admin, "agent-a.example").await;
    let _z2 = make_zone(&env, &app, &admin, "agent-b.example").await;

    let register = |name: &str, addr: &str| j(serde_json::json!({"name": name, "addr": addr}));
    let (st, a, raw) = call!(
        app,
        post,
        "/api/v1/agents/register",
        Some(&admin),
        register("edge-a", "10.0.0.1:53")
    );
    assert_eq!(st, 201, "{raw}");
    let (st, b, raw) = call!(
        app,
        post,
        "/api/v1/agents/register",
        Some(&admin),
        register("edge-b", "10.0.0.2:53")
    );
    assert_eq!(st, 201, "{raw}");
    let (aid, atok) = (a["id"].as_str().unwrap(), a["token"].as_str().unwrap());
    let (bid, btok) = (b["id"].as_str().unwrap(), b["token"].as_str().unwrap());

    let bundle = |id: &str, _token: &str| format!("/api/v1/agents/{id}/bundle");
    let (st, _empty, raw) = call!(app, get, &bundle(aid, atok), Some(atok), None);
    assert_eq!(st, 200, "{raw}");
    assert!(
        !raw.contains("agent-a.example") && !raw.contains("agent-b.example"),
        "unassigned agent must not receive zones: {raw}"
    );
    let (st, cfg, _) = call!(
        app,
        get,
        &format!("/api/v1/agents/{aid}/config"),
        Some(atok),
        None
    );
    assert_eq!(st, 200);
    assert_eq!(
        cfg["zones"].as_array().unwrap().len(),
        0,
        "legacy config endpoint must also default-deny"
    );

    let (st, assigned, raw) = call!(
        app,
        put,
        &format!("/api/v1/agents/{aid}/zones"),
        Some(&admin),
        j(serde_json::json!({"zone_ids":[z1]}))
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(assigned["zones"].as_array().unwrap().len(), 1);
    let (st, one, raw) = call!(app, get, &bundle(aid, atok), Some(atok), None);
    assert_eq!(st, 200, "{raw}");
    assert!(
        raw.contains("agent-a.example") && !raw.contains("agent-b.example"),
        "agent got another agent's zone: {raw}"
    );
    let (st, cfg, _) = call!(
        app,
        get,
        &format!("/api/v1/agents/{aid}/config"),
        Some(atok),
        None
    );
    assert_eq!(st, 200);
    assert_eq!(cfg["zones"].as_array().unwrap().len(), 1);
    assert_eq!(cfg["zones"][0]["domain"], "agent-a.example");
    assert!(
        one["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["name"] == "zone.agent-a.example")
    );

    let (st, empty, _) = call!(app, get, &bundle(bid, btok), Some(btok), None);
    assert_eq!(st, 200);
    assert!(
        !empty["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["name"].as_str().unwrap_or("").starts_with("zone.")),
        "unassigned agent received a zone file"
    );
    assert_eq!(
        call!(
            app,
            get,
            &format!("/api/v1/agents/{aid}/zones"),
            Some(atok),
            None
        )
        .0,
        401,
        "agents cannot administer assignments"
    );

    let (st, hb, raw) = call!(
        app,
        post,
        "/api/v1/agents/heartbeat",
        Some(atok),
        j(serde_json::json!({"id": aid, "name": "edge-a", "addr": "10.0.0.1:53"}))
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(hb["agent_id"], aid);
    assert_eq!(
        call!(
            app,
            post,
            "/api/v1/agents/heartbeat",
            Some(btok),
            j(serde_json::json!({"id": aid, "addr": "10.0.0.1:53"}))
        )
        .0,
        401
    );
    env.state
        .db
        .execute(
            "UPDATE agents SET token_sha256 = NULL WHERE CAST(id AS varchar) = $1",
            &[&aid],
        )
        .await
        .unwrap();
    let (st, hb, raw) = call!(
        app,
        post,
        "/api/v1/agents/heartbeat",
        Some(atok),
        j(serde_json::json!({"name": "edge-a", "addr": "10.0.0.1:53"}))
    );
    assert_eq!(st, 200, "legacy heartbeat must keep working: {raw}");
    assert_eq!(hb["agent_id"], aid);
    let fp: Option<String> = env
        .state
        .db
        .query_one(
            "SELECT token_sha256 FROM agents WHERE CAST(id AS varchar) = $1",
            &[&aid],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        fp.is_some(),
        "legacy authentication must upgrade to a token fingerprint"
    );
    env.cleanup().await;
}

#[actix_web::test]
async fn legacy_heartbeat_argon2_work_is_bounded_and_rate_limited() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let addr = "198.51.100.10:53";
    let wrong = Argon2::default()
        .hash_password(b"wrong-legacy-token", &generate_salt())
        .unwrap()
        .to_string();
    let right = Argon2::default()
        .hash_password(b"right-legacy-token", &generate_salt())
        .unwrap()
        .to_string();
    for i in 0..9 {
        let hash = if i == 8 { &right } else { &wrong };
        env.state.db.execute(
            "INSERT INTO agents (id, name, addr, token_hash, created_at) VALUES ($1::text::uuid, $2, $3, $4, now() - ($5::int * interval '1 second'))",
            &[&Uuid::new_v4().to_string(), &format!("legacy-{i}"), &addr, hash, &(8 - i)],
        ).await.unwrap();
    }
    // Only the eight oldest legacy rows are checked: the ninth row's (correct)
    // token must not be verified, otherwise a single request can force unbounded
    // Argon2 work by creating many agents with the same address.
    let req = test::TestRequest::post()
        .uri("/api/v1/agents/heartbeat")
        .peer_addr("198.51.100.77:5000".parse().unwrap())
        .insert_header(("Authorization", "Bearer right-legacy-token"))
        .set_json(serde_json::json!({"name": "legacy-8", "addr": addr}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);

    // Each address gets a fixed budget for legacy attempts, so even the bounded
    // eight verifications per request cannot be repeated indefinitely.
    let bucket = "agent-legacy:198.51.100.78";
    for _ in 0..20 {
        assert!(
            shared::limited(&env.state.db, bucket, 20, 60, || true)
                .await
                .is_none()
        );
    }
    let req = test::TestRequest::post()
        .uri("/api/v1/agents/heartbeat")
        .peer_addr("198.51.100.78:5000".parse().unwrap())
        .insert_header(("Authorization", "Bearer wrong-legacy-token"))
        .set_json(serde_json::json!({"name": "legacy-0", "addr": addr}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 429);
    env.cleanup().await;
}

#[actix_web::test]
async fn server_create_update_delete_are_audited_and_update_in_place() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let (st, created, raw) = call!(
        app,
        post,
        "/api/v1/servers",
        Some(&t),
        j(serde_json::json!({
            "name":"edge-one","address":"127.0.0.1","port":5353,"region":"eu","enabled":true,
            "dnssec":false,"enable_logging":true,"max_cache_ttl":3600,"min_cache_ttl":60
        }))
    );
    assert_eq!(st, 201, "{raw}");
    let id = created["id"].as_str().unwrap().to_string();
    let (st, updated, raw) = call!(
        app,
        put,
        &format!("/api/v1/servers/{id}"),
        Some(&t),
        j(serde_json::json!({
            "name":"edge-one-renamed","address":"127.0.0.1","port":5354,"region":"us","enabled":false,
            "dnssec":true,"enable_logging":false,"max_cache_ttl":7200,"min_cache_ttl":120
        }))
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(updated["id"], id);
    let (_, list, _) = call!(app, get, "/api/v1/servers", Some(&t), None);
    assert_eq!(
        list.as_array().unwrap().len(),
        1,
        "editing must not create a duplicate server"
    );
    let row = list[0].as_object().unwrap();
    assert_eq!(row["name"], "edge-one-renamed");
    assert_eq!(row["port"], 5354);
    assert_eq!(row["dnssec"], true);
    assert_eq!(row["enabled"], false);
    let (st, _, raw) = call!(
        app,
        delete,
        &format!("/api/v1/servers/{id}"),
        Some(&t),
        None
    );
    assert_eq!(st, 200, "{raw}");
    let (st, logs, _) = call!(
        app,
        get,
        "/api/v1/audit/logs?resource_type=server&limit=20",
        Some(&t),
        None
    );
    assert_eq!(st, 200);
    let actions: Vec<String> = logs["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|l| l["action"].as_str().map(str::to_string))
        .collect();
    for action in ["create_server", "update_server", "delete_server"] {
        assert!(
            actions.contains(&action.to_string()),
            "missing {action}: {actions:?}"
        );
    }
    env.cleanup().await;
}

#[actix_web::test]
async fn status_endpoints_and_server_health() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    make_zone(&env, &app, &t, "status.example").await;
    let (st, s, _) = call!(app, get, "/api/v1/dns/status", Some(&t), None);
    assert_eq!(st, 200);
    assert_eq!(s["last_publish"]["ok"], true);
    assert!(s["last_publish"]["published"].as_i64().unwrap() >= 1);
    assert!(s["bundle_version"].as_i64().unwrap() >= 1);
    assert!(s["db_connections"]["healthy"].as_i64().unwrap() >= 1);
    // server health is a real TCP probe: one listener, one dead port
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let live = l.local_addr().unwrap().port();
    let dead = {
        let d = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        d.local_addr().unwrap().port()
    };
    for (n, port) in [("up", live), ("down", dead)] {
        let (st, _, raw) = call!(
            app,
            post,
            "/api/v1/servers",
            Some(&t),
            j(serde_json::json!({"name": n, "address": "127.0.0.1", "port": port}))
        );
        assert_eq!(st, 201, "{raw}");
    }
    let (_, list, _) = call!(app, get, "/api/v1/servers", Some(&t), None);
    let status_of = |n: &str| {
        list.as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == n)
            .unwrap()["status"]
            .clone()
    };
    assert_eq!(status_of("up"), "running");
    assert_eq!(status_of("down"), "unreachable");
    // non-admin cannot read publication status, nor the list of servers
    let u = add_user(&env.state, "plain", "plain-pass-12", "user").await;
    let (st, _, _) = call!(
        app,
        get,
        "/api/v1/servers",
        Some(&env.token(&u, "user")),
        None
    );
    assert_eq!(st, 403, "server addresses are admin-only");
    let (st, _, _) = call!(
        app,
        get,
        "/api/v1/dns/status",
        Some(&env.token(&u, "user")),
        None
    );
    assert_eq!(st, 403);
    // query metrics need DNS_METRICS_URL
    let (st, _, _) = call!(app, get, "/api/v1/metrics/queries", Some(&t), None);
    assert_eq!(st, 503);
    drop(l);
    env.cleanup().await;
}

#[actix_web::test]
async fn query_metrics_are_read_from_the_dns_server_exporter() {
    let Some(mut env) = setup().await else { return };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            let mut b = [0u8; 512];
            let _ = s.read(&mut b).await;
            let body = "# TYPE hickory_request_total counter\nhickory_request_total{protocol=\"udp\"} 40\nhickory_request_total{protocol=\"tcp\"} 2\nunrelated 9\n";
            let _ = s
                .write_all(
                    format!(
                        "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .as_bytes(),
                )
                .await;
        }
    });
    env.state.dns_metrics_url = Some(format!("http://127.0.0.1:{port}/metrics"));
    env.full.inner = env.state.clone();
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let (st, b, raw) = call!(app, get, "/api/v1/metrics/queries", Some(&t), None);
    assert_eq!(st, 200, "{raw}");
    assert_eq!(b["requests_total"], 42.0);
    env.cleanup().await;
}

#[actix_web::test]
async fn pool_replaces_dropped_connections() {
    let Some(env) = setup().await else { return };
    // a dedicated pool whose sessions can be told apart from other tests' sessions
    let url = std::env::var("TEST_DATABASE_URL").unwrap();
    let marked = if url.contains('?') {
        format!("{url}&application_name=pooltest")
    } else {
        format!("{url}?application_name=pooltest")
    };
    let pool = Pool::connect(&marked, 3, None).await.expect("pool");
    assert_eq!(pool.healthy(), 3);
    let (c, conn) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let n = c.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = 'pooltest'", &[]).await.unwrap();
    assert_eq!(n, 6, "3 query + 3 transaction pool connections");
    // within a few seconds the supervisors have reconnected and queries work again
    let mut ok = false;
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        if pool.healthy() == 3
            && pool.healthy_transactions() == 3
            && pool.query_one("SELECT 1", &[]).await.is_ok()
        {
            ok = true;
            break;
        }
    }
    assert!(ok, "pool must recover after its connections were killed");
    env.cleanup().await;
}

#[actix_web::test]
async fn bounded_transaction_pool_runs_concurrently_and_rolls_back_isolated_work() {
    let Some(env) = setup().await else { return };
    let pool = env.state.db.clone();
    let mut session_ids = std::collections::HashSet::new();
    for _ in 0..4 {
        let tx = pool.begin().await.unwrap();
        session_ids.insert(
            tx.client()
                .query_one("SELECT pg_backend_pid()", &[])
                .await
                .unwrap()
                .get::<_, i32>(0),
        );
    }
    assert_eq!(
        session_ids.len(),
        4,
        "each transaction slot must be a distinct PostgreSQL backend"
    );
    let started = std::time::Instant::now();
    let tasks = (0..4).map(|_| {
        let pool = pool.clone();
        tokio::spawn(async move {
            let tx = pool.begin().await.unwrap();
            tx.client().batch_execute("BEGIN").await.unwrap();
            tx.client()
                .query_one("SELECT pg_sleep(0.2)", &[])
                .await
                .unwrap();
            tx.client().batch_execute("ROLLBACK").await.unwrap();
        })
    });
    for task in futures_util::future::join_all(tasks).await {
        task.unwrap();
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "four bounded transactions should overlap despite remote round-trip latency; took {elapsed:?}"
    );
    eprintln!(
        "ARCH-003 bounded transaction benchmark: 4 concurrent pg_sleep(200ms) transactions completed in {elapsed:?} over germ SSH tunnel"
    );
    let url = std::env::var("TEST_DATABASE_URL").unwrap();
    let serial_pool = Pool::connect(&url, 1, Some(&env.schema)).await.unwrap();
    let serial_started = std::time::Instant::now();
    let serial_tasks = (0..4).map(|_| {
        let pool = serial_pool.clone();
        tokio::spawn(async move {
            let tx = pool.begin().await.unwrap();
            tx.client().batch_execute("BEGIN").await.unwrap();
            tx.client()
                .query_one("SELECT pg_sleep(0.2)", &[])
                .await
                .unwrap();
            tx.client().batch_execute("ROLLBACK").await.unwrap();
        })
    });
    for task in futures_util::future::join_all(serial_tasks).await {
        task.unwrap();
    }
    let serial_elapsed = serial_started.elapsed();
    assert!(
        elapsed < serial_elapsed,
        "bounded pool {elapsed:?} must outperform one transaction slot {serial_elapsed:?}"
    );
    eprintln!(
        "ARCH-003 single-slot baseline: 4 concurrent pg_sleep(200ms) transactions completed in {serial_elapsed:?}; bounded speedup {:.2}x",
        serial_elapsed.as_secs_f64() / elapsed.as_secs_f64()
    );

    env.state
        .db
        .batch_execute("CREATE TABLE tx_rollback_probe (value integer NOT NULL)")
        .await
        .unwrap();
    let tx = env.state.db.begin().await.unwrap();
    tx.client().batch_execute("BEGIN").await.unwrap();
    tx.client()
        .execute("INSERT INTO tx_rollback_probe(value) VALUES(1)", &[])
        .await
        .unwrap();
    tx.client().batch_execute("ROLLBACK").await.unwrap();
    drop(tx);
    assert_eq!(
        env.state
            .db
            .query_one("SELECT count(*) FROM tx_rollback_probe", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    env.cleanup().await;
}

#[::core::prelude::v1::test]
fn startup_checks_reject_placeholders() {
    let good = "k8Vx0pZq3mT7wRn2Yb9LcHs5Df6GjA1e";
    assert!(
        startup_problems(
            good,
            "postgres://u:s3cr3tX9@db/x",
            Some("a-long-unique-pw-1"),
            false
        )
        .is_empty()
    );
    assert!(
        !startup_problems(
            "CHANGE_ME_to_a_random_value_please_0000",
            "postgres://u:x@db/x",
            None,
            false
        )
        .is_empty()
    );
    assert!(
        !startup_problems(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "postgres://u:x@db/x",
            None,
            false
        )
        .is_empty()
    );
    assert!(
        !startup_problems(
            good,
            "postgres://postgres:CHANGE_ME_STRONG_PASSWORD@db/x",
            None,
            false
        )
        .is_empty()
    );
    assert!(!startup_problems(good, "postgres://postgres:password@db/x", None, false).is_empty());
    assert!(
        !startup_problems(good, "postgres://u:s3cr3t@db/x", Some("admin123"), false).is_empty()
    );
    assert!(!startup_problems(good, "postgres://u:s3cr3t@db/x", Some("short"), false).is_empty());
    assert!(
        !startup_problems(
            good,
            "postgres://u:s3cr3t@db/x",
            Some("a-long-unique-pw-1"),
            true
        )
        .is_empty(),
        "FORCE_BOOTSTRAP is flagged"
    );
}

#[::core::prelude::v1::test]
fn forwarded_for_is_only_trusted_from_trusted_proxies() {
    let trusted = ext::parse_trusted_proxies("10.0.0.0/8, 192.0.2.1, junk");
    assert_eq!(trusted.len(), 2);
    let mk = |peer: &str, xff: &str| {
        test::TestRequest::get()
            .peer_addr(peer.parse().unwrap())
            .insert_header(("X-Forwarded-For", xff))
            .to_http_request()
    };
    // untrusted peer: header ignored (cannot be spoofed)
    assert_eq!(
        ext::client_ip(&mk("203.0.113.9:1", "1.2.3.4"), &trusted),
        Some("203.0.113.9".parse().unwrap())
    );
    // trusted proxy: the right-most non-proxy address wins, left-most entries are attacker controlled
    assert_eq!(
        ext::client_ip(
            &mk("10.1.1.1:1", "6.6.6.6, 198.51.100.7, 10.2.2.2"),
            &trusted
        ),
        Some("198.51.100.7".parse().unwrap())
    );
    // no proxies configured: never trust the header
    assert_eq!(
        ext::client_ip(&mk("10.1.1.1:1", "1.2.3.4"), &[]),
        Some("10.1.1.1".parse().unwrap())
    );
    // header absent or garbage from a trusted proxy: fall back to the peer
    assert_eq!(
        ext::client_ip(&mk("10.1.1.1:1", "not-an-ip"), &trusted),
        Some("10.1.1.1".parse().unwrap())
    );
}

#[::core::prelude::v1::test]
fn listen_addresses_come_from_the_environment() {
    std::env::set_var("LISTEN_ADDRS_IPV6", "::, nonsense");
    std::env::set_var("LISTEN_ADDRS_IPV4", "192.0.2.5");
    let out = dns_builder::TomlConfigBuilder::from_env().build().unwrap();
    std::env::remove_var("LISTEN_ADDRS_IPV6");
    std::env::remove_var("LISTEN_ADDRS_IPV4");
    assert!(out.contains("listen_addrs_ipv4 = [\"192.0.2.5\"]"), "{out}");
    assert!(out.contains("listen_addrs_ipv6 = [\"::\"]"), "{out}");
    assert!(!out.contains("nonsense"));
    // default stays IPv4-only
    let d = dns_builder::TomlConfigBuilder::from_env().build().unwrap();
    assert!(
        d.contains("listen_addrs_ipv4 = [\"0.0.0.0\"]") && !d.contains("ipv6"),
        "{d}"
    );
}

#[actix_web::test]
async fn metrics_endpoint_can_require_a_token() {
    let app = test::init_service(
        App::new()
            .wrap(actix_web::middleware::from_fn(metrics_guard))
            .route(
                "/metrics",
                web::get().to(|| async { HttpResponse::Ok().body("m 1") }),
            )
            .route(
                "/health",
                web::get().to(|| async { HttpResponse::Ok().finish() }),
            ),
    )
    .await;
    std::env::remove_var("METRICS_TOKEN");
    let r = test::call_service(&app, test::TestRequest::get().uri("/metrics").to_request()).await;
    assert_eq!(
        r.status().as_u16(),
        200,
        "open when no token is configured (previous behaviour)"
    );
    std::env::set_var("METRICS_TOKEN", "scrape-secret-123");
    let r = test::call_service(&app, test::TestRequest::get().uri("/metrics").to_request()).await;
    assert_eq!(r.status().as_u16(), 401);
    let r = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/metrics")
            .insert_header(("Authorization", "Bearer wrong"))
            .to_request(),
    )
    .await;
    assert_eq!(r.status().as_u16(), 401);
    let r = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/metrics")
            .insert_header(("Authorization", "Bearer scrape-secret-123"))
            .to_request(),
    )
    .await;
    assert_eq!(r.status().as_u16(), 200);
    let r = test::call_service(&app, test::TestRequest::get().uri("/health").to_request()).await;
    assert_eq!(r.status().as_u16(), 200, "only /metrics is guarded");
    std::env::remove_var("METRICS_TOKEN");
}

#[actix_web::test]
async fn publication_gauges_are_exported_on_metrics() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    metrics::init();
    let t = env.token(&env.admin, "admin");
    make_zone(&env, &app, &t, "gauge.example").await;
    // the gauges live in the registry shared with the HTTP metrics middleware
    let app = test::init_service(
        App::new()
            .wrap(
                actix_web_prom::PrometheusMetricsBuilder::new("t")
                    .registry(prometheus::default_registry().clone())
                    .endpoint("/metrics")
                    .build()
                    .unwrap(),
            )
            .route(
                "/x",
                web::get().to(|| async { HttpResponse::Ok().finish() }),
            ),
    )
    .await;
    let r = test::call_service(&app, test::TestRequest::get().uri("/metrics").to_request()).await;
    let body = String::from_utf8(test::read_body(r).await.to_vec()).unwrap();
    for g in [
        "outis_zones_published",
        "outis_zones_failed",
        "outis_last_publish_ok 1",
        "outis_last_publish_timestamp_seconds",
        "outis_bundle_version",
    ] {
        assert!(body.contains(g), "missing {g} in /metrics");
    }
    env.cleanup().await;
}

#[actix_web::test]
async fn zones_records_users_support_opt_in_pagination_and_search() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    for d in ["a1.test", "a2.test", "a3.test", "b1.test", "b2.test"] {
        make_zone(&env, &app, &t, d).await;
    }
    for i in 0..5 {
        add_user(&env.state, &format!("pgu{i}"), "pg-user-pass-1", "user").await;
    }
    // helper: GET and return (body, X-Total-Count)
    macro_rules! get_total {
        ($uri:expr) => {{
            let r = test::TestRequest::get()
                .uri($uri)
                .insert_header(("Authorization", format!("Bearer {t}")))
                .to_request();
            let resp = test::call_service(&app, r).await;
            let total = resp
                .headers()
                .get("X-Total-Count")
                .map(|v| v.to_str().unwrap().to_string());
            let body: serde_json::Value = test::read_body_json(resp).await;
            (body, total)
        }};
    }
    // zones: unchanged without params, windowed with them, searchable
    let (b, total) = get_total!("/api/v1/zones");
    assert_eq!(b["data"].as_array().unwrap().len(), 5);
    assert_eq!(total.as_deref(), Some("5"));
    let (b, total) = get_total!("/api/v1/zones?limit=2&offset=0");
    assert_eq!(b["data"].as_array().unwrap().len(), 2);
    assert_eq!(total.as_deref(), Some("5"));
    assert_eq!(b["data"][0]["domain"], "a1.test");
    let (b, _) = get_total!("/api/v1/zones?limit=2&offset=4");
    assert_eq!(b["data"].as_array().unwrap().len(), 1, "last partial page");
    let (b, total) = get_total!("/api/v1/zones?q=b");
    assert_eq!(b["data"].as_array().unwrap().len(), 2);
    assert_eq!(total.as_deref(), Some("2"));
    // Cursor pagination uses a stable (domain, id) key and exposes the next
    // opaque cursor without changing the response body contract.
    let first = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/api/v1/zones?q=a&limit=2&sort=domain")
            .insert_header(("Authorization", format!("Bearer {t}")))
            .to_request(),
    )
    .await;
    assert_eq!(first.headers().get("X-Total-Count").unwrap(), "3");
    let cursor = first
        .headers()
        .get("X-Next-Cursor")
        .expect("first page has a cursor")
        .to_str()
        .unwrap()
        .to_string();
    let first_body: serde_json::Value = test::read_body_json(first).await;
    assert_eq!(first_body["data"][0]["domain"], "a1.test");
    assert_eq!(first_body["data"][1]["domain"], "a2.test");
    let next = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/api/v1/zones?q=a&limit=2&sort=domain&cursor={cursor}"
            ))
            .insert_header(("Authorization", format!("Bearer {t}")))
            .to_request(),
    )
    .await;
    assert_eq!(next.headers().get("X-Total-Count").unwrap(), "3");
    assert!(next.headers().get("X-Next-Cursor").is_none());
    let next_body: serde_json::Value = test::read_body_json(next).await;
    assert_eq!(next_body["data"].as_array().unwrap().len(), 1);
    assert_eq!(next_body["data"][0]["domain"], "a3.test");
    let invalid = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/api/v1/zones?cursor=not-a-cursor")
            .insert_header(("Authorization", format!("Bearer {t}")))
            .to_request(),
    )
    .await;
    assert_eq!(invalid.status(), 400);
    // records
    let zid = make_zone(&env, &app, &t, "rec.test").await;
    for i in 0..7 {
        let (st, _, raw) = call!(
            app,
            post,
            &format!("/api/v1/zones/{zid}/records"),
            Some(&t),
            j(
                serde_json::json!({"name": format!("h{i}"), "record_type": "A", "value": format!("192.0.2.{}", i + 1), "ttl": 300})
            )
        );
        assert_eq!(st, 201, "{raw}");
    }
    let (b, total) = get_total!(&format!("/api/v1/zones/{zid}/records?limit=3&offset=3"));
    assert_eq!(b.as_array().unwrap().len(), 3);
    assert_eq!(
        total.as_deref(),
        Some("10"),
        "7 added + 3 default apex records"
    );
    let (b, total) = get_total!(&format!("/api/v1/zones/{zid}/records?q=192.0.2.5"));
    assert_eq!(b.as_array().unwrap().len(), 1);
    assert_eq!(total.as_deref(), Some("1"));
    let first_records = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/api/v1/zones/{zid}/records?q=192.0.2&limit=2&sort=name"
            ))
            .insert_header(("Authorization", format!("Bearer {t}")))
            .to_request(),
    )
    .await;
    assert_eq!(first_records.headers().get("X-Total-Count").unwrap(), "7");
    let record_cursor = first_records
        .headers()
        .get("X-Next-Cursor")
        .expect("first record page has a next cursor")
        .to_str()
        .unwrap()
        .to_string();
    let first_records: serde_json::Value = test::read_body_json(first_records).await;
    assert_eq!(first_records[0]["name"], "h0");
    assert_eq!(first_records[1]["name"], "h1");
    let next_records = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/api/v1/zones/{zid}/records?q=192.0.2&limit=2&sort=name&cursor={record_cursor}"
            ))
            .insert_header(("Authorization", format!("Bearer {t}")))
            .to_request(),
    )
    .await;
    assert_eq!(next_records.headers().get("X-Total-Count").unwrap(), "7");
    let next_records: serde_json::Value = test::read_body_json(next_records).await;
    assert_eq!(next_records[0]["name"], "h2");
    let (b, _) = get_total!(&format!("/api/v1/zones/{zid}/records"));
    assert_eq!(
        b.as_array().unwrap().len(),
        10,
        "no params = everything (backward compatible)"
    );
    // users
    let (b, total) = get_total!("/api/v1/users?limit=2&offset=2&q=pgu");
    assert_eq!(b.as_array().unwrap().len(), 2);
    assert_eq!(total.as_deref(), Some("5"));
    // limit is clamped and negative offsets are treated as 0
    let (b, _) = get_total!("/api/v1/users?limit=1000000&offset=-5&q=pgu");
    assert_eq!(b.as_array().unwrap().len(), 5);
    // authorization is unchanged: a tenant only pages their own zones
    let u = add_user(&env.state, "tenant1", "tenant-pass-123", "user").await;
    let tt = env.token(&u, "user");
    let (st, _, _) = call!(app, get, "/api/v1/users?limit=1", Some(&tt), None);
    assert_eq!(st, 403);
    let r = test::TestRequest::get()
        .uri("/api/v1/zones?limit=10")
        .insert_header(("Authorization", format!("Bearer {tt}")))
        .to_request();
    let resp = test::call_service(&app, r).await;
    assert_eq!(resp.headers().get("X-Total-Count").unwrap(), "0");
    env.cleanup().await;
}

#[actix_web::test]
async fn dnssec_lifecycle_keys_ds_rollover_and_guards() {
    use std::os::unix::fs::PermissionsExt;
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let zid = make_zone(&env, &app, &t, "signed.test").await;
    let named = || std::fs::read_to_string(env.dir.path().join("named.toml")).unwrap();
    assert!(!named().contains("keys = ["), "unsigned zones have no keys");

    // GeoDNS rules block enabling DNSSEC (their answers cannot be signed)
    let (st, _, raw) = call!(
        app,
        post,
        "/api/v1/georules",
        Some(&t),
        j(
            serde_json::json!({"zone_id": zid, "match_type": "country", "match_value": "US", "target": "192.0.2.1"})
        )
    );
    assert_eq!(st, 201, "{raw}");
    let (st, b, _) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/dnssec/enable"),
        Some(&t),
        j(serde_json::json!({}))
    );
    assert_eq!(
        (st, b["error"].as_str()),
        (409, Some("geodns_rules_present"))
    );
    let rules = call!(app, get, "/api/v1/georules", Some(&t), None).1;
    let rid = rules.as_array().or(rules["data"].as_array()).unwrap()[0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        call!(
            app,
            delete,
            &format!("/api/v1/georules/{rid}"),
            Some(&t),
            None
        )
        .0,
        200
    );

    // bad algorithm; then enable with the default
    let (st, _, _) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/dnssec/enable"),
        Some(&t),
        j(serde_json::json!({"algorithm": "RSASHA1"}))
    );
    assert_eq!(st, 400);
    let (st, b, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/dnssec/enable"),
        Some(&t),
        j(serde_json::json!({}))
    );
    assert_eq!(st, 201, "{raw}");
    assert_eq!(b["enabled"], true);
    let key = &b["keys"][0];
    assert_eq!(key["algorithm"], "ECDSAP256SHA256");
    assert_eq!(key["flags"], 257);
    assert_eq!(key["ds"].as_array().unwrap().len(), 2);
    assert!(
        key["ds"][0]["text"]
            .as_str()
            .unwrap()
            .starts_with("signed.test. IN DS ")
    );
    assert!(
        !raw.contains("PRIVATE KEY"),
        "private key material is never returned"
    );
    // key file on disk with restricted mode; named.toml references it; geodns is off for the zone
    let tag = key["key_tag"].as_i64().unwrap();
    let kf = env
        .dir
        .path()
        .join("dnssec-keys")
        .join(format!("signed.test.{tag}.pem"));
    assert!(kf.is_file());
    assert_eq!(
        std::fs::metadata(&kf).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(
        std::fs::read_to_string(&kf)
            .unwrap()
            .starts_with("-----BEGIN PRIVATE KEY-----")
    );
    let n = named();
    assert!(
        n.contains(&format!("key_path = \"{}\"", kf.display()))
            && n.contains("algorithm = \"ECDSAP256SHA256\""),
        "{n}"
    );
    let proof_url = format!("/api/v1/zones/{zid}/dnssec/proof");
    let (proof_status, proof, proof_raw) = call!(
        app,
        put,
        &proof_url,
        Some(&t),
        j(serde_json::json!({
            "proof_type":"nsec3", "nsec3_salt":"A1b2", "nsec3_iterations":12,
            "nsec3_opt_out":true
        }))
    );
    assert_eq!(proof_status, 200, "{proof_raw}");
    assert_eq!(proof["proof"]["type"], "nsec3");
    assert_eq!(proof["proof"]["nsec3_salt"], "a1b2");
    assert_eq!(proof["proof"]["nsec3_iterations"], 12);
    assert_eq!(proof["proof"]["nsec3_opt_out"], true);
    let multi_signer_url = format!("/api/v1/zones/{zid}/dnssec/multi-signer");
    let (unsupported_status, unsupported, unsupported_raw) = call!(
        app,
        post,
        &multi_signer_url,
        Some(&t),
        j(serde_json::json!({}))
    );
    assert_eq!(unsupported_status, 501, "{unsupported_raw}");
    assert_eq!(unsupported["error"], "multi_signer_unsupported");
    assert_eq!(unsupported["supported"], false);
    assert!(
        unsupported["details"]
            .as_str()
            .unwrap()
            .contains("No DNSSEC state was changed")
    );
    let nsec3_config = named();
    assert!(
        nsec3_config.contains("nx_proof_kind = { nsec3 = { algorithm = \"SHA-1\""),
        "{nsec3_config}"
    );
    assert!(
        nsec3_config.contains("salt = [161, 178], iterations = 12, opt_out = true"),
        "{nsec3_config}"
    );
    let (invalid_salt_status, _, _) = call!(
        app,
        put,
        &proof_url,
        Some(&t),
        j(serde_json::json!({"proof_type":"nsec3","nsec3_salt":"xyz","nsec3_iterations":0}))
    );
    assert_eq!(invalid_salt_status, 400);
    let (invalid_iteration_status, _, _) = call!(
        app,
        put,
        &proof_url,
        Some(&t),
        j(serde_json::json!({"proof_type":"nsec3","nsec3_iterations":151}))
    );
    assert_eq!(invalid_iteration_status, 400);
    // A publication failure must restore both the NSEC3 database state and
    // last-known-good named configuration.
    let blocked_config = env.dir.path().join("named.toml");
    std::fs::remove_file(&blocked_config).unwrap();
    std::fs::create_dir(&blocked_config).unwrap();
    let (failed_status, failed_body, failed_raw) = call!(
        app,
        put,
        &proof_url,
        Some(&t),
        j(serde_json::json!({"proof_type":"nsec","nsec3_salt":"","nsec3_iterations":0}))
    );
    assert_eq!(failed_status, 500, "{failed_raw}");
    assert_eq!(failed_body["error"], "publish_failed", "{failed_raw}");
    let restored: (String, String, i32, bool) = {
        let row = env.state.db.query_one(
            "SELECT dnssec_proof_type,dnssec_nsec3_salt,dnssec_nsec3_iterations,dnssec_nsec3_opt_out FROM zones WHERE CAST(id AS varchar)=$1",
            &[&zid],
        ).await.unwrap();
        (row.get(0), row.get(1), row.get(2), row.get(3))
    };
    assert_eq!(restored, ("nsec3".into(), "a1b2".into(), 12, true));
    std::fs::remove_dir_all(&blocked_config).unwrap();
    // twice is refused
    assert_eq!(
        call!(
            app,
            post,
            &format!("/api/v1/zones/{zid}/dnssec/enable"),
            Some(&t),
            j(serde_json::json!({}))
        )
        .0,
        409
    );

    // a signed zone refuses GeoDNS, renames
    let (st, b, _) = call!(
        app,
        post,
        "/api/v1/georules",
        Some(&t),
        j(
            serde_json::json!({"zone_id": zid, "match_type": "country", "match_value": "US", "target": "192.0.2.1"})
        )
    );
    assert_eq!((st, b["error"].as_str()), (409, Some("dnssec_enabled")));
    assert_eq!(
        call!(
            app,
            put,
            &format!("/api/v1/zones/{zid}"),
            Some(&t),
            j(serde_json::json!({"geodns_enabled": true}))
        )
        .0,
        409
    );
    assert_eq!(
        call!(
            app,
            put,
            &format!("/api/v1/zones/{zid}"),
            Some(&t),
            j(serde_json::json!({"domain": "renamed.test"}))
        )
        .0,
        409
    );
    // records can still change; the zone stays signed
    assert_eq!(
        call!(
            app,
            post,
            &format!("/api/v1/zones/{zid}/records"),
            Some(&t),
            j(serde_json::json!({"name":"www","record_type":"A","value":"192.0.2.9","ttl":300}))
        )
        .0,
        201
    );
    assert!(named().contains("keys = ["));

    // authorization: other tenants cannot see or change it, viewers can read but not change
    let other = add_user(&env.state, "other", "other-pass-123", "user").await;
    let ot = env.token(&other, "user");
    assert_eq!(
        call!(
            app,
            get,
            &format!("/api/v1/zones/{zid}/dnssec"),
            Some(&ot),
            None
        )
        .0,
        403
    );
    assert_eq!(
        call!(
            app,
            post,
            &format!("/api/v1/zones/{zid}/dnssec/rollover"),
            Some(&ot),
            j(serde_json::json!({}))
        )
        .0,
        403
    );
    assert_eq!(
        call!(
            app,
            get,
            &format!("/api/v1/zones/{zid}/dnssec"),
            None::<&str>,
            None
        )
        .0,
        401
    );
    let (st, _, _) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zid}/members"),
        Some(&t),
        j(serde_json::json!({"username": "other", "role": "viewer"}))
    );
    assert_eq!(st, 200, "share");
    assert_eq!(
        call!(
            app,
            get,
            &format!("/api/v1/zones/{zid}/dnssec"),
            Some(&ot),
            None
        )
        .0,
        200
    );
    assert_eq!(
        call!(
            app,
            post,
            &format!("/api/v1/zones/{zid}/dnssec/rollover"),
            Some(&ot),
            j(serde_json::json!({}))
        )
        .0,
        403
    );
    assert_eq!(
        call!(
            app,
            post,
            &format!("/api/v1/zones/{zid}/dnssec/disable"),
            Some(&ot),
            j(serde_json::json!({"confirm_ds_removed": true}))
        )
        .0,
        403
    );

    // rollover: second key joins, both are referenced; a second rollover is refused
    let (st, b, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/dnssec/rollover"),
        Some(&t),
        j(serde_json::json!({"algorithm": "ED25519"}))
    );
    assert_eq!(st, 201, "{raw}");
    assert_eq!(b["keys"].as_array().unwrap().len(), 2);
    assert_eq!(b["keys"][1]["status"], "new");
    assert_eq!(b["keys"][1]["algorithm"], "ED25519");
    assert_eq!(named().matches("key_path").count(), 2);
    assert_eq!(
        call!(
            app,
            post,
            &format!("/api/v1/zones/{zid}/dnssec/rollover"),
            Some(&t),
            j(serde_json::json!({}))
        )
        .0,
        409
    );
    // completing retires the named key, keeps the other, and archives (not deletes) the private key
    assert_eq!(
        call!(
            app,
            post,
            &format!("/api/v1/zones/{zid}/dnssec/rollover/complete"),
            Some(&t),
            j(serde_json::json!({"retire_key_tag": 1}))
        )
        .0,
        404
    );
    let (st, b, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/dnssec/rollover/complete"),
        Some(&t),
        j(serde_json::json!({"retire_key_tag": tag}))
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(b["keys"].as_array().unwrap().len(), 1);
    assert_eq!(b["keys"][0]["algorithm"], "ED25519");
    assert_eq!(b["keys"][0]["status"], "active");
    assert_eq!(named().matches("key_path").count(), 1);
    assert!(
        !kf.exists()
            && env
                .dir
                .path()
                .join("dnssec-keys/retired")
                .join(format!("signed.test.{tag}.pem"))
                .is_file()
    );
    // the last key cannot be "completed" away
    let last = b["keys"][0]["key_tag"].as_i64().unwrap();
    assert_eq!(
        call!(
            app,
            post,
            &format!("/api/v1/zones/{zid}/dnssec/rollover/complete"),
            Some(&t),
            j(serde_json::json!({"retire_key_tag": last}))
        )
        .0,
        409
    );

    // disabling needs confirmation that the DS is gone
    let (st, b, _) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/dnssec/disable"),
        Some(&t),
        j(serde_json::json!({}))
    );
    assert_eq!((st, b["error"].as_str()), (409, Some("ds_not_confirmed")));
    assert!(
        named().contains("keys = ["),
        "nothing changed without confirmation"
    );
    let (st, b, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/dnssec/disable"),
        Some(&t),
        j(serde_json::json!({"confirm_ds_removed": true}))
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(b["enabled"], false);
    assert!(!named().contains("keys = ["));
    // after disabling, rename/GeoDNS work again
    assert_eq!(
        call!(
            app,
            put,
            &format!("/api/v1/zones/{zid}"),
            Some(&t),
            j(serde_json::json!({"geodns_enabled": true}))
        )
        .0,
        200
    );
    // audit trail
    let (_, logs, _) = call!(
        app,
        get,
        "/api/v1/audit/logs?resource_type=zone&limit=100",
        Some(&t),
        None
    );
    let actions: Vec<String> = logs["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["action"].as_str().unwrap().to_string())
        .collect();
    for a in [
        "dnssec_enable",
        "dnssec_rollover",
        "dnssec_rollover_complete",
        "dnssec_disable",
    ] {
        assert!(
            actions.contains(&a.to_string()),
            "missing audit action {a}: {actions:?}"
        );
    }
    env.cleanup().await;
}

#[actix_web::test]
async fn dnssec_rollover_publication_failure_queues_retry_and_preserves_retired_key_file() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let token = env.token(&env.admin, "admin");
    let zone_id = make_zone(&env, &app, &token, "rollover-retry.test").await;

    let (status, enabled, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zone_id}/dnssec/enable"),
        Some(&token),
        j(serde_json::json!({"algorithm": "ED25519"}))
    );
    assert_eq!(status, 201, "{raw}");
    let old_tag = enabled["keys"][0]["key_tag"].as_i64().unwrap() as i32;

    let (status, _, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zone_id}/dnssec/rollover"),
        Some(&token),
        j(serde_json::json!({}))
    );
    assert_eq!(status, 201, "{raw}");
    let old_key = env
        .dir
        .path()
        .join("dnssec-keys")
        .join(format!("rollover-retry.test.{old_tag}.pem"));
    assert!(old_key.is_file());

    // Simulate a bad RR inserted outside the validated API. Publication must
    // fail after the rollover DB transition, exercising its retry path.
    let bad_record_id = Uuid::new_v4().to_string();
    env.state
        .db
        .execute(
            "INSERT INTO records(id, zone_id, name, record_type, value, ttl) \
             VALUES($1::text::uuid, $2::text::uuid, 'broken', 'A', 'not-an-ip', 300)",
            &[&bad_record_id, &zone_id],
        )
        .await
        .unwrap();

    let (status, result, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zone_id}/dnssec/rollover/complete"),
        Some(&token),
        j(serde_json::json!({"retire_key_tag": old_tag}))
    );
    assert_eq!(status, 200, "{raw}");
    assert!(result["publish_warning"].is_string(), "{result}");
    assert!(
        old_key.is_file(),
        "failed publication must keep the key at its configured path"
    );
    assert!(
        !env.dir
            .path()
            .join("dnssec-keys/retired")
            .join(format!("rollover-retry.test.{old_tag}.pem"))
            .exists(),
        "key archival must wait until publication succeeds"
    );
    let queued: i64 = env
        .state
        .db
        .query_one(
            "SELECT count(*) FROM publication_outbox WHERE zone_domain = 'rollover-retry.test' AND status = 'pending'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(queued, 1, "failed DNSSEC publication must be retried");

    env.state
        .db
        .execute(
            "DELETE FROM records WHERE CAST(id AS varchar) = $1",
            &[&bad_record_id],
        )
        .await
        .unwrap();
    assert!(
        publication_retry_once(&env.state.dns_manager, &env.state.db)
            .await
            .unwrap()
    );
    let remaining: i64 = env
        .state
        .db
        .query_one(
            "SELECT count(*) FROM publication_outbox WHERE zone_domain = 'rollover-retry.test'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        remaining, 0,
        "successful retry must acknowledge the outbox job"
    );
    let named = std::fs::read_to_string(env.dir.path().join("named.toml")).unwrap();
    assert_eq!(named.matches("key_path").count(), 1);

    let active_file: String = env
        .state
        .db
        .query_one(
            "SELECT key_file FROM dnssec_keys WHERE CAST(zone_id AS varchar) = $1 AND status = 'active'",
            &[&zone_id],
        )
        .await
        .unwrap()
        .get(0);
    let active_path = env.dir.path().join("dnssec-keys").join(&active_file);
    let bad_record_id = Uuid::new_v4().to_string();
    env.state
        .db
        .execute(
            "INSERT INTO records(id, zone_id, name, record_type, value, ttl) \
             VALUES($1::text::uuid, $2::text::uuid, 'broken-disable', 'A', 'not-an-ip', 300)",
            &[&bad_record_id, &zone_id],
        )
        .await
        .unwrap();
    let (status, disabled, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zone_id}/dnssec/disable"),
        Some(&token),
        j(serde_json::json!({"confirm_ds_removed": true}))
    );
    assert_eq!(status, 200, "{raw}");
    assert!(disabled["publish_warning"].is_string(), "{disabled}");
    assert!(
        active_path.is_file(),
        "failed DNSSEC disable publication must retain referenced key files"
    );
    let pending: i64 = env
        .state
        .db
        .query_one(
            "SELECT count(*) FROM publication_outbox WHERE zone_domain = 'rollover-retry.test' AND status = 'pending'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(pending, 1);
    env.state
        .db
        .execute(
            "DELETE FROM records WHERE CAST(id AS varchar) = $1",
            &[&bad_record_id],
        )
        .await
        .unwrap();
    assert!(
        publication_retry_once(&env.state.dns_manager, &env.state.db)
            .await
            .unwrap()
    );
    let named = std::fs::read_to_string(env.dir.path().join("named.toml")).unwrap();
    assert!(!named.contains("key_path"));
    let enabled: bool = env
        .state
        .db
        .query_one(
            "SELECT dnssec_enabled FROM zones WHERE CAST(id AS varchar) = $1",
            &[&zone_id],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!enabled);
    env.cleanup().await;
}

/// A database created by the *original* migrations (committed fixtures from the first
/// release) must upgrade in place: data kept, new columns/tables added, running twice is a no-op.
#[actix_web::test]
async fn legacy_schema_upgrades_in_place_keeping_data() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("SKIPPED: TEST_DATABASE_URL not set");
        return;
    };
    let schema = format!("t_{}", Uuid::new_v4().simple());
    let (c, conn) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    c.batch_execute(&format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema}"
    ))
    .await
    .unwrap();
    drop(c);
    let pool = Pool::connect(&url, 2, Some(&schema)).await.unwrap();
    for f in [
        "legacy_001_initial_schema.sql",
        "legacy_002_add_nameservers.sql",
        "legacy_002_add_release_channels.sql",
    ] {
        let sql =
            std::fs::read_to_string(format!("{}/tests/fixtures/{f}", env!("CARGO_MANIFEST_DIR")))
                .unwrap();
        pool.batch_execute(&sql)
            .await
            .unwrap_or_else(|e| panic!("legacy fixture {f}: {}", full_error_string(&e)));
    }
    // data written by the old release
    let hash = Argon2::default()
        .hash_password(b"old-admin-pass-1", &generate_salt())
        .unwrap()
        .to_string();
    let (uid, zid) = (Uuid::new_v4().to_string(), Uuid::new_v4().to_string());
    pool.execute("INSERT INTO users (id, username, password_hash, role) VALUES ($1::text::uuid, 'legacyadmin', $2, 'admin')", &[&uid, &hash]).await.unwrap();
    pool.execute("INSERT INTO zones (id, domain, owner) VALUES ($1::text::uuid, 'legacy.example', $2::text::uuid)", &[&zid, &uid]).await.unwrap();
    for (i, v) in ["192.0.2.1", "192.0.2.2"].iter().enumerate() {
        pool.execute("INSERT INTO records (id, zone_id, name, type, value) VALUES ($1::text::uuid, $2::text::uuid, 'www', 'A', $3)", &[&Uuid::new_v4().to_string(), &zid, v]).await
            .unwrap_or_else(|e| panic!("record {i}: {}", full_error_string(&e)));
    }
    // upgrade, twice (idempotent)
    migrate_db(&pool)
        .await
        .unwrap_or_else(|e| panic!("first upgrade: {}", full_error_string(&e)));
    migrate_db(&pool)
        .await
        .unwrap_or_else(|e| panic!("second upgrade: {}", full_error_string(&e)));
    // data intact
    assert_eq!(
        pool.query_one("SELECT count(*) FROM records WHERE name = 'www'", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        2
    );
    let z = pool
        .query_one(
            "SELECT status, ecs_enabled, dnssec_enabled FROM zones WHERE domain = 'legacy.example'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        (
            z.get::<_, String>(0),
            z.get::<_, bool>(1),
            z.get::<_, bool>(2)
        ),
        ("active".to_string(), false, false)
    );
    for t in [
        "zone_members",
        "zone_revisions",
        "dnssec_keys",
        "publish_state",
    ] {
        let n: i64 = pool
            .query_one(&format!("SELECT count(*) FROM {t}"), &[])
            .await
            .unwrap_or_else(|e| panic!("table {t} missing: {}", full_error_string(&e)))
            .get(0);
        assert!(n >= 0);
    }
    // the old unique constraint no longer prevents an RRset with several values (already inserted above) and
    // the upgraded database serves the legacy account and publishes the legacy zone
    let dir = tempfile::tempdir().unwrap();
    let state = AppState {
        db: pool.clone(),
        jwt_secret: "unit-test-secret-unit-test-secret-1234".into(),
        agent_signing_secret: "agent-test-secret-agent-test-secret-1234".into(),
        dns_manager: Arc::new(DnsManager::new(dir.path().to_string_lossy().to_string())),
        verify_resolver: "127.0.0.1:9".parse().unwrap(),
        verify_domains: false,
        dns_metrics_url: None,
        lookup_resolvers: vec![],
    };
    let full = FullState {
        inner: state.clone(),
        geo: Arc::new(tokio::sync::Mutex::new(GeoState { db: None })),
        processes: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
    };
    let env = Env {
        state,
        full,
        dir,
        schema: schema.clone(),
        admin: uid,
    };
    let app = app!(env);
    let (st, b, raw) = call!(
        app,
        post,
        "/api/v1/auth/login",
        None::<&str>,
        j(serde_json::json!({"username": "legacyadmin", "password": "old-admin-pass-1"}))
    );
    assert_eq!(st, 200, "{raw}");
    let tok = b["token"].as_str().unwrap().to_string();
    let (_, recs, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{zid}/records"),
        Some(&tok),
        None
    );
    assert_eq!(recs.as_array().unwrap().len(), 2);
    let rep = env
        .state
        .dns_manager
        .regenerate_zones(env.state.db.clone())
        .await
        .unwrap();
    assert!(rep.failed.is_empty(), "{:?}", rep.failed);
    let zf = std::fs::read_to_string(env.zone_file("legacy.example")).unwrap();
    assert!(zf.contains("192.0.2.1") && zf.contains("192.0.2.2"));
    env.cleanup().await;
}

#[actix_web::test]
async fn very_long_record_values_never_crash_the_api() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let zid = make_zone(&env, &app, &t, "long.test").await;
    for len in [255usize, 4_095, 4_096, 20_000] {
        let (st, _, raw) = call!(
            app,
            post,
            &format!("/api/v1/zones/{zid}/records"),
            Some(&t),
            j(
                serde_json::json!({"name": format!("t{len}"), "record_type": "TXT", "value": "a".repeat(len), "ttl": 300})
            )
        );
        assert!(
            st == 201 || st == 400,
            "TXT of {len} chars must be accepted or refused cleanly, got {st}: {}",
            &raw[..raw.len().min(200)]
        );
    }
    // the API is still serving and the published zone is intact
    let (st, _, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{zid}/records"),
        Some(&t),
        None
    );
    assert_eq!(st, 200);
    let zf = std::fs::read_to_string(env.zone_file("long.test")).unwrap();
    assert!(zf.contains("SOA"));
    env.cleanup().await;
}

#[actix_web::test]
async fn publication_is_serialised_across_api_instances() {
    let Some(env) = setup().await else { return };
    // a second "instance" holding the cluster lock blocks publication until it lets go
    let url = std::env::var("TEST_DATABASE_URL").unwrap();
    let other = Pool::connect(&url, 1, Some(&env.schema)).await.unwrap();
    let held = other.advisory_lock(0x4f55_5449_5350_5542).await.unwrap();
    let st = env.state.clone();
    let started = std::time::Instant::now();
    let publish = tokio::spawn(async move { st.dns_manager.regenerate_zones(st.db.clone()).await });
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    assert!(
        !publish.is_finished(),
        "publication must wait for the other instance"
    );
    drop(held);
    let rep = publish.await.unwrap().unwrap();
    assert!(rep.failed.is_empty());
    assert!(started.elapsed() >= std::time::Duration::from_millis(1200));
    env.cleanup().await;
}

// ===========================================================================
// DNS lookup, tenants, quotas, overview, analytics, authorization
// ===========================================================================

/// UDP+TCP fake resolver answering every supported type; `big.example` is truncated over UDP.
async fn fake_multi_resolver() -> std::net::SocketAddr {
    use hickory_proto::dnssec::{
        Algorithm, DigestType, PublicKeyBuf,
        rdata::{DNSKEY, DS},
    };
    use hickory_proto::op::{Message, ResponseCode};
    use hickory_proto::rr::rdata::{
        A, AAAA, CAA, CNAME, MX, NS, PTR, SOA, SRV, TXT, caa::KeyValue,
    };
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    fn answer(q: &Message, over_udp: bool) -> Vec<u8> {
        let mut r = Message::response(q.id(), q.op_code());
        r.set_recursion_available(true);
        for qq in q.queries() {
            r.add_query(qq.clone());
            let n = qq.name().clone();
            let s = n.to_ascii();
            if s.starts_with("nx.") {
                r.set_response_code(ResponseCode::NXDomain);
                r.add_authority(Record::from_rdata(
                    Name::from_ascii("example.").unwrap(),
                    900,
                    RData::SOA(SOA::new(
                        Name::from_ascii("ns.example.").unwrap(),
                        Name::from_ascii("h.example.").unwrap(),
                        1,
                        2,
                        3,
                        4,
                        900,
                    )),
                ));
                continue;
            }
            if s.starts_with("nodata.") {
                r.add_authority(Record::from_rdata(
                    Name::from_ascii("example.").unwrap(),
                    777,
                    RData::SOA(SOA::new(
                        Name::from_ascii("ns.example.").unwrap(),
                        Name::from_ascii("h.example.").unwrap(),
                        1,
                        2,
                        3,
                        4,
                        777,
                    )),
                ));
                continue;
            }
            if s.starts_with("big.") && over_udp {
                r.set_truncated(true);
                continue;
            }
            let t = |x: RData, ttl: u32| Record::from_rdata(n.clone(), ttl, x);
            let rr = match qq.query_type() {
                RecordType::A => Some(t(RData::A(A::new(192, 0, 2, 1)), 301)),
                RecordType::AAAA => Some(t(
                    RData::AAAA(AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                    302,
                )),
                RecordType::MX => Some(t(
                    RData::MX(MX::new(10, Name::from_ascii("mail.example.").unwrap())),
                    303,
                )),
                RecordType::TXT => Some(t(RData::TXT(TXT::new(vec!["v=spf1 -all".into()])), 304)),
                RecordType::NS => Some(t(
                    RData::NS(NS(Name::from_ascii("ns1.example.").unwrap())),
                    305,
                )),
                RecordType::CNAME => Some(t(
                    RData::CNAME(CNAME(Name::from_ascii("target.example.").unwrap())),
                    306,
                )),
                RecordType::SOA => Some(t(
                    RData::SOA(SOA::new(
                        Name::from_ascii("ns1.example.").unwrap(),
                        Name::from_ascii("hostmaster.example.").unwrap(),
                        2024010101,
                        7200,
                        3600,
                        1209600,
                        300,
                    )),
                    307,
                )),
                RecordType::SRV => Some(t(
                    RData::SRV(SRV::new(
                        5,
                        6,
                        5060,
                        Name::from_ascii("sip.example.").unwrap(),
                    )),
                    308,
                )),
                RecordType::PTR => Some(t(
                    RData::PTR(PTR(Name::from_ascii("host.example.").unwrap())),
                    309,
                )),
                RecordType::CAA => Some(t(
                    RData::CAA(CAA::new_issue(
                        false,
                        Some(Name::from_ascii("letsencrypt.org").unwrap()),
                        Vec::<KeyValue>::new(),
                    )),
                    310,
                )),
                RecordType::DNSKEY => Some(t(
                    RData::DNSSEC(hickory_proto::dnssec::rdata::DNSSECRData::DNSKEY(
                        DNSKEY::new(
                            true,
                            true,
                            false,
                            PublicKeyBuf::new(vec![7u8; 64], Algorithm::ECDSAP256SHA256),
                        ),
                    )),
                    311,
                )),
                RecordType::DS => Some(t(
                    RData::DNSSEC(hickory_proto::dnssec::rdata::DNSSECRData::DS(DS::new(
                        12345,
                        Algorithm::ECDSAP256SHA256,
                        DigestType::SHA256,
                        vec![0xab; 32],
                    ))),
                    312,
                )),
                _ => None,
            };
            if let Some(rr) = rr {
                r.add_answer(rr);
            }
        }
        r.to_vec().unwrap()
    }
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = tokio::net::TcpListener::bind(addr).await.unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            let Ok((n, from)) = udp.recv_from(&mut buf).await else {
                return;
            };
            let Ok(q) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            let _ = udp.send_to(&answer(&q, true), from).await;
        }
    });
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let Ok((mut s, _)) = tcp.accept().await else {
                return;
            };
            let mut l = [0u8; 2];
            if s.read_exact(&mut l).await.is_err() {
                continue;
            }
            let mut b = vec![0u8; u16::from_be_bytes(l) as usize];
            if s.read_exact(&mut b).await.is_err() {
                continue;
            }
            let Ok(q) = Message::from_vec(&b) else {
                continue;
            };
            let a = answer(&q, false);
            let mut out = (a.len() as u16).to_be_bytes().to_vec();
            out.extend(a);
            let _ = s.write_all(&out).await;
        }
    });
    addr
}

#[actix_web::test]
async fn dns_lookup_supports_every_advertised_type_with_real_answers() {
    let Some(mut env) = setup().await else { return };
    env.state.lookup_resolvers =
        lookup::parse_resolvers(&fake_multi_resolver().await.to_string()).unwrap();
    env.full.inner = env.state.clone();
    let user = add_user(&env.state, "lookup-user", "lookup-pass-1", "user").await;
    let viewer = add_user(&env.state, "lookup-viewer", "lookup-pass-2", "viewer").await;
    let (tu, tv) = (env.token(&user, "user"), env.token(&viewer, "viewer"));
    let app = app!(env);
    let expect: [(&str, u32, &str); 12] = [
        ("A", 301, "192.0.2.1"),
        ("AAAA", 302, "2001:db8::1"),
        ("MX", 303, "10 mail.example."),
        ("TXT", 304, "v=spf1 -all"),
        ("NS", 305, "ns1.example."),
        ("CNAME", 306, "target.example."),
        (
            "SOA",
            307,
            "ns1.example. hostmaster.example. 2024010101 7200 3600 1209600 300",
        ),
        ("SRV", 308, "5 6 5060 sip.example."),
        ("PTR", 309, "host.example."),
        ("CAA", 310, "0 issue \"letsencrypt.org\""),
        ("DNSKEY", 311, "257 3 13"),
        ("DS", 312, "12345 13 2"),
    ];
    assert_eq!(expect.len(), lookup::SUPPORTED_TYPES.len());
    for (t, ttl, needle) in expect {
        let (st, b, raw) = call!(
            app,
            post,
            "/api/v1/dns/lookup",
            Some(&tu),
            j(serde_json::json!({"domain":"www.example","record_type":t}))
        );
        assert_eq!(st, 200, "{t}: {raw}");
        assert_eq!(b["status"], "NOERROR", "{t}");
        let recs = b["records"].as_array().unwrap();
        assert_eq!(recs.len(), 1, "{t}: {raw}");
        assert_eq!(recs[0]["type"], t, "{raw}");
        assert_eq!(recs[0]["ttl"], ttl, "{t} ttl: {raw}");
        assert!(
            recs[0]["value"].as_str().unwrap().contains(needle),
            "{t}: {} should contain {needle}",
            recs[0]["value"]
        );
        assert!(b["note"].is_null(), "{t}: a populated answer needs no note");
    }
    // PTR from an IP address
    let (st, b, raw) = call!(
        app,
        post,
        "/api/v1/dns/lookup",
        Some(&tu),
        j(serde_json::json!({"domain":"192.0.2.1","record_type":"PTR"}))
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(b["records"][0]["value"], "host.example.");
    // negative answers are reported honestly, with the SOA that proves them
    let (_, b, raw) = call!(
        app,
        post,
        "/api/v1/dns/lookup",
        Some(&tu),
        j(serde_json::json!({"domain":"nx.example","record_type":"A"}))
    );
    assert_eq!(b["status"], "NXDOMAIN", "{raw}");
    assert_eq!(b["records"].as_array().unwrap().len(), 0);
    assert_eq!(b["authority"][0]["ttl"], 900);
    let (_, b, raw) = call!(
        app,
        post,
        "/api/v1/dns/lookup",
        Some(&tu),
        j(serde_json::json!({"domain":"nodata.example","record_type":"MX"}))
    );
    assert_eq!(b["status"], "NOERROR", "{raw}");
    assert_eq!(b["records"].as_array().unwrap().len(), 0);
    assert!(b["note"].as_str().unwrap().contains("no MX"), "{raw}");
    // truncated UDP answers are retried over TCP
    let (_, b, raw) = call!(
        app,
        post,
        "/api/v1/dns/lookup",
        Some(&tu),
        j(serde_json::json!({"domain":"big.example","record_type":"A"}))
    );
    assert_eq!(b["transport"], "tcp", "{raw}");
    assert_eq!(b["records"][0]["value"], "192.0.2.1");
    // validation
    for (d, t) in [
        ("www.example", "ANY"),
        ("www.example", "AXFR"),
        ("bad name", "A"),
        ("", "A"),
        ("192.0.2.1", "A"),
    ] {
        let (st, _, raw) = call!(
            app,
            post,
            "/api/v1/dns/lookup",
            Some(&tu),
            j(serde_json::json!({"domain":d,"record_type":t}))
        );
        assert_eq!(st, 400, "{d}/{t}: {raw}");
    }
    // authorization: login required, read-only accounts may use the (read-only) tool
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/dns/lookup",
        None::<&str>,
        j(serde_json::json!({"domain":"www.example"}))
    );
    assert_eq!(st, 401);
    let (st, _, raw) = call!(
        app,
        post,
        "/api/v1/dns/lookup",
        Some(&tv),
        j(serde_json::json!({"domain":"www.example","record_type":"A"}))
    );
    assert_eq!(st, 200, "viewer: {raw}");
    // per-account rate limit (default 30/min): the 31st call in a window is refused, other accounts are unaffected
    let spammer = add_user(&env.state, "spammer", "spam-pass-1", "user").await;
    let ts = env.token(&spammer, "user");
    // fixed 60 s windows on the database clock: a window boundary can fall inside the loop, so allow one retry round
    let mut limited = 0;
    for _round in 0..2 {
        limited = 0;
        for _ in 0..40 {
            let (st, _, _) = call!(
                app,
                post,
                "/api/v1/dns/lookup",
                Some(&ts),
                j(serde_json::json!({"domain":"www.example","record_type":"A"}))
            );
            if st == 429 {
                limited += 1;
            }
        }
        if limited >= 10 {
            break;
        }
    }
    assert!(
        limited >= 10,
        "calls above the budget are refused (got {limited})"
    );
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/dns/lookup",
        Some(&tu),
        j(serde_json::json!({"domain":"www.example","record_type":"A"}))
    );
    assert_eq!(st, 200);
    env.cleanup().await;
}

#[actix_web::test]
async fn dns_lookup_reports_unreachable_resolver_as_error_not_empty_result() {
    let Some(mut env) = setup().await else { return };
    // a closed port on localhost: the resolver is unreachable
    env.state.lookup_resolvers = lookup::parse_resolvers("127.0.0.1:9").unwrap();
    env.full.inner = env.state.clone();
    let u = add_user(&env.state, "lk2", "lookup-pass-1", "user").await;
    let tu = env.token(&u, "user");
    let app = app!(env);
    let (st, b, raw) = call!(
        app,
        post,
        "/api/v1/dns/lookup",
        Some(&tu),
        j(serde_json::json!({"domain":"www.example","record_type":"A"}))
    );
    assert_eq!(st, 502, "{raw}");
    assert_eq!(b["error"], "resolver_unavailable");
    assert!(
        !raw.contains("127.0.0.1") && !raw.contains("attempts"),
        "customers must not learn resolver addresses: {raw}"
    );
    env.cleanup().await;
}

#[actix_web::test]
async fn nameservers_and_server_status_authorization() {
    let Some(env) = setup().await else { return };
    let cust = add_user(&env.state, "cust", "cust-pass-123", "user").await;
    let (tc, ta) = (env.token(&cust, "user"), env.token(&env.admin, "admin"));
    let app = app!(env);
    env.state.db.execute("INSERT INTO nameservers (id, hostname, ip_address, sort_order, enabled) VALUES (gen_random_uuid(), 'ns-on.example', '192.0.2.53', 1, true), (gen_random_uuid(), 'ns-off.example', '192.0.2.54', 2, false)", &[]).await.unwrap();
    let (st, _, _) = call!(app, get, "/api/v1/nameservers", None::<&str>, None);
    assert_eq!(st, 401);
    let (st, b, raw) = call!(app, get, "/api/v1/nameservers", Some(&tc), None);
    assert_eq!(st, 200, "{raw}");
    let hosts: Vec<String> = b
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["hostname"].as_str().unwrap().to_string())
        .collect();
    assert!(
        hosts.contains(&"ns-on.example".to_string())
            && !hosts.contains(&"ns-off.example".to_string()),
        "customers see enabled nameservers only: {hosts:?}"
    );
    let paged = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/api/v1/nameservers?limit=1&offset=0&q=ns-on")
            .insert_header(("Authorization", format!("Bearer {tc}")))
            .to_request(),
    )
    .await;
    assert_eq!(paged.status(), 200);
    assert_eq!(paged.headers().get("X-Total-Count").unwrap(), "1");
    let paged_body: serde_json::Value = test::read_body_json(paged).await;
    assert_eq!(paged_body.as_array().unwrap().len(), 1);
    let empty_page = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/api/v1/nameservers?limit=1&offset=100")
            .insert_header(("Authorization", format!("Bearer {tc}")))
            .to_request(),
    )
    .await;
    assert_eq!(empty_page.headers().get("X-Total-Count").unwrap(), "1");
    let empty_body: serde_json::Value = test::read_body_json(empty_page).await;
    assert_eq!(empty_body.as_array().unwrap().len(), 0);
    let (_, b, _) = call!(app, get, "/api/v1/nameservers", Some(&ta), None);
    assert_eq!(b.as_array().unwrap().len(), 2, "admins see all");
    let admin_page = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/api/v1/nameservers?limit=1")
            .insert_header(("Authorization", format!("Bearer {ta}")))
            .to_request(),
    )
    .await;
    assert_eq!(admin_page.headers().get("X-Total-Count").unwrap(), "2");
    let admin_body: serde_json::Value = test::read_body_json(admin_page).await;
    assert_eq!(admin_body.as_array().unwrap().len(), 1);
    let sorted_response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/api/v1/nameservers?sort=hostname&order=desc")
            .insert_header(("Authorization", format!("Bearer {ta}")))
            .to_request(),
    )
    .await;
    assert_eq!(sorted_response.status(), 200);
    let sorted_body: serde_json::Value = test::read_body_json(sorted_response).await;
    assert_eq!(sorted_body[0]["hostname"], "ns-on.example");
    let invalid_sort = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/api/v1/nameservers?sort=hostname%20DESC")
            .insert_header(("Authorization", format!("Bearer {ta}")))
            .to_request(),
    )
    .await;
    assert_eq!(invalid_sort.status(), 400);
    let invalid_body: serde_json::Value = test::read_body_json(invalid_sort).await;
    assert_eq!(invalid_body["error"], "invalid_query");
    // writes stay admin-only
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/nameservers",
        Some(&tc),
        j(serde_json::json!({"hostname":"evil.example","ip_address":"192.0.2.9"}))
    );
    assert_eq!(st, 403);
    // server status (infrastructure probe) is admin-only
    let (st, _, _) = call!(
        app,
        get,
        "/api/v1/servers/00000000-0000-0000-0000-000000000000/status",
        Some(&tc),
        None
    );
    assert_eq!(st, 403);
    env.cleanup().await;
}

#[actix_web::test]
async fn legacy_zones_migrate_into_personal_tenants_without_loss() {
    let Some(env) = setup().await else { return };
    // state before this feature: users own zones, zones have no tenant
    let bob = add_user(&env.state, "bob", "bob-pass-1234", "user").await;
    let zid = Uuid::new_v4().to_string();
    env.state.db.execute("INSERT INTO zones (id, domain, owner) VALUES ($1::text::uuid, 'bob-legacy.example', $2::text::uuid)", &[&zid, &bob]).await.unwrap();
    env.state
        .db
        .execute("UPDATE zones SET tenant_id = NULL", &[])
        .await
        .unwrap();
    env.state
        .db
        .execute("DELETE FROM tenant_members", &[])
        .await
        .unwrap();
    env.state
        .db
        .execute("DELETE FROM tenants", &[])
        .await
        .unwrap();
    let admin_zone = Uuid::new_v4().to_string();
    env.state.db.execute("INSERT INTO zones (id, domain, owner) VALUES ($1::text::uuid, 'platform.example', $2::text::uuid)", &[&admin_zone, &env.admin]).await.unwrap();
    for _ in 0..2 {
        env.state.db.batch_execute(tenants::SCHEMA).await.unwrap();
    } // idempotent
    let n: i64 = env
        .state
        .db
        .query_one("SELECT count(*) FROM tenants", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        n, 1,
        "one personal tenant for the one non-admin user (admins get none), not duplicated on re-run"
    );
    let r = env.state.db.query_one("SELECT CAST(tenant_id AS varchar) IS NOT NULL FROM zones WHERE domain = 'bob-legacy.example'", &[]).await.unwrap();
    assert!(
        r.get::<_, bool>(0),
        "legacy zone assigned to the owner's tenant"
    );
    let r = env
        .state
        .db
        .query_one(
            "SELECT tenant_id IS NULL FROM zones WHERE domain = 'platform.example'",
            &[],
        )
        .await
        .unwrap();
    assert!(r.get::<_, bool>(0), "admin-owned zones stay platform-level");
    let (m, q): (i64, i64) = {
        let r = env.state.db.query_one("SELECT (SELECT count(*) FROM tenant_members WHERE role='owner'), (SELECT count(*) FROM tenants WHERE max_zones IS NOT NULL OR max_records IS NOT NULL)", &[]).await.unwrap();
        (r.get(0), r.get(1))
    };
    assert_eq!(
        (m, q),
        (1, 0),
        "owner membership created, migrated tenants are unlimited"
    );
    // still fully functional through the API
    let tb = env.token(&bob, "user");
    let app = app!(env);
    let (st, b, raw) = call!(app, get, "/api/v1/zones", Some(&tb), None);
    assert_eq!(st, 200, "{raw}");
    assert_eq!(b["data"].as_array().unwrap().len(), 1);
    let (st, _, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{}/records", zid),
        Some(&tb),
        j(serde_json::json!({"name":"www","record_type":"A","value":"192.0.2.7","ttl":300}))
    );
    assert_eq!(st, 201, "{raw}");
    env.cleanup().await;
}

#[actix_web::test]
async fn tenants_isolate_customers_and_enforce_quotas() {
    let Some(env) = setup().await else { return };
    let alice = add_user(&env.state, "alice", "alice-pass-1", "user").await;
    let carol = add_user(&env.state, "carol", "carol-pass-1", "user").await;
    let (ta, tc, tadmin) = (
        env.token(&alice, "user"),
        env.token(&carol, "user"),
        env.token(&env.admin, "admin"),
    );
    let app = app!(env);
    let az = make_zone(&env, &app, &ta, "alice-one.example").await;
    let _cz = make_zone(&env, &app, &tc, "carol-one.example").await;

    let tenant_page = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/api/v1/tenants?limit=1&offset=1")
            .insert_header(("Authorization", format!("Bearer {tadmin}")))
            .to_request(),
    )
    .await;
    assert_eq!(tenant_page.status(), 200);
    assert_eq!(tenant_page.headers().get("X-Total-Count").unwrap(), "2");
    let tenant_page_body: serde_json::Value = test::read_body_json(tenant_page).await;
    assert_eq!(tenant_page_body.as_array().unwrap().len(), 1);

    // each customer lives in their own tenant and only sees it
    let (_, at, _) = call!(app, get, "/api/v1/tenants", Some(&ta), None);
    let (_, ct, _) = call!(app, get, "/api/v1/tenants", Some(&tc), None);
    assert_eq!(at.as_array().unwrap().len(), 1);
    assert_eq!(ct.as_array().unwrap().len(), 1);
    let atid = at[0]["id"].as_str().unwrap().to_string();
    let ctid = ct[0]["id"].as_str().unwrap().to_string();
    assert_ne!(atid, ctid);
    assert_eq!(at[0]["zones"], 1);
    let member_page = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/api/v1/tenants/{atid}/members?limit=1&q=alice"))
            .insert_header(("Authorization", format!("Bearer {ta}")))
            .to_request(),
    )
    .await;
    assert_eq!(member_page.status(), 200);
    assert_eq!(member_page.headers().get("X-Total-Count").unwrap(), "1");
    let member_page_body: serde_json::Value = test::read_body_json(member_page).await;
    assert_eq!(member_page_body.as_array().unwrap().len(), 1);
    // cross-tenant access is refused everywhere
    for (m, uri) in [("members", format!("/api/v1/tenants/{}/members", ctid))] {
        let _ = m;
        let (st, _, _) = call!(app, get, &uri, Some(&ta), None);
        assert_eq!(st, 404, "{uri}");
    }
    let (st, _, _) = call!(
        app,
        put,
        &format!("/api/v1/tenants/{}/members", ctid),
        Some(&ta),
        j(serde_json::json!({"username":"alice","role":"owner"}))
    );
    assert_eq!(st, 404);
    let (st, _, _) = call!(
        app,
        get,
        &format!("/api/v1/analytics/tenant?tenant_id={}", ctid),
        Some(&ta),
        None
    );
    assert_eq!(st, 404);
    let (st, _, _) = call!(app, get, "/api/v1/analytics/global", Some(&ta), None);
    assert_eq!(st, 403);
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/tenants",
        Some(&ta),
        j(serde_json::json!({"name":"mine"}))
    );
    assert_eq!(st, 403);
    let (st, _, _) = call!(
        app,
        put,
        &format!("/api/v1/tenants/{}", atid),
        Some(&ta),
        j(serde_json::json!({"name":"x","max_zones":9999}))
    );
    assert_eq!(st, 403, "customers cannot raise their own quota");
    let (st, _, _) = call!(
        app,
        delete,
        &format!("/api/v1/tenants/{}", atid),
        Some(&ta),
        None
    );
    assert_eq!(st, 403);
    let (st, _, _) = call!(
        app,
        put,
        &format!("/api/v1/zones/{}/tenant", az),
        Some(&ta),
        j(serde_json::json!({"tenant_id": ctid}))
    );
    assert_eq!(st, 403, "customers cannot move zones between tenants");
    let (st, _, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{}/records", az),
        Some(&tc),
        None
    );
    assert_eq!(st, 403);
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/zones",
        Some(&ta),
        j(serde_json::json!({"domain":"x.example","tenant_id": ctid}))
    );
    assert_eq!(st, 403, "cannot create zones in someone else's tenant");
    let (_, ov, _) = call!(app, get, "/api/v1/overview", Some(&tc), None);
    let doms: Vec<&str> = ov["zones"]
        .as_array()
        .unwrap()
        .iter()
        .map(|z| z["domain"].as_str().unwrap())
        .collect();
    assert_eq!(
        doms,
        vec!["carol-one.example"],
        "overview never leaks other tenants' zones"
    );

    // quotas: zones
    let (st, _, raw) = call!(
        app,
        put,
        &format!("/api/v1/tenants/{}", atid),
        Some(&tadmin),
        j(serde_json::json!({"name":"personal-alice","max_zones":2,"max_records":null}))
    );
    assert_eq!(st, 200, "{raw}");
    let _ = make_zone(&env, &app, &ta, "alice-two.example").await;
    let (st, b, raw) = call!(
        app,
        post,
        "/api/v1/zones",
        Some(&ta),
        j(serde_json::json!({"domain":"alice-three.example"}))
    );
    assert_eq!(st, 403, "{raw}");
    assert_eq!(b["error"], "quota_exceeded");
    assert_eq!(b["quota"], "zones");
    assert_eq!(b["limit"], 2);
    assert_eq!(b["used"], 2);
    assert!(!env.zone_file("alice-three.example").exists());
    // admin override (platform operators are not limited) and quota relief by raising the limit
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/zones",
        Some(&tadmin),
        j(serde_json::json!({"domain":"admin-for-alice.example","tenant_id": atid}))
    );
    assert_eq!(st, 201);
    // records
    let used: i64 = env.state.db.query_one("SELECT count(*) FROM records r JOIN zones z ON z.id=r.zone_id WHERE CAST(z.tenant_id AS varchar)=$1", &[&atid]).await.unwrap().get(0);
    call!(
        app,
        put,
        &format!("/api/v1/tenants/{}", atid),
        Some(&tadmin),
        j(serde_json::json!({"name":"personal-alice","max_zones":10,"max_records":used + 2}))
    );
    for i in 0..2 {
        let (st, _, raw) = call!(
            app,
            post,
            &format!("/api/v1/zones/{}/records", az),
            Some(&ta),
            j(
                serde_json::json!({"name":format!("h{i}"),"record_type":"A","value":"192.0.2.1","ttl":300})
            )
        );
        assert_eq!(st, 201, "{raw}");
    }
    let (st, b, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{}/records", az),
        Some(&ta),
        j(serde_json::json!({"name":"over","record_type":"A","value":"192.0.2.1","ttl":300}))
    );
    assert_eq!(st, 403, "{raw}");
    assert_eq!(b["quota"], "records");
    let (st, b, _) = call!(
        app,
        post,
        &format!("/api/v1/zones/{}/import", az),
        Some(&ta),
        j(serde_json::json!({"records":[{"name":"i1","record_type":"A","value":"192.0.2.2"}]}))
    );
    assert_eq!(st, 403, "import counts against the quota: {b}");
    let (st, _, _) = call!(
        app,
        post,
        &format!("/api/v1/zones/{}/records", az),
        Some(&tadmin),
        j(serde_json::json!({"name":"adm","record_type":"A","value":"192.0.2.1","ttl":300}))
    );
    assert_eq!(st, 201, "admin bypasses record quota");
    // deleting frees quota; other tenants were never affected
    let (_, recs, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{}/records", az),
        Some(&ta),
        None
    );
    let victim = recs
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "h0")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (st, _, _) = call!(
        app,
        delete,
        &format!("/api/v1/zones/{}/records/{}", az, victim),
        Some(&ta),
        None
    );
    assert_eq!(st, 200);
    // (admin added one record above, so usage is still at the limit until a second deletion)
    let victim2 = recs
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "h1")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    call!(
        app,
        delete,
        &format!("/api/v1/zones/{}/records/{}", az, victim2),
        Some(&ta),
        None
    );
    let (st, _, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{}/records", az),
        Some(&ta),
        j(serde_json::json!({"name":"again","record_type":"A","value":"192.0.2.1","ttl":300}))
    );
    assert_eq!(st, 201, "{raw}");
    let (st, _, raw) = call!(
        app,
        post,
        "/api/v1/zones",
        Some(&tc),
        j(serde_json::json!({"domain":"carol-two.example"}))
    );
    assert_eq!(st, 201, "carol unlimited: {raw}");
    // a restore cannot be used to get around the record quota (only growth is counted)
    let big: String = env.state.db.query_one("SELECT CAST(id AS varchar) FROM zone_revisions WHERE CAST(zone_id AS varchar) = $1 ORDER BY jsonb_array_length(records) DESC LIMIT 1", &[&az]).await.unwrap().get(0);
    let (st, b, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{}/revisions/{}/restore", az, big),
        Some(&ta),
        None
    );
    assert_eq!(
        st, 403,
        "restoring a larger revision must respect the quota: {raw}"
    );
    assert_eq!(b["error"], "quota_exceeded");

    // invalid quota values
    let (st, _, _) = call!(
        app,
        put,
        &format!("/api/v1/tenants/{}", atid),
        Some(&tadmin),
        j(serde_json::json!({"name":"personal-alice","max_zones":-1}))
    );
    assert_eq!(st, 400);
    // deleting a tenant that owns zones is refused (no silent orphaning)
    let (st, b, _) = call!(
        app,
        delete,
        &format!("/api/v1/tenants/{}", atid),
        Some(&tadmin),
        None
    );
    assert_eq!(st, 409, "{b}");
    env.cleanup().await;
}

#[actix_web::test]
async fn deleting_empty_tenant_removes_all_its_analytics_without_orphaning_zones() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let token = env.token(&env.admin, "admin");
    let (st, body, raw) = call!(
        app,
        post,
        "/api/v1/tenants",
        Some(&token),
        j(serde_json::json!({"name":"delete-fixture"}))
    );
    assert_eq!(st, 201, "{raw}");
    let id = body["id"].as_str().unwrap();
    for sql in [
        "INSERT INTO zone_query_samples(ts,tenant_id,domain,queries,failed) VALUES(now(),$1::text::uuid,'old.example',1,0)",
        "INSERT INTO zone_qtype_samples(ts,tenant_id,domain,qtype,queries) VALUES(now(),$1::text::uuid,'old.example','A',1)",
        "INSERT INTO zone_country_samples(ts,tenant_id,domain,country,queries) VALUES(now(),$1::text::uuid,'old.example','US',1)",
        "INSERT INTO tenant_usage_samples(ts,tenant_id,zones,records) VALUES(now(),$1::text::uuid,0,0)",
    ] {
        env.state.db.execute(sql, &[&id]).await.unwrap();
    }
    let (st, _, raw) = call!(
        app,
        delete,
        &format!("/api/v1/tenants/{id}"),
        Some(&token),
        None
    );
    assert_eq!(st, 200, "{raw}");
    for table in [
        "zone_query_samples",
        "zone_qtype_samples",
        "zone_country_samples",
        "tenant_usage_samples",
    ] {
        let n: i64 = env
            .state
            .db
            .query_one(
                &format!("SELECT count(*) FROM {table} WHERE CAST(tenant_id AS varchar)=$1"),
                &[&id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(n, 0, "{table} retained deleted tenant data");
    }
    let (st, _, _) = call!(
        app,
        delete,
        &format!("/api/v1/tenants/{id}"),
        Some(&token),
        None
    );
    assert_eq!(st, 404);
    env.cleanup().await;
}

#[actix_web::test]
async fn concurrent_zone_creates_cannot_exceed_quota() {
    let Some(env) = setup().await else { return };
    let dave = add_user(&env.state, "race-dave", "dave-pass-1", "user").await;
    let td = env.token(&dave, "user");
    let tadmin = env.token(&env.admin, "admin");
    let app = app!(env);
    let (_, ts, _) = call!(app, get, "/api/v1/tenants", Some(&td), None);
    let tid = ts[0]["id"].as_str().unwrap().to_string();
    let tname = ts[0]["name"].as_str().unwrap().to_string();
    let (st, _, raw) = call!(
        app,
        put,
        &format!("/api/v1/tenants/{}", tid),
        Some(&tadmin),
        j(serde_json::json!({"name": tname, "max_zones": 1, "max_records": null}))
    );
    assert_eq!(st, 200, "{raw}");
    let app_ref = &app;
    let results = futures_util::future::join_all((0..8).map(|i| {
        let td = td.clone();
        let domain = format!("race-zone-{i}.example");
        async move {
            let req = test::TestRequest::post()
                .uri("/api/v1/zones")
                .insert_header(("Authorization", format!("Bearer {}", td)))
                .set_json(serde_json::json!({"domain": domain}))
                .to_request();
            test::call_service(app_ref, req).await.status().as_u16()
        }
    }))
    .await;
    let created = results.iter().filter(|s| **s == 201).count();
    assert_eq!(
        created, 1,
        "only one concurrent creation may fit: {results:?}"
    );
    for st in results {
        assert!(st == 201 || st == 403, "unexpected status {st}");
    }
    let n: i64 = env
        .state
        .db
        .query_one(
            "SELECT count(*) FROM zones WHERE CAST(tenant_id AS varchar) = $1",
            &[&tid],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        n, 1,
        "the quota must be enforced in the database, not just pre-checked"
    );
    env.cleanup().await;
}

#[actix_web::test]
async fn concurrent_record_creates_cannot_exceed_quota() {
    let Some(env) = setup().await else { return };
    let dave = add_user(&env.state, "rec-dave", "dave-pass-1", "user").await;
    let td = env.token(&dave, "user");
    let tadmin = env.token(&env.admin, "admin");
    let app = app!(env);
    let z = make_zone(&env, &app, &td, "race-records.example").await;
    let (_, ts, _) = call!(app, get, "/api/v1/tenants", Some(&td), None);
    let tid = ts[0]["id"].as_str().unwrap().to_string();
    let tname = ts[0]["name"].as_str().unwrap().to_string();
    let used: i64 = env.state.db.query_one("SELECT count(*) FROM records r JOIN zones z ON z.id = r.zone_id WHERE CAST(z.tenant_id AS varchar) = $1", &[&tid]).await.unwrap().get(0);
    let (st, _, raw) = call!(
        app,
        put,
        &format!("/api/v1/tenants/{}", tid),
        Some(&tadmin),
        j(serde_json::json!({"name": tname, "max_zones": null, "max_records": used + 1}))
    );
    assert_eq!(st, 200, "{raw}");
    let app_ref = &app;
    let results = futures_util::future::join_all((0..8).map(|i| {
        let td = td.clone();
        let z = z.clone();
        async move {
            let req = test::TestRequest::post()
                .uri(&format!("/api/v1/zones/{}/records", z))
                .insert_header(("Authorization", format!("Bearer {}", td)))
                .set_json(serde_json::json!({"name": format!("r{i}"), "record_type": "A", "value": "192.0.2.1", "ttl": 300}))
                .to_request();
            test::call_service(app_ref, req).await.status().as_u16()
        }
    }))
    .await;
    let created = results.iter().filter(|s| **s == 201).count();
    assert_eq!(
        created, 1,
        "only one concurrent record may fit: {results:?}"
    );
    for st in results {
        assert!(st == 201 || st == 403, "unexpected status {st}");
    }
    let n: i64 = env.state.db.query_one("SELECT count(*) FROM records r JOIN zones z ON z.id = r.zone_id WHERE CAST(z.tenant_id AS varchar) = $1", &[&tid]).await.unwrap().get(0);
    assert_eq!(n, used + 1);
    env.cleanup().await;
}

#[actix_web::test]
async fn concurrent_imports_cannot_exceed_quota() {
    let Some(env) = setup().await else { return };
    let dave = add_user(&env.state, "imp-dave", "dave-pass-1", "user").await;
    let td = env.token(&dave, "user");
    let tadmin = env.token(&env.admin, "admin");
    let app = app!(env);
    let z = make_zone(&env, &app, &td, "race-imports.example").await;
    let (_, ts, _) = call!(app, get, "/api/v1/tenants", Some(&td), None);
    let tid = ts[0]["id"].as_str().unwrap().to_string();
    let tname = ts[0]["name"].as_str().unwrap().to_string();
    let used: i64 = env.state.db.query_one("SELECT count(*) FROM records r JOIN zones z ON z.id = r.zone_id WHERE CAST(z.tenant_id AS varchar) = $1", &[&tid]).await.unwrap().get(0);
    let (st, _, raw) = call!(
        app,
        put,
        &format!("/api/v1/tenants/{}", tid),
        Some(&tadmin),
        j(serde_json::json!({"name": tname, "max_zones": null, "max_records": used + 1}))
    );
    assert_eq!(st, 200, "{raw}");
    let app_ref = &app;
    let results = futures_util::future::join_all((0..4).map(|i| {
        let td = td.clone();
        let z = z.clone();
        async move {
            let req = test::TestRequest::post()
                .uri(&format!("/api/v1/zones/{}/import", z))
                .insert_header(("Authorization", format!("Bearer {}", td)))
                .set_json(serde_json::json!({"records": [{"name": format!("i{i}"), "record_type": "A", "value": "192.0.2.2"}]}))
                .to_request();
            test::call_service(app_ref, req).await.status().as_u16()
        }
    }))
    .await;
    let imported = results.iter().filter(|s| **s == 200).count();
    assert_eq!(
        imported, 1,
        "only one concurrent import may fit: {results:?}"
    );
    for st in results {
        assert!(st == 200 || st == 403, "unexpected status {st}");
    }
    let n: i64 = env.state.db.query_one("SELECT count(*) FROM records r JOIN zones z ON z.id = r.zone_id WHERE CAST(z.tenant_id AS varchar) = $1", &[&tid]).await.unwrap().get(0);
    assert_eq!(n, used + 1);
    env.cleanup().await;
}

#[actix_web::test]
async fn tenant_roles_control_zone_access_and_membership() {
    let Some(env) = setup().await else { return };
    let owner = add_user(&env.state, "org-owner", "owner-pass-1", "user").await;
    let ed = add_user(&env.state, "org-editor", "editor-pass-1", "user").await;
    let vw = add_user(&env.state, "org-viewer", "viewer-pass-1", "user").await;
    let out = add_user(&env.state, "outsider", "outsider-pass-1", "user").await;
    let (to, te, tv, tx, tadmin) = (
        env.token(&owner, "user"),
        env.token(&ed, "user"),
        env.token(&vw, "user"),
        env.token(&out, "user"),
        env.token(&env.admin, "admin"),
    );
    let app = app!(env);
    let z = make_zone(&env, &app, &to, "org.example").await;
    let (_, ts, _) = call!(app, get, "/api/v1/tenants", Some(&to), None);
    let tid = ts[0]["id"].as_str().unwrap().to_string();
    // owner invites an editor and a viewer
    for (u, r) in [("org-editor", "editor"), ("org-viewer", "viewer")] {
        let (st, _, raw) = call!(
            app,
            put,
            &format!("/api/v1/tenants/{}/members", tid),
            Some(&to),
            j(serde_json::json!({"username":u,"role":r}))
        );
        assert_eq!(st, 200, "{raw}");
    }
    let rec = serde_json::json!({"name":"w","record_type":"A","value":"192.0.2.3","ttl":300});
    let (st, _, _) = call!(
        app,
        post,
        &format!("/api/v1/zones/{}/records", z),
        Some(&te),
        j(rec.clone())
    );
    assert_eq!(st, 201, "editor writes");
    let (st, _, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{}/records", z),
        Some(&tv),
        None
    );
    assert_eq!(st, 200, "viewer reads");
    let (st, _, _) = call!(
        app,
        post,
        &format!("/api/v1/zones/{}/records", z),
        Some(&tv),
        j(rec.clone())
    );
    assert_eq!(st, 403, "tenant viewer cannot write");
    let (st, _, _) = call!(
        app,
        delete,
        &format!("/api/v1/zones/{}", z),
        Some(&te),
        None
    );
    assert_eq!(st, 403, "editor cannot delete the zone");
    let (st, _, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{}/records", z),
        Some(&tx),
        None
    );
    assert_eq!(st, 403, "outsider");
    let (_, l, _) = call!(app, get, "/api/v1/zones", Some(&te), None);
    assert_eq!(l["data"][0]["access"], "editor");
    assert_eq!(l["data"].as_array().unwrap().len(), 1);
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/zones",
        Some(&tv),
        j(serde_json::json!({"domain":"v.example"}))
    );
    assert!(
        st == 403 || st == 201 && false,
        "a tenant viewer's own personal tenant is separate; creating in the org tenant is refused"
    );
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/zones",
        Some(&tv),
        j(serde_json::json!({"domain":"v.example","tenant_id":tid}))
    );
    assert_eq!(st, 403);
    // membership management is owner-only
    let (st, _, _) = call!(
        app,
        put,
        &format!("/api/v1/tenants/{}/members", tid),
        Some(&te),
        j(serde_json::json!({"username":"outsider","role":"viewer"}))
    );
    assert_eq!(st, 403);
    let (st, m, _) = call!(
        app,
        get,
        &format!("/api/v1/tenants/{}/members", tid),
        Some(&tv),
        None
    );
    assert_eq!(st, 200);
    assert_eq!(m.as_array().unwrap().len(), 3);
    // the last owner cannot be removed or demoted
    let (st, _, _) = call!(
        app,
        delete,
        &format!("/api/v1/tenants/{}/members/{}", tid, owner),
        Some(&to),
        None
    );
    assert_eq!(st, 409);
    let (st, _, _) = call!(
        app,
        put,
        &format!("/api/v1/tenants/{}/members", tid),
        Some(&to),
        j(serde_json::json!({"user_id":owner,"role":"viewer"}))
    );
    assert_eq!(st, 409);
    // revocation is immediate
    let (st, _, _) = call!(
        app,
        delete,
        &format!("/api/v1/tenants/{}/members/{}", tid, ed),
        Some(&to),
        None
    );
    assert_eq!(st, 200);
    let (st, _, _) = call!(
        app,
        post,
        &format!("/api/v1/zones/{}/records", z),
        Some(&te),
        j(rec)
    );
    assert_eq!(st, 403);
    // admin can reassign the zone; target quota applies
    let (st, _, _) = call!(
        app,
        put,
        &format!("/api/v1/zones/{}/tenant", z),
        Some(&tadmin),
        j(serde_json::json!({"tenant_id": null}))
    );
    assert_eq!(st, 200);
    let (st, _, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{}/records", z),
        Some(&tv),
        None
    );
    assert_eq!(
        st, 403,
        "detached zone is no longer visible through the tenant"
    );
    env.cleanup().await;
}

#[actix_web::test]
async fn overview_is_one_accurate_tenant_scoped_query_and_scales() {
    let Some(env) = setup().await else { return };
    let alice = add_user(&env.state, "ov-alice", "alice-pass-1", "user").await;
    let other = add_user(&env.state, "ov-other", "other-pass-1", "user").await;
    let (ta, to, tadmin) = (
        env.token(&alice, "user"),
        env.token(&other, "user"),
        env.token(&env.admin, "admin"),
    );
    let app = app!(env);
    let z1 = make_zone(&env, &app, &ta, "ov-a.example").await;
    let _z2 = make_zone(&env, &app, &ta, "ov-b.example").await;
    let _zo = make_zone(&env, &app, &to, "ov-other.example").await;
    for i in 0..5 {
        call!(
            app,
            post,
            &format!("/api/v1/zones/{}/records", z1),
            Some(&ta),
            j(
                serde_json::json!({"name":format!("r{i}"),"record_type":"A","value":"192.0.2.1","ttl":300})
            )
        );
    }
    call!(
        app,
        post,
        &format!("/api/v1/zones/{}/records", z1),
        Some(&ta),
        j(serde_json::json!({"name":"m","record_type":"TXT","value":"hello","ttl":300}))
    );
    let (st, ov, raw) = call!(app, get, "/api/v1/overview", Some(&ta), None);
    assert_eq!(st, 200, "{raw}");
    assert_eq!(ov["zones_total"], 2);
    // counts equal what the records endpoint lists, per zone
    let mut sum = 0;
    for z in ov["zones"].as_array().unwrap() {
        let (_, recs, _) = call!(
            app,
            get,
            &format!("/api/v1/zones/{}/records", z["id"].as_str().unwrap()),
            Some(&ta),
            None
        );
        assert_eq!(
            z["records"].as_i64().unwrap(),
            recs.as_array().unwrap().len() as i64,
            "{}",
            z["domain"]
        );
        sum += z["records"].as_i64().unwrap();
    }
    assert_eq!(ov["records_total"], sum);
    assert_eq!(ov["records_by_type"]["TXT"], 1);
    assert_eq!(ov["tenants"].as_array().unwrap().len(), 1);
    assert_eq!(ov["tenants"][0]["records"], sum);

    // scale: 3,000 zones x 10 records in one tenant-less admin view plus a big customer
    env.state.db.batch_execute("INSERT INTO zones (id, domain, owner, tenant_id) SELECT gen_random_uuid(), 'bulk' || g || '.example', NULL, NULL FROM generate_series(1, 3000) g").await.unwrap();
    env.state.db.batch_execute("INSERT INTO records (id, zone_id, name, record_type, value, ttl) SELECT gen_random_uuid(), z.id, 'h' || g, 'A', '192.0.2.' || (g % 250 + 1), 300 FROM zones z, generate_series(1, 10) g WHERE z.domain LIKE 'bulk%'").await.unwrap();
    let queries_before = env.state.db.query_count();
    let t0 = std::time::Instant::now();
    let (st, ov, raw) = call!(app, get, "/api/v1/overview", Some(&tadmin), None);
    let admin_ms = t0.elapsed().as_millis();
    let overview_queries = env.state.db.query_count() - queries_before;
    assert_eq!(st, 200, "{}", &raw[..200.min(raw.len())]);
    assert_eq!(
        overview_queries, 2,
        "admin overview must stay one auth lookup plus one data query regardless of zone count"
    );
    assert!(ov["zones_total"].as_i64().unwrap() >= 3003);
    assert!(ov["records_total"].as_i64().unwrap() >= 30000);
    let t0 = std::time::Instant::now();
    let cust_before = env.state.db.query_count();
    let (_, ov2, _) = call!(app, get, "/api/v1/overview", Some(&ta), None);
    let cust_ms = t0.elapsed().as_millis();
    let customer_queries = env.state.db.query_count() - cust_before;
    assert_eq!(
        customer_queries, 3,
        "customer overview must stay one auth lookup plus two bounded data queries"
    );
    assert_eq!(
        ov2["zones_total"], 2,
        "bulk platform zones never leak into a customer's overview"
    );
    eprintln!(
        "overview timing: admin ({} zones, {} records) {} ms; customer {} ms",
        ov["zones_total"], ov["records_total"], admin_ms, cust_ms
    );
    assert!(
        admin_ms < 3000,
        "admin overview over 3,000 zones took {admin_ms} ms"
    );
    assert!(cust_ms < 500, "customer overview took {cust_ms} ms");
    env.cleanup().await;
}

#[actix_web::test]
async fn analytics_are_persistent_tenant_scoped_and_retained_configurably() {
    let Some(env) = setup().await else { return };
    let alice = add_user(&env.state, "an-alice", "alice-pass-1", "user").await;
    let carol = add_user(&env.state, "an-carol", "carol-pass-1", "user").await;
    let (ta, tc, tadmin) = (
        env.token(&alice, "user"),
        env.token(&carol, "user"),
        env.token(&env.admin, "admin"),
    );
    let app = app!(env);
    let _ = make_zone(&env, &app, &ta, "an-alice.example").await;
    let _ = make_zone(&env, &app, &tc, "an-carol.example").await;
    let metrics = |a: u32, c: u32, total: u32, ae: u32| {
        format!(
            "hickory_request_total{{class=\"in\"}} {total}\nhickory_zone_queries_total{{zone=\"an-alice.example.\",result=\"ok\"}} {a}\n\
         hickory_zone_queries_total{{zone=\"an-alice.example.\",result=\"error\"}} {ae}\nhickory_zone_queries_total{{zone=\"an-carol.example.\",result=\"ok\"}} {c}\n"
        )
    };
    let mut prev = tenants::Prev::default();
    let now = chrono::Utc::now().timestamp();
    let collect_db = env.state.db.connection();
    // first scrape is the baseline (no delta can be computed), later scrapes store the differences
    assert_eq!(
        tenants::ingest(
            &collect_db,
            &metrics(100, 50, 1000, 0),
            &mut prev,
            now - 120
        )
        .await
        .unwrap(),
        (0, 0)
    );
    assert_eq!(
        tenants::ingest(&collect_db, &metrics(160, 55, 1100, 4), &mut prev, now - 60)
            .await
            .unwrap(),
        (100, 2)
    );
    // a restart of the DNS server resets counters: the new value is the delta
    tenants::ingest(&collect_db, &metrics(10, 0, 20, 0), &mut prev, now)
        .await
        .unwrap();
    tenants::snapshot_usage(&env.state.db, now).await.unwrap();

    let (st, a, raw) = call!(
        app,
        get,
        "/api/v1/analytics/tenant?range=1h",
        Some(&ta),
        None
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(
        a["total_queries"],
        60 + 4 + 10,
        "alice: 60 ok + 4 errors in the first interval, 10 after reset: {raw}"
    );
    let zones: Vec<&str> = a["zones"]
        .as_array()
        .unwrap()
        .iter()
        .map(|z| z["domain"].as_str().unwrap())
        .collect();
    assert_eq!(
        zones,
        vec!["an-alice.example"],
        "a customer never sees other tenants' zones"
    );
    assert!(a["usage"].as_array().unwrap().len() >= 1);
    let (_, c, _) = call!(
        app,
        get,
        "/api/v1/analytics/tenant?range=1h",
        Some(&tc),
        None
    );
    assert_eq!(c["total_queries"], 5);
    assert_eq!(c["zones"].as_array().unwrap().len(), 1);
    // admin: global totals and any tenant
    let (st, g, raw) = call!(
        app,
        get,
        "/api/v1/analytics/global?range=24h",
        Some(&tadmin),
        None
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(g["total"], 100 + 20);
    assert!(g["top_zones"].as_array().unwrap().len() >= 2);
    let (_, all, _) = call!(
        app,
        get,
        "/api/v1/analytics/tenant?range=1h",
        Some(&tadmin),
        None
    );
    assert_eq!(all["zones"].as_array().unwrap().len(), 2);
    // zone filter inside a tenant
    let (_, f, _) = call!(
        app,
        get,
        "/api/v1/analytics/tenant?range=1h&zone=an-alice.example",
        Some(&ta),
        None
    );
    assert_eq!(f["total_queries"], 74);
    let (st, _, _) = call!(
        app,
        get,
        "/api/v1/analytics/tenant?range=forever",
        Some(&ta),
        None
    );
    assert_eq!(
        st, 400,
        "unknown ranges must be rejected, not silently defaulted"
    );
    let (st, _, _) = call!(
        app,
        get,
        "/api/v1/analytics/tenant?range=1h&interval=2m",
        Some(&ta),
        None
    );
    assert_eq!(st, 400, "unknown intervals must be rejected");
    // history survives deleting the zone (no foreign key) and is purged by the configurable retention
    env.state
        .db
        .execute("DELETE FROM zones WHERE domain = 'an-alice.example'", &[])
        .await
        .unwrap();
    let n: i64 = env
        .state
        .db
        .query_one(
            "SELECT count(*) FROM zone_query_samples WHERE domain='an-alice.example'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(n > 0, "history persists after zone deletion");
    env.state
        .db
        .execute(
            "UPDATE zone_query_samples SET ts = ts - interval '40 days'",
            &[],
        )
        .await
        .unwrap();
    assert!(tenants::purge_analytics(&env.state.db, 30).await.unwrap() > 0);
    let n: i64 = env
        .state
        .db
        .query_one("SELECT count(*) FROM zone_query_samples", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(n, 0, "rows older than the retention are removed");
    env.cleanup().await;
}

// ===========================================================================
// Zone transfer between tenants
// ===========================================================================

#[actix_web::test]
async fn zone_transfer_is_atomic_authorised_quota_checked_and_audited() {
    let Some(env) = setup().await else { return };
    let alice = add_user(&env.state, "tr-alice", "alice-pass-1", "user").await;
    let carol = add_user(&env.state, "tr-carol", "carol-pass-1", "user").await;
    let sharee = add_user(&env.state, "tr-sharee", "sharee-pass-1", "user").await;
    let (ta, tc, ts, tadmin) = (
        env.token(&alice, "user"),
        env.token(&carol, "user"),
        env.token(&sharee, "user"),
        env.token(&env.admin, "admin"),
    );
    let app = app!(env);
    let z = make_zone(&env, &app, &ta, "moveme.example").await;
    let _z2 = make_zone(&env, &app, &ta, "moveme2.example").await;
    let _cz = make_zone(&env, &app, &tc, "carol-home.example").await;
    for i in 0..3 {
        call!(
            app,
            post,
            &format!("/api/v1/zones/{}/records", z),
            Some(&ta),
            j(
                serde_json::json!({"name":format!("h{i}"),"record_type":"A","value":"192.0.2.1","ttl":300})
            )
        );
    }
    let (_, tl, _) = call!(app, get, "/api/v1/tenants", Some(&tadmin), None);
    let tid = |n: &str| {
        tl.as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == n)
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let (at, ct) = (tid("personal-tr-alice"), tid("personal-tr-carol"));
    // a share and a geo rule that must survive / be handled
    let (st, _, raw) = call!(
        app,
        put,
        &format!("/api/v1/zones/{}/members", z),
        Some(&ta),
        j(serde_json::json!({"username":"tr-sharee","role":"viewer"}))
    );
    assert_eq!(st, 200, "{raw}");
    let (st, _, raw) = call!(
        app,
        post,
        "/api/v1/georules",
        Some(&ta),
        j(
            serde_json::json!({"zone_id": z, "match_type":"country","match_value":"DE","target":"192.0.2.9","priority":1,"enabled":true})
        )
    );
    assert!(st == 200 || st == 201, "{raw}");
    let ids = |v: &serde_json::Value| {
        let mut x: Vec<String> = v
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap().to_string())
            .collect();
        x.sort();
        x
    };
    let (_, before, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{}/records", z),
        Some(&ta),
        None
    );
    let before_ids = ids(&before);
    let nrules_before: i64 = env
        .state
        .db
        .query_one(
            "SELECT count(*) FROM georules WHERE CAST(zone_id AS varchar) = $1",
            &[&z],
        )
        .await
        .unwrap()
        .get(0);

    // authorization and validation
    let uri = format!("/api/v1/zones/{}/tenant", z);
    for t in [&ta, &tc, &ts] {
        let (st, _, _) = call!(
            app,
            put,
            &uri,
            Some(t),
            j(serde_json::json!({"tenant_id": ct}))
        );
        assert_eq!(st, 403, "only administrators transfer zones");
    }
    let (st, _, _) = call!(
        app,
        put,
        &uri,
        None::<&str>,
        j(serde_json::json!({"tenant_id": ct}))
    );
    assert_eq!(st, 401);
    let (st, _, _) = call!(
        app,
        put,
        &uri,
        Some(&tadmin),
        j(serde_json::json!({"tenant_id": Uuid::new_v4().to_string()}))
    );
    assert_eq!(st, 404, "unknown destination");
    let (st, _, _) = call!(
        app,
        put,
        &uri,
        Some(&tadmin),
        j(serde_json::json!({"tenant_id": "not-a-uuid"}))
    );
    assert_eq!(st, 400);
    let (st, _, _) = call!(
        app,
        put,
        &uri,
        Some(&tadmin),
        j(serde_json::json!({"tenant_id": at}))
    );
    assert_eq!(st, 400, "same tenant is a no-op error");
    let (st, _, _) = call!(
        app,
        put,
        &format!("/api/v1/zones/{}/tenant", Uuid::new_v4()),
        Some(&tadmin),
        j(serde_json::json!({"tenant_id": ct}))
    );
    assert_eq!(st, 404);

    // quota failures leave EVERYTHING untouched (atomic)
    call!(
        app,
        put,
        &format!("/api/v1/tenants/{}", ct),
        Some(&tadmin),
        j(serde_json::json!({"name":"personal-tr-carol","max_zones":1,"max_records":null}))
    );
    let (st, b, raw) = call!(
        app,
        put,
        &uri,
        Some(&tadmin),
        j(serde_json::json!({"tenant_id": ct}))
    );
    assert_eq!(st, 403, "{raw}");
    assert_eq!(b["quota"], "zones");
    let used: i64 = env.state.db.query_one("SELECT count(*) FROM records r JOIN zones z ON z.id=r.zone_id WHERE CAST(z.tenant_id AS varchar)=$1", &[&ct]).await.unwrap().get(0);
    call!(
        app,
        put,
        &format!("/api/v1/tenants/{}", ct),
        Some(&tadmin),
        j(serde_json::json!({"name":"personal-tr-carol","max_zones":5,"max_records":used + 2}))
    );
    let (st, b, raw) = call!(
        app,
        put,
        &uri,
        Some(&tadmin),
        j(serde_json::json!({"tenant_id": ct}))
    );
    assert_eq!(st, 403, "{raw}");
    assert_eq!(b["quota"], "records");
    let cur: (Option<String>, i64) = {
        let r = env.state.db.query_one("SELECT CAST(tenant_id AS varchar), (SELECT count(*) FROM zone_members WHERE CAST(zone_id AS varchar)=$1) FROM zones WHERE CAST(id AS varchar)=$1", &[&z]).await.unwrap();
        (r.get(0), r.get(1))
    };
    assert_eq!(
        cur.0.as_deref(),
        Some(at.as_str()),
        "failed transfer must not move the zone"
    );
    assert_eq!(cur.1, 1, "nor drop the share");

    // success
    call!(
        app,
        put,
        &format!("/api/v1/tenants/{}", ct),
        Some(&tadmin),
        j(serde_json::json!({"name":"personal-tr-carol","max_zones":5,"max_records":null}))
    );
    let (st, b, raw) = call!(
        app,
        put,
        &uri,
        Some(&tadmin),
        j(serde_json::json!({"tenant_id": ct}))
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(b["records"], before_ids.len() as i64);
    assert_eq!(b["shares_removed"], 1);
    assert_eq!(b["owner_changed"], true);
    assert_eq!(b["from"]["name"], "personal-tr-alice");
    assert_eq!(b["to"]["name"], "personal-tr-carol");
    let (_, after, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{}/records", z),
        Some(&tc),
        None
    );
    assert_eq!(
        ids(&after),
        before_ids,
        "same record rows: nothing duplicated or lost"
    );
    let nrules: i64 = env
        .state
        .db
        .query_one(
            "SELECT count(*) FROM georules WHERE CAST(zone_id AS varchar) = $1",
            &[&z],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(nrules, nrules_before, "geo rules preserved");
    assert!(
        env.zone_file("moveme.example").is_file(),
        "zone still published"
    );
    let (st, _, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{}/records", z),
        Some(&ta),
        None
    );
    assert_eq!(
        st, 403,
        "previous tenant lost access (owner moved, shares removed)"
    );
    let (st, _, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{}/records", z),
        Some(&ts),
        None
    );
    assert_eq!(st, 403, "removed share");
    let (_, lz, _) = call!(app, get, "/api/v1/zones", Some(&tadmin), None);
    let row = lz["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["domain"] == "moveme.example")
        .unwrap();
    assert_eq!(row["tenant_name"], "personal-tr-carol");
    assert_eq!(row["tenant_id"], ct.as_str());
    // audit
    let (_, au, _) = call!(
        app,
        get,
        "/api/v1/audit/logs?action=zone.transfer",
        Some(&tadmin),
        None
    );
    let e = au
        .as_array()
        .map(|a| a.to_vec())
        .or_else(|| au["data"].as_array().cloned())
        .unwrap_or_default();
    assert!(!e.is_empty(), "transfer is audited: {au}");
    let d = e[0]["details"].to_string();
    assert!(
        d.contains("personal-tr-alice")
            && d.contains("personal-tr-carol")
            && d.contains("moveme.example")
            && d.contains(&env.admin),
        "audit lacks source/destination/actor: {d}"
    );

    // keep_shares keeps the explicit grant
    call!(
        app,
        put,
        &format!("/api/v1/zones/{}/members", _z2),
        Some(&ta),
        j(serde_json::json!({"username":"tr-sharee","role":"viewer"}))
    );
    let (st, b, raw) = call!(
        app,
        put,
        &format!("/api/v1/zones/{}/tenant", _z2),
        Some(&tadmin),
        j(serde_json::json!({"tenant_id": ct, "keep_shares": true}))
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(b["shares_removed"], 0);
    let (st, _, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{}/records", _z2),
        Some(&ts),
        None
    );
    assert_eq!(st, 200);

    // race: two zones into a tenant with room for exactly one more
    let r1 = make_zone(&env, &app, &tadmin, "race-a.example").await;
    let r2 = make_zone(&env, &app, &tadmin, "race-b.example").await;
    let zones_now: i64 = env
        .state
        .db
        .query_one(
            "SELECT count(*) FROM zones WHERE CAST(tenant_id AS varchar)=$1",
            &[&ct],
        )
        .await
        .unwrap()
        .get(0);
    call!(
        app,
        put,
        &format!("/api/v1/tenants/{}", ct),
        Some(&tadmin),
        j(
            serde_json::json!({"name":"personal-tr-carol","max_zones": zones_now + 1,"max_records":null})
        )
    );
    let (u1, u2) = (
        format!("/api/v1/zones/{}/tenant", r1),
        format!("/api/v1/zones/{}/tenant", r2),
    );
    let (a, b) = futures_util::future::join(
        async {
            call!(
                app,
                put,
                &u1,
                Some(&tadmin),
                j(serde_json::json!({"tenant_id": ct}))
            )
            .0
        },
        async {
            call!(
                app,
                put,
                &u2,
                Some(&tadmin),
                j(serde_json::json!({"tenant_id": ct}))
            )
            .0
        },
    )
    .await;
    let mut got = vec![a, b];
    got.sort();
    assert_eq!(
        got,
        vec![200, 403],
        "exactly one concurrent transfer fits the quota"
    );
    let zones_end: i64 = env
        .state
        .db
        .query_one(
            "SELECT count(*) FROM zones WHERE CAST(tenant_id AS varchar)=$1",
            &[&ct],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(zones_end, zones_now + 1);
    // detach to platform
    let (st, _, raw) = call!(
        app,
        put,
        &uri,
        Some(&tadmin),
        j(serde_json::json!({"tenant_id": null}))
    );
    assert_eq!(st, 200, "{raw}");
    let (st, _, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{}/records", z),
        Some(&tc),
        None
    );
    assert_eq!(st, 403, "detached zone is invisible to tenant members");
    env.cleanup().await;
}

// ===========================================================================
// DNS Lookup: multiple resolvers, failover, selection, IPv4/IPv6
// ===========================================================================

#[derive(Clone, Copy, PartialEq)]
enum Behave {
    Answer,
    Servfail,
    Refused,
    Silent,
}

/// UDP resolver on `bind` that answers A queries with TTL `ttl` (or misbehaves). Counts the queries it received.
async fn behaving_resolver(
    bind: &str,
    how: Behave,
    ttl: u32,
) -> Option<(std::net::SocketAddr, Arc<std::sync::atomic::AtomicUsize>)> {
    use hickory_proto::op::{Message, ResponseCode};
    use hickory_proto::rr::{RData, Record, rdata::A};
    let sock = tokio::net::UdpSocket::bind(bind).await.ok()?;
    let addr = sock.local_addr().ok()?;
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let h = hits.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            h.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let Ok(q) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            if how == Behave::Silent {
                continue;
            }
            let mut r = Message::response(q.id(), q.op_code());
            for qq in q.queries() {
                r.add_query(qq.clone());
                match how {
                    Behave::Servfail => {
                        r.set_response_code(ResponseCode::ServFail);
                    }
                    Behave::Refused => {
                        r.set_response_code(ResponseCode::Refused);
                    }
                    _ => {
                        r.add_answer(Record::from_rdata(
                            qq.name().clone(),
                            ttl,
                            RData::A(A::new(192, 0, 2, 1)),
                        ));
                    }
                }
            }
            let _ = sock.send_to(&r.to_vec().unwrap(), from).await;
        }
    });
    Some((addr, hits))
}

fn spec(addrs: &[(&str, std::net::SocketAddr)]) -> Vec<lookup::ResolverSpec> {
    addrs
        .iter()
        .map(|(l, a)| lookup::ResolverSpec {
            label: l.to_string(),
            addr: *a,
        })
        .collect()
}

#[actix_web::test]
async fn dns_lookup_failover_selection_and_information_hiding() {
    std::env::set_var("DNS_LOOKUP_TIMEOUT_MS", "400");
    let Some(mut env) = setup().await else { return };
    let user = add_user(&env.state, "mr-user", "mr-user-pass-1", "user").await;
    let (tu, tadmin) = (env.token(&user, "user"), env.token(&env.admin, "admin"));
    let (a1, h1) = behaving_resolver("127.0.0.1:0", Behave::Answer, 111)
        .await
        .unwrap();
    let (a2, _h2) = behaving_resolver("127.0.0.1:0", Behave::Answer, 222)
        .await
        .unwrap();
    let (sf, _) = behaving_resolver("127.0.0.1:0", Behave::Servfail, 0)
        .await
        .unwrap();
    let (rf, _) = behaving_resolver("127.0.0.1:0", Behave::Refused, 0)
        .await
        .unwrap();
    let (si, hs) = behaving_resolver("127.0.0.1:0", Behave::Silent, 0)
        .await
        .unwrap();
    let q = serde_json::json!({"domain":"www.example","record_type":"A"});

    // 0. nothing configured -> explicit "not configured", never a built-in public resolver
    {
        let app = app!(env);
        let (st, b, raw) = call!(app, post, "/api/v1/dns/lookup", Some(&tu), j(q.clone()));
        assert_eq!(st, 503, "{raw}");
        assert_eq!(b["error"], "not_configured");
    }

    // 1. primary success: the second resolver is never asked
    env.state.lookup_resolvers = spec(&[("primary", a1), ("secondary", a2)]);
    env.full.inner = env.state.clone();
    let app = app!(env);
    let (st, b, raw) = call!(app, post, "/api/v1/dns/lookup", Some(&tu), j(q.clone()));
    assert_eq!(st, 200, "{raw}");
    assert_eq!(b["records"][0]["ttl"], 111);
    assert!(
        b.get("resolver").is_none() && b.get("attempts").is_none(),
        "customers see no resolver details: {raw}"
    );
    assert!(
        !raw.contains("127.0.0.1") && !raw.contains("primary"),
        "{raw}"
    );
    let (_, ba, _) = call!(app, post, "/api/v1/dns/lookup", Some(&tadmin), j(q.clone()));
    assert!(
        ba["resolver"]
            .as_str()
            .unwrap()
            .starts_with("primary (127.0.0.1:"),
        "{ba}"
    );
    assert_eq!(ba["attempts"].as_array().unwrap().len(), 1);

    // 2. primary times out -> fallback answers, within roughly one timeout
    env.state.lookup_resolvers = spec(&[("dead", si), ("backup", a2)]);
    env.full.inner = env.state.clone();
    let app = app!(env);
    let t0 = std::time::Instant::now();
    let (st, b, raw) = call!(app, post, "/api/v1/dns/lookup", Some(&tu), j(q.clone()));
    let first = t0.elapsed();
    assert_eq!(st, 200, "{raw}");
    assert_eq!(b["records"][0]["ttl"], 222);
    assert!(
        first >= std::time::Duration::from_millis(380)
            && first < std::time::Duration::from_millis(1500),
        "one timeout, not more: {first:?}"
    );
    let (_, ba, _) = call!(
        app,
        post,
        "/api/v1/dns/lookup",
        Some(&tadmin),
        j(serde_json::json!({"domain":"www.example","record_type":"A"}))
    );
    // 3. the failed resolver is remembered: the next lookups do not pay the timeout again
    let before = hs.load(std::sync::atomic::Ordering::SeqCst);
    let t1 = std::time::Instant::now();
    let (st, _, _) = call!(app, post, "/api/v1/dns/lookup", Some(&tu), j(q.clone()));
    assert_eq!(st, 200);
    assert!(
        t1.elapsed() < std::time::Duration::from_millis(300),
        "demoted resolver must not delay the next lookup: {:?}",
        t1.elapsed()
    );
    assert_eq!(
        hs.load(std::sync::atomic::Ordering::SeqCst),
        before,
        "demoted resolver was not queried again"
    );
    let _ = ba;

    // 4. SERVFAIL / REFUSED on the primary -> fallback success
    for (label, bad) in [("servfail", sf), ("refused", rf)] {
        env.state.lookup_resolvers = spec(&[(label, bad), ("good", a1)]);
        env.full.inner = env.state.clone();
        let app = app!(env);
        let (st, b, raw) = call!(
            app,
            post,
            "/api/v1/dns/lookup",
            Some(&tu),
            j(serde_json::json!({"domain":format!("{label}.example"),"record_type":"A"}))
        );
        assert_eq!(st, 200, "{label}: {raw}");
        assert_eq!(b["status"], "NOERROR");
        assert_eq!(b["records"][0]["ttl"], 111);
    }
    // 5. every resolver answers SERVFAIL: that status is returned honestly (not an invented success, not a 502)
    env.state.lookup_resolvers = spec(&[("s1", sf), ("s2", rf)]);
    env.full.inner = env.state.clone();
    {
        let app = app!(env);
        let (st, b, raw) = call!(
            app,
            post,
            "/api/v1/dns/lookup",
            Some(&tu),
            j(serde_json::json!({"domain":"allbad.example","record_type":"A"}))
        );
        assert_eq!(st, 200, "{raw}");
        assert_eq!(b["status"], "REFUSED");
        assert!(b["records"].as_array().unwrap().is_empty());
    }
    // 6. all unavailable -> 502; customers see no addresses, administrators see each resolver's outcome
    env.state.lookup_resolvers = spec(&[("x1", "127.0.0.1:9".parse().unwrap()), ("x2", si)]);
    env.full.inner = env.state.clone();
    {
        let app = app!(env);
        let (st, b, raw) = call!(
            app,
            post,
            "/api/v1/dns/lookup",
            Some(&tu),
            j(serde_json::json!({"domain":"down.example","record_type":"A"}))
        );
        assert_eq!(st, 502, "{raw}");
        assert_eq!(b["error"], "resolver_unavailable");
        assert!(
            !raw.contains("127.0.0.1") && !raw.contains("x1") && !raw.contains("attempts"),
            "{raw}"
        );
        let (st, b, raw) = call!(
            app,
            post,
            "/api/v1/dns/lookup",
            Some(&tadmin),
            j(serde_json::json!({"domain":"down2.example","record_type":"A"}))
        );
        assert_eq!(st, 502);
        assert_eq!(b["attempts"].as_array().unwrap().len(), 2, "{raw}");
        assert!(raw.contains("127.0.0.1"));
    }
    // 7. selection: administrators may pick a resolver by label, customers may not, unknown labels are rejected
    env.state.lookup_resolvers = spec(&[("one", a1), ("two", a2)]);
    env.full.inner = env.state.clone();
    {
        let app = app!(env);
        let (st, b, _) = call!(
            app,
            post,
            "/api/v1/dns/lookup",
            Some(&tadmin),
            j(serde_json::json!({"domain":"sel.example","record_type":"A","resolver":"two"}))
        );
        assert_eq!(st, 200);
        assert_eq!(b["records"][0]["ttl"], 222);
        let (st, _, _) = call!(
            app,
            post,
            "/api/v1/dns/lookup",
            Some(&tu),
            j(serde_json::json!({"domain":"sel.example","record_type":"A","resolver":"two"}))
        );
        assert_eq!(st, 403);
        let (st, _, _) = call!(
            app,
            post,
            "/api/v1/dns/lookup",
            Some(&tadmin),
            j(serde_json::json!({"domain":"sel.example","record_type":"A","resolver":"nope"}))
        );
        assert_eq!(st, 400);
    }
    let _ = h1;
    env.cleanup().await;
}

#[actix_web::test]
async fn dns_lookup_works_with_ipv6_resolvers_and_mixed_families() {
    std::env::set_var("DNS_LOOKUP_TIMEOUT_MS", "400");
    let Some(mut env) = setup().await else { return };
    let Some((v6, _)) = behaving_resolver("[::1]:0", Behave::Answer, 606).await else {
        eprintln!("SKIPPED: no IPv6 loopback");
        env.cleanup().await;
        return;
    };
    let (v4dead, _) = behaving_resolver("127.0.0.1:0", Behave::Silent, 0)
        .await
        .unwrap();
    let user = add_user(&env.state, "v6-user", "v6-user-pass-1", "user").await;
    let tu = env.token(&user, "user");
    assert!(v6.is_ipv6());
    // textual configuration round trip for IPv6
    let cfg = lookup::parse_resolvers(&format!("six={}", v6)).unwrap();
    assert_eq!(cfg[0].addr, v6);
    env.state.lookup_resolvers = cfg;
    env.full.inner = env.state.clone();
    {
        let app = app!(env);
        let (st, b, raw) = call!(
            app,
            post,
            "/api/v1/dns/lookup",
            Some(&tu),
            j(serde_json::json!({"domain":"v6.example","record_type":"A"}))
        );
        assert_eq!(st, 200, "{raw}");
        assert_eq!(b["records"][0]["ttl"], 606);
    }
    env.state.lookup_resolvers = spec(&[("v4dead", v4dead), ("six", v6)]);
    env.full.inner = env.state.clone();
    {
        let app = app!(env);
        let (st, b, raw) = call!(
            app,
            post,
            "/api/v1/dns/lookup",
            Some(&tu),
            j(serde_json::json!({"domain":"mixed.example","record_type":"A"}))
        );
        assert_eq!(st, 200, "{raw}");
        assert_eq!(
            b["records"][0]["ttl"], 606,
            "IPv4 resolver down -> IPv6 fallback"
        );
    }
    env.cleanup().await;
}

// ===========================================================================
// Shared coordination primitives (what the multi-replica lab relies on)
// ===========================================================================

#[actix_web::test]
async fn shared_rate_limit_is_atomic_under_concurrency() {
    let Some(env) = setup().await else { return };
    // 40 concurrent "replicas" (separate pooled connections) against ONE bucket with a budget of 10
    let db = env.state.db.clone();
    let mut tasks = vec![];
    for _ in 0..40 {
        let db = db.clone();
        tasks.push(tokio::spawn(async move {
            shared::hit(&db, "t:one", 10, 60).await.unwrap()
        }));
    }
    let mut allowed = 0;
    for t in tasks {
        if t.await.unwrap().is_none() {
            allowed += 1;
        }
    }
    assert_eq!(allowed, 10, "exactly the budget is granted, never more");
    // buckets are isolated from each other
    assert!(shared::hit(&db, "t:other", 10, 60).await.unwrap().is_none());
    let wait = shared::hit(&db, "t:one", 10, 60).await.unwrap().unwrap();
    assert!(wait >= 1 && wait <= 60, "retry-after is reported: {wait}");
    // purge removes only expired windows
    db.execute("UPDATE shared_rate_limits SET window_start = window_start - interval '1 hour' WHERE bucket = 't:other'", &[]).await.unwrap();
    assert_eq!(shared::purge_rate_limits(&db).await.unwrap(), 1);
    env.cleanup().await;
}

#[actix_web::test]
async fn collector_lease_has_one_holder_and_expires() {
    let Some(env) = setup().await else { return };
    let db = &env.state.db;
    assert!(shared::try_lease(db, "x", "A", 60.0).await.unwrap());
    assert!(
        !shared::try_lease(db, "x", "B", 60.0).await.unwrap(),
        "second replica is refused while the lease is valid"
    );
    assert!(
        shared::try_lease(db, "x", "A", 60.0).await.unwrap(),
        "holder renews"
    );
    db.execute(
        "UPDATE collector_lease SET expires_at = now() - interval '1 second' WHERE name = 'x'",
        &[],
    )
    .await
    .unwrap();
    assert!(
        shared::try_lease(db, "x", "B", 60.0).await.unwrap(),
        "expired lease is taken over"
    );
    assert!(
        !shared::try_lease(db, "x", "A", 60.0).await.unwrap(),
        "the former holder is now refused"
    );
    env.cleanup().await;
}

#[actix_web::test]
async fn persisted_collector_state_prevents_duplicates_and_loses_nothing() {
    let Some(env) = setup().await else { return };
    let db = &env.state.db;
    let alice = add_user(&env.state, "cs-alice", "alice-pass-1", "user").await;
    let ta = env.token(&alice, "user");
    let app = app!(env);
    let _ = make_zone(&env, &app, &ta, "cs-zone.example").await;
    let m = |total: u32, z: u32| {
        format!(
            "hickory_request_total{{class=\"in\"}} {total}\nhickory_zone_queries_total{{zone=\"cs-zone.example.\",result=\"ok\"}} {z}\n"
        )
    };
    let sum = || async {
        let r = db.query_one("SELECT COALESCE(sum(requests),0)::bigint, (SELECT COALESCE(sum(queries),0)::bigint FROM zone_query_samples) FROM analytics_samples", &[]).await.unwrap();
        (r.get::<_, i64>(0), r.get::<_, i64>(1))
    };
    let now = chrono::Utc::now().timestamp();
    tenants::ingest_persistent(db, &m(1000, 100), now - 100)
        .await
        .unwrap(); // baseline
    tenants::ingest_persistent(db, &m(1050, 130), now - 90)
        .await
        .unwrap(); // +50 / +30
    // a second replica (or a retry) delivering the SAME scrape adds nothing
    tenants::ingest_persistent(db, &m(1050, 130), now - 85)
        .await
        .unwrap();
    assert_eq!(
        sum().await,
        (50, 30),
        "duplicate delivery must not double count"
    );
    // two writers racing on the same new scrape: exactly one delta
    let (m1, m2) = (m(1100, 160), m(1100, 160));
    let (a, b) = tokio::join!(
        tenants::ingest_persistent(db, &m1, now - 80),
        tenants::ingest_persistent(db, &m2, now - 79)
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(
        sum().await,
        (100, 60),
        "concurrent writers produce one sample, not two"
    );
    // an outage: several scrapes are never ingested; the first one afterwards records the entire gap
    tenants::ingest_persistent(db, &m(1400, 400), now - 10)
        .await
        .unwrap();
    assert_eq!(sum().await, (400, 300), "no data lost across a gap");
    // a failed write rolls back everything including the stored counters (so it is retried, not skipped)
    db.batch_execute("ALTER TABLE analytics_samples RENAME TO analytics_samples_x")
        .await
        .unwrap();
    assert!(
        tenants::ingest_persistent(db, &m(1500, 500), now)
            .await
            .is_err()
    );
    db.batch_execute("ALTER TABLE analytics_samples_x RENAME TO analytics_samples")
        .await
        .unwrap();
    tenants::ingest_persistent(db, &m(1500, 500), now)
        .await
        .unwrap();
    assert_eq!(
        sum().await,
        (500, 400),
        "the failed attempt left no trace and the retry recorded the full delta"
    );
    // counter reset (DNS server restart): the new value is the delta
    tenants::ingest_persistent(db, &m(20, 5), now + 5)
        .await
        .unwrap();
    assert_eq!(sum().await, (520, 405));
    env.cleanup().await;
}

// ===========================================================================
// Record-type / country breakdowns
// ===========================================================================

#[actix_web::test]
async fn breakdowns_are_isolated_bounded_honest_and_from_real_samples() {
    let Some(env) = setup().await else { return };
    let db = &env.state.db;
    let alice = add_user(&env.state, "bd-alice", "alice-pass-1", "user").await;
    let carol = add_user(&env.state, "bd-carol", "carol-pass-1", "user").await;
    let (ta, tc, tadmin) = (
        env.token(&alice, "user"),
        env.token(&carol, "user"),
        env.token(&env.admin, "admin"),
    );
    let app = app!(env);
    let _ = make_zone(&env, &app, &ta, "bd-alice.example").await;
    let _ = make_zone(&env, &app, &ta, "bd-alice2.example").await;
    let _ = make_zone(&env, &app, &tc, "bd-carol.example").await;
    let scrape = |k: u32| {
        format!(
            "hickory_request_total{{class=\"in\"}} {}\n\
         hickory_zone_queries_total{{zone=\"bd-alice.example.\",result=\"ok\"}} {}\n\
         hickory_zone_qtype_total{{zone=\"bd-alice.example.\",qtype=\"A\"}} {}\nhickory_zone_qtype_total{{zone=\"bd-alice.example.\",qtype=\"MX\"}} {}\n\
         hickory_zone_qtype_total{{zone=\"bd-alice2.example.\",qtype=\"TXT\"}} {}\n\
         hickory_zone_qtype_total{{zone=\"bd-carol.example.\",qtype=\"CAA\"}} {}\n\
         hickory_zone_qtype_total{{zone=\"bd-alice.example.\",qtype=\"A;DROP\"}} 99999\n\
         hickory_zone_country_total{{zone=\"bd-alice.example.\",country=\"DE\"}} {}\nhickory_zone_country_total{{zone=\"bd-alice.example.\",country=\"ZZ-private\"}} {}\n\
         hickory_zone_country_total{{zone=\"bd-alice2.example.\",country=\"ZZ-unknown\"}} {}\n\
         hickory_zone_country_total{{zone=\"bd-carol.example.\",country=\"ZZ-nodata\"}} {}\nhickory_zone_country_total{{zone=\"bd-carol.example.\",country=\"ZZ-private\"}} {}\n\
         hickory_geoip_build_epoch 1700000000\n",
            100 + 10 * k,
            5 * k,
            3 * k,
            2 * k,
            4 * k,
            k,
            2 * k,
            k,
            4 * k,
            6 * k,
            k
        )
    };
    let now = chrono::Utc::now().timestamp();
    tenants::ingest_persistent(db, &scrape(0), now - 100)
        .await
        .unwrap();
    tenants::ingest_persistent(db, &scrape(10), now - 50)
        .await
        .unwrap();
    tenants::ingest_persistent(db, &scrape(10), now - 40)
        .await
        .unwrap(); // duplicate delivery: no change

    let (st, a, raw) = call!(
        app,
        get,
        "/api/v1/analytics/tenant?range=1h",
        Some(&ta),
        None
    );
    assert_eq!(st, 200, "{raw}");
    let qt: Vec<(String, i64)> = a["breakdown"]["qtypes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["qtype"].as_str().unwrap().to_string(),
                x["queries"].as_i64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        qt,
        vec![("TXT".into(), 40), ("A".into(), 30), ("MX".into(), 20)],
        "alice sees only her zones, summed over zones, malicious label ignored: {raw}"
    );
    let co = a["breakdown"]["countries"].as_array().unwrap();
    let find = |kind: &str| {
        co.iter()
            .find(|c| c["kind"] == kind)
            .map(|c| c["queries"].as_i64().unwrap())
    };
    assert_eq!(
        co.iter().find(|c| c["code"] == "DE").unwrap()["queries"],
        20
    );
    assert_eq!(find("private"), Some(10));
    assert_eq!(find("unknown"), Some(40));
    assert_eq!(
        find("no_geoip"),
        None,
        "carol's sentinel must not leak into alice's view"
    );
    assert_eq!(a["breakdown"]["country_status"], "ok");
    assert_eq!(a["breakdown"]["geoip"]["available"], true);
    // zone filter inside the tenant
    let (_, z, _) = call!(
        app,
        get,
        "/api/v1/analytics/tenant?range=1h&zone=bd-alice2.example",
        Some(&ta),
        None
    );
    assert_eq!(z["breakdown"]["qtypes"].as_array().unwrap().len(), 1);
    assert_eq!(z["breakdown"]["qtypes"][0]["qtype"], "TXT");
    // carol: only CAA, and her country data is entirely "GeoIP unavailable" (+private) -> status says so instead of inventing a country
    let (_, c, _) = call!(
        app,
        get,
        "/api/v1/analytics/tenant?range=1h",
        Some(&tc),
        None
    );
    assert_eq!(c["breakdown"]["qtypes"].as_array().unwrap().len(), 1);
    assert_eq!(c["breakdown"]["qtypes"][0]["qtype"], "CAA");
    assert_eq!(c["breakdown"]["country_status"], "geoip_unavailable");
    assert!(
        c["breakdown"]["countries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|x| x["code"] == ""),
        "no country codes fabricated"
    );
    // asking for another tenant's data is refused; foreign zone filter yields nothing
    let (_, tl, _) = call!(app, get, "/api/v1/tenants", Some(&tadmin), None);
    let ctid = tl
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "personal-bd-carol")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (st, _, _) = call!(
        app,
        get,
        &format!("/api/v1/analytics/tenant?tenant_id={}", ctid),
        Some(&ta),
        None
    );
    assert_eq!(st, 404);
    let (_, x, _) = call!(
        app,
        get,
        "/api/v1/analytics/tenant?range=1h&zone=bd-carol.example",
        Some(&ta),
        None
    );
    assert!(
        x["breakdown"]["qtypes"].as_array().unwrap().is_empty(),
        "foreign zone filter leaks nothing: {x}"
    );
    // admin: global view is separate and covers everyone; customers cannot call it
    let (st, g, raw) = call!(
        app,
        get,
        "/api/v1/analytics/global?range=1h",
        Some(&tadmin),
        None
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(g["breakdown"]["qtypes"].as_array().unwrap().len(), 4);
    let (st, _, _) = call!(app, get, "/api/v1/analytics/global", Some(&ta), None);
    assert_eq!(st, 403);
    // intervals
    let (st, i, _) = call!(
        app,
        get,
        "/api/v1/analytics/tenant?range=7d&interval=1d",
        Some(&ta),
        None
    );
    assert_eq!(st, 200);
    assert_eq!(i["bucket_seconds"], 86400);
    let (st, _, _) = call!(
        app,
        get,
        "/api/v1/analytics/tenant?range=90d&interval=1m",
        Some(&ta),
        None
    );
    assert_eq!(st, 400, "would exceed 2,000 buckets");
    let (st, _, _) = call!(
        app,
        get,
        "/api/v1/analytics/tenant?interval=7s",
        Some(&ta),
        None
    );
    assert_eq!(st, 400);
    // retention covers the new tables
    db.execute(
        "UPDATE zone_qtype_samples SET ts = ts - interval '200 days'",
        &[],
    )
    .await
    .unwrap();
    db.execute(
        "UPDATE zone_country_samples SET ts = ts - interval '200 days'",
        &[],
    )
    .await
    .unwrap();
    assert!(tenants::purge_analytics(db, 90).await.unwrap() > 0);
    let n: i64 = db.query_one("SELECT (SELECT count(*) FROM zone_qtype_samples) + (SELECT count(*) FROM zone_country_samples)", &[]).await.unwrap().get(0);
    assert_eq!(n, 0);
    env.cleanup().await;
}

#[actix_web::test]
async fn rollup_preserves_sums_bounds_growth_and_is_idempotent() {
    let Some(env) = setup().await else { return };
    let db = &env.state.db;
    let alice = add_user(&env.state, "ru-alice", "alice-pass-1", "user").await;
    let ta = env.token(&alice, "user");
    let app = app!(env);
    let _ = make_zone(&env, &app, &ta, "ru.example").await;
    // 5-minute samples: 3 days old (to be rolled up) and 10 minutes old (must stay untouched)
    db.batch_execute("INSERT INTO zone_query_samples (ts, tenant_id, domain, queries, failed) \
        SELECT now() - interval '3 days' + make_interval(secs => s * 300), (SELECT tenant_id FROM zones WHERE domain='ru.example'), 'ru.example', 10, s % 2 FROM generate_series(0, 287) s; \
        INSERT INTO zone_qtype_samples (ts, tenant_id, domain, qtype, queries) SELECT now() - interval '3 days' + make_interval(secs => s * 300), (SELECT tenant_id FROM zones WHERE domain='ru.example'), 'ru.example', t, 2 FROM generate_series(0, 287) s, unnest(ARRAY['A','MX']) t; \
        INSERT INTO zone_country_samples (ts, tenant_id, domain, country, queries) SELECT now() - interval '3 days' + make_interval(secs => s * 300), (SELECT tenant_id FROM zones WHERE domain='ru.example'), 'ru.example', 'DE', 3 FROM generate_series(0, 287) s; \
        INSERT INTO analytics_samples (ts, requests) SELECT now() - interval '3 days' + make_interval(secs => s * 300), 7 FROM generate_series(0, 287) s; \
        INSERT INTO zone_query_samples (ts, tenant_id, domain, queries, failed) VALUES (now() - interval '10 minutes', (SELECT tenant_id FROM zones WHERE domain='ru.example'), 'ru.example', 5, 0)").await.unwrap();
    let snap = || async {
        let r = db.query_one("SELECT (SELECT sum(queries)::bigint FROM zone_query_samples), (SELECT sum(failed)::bigint FROM zone_query_samples), (SELECT sum(queries)::bigint FROM zone_qtype_samples), (SELECT sum(queries)::bigint FROM zone_country_samples), (SELECT sum(requests)::bigint FROM analytics_samples), (SELECT count(*) FROM zone_query_samples) + (SELECT count(*) FROM zone_qtype_samples) + (SELECT count(*) FROM zone_country_samples) + (SELECT count(*) FROM analytics_samples)", &[]).await.unwrap();
        (
            (
                r.get::<_, i64>(0),
                r.get::<_, i64>(1),
                r.get::<_, i64>(2),
                r.get::<_, i64>(3),
                r.get::<_, i64>(4),
            ),
            r.get::<_, i64>(5),
        )
    };
    let (sums_before, rows_before) = snap().await;
    assert!(tenants::rollup_analytics(db).await.unwrap() > 0);
    let (sums_after, rows_after) = snap().await;
    assert_eq!(sums_before, sums_after, "every sum is preserved exactly");
    assert!(
        rows_after < rows_before / 4,
        "row count shrinks: {rows_before} -> {rows_after}"
    );
    let recent: i64 = db
        .query_one(
            "SELECT count(*) FROM zone_query_samples WHERE ts > now() - interval '1 hour'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(recent, 1, "recent detail is kept");
    let non_hour: i64 = db.query_one("SELECT count(*) FROM zone_qtype_samples WHERE ts < now() - interval '49 hours' AND ts <> date_trunc('hour', ts)", &[]).await.unwrap().get(0);
    assert_eq!(non_hour, 0, "old rows are hour-aligned");
    assert_eq!(
        tenants::rollup_analytics(db).await.unwrap(),
        0,
        "idempotent: nothing left to merge"
    );
    assert_eq!(snap().await.0, sums_before);
    // the API serves the same totals from the rolled-up data
    let (_, a, _) = call!(
        app,
        get,
        "/api/v1/analytics/tenant?range=7d",
        Some(&ta),
        None
    );
    assert_eq!(a["total_queries"], 288 * 10 + 5);
    env.cleanup().await;
}

/// The checked-in SQL migrations and the runtime `migrate_db()` path must produce
/// the same schema. This closes ARCH-001: fresh Compose databases and fresh
/// Kubernetes/test databases can no longer diverge silently.
#[actix_web::test]
async fn migration_files_and_runtime_ddl_have_no_schema_drift() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("SKIPPED: TEST_DATABASE_URL not set");
        return;
    };

    let schemas = [
        format!("t_mig_{}", Uuid::new_v4().simple()),
        format!("t_run_{}", Uuid::new_v4().simple()),
    ];
    {
        let (c, conn) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        for schema in &schemas {
            c.batch_execute(&format!("CREATE SCHEMA {schema}"))
                .await
                .unwrap();
        }
    }

    let migrations_dir = format!("{}/migrations", env!("CARGO_MANIFEST_DIR"));
    let mut files = std::fs::read_dir(&migrations_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("sql"))
        .collect::<Vec<_>>();
    files.sort();
    for path in files {
        let sql = std::fs::read_to_string(&path).unwrap();
        let (c, conn) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        c.batch_execute(&format!("SET search_path TO {}", schemas[0]))
            .await
            .unwrap();
        c.batch_execute(&sql)
            .await
            .unwrap_or_else(|e| panic!("migration {}: {}", path.display(), full_error_string(&e)));
    }

    for schema in &schemas {
        let pool = Pool::connect(&url, 2, Some(schema)).await.unwrap();
        migrate_db(&pool)
            .await
            .unwrap_or_else(|e| panic!("migrate_db {schema}: {}", full_error_string(&e)));
    }

    let (admin, conn) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    async fn catalog(client: &tokio_postgres::Client, schema: &str) -> (Vec<String>, Vec<String>) {
        let cols = client
            .query(
                "SELECT table_name, column_name, data_type, is_nullable, coalesce(column_default, '')
                 FROM information_schema.columns
                 WHERE table_schema = $1
                 ORDER BY 1, 2",
                &[&schema],
            )
            .await
            .unwrap()
            .into_iter()
            .map(|r| {
                format!(
                    "{}|{}|{}|{}|{}",
                    r.get::<_, String>(0),
                    r.get::<_, String>(1),
                    r.get::<_, String>(2),
                    r.get::<_, String>(3),
                    r.get::<_, String>(4)
                )
            })
            .collect::<Vec<_>>();

        let idx = client
            .query(
                "SELECT tablename, indexname, indexdef FROM pg_indexes
                 WHERE schemaname = $1 ORDER BY 1, 2",
                &[&schema],
            )
            .await
            .unwrap()
            .into_iter()
            .map(|r| {
                format!(
                    "{}|{}|{}",
                    r.get::<_, String>(0),
                    r.get::<_, String>(1),
                    r.get::<_, String>(2).replace(schema, "SCHEMA")
                )
            })
            .collect::<Vec<_>>();
        (cols, idx)
    }

    let (mig_cols, mig_idx) = catalog(&admin, &schemas[0]).await;
    let (run_cols, run_idx) = catalog(&admin, &schemas[1]).await;
    assert_eq!(
        mig_cols, run_cols,
        "SQL migrations and runtime DDL columns differ"
    );
    assert_eq!(
        mig_idx, run_idx,
        "SQL migrations and runtime DDL indexes differ"
    );

    for schema in &schemas {
        let unique = admin
            .query_one(
                "SELECT count(*) FROM pg_indexes
                 WHERE schemaname = $1 AND indexname = 'uq_records_rrset_value'",
                &[&schema],
            )
            .await
            .unwrap()
            .get::<_, i64>(0);
        assert_eq!(unique, 1, "uq_records_rrset_value missing in {schema}");

        let legacy = admin
            .query_one(
                "SELECT count(*) FROM pg_constraint c
                 JOIN pg_namespace n ON n.oid = c.connamespace
                 WHERE n.nspname = $1 AND c.conname = 'records_zone_id_name_record_type_key'",
                &[&schema],
            )
            .await
            .unwrap()
            .get::<_, i64>(0);
        assert_eq!(
            legacy, 0,
            "legacy RRset constraint still present in {schema}"
        );
    }

    let pool = Pool::connect(&url, 2, Some(&schemas[1])).await.unwrap();
    let zone = Uuid::new_v4().to_string();
    pool.execute(
        "INSERT INTO zones (id, domain) VALUES ($1::text::uuid, 'rrset.example')",
        &[&zone],
    )
    .await
    .unwrap();
    let value = "192.0.2.10";
    pool.execute(
        "INSERT INTO records (id, zone_id, name, record_type, value)
         VALUES ($1::text::uuid, $2::text::uuid, 'WWW', 'A', $3)",
        &[&Uuid::new_v4().to_string(), &zone, &value],
    )
    .await
    .unwrap();
    let duplicate = pool
        .execute(
            "INSERT INTO records (id, zone_id, name, record_type, value)
             VALUES ($1::text::uuid, $2::text::uuid, 'www', 'A', $3)",
            &[&Uuid::new_v4().to_string(), &zone, &value],
        )
        .await
        .expect_err("exact duplicate must be rejected");
    assert!(
        full_error_string(&duplicate).contains("uq_records_rrset_value"),
        "duplicate RRset value must be rejected by the unique index"
    );

    pool.execute(
        "INSERT INTO records (id, zone_id, name, record_type, value)
         VALUES ($1::text::uuid, $2::text::uuid, 'www', 'A', '192.0.2.11')",
        &[&Uuid::new_v4().to_string(), &zone],
    )
    .await
    .expect("a second value in the same RRset must be accepted");

    for schema in &schemas {
        admin
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}

#[actix_web::test]
async fn record_update_publish_failure_restores_old_value() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let zid = make_zone(&env, &app, &t, "rec-rollback.example").await;

    let (st, rec, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/records"),
        Some(&t),
        j(serde_json::json!({"name":"www","record_type":"A","value":"192.0.2.10","ttl":300}))
    );
    assert_eq!(st, 201, "{raw}");
    let rid = rec["id"].as_str().unwrap().to_string();

    std::fs::remove_dir_all(env.dir.path()).unwrap();
    std::fs::write(env.dir.path(), b"not a directory").unwrap();
    let (st, body, raw) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zid}/records/{rid}"),
        Some(&t),
        j(serde_json::json!({"value":"192.0.2.99"}))
    );
    assert_eq!(st, 500, "{raw}");
    assert_eq!(body["error"], "publish_failed");
    assert_eq!(body["saved"], false);

    let value: String = env
        .state
        .db
        .query_one(
            "SELECT value FROM records WHERE CAST(id AS varchar) = $1",
            &[&rid],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        value, "192.0.2.10",
        "failed publication must restore the old value"
    );

    std::fs::remove_file(env.dir.path()).unwrap();
    std::fs::create_dir_all(env.dir.path()).unwrap();
    env.cleanup().await;
}

#[actix_web::test]
async fn record_delete_publish_failure_restores_record() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let zid = make_zone(&env, &app, &t, "rec-del-rollback.example").await;

    let (st, rec, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/records"),
        Some(&t),
        j(serde_json::json!({"name":"del","record_type":"A","value":"192.0.2.20","ttl":300}))
    );
    assert_eq!(st, 201, "{raw}");
    let rid = rec["id"].as_str().unwrap().to_string();

    std::fs::remove_dir_all(env.dir.path()).unwrap();
    std::fs::write(env.dir.path(), b"not a directory").unwrap();
    let (st, body, raw) = call!(
        app,
        delete,
        &format!("/api/v1/zones/{zid}/records/{rid}"),
        Some(&t),
        None
    );
    assert_eq!(st, 500, "{raw}");
    assert_eq!(body["error"], "publish_failed");
    assert_eq!(body["saved"], false);

    let count: i64 = env
        .state
        .db
        .query_one(
            "SELECT count(*) FROM records WHERE CAST(id AS varchar) = $1",
            &[&rid],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        count, 1,
        "failed publication must restore the deleted record"
    );

    std::fs::remove_file(env.dir.path()).unwrap();
    std::fs::create_dir_all(env.dir.path()).unwrap();
    env.cleanup().await;
}

#[actix_web::test]
async fn bulk_record_delete_is_atomic_scoped_and_preserves_last_known_good_on_publish_failure() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let token = env.token(&env.admin, "admin");
    let zone = make_zone(&env, &app, &token, "bulk-delete.example").await;
    let other_zone = make_zone(&env, &app, &token, "bulk-delete-other.example").await;
    let zone_records = format!("/api/v1/zones/{zone}/records");

    let create = |name: &str, value: &str| {
        j(serde_json::json!({"name":name,"record_type":"A","value":value,"ttl":300}))
    };
    let (status, first, raw) = call!(
        app,
        post,
        &zone_records,
        Some(&token),
        create("bulk-a", "192.0.2.10")
    );
    assert_eq!(status, 201, "{raw}");
    let first_id = first["id"].as_str().unwrap().to_string();
    let (status, second, raw) = call!(
        app,
        post,
        &zone_records,
        Some(&token),
        create("bulk-b", "192.0.2.11")
    );
    assert_eq!(status, 201, "{raw}");
    let second_id = second["id"].as_str().unwrap().to_string();

    let metadata_url = format!("/api/v1/zones/{zone}/records/{first_id}/metadata");
    let (status, _, raw) = call!(
        app,
        put,
        &metadata_url,
        Some(&token),
        j(serde_json::json!({"comment":"keep on rollback","tags":["bulk","rollback"]}))
    );
    assert_eq!(status, 200, "{raw}");

    let other_record_id: String = env
        .state
        .db
        .query_one(
            "SELECT CAST(id AS varchar) FROM records WHERE CAST(zone_id AS varchar) = $1 LIMIT 1",
            &[&other_zone],
        )
        .await
        .unwrap()
        .get(0);
    let bulk_url = format!("/api/v1/zones/{zone}/records/bulk-delete");
    let (status, _, _) = call!(
        app,
        post,
        &bulk_url,
        Some(&token),
        j(serde_json::json!({"record_ids":[first_id, other_record_id]}))
    );
    assert_eq!(
        status, 404,
        "a foreign-zone id must abort the complete selection"
    );

    let soa_id: String = env.state.db.query_one(
        "SELECT CAST(id AS varchar) FROM records WHERE CAST(zone_id AS varchar) = $1 AND upper(record_type) = 'SOA' LIMIT 1",
        &[&zone],
    ).await.unwrap().get(0);
    let (status, body, _) = call!(
        app,
        post,
        &bulk_url,
        Some(&token),
        j(serde_json::json!({"record_ids":[soa_id]}))
    );
    assert_eq!(status, 409);
    assert!(body["error"].as_str().unwrap().contains("SOA"));

    let apex_ns: Vec<String> = env.state.db.query(
        "SELECT CAST(id AS varchar) FROM records WHERE CAST(zone_id AS varchar) = $1 AND lower(name)='@' AND upper(record_type)='NS'",
        &[&zone],
    ).await.unwrap().into_iter().map(|row| row.get(0)).collect();
    let (status, body, _) = call!(
        app,
        post,
        &bulk_url,
        Some(&token),
        j(serde_json::json!({"record_ids":apex_ns}))
    );
    assert_eq!(status, 409);
    assert!(body["error"].as_str().unwrap().contains("final apex NS"));

    std::fs::remove_dir_all(env.dir.path()).unwrap();
    std::fs::write(env.dir.path(), b"not a directory").unwrap();
    let (status, body, raw) = call!(
        app,
        post,
        &bulk_url,
        Some(&token),
        j(serde_json::json!({"record_ids":[first_id, second_id]}))
    );
    assert_eq!(status, 500, "{raw}");
    assert_eq!(body["error"], "publish_failed", "{raw}");
    let restored = env.state.db.query(
        "SELECT comment, tags::text FROM records WHERE CAST(zone_id AS varchar) = $1 AND name='bulk-a'",
        &[&zone],
    ).await.unwrap();
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].get::<_, String>(0), "keep on rollback");
    assert!(restored[0].get::<_, String>(1).contains("rollback"));
    let remaining: i64 = env.state.db.query_one(
        "SELECT count(*) FROM records WHERE CAST(zone_id AS varchar) = $1 AND name IN ('bulk-a','bulk-b')",
        &[&zone],
    ).await.unwrap().get(0);
    assert_eq!(
        remaining, 2,
        "publication failure restores the whole selection"
    );
    std::fs::remove_file(env.dir.path()).unwrap();
    std::fs::create_dir_all(env.dir.path()).unwrap();
    env.cleanup().await;
}

#[actix_web::test]
async fn import_dry_run_writes_nothing() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let zid = make_zone(&env, &app, &t, "dryrun.example").await;
    let before = std::fs::read_to_string(env.zone_file("dryrun.example")).unwrap();

    let (st, body, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/import"),
        Some(&t),
        j(serde_json::json!({"dry_run":true,"records":[
            {"name":"one","record_type":"A","value":"192.0.2.1"},
            {"name":"two","record_type":"TXT","value":"hello"}
        ]}))
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(body["dry_run"], true);
    assert_eq!(body["would_import"], 2);

    let (_, list, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{zid}/records"),
        Some(&t),
        None
    );
    assert!(list.as_array().unwrap().iter().all(|r| {
        let name = r["name"].as_str().unwrap_or_default();
        name != "one" && name != "two"
    }));
    assert_eq!(
        std::fs::read_to_string(env.zone_file("dryrun.example")).unwrap(),
        before
    );
    env.cleanup().await;
}

#[actix_web::test]
async fn import_reports_all_row_errors() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let zid = make_zone(&env, &app, &t, "rowerrors.example").await;

    let (st, body, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/import"),
        Some(&t),
        j(serde_json::json!({"records":[
            {"name":"bad1","record_type":"A","value":"999.0.2.1"},
            {"name":"bad2","record_type":"A","value":"not-an-ip"}
        ]}))
    );
    assert_eq!(st, 400, "{raw}");
    let errors = body["errors"].as_array().expect("errors array");
    assert_eq!(errors.len(), 2, "{raw}");
    assert_eq!(errors[0]["row"], 0);
    assert_eq!(errors[1]["row"], 1);

    let (_, list, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{zid}/records"),
        Some(&t),
        None
    );
    assert!(
        list.as_array()
            .unwrap()
            .iter()
            .all(|r| r["name"] != "bad1" && r["name"] != "bad2")
    );
    env.cleanup().await;
}

#[actix_web::test]
async fn revision_diff_reports_added_and_removed_records() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let zid = make_zone(&env, &app, &t, "diff.example").await;
    let url = format!("/api/v1/zones/{zid}/records");
    let (_, record, raw) = call!(
        app,
        post,
        &url,
        Some(&t),
        j(serde_json::json!({"name":"old","record_type":"A","value":"192.0.2.1","ttl":60}))
    );
    assert!(!raw.contains("error"), "{raw}");
    let rid = record["id"].as_str().unwrap().to_string();
    let (_, revisions, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{zid}/revisions"),
        Some(&t),
        None
    );
    let rev = revisions[0]["id"].as_str().unwrap().to_string();

    call!(app, delete, &format!("{url}/{rid}"), Some(&t), None);
    call!(
        app,
        post,
        &url,
        Some(&t),
        j(serde_json::json!({"name":"new","record_type":"A","value":"192.0.2.2","ttl":60}))
    );
    let (st, body, raw) = call!(
        app,
        get,
        &format!("/api/v1/zones/{zid}/revisions/{rev}/diff"),
        Some(&t),
        None
    );
    assert_eq!(st, 200, "{raw}");
    assert!(
        body["added"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["name"] == "new")
    );
    assert!(
        body["removed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["name"] == "old")
    );
    env.cleanup().await;
}

#[actix_web::test]
async fn revision_retention_prunes_old_snapshots() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let zone_id = make_zone(&env, &app, &t, "retention.example").await;
    for (name, value) in [("first", "192.0.2.1"), ("second", "192.0.2.2")] {
        let (status, _, raw) = call!(
            app,
            post,
            &format!("/api/v1/zones/{zone_id}/records"),
            Some(&t),
            j(serde_json::json!({"name": name, "record_type": "A", "value": value, "ttl": 60}))
        );
        assert_eq!(status, 201, "{raw}");
    }
    env.state
        .db
        .execute(
            "UPDATE zones SET domain = 'retained.example' WHERE CAST(id AS varchar) = $1",
            &[&zone_id],
        )
        .await
        .unwrap();
    ext::snapshot_zone_with_retention(
        &env.state.db,
        &zone_id,
        Some(&env.admin),
        "retention test",
        2,
    )
    .await;
    let count: i64 = env
        .state
        .db
        .query_one(
            "SELECT count(*) FROM zone_revisions WHERE CAST(zone_id AS varchar) = $1",
            &[&zone_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 2);
    env.cleanup().await;
}

#[actix_web::test]
async fn revision_restore_restores_zone_publication_settings() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let token = env.token(&env.admin, "admin");
    let zone_id = make_zone(&env, &app, &token, "settings-history.example").await;
    let (_, revisions, raw) = call!(
        app,
        get,
        &format!("/api/v1/zones/{zone_id}/revisions"),
        Some(&token),
        None
    );
    assert!(!revisions.as_array().unwrap().is_empty(), "{raw}");
    let original = revisions[0]["id"].as_str().unwrap().to_owned();

    let (status, _, raw) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zone_id}"),
        Some(&token),
        j(serde_json::json!({
            "ecs_enabled": true,
            "geodns_enabled": false,
            "zone_type": "primary"
        }))
    );
    assert_eq!(status, 200, "{raw}");
    let (status, diff, raw) = call!(
        app,
        get,
        &format!("/api/v1/zones/{zone_id}/revisions/{original}/diff"),
        Some(&token),
        None
    );
    assert_eq!(status, 200, "{raw}");
    assert_eq!(diff["settings_changed"]["from"]["ecs_enabled"], false);
    assert_eq!(diff["settings_changed"]["to"]["ecs_enabled"], true);
    let (status, _, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zone_id}/revisions/{original}/restore"),
        Some(&token),
        None
    );
    assert_eq!(status, 200, "{raw}");

    let settings = env
        .state
        .db
        .query_one(
            "SELECT ecs_enabled, geodns_enabled FROM zones WHERE CAST(id AS varchar) = $1",
            &[&zone_id],
        )
        .await
        .unwrap();
    assert!(
        !settings.get::<_, bool>(0),
        "ECS must return to the snapshotted value"
    );
    assert!(
        settings.get::<_, bool>(1),
        "GeoDNS must return to the snapshotted value"
    );
    env.cleanup().await;
}

#[actix_web::test]
async fn zone_and_record_metadata_roundtrip() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let zid = make_zone(&env, &app, &t, "metadata.example").await;

    let (st, body, raw) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zid}/metadata"),
        Some(&t),
        j(
            serde_json::json!({"description":"primary customer zone","tags":["prod","customer","prod"]})
        )
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(
        body["tags"].as_array().unwrap().len(),
        2,
        "tags are deduplicated"
    );

    let (st, _, raw) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zid}/metadata"),
        Some(&t),
        j(serde_json::json!({"tags":["bad tag!"]}))
    );
    assert_eq!(st, 400, "{raw}");

    let (st, record, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/records"),
        Some(&t),
        j(serde_json::json!({"name":"www","record_type":"A","value":"192.0.2.1","ttl":300}))
    );
    assert_eq!(st, 201, "{raw}");
    let rid = record["id"].as_str().unwrap().to_string();
    let (st, _, raw) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zid}/records/{rid}/metadata"),
        Some(&t),
        j(serde_json::json!({"comment":"web front door","tags":["web"]}))
    );
    assert_eq!(st, 200, "{raw}");

    let description: String = env
        .state
        .db
        .query_one(
            "SELECT description FROM zones WHERE CAST(id AS varchar) = $1",
            &[&zid],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(description, "primary customer zone");
    let comment: String = env
        .state
        .db
        .query_one(
            "SELECT comment FROM records WHERE CAST(id AS varchar) = $1",
            &[&rid],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(comment, "web front door");
    let (st, listed, raw) = call!(
        app,
        get,
        &format!("/api/v1/zones/{zid}/records"),
        Some(&t),
        None
    );
    assert_eq!(st, 200, "{raw}");
    let listed = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == rid.as_str())
        .expect("record listed");
    assert_eq!(listed["comment"], "web front door");
    assert_eq!(listed["tags"][0], "web");

    let (st, body, raw) = call!(app, get, "/api/v1/zones?tag=customer", Some(&t), None);
    assert_eq!(st, 200, "{raw}");
    assert!(
        body["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|z| z["id"] == zid.as_str()),
        "tag filter includes the tagged zone: {raw}"
    );
    let (st, body, raw) = call!(app, get, "/api/v1/zones?tag=absent", Some(&t), None);
    assert_eq!(st, 200, "{raw}");
    assert!(
        body["data"]
            .as_array()
            .unwrap()
            .iter()
            .all(|z| z["id"] != zid.as_str()),
        "tag filter excludes untagged zones: {raw}"
    );
    env.cleanup().await;
}

#[actix_web::test]
async fn caa_record_roundtrips_through_api_database_and_zone_publication() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let token = env.token(&env.admin, "admin");
    let zone_id = make_zone(&env, &app, &token, "caa-roundtrip.example").await;

    let (status, created, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zone_id}/records"),
        Some(&token),
        j(serde_json::json!({
            "name":"@", "record_type":"CAA",
            "value":"0 issue \"letsencrypt.org\"", "ttl":300
        }))
    );
    assert_eq!(status, 201, "{raw}");
    assert_eq!(created["type"], "CAA");
    assert_eq!(created["value"], "0 issue \"letsencrypt.org\"");

    let (status, listed, raw) = call!(
        app,
        get,
        &format!("/api/v1/zones/{zone_id}/records"),
        Some(&token),
        None
    );
    assert_eq!(status, 200, "{raw}");
    assert!(listed.as_array().unwrap().iter().any(|record| {
        record["record_type"] == "CAA" && record["value"] == "0 issue \"letsencrypt.org\""
    }));

    let published = std::fs::read_to_string(env.zone_file("caa-roundtrip.example")).unwrap();
    assert!(
        published.contains("CAA 0 issue \"letsencrypt.org\""),
        "{published}"
    );

    // Unsupported standardized types must fail at the API boundary with an
    // actionable response, before a database row or zone publication exists.
    for record_type in ["DNAME", "LOC"] {
        let (status, body, raw) = call!(
            app,
            post,
            &format!("/api/v1/zones/{zone_id}/records"),
            Some(&token),
            j(serde_json::json!({
                "name":"unsupported", "record_type":record_type,
                "value":"unsupported.example.", "ttl":300
            }))
        );
        assert_eq!(status, 400, "{record_type}: {raw}");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("not supported by this Hickory build")
        );
    }
    env.cleanup().await;
}

#[actix_web::test]
async fn clone_zone_copies_records_with_rewritten_domain() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let zid = make_zone(&env, &app, &t, "source.example").await;
    call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/records"),
        Some(&t),
        j(serde_json::json!({"name":"www","record_type":"A","value":"192.0.2.1","ttl":300}))
    );
    let (st, _, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/records"),
        Some(&t),
        j(
            serde_json::json!({"name":"alias","record_type":"CNAME","value":"www.source.example.","ttl":300})
        )
    );
    assert_eq!(st, 201, "{raw}");
    let (st, _, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/records"),
        Some(&t),
        j(
            serde_json::json!({"name":"note","record_type":"TXT","value":"source.example","ttl":300})
        )
    );
    assert_eq!(st, 201, "{raw}");

    let (st, body, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/clone"),
        Some(&t),
        j(serde_json::json!({"domain":"copy.example"}))
    );
    assert_eq!(st, 201, "{raw}");
    assert_eq!(body["domain"], "copy.example");
    let new_id = body["id"].as_str().expect("clone response id").to_string();
    let (_, records, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{new_id}/records"),
        Some(&t),
        None
    );
    assert!(
        records
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["record_type"] == "SOA")
    );
    assert!(
        records
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["record_type"] == "NS")
    );
    assert!(
        records
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["name"] == "www")
    );
    assert!(
        records
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["name"] == "alias" && r["value"] == "www.copy.example.")
    );
    assert!(
        records
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["name"] == "note" && r["value"] == "source.example")
    );
    let dnssec_enabled: bool = env
        .state
        .db
        .query_one(
            "SELECT dnssec_enabled FROM zones WHERE CAST(id AS varchar)=$1",
            &[&new_id],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        !dnssec_enabled,
        "a clone must not enable DNSSEC without copying its signing keys"
    );
    let zone_file = std::fs::read_to_string(env.zone_file("copy.example")).unwrap();
    assert!(zone_file.contains("copy.example"));
    env.cleanup().await;
}

#[actix_web::test]
async fn zone_lifecycle_suspend_and_activate() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let zid = make_zone(&env, &app, &t, "lifecycle.example").await;
    assert!(env.zone_file("lifecycle.example").exists());

    let (st, body, raw) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zid}/lifecycle"),
        Some(&t),
        j(serde_json::json!({"status":"suspended"}))
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(body["status"], "suspended");
    assert!(!env.zone_file("lifecycle.example").exists());

    let (st, _, raw) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zid}/lifecycle"),
        Some(&t),
        j(serde_json::json!({"status":"active"}))
    );
    assert_eq!(st, 200, "{raw}");
    assert!(env.zone_file("lifecycle.example").exists());

    let (st, _, _) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zid}/lifecycle"),
        Some(&t),
        j(serde_json::json!({"status":"bogus"}))
    );
    assert_eq!(st, 400);
    env.cleanup().await;
}

#[actix_web::test]
async fn dnssec_rollover_carries_algorithm_and_protects_new_key() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let zid = make_zone(&env, &app, &t, "dnssec-hardening.example").await;

    let (st, body, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/dnssec/enable"),
        Some(&t),
        j(serde_json::json!({"algorithm":"ED25519"}))
    );
    assert_eq!(st, 201, "{raw}");
    assert_eq!(body["keys"][0]["algorithm"], "ED25519");

    let (st, body, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/dnssec/rollover"),
        Some(&t),
        j(serde_json::json!({}))
    );
    assert_eq!(st, 201, "{raw}");
    assert_eq!(
        body["keys"][1]["algorithm"], "ED25519",
        "rollover must carry the live algorithm"
    );
    let new_tag = body["keys"][1]["key_tag"].as_i64().unwrap() as i32;

    let (st, body, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/dnssec/rollover/complete"),
        Some(&t),
        j(serde_json::json!({"retire_key_tag": new_tag}))
    );
    assert_eq!(st, 409, "{raw}");
    assert_eq!(body["error"], "cannot_retire_new_key");
    env.cleanup().await;
}

#[actix_web::test]
async fn zone_transfer_policy_endpoint_and_validation() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let zid = make_zone(&env, &app, &t, "transfer-policy.example").await;

    let (st, body, raw) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zid}/transfer-policy"),
        Some(&t),
        j(serde_json::json!({"policy":"AllowAll", "allowed_peers":["127.0.0.1"]}))
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(body["policy"], "AllowAll");
    let named = std::fs::read_to_string(env.dir.path().join("named.toml")).unwrap();
    assert!(named.contains("zone = \"transfer-policy.example\"\nzone_type = \"Primary\"\naxfr_policy = \"AllowAll\""), "policy must reach the running-server config: {named}");
    assert!(
        named.contains("allowed_transfer_peers = [\"127.0.0.1\"]"),
        "peer ACL must reach the file-store config: {named}"
    );
    assert_eq!(body["allowed_peers"][0], "127.0.0.1");
    let stored: String = env
        .state
        .db
        .query_one(
            "SELECT axfr_policy FROM zones WHERE CAST(id AS varchar) = $1",
            &[&zid],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(stored, "AllowAll");

    let (st, body, raw) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zid}/transfer-policy"),
        Some(&t),
        j(serde_json::json!({"policy":"Deny", "allowed_peers":[]}))
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(body["policy"], "Deny");
    let named = std::fs::read_to_string(env.dir.path().join("named.toml")).unwrap();
    assert!(
        named.contains(
            "zone = \"transfer-policy.example\"\nzone_type = \"Primary\"\naxfr_policy = \"Deny\""
        ),
        "deny policy must be republished: {named}"
    );

    let (st, _, _) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zid}/transfer-policy"),
        Some(&t),
        j(serde_json::json!({"policy":"Deny", "allowed_peers":["not-an-ip"]}))
    );
    assert_eq!(st, 400);

    // A publication read failure must restore the persisted policy and leave
    // the already published Deny configuration untouched.
    env.state
        .db
        .batch_execute("ALTER TABLE georules RENAME TO georules_transfer_test")
        .await
        .unwrap();
    let (st, body, _) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zid}/transfer-policy"),
        Some(&t),
        j(serde_json::json!({"policy":"AllowAll"}))
    );
    assert_eq!(st, 500, "{body}");
    let restored: String = env
        .state
        .db
        .query_one(
            "SELECT axfr_policy FROM zones WHERE CAST(id AS varchar) = $1",
            &[&zid],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(restored, "Deny");
    let restored_peers: Vec<String> = env
        .state
        .db
        .query_one(
            "SELECT axfr_allowed_peers FROM zones WHERE CAST(id AS varchar) = $1",
            &[&zid],
        )
        .await
        .unwrap()
        .get(0);
    assert!(restored_peers.is_empty());
    let preserved = std::fs::read_to_string(env.dir.path().join("named.toml")).unwrap();
    assert!(
        preserved.contains("axfr_policy = \"Deny\""),
        "failed publication must preserve last known config: {preserved}"
    );
    env.state
        .db
        .batch_execute("ALTER TABLE georules_transfer_test RENAME TO georules")
        .await
        .unwrap();

    let (st, _, _) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zid}/transfer-policy"),
        Some(&t),
        j(serde_json::json!({"policy":"AllowSigned"}))
    );
    assert_eq!(st, 400);
    env.cleanup().await;
}

#[actix_web::test]
async fn georule_list_supports_search_and_pagination() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let zid = make_zone(&env, &app, &t, "geopage.example").await;
    for value in ["US", "CA", "GB"] {
        let (st, _, raw) = call!(
            app,
            post,
            "/api/v1/georules",
            Some(&t),
            j(
                serde_json::json!({"zone_id": zid, "match_type":"country","match_value":value,"target":"192.0.2.10"})
            )
        );
        assert_eq!(st, 201, "{raw}");
    }
    let (st, _, raw) = call!(
        app,
        get,
        "/api/v1/georules?limit=2&offset=0&q=US",
        Some(&t),
        None
    );
    assert_eq!(st, 200, "{raw}");
    env.cleanup().await;
}

#[actix_web::test]
async fn create_zone_idempotency_key_replays_first_response() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");

    let first = test::TestRequest::post()
        .uri("/api/v1/zones")
        .insert_header(("Authorization", format!("Bearer {t}")))
        .insert_header(("Idempotency-Key", "create-first"))
        .set_json(serde_json::json!({"domain":"idem-first.example"}))
        .to_request();
    let response = test::call_service(&app, first).await;
    assert_eq!(response.status(), 201);
    let first_body: serde_json::Value = test::read_body_json(response).await;
    let first_id = first_body["id"].as_str().unwrap().to_string();

    let second = test::TestRequest::post()
        .uri("/api/v1/zones")
        .insert_header(("Authorization", format!("Bearer {t}")))
        .insert_header(("Idempotency-Key", "create-first"))
        .set_json(serde_json::json!({"domain":"idem-second.example"}))
        .to_request();
    let response = test::call_service(&app, second).await;
    assert_eq!(response.status(), 201);
    let second_body: serde_json::Value = test::read_body_json(response).await;
    assert_eq!(second_body["id"], first_id);
    assert_eq!(second_body["domain"], "idem-first.example");

    let (_, _, raw) = call!(
        app,
        get,
        "/api/v1/zones?q=idem-second.example",
        Some(&t),
        None
    );
    assert!(!raw.contains("idem-second.example"));
    env.cleanup().await;
}

#[actix_web::test]
async fn audit_detail_and_export_endpoints() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let t = env.token(&env.admin, "admin");
    let zid = make_zone(&env, &app, &t, "audit-api.example").await;
    assert!(!zid.is_empty());

    let (_, list, _) = call!(app, get, "/api/v1/audit/logs", Some(&t), None);
    let id = list["data"][0]["id"].as_str().unwrap().to_string();
    let (st, filtered, raw) = call!(
        app,
        get,
        "/api/v1/audit/logs?q=audit-api.example",
        Some(&t),
        None
    );
    assert_eq!(st, 200, "{raw}");
    assert!(!filtered["data"].as_array().unwrap().is_empty());
    let (st, empty, raw) = call!(
        app,
        get,
        "/api/v1/audit/logs?q=no-such-audit-search-value",
        Some(&t),
        None
    );
    assert_eq!(st, 200, "{raw}");
    assert!(empty["data"].as_array().unwrap().is_empty());
    for uri in [
        "/api/v1/audit/logs?since=bad",
        "/api/v1/audit/logs/export?since=bad",
    ] {
        let (st, _, raw) = call!(app, get, uri, Some(&t), None);
        assert_eq!(st, 400, "{uri}: {raw}");
    }
    let viewer = add_user(&env.state, "audit-viewer", "viewer-pass-1", "user").await;
    let viewer_token = env.token(&viewer, "user");
    let (st, _, _) = call!(
        app,
        get,
        "/api/v1/audit/logs/export",
        Some(&viewer_token),
        None
    );
    assert_eq!(st, 403);

    let (st, detail, raw) = call!(
        app,
        get,
        &format!("/api/v1/audit/logs/{id}"),
        Some(&t),
        None
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(detail["data"]["id"], id);

    let (st, _, raw) = call!(
        app,
        get,
        "/api/v1/audit/logs/export?limit=10",
        Some(&t),
        None
    );
    assert_eq!(st, 200, "{raw}");
    assert!(raw.contains("id,user_id,action"));
    let (st, _, raw) = call!(
        app,
        get,
        "/api/v1/audit/logs/export?q=no-such-audit-search-value",
        Some(&t),
        None
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(raw.lines().count(), 1, "only CSV header should remain");
    env.cleanup().await;
}

#[actix_web::test]
async fn openapi_spec_is_published() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let (st, body, raw) = call!(app, get, "/openapi.json", None::<&str>, None);
    assert_eq!(st, 200, "{raw}");
    assert!(
        body["openapi"]
            .as_str()
            .unwrap_or_default()
            .starts_with("3.")
    );
    assert!(body["components"]["schemas"].is_object());
    assert_eq!(
        body["components"]["schemas"]["ErrorResponse"]["required"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert!(!body["paths"].as_object().unwrap().contains_key("/test"));
    let zone_request = &body["paths"]["/api/v1/zones"]["post"]["requestBody"]["content"]["application/json"]
        ["schema"];
    assert_eq!(zone_request["$ref"], "#/components/schemas/CreateZoneReq");
    assert!(body["components"]["schemas"]["CreateZoneReq"]["properties"]["domain"].is_object());
    assert!(
        body["components"]["schemas"]["CreateZoneReq"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field == "domain")
    );
    assert!(body["paths"]["/api/v1/auth/mfa/setup"]["post"]["security"].is_array());
    assert!(
        body["paths"]["/api/v1/auth/login"]["post"]
            .get("security")
            .is_none()
    );
    assert_eq!(
        body["paths"]["/api/v1/auth/mfa/enable"]["post"]["requestBody"]["content"]["application/json"]
            ["schema"]["$ref"],
        "#/components/schemas/CodeReq"
    );
    let published_operations: usize = body["paths"]
        .as_object()
        .unwrap()
        .values()
        .map(|methods| methods.as_object().map_or(0, serde_json::Map::len))
        .sum();
    assert!(published_operations >= 110);
    assert!(body["paths"]["/api/v1/zones/{id}/dnssec/multi-signer"]["post"].is_object());
    assert_eq!(
        body["components"]["securitySchemes"]["BearerAuth"]["scheme"],
        "bearer"
    );
    env.cleanup().await;
}

#[actix_web::test]
async fn api_errors_have_stable_codes_without_breaking_legacy_error_fields() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let (status, unauthorized_body, _) = call!(app, get, "/api/v1/users", None::<&str>, None);
    assert_eq!(status, 401);
    assert_eq!(unauthorized_body["code"], "unauthorized");
    assert_eq!(unauthorized_body["error"], "unauthorized");
    assert_eq!(
        unauthorized_body["details"],
        "Authentication token required"
    );

    let user = add_user(
        &env.state,
        "error-envelope-user",
        "error-envelope-pass",
        "user",
    )
    .await;
    let user_token = env.token(&user, "user");
    let (status, forbidden_body, _) = call!(app, get, "/api/v1/users", Some(&user_token), None);
    assert_eq!(status, 403);
    assert_eq!(forbidden_body["code"], "forbidden");
    assert_eq!(forbidden_body["error"], "forbidden");
    assert_eq!(
        forbidden_body["details"],
        "Admin role required to list users"
    );
    env.cleanup().await;
}

#[actix_web::test]
async fn per_user_password_reset_revokes_sessions() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let uid = add_user(&env.state, "resetpath", "old-password-1", "user").await;
    let (st, body, raw) = call!(
        app,
        post,
        "/api/v1/auth/login",
        None::<&str>,
        j(serde_json::json!({"username":"resetpath","password":"old-password-1"}))
    );
    assert_eq!(st, 200, "{raw}");
    let old_access = body["token"].as_str().unwrap().to_string();

    let admin = env.token(&env.admin, "admin");
    let (st, _, raw) = call!(
        app,
        post,
        &format!("/api/v1/users/{uid}/password"),
        Some(&admin),
        j(serde_json::json!({"new_password":"new-password-1"}))
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(
        call!(app, get, "/api/v1/auth/me", Some(&old_access), None).0,
        401
    );
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/auth/login",
        None::<&str>,
        j(serde_json::json!({"username":"resetpath","password":"new-password-1"}))
    );
    assert_eq!(st, 200);
    env.cleanup().await;
}

#[actix_web::test]
async fn api_tokens_are_scoped_revocable_and_can_rotate() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let admin = env.token(&env.admin, "admin");

    let (st, body, raw) = call!(
        app,
        post,
        "/api/v1/tokens",
        Some(&admin),
        j(serde_json::json!({"name":"read only","scopes":["zones:read"],"expires_in_days":30}))
    );
    assert_eq!(st, 201, "{raw}");
    let token = body["token"].as_str().unwrap().to_string();
    assert!(token.starts_with("ocd_"));
    assert!(!raw.contains("token_hash"));
    let (st, _, raw) = call!(
        app,
        post,
        "/api/v1/tokens",
        Some(&admin),
        j(serde_json::json!({"name":"z token","scopes":["zones:read"]}))
    );
    assert_eq!(st, 201, "{raw}");
    let token_page = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/api/v1/tokens?limit=1&sort=name&order=asc")
            .insert_header(("Authorization", format!("Bearer {admin}")))
            .to_request(),
    )
    .await;
    assert_eq!(token_page.status(), 200);
    assert_eq!(token_page.headers().get("X-Total-Count").unwrap(), "2");
    let token_page_body: serde_json::Value = test::read_body_json(token_page).await;
    assert_eq!(token_page_body["tokens"].as_array().unwrap().len(), 1);
    assert_eq!(token_page_body["tokens"][0]["name"], "read only");

    for expires_in_days in [0, 366] {
        let (status, _, raw) = call!(
            app,
            post,
            "/api/v1/tokens",
            Some(&admin),
            j(serde_json::json!({"name":"invalid expiry","expires_in_days":expires_in_days}))
        );
        assert_eq!(status, 400, "{raw}");
    }
    let (status, _, raw) = call!(
        app,
        post,
        "/api/v1/tokens",
        Some(&admin),
        j(serde_json::json!({"name":"invalid scope","scopes":["zones:root"]}))
    );
    assert_eq!(status, 400, "{raw}");

    let user_id = add_user(&env.state, "token-user", "token-user-password-1", "user").await;
    let user_jwt = env.token(&user_id, "user");
    let (status, _, raw) = call!(
        app,
        post,
        "/api/v1/tokens",
        Some(&user_jwt),
        j(serde_json::json!({"name":"forbidden admin scope","scopes":["admin"]}))
    );
    assert_eq!(status, 403, "{raw}");

    let (st, _, _) = call!(app, get, "/api/v1/zones", Some(&token), None);
    assert_eq!(st, 200, "read scope must allow GET");
    let last_used: bool = env
        .state
        .db
        .query_one(
            "SELECT last_used_at IS NOT NULL FROM api_tokens WHERE token_hash=$1",
            &[&hash_token(&token)],
        )
        .await
        .unwrap()
        .get(0);
    assert!(last_used, "successful API-token use updates last_used_at");
    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/zones",
        Some(&token),
        j(serde_json::json!({"domain":"token-denied.test"}))
    );
    assert_eq!(st, 403, "read scope must not allow writes");

    let id = body["id"].as_str().unwrap().to_string();
    let (st, rotated, raw) = call!(
        app,
        post,
        &format!("/api/v1/tokens/{id}/rotate"),
        Some(&admin),
        None
    );
    assert_eq!(st, 201, "{raw}");
    let new_token = rotated["token"].as_str().unwrap().to_string();
    assert_ne!(new_token, token);
    let (st, _, _) = call!(app, get, "/api/v1/zones", Some(&token), None);
    assert_eq!(st, 401, "rotated token must stop working");
    let (st, _, _) = call!(app, get, "/api/v1/zones", Some(&new_token), None);
    assert_eq!(st, 200);
    env.state
        .db
        .execute(
            "UPDATE api_tokens SET expires_at=now()-interval '1 second' WHERE token_hash=$1",
            &[&hash_token(&new_token)],
        )
        .await
        .unwrap();
    let (st, _, _) = call!(app, get, "/api/v1/zones", Some(&new_token), None);
    assert_eq!(st, 401, "expired personal tokens are rejected");

    let (st, _, _) = call!(
        app,
        delete,
        &format!("/api/v1/tokens/{}", rotated["id"].as_str().unwrap()),
        Some(&admin),
        None
    );
    assert_eq!(st, 200);
    let (st, _, _) = call!(app, get, "/api/v1/zones", Some(&new_token), None);
    assert_eq!(st, 401);
    env.cleanup().await;
}

#[actix_web::test]
async fn automation_list_filters_sort_and_count_empty_pages() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let admin = env.token(&env.admin, "admin");
    for (kind, url, n) in [
        ("zeta", "https://zeta.example/hook", 1i32),
        ("alpha", "https://alpha.example/hook", 2i32),
    ] {
        env.state.db.execute(
            "INSERT INTO jobs (id,user_id,kind,status,progress,total) VALUES ($1::text::uuid,$2::text::uuid,$3,'queued',0,0)",
            &[&Uuid::new_v4().to_string(), &env.admin, &kind],
        ).await.unwrap();
        env.state.db.execute(
            "INSERT INTO webhooks (id,user_id,url,secret,events) VALUES ($1::text::uuid,$2::text::uuid,$3,'test-secret','[\"zone.updated\"]'::jsonb)",
            &[&Uuid::new_v4().to_string(), &env.admin, &url],
        ).await.unwrap();
        env.state
            .db
            .execute(
                "UPDATE jobs SET created_at=now()-($2::int * interval '1 second') WHERE kind=$1",
                &[&kind, &n],
            )
            .await
            .unwrap();
    }

    let jobs = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/api/v1/jobs?limit=1&sort=kind&order=asc")
            .insert_header(("Authorization", format!("Bearer {admin}")))
            .to_request(),
    )
    .await;
    assert_eq!(jobs.status(), 200);
    assert_eq!(jobs.headers().get("X-Total-Count").unwrap(), "2");
    let jobs_body: serde_json::Value = test::read_body_json(jobs).await;
    assert_eq!(jobs_body["jobs"].as_array().unwrap().len(), 1);
    assert_eq!(jobs_body["jobs"][0]["kind"], "alpha");

    let hooks = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/api/v1/webhooks?limit=1&q=alpha&sort=url&order=asc")
            .insert_header(("Authorization", format!("Bearer {admin}")))
            .to_request(),
    )
    .await;
    assert_eq!(hooks.status(), 200);
    assert_eq!(hooks.headers().get("X-Total-Count").unwrap(), "1");
    let hooks_body: serde_json::Value = test::read_body_json(hooks).await;
    assert_eq!(hooks_body["webhooks"].as_array().unwrap().len(), 1);
    assert_eq!(
        hooks_body["webhooks"][0]["url"],
        "https://alpha.example/hook"
    );

    let empty_jobs = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/api/v1/jobs?offset=100")
            .insert_header(("Authorization", format!("Bearer {admin}")))
            .to_request(),
    )
    .await;
    assert_eq!(empty_jobs.headers().get("X-Total-Count").unwrap(), "2");
    let empty_body: serde_json::Value = test::read_body_json(empty_jobs).await;
    assert_eq!(empty_body["jobs"].as_array().unwrap().len(), 0);
    env.cleanup().await;
}

#[actix_web::test]
async fn bulk_import_runs_as_a_durable_job() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let admin = env.token(&env.admin, "admin");

    let payload = serde_json::json!({
        "dry_run": true,
        "zones": [{
            "domain": "bulk.test",
            "records": [
                {"name":"www","record_type":"A","value":"192.0.2.20","ttl":300},
                {"name":"@","record_type":"TXT","value":"hello","ttl":300}
            ]
        }]
    });
    let (st, body, raw) = call!(
        app,
        post,
        "/api/v1/zones/bulk-import",
        Some(&admin),
        j(payload.clone())
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(body["valid"], true);

    let mut payload = payload;
    payload["dry_run"] = serde_json::json!(false);
    let (st, body, raw) = call!(
        app,
        post,
        "/api/v1/zones/bulk-import",
        Some(&admin),
        j(payload)
    );
    assert_eq!(st, 202, "{raw}");
    let job_id = body["job_id"].as_str().unwrap().to_string();
    let row = env
        .state
        .db
        .query_one(
            "SELECT input FROM jobs WHERE CAST(id AS varchar) = $1",
            &[&job_id],
        )
        .await
        .unwrap();
    let input: serde_json::Value = row.get(0);
    let result = zone_ops::run_bulk_import_job(&env.state, &job_id, &env.admin, Some(input))
        .await
        .expect("job executes");
    assert_eq!(result["zones_succeeded"], 1, "{result}");
    automation::job_finish(&env.state.db, &job_id, "completed", Some(&result), None).await;

    let (st, job, raw) = call!(
        app,
        get,
        &format!("/api/v1/jobs/{job_id}"),
        Some(&admin),
        None
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(job["status"], "completed");
    assert_eq!(job["progress"], 1);
    assert_eq!(job["result"]["zones_succeeded"], 1);
    let zone_id = result["results"][0]["zone_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (st, _, _) = call!(
        app,
        get,
        &format!("/api/v1/zones/{zone_id}"),
        Some(&admin),
        None
    );
    assert_eq!(st, 200);
    assert!(env.zone_file("bulk.test").is_file());
    env.cleanup().await;
}

#[actix_web::test]
async fn bind_import_and_rrset_batch_are_atomic() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let admin = env.token(&env.admin, "admin");
    let zid = make_zone(&env, &app, &admin, "bind.test").await;

    let zone_text = "$TTL 300\nwww 300 IN A 192.0.2.10\nmail 300 IN MX 10 mail.bind.test.\n";
    let (st, body, raw) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/import-bind"),
        Some(&admin),
        j(serde_json::json!({"zone_text": zone_text}))
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(body["imported"], 2);
    assert!(env.zone_file("bind.test").is_file());

    let (st, _, _) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/import-bind"),
        Some(&admin),
        j(serde_json::json!({"zone_text":"evil.other.test. 300 IN A 192.0.2.1\n"}))
    );
    assert_eq!(st, 400, "records outside the zone are rejected");

    let (st, body, raw) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zid}/rrsets"),
        Some(&admin),
        j(serde_json::json!({
            "rrsets": [{
                "name":"www","record_type":"A","ttl":120,
                "values":[{"value":"192.0.2.11"},{"value":"192.0.2.12"}]
            }]
        }))
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(body["records_added"], 2);
    assert_eq!(body["records_removed"], 1);
    let text = std::fs::read_to_string(env.zone_file("bind.test")).unwrap();
    assert!(text.contains("192.0.2.11") && text.contains("192.0.2.12"));
    assert!(!text.contains("192.0.2.10"), "{text}");

    let (st, body, _) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zid}/rrsets"),
        Some(&admin),
        j(serde_json::json!({
            "rrsets": [{"name":"www","record_type":"A","values":[{"value":"not-an-ip"}]}]
        }))
    );
    assert_eq!(st, 400);
    assert!(body["errors"].as_array().is_some());
    env.cleanup().await;
}

#[actix_web::test]
async fn hold_archive_and_restore_control_serving_and_writes() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let admin = env.token(&env.admin, "admin");
    let zid = make_zone(&env, &app, &admin, "lifecycle.test").await;

    let (st, body, raw) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zid}/lifecycle"),
        Some(&admin),
        j(serde_json::json!({"status":"held","hold_reason":"billing review"}))
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(body["status"], "held");
    assert_eq!(body["hold_reason"], "billing review");
    assert!(
        env.zone_file("lifecycle.test").is_file(),
        "held zones stay served"
    );

    let (st, _, _) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/records"),
        Some(&admin),
        j(serde_json::json!({"name":"www","record_type":"A","value":"192.0.2.30","ttl":300}))
    );
    assert_eq!(st, 201);

    let (st, _, raw) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zid}/lifecycle"),
        Some(&admin),
        j(serde_json::json!({"status":"archived"}))
    );
    assert_eq!(st, 200, "{raw}");
    assert!(
        !env.zone_file("lifecycle.test").exists(),
        "archived zones must not be served"
    );
    let (st, _, _) = call!(
        app,
        post,
        &format!("/api/v1/zones/{zid}/records"),
        Some(&admin),
        j(serde_json::json!({"name":"api","record_type":"A","value":"192.0.2.31","ttl":300}))
    );
    assert_eq!(st, 409, "archived zones are read-only");

    let (st, _, raw) = call!(
        app,
        put,
        &format!("/api/v1/zones/{zid}/lifecycle"),
        Some(&admin),
        j(serde_json::json!({"status":"active"}))
    );
    assert_eq!(st, 200, "{raw}");
    assert!(env.zone_file("lifecycle.test").is_file());
    env.cleanup().await;
}

#[actix_web::test]
async fn health_checks_reject_private_targets_and_record_state() {
    let Some(env) = setup().await else { return };
    let app = app!(env);
    let admin = env.token(&env.admin, "admin");
    let zid = make_zone(&env, &app, &admin, "health.test").await;

    let (st, _, _) = call!(
        app,
        post,
        "/api/v1/health-checks",
        Some(&admin),
        j(serde_json::json!({
            "zone_id": zid, "name":"private", "record_name":"www",
            "record_type":"A", "target":"10.0.0.1"
        }))
    );
    assert_eq!(st, 400, "private targets are SSRF-blocked");

    let (st, body, raw) = call!(
        app,
        post,
        "/api/v1/health-checks",
        Some(&admin),
        j(serde_json::json!({
            "zone_id": zid, "name":"www probe", "record_name":"www",
            "record_type":"A", "target":"192.0.2.1", "timeout_ms":100,
            "failure_threshold":1, "success_threshold":1, "interval_secs":5
        }))
    );
    assert_eq!(st, 201, "{raw}");
    let id = body["id"].as_str().unwrap().to_string();

    let (st, run, raw) = call!(
        app,
        post,
        &format!("/api/v1/health-checks/{id}/run"),
        Some(&admin),
        None
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(run["ok"], false);
    assert_eq!(run["status"], "down");

    let (st, detail, raw) = call!(
        app,
        get,
        &format!("/api/v1/health-checks/{id}"),
        Some(&admin),
        None
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(detail["status"], "down");
    assert_eq!(detail["history"].as_array().unwrap().len(), 1);

    let (st, list, raw) = call!(
        app,
        get,
        &format!("/api/v1/health-checks?zone_id={zid}"),
        Some(&admin),
        None
    );
    assert_eq!(st, 200, "{raw}");
    assert_eq!(list["checks"].as_array().unwrap().len(), 1);

    let (st, _, _) = call!(
        app,
        delete,
        &format!("/api/v1/health-checks/{id}"),
        Some(&admin),
        None
    );
    assert_eq!(st, 200);
    env.cleanup().await;
}

#[actix_web::test]
async fn security_headers_are_present_and_auth_responses_are_not_cached() {
    let Some(env) = setup().await else { return };
    let app = app!(env);

    let resp = test::call_service(&app, test::TestRequest::get().uri("/health").to_request()).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert_eq!(resp.headers().get("x-frame-options").unwrap(), "DENY");
    assert_eq!(
        resp.headers().get("referrer-policy").unwrap(),
        "no-referrer"
    );
    assert!(
        resp.headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/api/v1/auth/login")
            .set_json(serde_json::json!({"username":"root","password":"wrong-password"}))
            .to_request(),
    )
    .await;
    assert_eq!(
        resp.headers().get("cache-control").unwrap(),
        "no-store",
        "auth responses must not be cached"
    );
    env.cleanup().await;
}
