use std::str::FromStr;

use test_support::subscribe;

use hickory_net::runtime::TokioRuntimeProvider;
use hickory_proto::rr::{Name, RData, Record, RecordType, rdata::CNAME};
#[cfg(feature = "__dnssec")]
use hickory_server::dnssec::NxProofKind;
use hickory_server::{
    store::in_memory::InMemoryZoneHandler,
    zone_handler::{AxfrPolicy, LookupOptions, ZoneHandler, ZoneType},
};

#[tokio::test]
async fn test_cname_loop() {
    subscribe();
    let mut auth = InMemoryZoneHandler::<TokioRuntimeProvider>::empty(
        Name::from_str("example.com.").unwrap(),
        ZoneType::Primary,
        AxfrPolicy::Deny,
        #[cfg(feature = "__dnssec")]
        Some(NxProofKind::Nsec),
    );

    auth.upsert_mut(
        Record::from_rdata(
            Name::from_str("foo.example.com.").unwrap(),
            300,
            RData::CNAME(CNAME(Name::from_str("foo.example.com.").unwrap())),
        ),
        0,
    );

    auth.upsert_mut(
        Record::from_rdata(
            Name::from_str("bar.example.com.").unwrap(),
            300,
            RData::CNAME(CNAME(Name::from_str("foo.example.com.").unwrap())),
        ),
        0,
    );

    auth.upsert_mut(
        Record::from_rdata(
            Name::from_str("baz.example.com.").unwrap(),
            300,
            RData::CNAME(CNAME(Name::from_str("boz.example.com.").unwrap())),
        ),
        0,
    );

    auth.upsert_mut(
        Record::from_rdata(
            Name::from_str("boz.example.com.").unwrap(),
            300,
            RData::CNAME(CNAME(Name::from_str("biz.example.com.").unwrap())),
        ),
        0,
    );

    auth.upsert_mut(
        Record::from_rdata(
            Name::from_str("biz.example.com.").unwrap(),
            300,
            RData::CNAME(CNAME(Name::from_str("baz.example.com.").unwrap())),
        ),
        0,
    );

    let lookup = auth
        .lookup(
            &Name::from_str("foo.example.com.").unwrap().into(),
            RecordType::A,
            None,
            LookupOptions::default(),
        )
        .await
        .unwrap();

    let records = lookup.iter().collect::<Vec<_>>();
    assert_eq!(records.len(), 1);
    let record = records[0];
    assert_eq!(record.name(), &Name::from_str("foo.example.com.").unwrap());
    assert_eq!(
        record.data(),
        &RData::CNAME(CNAME(Name::from_str("foo.example.com.").unwrap()))
    );

    assert!(
        lookup.additionals().is_none(),
        "Should be no additional records."
    );

    let lookup = auth
        .lookup(
            &Name::from_str("bar.example.com.").unwrap().into(),
            RecordType::A,
            None,
            LookupOptions::default(),
        )
        .await
        .unwrap();

    let records = lookup.iter().collect::<Vec<_>>();
    assert_eq!(records.len(), 1);
    let record = records[0];
    assert_eq!(record.name(), &Name::from_str("bar.example.com.").unwrap());
    assert_eq!(
        record.data(),
        &RData::CNAME(CNAME(Name::from_str("foo.example.com.").unwrap()))
    );

    let additionals = lookup
        .additionals()
        .expect("Should be additional records")
        .collect::<Vec<_>>();
    assert_eq!(additionals.len(), 1);
    let record = additionals[0];
    assert_eq!(record.name(), &Name::from_str("foo.example.com.").unwrap());
    assert_eq!(
        record.data(),
        &RData::CNAME(CNAME(Name::from_str("foo.example.com.").unwrap()))
    );

    let lookup = auth
        .lookup(
            &Name::from_str("baz.example.com.").unwrap().into(),
            RecordType::A,
            None,
            LookupOptions::default(),
        )
        .await
        .unwrap();

    let records = lookup.iter().collect::<Vec<_>>();
    assert_eq!(records.len(), 1);
    let record = records[0];
    assert_eq!(record.name(), &Name::from_str("baz.example.com.").unwrap());
    assert_eq!(
        record.data(),
        &RData::CNAME(CNAME(Name::from_str("boz.example.com.").unwrap()))
    );

    let additionals = lookup
        .additionals()
        .expect("Should be additional records")
        .collect::<Vec<_>>();
    assert_eq!(additionals.len(), 2);
    let record = additionals[0];
    assert_eq!(record.name(), &Name::from_str("boz.example.com.").unwrap());
    assert_eq!(
        record.data(),
        &RData::CNAME(CNAME(Name::from_str("biz.example.com.").unwrap()))
    );
    let record = additionals[1];
    assert_eq!(record.name(), &Name::from_str("biz.example.com.").unwrap());
    assert_eq!(
        record.data(),
        &RData::CNAME(CNAME(Name::from_str("baz.example.com.").unwrap()))
    );
}

/// A miss must not cost O(zone size): every NXDOMAIN used to scan all RRsets.
/// Also pins the answers around the range probe (empty non-terminals, siblings,
/// names that sort right before/after existing ones, other zones).
#[tokio::test]
async fn test_negative_lookup_is_correct_and_independent_of_zone_size() {
    use hickory_proto::rr::rdata::A;
    use hickory_server::zone_handler::LookupError;
    use std::time::Instant;
    subscribe();
    let mut auth = InMemoryZoneHandler::<TokioRuntimeProvider>::empty(
        Name::from_str("example.com.").unwrap(),
        ZoneType::Primary,
        AxfrPolicy::Deny,
        #[cfg(feature = "__dnssec")]
        Some(NxProofKind::Nsec),
    );
    for i in 0..30_000u32 {
        auth.upsert_mut(
            Record::from_rdata(Name::from_str(&format!("h{i}.example.com.")).unwrap(), 300, RData::A(A::new(10, 0, (i >> 8) as u8, i as u8))),
            0,
        );
    }
    auth.upsert_mut(Record::from_rdata(Name::from_str("a.b.deep.example.com.").unwrap(), 300, RData::A(A::new(10, 9, 9, 9))), 0);

    let look = |n: &str| {
        let auth = &auth;
        let n = Name::from_str(n).unwrap();
        async move {
            let n = n.into();
            auth.lookup(&n, RecordType::A, None, LookupOptions::default()).await
        }
    };
    use hickory_server::zone_handler::LookupControlFlow;
    let err = |f: LookupControlFlow<_>| match f {
        LookupControlFlow::Continue(Err(e)) | LookupControlFlow::Break(Err(e)) => e,
        _ => panic!("expected an error"),
    };
    // empty non-terminals exist (NODATA), true misses are NXDOMAIN, other zones REFUSED
    assert!(matches!(err(look("deep.example.com.").await), LookupError::NameExists));
    assert!(matches!(err(look("b.deep.example.com.").await), LookupError::NameExists));
    assert!(matches!(err(look("nope.example.com.").await), LookupError::ResponseCode(rc) if rc == hickory_proto::op::ResponseCode::NXDomain));
    assert!(matches!(err(look("x.deep.example.com.").await), LookupError::ResponseCode(rc) if rc == hickory_proto::op::ResponseCode::NXDomain));
    assert!(matches!(err(look("h29999x.example.com.").await), LookupError::ResponseCode(rc) if rc == hickory_proto::op::ResponseCode::NXDomain));
    assert!(matches!(err(look("other.test.").await), LookupError::ResponseCode(rc) if rc == hickory_proto::op::ResponseCode::Refused));
    // an existing name with a different type is NameExists too
    let n: hickory_proto::rr::LowerName = Name::from_str("h5.example.com.").unwrap().into();
    let f = auth.lookup(&n, RecordType::AAAA, None, LookupOptions::default()).await;
    assert!(matches!(err(f), LookupError::NameExists));

    // cost of a miss must not grow with the zone: compare 1k vs 30k RRsets (log n -> ~1.3x, a full scan -> ~30x)
    let mut small = InMemoryZoneHandler::<TokioRuntimeProvider>::empty(
        Name::from_str("example.com.").unwrap(),
        ZoneType::Primary,
        AxfrPolicy::Deny,
        #[cfg(feature = "__dnssec")]
        Some(NxProofKind::Nsec),
    );
    for i in 0..1_000u32 {
        small.upsert_mut(Record::from_rdata(Name::from_str(&format!("h{i}.example.com.")).unwrap(), 300, RData::A(A::new(10, 0, 0, i as u8))), 0);
    }
    let t_small = time_misses(&small).await;
    let t_big = time_misses(&auth).await;
    assert!(t_big < t_small * 6, "misses scale with zone size again: 1k RRsets {t_small:?} vs 30k RRsets {t_big:?}");
}

async fn time_misses(z: &InMemoryZoneHandler<TokioRuntimeProvider>) -> std::time::Duration {
    let names: Vec<hickory_proto::rr::LowerName> = (0..3_000).map(|i| Name::from_str(&format!("miss{i}.example.com.")).unwrap().into()).collect();
    let start = std::time::Instant::now();
    for n in &names {
        let _ = z.lookup(n, RecordType::A, None, LookupOptions::default()).await;
    }
    start.elapsed()
}
