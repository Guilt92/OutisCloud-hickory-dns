// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Zone file based serving with Dynamic DNS and journaling support

#[cfg(feature = "__dnssec")]
use std::{fs, str::FromStr};
use std::{
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
};

#[cfg(feature = "metrics")]
use crate::metrics::PersistentStoreMetrics;
#[cfg(feature = "__dnssec")]
use crate::proto::rr::{
    TSigner,
    rdata::tsig::{TsigAlgorithm, TsigError},
};
#[cfg(feature = "__dnssec")]
use crate::{
    dnssec::NxProofKind,
    proto::dnssec::{DnsSecResult, DnssecSigner},
    zone_handler::{DnssecZoneHandler, Nsec3QueryInfo},
};
use crate::{
    proto::op::ResponseCode,
    proto::rr::{LowerName, Name, RecordType},
    server::{Request, RequestInfo},
    store::in_memory::{InMemoryZoneHandler, zone_from_path},
    zone_handler::{
        AuthLookup, AxfrPolicy, LookupControlFlow, LookupError, LookupOptions, ZoneHandler,
        ZoneTransfer, ZoneType,
    },
};
use hickory_proto::rr::TSigResponseContext;
use serde::Deserialize;
#[cfg(feature = "__dnssec")]
use tracing::warn;

/// FileZoneHandler is responsible for storing the resource records for a particular zone.
///
/// Zone handlers default to DNSClass IN. The ZoneType specifies if this should be treated as the
/// start of authority for the zone, is a Secondary, or a cached zone.
pub struct FileZoneHandler {
    in_memory: InMemoryZoneHandler,
    axfr_policy: AxfrPolicy,
    allowed_transfer_peers: Vec<std::net::IpAddr>,
    #[cfg(feature = "__dnssec")]
    tsig_signers: Vec<TSigner>,
    #[cfg(feature = "metrics")]
    #[allow(unused)]
    metrics: PersistentStoreMetrics,
}

impl FileZoneHandler {
    /// Creates a new ZoneHandler.
    ///
    /// # Arguments
    ///
    /// * `origin` - The zone `Name` being created, this should match that of the `RecordType::SOA`
    ///   record.
    /// * `records` - The map of the initial set of records in the zone.
    /// * `zone_type` - The type of zone, i.e. is this authoritative?
    /// * `axfr_policy` - A policy for determining if AXFR is allowed.
    /// * `nx_proof_kind` - The kind of non-existence proof to be used by the server.
    ///
    /// # Return value
    ///
    /// The new `ZoneHandler`.
    pub async fn new(in_memory: InMemoryZoneHandler) -> Self {
        let axfr_policy = in_memory.axfr_policy();
        Self {
            axfr_policy,
            allowed_transfer_peers: Vec::new(),
            #[cfg(feature = "__dnssec")]
            tsig_signers: Vec::new(),
            #[cfg(feature = "metrics")]
            metrics: {
                let new = PersistentStoreMetrics::new("file");
                let records = in_memory.records().await;
                new.zone_records.increment(records.len() as f64);
                new
            },
            in_memory,
        }
    }

    /// Read the ZoneHandler for the origin from the specified configuration
    pub fn try_from_config(
        origin: Name,
        zone_type: ZoneType,
        axfr_policy: AxfrPolicy,
        root_dir: Option<&Path>,
        config: &FileConfig,
        #[cfg(feature = "__dnssec")] nx_proof_kind: Option<NxProofKind>,
    ) -> Result<Self, String> {
        let zone_path = rooted(&config.zone_path, root_dir);
        let records = zone_from_path(&zone_path, origin.clone())
            .map_err(|e| format!("failed to load zone file: {e}"))?;
        #[cfg(feature = "__dnssec")]
        let tsig_signers = config
            .tsig_keys
            .iter()
            .map(|key| key.to_signer(&origin, root_dir))
            .collect::<Result<Vec<_>, _>>()?;

        // Don't call `new()`, since it needs to be async to get the number of records to initialize metrics
        Ok(Self {
            axfr_policy,
            allowed_transfer_peers: config.allowed_transfer_peers.clone(),
            #[cfg(feature = "__dnssec")]
            tsig_signers,
            #[cfg(feature = "metrics")]
            metrics: {
                let new = PersistentStoreMetrics::new("file");
                new.zone_records.increment(records.len() as f64);
                new
            },
            in_memory: InMemoryZoneHandler::new(
                origin,
                records,
                zone_type,
                // The file wrapper performs the configured transfer policy and TSIG
                // verification before delegating to this in-memory record store.
                AxfrPolicy::AllowAll,
                #[cfg(feature = "__dnssec")]
                nx_proof_kind,
            )?,
        })
    }

    #[cfg(feature = "__dnssec")]
    async fn authorize_axfr(
        &self,
        request: &Request,
        now: u64,
    ) -> (Result<(), ResponseCode>, Option<TSigResponseContext>) {
        match self.axfr_policy {
            AxfrPolicy::Deny => (Err(ResponseCode::Refused), None),
            AxfrPolicy::AllowAll => (Ok(()), None),
            AxfrPolicy::AllowSigned => match request.signature() {
                Some(tsig) => {
                    let req_id = request.header().id();
                    let Some(signer) = self
                        .tsig_signers
                        .iter()
                        .find(|signer| signer.signer_name() == tsig.name())
                    else {
                        warn!("no TSIG key name matched for AXFR request id {req_id}");
                        return (
                            Err(ResponseCode::NotAuth),
                            Some(TSigResponseContext::unknown_key(
                                req_id,
                                now,
                                tsig.name().clone(),
                            )),
                        );
                    };
                    let Ok((_, _, range)) =
                        signer.verify_message_byte(request.as_slice(), None, true)
                    else {
                        warn!("invalid TSIG signature for AXFR request id {req_id}");
                        return (
                            Err(ResponseCode::NotAuth),
                            Some(TSigResponseContext::bad_signature(
                                req_id,
                                now,
                                signer.clone(),
                            )),
                        );
                    };
                    let (response, error) = if range.contains(&now) {
                        (Ok(()), None)
                    } else {
                        warn!("expired TSIG signature for AXFR request id {req_id}");
                        (Err(ResponseCode::NotAuth), Some(TsigError::BadTime))
                    };
                    (
                        response,
                        Some(TSigResponseContext::new(
                            req_id,
                            now,
                            signer.clone(),
                            tsig.data().mac().to_vec(),
                            error,
                        )),
                    )
                }
                None => {
                    warn!("AXFR request was not signed");
                    (Err(ResponseCode::Refused), None)
                }
            },
        }
    }
}

impl Deref for FileZoneHandler {
    type Target = InMemoryZoneHandler;

    fn deref(&self) -> &Self::Target {
        &self.in_memory
    }
}

impl DerefMut for FileZoneHandler {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.in_memory
    }
}

#[async_trait::async_trait]
impl ZoneHandler for FileZoneHandler {
    async fn notify(
        &self,
        request: &Request,
        now: u64,
    ) -> (ResponseCode, Option<TSigResponseContext>) {
        #[cfg(feature = "__dnssec")]
        {
            if self.tsig_signers.is_empty() {
                return if request.signature().is_some() {
                    (ResponseCode::NotAuth, None)
                } else {
                    (ResponseCode::NoError, None)
                };
            }
            let Some(tsig) = request.signature() else {
                return (ResponseCode::Refused, None);
            };
            let request_id = request.header().id();
            let Some(signer) = self
                .tsig_signers
                .iter()
                .find(|signer| signer.signer_name() == tsig.name())
            else {
                return (
                    ResponseCode::NotAuth,
                    Some(TSigResponseContext::unknown_key(
                        request_id,
                        now,
                        tsig.name().clone(),
                    )),
                );
            };
            let Ok((_, _, range)) = signer.verify_message_byte(request.as_slice(), None, true)
            else {
                return (
                    ResponseCode::NotAuth,
                    Some(TSigResponseContext::bad_signature(
                        request_id,
                        now,
                        signer.clone(),
                    )),
                );
            };
            let expired = !range.contains(&now);
            let context = TSigResponseContext::new(
                request_id,
                now,
                signer.clone(),
                tsig.data().mac().to_vec(),
                expired.then_some(TsigError::BadTime),
            );
            return (
                if expired {
                    ResponseCode::NotAuth
                } else {
                    ResponseCode::NoError
                },
                Some(context),
            );
        }
        #[cfg(not(feature = "__dnssec"))]
        {
            let _ = (request, now);
            (ResponseCode::NoError, None)
        }
    }

    /// What type is this zone
    fn zone_type(&self) -> ZoneType {
        self.in_memory.zone_type()
    }

    /// Return the policy for determining if AXFR requests are allowed
    fn axfr_policy(&self) -> AxfrPolicy {
        self.axfr_policy
    }

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    fn origin(&self) -> &LowerName {
        self.in_memory.origin()
    }

    /// Looks up all Resource Records matching the given `Name` and `RecordType`.
    ///
    /// # Arguments
    ///
    /// * `name` - The name to look up.
    /// * `rtype` - The `RecordType` to look up. `RecordType::ANY` will return all records matching
    ///   `name`. `RecordType::AXFR` will return all record types except `RecordType::SOA`
    ///   due to the requirements that on zone transfers the `RecordType::SOA` must both
    ///   precede and follow all other records.
    /// * `lookup_options` - Query-related lookup options (e.g., DNSSEC DO bit, supported hash
    ///   algorithms, etc.)
    ///
    /// # Return value
    ///
    /// A LookupControlFlow containing the lookup that should be returned to the client.
    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        request_info: Option<&RequestInfo<'_>>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.in_memory
            .lookup(name, rtype, request_info, lookup_options)
            .await
    }

    /// Using the specified query, perform a lookup against this zone.
    ///
    /// # Arguments
    ///
    /// * `request` - the query to perform the lookup with.
    /// * `lookup_options` - Query-related lookup options (e.g., DNSSEC DO bit, supported hash
    ///   algorithms, etc.)
    ///
    /// # Return value
    ///
    /// A LookupControlFlow containing the lookup that should be returned to the client.
    async fn search(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        self.in_memory.search(request, lookup_options).await
    }

    async fn zone_transfer(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
        now: u64,
    ) -> Option<(
        Result<ZoneTransfer, LookupError>,
        Option<TSigResponseContext>,
    )> {
        if !self.allowed_transfer_peers.is_empty()
            && !self.allowed_transfer_peers.contains(&request.src().ip())
        {
            tracing::warn!(client = %request.src(), "AXFR request rejected by peer ACL");
            return Some((Err(LookupError::ResponseCode(ResponseCode::Refused)), None));
        }
        #[cfg(feature = "__dnssec")]
        let signer = match self.authorize_axfr(request, now).await {
            (Ok(()), signer) => signer,
            (Err(code), signer) => return Some((Err(LookupError::ResponseCode(code)), signer)),
        };
        #[cfg(not(feature = "__dnssec"))]
        if self.axfr_policy != AxfrPolicy::AllowAll {
            return Some((Err(LookupError::ResponseCode(ResponseCode::Refused)), None));
        }

        let (transfer, _) = self
            .in_memory
            .zone_transfer(request, lookup_options, now)
            .await?;
        #[cfg(feature = "__dnssec")]
        return Some((transfer, signer));
        #[cfg(not(feature = "__dnssec"))]
        Some((transfer, None))
    }

    /// Return the NSEC records based on the given name
    ///
    /// # Arguments
    ///
    /// * `name` - given this name (i.e. the lookup name), return the NSEC record that is less than
    ///   this
    /// * `lookup_options` - Query-related lookup options (e.g., DNSSEC DO bit, supported hash
    ///   algorithms, etc.)
    async fn nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.in_memory.nsec_records(name, lookup_options).await
    }

    #[cfg(feature = "__dnssec")]
    async fn nsec3_records(
        &self,
        info: Nsec3QueryInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.in_memory.nsec3_records(info, lookup_options).await
    }

    #[cfg(feature = "__dnssec")]
    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        self.in_memory.nx_proof_kind()
    }

    #[cfg(feature = "metrics")]
    fn metrics_label(&self) -> &'static str {
        "file"
    }
}

#[cfg(feature = "__dnssec")]
#[async_trait::async_trait]
impl DnssecZoneHandler for FileZoneHandler {
    /// Add Signer
    async fn add_zone_signing_key(&self, signer: DnssecSigner) -> DnsSecResult<()> {
        self.in_memory.add_zone_signing_key(signer).await
    }

    /// Sign the zone for DNSSEC
    async fn secure_zone(&self) -> DnsSecResult<()> {
        DnssecZoneHandler::secure_zone(&self.in_memory).await
    }
}

/// Configuration for file based zones
#[derive(Clone, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    /// path to the zone file
    pub zone_path: PathBuf,
    /// Optional IP allowlist for AXFR. An empty list leaves authorization to
    /// `axfr_policy`; a non-empty list is checked before TSIG authorization.
    #[serde(default)]
    pub allowed_transfer_peers: Vec<std::net::IpAddr>,
    /// TSIG keys allowed to authenticate signed AXFR requests.
    #[cfg(feature = "__dnssec")]
    #[serde(default)]
    pub tsig_keys: Vec<TsigKeyConfig>,
}

/// Configuration for a TSIG key used by file-backed zone transfers.
#[cfg(feature = "__dnssec")]
#[derive(Clone, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct TsigKeyConfig {
    /// The key name.
    pub name: String,
    /// File containing the unencoded symmetric HMAC key data.
    pub key_file: PathBuf,
    /// The TSIG HMAC algorithm.
    pub algorithm: TsigAlgorithm,
    /// Maximum permitted request signature age in seconds.
    #[serde(default = "default_fudge")]
    pub fudge: u16,
}

#[cfg(feature = "__dnssec")]
impl TsigKeyConfig {
    fn to_signer(&self, zone_name: &Name, root_dir: Option<&Path>) -> Result<TSigner, String> {
        let key_file = rooted(&self.key_file, root_dir);
        let key_data = fs::read(&key_file)
            .map_err(|e| format!("error reading TSIG key file: {}: {e}", key_file.display()))?;
        let signer_name = Name::from_str(&self.name).unwrap_or_else(|_| zone_name.clone());
        TSigner::new(key_data, self.algorithm.clone(), signer_name, self.fudge)
            .map_err(|e| format!("invalid TSIG key configuration: {e}"))
    }
}

#[cfg(feature = "__dnssec")]
fn default_fudge() -> u16 {
    300
}

pub(crate) fn rooted(zone_file: &Path, root_dir: Option<&Path>) -> PathBuf {
    match root_dir {
        Some(root) => root.join(zone_file),
        None => zone_file.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::proto::rr::{RData, rdata::A};

    use futures_executor::block_on;
    use test_support::subscribe;

    use super::*;
    use crate::zone_handler::ZoneType;

    #[test]
    fn test_load_zone() {
        subscribe();

        #[cfg(feature = "__dnssec")]
        let config = FileConfig {
            zone_path: PathBuf::from("../../tests/test-data/test_configs/dnssec/example.com.zone"),
            allowed_transfer_peers: Vec::new(),
            #[cfg(feature = "__dnssec")]
            tsig_keys: Vec::new(),
        };
        #[cfg(not(feature = "__dnssec"))]
        let config = FileConfig {
            zone_path: PathBuf::from("../../tests/test-data/test_configs/example.com.zone"),
            allowed_transfer_peers: Vec::new(),
        };
        let handler = FileZoneHandler::try_from_config(
            Name::from_str("example.com.").unwrap(),
            ZoneType::Primary,
            AxfrPolicy::Deny,
            None,
            &config,
            #[cfg(feature = "__dnssec")]
            Some(NxProofKind::Nsec),
        )
        .expect("failed to load file");

        let lookup = block_on(ZoneHandler::lookup(
            &handler,
            &LowerName::from_str("www.example.com.").unwrap(),
            RecordType::A,
            None,
            LookupOptions::default(),
        ))
        .expect("lookup failed");

        match lookup
            .into_iter()
            .next()
            .expect("A record not found in zone handler")
            .data()
        {
            RData::A(ip) => assert_eq!(A::new(127, 0, 0, 1), *ip),
            _ => panic!("wrong rdata type returned"),
        }

        let include_lookup = block_on(ZoneHandler::lookup(
            &handler,
            &LowerName::from_str("include.alias.example.com.").unwrap(),
            RecordType::A,
            None,
            LookupOptions::default(),
        ))
        .expect("INCLUDE lookup failed");

        match include_lookup
            .into_iter()
            .next()
            .expect("A record not found in zone handler")
            .data()
        {
            RData::A(ip) => assert_eq!(A::new(127, 0, 0, 5), *ip),
            _ => panic!("wrong rdata type returned"),
        }
    }
}
