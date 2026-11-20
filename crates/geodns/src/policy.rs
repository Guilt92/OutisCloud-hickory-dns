//! Deterministic traffic-policy primitives.
//!
//! Selection is hash-based rather than random so every authoritative replica
//! makes the same decision for the same inputs. No external runtime state is
//! read here; health information is supplied by the caller.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub name: String,
    pub address: String,
    pub weight: u32,
    pub healthy: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureMode {
    FailOpen,
    FailClosed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectionContext<'a> {
    pub client_key: &'a str,
    pub rule_key: &'a str,
    pub record_name: &'a str,
    pub record_type: &'a str,
    pub failure_mode: FailureMode,
}

fn bucket(ctx: &SelectionContext<'_>, seq: usize) -> u64 {
    let mut hasher = DefaultHasher::new();
    (
        ctx.client_key,
        ctx.rule_key,
        ctx.record_name,
        ctx.record_type,
        seq,
    )
        .hash(&mut hasher);
    hasher.finish()
}

/// Weighted, deterministic ordering of healthy targets.
///
/// Targets with zero weight or `healthy = false` are excluded. If no healthy
/// weighted target remains, `FailOpen` returns the unhealthy targets in input
/// order and `FailClosed` returns an empty list.
pub fn select_order(targets: &[Target], ctx: &SelectionContext<'_>) -> Vec<String> {
    let healthy: Vec<&Target> = targets
        .iter()
        .filter(|t| t.healthy && t.weight > 0)
        .collect();
    if healthy.is_empty() {
        return match ctx.failure_mode {
            FailureMode::FailOpen => targets
                .iter()
                .filter(|t| t.weight > 0)
                .map(|t| t.address.clone())
                .collect(),
            FailureMode::FailClosed => Vec::new(),
        };
    }

    let total: u64 = healthy.iter().map(|t| u64::from(t.weight)).sum();
    let mut chosen = bucket(ctx, 0) % total;
    let mut ranked: Vec<(u64, &Target)> = Vec::with_capacity(healthy.len());
    for target in healthy {
        let score = bucket(ctx, ranked.len() + 1);
        ranked.push((score, target));
    }
    ranked.sort_by(|a, b| a.0.cmp(&b.0));

    let mut first = None;
    for (_, target) in &ranked {
        if chosen < u64::from(target.weight) {
            first = Some(target);
            break;
        }
        chosen -= u64::from(target.weight);
    }
    let first = first.expect("weighted selection always chooses a target");

    let mut order = vec![first.address.clone()];
    order.extend(
        ranked
            .iter()
            .filter(|(_, t)| t.address != first.address)
            .map(|(_, t)| t.address.clone()),
    );
    order
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(mode: FailureMode) -> SelectionContext<'static> {
        SelectionContext {
            client_key: "192.0.2.10/32",
            rule_key: "rule-1",
            record_name: "www.example.com.",
            record_type: "A",
            failure_mode: mode,
        }
    }

    #[test]
    fn selection_is_deterministic_and_excludes_unhealthy_targets() {
        let targets = vec![
            Target {
                name: "a".into(),
                address: "192.0.2.1".into(),
                weight: 1,
                healthy: true,
            },
            Target {
                name: "b".into(),
                address: "192.0.2.2".into(),
                weight: 3,
                healthy: true,
            },
            Target {
                name: "c".into(),
                address: "192.0.2.3".into(),
                weight: 9,
                healthy: false,
            },
            Target {
                name: "d".into(),
                address: "192.0.2.4".into(),
                weight: 0,
                healthy: true,
            },
        ];
        let first = select_order(&targets, &ctx(FailureMode::FailClosed));
        assert_eq!(first, select_order(&targets, &ctx(FailureMode::FailClosed)));
        assert_eq!(first.len(), 2);
        assert!(first.iter().all(|a| a != "192.0.2.3" && a != "192.0.2.4"));
    }

    #[test]
    fn different_clients_can_select_different_targets() {
        let targets = vec![
            Target {
                name: "a".into(),
                address: "192.0.2.1".into(),
                weight: 1,
                healthy: true,
            },
            Target {
                name: "b".into(),
                address: "192.0.2.2".into(),
                weight: 1,
                healthy: true,
            },
        ];
        let mut seen = std::collections::HashSet::new();
        for i in 0..64 {
            let context = SelectionContext {
                client_key: Box::leak(format!("192.0.2.{i}/32").into_boxed_str()),
                ..ctx(FailureMode::FailClosed)
            };
            seen.insert(select_order(&targets, &context)[0].clone());
        }
        assert_eq!(seen.len(), 2, "weighted distribution must use both targets");
    }

    #[test]
    fn failure_modes_are_explicit() {
        let targets = vec![Target {
            name: "a".into(),
            address: "192.0.2.1".into(),
            weight: 1,
            healthy: false,
        }];
        assert_eq!(
            select_order(&targets, &ctx(FailureMode::FailOpen)),
            vec!["192.0.2.1"]
        );
        assert!(select_order(&targets, &ctx(FailureMode::FailClosed)).is_empty());
    }
}
