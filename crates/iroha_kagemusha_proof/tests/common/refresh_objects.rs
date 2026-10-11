//! Genuine signed updates and exact state/map witnesses for all Refresh kinds.

use super::{bootstrap, bootstrap_objects};
use bootstrap_objects::{Signed, id, key, sec1, sign, small_id};
use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{
    a_relation::own::OwnPolicy,
    admin_sigma::{
        BootstrapWitness, RefreshKind, RefreshUpdateWitness, RefreshWitness, StateWitness,
    },
    operation_relation::{map_effects::BLACKLIST_HISTORY_DOMAIN, objects::ObjectKind},
    tree::{
        BlacklistTree, IndexedInsert, IndexedTree, QuotaUsageTree, QuotaWindow, QuotaWindowTree,
    },
    witness::core_index as core,
};
use iroha_pasta::{Fp, poseidon::hash_with_domain};
use iroha_plonk_gadgets::{bytes::p_bytes_native, statement::STATEMENT_DOMAIN};
use iroha_plonk_recursion::obligation::ledger::Variant;

/// Fixed variants, in the tag7 effect-kind order.
pub const VARIANTS: [Variant; 5] = [
    Variant::RefreshCredential,
    Variant::RefreshSchemePolicy,
    Variant::RefreshBlacklist,
    Variant::RefreshQuotaShare,
    Variant::RefreshTimeAnchor,
];

/// Actual fixed64 arrays opened by the quota-map owner.
#[derive(Clone)]
pub struct QuotaFixture {
    pub old: [[Fp; 4]; 64],
    pub windows: [[Fp; 4]; 64],
    pub used: [Fp; 64],
    pub issued: Fp,
    pub count: Fp,
}

impl QuotaFixture {
    /// Typed old/window/used subhashes followed by the exact issue/count words.
    pub fn commitments(&self) -> [Fp; 5] {
        let hash = |tag: u64, fields: Vec<Fp>| {
            let mut words = vec![
                Fp::from(tag),
                Fp::from(u64::try_from(fields.len()).unwrap()),
            ];
            words.extend(fields);
            hash_with_domain(u64::from_le_bytes(*b"kgwciw_1"), &words)
        };
        [
            hash(7, self.old.iter().flatten().copied().collect()),
            hash(8, self.windows.iter().flatten().copied().collect()),
            hash(9, self.used.to_vec()),
            self.issued,
            self.count,
        ]
    }
}

/// Original signed objects; the Receipt is created only for supplied sigma bytes.
#[derive(Clone)]
pub struct RefreshFixture {
    pub variant: Variant,
    pub witness: RefreshWitness,
    pub update_certificate: Signed,
    pub update: Signed,
    pub current_certificate: Signed,
    pub current_credential: Signed,
    pub blacklist: Option<IndexedInsert<Fp>>,
    pub quota: Option<QuotaFixture>,
}

/// Same root/provider policy used by the genuine Bootstrap signing helpers.
pub fn policy() -> OwnPolicy {
    OwnPolicy::new([31, 32], key(23)).unwrap()
}

/// Seed an enrolled wallet without requiring any Load trust assumption.
pub fn fixture(variant: Variant) -> RefreshFixture {
    let (before, certificate, credential) = bootstrap_objects::enrollment();
    authorized(&before, &certificate, &credential, variant)
}

/// Build from an actual Bootstrap predecessor and its original enrollment tapes.
/// Blacklist/quota cases start with that predecessor's empty history/usage arrays.
pub fn authorized(
    before: &BootstrapWitness,
    current_certificate: &Signed,
    current_credential: &Signed,
    variant: Variant,
) -> RefreshFixture {
    assert_eq!(current_credential.digest(), before.core[core::CREDENTIAL]);
    let kind = VARIANTS.iter().position(|v| *v == variant).unwrap() + 1;
    let role = match variant {
        Variant::RefreshCredential => 1,
        Variant::RefreshTimeAnchor => 4,
        _ => 3,
    };
    let mut body = 1u16.to_le_bytes().to_vec();
    body.extend(id(before.core[1], before.core[2]));
    body.push(role);
    body.extend(sec1(key(19)));
    body.extend(2u64.to_le_bytes());
    let certificate = sign(ObjectKind::Certificate, body, 23, 73);
    let mut after = *before;
    after.core[core::SEQUENCE] += Fp::ONE;
    after.core[core::STATE_NONCE] += Fp::ONE;
    let issued = if variant == Variant::RefreshSchemePolicy {
        before.core[core::TIME_FLOOR]
    } else {
        Fp::from(201)
    };
    after.core[core::TIME_FLOOR] = issued;
    let mut blacklist = None;
    let mut quota = None;
    let mut body = 1u16.to_le_bytes().to_vec();
    body.extend(id(before.core[1], before.core[2]));
    let object_kind = match variant {
        Variant::RefreshCredential => {
            body = current_credential.bytes[..ObjectKind::Credential.body_len()].to_vec();
            let tail = body.len() - 52;
            body[tail..tail + 8].copy_from_slice(&201u64.to_le_bytes());
            body[tail + 8..tail + 12].copy_from_slice(&1u32.to_le_bytes());
            body[tail + 20..].copy_from_slice(&certificate.digest().to_repr());
            ObjectKind::Credential
        }
        Variant::RefreshSchemePolicy => {
            body.extend(id(before.core[3], before.core[4]));
            body.extend(1u64.to_le_bytes());
            body.extend(7u32.to_le_bytes());
            body.extend(Fp::ZERO.to_repr());
            body.extend(certificate.digest().to_repr());
            after.core[core::POLICY_EPOCH] = Fp::ONE;
            // The genuine initial credential permits none of these controls.
            after.core[core::ENABLED_CONTROLS] = Fp::ZERO;
            ObjectKind::SchemePolicy
        }
        Variant::RefreshBlacklist => {
            let root = BlacklistTree::new(vec![]).unwrap().root::<Fp>();
            body.extend(1u64.to_le_bytes());
            body.extend(201u64.to_le_bytes());
            body.extend(0u32.to_le_bytes());
            body.extend(root.to_repr());
            body.extend(certificate.digest().to_repr());
            after.core[core::BLACKLIST_VERSION] = Fp::ONE;
            after.core[core::BLACKLIST_ROOT] = root;
            after.core[core::BLACKLIST_ISSUED_AT] = issued;
            let mut history = IndexedTree::new();
            assert_eq!(history.root(), before.rest[7]);
            blacklist = Some(
                history
                    .insert(
                        Fp::ONE,
                        hash_with_domain(BLACKLIST_HISTORY_DOMAIN, &[Fp::ONE, root]),
                    )
                    .unwrap(),
            );
            after.rest[7] = history.root();
            ObjectKind::Blacklist
        }
        Variant::RefreshQuotaShare => {
            let windows = QuotaWindowTree::new(&[QuotaWindow {
                kind: 1,
                start_ms: 201,
                end_ms: 400,
                limit: 1000,
            }])
            .unwrap();
            let usage = QuotaUsageTree::<Fp>::new(&windows);
            let old = QuotaUsageTree::<Fp>::new(&QuotaWindowTree::new(&[]).unwrap());
            assert_eq!(old.root(), before.core[core::QUOTA_USAGE_ROOT]);
            body.extend(id(before.core[3], before.core[4]));
            body.extend(id(before.core[5], before.core[6]));
            body.extend(1u64.to_le_bytes());
            body.extend(201u64.to_le_bytes());
            body.extend(500u64.to_le_bytes());
            body.extend(windows.root::<Fp>().to_repr());
            body.extend(1u32.to_le_bytes());
            body.extend(certificate.digest().to_repr());
            after.rest[5] = Fp::ONE;
            after.core[core::QUOTA_WINDOWS_ROOT] = windows.root();
            after.core[core::QUOTA_SHARE_EXPIRY] = Fp::from(500);
            after.core[core::QUOTA_USAGE_ROOT] = usage.root();
            quota = Some(QuotaFixture {
                old: [[Fp::ZERO; 4]; 64],
                windows: ::core::array::from_fn(|i| {
                    let w = windows.slot(i);
                    [
                        Fp::from(u64::from(w.kind)),
                        Fp::from(w.start_ms),
                        Fp::from(w.end_ms),
                        Fp::from_u128(w.limit),
                    ]
                }),
                used: [Fp::ZERO; 64],
                issued,
                count: Fp::ONE,
            });
            ObjectKind::QuotaShare
        }
        Variant::RefreshTimeAnchor => {
            body.extend(id(before.core[5], before.core[6]));
            body.extend(small_id(501, 502));
            body.extend(201u64.to_le_bytes());
            body.extend(certificate.digest().to_repr());
            ObjectKind::TimeAnchor
        }
        _ => unreachable!(),
    };
    let update = sign(object_kind, body, 19, 79);
    match variant {
        Variant::RefreshCredential => after.core[core::CREDENTIAL] = update.digest(),
        Variant::RefreshSchemePolicy => after.rest[1] = update.digest(),
        Variant::RefreshBlacklist => after.rest[3] = update.digest(),
        Variant::RefreshQuotaShare => after.rest[4] = update.digest(),
        Variant::RefreshTimeAnchor => after.rest[6] = update.digest(),
        _ => unreachable!(),
    }
    after.statement[12..].fill(Fp::ZERO);
    after.statement[11] = before.core[core::ENABLED_CONTROLS];
    after.statement[14] = before.lineage[5];
    after.statement[16] = Fp::from(7);
    after.statement[17] = Fp::from(u64::try_from(kind).unwrap());
    after.statement[18] = update.digest();
    after.statement[19] = issued;
    bootstrap::rebind(&mut after);
    RefreshFixture {
        variant,
        witness: RefreshWitness {
            predecessor: StateWitness::from(before),
            successor: StateWitness::from(&after),
            statement: after.statement,
            update: RefreshUpdateWitness {
                kind: match variant {
                    Variant::RefreshCredential => RefreshKind::Credential,
                    Variant::RefreshSchemePolicy => RefreshKind::SchemePolicy,
                    Variant::RefreshBlacklist => RefreshKind::Blacklist,
                    Variant::RefreshQuotaShare => RefreshKind::QuotaShare,
                    Variant::RefreshTimeAnchor => RefreshKind::TimeAnchor,
                    _ => unreachable!(),
                },
                digest: update.digest(),
                scheme: if variant == Variant::RefreshCredential {
                    [Fp::ZERO; 2]
                } else {
                    [before.core[1], before.core[2]]
                },
                asset: if matches!(
                    variant,
                    Variant::RefreshSchemePolicy | Variant::RefreshQuotaShare
                ) {
                    [before.core[3], before.core[4]]
                } else {
                    [Fp::ZERO; 2]
                },
                wallet: if matches!(
                    variant,
                    Variant::RefreshQuotaShare | Variant::RefreshTimeAnchor
                ) {
                    [before.core[5], before.core[6]]
                } else {
                    [Fp::ZERO; 2]
                },
                counter: match variant {
                    Variant::RefreshSchemePolicy => after.core[core::POLICY_EPOCH],
                    Variant::RefreshBlacklist => after.core[core::BLACKLIST_VERSION],
                    Variant::RefreshQuotaShare => after.rest[5],
                    _ => Fp::ZERO,
                },
                issued_at_ms: if variant == Variant::RefreshSchemePolicy {
                    Fp::ZERO
                } else {
                    issued
                },
                expires_at_ms: match variant {
                    Variant::RefreshCredential => {
                        let end = ObjectKind::Credential.body_len();
                        Fp::from(u64::from_le_bytes(
                            update.bytes[end - 40..end - 32].try_into().unwrap(),
                        ))
                    }
                    Variant::RefreshQuotaShare => Fp::from(500),
                    _ => Fp::ZERO,
                },
                root: match variant {
                    Variant::RefreshBlacklist => after.core[core::BLACKLIST_ROOT],
                    Variant::RefreshQuotaShare => after.core[core::QUOTA_WINDOWS_ROOT],
                    _ => Fp::ZERO,
                },
                controls: Fp::from(if variant == Variant::RefreshSchemePolicy {
                    7
                } else {
                    0
                }),
                fee_schedule: Fp::ZERO,
            },
        },
        update_certificate: certificate,
        update,
        current_certificate: current_certificate.clone(),
        current_credential: current_credential.clone(),
        blacklist,
        quota,
    }
}

impl RefreshFixture {
    /// Sign the Receipt over the exact retained sigma, after proving the leaf.
    pub fn objects(&self, sigma: &[u8]) -> [Signed; 5] {
        let w = &self.witness;
        let mut framed = u32::try_from(sigma.len()).unwrap().to_le_bytes().to_vec();
        framed.extend(sigma);
        let proof = p_bytes_native(u64::from_le_bytes(*b"kgwstep1"), &framed);
        let operation = hash_with_domain(
            u64::from_le_bytes(*b"kgwopid1"),
            &[
                w.predecessor.core[5],
                w.predecessor.core[6],
                Fp::from(7),
                w.statement[18],
            ],
        );
        let mut body = 1u16.to_le_bytes().to_vec();
        body.extend(id(w.predecessor.core[1], w.predecessor.core[2]));
        body.extend(id(w.predecessor.core[5], w.predecessor.core[6]));
        body.extend(small_id(31, 32));
        body.extend(&w.statement[9].to_repr()[..16]);
        for value in [
            operation,
            w.statement[14],
            w.statement[15],
            hash_with_domain(STATEMENT_DOMAIN, &w.statement),
            proof,
        ] {
            body.extend(value.to_repr());
        }
        body.extend(small_id(511, 512));
        body.extend(Fp::ZERO.to_repr());
        [
            self.update_certificate.clone(),
            self.update.clone(),
            sign(ObjectKind::Receipt, body, 29, 83),
            self.current_certificate.clone(),
            self.current_credential.clone(),
        ]
    }
}
