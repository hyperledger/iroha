//! Canonical field representation without accepting an incoming statement's semantics.

use super::*;

fn word(bytes: [u8; 32]) -> Result<Fp, Error> {
    Option::<Fp>::from(Fp::from_repr(bytes)).ok_or(Error::Authority)
}

fn limbs(bytes: [u8; 32]) -> [Fp; 2] {
    core::array::from_fn(|i| {
        let mut limb = [0; 16];
        limb.copy_from_slice(&bytes[i * 16..(i + 1) * 16]);
        Fp::from_u128(u128::from_le_bytes(limb))
    })
}

pub(super) fn fields(value: &KagemushaWalletStatementV1) -> Result<[Fp; 26], Error> {
    let relation = limbs(value.relation_id);
    let scheme = limbs(value.scheme_id);
    let asset = limbs(value.asset_digest);
    let mut out = vec![
        Fp::from(u64::from(value.version)),
        relation[0],
        relation[1],
        scheme[0],
        scheme[1],
        asset[0],
        asset[1],
        word(value.credential_digest)?,
        Fp::from(u64::from(value.lifecycle.tag())),
        Fp::from_u128(value.sequence),
        Fp::from_u128(value.next_load),
        Fp::from(u64::from(value.enabled_controls)),
        Fp::from_u128(value.lineage_burned_total),
        word(value.lineage_pending_outgoing_root)?,
        word(value.predecessor.value)?,
        word(value.successor.value)?,
        Fp::from(u64::from(value.effect.tag())),
    ];
    match value.effect {
        KagemushaWalletEffectV1::Bootstrap {
            enrollment_id,
            enrollment_marker,
        } => {
            out.extend(limbs(enrollment_id));
            out.extend(limbs(enrollment_marker));
        }
        KagemushaWalletEffectV1::Load {
            receipt_digest,
            load_ordinal,
            amount,
            online_charge,
        } => out.extend([
            word(receipt_digest)?,
            Fp::from_u128(load_ordinal),
            Fp::from_u128(amount),
            Fp::from_u128(online_charge),
        ]),
        KagemushaWalletEffectV1::Send {
            credit_id,
            receiver_wallet_id,
            send_ordinal,
            amount,
            fee,
            request,
            accepted_lower_ms,
            accepted_upper_ms,
        } => {
            out.push(word(credit_id)?);
            out.extend(limbs(receiver_wallet_id));
            out.extend([
                Fp::from_u128(send_ordinal),
                Fp::from_u128(amount),
                Fp::from_u128(fee),
                word(request)?,
                Fp::from(accepted_lower_ms),
                Fp::from(accepted_upper_ms),
            ]);
        }
        KagemushaWalletEffectV1::Receive {
            credit_id,
            payer_wallet_id,
            amount,
        } => {
            out.push(word(credit_id)?);
            out.extend(limbs(payer_wallet_id));
            out.push(Fp::from_u128(amount));
        }
        KagemushaWalletEffectV1::ArchiveSent {
            credit_id,
            credited,
        } => out.extend([word(credit_id)?, word(credited)?]),
        KagemushaWalletEffectV1::Unload {
            nullifier,
            redeem_ordinal,
            amount,
            online_charge,
            charge_quote,
        } => out.extend([
            word(nullifier)?,
            Fp::from_u128(redeem_ordinal),
            Fp::from_u128(amount),
            Fp::from_u128(online_charge),
            word(charge_quote)?,
        ]),
        KagemushaWalletEffectV1::RefreshPolicy {
            update_kind,
            update,
            accepted_time_floor_ms,
        } => out.extend([
            Fp::from(u64::from(update_kind.tag())),
            word(update)?,
            Fp::from(accepted_time_floor_ms),
        ]),
        KagemushaWalletEffectV1::Retiring => {}
    }
    if out.len() > 26 {
        return Err(Error::Authority);
    }
    out.resize(26, Fp::from(0));
    out.try_into().map_err(|_| Error::Authority)
}

pub(super) fn digest(value: &KagemushaWalletStatementV1) -> Result<[u8; 32], Error> {
    authority(kagemusha_wallet_poseidon_v1(
        KAGEMUSHA_WALLET_STATEMENT_DOMAIN_V1,
        &fields(value)?.map(|value| value.to_repr()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_effects_match_model_projection_and_invalid_represented_fields_remain_visible() {
        let f = kagemusha_wallet_field_from_u128_v1;
        let effects = [
            KagemushaWalletEffectV1::Bootstrap {
                enrollment_id: [1; 32],
                enrollment_marker: [2; 32],
            },
            KagemushaWalletEffectV1::Load {
                receipt_digest: f(1),
                load_ordinal: 2,
                amount: 3,
                online_charge: 4,
            },
            KagemushaWalletEffectV1::Send {
                credit_id: f(1),
                receiver_wallet_id: [2; 32],
                send_ordinal: 3,
                amount: 4,
                fee: 5,
                request: f(6),
                accepted_lower_ms: 7,
                accepted_upper_ms: 8,
            },
            KagemushaWalletEffectV1::Receive {
                credit_id: f(1),
                payer_wallet_id: [2; 32],
                amount: 3,
            },
            KagemushaWalletEffectV1::ArchiveSent {
                credit_id: f(1),
                credited: f(2),
            },
            KagemushaWalletEffectV1::Unload {
                nullifier: f(1),
                redeem_ordinal: 2,
                amount: 5,
                online_charge: 3,
                charge_quote: f(4),
            },
            KagemushaWalletEffectV1::RefreshPolicy {
                update_kind: KagemushaWalletPolicyUpdateKindV1::SchemePolicy,
                update: f(1),
                accepted_time_floor_ms: 2,
            },
            KagemushaWalletEffectV1::Retiring,
        ];
        for effect in effects {
            let bootstrap = effect.kind() == KagemushaWalletOperationKindV1::Bootstrap;
            let consuming = effect.kind().consumes_lineage();
            let mut value = KagemushaWalletStatementV1 {
                version: 1,
                relation_id: [1; 32],
                scheme_id: [2; 32],
                asset_digest: [3; 32],
                credential_digest: f(4),
                lifecycle: KagemushaWalletLifecycleV1::Active,
                sequence: if bootstrap { 0 } else { 1 },
                next_load: 0,
                enabled_controls: 0,
                lineage_burned_total: 0,
                lineage_pending_outgoing_root: if consuming { f(5) } else { f(0) },
                predecessor: KagemushaWalletStateCommitmentV1 {
                    value: if bootstrap { f(0) } else { f(6) },
                },
                successor: KagemushaWalletStateCommitmentV1 { value: f(7) },
                effect,
            };
            if let KagemushaWalletEffectV1::Load { load_ordinal, .. } = effect {
                value.next_load = load_ordinal + 1;
            }
            if effect.kind() == KagemushaWalletOperationKindV1::Retiring {
                value.lifecycle = KagemushaWalletLifecycleV1::Retiring;
            }
            assert_eq!(
                fields(&value).unwrap().map(|x| x.to_repr()).to_vec(),
                value.field_items().unwrap()
            );
            assert_eq!(digest(&value).unwrap(), value.statement_digest().unwrap());
            value.version = 9;
            value.enabled_controls = 99;
            assert!(value.field_items().is_err());
            let raw = fields(&value).unwrap();
            assert_eq!(raw[0], Fp::from(9));
            assert_eq!(raw[11], Fp::from(99));
            value.credential_digest = [0xff; 32];
            assert!(fields(&value).is_err());
        }
    }
}
