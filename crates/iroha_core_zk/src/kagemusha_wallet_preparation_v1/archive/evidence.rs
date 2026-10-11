//! Original semantic tapes, without upgrading incoming soft verdicts into native admission.

use super::*;

fn digest(domain: &[u8; 8], original: &[u8]) -> [u8; 32] {
    kagemusha_wallet_poseidon_bytes_v1(u64::from_le_bytes(*domain), original)
}

// Preserve the carried operation/version/capsule/payment and signature even when
// they are invalid. Canonical statement field conversion is a shape boundary;
// receipt semantics, signature and membership belong to the soft source owners.
fn receipt(
    signer: &KagemushaWalletReceiptSignerV1,
    statement: &KagemushaWalletStatementV1,
    proof: [u8; 32],
    original: &KagemushaWalletReceiptV1,
) -> Result<(Vec<u8>, [u8; 32]), Error> {
    let body = KagemushaWalletReceiptBodyV1 {
        version: original.version,
        scheme_id: signer.scheme_id,
        wallet_id: signer.wallet_id,
        provider_contract: signer.provider_contract,
        sequence: statement.sequence,
        operation_id: original.operation_id,
        predecessor: statement.predecessor,
        successor: statement.successor,
        statement_digest: incoming_statement::digest(statement)?,
        proof_digest: proof,
        capsule_digest: original.capsule_digest,
        payment_digest: original.payment_digest,
    };
    let object = kagemusha_wallet_signed_object_digest_v1(
        KagemushaWalletObjectDigestDomainV1::Receipt,
        &body.signing_message(),
        &original.signature,
    );
    Ok((signed_tape(body.transcript(), &original.signature), object))
}

fn credited_tape(
    version: u16,
    tag: u8,
    credit: [u8; 32],
    payment: [u8; 32],
    evidence: [u8; 32],
) -> Vec<u8> {
    let mut tape = version.to_le_bytes().to_vec();
    tape.push(tag);
    for word in [credit, payment, evidence] {
        tape.extend_from_slice(&word);
    }
    tape
}

fn opening_tape(original: &KagemushaWalletCreditOpeningV1) -> Result<Vec<u8>, Error> {
    if original.siblings.len() != 32 * 32 {
        return Err(Error::Authority);
    }
    let mut tape = Vec::with_capacity(1125);
    tape.extend_from_slice(&original.credit_id);
    tape.extend_from_slice(&original.payment_digest);
    tape.push(u8::from(original.burned));
    tape.extend_from_slice(&original.next_key);
    tape.extend_from_slice(&original.slot.to_le_bytes());
    tape.extend_from_slice(&original.siblings);
    Ok(tape)
}

enum Original {
    Receive {
        statement: [Fp; 26],
        receipt: Vec<u8>,
        sigma: Vec<u8>,
        credited: Vec<u8>,
    },
    Status {
        statement: [Fp; 26],
        receipt: Vec<u8>,
        omega: Vec<u8>,
        credited: Vec<u8>,
        status: Vec<u8>,
        credit_opening: Vec<u8>,
    },
}
impl Original {
    fn credited(&self) -> &[u8] {
        match self {
            Self::Receive { credited, .. } | Self::Status { credited, .. } => credited,
        }
    }
}

fn decode_original(
    bytes: &[u8],
    request: &KagemushaWalletRequestV1,
    payment_digest: &[u8; 32],
) -> Result<Original, Error> {
    let credited: KagemushaWalletCreditedV1 = decode(bytes)?;
    if credited.scheme_id != credited.evidence.statement().scheme_id {
        return Err(Error::Authority);
    }
    Ok(match credited.evidence {
        KagemushaWalletCreditedEvidenceV1::Receive { package } => {
            if package.version != 1
                || package.lineage != KagemushaWalletLineageSlotV1::None
                || package.statement.effect.kind() != KagemushaWalletOperationKindV1::Receive
            {
                return Err(Error::Authority);
            }
            let mut proof_tape = u32::try_from(package.step_proof.bytes.len())
                .map_err(|_| Error::Authority)?
                .to_le_bytes()
                .to_vec();
            proof_tape.extend_from_slice(&package.step_proof.bytes);
            let proof = digest(b"kgwstep1", &proof_tape);
            let signer = authority(KagemushaWalletReceiptSignerV1::from_credential(
                &request.receiver_credential,
            ))?;
            let (receipt, receipt_digest) =
                receipt(&signer, &package.statement, proof, &package.receipt)?;
            let package_digest = authority(kagemusha_wallet_package_digest_v1(
                &incoming_statement::digest(&package.statement)?,
                &proof,
                &receipt_digest,
            ))?;
            Original::Receive {
                statement: incoming_statement::fields(&package.statement)?,
                receipt,
                sigma: package.step_proof.bytes,
                credited: credited_tape(
                    credited.version,
                    1,
                    request.body.credit_id(),
                    *payment_digest,
                    package_digest,
                ),
            }
        }
        KagemushaWalletCreditedEvidenceV1::Status { status } => {
            let signer = KagemushaWalletReceiptSignerV1 {
                scheme_id: status.lineage.public.scheme_id,
                wallet_id: status.lineage.public.wallet_id,
                provider_contract: kagemusha_wallet_provider_contract_v1(),
                payment_key: status.lineage.public.payment_key,
            };
            let (receipt, receipt_digest) = receipt(
                &signer,
                &status.statement,
                status.proof_digest,
                &status.receipt,
            )?;
            let opening = opening_tape(&status.opening)?;
            let mut tape = status.version.to_le_bytes().to_vec();
            for word in [
                incoming_statement::digest(&status.statement)?,
                status.proof_digest,
                receipt_digest,
                status.lineage.lineage_digest(),
                digest(b"kgwcopn1", &opening),
            ] {
                tape.extend_from_slice(&word);
            }
            Original::Status {
                statement: incoming_statement::fields(&status.statement)?,
                receipt,
                omega: status.lineage.bytes(),
                credited: credited_tape(
                    credited.version,
                    2,
                    request.body.credit_id(),
                    *payment_digest,
                    digest(b"kgwcsts1", &tape),
                ),
                status: tape,
                credit_opening: opening,
            }
        }
    })
}

// Bind exact incoming bytes without granting any incoming signature/proof/membership verdict.
pub(super) fn credited_digest(
    bytes: &[u8],
    request: &KagemushaWalletRequestV1,
    payment_digest: &[u8; 32],
) -> Result<[u8; 32], Error> {
    Ok(digest(
        b"kgwcrdd1",
        decode_original(bytes, request, payment_digest)?.credited(),
    ))
}

pub(super) fn original(
    bytes: &[u8],
    request: &KagemushaWalletRequestV1,
    payment_digest: &[u8; 32],
    expected_digest: &[u8; 32],
    proposal: ArchiveIncomingWitnessV1,
) -> Result<native::Evidence, Error> {
    let original = decode_original(bytes, request, payment_digest)?;
    if digest(b"kgwcrdd1", original.credited()) != *expected_digest {
        return Err(Error::Authority);
    }
    match (original, proposal) {
        (
            Original::Receive {
                statement,
                receipt,
                sigma,
                credited,
            },
            ArchiveIncomingWitnessV1::Receive(mode),
        ) => Ok(native::Evidence::Receive {
            statement,
            receipt,
            sigma,
            credited,
            mode: *mode,
        }),
        (
            Original::Status {
                statement,
                receipt,
                omega,
                credited,
                status,
                credit_opening,
            },
            ArchiveIncomingWitnessV1::Status(witness),
        ) => Ok(native::Evidence::Status {
            statement,
            receipt,
            omega,
            credited,
            status,
            credit_opening,
            witness,
        }),
        _ => Err(Error::Authority),
    }
}
