//! Envelope sizes of the split-lineage layouts (§8, design §7).
//!
//! Every case uses structurally valid objects and is checked against its complete-frame
//! bound. The sample lengths cover the current 3,456-byte maximum Send proof and 4,800-byte
//! three-terminal Omega transport. The bytes themselves are stand-ins: these tests qualify
//! encoding overhead and exact size limits, not cryptographic proof acceptance or frozen keys.
//! Receive uses the same conservative 3,456-byte sample. The credit-status opening has exactly
//! 32 siblings, so its complete envelope has a fixed overhead plus the Omega proof length.
//! The signed blacklist is downloaded online and has no peer-envelope case here.

use super::{
    messages::messages_tests::MessageFixture,
    vectors_tests::{vector_control, vector_offer, vector_world},
    *,
};

/// Structural sample covering the currently measured largest Send proof.
const SAMPLE_SIGMA_SEND_BYTES: usize = 3_456;
/// Structural sample of the currently measured three-terminal Omega transport.
const SAMPLE_OMEGA_PROOF_BYTES: usize = 4_800;
/// Conservative Receive proof sample; acceptance remains a native-verifier obligation.
const SAMPLE_SIGMA_RECV_BYTES: usize = 3_456;
/// Other credits recorded in the worst-case `CreditStatus` tree; the opening has exactly 32
/// siblings whatever the count.
const STATUS_OTHER_CREDITS: usize = 5;
/// Largest proof length searched for.
const SEARCH_LIMIT: usize = KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1;

/// Complete canonical envelope frame length of `message`, without validation.
fn envelope_len(message: &KagemushaWalletMessageV1) -> usize {
    norito::encode_canonical(&KagemushaWalletEnvelopeV1::new(message.clone()))
        .expect("encode envelope")
        .len()
}

/// Stand-in proof bytes of exactly `len` bytes.
fn bytes_of(len: usize) -> Vec<u8> {
    vec![0xa5; len]
}

/// Largest `len` in `0..=limit` with `frame_len(len) <= bound`, for a nondecreasing
/// `frame_len`; zero when even one byte does not fit.
fn largest_fitting(bound: usize, limit: usize, frame_len: impl Fn(usize) -> usize) -> usize {
    let (mut fits, mut exceeds) = (0, limit + 1);
    while exceeds - fits > 1 {
        let middle = fits + (exceeds - fits) / 2;
        if frame_len(middle) <= bound {
            fits = middle;
        } else {
            exceeds = middle;
        }
    }
    fits
}

/// `payment` with its Ω(pred) transport proof and `σ_send` resized.
fn payment_with(
    payment: &KagemushaWalletPaymentV1,
    omega: usize,
    sigma: usize,
) -> KagemushaWalletMessageV1 {
    let mut payment = payment.clone();
    payment.send.step_proof.bytes = bytes_of(sigma);
    if let KagemushaWalletLineageSlotV1::Present { lineage } = &mut payment.send.lineage {
        lineage.proof = bytes_of(omega);
    }
    KagemushaWalletMessageV1::Payment { payment }
}

/// `credited` with its `σ_recv` (Receive) or Ω(h) proof (Status) resized.
fn credited_with(credited: &KagemushaWalletCreditedV1, proof: usize) -> KagemushaWalletMessageV1 {
    let mut credited = credited.clone();
    match &mut credited.evidence {
        KagemushaWalletCreditedEvidenceV1::Receive { package } => {
            package.step_proof.bytes = bytes_of(proof);
        }
        KagemushaWalletCreditedEvidenceV1::Status { status } => {
            status.lineage.proof = bytes_of(proof);
        }
    }
    KagemushaWalletMessageV1::Credited { credited }
}

/// `lineage` with its transport proof resized.
fn lineage_with(
    lineage: &KagemushaWalletLineageMessageV1,
    omega: usize,
) -> KagemushaWalletMessageV1 {
    let mut lineage = lineage.clone();
    lineage.lineage.proof = bytes_of(omega);
    KagemushaWalletMessageV1::Lineage { lineage }
}

/// Measured split-lineage sizes in complete envelope bytes.
struct Sizes {
    offer: usize,
    credential: usize,
    session_control: usize,
    request: usize,
    payment: usize,
    payment_overhead: usize,
    largest_omega_with_sample_sigma: usize,
    largest_joint_proof: usize,
    credited_receive: usize,
    credited_receive_overhead: usize,
    largest_sigma_in_receive: usize,
    credited_status: usize,
    credited_status_overhead: usize,
    credit_status: usize,
    largest_omega_in_status: usize,
    lineage: usize,
    lineage_overhead: usize,
    certificates: usize,
}

/// Validate every structural sample and measure its exact canonical encoding.
fn measure(f: &MessageFixture) -> Sizes {
    let message_max = KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1;
    let (omega, sigma, sigma_recv) = (
        SAMPLE_OMEGA_PROOF_BYTES,
        SAMPLE_SIGMA_SEND_BYTES,
        SAMPLE_SIGMA_RECV_BYTES,
    );
    let request = f.request(true);
    let payment = f.payment_with(true, omega, sigma);
    assert!(
        payment.request.body.fee > 0,
        "the largest Request carries a fee"
    );
    assert_eq!(request.certificates.len(), 2);
    let credited_receive =
        KagemushaWalletCreditedV1::from_receive(f.receive_package(&payment, sigma_recv))
            .expect("credited receive");
    let status = f.credit_status(&payment, omega, STATUS_OTHER_CREDITS, false);
    let credited_status =
        KagemushaWalletCreditedV1::from_status(status.clone()).expect("credited status");
    let lineage = f.lineage_message(&payment);
    let certificates = KagemushaWalletPolicyDataV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id: f.scheme_id(),
        asset_digest: f.asset_digest(),
        item: KagemushaWalletPolicyDataItemV1::Certificates {
            certificates: KagemushaWalletCertificateSetV1::new(vec![
                f.payer.enrollment_certificate,
                f.receiver.enrollment_certificate,
                f.regulator_certificate,
            ])
            .expect("three certificates"),
        },
    };
    let offer = vector_offer(f);
    let messages = [
        KagemushaWalletMessageV1::Offer {
            offer: offer.clone(),
        },
        KagemushaWalletMessageV1::SessionControl {
            control: vector_control(f, KagemushaWalletSessionControlKindV1::ReceiveDeferred),
        },
        KagemushaWalletMessageV1::Request { request },
        KagemushaWalletMessageV1::Payment {
            payment: payment.clone(),
        },
        KagemushaWalletMessageV1::Credited {
            credited: credited_receive.clone(),
        },
        KagemushaWalletMessageV1::Credited {
            credited: credited_status.clone(),
        },
        KagemushaWalletMessageV1::Lineage {
            lineage: lineage.clone(),
        },
        KagemushaWalletMessageV1::PolicyData { data: certificates },
    ];
    // Every case is a fully valid envelope within its kind's bound.
    let lengths: Vec<usize> = messages
        .iter()
        .map(|message| {
            let frame = KagemushaWalletEnvelopeV1::new(message.clone())
                .to_canonical_bytes()
                .expect("valid envelope");
            assert_eq!(frame.len(), envelope_len(message));
            frame.len()
        })
        .collect();

    let payment_len =
        |omega: usize, sigma: usize| envelope_len(&payment_with(&payment, omega, sigma));
    let receive_len = |proof: usize| envelope_len(&credited_with(&credited_receive, proof));
    let status_len = |proof: usize| envelope_len(&credited_with(&credited_status, proof));
    let lineage_len = |omega: usize| envelope_len(&lineage_with(&lineage, omega));
    assert_eq!(payment_len(omega, sigma), lengths[3]);
    assert_eq!(receive_len(sigma_recv), lengths[4]);
    assert_eq!(status_len(omega), lengths[5]);
    assert_eq!(lineage_len(omega), lengths[6]);

    Sizes {
        offer: lengths[0],
        credential: offer
            .payer_credential
            .to_canonical_bytes()
            .expect("credential frame")
            .len(),
        session_control: lengths[1],
        request: lengths[2],
        payment: lengths[3],
        payment_overhead: lengths[3] - omega - sigma,
        largest_omega_with_sample_sigma: largest_fitting(message_max, SEARCH_LIMIT, |omega| {
            payment_len(omega, sigma)
        }),
        largest_joint_proof: largest_fitting(message_max, SEARCH_LIMIT, |joint| {
            payment_len(joint / 2, joint - joint / 2)
        }),
        credited_receive: lengths[4],
        credited_receive_overhead: lengths[4] - sigma_recv,
        largest_sigma_in_receive: largest_fitting(message_max, SEARCH_LIMIT, receive_len),
        credited_status: lengths[5],
        credited_status_overhead: lengths[5] - omega,
        credit_status: norito::encode_canonical(&status)
            .expect("credit status frame")
            .len(),
        largest_omega_in_status: largest_fitting(message_max, SEARCH_LIMIT, status_len),
        lineage: lengths[6],
        lineage_overhead: lengths[6] - omega,
        certificates: lengths[7],
    }
}

#[test]
fn kagemusha_wallet_v1_split_lineage_envelopes_fit_their_bounds() {
    let sizes = measure(&vector_world().f);
    let session_max = KAGEMUSHA_WALLET_SESSION_MAX_BYTES_V1;
    let message_max = KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1;
    println!(
        "KAGEMUSHA wallet V1 split-lineage envelopes (bytes): Offer {} / {session_max} \
         (credential frame {} / {}), SessionControl {} / {session_max}, Request {} / \
         {message_max}, Payment {} / {message_max} with σ_send {SAMPLE_SIGMA_SEND_BYTES} and \
         sample Ω proof {SAMPLE_OMEGA_PROOF_BYTES}, Credited::Receive {} / \
         {message_max} with σ_recv {SAMPLE_SIGMA_RECV_BYTES}, Credited::Status \
         {} / {message_max} with sample Ω(h) proof {SAMPLE_OMEGA_PROOF_BYTES} and 32 \
         siblings (CreditStatus frame {}), Lineage {} / {message_max}, PolicyData \
         certificates (3) {} / {message_max}",
        sizes.offer,
        sizes.credential,
        KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1,
        sizes.session_control,
        sizes.request,
        sizes.payment,
        sizes.credited_receive,
        sizes.credited_status,
        sizes.credit_status,
        sizes.lineage,
        sizes.certificates,
    );
    println!(
        "KAGEMUSHA wallet V1 fixed overheads (bytes): Payment {} + |Ω proof| + |σ_send|, \
         Credited::Receive {} + |σ_recv|, Credited::Status {} + |Ω(h) proof| (32 siblings), \
         Lineage {} + |Ω proof|; largest Ω proof in a Payment with the sample σ_send {}, \
         largest |Ω proof| + |σ_send| {}, largest σ_recv in Credited::Receive {}, \
         largest Ω(h) proof in Credited::Status {}",
        sizes.payment_overhead,
        sizes.credited_receive_overhead,
        sizes.credited_status_overhead,
        sizes.lineage_overhead,
        sizes.largest_omega_with_sample_sigma,
        sizes.largest_joint_proof,
        sizes.largest_sigma_in_receive,
        sizes.largest_omega_in_status,
    );
    for (name, len, bound) in [
        ("Offer", sizes.offer, session_max),
        (
            "Offer credential",
            sizes.credential,
            KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1,
        ),
        ("SessionControl", sizes.session_control, session_max),
        ("Request", sizes.request, message_max),
        ("Payment", sizes.payment, message_max),
        ("Credited::Receive", sizes.credited_receive, message_max),
        ("Credited::Status", sizes.credited_status, message_max),
        ("Lineage", sizes.lineage, message_max),
        ("PolicyData certificates", sizes.certificates, message_max),
    ] {
        assert!(len <= bound, "{name}: {len} > {bound}");
    }
    // A Lineage message is smaller than the Payment that carries the same Ω (§8).
    assert!(sizes.lineage < sizes.payment);
    assert!(sizes.largest_omega_with_sample_sigma >= SAMPLE_OMEGA_PROOF_BYTES);
    assert!(sizes.largest_omega_in_status >= SAMPLE_OMEGA_PROOF_BYTES);
    // F_payment and the joint R9 budget of |Ω| + |σ_send| (owner answer Q6) are pinned.
    assert_eq!(
        sizes.payment_overhead,
        KAGEMUSHA_WALLET_PAYMENT_FIXED_BYTES_V1
    );
    assert_eq!(
        sizes.largest_joint_proof,
        KAGEMUSHA_WALLET_PAYMENT_PROOF_BUDGET_V1
    );
    assert_eq!(
        sizes.largest_omega_with_sample_sigma,
        KAGEMUSHA_WALLET_PAYMENT_PROOF_BUDGET_V1 - SAMPLE_SIGMA_SEND_BYTES
    );
    // Receive is bounded by its complete carrying envelope, independently of the sample
    // proof length. The frozen key still selects one exact length within this budget.
    assert_eq!(
        sizes.credited_receive_overhead,
        KAGEMUSHA_WALLET_CREDITED_RECEIVE_FIXED_BYTES_V1
    );
    assert_eq!(
        sizes.largest_sigma_in_receive,
        KAGEMUSHA_WALLET_CREDITED_RECEIVE_PROOF_BUDGET_V1
    );
    let f = &vector_world().f;
    let credited = f.credited_receive(&f.payment(false, 32), 32);
    let receive_at_cap =
        credited_with(&credited, KAGEMUSHA_WALLET_CREDITED_RECEIVE_PROOF_BUDGET_V1);
    assert_eq!(envelope_len(&receive_at_cap), message_max);
    KagemushaWalletEnvelopeV1::new(receive_at_cap)
        .to_canonical_bytes()
        .expect("Receive at its complete envelope limit");
    let receive_over_cap = credited_with(
        &credited,
        KAGEMUSHA_WALLET_CREDITED_RECEIVE_PROOF_BUDGET_V1 + 1,
    );
    assert_eq!(envelope_len(&receive_over_cap), message_max + 1);
    assert!(
        KagemushaWalletEnvelopeV1::new(receive_over_cap)
            .to_canonical_bytes()
            .is_err()
    );
    // F_status and the Ω cap of the verifying-key allowlist are pinned: with the fixed
    // 32-sibling opening the Credited::Status bound caps Ω at 10,000 − F_status.
    assert_eq!(
        sizes.credited_status_overhead,
        KAGEMUSHA_WALLET_CREDITED_STATUS_FIXED_BYTES_V1
    );
    assert_eq!(
        sizes.largest_omega_in_status,
        KAGEMUSHA_WALLET_LINEAGE_PROOF_CAP_V1
    );
}

#[test]
fn kagemusha_wallet_v1_size_search_helpers() {
    assert_eq!(largest_fitting(10, 100, |len| len), 10);
    assert_eq!(largest_fitting(10, 5, |len| len), 5);
    assert_eq!(largest_fitting(10, 100, |len| len + 11), 0);
    assert_eq!(largest_fitting(100, 1_000, |len| 3 * len + 1), 33);
    assert_eq!(bytes_of(5), vec![0xa5; 5]);

    let f = &vector_world().f;
    let payment = f.payment(false, 32);
    let message = KagemushaWalletMessageV1::Payment {
        payment: payment.clone(),
    };
    let frame = KagemushaWalletEnvelopeV1::new(message.clone())
        .to_canonical_bytes()
        .expect("frame");
    assert_eq!(envelope_len(&message), frame.len());
    let KagemushaWalletMessageV1::Payment { payment: resized } = payment_with(&payment, 50, 40)
    else {
        panic!("payment");
    };
    assert_eq!(resized.send.step_proof.bytes.len(), 40);
    assert_eq!(resized.send.lineage.lineage().expect("Ω").proof.len(), 50);

    let credited = f.credited_status(&payment, 32, 2);
    let KagemushaWalletMessageV1::Credited { credited: resized } = credited_with(&credited, 40)
    else {
        panic!("credited");
    };
    let KagemushaWalletCreditedEvidenceV1::Status { status } = resized.evidence else {
        panic!("status");
    };
    assert_eq!(
        (status.lineage.proof.len(), status.opening.siblings.len()),
        (40, 32 * 32)
    );
    status.opening.validate().expect("opening");
    let one_byte_more = envelope_len(&credited_with(&credited, 33));
    assert_eq!(
        one_byte_more,
        envelope_len(&credited_with(&credited, 32)) + 1
    );
    let lineage = f.lineage_message(&payment);
    assert_eq!(
        envelope_len(&lineage_with(&lineage, 49)),
        envelope_len(&lineage_with(&lineage, 48)) + 1
    );
}
