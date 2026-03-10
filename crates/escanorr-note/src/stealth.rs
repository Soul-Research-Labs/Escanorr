//! Stealth addresses — ECDH-based one-time addresses for receiver privacy.
//!
//! Protocol:
//! 1. Recipient publishes stealth meta-address: `(spend_pk, view_pk)`.
//! 2. Sender generates ephemeral keypair `(r, R = r·G)`.
//! 3. Sender computes shared secret `S = r · view_pk`.
//! 4. Sender derives one-time owner: `owner = spend_pk + Poseidon(S_x) · G`.
//! 5. Sender includes `R` (ephemeral pubkey) in the encrypted note.
//! 6. Recipient scans: `S' = view_sk · R`, derives `owner'`, checks match.
//! 7. If match: `stealth_sk = spend_sk + Poseidon(S'_x)`.

use ff::{Field, PrimeField};
use group::Group;
use pasta_curves::{arithmetic::CurveAffine, pallas};
use rand::rngs::OsRng;

use escanorr_primitives::poseidon::poseidon_hash_single;

/// Stealth meta-address published by the recipient.
#[derive(Clone, Debug)]
pub struct StealthMeta {
    /// Recipient's spending public key.
    pub spend_pk: pallas::Point,
    /// Recipient's viewing public key.
    pub view_pk: pallas::Point,
}

/// Result of stealth address generation by the sender.
#[derive(Clone, Debug)]
pub struct StealthAddress {
    /// The one-time owner field to use in the note.
    pub owner: pallas::Base,
    /// Ephemeral public key R (included in note payload for recipient scanning).
    pub ephemeral_pk: pallas::Point,
}

/// Generate a stealth address for a recipient.
///
/// Called by the sender. Returns the one-time owner and ephemeral public key.
pub fn stealth_send(meta: &StealthMeta) -> StealthAddress {
    // 1. Generate ephemeral keypair
    let r = pallas::Scalar::random(OsRng);
    let big_r = pallas::Point::generator() * r;

    // 2. Compute shared secret S = r * view_pk
    let shared_point = meta.view_pk * r;
    let shared_x = point_to_x(&shared_point);

    // 3. Derive one-time key offset: h = Poseidon(S_x)
    let h = poseidon_hash_single(shared_x);

    // 4. One-time address: P = spend_pk + h·G
    let h_scalar = base_to_scalar(h);
    let one_time_point = meta.spend_pk + pallas::Point::generator() * h_scalar;
    let owner = point_to_x(&one_time_point);

    StealthAddress {
        owner,
        ephemeral_pk: big_r,
    }
}

/// Scan an ephemeral public key to check if a note is addressed to us.
///
/// Called by the recipient. Returns `Some(stealth_sk)` if the note is ours.
pub fn stealth_receive(
    spend_sk: pallas::Scalar,
    view_sk: pallas::Scalar,
    ephemeral_pk: pallas::Point,
    note_owner: pallas::Base,
) -> Option<pallas::Scalar> {
    // 1. Compute shared secret S' = view_sk * R
    let shared_point = ephemeral_pk * view_sk;
    let shared_x = point_to_x(&shared_point);

    // 2. Derive offset: h' = Poseidon(S'_x)
    let h = poseidon_hash_single(shared_x);

    // 3. Compute expected one-time point: P' = spend_pk + h'·G
    let spend_pk = pallas::Point::generator() * spend_sk;
    let h_scalar = base_to_scalar(h);
    let expected_point = spend_pk + pallas::Point::generator() * h_scalar;
    let expected_owner = point_to_x(&expected_point);

    // 4. Check if it matches
    if expected_owner == note_owner {
        // 5. Derive stealth spending key: stealth_sk = spend_sk + h'
        Some(spend_sk + h_scalar)
    } else {
        None
    }
}

/// Extract the x-coordinate of a Pallas point as a base field element.
fn point_to_x(point: &pallas::Point) -> pallas::Base {
    let affine: pallas::Affine = (*point).into();
    let coords = affine.coordinates();
    if bool::from(coords.is_some()) {
        *coords.unwrap().x()
    } else {
        pallas::Base::zero()
    }
}

/// Convert a base field element to a scalar (for EC multiplication).
/// This reinterprets the byte representation.
fn base_to_scalar(base: pallas::Base) -> pallas::Scalar {
    let bytes = base.to_repr();
    // Clear top bits to fit in scalar field
    let mut scalar_bytes = bytes;
    scalar_bytes[31] &= 0x0f;
    pallas::Scalar::from_repr(scalar_bytes).unwrap_or(pallas::Scalar::zero())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stealth_send_receive_roundtrip() {
        // Recipient generates keys
        let spend_sk = pallas::Scalar::random(OsRng);
        let view_sk = pallas::Scalar::random(OsRng);
        let meta = StealthMeta {
            spend_pk: pallas::Point::generator() * spend_sk,
            view_pk: pallas::Point::generator() * view_sk,
        };

        // Sender generates stealth address
        let stealth = stealth_send(&meta);

        // Recipient scans and detects the note
        let result = stealth_receive(spend_sk, view_sk, stealth.ephemeral_pk, stealth.owner);
        assert!(result.is_some(), "recipient should detect their stealth note");
    }

    #[test]
    fn stealth_wrong_recipient_fails() {
        let spend_sk = pallas::Scalar::random(OsRng);
        let view_sk = pallas::Scalar::random(OsRng);
        let meta = StealthMeta {
            spend_pk: pallas::Point::generator() * spend_sk,
            view_pk: pallas::Point::generator() * view_sk,
        };

        let stealth = stealth_send(&meta);

        // Wrong recipient tries to scan
        let wrong_spend = pallas::Scalar::random(OsRng);
        let wrong_view = pallas::Scalar::random(OsRng);
        let result = stealth_receive(wrong_spend, wrong_view, stealth.ephemeral_pk, stealth.owner);
        assert!(result.is_none(), "wrong recipient should not detect the note");
    }

    #[test]
    fn stealth_addresses_are_unique() {
        let spend_sk = pallas::Scalar::random(OsRng);
        let view_sk = pallas::Scalar::random(OsRng);
        let meta = StealthMeta {
            spend_pk: pallas::Point::generator() * spend_sk,
            view_pk: pallas::Point::generator() * view_sk,
        };

        let s1 = stealth_send(&meta);
        let s2 = stealth_send(&meta);
        assert_ne!(
            s1.owner, s2.owner,
            "each stealth address should be unique (different ephemeral keys)"
        );
    }
}
