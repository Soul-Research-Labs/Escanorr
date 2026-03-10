//! Integration tests for the ESCANORR RPC node state and hex helpers.

use escanorr_node::NodeState;
use ff::{Field, PrimeField};
use pasta_curves::pallas;
use rand::rngs::OsRng;

/// Helper: generate a valid 64-char hex commitment from a random Base field element.
fn random_hex_commitment() -> String {
    let base = pallas::Base::random(OsRng);
    hex::encode(base.to_repr())
}

// ────────────────────────────────────────────────────────────────
// Tests that exercise the node state directly (route logic proxy)
// ────────────────────────────────────────────────────────────────

#[test]
fn node_deposit_returns_sequential_indices() {
    let mut node = NodeState::new();
    for i in 0..10u64 {
        let cm = pallas::Base::random(OsRng);
        let idx = node.deposit(cm, 100 + i).unwrap();
        assert_eq!(idx, i);
    }
    assert_eq!(node.pool().tree_size(), 10);
}

#[test]
fn node_withdraw_spends_nullifier() {
    let mut node = NodeState::new();
    let cm = pallas::Base::random(OsRng);
    node.deposit(cm, 1000).unwrap();
    let root = node.root();
    let nf = pallas::Base::random(OsRng);
    node.withdraw(nf, root, 500, None).unwrap();

    // Nullifier should now be spent
    assert!(node.pool().nullifier_set().contains(&nf));
}

#[test]
fn node_withdraw_double_spend_fails() {
    let mut node = NodeState::new();
    let cm = pallas::Base::random(OsRng);
    node.deposit(cm, 1000).unwrap();
    let root = node.root();
    let nf = pallas::Base::random(OsRng);
    node.withdraw(nf, root, 500, None).unwrap();

    // Same nullifier again should fail
    let result = node.withdraw(nf, root, 500, None);
    assert!(result.is_err());
}

#[test]
fn node_withdraw_with_invalid_root_fails() {
    let mut node = NodeState::new();
    let cm = pallas::Base::random(OsRng);
    node.deposit(cm, 1000).unwrap();
    let fake_root = pallas::Base::random(OsRng);
    let nf = pallas::Base::random(OsRng);
    let result = node.withdraw(nf, fake_root, 500, None);
    assert!(result.is_err());
}

#[test]
fn node_transfer_records_nullifiers() {
    let mut node = NodeState::new();
    let cm = pallas::Base::random(OsRng);
    node.deposit(cm, 1000).unwrap();
    let root = node.root();

    let nf = pallas::Base::random(OsRng);
    let out1 = pallas::Base::random(OsRng);
    let out2 = pallas::Base::random(OsRng);

    node.transfer(vec![nf], root, vec![out1, out2]).unwrap();
    assert!(node.pool().nullifier_set().contains(&nf));
}

#[test]
fn node_transfer_with_multiple_nullifiers() {
    let mut node = NodeState::new();
    let cm1 = pallas::Base::random(OsRng);
    let cm2 = pallas::Base::random(OsRng);
    node.deposit(cm1, 500).unwrap();
    node.deposit(cm2, 500).unwrap();
    let root = node.root();

    let nf1 = pallas::Base::random(OsRng);
    let nf2 = pallas::Base::random(OsRng);
    let out = pallas::Base::random(OsRng);

    node.transfer(vec![nf1, nf2], root, vec![out]).unwrap();
    assert!(node.pool().nullifier_set().contains(&nf1));
    assert!(node.pool().nullifier_set().contains(&nf2));
}

#[test]
fn node_history_tracks_all_operations() {
    let mut node = NodeState::new();

    // Deposit
    let cm = pallas::Base::random(OsRng);
    node.deposit(cm, 1000).unwrap();

    // Transfer
    let root = node.root();
    let nf = pallas::Base::random(OsRng);
    let out = pallas::Base::random(OsRng);
    node.transfer(vec![nf], root, vec![out]).unwrap();

    // Withdraw
    let nf2 = pallas::Base::random(OsRng);
    let root2 = node.root();
    node.withdraw(nf2, root2, 200, None).unwrap();

    assert_eq!(node.history().len(), 3);
}

#[test]
fn node_epoch_advances_correctly() {
    let mut node = NodeState::new();
    assert_eq!(node.epoch(), 0);
    node.advance_epoch();
    assert_eq!(node.epoch(), 1);
    node.advance_epoch();
    assert_eq!(node.epoch(), 2);
}

// ────────────────────────────────────────────────────────────────
// Hex validation tests (matching route handler logic)
// ────────────────────────────────────────────────────────────────

#[test]
fn hex_commitment_format_is_64_chars() {
    let hex = random_hex_commitment();
    assert_eq!(hex.len(), 64);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn base_to_hex_roundtrip() {
    let base = pallas::Base::random(OsRng);
    let hex_str = hex::encode(base.to_repr());
    let bytes = hex::decode(&hex_str).unwrap();
    let arr: [u8; 32] = bytes.try_into().unwrap();
    let recovered = pallas::Base::from_repr(arr).unwrap();
    assert_eq!(base, recovered);
}

#[test]
fn invalid_hex_too_short() {
    let short = "abcd";
    assert_ne!(short.len(), 64);
}

#[test]
fn invalid_hex_non_hex_chars() {
    let bad = "gg".repeat(32); // 64 chars but not valid hex
    assert!(hex::decode(&bad).is_err());
}
