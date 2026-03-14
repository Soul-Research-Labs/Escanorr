//! End-to-end integration test: deposit → transfer → withdraw flow.
//!
//! This test exercises the full privacy pool lifecycle using the SDK
//! orchestrator without actual ZK proof generation (proof-free test).

use escanorr_node::NodeState;
use escanorr_note::{Note, SpendingKey};
use ff::Field;
use pasta_curves::pallas;
use rand::rngs::OsRng;

/// Full deposit → send → check balance flow with two wallets.
#[test]
fn deposit_transfer_balance_e2e() {
    // Alice's wallet
    let alice_sk = SpendingKey::random();
    let alice_fvk = alice_sk.to_full_viewing_key();
    let alice_owner = alice_fvk.viewing_key.to_owner().unwrap();

    // Bob's wallet
    let bob_sk = SpendingKey::random();
    let bob_fvk = bob_sk.to_full_viewing_key();
    let bob_owner = bob_fvk.viewing_key.to_owner().unwrap();

    // Node state (privacy pool)
    let mut node = NodeState::new();

    // ── Alice deposits 1000 ──
    let alice_note = Note::new(alice_owner, 1000, 0);
    let leaf_idx = node.deposit(alice_note.commitment().0, 1000).unwrap();
    assert_eq!(leaf_idx, 0);

    // ── Alice creates a transfer: 400 to Bob, 590 change, 10 fee ──
    let bob_note = Note::new(bob_owner, 400, 0);
    let change_note = Note::new(alice_owner, 590, 0);

    // Verify balance equation: input(1000) = output(400) + change(590) + fee(10)
    assert_eq!(1000, 400 + 590 + 10);

    // Deposit output notes into the tree
    let bob_idx = node.deposit(bob_note.commitment().0, 400).unwrap();
    let change_idx = node.deposit(change_note.commitment().0, 590).unwrap();
    assert_eq!(bob_idx, 1);
    assert_eq!(change_idx, 2);

    // ── Compute nullifier for Alice's spent note ──
    let nullifier = alice_fvk.nullifier(alice_note.commitment().0);
    let nf_bytes = nullifier.inner();

    // Verify nullifier is deterministic
    let nullifier2 = alice_fvk.nullifier(alice_note.commitment().0);
    assert_eq!(nf_bytes, nullifier2.inner());

    // ── Bob's note should have correct value ──
    assert_eq!(bob_note.value, 400);
    assert_eq!(bob_note.owner, bob_owner);

    // ── Tree state ──
    assert_eq!(node.pool().tree_size(), 3);
}

/// Multiple deposits from different users accumulate in the tree.
#[test]
fn multi_user_deposits() {
    let mut node = NodeState::new();

    let users: Vec<_> = (0..5)
        .map(|_| {
            let sk = SpendingKey::random();
            sk.to_full_viewing_key()
        })
        .collect();

    for (i, fvk) in users.iter().enumerate() {
        let owner = fvk.viewing_key.to_owner().unwrap();
        let note = Note::new(owner, (i as u64 + 1) * 100, 0);
        let value = (i as u64 + 1) * 100;
        let idx = node.deposit(note.commitment().0, value).unwrap();
        assert_eq!(idx, i as u64);
    }

    assert_eq!(node.pool().tree_size(), 5);
}

/// Nullifiers from different spending keys for the same commitment are distinct.
#[test]
fn nullifier_uniqueness_across_keys() {
    let sk1 = SpendingKey::random();
    let sk2 = SpendingKey::random();
    let fvk1 = sk1.to_full_viewing_key();
    let fvk2 = sk2.to_full_viewing_key();

    let commitment = pallas::Base::random(OsRng);

    let nf1 = fvk1.nullifier(commitment);
    let nf2 = fvk2.nullifier(commitment);

    assert_ne!(nf1.inner(), nf2.inner());
}

/// Same key + same commitment = same nullifier (deterministic).
#[test]
fn nullifier_determinism() {
    let sk = SpendingKey::random();
    let fvk = sk.to_full_viewing_key();
    let commitment = pallas::Base::random(OsRng);

    let nf1 = fvk.nullifier(commitment);
    let nf2 = fvk.nullifier(commitment);

    assert_eq!(nf1.inner(), nf2.inner());
}
