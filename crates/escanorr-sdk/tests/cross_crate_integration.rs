//! Cross-crate integration tests: wallet, pool, tree, nullifiers, persistence.
//!
//! These tests validate the full pipeline across crates without
//! invoking the expensive Halo2 prover.

use escanorr_client::Wallet;
use escanorr_node::NodeState;
use escanorr_note::{Note, SpendingKey};
use escanorr_primitives::compute_nullifier_v1;
use escanorr_sdk::Escanorr;
use escanorr_tree::IncrementalMerkleTree;
use ff::Field;
use pasta_curves::pallas;
use rand::rngs::OsRng;

// ── SDK deposit ↔ balance consistency ──────────────────────────────────

#[test]
fn sdk_deposit_updates_balance_and_root() {
    let mut esc = Escanorr::new();
    assert_eq!(esc.balance(), 0);
    let root_empty = esc.root();

    esc.deposit(1000).unwrap();
    assert_eq!(esc.balance(), 1000);
    assert_ne!(esc.root(), root_empty);

    esc.deposit(500).unwrap();
    assert_eq!(esc.balance(), 1500);
}

// ── Coin selection across multiple deposits ────────────────────────────

#[test]
fn coin_selection_greedy_across_deposits() {
    let mut esc = Escanorr::new();
    esc.deposit(100).unwrap();
    esc.deposit(200).unwrap();
    esc.deposit(50).unwrap();

    let (selected, total) = esc.wallet().select_coins(250).unwrap();
    assert!(total >= 250);
    assert!(!selected.is_empty());
}

#[test]
fn coin_selection_rejects_insufficient() {
    let mut esc = Escanorr::new();
    esc.deposit(100).unwrap();
    assert!(esc.wallet().select_coins(200).is_err());
}

// ── Nullifier uniqueness ───────────────────────────────────────────────

#[test]
fn nullifiers_differ_for_different_keys_and_commitments() {
    let sk1 = SpendingKey::random();
    let sk2 = SpendingKey::random();
    let cm = pallas::Base::from(42u64);

    let nf_a = compute_nullifier_v1(sk1.to_base(), cm);
    let nf_b = compute_nullifier_v1(sk2.to_base(), cm);
    assert_ne!(nf_a, nf_b);

    let cm2 = pallas::Base::from(43u64);
    let nf_c = compute_nullifier_v1(sk1.to_base(), cm2);
    assert_ne!(nf_a, nf_c);
}

// ── Note commitment determinism ────────────────────────────────────────

#[test]
fn note_commitment_deterministic_and_value_sensitive() {
    let owner = pallas::Base::from(1u64);
    let blinding = pallas::Base::from(99u64);

    let note_a = Note::with_blinding(owner, 500, 0, blinding);
    let note_b = Note::with_blinding(owner, 500, 0, blinding);
    assert_eq!(note_a.commitment(), note_b.commitment());

    let note_c = Note::with_blinding(owner, 501, 0, blinding);
    assert_ne!(note_a.commitment(), note_c.commitment());
}

// ── Merkle auth path verification after multi-insert ───────────────────

#[test]
fn merkle_auth_paths_verify_for_all_leaves() {
    let mut tree = IncrementalMerkleTree::new();
    let leaves: Vec<pallas::Base> = (0..10)
        .map(|i| pallas::Base::from(i + 1))
        .collect();

    for leaf in &leaves {
        tree.insert(*leaf);
    }

    for i in 0..10u64 {
        let (siblings, positions) = tree.auth_path(i).expect("auth path exists");
        assert!(IncrementalMerkleTree::verify_proof(
            tree.root(),
            leaves[i as usize],
            &siblings,
            &positions,
        ));
    }
}

// ── Node double-spend prevention ───────────────────────────────────────

#[test]
fn node_rejects_double_spend_nullifier() {
    let mut node = NodeState::new();
    let cm = pallas::Base::random(OsRng);
    node.deposit(cm, 1000).unwrap();
    let root = node.root();

    let nf = pallas::Base::random(OsRng);
    let out = pallas::Base::random(OsRng);

    node.transfer(vec![nf], root, vec![out]).unwrap();
    assert!(node.transfer(vec![nf], root, vec![pallas::Base::random(OsRng)]).is_err());
}

// ── Encrypted wallet persistence roundtrip ─────────────────────────────

#[test]
fn wallet_encrypted_roundtrip_preserves_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.enc");
    let password = b"integration-test-pw";

    let mut wallet = Wallet::random();
    let owner = wallet.owner().unwrap();
    let note = Note {
        owner,
        value: 777,
        asset_id: 0,
        blinding: pallas::Base::random(OsRng),
    };
    wallet.add_note(note, 0);
    wallet.save(&path, password).unwrap();

    let loaded = Wallet::load(&path, password).unwrap();
    assert_eq!(loaded.owner().unwrap(), owner);
    assert_eq!(loaded.balance(), 777);
    assert_eq!(loaded.unspent_notes().len(), 1);
}

#[test]
fn wallet_load_rejects_wrong_password() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.enc");

    let wallet = Wallet::random();
    wallet.save(&path, b"correct").unwrap();
    assert!(Wallet::load(&path, b"wrong").is_err());
}

// ── Mnemonic determinism ───────────────────────────────────────────────

#[test]
fn wallet_from_mnemonic_deterministic() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let w1 = Wallet::from_mnemonic(phrase).unwrap();
    let w2 = Wallet::from_mnemonic(phrase).unwrap();
    assert_eq!(w1.owner().unwrap(), w2.owner().unwrap());
}

// ── Mark-spent reflects in balance ─────────────────────────────────────

#[test]
fn mark_spent_reduces_balance() {
    let mut esc = Escanorr::new();
    esc.deposit(1000).unwrap();
    esc.deposit(500).unwrap();
    assert_eq!(esc.balance(), 1500);

    esc.wallet_mut().mark_spent(0);
    assert_eq!(esc.balance(), 500);
}

// ── Merkle tree root determinism ───────────────────────────────────────

#[test]
fn merkle_tree_root_is_deterministic() {
    let leaf = pallas::Base::from(42u64);
    let mut t1 = IncrementalMerkleTree::new();
    let mut t2 = IncrementalMerkleTree::new();
    t1.insert(leaf);
    t2.insert(leaf);
    assert_eq!(t1.root(), t2.root());
}
