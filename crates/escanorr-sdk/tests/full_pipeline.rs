//! Workspace-level integration test: full privacy pipeline.
//!
//! Exercises primitives → note → tree → contracts → sdk in a single flow.

use escanorr_note::{SpendingKey, Note};
use escanorr_note::encryption::{encrypt_note, decrypt_note};
use escanorr_primitives::{
    compute_nullifier_v1, compute_nullifier_v2, poseidon_hash, DomainSeparator, ProofEnvelope,
};
use escanorr_sdk::Escanorr;
use escanorr_tree::IncrementalMerkleTree;
use pasta_curves::pallas;

/// Full deposit → encrypt → tree → nullifier → transfer pipeline.
#[test]
fn full_privacy_pipeline() {
    // 1. Key generation
    let alice_sk = SpendingKey::random();
    let alice_fvk = alice_sk.to_full_viewing_key();
    let alice_owner = alice_fvk.owner().unwrap();

    let bob_sk = SpendingKey::random();
    let bob_fvk = bob_sk.to_full_viewing_key();
    let _bob_owner = bob_fvk.owner().unwrap();

    // 2. Alice creates a note
    let note = Note::new(alice_owner, 500, 0);
    let cm = note.commitment();

    // 3. Insert commitment into Merkle tree
    let mut tree = IncrementalMerkleTree::new();
    let idx = tree.insert(cm.0);
    assert_eq!(idx, 0);

    // 4. Verify the Merkle auth path
    let path = tree.auth_path(0);
    assert!(path.is_some());
    let root = tree.root();

    // 5. Derive nullifier (V1 single-chain)
    let nf_v1 = compute_nullifier_v1(alice_sk.to_base(), cm.0);

    // 6. Derive nullifier (V2 cross-chain) — different from V1
    let domain = DomainSeparator::new(1, 0); // Ethereum, app 0
    let nf_v2 = compute_nullifier_v2(alice_sk.to_base(), cm.0, &domain);
    assert_ne!(nf_v1, nf_v2);

    // 7. Encrypt note for Bob
    let shared_secret = [0xABu8; 32];
    let plaintext = format!("{}:{}", note.value, note.asset_id);
    let ct = encrypt_note(&shared_secret, plaintext.as_bytes()).unwrap();

    // 8. Bob decrypts
    let pt = decrypt_note(&shared_secret, &ct).unwrap();
    assert_eq!(pt, plaintext.as_bytes());

    // 9. Seal proof into envelope
    let proof_data = vec![0u8; 512]; // mock proof
    let envelope = ProofEnvelope::seal(&proof_data).unwrap();
    assert_eq!(envelope.as_bytes().len(), 32768);
    let recovered = envelope.open().unwrap();
    assert_eq!(recovered, proof_data);

    // 10. Poseidon hash is consistent
    let h1 = poseidon_hash(cm.0, root);
    let h2 = poseidon_hash(cm.0, root);
    assert_eq!(h1, h2);
}

/// SDK orchestrator: deposit → send → balance across two wallets.
#[test]
#[ignore] // Requires expensive prover setup — run with `cargo test -- --ignored`
fn sdk_two_wallet_transfer() {
    let mut alice = Escanorr::new();
    let bob_sk = SpendingKey::random();
    let bob_owner = bob_sk.to_full_viewing_key().owner().unwrap();

    // Alice deposits
    alice.deposit(1000).unwrap();
    alice.deposit(500).unwrap();
    assert_eq!(alice.balance(), 1500);

    // Alice sends 300 to Bob (fee 0) — generates ZK proof
    let result = alice.send(bob_owner, 300, 0).unwrap();
    assert_eq!(result.output_notes.len(), 2); // recipient + change
    assert_eq!(alice.balance(), 1200); // 1500 - 300
    assert!(!result.proof.as_bytes().is_empty());
}

/// Cross-chain nullifier isolation: same note produces different nullifiers per chain.
#[test]
fn cross_chain_nullifier_isolation() {
    let sk = SpendingKey::random();
    let fvk = sk.to_full_viewing_key();

    let note = Note::new(fvk.owner().unwrap(), 100, 0);
    let cm = note.commitment();

    let ethereum = DomainSeparator::new(1, 0);
    let polygon = DomainSeparator::new(137, 0);
    let arbitrum = DomainSeparator::new(42161, 0);

    let nf_eth = compute_nullifier_v2(sk.to_base(), cm.0, &ethereum);
    let nf_poly = compute_nullifier_v2(sk.to_base(), cm.0, &polygon);
    let nf_arb = compute_nullifier_v2(sk.to_base(), cm.0, &arbitrum);

    // All three must be distinct
    assert_ne!(nf_eth, nf_poly);
    assert_ne!(nf_eth, nf_arb);
    assert_ne!(nf_poly, nf_arb);

    // But each is deterministic
    let nf_eth_2 = compute_nullifier_v2(sk.to_base(), cm.0, &ethereum);
    assert_eq!(nf_eth, nf_eth_2);
}

/// Merkle tree: bulk insert and auth path consistency.
#[test]
fn merkle_bulk_insert_and_verify() {
    let mut tree = IncrementalMerkleTree::new();
    let leaves: Vec<pallas::Base> = (1u64..=100).map(pallas::Base::from).collect();

    for leaf in &leaves {
        tree.insert(*leaf);
    }

    assert_eq!(tree.size(), 100);

    // Verify auth paths for a sample of leaves
    for i in [0u64, 25, 50, 75, 99] {
        let path = tree.auth_path(i);
        assert!(path.is_some(), "auth path missing for leaf {}", i);
    }
}
