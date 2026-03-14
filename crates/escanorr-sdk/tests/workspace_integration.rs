//! Workspace-level integration tests for cross-crate lifecycle flows.
//!
//! Covers: node storage persistence across restarts, batch accumulator → node
//! drain lifecycle, wallet mnemonic recovery, deposit → double-spend prevention,
//! Merkle auth path stability, and coin selection with spent notes.

use escanorr_client::Wallet;
use escanorr_node::{BatchAccumulator, BatchConfig, NodeState, NodeStorage, PendingTx};
use escanorr_note::{Note, SpendingKey};
use escanorr_primitives::{compute_nullifier_v1, ProofEnvelope};
use escanorr_sdk::Escanorr;
use escanorr_tree::IncrementalMerkleTree;
use ff::Field;
use pasta_curves::pallas;
use rand::rngs::OsRng;
use std::time::Duration;

// ── Storage persistence across node restart ────────────────────────────

#[test]
fn node_state_survives_restart_via_storage() {
    let dir = tempfile::tempdir().unwrap();

    let root;
    let epoch;
    let history_len;

    {
        let storage = NodeStorage::open(dir.path()).unwrap();
        let mut state = NodeState::new();
        let cm = pallas::Base::random(OsRng);
        state.deposit(cm, 500).unwrap();
        state.advance_epoch();
        state.advance_epoch();

        root = state.root();
        epoch = state.epoch();
        history_len = state.history().len();

        storage.save(&state).unwrap();
    }

    {
        let storage = NodeStorage::open(dir.path()).unwrap();
        let loaded = storage.load().unwrap().expect("state should exist");
        assert_eq!(loaded.root(), root);
        assert_eq!(loaded.epoch(), epoch);
        assert_eq!(loaded.history().len(), history_len);
    }
}

// ── Batch accumulator drains into node state ───────────────────────────

#[test]
fn batch_drain_applies_deposits_to_node() {
    let config = BatchConfig {
        max_batch_size: 3,
        max_batch_delay: Duration::from_secs(60),
    };
    let mut batch = BatchAccumulator::new(config);
    let mut node = NodeState::new();

    let commitments: Vec<pallas::Base> = (0..3)
        .map(|_| pallas::Base::random(OsRng))
        .collect();

    for cm in &commitments {
        batch.push(PendingTx::Deposit {
            commitment: *cm,
            value: 100,
        });
    }

    assert!(batch.is_ready());
    let pending = batch.drain();
    assert_eq!(pending.len(), 3);

    for tx in pending {
        match tx {
            PendingTx::Deposit { commitment, value } => {
                node.deposit(commitment, value).unwrap();
            }
            _ => unreachable!(),
        }
    }

    assert_eq!(node.pool().tree_size(), 3);
    assert_eq!(batch.len(), 0);
}

// ── Wallet mnemonic → deposit → persist → reload ──────────────────────

#[test]
fn mnemonic_wallet_deposit_persist_reload() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.enc");
    let password = b"test-password-123";

    let owner;
    {
        let mut wallet = Wallet::from_mnemonic(phrase).unwrap();
        owner = wallet.owner().unwrap();
        let note = Note::new(owner, 1000, 0);
        wallet.add_note(note, 0);
        wallet.save(&path, password).unwrap();
    }

    {
        let loaded = Wallet::load(&path, password).unwrap();
        assert_eq!(loaded.owner().unwrap(), owner);
        assert_eq!(loaded.balance(), 1000);
    }

    {
        let wallet2 = Wallet::from_mnemonic(phrase).unwrap();
        assert_eq!(wallet2.owner().unwrap(), owner);
    }
}

// ── Double-spend prevention across deposit-withdraw flows ──────────────

#[test]
fn double_spend_prevention_end_to_end() {
    let mut node = NodeState::new();

    let sk = SpendingKey::random();
    let owner = sk.to_full_viewing_key().viewing_key.to_owner();
    let note = Note::new(owner, 1000, 0);
    let cm = note.commitment();
    node.deposit(cm.0, 1000).unwrap();

    let root = node.root();
    let nf = compute_nullifier_v1(sk.to_base(), cm.0);

    node.withdraw(nf.inner(), root, 500, None).unwrap();

    let result = node.withdraw(nf.inner(), root, 500, None);
    assert!(result.is_err(), "double-spend should be rejected");
}

// ── Merkle auth path valid after subsequent inserts ────────────────────

#[test]
fn auth_path_valid_after_subsequent_inserts() {
    let mut tree = IncrementalMerkleTree::new();
    let leaf0 = pallas::Base::from(42u64);
    tree.insert(leaf0);

    for i in 1..=50 {
        tree.insert(pallas::Base::from(i + 100));
    }

    let (siblings, positions) = tree.auth_path(0).expect("path exists");
    assert!(IncrementalMerkleTree::verify_proof(
        tree.root(),
        leaf0,
        &siblings,
        &positions,
    ));
}

// ── Proof envelope seal/open roundtrip ─────────────────────────────────

#[test]
fn proof_envelope_roundtrip_various_sizes() {
    for size in [0, 1, 256, 1024, 16000] {
        let data = vec![0xAB; size];
        let envelope = ProofEnvelope::seal(&data).unwrap();
        assert_eq!(envelope.as_bytes().len(), 32768);
        let recovered = envelope.open().unwrap();
        assert_eq!(recovered, data);
    }
}

// ── SDK deposit reflects in node tree ──────────────────────────────────

#[test]
fn sdk_deposit_updates_node_tree() {
    let mut esc = Escanorr::new();

    for i in 1..=10 {
        esc.deposit(i * 100).unwrap();
    }

    assert_eq!(esc.node().pool().tree_size(), 10);
    assert_eq!(esc.balance(), 5500);
}

// ── Node history bounded capacity ──────────────────────────────────────

#[test]
fn node_history_tracks_correct_kinds() {
    let mut node = NodeState::new();

    for i in 0..50 {
        let cm = pallas::Base::from(i + 1);
        node.deposit(cm, 10).unwrap();
    }

    assert_eq!(node.history().len(), 50);

    for record in node.history() {
        match &record.kind {
            escanorr_node::TxKind::Deposit { value } => assert_eq!(*value, 10),
            _ => panic!("expected deposit"),
        }
    }
}

// ── Spent notes excluded from coin selection ───────────────────────────

#[test]
fn spent_notes_excluded_from_coin_selection() {
    let mut esc = Escanorr::new();
    esc.deposit(100).unwrap();
    esc.deposit(200).unwrap();
    esc.deposit(300).unwrap();

    assert_eq!(esc.balance(), 600);

    esc.wallet_mut().mark_spent(1);
    assert_eq!(esc.balance(), 400);

    let (selected, total) = esc.wallet().select_coins(350).unwrap();
    assert!(total >= 350);
    assert!(selected.iter().all(|n| n.tree_index != 1));
}

// ── Mixed batch: deposits + withdrawals ────────────────────────────────

#[test]
fn mixed_batch_deposit_and_withdraw() {
    let config = BatchConfig {
        max_batch_size: 4,
        max_batch_delay: Duration::from_secs(60),
    };
    let mut batch = BatchAccumulator::new(config);
    let mut node = NodeState::new();

    // Pre-seed the node so we have a valid root for withdrawals
    let cm = pallas::Base::random(OsRng);
    node.deposit(cm, 1000).unwrap();
    let root = node.root();

    // Queue mixed transactions
    batch.push(PendingTx::Deposit {
        commitment: pallas::Base::random(OsRng),
        value: 200,
    });
    batch.push(PendingTx::Deposit {
        commitment: pallas::Base::random(OsRng),
        value: 300,
    });
    batch.push(PendingTx::Withdraw {
        nullifier: pallas::Base::random(OsRng),
        merkle_root: root,
        exit_value: 100,
        change_commitment: None,
    });
    batch.push(PendingTx::Deposit {
        commitment: pallas::Base::random(OsRng),
        value: 150,
    });

    assert!(batch.is_ready());
    let pending = batch.drain();

    let mut deposits = 0;
    let mut withdrawals = 0;
    for tx in pending {
        match tx {
            PendingTx::Deposit { commitment, value } => {
                node.deposit(commitment, value).unwrap();
                deposits += 1;
            }
            PendingTx::Withdraw {
                nullifier,
                merkle_root,
                exit_value,
                change_commitment,
            } => {
                node.withdraw(nullifier, merkle_root, exit_value, change_commitment)
                    .unwrap();
                withdrawals += 1;
            }
            _ => {}
        }
    }

    assert_eq!(deposits, 3);
    assert_eq!(withdrawals, 1);
    assert_eq!(node.pool().tree_size(), 4); // 1 pre-seed + 3 new
}
