//! High-level orchestrator for the ESCANORR privacy coprocessor.
//!
//! Provides `deposit`, `send`, `withdraw`, and `bridge` operations,
//! each generating Halo2 IPA proofs via the prover crate.

use escanorr_circuits::{TransferCircuit, WithdrawCircuit, BridgeCircuit};
use escanorr_client::{Wallet, WalletError};
use escanorr_node::NodeState;
use escanorr_note::Note;
use escanorr_primitives::{Base, ProofEnvelope, compute_nullifier_v1};
use escanorr_prover::{ProverParams, prove_transfer, prove_withdraw, prove_bridge};
use escanorr_tree::TREE_DEPTH;
use ff::Field;
use pasta_curves::pallas;
use rand::rngs::OsRng;
use thiserror::Error;

/// SDK errors.
#[derive(Debug, Error)]
pub enum SdkError {
    #[error("wallet error: {0}")]
    Wallet(#[from] WalletError),
    #[error("pool error: {0}")]
    Pool(#[from] escanorr_contracts::PoolError),
    #[error("no wallet loaded")]
    NoWallet,
    #[error("proof generation failed: {0}")]
    Proof(String),
    #[error("missing Merkle auth path for index {0}")]
    MissingAuthPath(u64),
    #[error("too many input notes for circuit (max 2, got {0})")]
    TooManyInputs(usize),
    #[error("no single note covers the required amount; consolidate first")]
    NeedConsolidation,
}

/// Result of a private transfer.
pub struct TransferResult {
    pub output_notes: Vec<Note>,
    pub proof: ProofEnvelope,
}

/// Result of a withdrawal.
pub struct WithdrawResult {
    pub change_note: Option<Note>,
    pub exit_value: u64,
    pub proof: ProofEnvelope,
}

/// Result of a bridge operation.
pub struct BridgeResult {
    pub dest_note: Note,
    pub proof: ProofEnvelope,
}

/// Extracted coin data (owned, no borrows on wallet).
struct CoinData {
    owner: pallas::Base,
    value: u64,
    asset_id: u64,
    blinding: pallas::Base,
    commitment: pallas::Base,
    tree_index: u64,
}

/// Convert raw auth_path `(Vec<Base>, Vec<u8>)` to fixed-size circuit arrays.
fn convert_auth_path(
    siblings: Vec<pallas::Base>,
    positions: Vec<u8>,
) -> Result<([pallas::Base; TREE_DEPTH], [pallas::Base; TREE_DEPTH]), SdkError> {
    let path: [pallas::Base; TREE_DEPTH] = siblings
        .try_into()
        .map_err(|_| SdkError::Proof("invalid auth path sibling count".into()))?;
    let pos: [pallas::Base; TREE_DEPTH] = positions
        .iter()
        .map(|&b| if b == 1 { pallas::Base::one() } else { pallas::Base::zero() })
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| SdkError::Proof("invalid auth path position count".into()))?;
    Ok((path, pos))
}

/// The top-level ESCANORR orchestrator.
pub struct Escanorr {
    wallet: Wallet,
    node: NodeState,
    prover_params: Option<ProverParams>,
}

impl Escanorr {
    /// Create a new ESCANORR instance with a random wallet.
    pub fn new() -> Self {
        Self {
            wallet: Wallet::random(),
            node: NodeState::new(),
            prover_params: None,
        }
    }

    /// Create an instance with a specific wallet.
    pub fn with_wallet(wallet: Wallet) -> Self {
        Self {
            wallet,
            node: NodeState::new(),
            prover_params: None,
        }
    }

    /// Initialize prover parameters (expensive one-time IPA setup).
    /// Called lazily on first proof generation if not called explicitly.
    pub fn init_prover(&mut self) {
        if self.prover_params.is_none() {
            self.prover_params = Some(ProverParams::setup());
        }
    }

    /// Get the wallet.
    pub fn wallet(&self) -> &Wallet {
        &self.wallet
    }

    /// Get a mutable reference to the wallet.
    pub fn wallet_mut(&mut self) -> &mut Wallet {
        &mut self.wallet
    }

    /// Get the node state.
    pub fn node(&self) -> &NodeState {
        &self.node
    }

    /// Deposit a value into the privacy pool.
    /// Returns the note and its tree index.
    pub fn deposit(&mut self, value: u64) -> Result<(Note, u64), SdkError> {
        let owner = self.wallet.owner().ok_or(SdkError::NoWallet)?;

        let note = Note {
            owner,
            value,
            asset_id: 0,
            blinding: pallas::Base::random(OsRng),
        };

        let cm = note.commitment();
        let index = self.node.deposit(cm.0, value)?;
        self.wallet.add_note(note.clone(), index);

        Ok((note, index))
    }

    /// Send a private transfer to a recipient, generating a ZK proof.
    ///
    /// The transfer circuit is 2-in-2-out. If only one input coin is selected,
    /// a zero-value dummy note is deposited to pad the second input slot.
    pub fn send(
        &mut self,
        recipient_owner: Base,
        amount: u64,
        fee: u64,
    ) -> Result<TransferResult, SdkError> {
        self.init_prover();

        let total_needed = amount + fee;
        let sk_base = self.wallet.spending_key().ok_or(SdkError::NoWallet)?.to_base();
        let my_owner = self.wallet.owner().ok_or(SdkError::NoWallet)?;

        // Select coins — extract into owned data to release borrow on wallet
        let (mut inputs, total_selected) = {
            let (selected, total) = self.wallet.select_coins(total_needed)?;
            let data: Vec<CoinData> = selected
                .iter()
                .map(|c| CoinData {
                    owner: c.note.owner,
                    value: c.note.value,
                    asset_id: c.note.asset_id,
                    blinding: c.note.blinding,
                    commitment: c.commitment.0,
                    tree_index: c.tree_index,
                })
                .collect();
            (data, total)
        };

        // Circuit is 2-in-2-out: reject if > 2 inputs needed
        if inputs.len() > 2 {
            return Err(SdkError::TooManyInputs(inputs.len()));
        }

        // Pad to 2 inputs with a zero-value dummy note if needed
        if inputs.len() < 2 {
            let dummy = Note::with_blinding(my_owner, 0, 0, pallas::Base::random(OsRng));
            let dummy_cm = dummy.commitment().0;
            let dummy_idx = self.node.deposit(dummy_cm, 0)?;
            inputs.push(CoinData {
                owner: dummy.owner,
                value: 0,
                asset_id: 0,
                blinding: dummy.blinding,
                commitment: dummy_cm,
                tree_index: dummy_idx,
            });
        }

        // Get Merkle root and auth paths (after any dummy deposit)
        let root = self.node.root();
        let (path_0, pos_0) = {
            let (s, p) = self.node.pool().auth_path(inputs[0].tree_index)
                .ok_or(SdkError::MissingAuthPath(inputs[0].tree_index))?;
            convert_auth_path(s, p)?
        };
        let (path_1, pos_1) = {
            let (s, p) = self.node.pool().auth_path(inputs[1].tree_index)
                .ok_or(SdkError::MissingAuthPath(inputs[1].tree_index))?;
            convert_auth_path(s, p)?
        };

        // Compute nullifiers
        let nf_0 = compute_nullifier_v1(sk_base, inputs[0].commitment).inner();
        let nf_1 = compute_nullifier_v1(sk_base, inputs[1].commitment).inner();

        // Build output notes
        let change = total_selected - total_needed;
        let recipient_note = Note {
            owner: recipient_owner,
            value: amount,
            asset_id: 0,
            blinding: pallas::Base::random(OsRng),
        };
        let change_note = Note {
            owner: my_owner,
            value: change,
            asset_id: 0,
            blinding: pallas::Base::random(OsRng),
        };
        let out_cm_0 = recipient_note.commitment().inner();
        let out_cm_1 = change_note.commitment().inner();

        // Build circuit
        let circuit = TransferCircuit::new(
            [sk_base, sk_base],
            [inputs[0].owner, inputs[1].owner],
            [inputs[0].value, inputs[1].value],
            [inputs[0].asset_id, inputs[1].asset_id],
            [inputs[0].blinding, inputs[1].blinding],
            [path_0, path_1],
            [pos_0, pos_1],
            [recipient_owner, my_owner],
            [amount, change],
            [0, 0],
            [recipient_note.blinding, change_note.blinding],
            fee,
        );

        // Public inputs: [root, nf_0, nf_1, out_cm_0, out_cm_1]
        let public_inputs = vec![root, nf_0, nf_1, out_cm_0, out_cm_1];
        let params = self.prover_params.as_ref().unwrap();
        let envelope = prove_transfer(params, circuit, &[&public_inputs])
            .map_err(|e| SdkError::Proof(format!("{e}")))?;

        // Execute the transfer on the node
        self.node.transfer(vec![nf_0, nf_1], root, vec![out_cm_0, out_cm_1])?;

        // Mark inputs as spent
        for input in &inputs {
            self.wallet.mark_spent(input.tree_index);
        }

        // Track change note (last inserted commitment)
        let change_index = self.node.pool().tree_size() - 1;
        self.wallet.add_note(change_note.clone(), change_index);

        Ok(TransferResult {
            output_notes: vec![recipient_note, change_note],
            proof: envelope,
        })
    }

    /// Withdraw from the privacy pool with a public exit value.
    ///
    /// Requires a single input note that covers `exit_value + fee`.
    /// Returns the change note (if any) and the ZK proof.
    pub fn withdraw(
        &mut self,
        exit_value: u64,
        fee: u64,
    ) -> Result<WithdrawResult, SdkError> {
        self.init_prover();

        let total_needed = exit_value + fee;
        let sk_base = self.wallet.spending_key().ok_or(SdkError::NoWallet)?.to_base();
        let my_owner = self.wallet.owner().ok_or(SdkError::NoWallet)?;

        // Select a single coin that covers the amount
        let input = {
            let (selected, _total) = self.wallet.select_coins(total_needed)?;
            if selected.len() > 1 {
                return Err(SdkError::NeedConsolidation);
            }
            let c = &selected[0];
            CoinData {
                owner: c.note.owner,
                value: c.note.value,
                asset_id: c.note.asset_id,
                blinding: c.note.blinding,
                commitment: c.commitment.0,
                tree_index: c.tree_index,
            }
        };

        let root = self.node.root();
        let (path, pos) = {
            let (s, p) = self.node.pool().auth_path(input.tree_index)
                .ok_or(SdkError::MissingAuthPath(input.tree_index))?;
            convert_auth_path(s, p)?
        };

        let nf = compute_nullifier_v1(sk_base, input.commitment).inner();
        let change_value = input.value - exit_value - fee;

        // Build change note (or dummy if no change)
        let change_blinding = pallas::Base::random(OsRng);
        let (chg_note, chg_owner, chg_val, chg_asset, chg_blind) = if change_value > 0 {
            let cn = Note::with_blinding(my_owner, change_value, 0, change_blinding);
            (Some(cn.clone()), my_owner, change_value, 0u64, change_blinding)
        } else {
            (None, my_owner, 0u64, 0u64, change_blinding)
        };
        let chg_cm = Note::with_blinding(chg_owner, chg_val, chg_asset, chg_blind)
            .commitment()
            .inner();

        let circuit = WithdrawCircuit::new(
            sk_base,
            input.owner,
            input.value,
            input.asset_id,
            input.blinding,
            path,
            pos,
            chg_owner,
            chg_val,
            chg_asset,
            chg_blind,
            exit_value,
            fee,
        );

        // Public inputs: [root, nullifier, change_cm, exit_value]
        let public_inputs = vec![root, nf, chg_cm, pallas::Base::from(exit_value)];
        let params = self.prover_params.as_ref().unwrap();
        let envelope = prove_withdraw(params, circuit, &[&public_inputs])
            .map_err(|e| SdkError::Proof(format!("{e}")))?;

        // Execute the withdrawal on the node
        let change_commitment = if change_value > 0 { Some(chg_cm) } else { None };
        self.node.withdraw(nf, root, exit_value, change_commitment)?;

        // Mark input as spent
        self.wallet.mark_spent(input.tree_index);

        // Track change note
        if let Some(ref cn) = chg_note {
            let change_index = self.node.pool().tree_size() - 1;
            self.wallet.add_note(cn.clone(), change_index);
        }

        Ok(WithdrawResult {
            change_note: chg_note,
            exit_value,
            proof: envelope,
        })
    }

    /// Bridge a note to another chain, generating a cross-chain proof.
    ///
    /// Nullifies the source note and produces a proof + destination note
    /// that a relayer can submit to the destination chain.
    pub fn bridge(
        &mut self,
        dest_owner: Base,
        src_chain_id: u64,
        dest_chain_id: u64,
        fee: u64,
    ) -> Result<BridgeResult, SdkError> {
        self.init_prover();

        let sk_base = self.wallet.spending_key().ok_or(SdkError::NoWallet)?.to_base();

        // Select a single coin for bridging (entire value minus fee)
        let input = {
            let (selected, _total) = self.wallet.select_coins(fee + 1)?;
            if selected.len() > 1 {
                return Err(SdkError::NeedConsolidation);
            }
            let c = &selected[0];
            CoinData {
                owner: c.note.owner,
                value: c.note.value,
                asset_id: c.note.asset_id,
                blinding: c.note.blinding,
                commitment: c.commitment.0,
                tree_index: c.tree_index,
            }
        };

        let dest_value = input.value - fee;
        let root = self.node.root();
        let (path, pos) = {
            let (s, p) = self.node.pool().auth_path(input.tree_index)
                .ok_or(SdkError::MissingAuthPath(input.tree_index))?;
            convert_auth_path(s, p)?
        };

        let nf = compute_nullifier_v1(sk_base, input.commitment).inner();

        let dest_note = Note {
            owner: dest_owner,
            value: dest_value,
            asset_id: input.asset_id,
            blinding: pallas::Base::random(OsRng),
        };
        let dest_cm = dest_note.commitment().inner();

        let circuit = BridgeCircuit::new(
            sk_base,
            input.owner,
            input.value,
            input.asset_id,
            input.blinding,
            path,
            pos,
            dest_owner,
            dest_value,
            input.asset_id,
            dest_note.blinding,
            src_chain_id,
            dest_chain_id,
            fee,
        );

        // Public inputs: [src_root, src_nullifier, dest_cm, src_chain_id, dest_chain_id]
        let public_inputs = vec![
            root,
            nf,
            dest_cm,
            pallas::Base::from(src_chain_id),
            pallas::Base::from(dest_chain_id),
        ];
        let params = self.prover_params.as_ref().unwrap();
        let envelope = prove_bridge(params, circuit, &[&public_inputs])
            .map_err(|e| SdkError::Proof(format!("{e}")))?;

        // On source chain: nullify the note (withdraw with 0 exit value)
        self.node.withdraw(nf, root, 0, None)?;

        // Mark input as spent
        self.wallet.mark_spent(input.tree_index);

        Ok(BridgeResult {
            dest_note,
            proof: envelope,
        })
    }

    /// Get the current pool root.
    pub fn root(&self) -> Base {
        self.node.root()
    }

    /// Get the wallet's balance.
    pub fn balance(&self) -> u64 {
        self.wallet.balance()
    }
}

impl Default for Escanorr {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use escanorr_note::SpendingKey;

    #[test]
    fn deposit_and_balance() {
        let mut esc = Escanorr::new();
        esc.deposit(1000).unwrap();
        assert_eq!(esc.balance(), 1000);
        esc.deposit(500).unwrap();
        assert_eq!(esc.balance(), 1500);
    }

    #[test]
    fn deposit_multiple() {
        let mut esc = Escanorr::new();
        esc.deposit(500).unwrap();
        esc.deposit(300).unwrap();
        assert_eq!(esc.balance(), 800);
    }

    #[test]
    #[ignore] // Requires expensive prover setup — run with `cargo test -- --ignored`
    fn full_deposit_send_with_proof() {
        let mut esc = Escanorr::new();

        // Deposit
        esc.deposit(1000).unwrap();
        assert_eq!(esc.balance(), 1000);

        // Create a recipient
        let recipient_sk = SpendingKey::random();
        let recipient_owner = recipient_sk.to_full_viewing_key().viewing_key.to_owner();

        // Send with ZK proof
        let result = esc.send(recipient_owner, 400, 10).unwrap();
        assert_eq!(result.output_notes.len(), 2);
        assert_eq!(result.output_notes[0].value, 400); // recipient
        assert_eq!(result.output_notes[1].value, 590); // change: 1000 - 400 - 10
        assert_eq!(esc.balance(), 590);
        assert!(!result.proof.open().unwrap().is_empty());
    }

    #[test]
    #[ignore] // Requires expensive prover setup
    fn full_deposit_and_withdraw() {
        let mut esc = Escanorr::new();
        esc.deposit(1000).unwrap();

        let result = esc.withdraw(400, 10).unwrap();
        assert_eq!(result.exit_value, 400);
        assert_eq!(result.change_note.as_ref().unwrap().value, 590);
        assert_eq!(esc.balance(), 590);
        assert!(!result.proof.open().unwrap().is_empty());
    }
}
