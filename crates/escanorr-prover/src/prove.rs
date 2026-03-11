//! Proof generation for transfer, withdraw, and bridge circuits.

use escanorr_circuits::{TransferCircuit, WithdrawCircuit, BridgeCircuit, K_TRANSFER};
use escanorr_primitives::ProofEnvelope;
use halo2_proofs::{
    pasta::{EqAffine, vesta},
    plonk::{self, keygen_pk, keygen_vk, ProvingKey, VerifyingKey},
    poly::commitment::Params,
    transcript::{Blake2bWrite, Challenge255},
};
use pasta_curves::pallas;
use rand::rngs::OsRng;

/// Holds the proving parameters for a specific circuit size.
pub struct ProverParams {
    pub params: Params<vesta::Affine>,
    pub transfer_pk: ProvingKey<vesta::Affine>,
    pub transfer_vk: VerifyingKey<vesta::Affine>,
    pub withdraw_pk: ProvingKey<vesta::Affine>,
    pub withdraw_vk: VerifyingKey<vesta::Affine>,
    pub bridge_pk: ProvingKey<vesta::Affine>,
    pub bridge_vk: VerifyingKey<vesta::Affine>,
}

impl ProverParams {
    /// Generate proving parameters for all circuits.
    /// This performs a one-time trusted setup (IPA — no toxic waste).
    pub fn setup() -> Self {
        let params = Params::<vesta::Affine>::new(K_TRANSFER);

        let transfer_circuit = TransferCircuit::default();
        let transfer_vk = keygen_vk(&params, &transfer_circuit)
            .expect("transfer vk keygen failed");
        let transfer_pk = keygen_pk(&params, transfer_vk.clone(), &transfer_circuit)
            .expect("transfer pk keygen failed");

        let withdraw_circuit = WithdrawCircuit::default();
        let withdraw_vk = keygen_vk(&params, &withdraw_circuit)
            .expect("withdraw vk keygen failed");
        let withdraw_pk = keygen_pk(&params, withdraw_vk.clone(), &withdraw_circuit)
            .expect("withdraw pk keygen failed");

        let bridge_circuit = BridgeCircuit::default();
        let bridge_vk = keygen_vk(&params, &bridge_circuit)
            .expect("bridge vk keygen failed");
        let bridge_pk = keygen_pk(&params, bridge_vk.clone(), &bridge_circuit)
            .expect("bridge pk keygen failed");

        Self {
            params,
            transfer_pk,
            transfer_vk,
            withdraw_pk,
            withdraw_vk,
            bridge_pk,
            bridge_vk,
        }
    }

    /// Get the common IPA parameters.
    pub fn params(&self) -> &Params<vesta::Affine> {
        &self.params
    }
}

/// Generate a proof for a transfer circuit.
///
/// Returns a `ProofEnvelope` containing the serialized proof.
pub fn prove_transfer(
    prover_params: &ProverParams,
    circuit: TransferCircuit,
    public_inputs: &[&[pallas::Base]],
) -> Result<ProofEnvelope, plonk::Error> {
    let proof_bytes = create_proof(
        &prover_params.params,
        &prover_params.transfer_pk,
        circuit,
        public_inputs,
    )?;
    let envelope = ProofEnvelope::seal(&proof_bytes)
        .map_err(|_| plonk::Error::ConstraintSystemFailure)?;
    Ok(envelope)
}

/// Generate a proof for a withdraw circuit.
pub fn prove_withdraw(
    prover_params: &ProverParams,
    circuit: WithdrawCircuit,
    public_inputs: &[&[pallas::Base]],
) -> Result<ProofEnvelope, plonk::Error> {
    let proof_bytes = create_proof(
        &prover_params.params,
        &prover_params.withdraw_pk,
        circuit,
        public_inputs,
    )?;
    let envelope = ProofEnvelope::seal(&proof_bytes)
        .map_err(|_| plonk::Error::ConstraintSystemFailure)?;
    Ok(envelope)
}

/// Generate a proof for a bridge circuit.
pub fn prove_bridge(
    prover_params: &ProverParams,
    circuit: BridgeCircuit,
    public_inputs: &[&[pallas::Base]],
) -> Result<ProofEnvelope, plonk::Error> {
    let proof_bytes = create_proof(
        &prover_params.params,
        &prover_params.bridge_pk,
        circuit,
        public_inputs,
    )?;
    let envelope = ProofEnvelope::seal(&proof_bytes)
        .map_err(|_| plonk::Error::ConstraintSystemFailure)?;
    Ok(envelope)
}

/// Internal: create a proof using Halo2's IPA prover.
fn create_proof<C: halo2_proofs::plonk::Circuit<pallas::Base>>(
    params: &Params<vesta::Affine>,
    pk: &ProvingKey<vesta::Affine>,
    circuit: C,
    public_inputs: &[&[pallas::Base]],
) -> Result<Vec<u8>, plonk::Error> {
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
    plonk::create_proof(params, pk, &[circuit], &[public_inputs], OsRng, &mut transcript)?;
    Ok(transcript.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use escanorr_note::Note;
    use escanorr_primitives::poseidon::{poseidon_hash_with_domain, DOMAIN_NULLIFIER};
    use escanorr_tree::{IncrementalMerkleTree, TREE_DEPTH};
    use ff::Field;
    use pasta_curves::pallas;

    fn native_nullifier(sk: pallas::Base, cm: pallas::Base) -> pallas::Base {
        poseidon_hash_with_domain(DOMAIN_NULLIFIER, sk, cm)
    }

    #[test]
    fn prover_setup_and_transfer_proof() {
        let params = ProverParams::setup();

        let sk0 = pallas::Base::from(111u64);
        let sk1 = pallas::Base::from(222u64);
        let owner0 = pallas::Base::from(10u64);
        let owner1 = pallas::Base::from(20u64);

        let note0 = Note::with_blinding(owner0, 100, 0, pallas::Base::from(1u64));
        let note1 = Note::with_blinding(owner1, 50, 0, pallas::Base::from(2u64));
        let out_note0 = Note::with_blinding(pallas::Base::from(30u64), 80, 0, pallas::Base::from(3u64));
        let out_note1 = Note::with_blinding(pallas::Base::from(40u64), 60, 0, pallas::Base::from(4u64));

        let cm0 = note0.commitment().inner();
        let cm1 = note1.commitment().inner();
        let out_cm0 = out_note0.commitment().inner();
        let out_cm1 = out_note1.commitment().inner();

        let mut tree = IncrementalMerkleTree::new();
        let idx0 = tree.insert(cm0);
        let idx1 = tree.insert(cm1);
        let root = tree.root();

        let (sibs_0, idx_0) = tree.auth_path(idx0).unwrap();
        let (sibs_1, idx_1) = tree.auth_path(idx1).unwrap();
        let path_0: [pallas::Base; TREE_DEPTH] = sibs_0.try_into().unwrap();
        let pos_0: [pallas::Base; TREE_DEPTH] = idx_0.iter()
            .map(|&b| if b == 1 { pallas::Base::ONE } else { pallas::Base::ZERO })
            .collect::<Vec<_>>().try_into().unwrap();
        let path_1: [pallas::Base; TREE_DEPTH] = sibs_1.try_into().unwrap();
        let pos_1: [pallas::Base; TREE_DEPTH] = idx_1.iter()
            .map(|&b| if b == 1 { pallas::Base::ONE } else { pallas::Base::ZERO })
            .collect::<Vec<_>>().try_into().unwrap();

        let nf0 = native_nullifier(sk0, cm0);
        let nf1 = native_nullifier(sk1, cm1);

        let circuit = TransferCircuit::new(
            [sk0, sk1],
            [owner0, owner1],
            [100, 50],
            [0, 0],
            [pallas::Base::from(1u64), pallas::Base::from(2u64)],
            [path_0, path_1],
            [pos_0, pos_1],
            [pallas::Base::from(30u64), pallas::Base::from(40u64)],
            [80, 60],
            [0, 0],
            [pallas::Base::from(3u64), pallas::Base::from(4u64)],
            10,
        );

        let public_inputs = vec![root, nf0, nf1, out_cm0, out_cm1];
        let envelope = prove_transfer(&params, circuit, &[&public_inputs]).unwrap();
        let proof_bytes = envelope.open().unwrap();
        assert!(!proof_bytes.is_empty());
    }
}
