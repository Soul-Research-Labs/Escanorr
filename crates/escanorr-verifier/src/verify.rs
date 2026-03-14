//! Proof verification for transfer, withdraw, and bridge circuits.

use escanorr_circuits::{TransferCircuit, WithdrawCircuit, BridgeCircuit, WealthProofCircuit, K_TRANSFER, K_WEALTH};
use escanorr_primitives::ProofEnvelope;
use halo2_proofs::{
    pasta::{EqAffine, vesta},
    plonk::{self, keygen_vk, VerifyingKey},
    poly::commitment::Params,
    transcript::{Blake2bRead, Challenge255},
};
use pasta_curves::pallas;

/// Holds the verifier parameters for all circuit types.
pub struct VerifierParams {
    pub params: Params<vesta::Affine>,
    pub transfer_vk: VerifyingKey<vesta::Affine>,
    pub withdraw_vk: VerifyingKey<vesta::Affine>,
    pub bridge_vk: VerifyingKey<vesta::Affine>,
    pub wealth_params: Params<vesta::Affine>,
    pub wealth_vk: VerifyingKey<vesta::Affine>,
}

impl VerifierParams {
    /// Generate verifier parameters (verification keys only).
    pub fn setup() -> Result<Self, plonk::Error> {
        let params = Params::<vesta::Affine>::new(K_TRANSFER);

        let transfer_vk = keygen_vk(&params, &TransferCircuit::default())?;
        let withdraw_vk = keygen_vk(&params, &WithdrawCircuit::default())?;
        let bridge_vk = keygen_vk(&params, &BridgeCircuit::default())?;

        let wealth_params = Params::<vesta::Affine>::new(K_WEALTH);
        let wealth_vk = keygen_vk(&wealth_params, &WealthProofCircuit::default())?;

        Ok(Self {
            params,
            transfer_vk,
            withdraw_vk,
            bridge_vk,
            wealth_params,
            wealth_vk,
        })
    }
}

/// Verify a transfer proof.
pub fn verify_transfer(
    verifier_params: &VerifierParams,
    envelope: &ProofEnvelope,
    public_inputs: &[&[pallas::Base]],
) -> Result<(), plonk::Error> {
    let proof_bytes = envelope.open().map_err(|_| plonk::Error::ConstraintSystemFailure)?;
    verify_proof(
        &verifier_params.params,
        &verifier_params.transfer_vk,
        &proof_bytes,
        public_inputs,
    )
}

/// Verify a withdraw proof.
pub fn verify_withdraw(
    verifier_params: &VerifierParams,
    envelope: &ProofEnvelope,
    public_inputs: &[&[pallas::Base]],
) -> Result<(), plonk::Error> {
    let proof_bytes = envelope.open().map_err(|_| plonk::Error::ConstraintSystemFailure)?;
    verify_proof(
        &verifier_params.params,
        &verifier_params.withdraw_vk,
        &proof_bytes,
        public_inputs,
    )
}

/// Verify a bridge proof.
pub fn verify_bridge(
    verifier_params: &VerifierParams,
    envelope: &ProofEnvelope,
    public_inputs: &[&[pallas::Base]],
) -> Result<(), plonk::Error> {
    let proof_bytes = envelope.open().map_err(|_| plonk::Error::ConstraintSystemFailure)?;
    verify_proof(
        &verifier_params.params,
        &verifier_params.bridge_vk,
        &proof_bytes,
        public_inputs,
    )
}

/// Verify a wealth proof.
pub fn verify_wealth(
    verifier_params: &VerifierParams,
    envelope: &ProofEnvelope,
    public_inputs: &[&[pallas::Base]],
) -> Result<(), plonk::Error> {
    let proof_bytes = envelope.open().map_err(|_| plonk::Error::ConstraintSystemFailure)?;
    verify_proof(
        &verifier_params.wealth_params,
        &verifier_params.wealth_vk,
        &proof_bytes,
        public_inputs,
    )
}

/// Internal: verify a proof using Halo2's IPA verifier.
fn verify_proof(
    params: &Params<vesta::Affine>,
    vk: &VerifyingKey<vesta::Affine>,
    proof_bytes: &[u8],
    public_inputs: &[&[pallas::Base]],
) -> Result<(), plonk::Error> {
    let strategy = halo2_proofs::plonk::SingleVerifier::new(params);
    let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(proof_bytes);
    plonk::verify_proof(params, vk, strategy, &[public_inputs], &mut transcript)
}

#[cfg(test)]
mod tests {
    use super::*;
    use escanorr_circuits::TransferCircuit;
    use escanorr_note::Note;
    use escanorr_primitives::poseidon::{poseidon_hash_with_domain, DOMAIN_NULLIFIER};
    use escanorr_prover::{ProverParams, prove_transfer};
    use escanorr_tree::{IncrementalMerkleTree, TREE_DEPTH};
    use ff::Field;

    fn native_nullifier(sk: pallas::Base, cm: pallas::Base) -> pallas::Base {
        poseidon_hash_with_domain(DOMAIN_NULLIFIER, sk, cm)
    }

    #[test]
    fn verify_valid_transfer() {
        let prover_params = ProverParams::setup().expect("prover setup");

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
        let envelope = prove_transfer(&prover_params, circuit, &[&public_inputs]).unwrap();

        let verifier_params = VerifierParams {
            params: prover_params.params,
            transfer_vk: prover_params.transfer_vk,
            withdraw_vk: prover_params.withdraw_vk,
            bridge_vk: prover_params.bridge_vk,
            wealth_params: prover_params.wealth_params,
            wealth_vk: prover_params.wealth_vk,
        };

        assert!(verify_transfer(&verifier_params, &envelope, &[&public_inputs]).is_ok());
    }
}
