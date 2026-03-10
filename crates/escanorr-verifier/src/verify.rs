//! Proof verification for transfer, withdraw, and bridge circuits.

use escanorr_circuits::{TransferCircuit, WithdrawCircuit, BridgeCircuit, K_TRANSFER};
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
}

impl VerifierParams {
    /// Generate verifier parameters (verification keys only).
    pub fn setup() -> Self {
        let params = Params::<vesta::Affine>::new(K_TRANSFER);

        let transfer_vk = keygen_vk(&params, &TransferCircuit::default())
            .expect("transfer vk keygen failed");
        let withdraw_vk = keygen_vk(&params, &WithdrawCircuit::default())
            .expect("withdraw vk keygen failed");
        let bridge_vk = keygen_vk(&params, &BridgeCircuit::default())
            .expect("bridge vk keygen failed");

        Self {
            params,
            transfer_vk,
            withdraw_vk,
            bridge_vk,
        }
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
    use escanorr_prover::{ProverParams, prove_transfer};

    #[test]
    fn verify_valid_transfer() {
        let prover_params = ProverParams::setup();

        let circuit = TransferCircuit::new(
            [100, 50],
            [pallas::Base::from(1u64), pallas::Base::from(2u64)],
            [pallas::Base::from(10u64), pallas::Base::from(20u64)],
            [80, 60],
            [pallas::Base::from(3u64), pallas::Base::from(4u64)],
            [pallas::Base::from(30u64), pallas::Base::from(40u64)],
            10,
        );

        let envelope = prove_transfer(&prover_params, circuit, &[&[]]).unwrap();

        // Verifier uses the same params (IPA is universal)
        let verifier_params = VerifierParams {
            params: prover_params.params,
            transfer_vk: prover_params.transfer_vk,
            withdraw_vk: prover_params.withdraw_vk,
            bridge_vk: prover_params.bridge_vk,
        };

        assert!(verify_transfer(&verifier_params, &envelope, &[&[]]).is_ok());
    }
}
