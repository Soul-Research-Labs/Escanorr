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
    use pasta_curves::pallas;

    #[test]
    fn prover_setup_and_transfer_proof() {
        let params = ProverParams::setup();

        let circuit = TransferCircuit::new(
            [100, 50],
            [pallas::Base::from(1u64), pallas::Base::from(2u64)],
            [pallas::Base::from(10u64), pallas::Base::from(20u64)],
            [80, 60],
            [pallas::Base::from(3u64), pallas::Base::from(4u64)],
            [pallas::Base::from(30u64), pallas::Base::from(40u64)],
            10,
        );

        let envelope = prove_transfer(&params, circuit, &[&[]]).unwrap();
        let proof_bytes = envelope.open().unwrap();
        assert!(!proof_bytes.is_empty());
    }
}
