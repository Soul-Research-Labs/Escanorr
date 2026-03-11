//! Transfer circuit — 2-in-2-out private transfer.
//!
//! Public inputs (instance column):
//!   [0] merkle_root
//!   [1] nullifier_0
//!   [2] nullifier_1
//!   [3] output_cm_0
//!   [4] output_cm_1
//!
//! The circuit proves:
//! 1. For each input note: commitment matches Merkle tree at claimed path → root
//! 2. For each input note: nullifier = Poseidon_domain(sk, cm)
//! 3. sum(input_values) == sum(output_values) + fee
//! 4. All values are non-negative (64-bit range check)
//! 5. Output commitments are correctly derived
//! 6. Both inputs share the same Merkle root

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector,
    },
    poly::Rotation,
};
use pasta_curves::pallas;

use crate::gadgets::{
    configure_poseidon, configure_range_check, merkle_membership_gadget,
    note_commitment_gadget, nullifier_gadget, range_check_gadget, PoseidonGadgetConfig,
    RangeCheckConfig,
};
use escanorr_tree::TREE_DEPTH;

/// Number of public inputs for the transfer circuit.
pub const TRANSFER_PUBLIC_INPUTS: usize = 5;
/// Number of bits for value range checks (u64).
const VALUE_BITS: usize = 64;

/// The transfer circuit for 2-in-2-out private transfers.
#[derive(Clone, Debug)]
pub struct TransferCircuit {
    // Spending keys (one per input note)
    pub spending_key_0: Value<pallas::Base>,
    pub spending_key_1: Value<pallas::Base>,

    // Input note 0
    pub input_owner_0: Value<pallas::Base>,
    pub input_value_0: Value<pallas::Base>,
    pub input_asset_id_0: Value<pallas::Base>,
    pub input_blinding_0: Value<pallas::Base>,
    pub input_path_0: [Value<pallas::Base>; TREE_DEPTH],
    pub input_position_0: [Value<pallas::Base>; TREE_DEPTH],

    // Input note 1
    pub input_owner_1: Value<pallas::Base>,
    pub input_value_1: Value<pallas::Base>,
    pub input_asset_id_1: Value<pallas::Base>,
    pub input_blinding_1: Value<pallas::Base>,
    pub input_path_1: [Value<pallas::Base>; TREE_DEPTH],
    pub input_position_1: [Value<pallas::Base>; TREE_DEPTH],

    // Output note 0
    pub output_owner_0: Value<pallas::Base>,
    pub output_value_0: Value<pallas::Base>,
    pub output_asset_id_0: Value<pallas::Base>,
    pub output_blinding_0: Value<pallas::Base>,

    // Output note 1
    pub output_owner_1: Value<pallas::Base>,
    pub output_value_1: Value<pallas::Base>,
    pub output_asset_id_1: Value<pallas::Base>,
    pub output_blinding_1: Value<pallas::Base>,

    // Fee
    pub fee: Value<pallas::Base>,
}

impl Default for TransferCircuit {
    fn default() -> Self {
        Self {
            spending_key_0: Value::unknown(),
            spending_key_1: Value::unknown(),
            input_owner_0: Value::unknown(),
            input_value_0: Value::unknown(),
            input_asset_id_0: Value::unknown(),
            input_blinding_0: Value::unknown(),
            input_path_0: [Value::unknown(); TREE_DEPTH],
            input_position_0: [Value::unknown(); TREE_DEPTH],
            input_owner_1: Value::unknown(),
            input_value_1: Value::unknown(),
            input_asset_id_1: Value::unknown(),
            input_blinding_1: Value::unknown(),
            input_path_1: [Value::unknown(); TREE_DEPTH],
            input_position_1: [Value::unknown(); TREE_DEPTH],
            output_owner_0: Value::unknown(),
            output_value_0: Value::unknown(),
            output_asset_id_0: Value::unknown(),
            output_blinding_0: Value::unknown(),
            output_owner_1: Value::unknown(),
            output_value_1: Value::unknown(),
            output_asset_id_1: Value::unknown(),
            output_blinding_1: Value::unknown(),
            fee: Value::unknown(),
        }
    }
}

/// Configuration for the transfer circuit.
#[derive(Clone, Debug)]
pub struct TransferConfig {
    poseidon_config: PoseidonGadgetConfig,
    range_config: RangeCheckConfig,
    advice: [Column<Advice>; 5],
    instance: Column<Instance>,
    balance_sel: Selector,
}

impl Circuit<pallas::Base> for TransferCircuit {
    type Config = TransferConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        let advice: [Column<Advice>; 5] = core::array::from_fn(|_| meta.advice_column());
        let instance = meta.instance_column();
        let rc_a: [Column<halo2_proofs::plonk::Fixed>; 3] = core::array::from_fn(|_| meta.fixed_column());
        let rc_b: [Column<halo2_proofs::plonk::Fixed>; 3] = core::array::from_fn(|_| meta.fixed_column());
        let constants = meta.fixed_column();
        meta.enable_constant(constants);
        meta.enable_equality(instance);
        meta.enable_equality(advice[4]);

        // Poseidon chip: state=[0..3], partial_sbox=[3]
        let poseidon_config = configure_poseidon(
            meta,
            [advice[0], advice[1], advice[2]],
            advice[3],
            rc_a,
            rc_b,
        );

        // Range check: z_col=[0], bit_col=[1]
        let range_config = configure_range_check(meta, advice[0], advice[1]);

        // Balance gate: advice[0] + advice[1] == advice[2] + advice[3] + advice[4]
        let balance_sel = meta.selector();
        meta.create_gate("balance", |meta| {
            let s = meta.query_selector(balance_sel);
            let in0 = meta.query_advice(advice[0], Rotation::cur());
            let in1 = meta.query_advice(advice[1], Rotation::cur());
            let out0 = meta.query_advice(advice[2], Rotation::cur());
            let out1 = meta.query_advice(advice[3], Rotation::cur());
            let fee = meta.query_advice(advice[4], Rotation::cur());
            vec![s * (in0 + in1 - out0 - out1 - fee)]
        });

        TransferConfig {
            poseidon_config,
            range_config,
            advice,
            instance,
            balance_sel,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        // ── Step 1: Assign private witnesses ─────────────────────────

        let (in0_owner, in0_value, in0_asset, in0_blinding, sk0) = layouter.assign_region(
            || "input 0 witnesses",
            |mut region| {
                let o = region.assign_advice(|| "owner_0", config.advice[0], 0, || self.input_owner_0)?;
                let v = region.assign_advice(|| "value_0", config.advice[1], 0, || self.input_value_0)?;
                let a = region.assign_advice(|| "asset_0", config.advice[2], 0, || self.input_asset_id_0)?;
                let b = region.assign_advice(|| "blind_0", config.advice[3], 0, || self.input_blinding_0)?;
                let s = region.assign_advice(|| "sk_0", config.advice[4], 0, || self.spending_key_0)?;
                Ok((o, v, a, b, s))
            },
        )?;

        let (in1_owner, in1_value, in1_asset, in1_blinding, sk1) = layouter.assign_region(
            || "input 1 witnesses",
            |mut region| {
                let o = region.assign_advice(|| "owner_1", config.advice[0], 0, || self.input_owner_1)?;
                let v = region.assign_advice(|| "value_1", config.advice[1], 0, || self.input_value_1)?;
                let a = region.assign_advice(|| "asset_1", config.advice[2], 0, || self.input_asset_id_1)?;
                let b = region.assign_advice(|| "blind_1", config.advice[3], 0, || self.input_blinding_1)?;
                let s = region.assign_advice(|| "sk_1", config.advice[4], 0, || self.spending_key_1)?;
                Ok((o, v, a, b, s))
            },
        )?;

        let (in0_path, in0_bits) = layouter.assign_region(
            || "merkle path 0",
            |mut region| {
                let mut path = Vec::with_capacity(TREE_DEPTH);
                let mut bits = Vec::with_capacity(TREE_DEPTH);
                for i in 0..TREE_DEPTH {
                    let sib = region.assign_advice(|| format!("sib_0_{i}"), config.advice[0], i, || self.input_path_0[i])?;
                    let bit = region.assign_advice(|| format!("bit_0_{i}"), config.advice[1], i, || self.input_position_0[i])?;
                    path.push(sib);
                    bits.push(bit);
                }
                Ok((path, bits))
            },
        )?;

        let (in1_path, in1_bits) = layouter.assign_region(
            || "merkle path 1",
            |mut region| {
                let mut path = Vec::with_capacity(TREE_DEPTH);
                let mut bits = Vec::with_capacity(TREE_DEPTH);
                for i in 0..TREE_DEPTH {
                    let sib = region.assign_advice(|| format!("sib_1_{i}"), config.advice[0], i, || self.input_path_1[i])?;
                    let bit = region.assign_advice(|| format!("bit_1_{i}"), config.advice[1], i, || self.input_position_1[i])?;
                    path.push(sib);
                    bits.push(bit);
                }
                Ok((path, bits))
            },
        )?;

        let (out0_owner, out0_value, out0_asset, out0_blinding) = layouter.assign_region(
            || "output 0 witnesses",
            |mut region| {
                let o = region.assign_advice(|| "out_owner_0", config.advice[0], 0, || self.output_owner_0)?;
                let v = region.assign_advice(|| "out_value_0", config.advice[1], 0, || self.output_value_0)?;
                let a = region.assign_advice(|| "out_asset_0", config.advice[2], 0, || self.output_asset_id_0)?;
                let b = region.assign_advice(|| "out_blind_0", config.advice[3], 0, || self.output_blinding_0)?;
                Ok((o, v, a, b))
            },
        )?;

        let (out1_owner, out1_value, out1_asset, out1_blinding) = layouter.assign_region(
            || "output 1 witnesses",
            |mut region| {
                let o = region.assign_advice(|| "out_owner_1", config.advice[0], 0, || self.output_owner_1)?;
                let v = region.assign_advice(|| "out_value_1", config.advice[1], 0, || self.output_value_1)?;
                let a = region.assign_advice(|| "out_asset_1", config.advice[2], 0, || self.output_asset_id_1)?;
                let b = region.assign_advice(|| "out_blind_1", config.advice[3], 0, || self.output_blinding_1)?;
                Ok((o, v, a, b))
            },
        )?;

        let fee_cell = layouter.assign_region(
            || "fee witness",
            |mut region| {
                region.assign_advice(|| "fee", config.advice[0], 0, || self.fee)
            },
        )?;

        // ── Step 2: Note commitments for input notes ─────────────────

        let cm_0 = note_commitment_gadget(
            &config.poseidon_config,
            layouter.namespace(|| "cm_0"),
            in0_owner,
            in0_value.clone(),
            in0_asset,
            in0_blinding,
        )?;

        let cm_1 = note_commitment_gadget(
            &config.poseidon_config,
            layouter.namespace(|| "cm_1"),
            in1_owner,
            in1_value.clone(),
            in1_asset,
            in1_blinding,
        )?;

        // ── Step 3: Nullifiers ───────────────────────────────────────

        let nf_0 = nullifier_gadget(
            &config.poseidon_config,
            layouter.namespace(|| "nf_0"),
            sk0,
            cm_0.clone(),
        )?;

        let nf_1 = nullifier_gadget(
            &config.poseidon_config,
            layouter.namespace(|| "nf_1"),
            sk1,
            cm_1.clone(),
        )?;

        // ── Step 4: Merkle membership ────────────────────────────────

        let root_0 = merkle_membership_gadget(
            &config.poseidon_config,
            layouter.namespace(|| "merkle_0"),
            cm_0,
            &in0_path,
            &in0_bits,
        )?;

        let root_1 = merkle_membership_gadget(
            &config.poseidon_config,
            layouter.namespace(|| "merkle_1"),
            cm_1,
            &in1_path,
            &in1_bits,
        )?;

        // ── Step 5: Output commitments ───────────────────────────────

        let out_cm_0 = note_commitment_gadget(
            &config.poseidon_config,
            layouter.namespace(|| "out_cm_0"),
            out0_owner,
            out0_value.clone(),
            out0_asset,
            out0_blinding,
        )?;

        let out_cm_1 = note_commitment_gadget(
            &config.poseidon_config,
            layouter.namespace(|| "out_cm_1"),
            out1_owner,
            out1_value.clone(),
            out1_asset,
            out1_blinding,
        )?;

        // ── Step 6: Balance check ────────────────────────────────────

        layouter.assign_region(
            || "balance check",
            |mut region| {
                config.balance_sel.enable(&mut region, 0)?;
                in0_value.copy_advice(|| "in0", &mut region, config.advice[0], 0)?;
                in1_value.copy_advice(|| "in1", &mut region, config.advice[1], 0)?;
                out0_value.copy_advice(|| "out0", &mut region, config.advice[2], 0)?;
                out1_value.copy_advice(|| "out1", &mut region, config.advice[3], 0)?;
                fee_cell.copy_advice(|| "fee", &mut region, config.advice[4], 0)?;
                Ok(())
            },
        )?;

        // ── Step 7: Range checks (64-bit) ────────────────────────────

        range_check_gadget(
            &config.range_config,
            layouter.namespace(|| "range_in0"),
            in0_value,
            VALUE_BITS,
        )?;
        range_check_gadget(
            &config.range_config,
            layouter.namespace(|| "range_in1"),
            in1_value,
            VALUE_BITS,
        )?;
        range_check_gadget(
            &config.range_config,
            layouter.namespace(|| "range_out0"),
            out0_value,
            VALUE_BITS,
        )?;
        range_check_gadget(
            &config.range_config,
            layouter.namespace(|| "range_out1"),
            out1_value,
            VALUE_BITS,
        )?;
        range_check_gadget(
            &config.range_config,
            layouter.namespace(|| "range_fee"),
            fee_cell,
            VALUE_BITS,
        )?;

        // ── Step 8: Expose public inputs ─────────────────────────────

        // Both inputs must share the same Merkle root
        layouter.constrain_instance(root_0.cell(), config.instance, 0)?;
        layouter.constrain_instance(root_1.cell(), config.instance, 0)?;

        layouter.constrain_instance(nf_0.cell(), config.instance, 1)?;
        layouter.constrain_instance(nf_1.cell(), config.instance, 2)?;
        layouter.constrain_instance(out_cm_0.cell(), config.instance, 3)?;
        layouter.constrain_instance(out_cm_1.cell(), config.instance, 4)?;

        Ok(())
    }
}

impl TransferCircuit {
    /// Create a new transfer circuit from concrete values.
    ///
    /// `input_paths` and `input_positions` provide the Merkle authentication paths
    /// (32 siblings and 32 position bits each) for the two input notes.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        spending_keys: [pallas::Base; 2],
        input_owners: [pallas::Base; 2],
        input_values: [u64; 2],
        input_asset_ids: [u64; 2],
        input_blindings: [pallas::Base; 2],
        input_paths: [[pallas::Base; TREE_DEPTH]; 2],
        input_positions: [[pallas::Base; TREE_DEPTH]; 2],
        output_owners: [pallas::Base; 2],
        output_values: [u64; 2],
        output_asset_ids: [u64; 2],
        output_blindings: [pallas::Base; 2],
        fee: u64,
    ) -> Self {
        Self {
            spending_key_0: Value::known(spending_keys[0]),
            spending_key_1: Value::known(spending_keys[1]),
            input_owner_0: Value::known(input_owners[0]),
            input_value_0: Value::known(pallas::Base::from(input_values[0])),
            input_asset_id_0: Value::known(pallas::Base::from(input_asset_ids[0])),
            input_blinding_0: Value::known(input_blindings[0]),
            input_path_0: input_paths[0].map(|v| Value::known(v)),
            input_position_0: input_positions[0].map(|v| Value::known(v)),
            input_owner_1: Value::known(input_owners[1]),
            input_value_1: Value::known(pallas::Base::from(input_values[1])),
            input_asset_id_1: Value::known(pallas::Base::from(input_asset_ids[1])),
            input_blinding_1: Value::known(input_blindings[1]),
            input_path_1: input_paths[1].map(|v| Value::known(v)),
            input_position_1: input_positions[1].map(|v| Value::known(v)),
            output_owner_0: Value::known(output_owners[0]),
            output_value_0: Value::known(pallas::Base::from(output_values[0])),
            output_asset_id_0: Value::known(pallas::Base::from(output_asset_ids[0])),
            output_blinding_0: Value::known(output_blindings[0]),
            output_owner_1: Value::known(output_owners[1]),
            output_value_1: Value::known(pallas::Base::from(output_values[1])),
            output_asset_id_1: Value::known(pallas::Base::from(output_asset_ids[1])),
            output_blinding_1: Value::known(output_blindings[1]),
            fee: Value::known(pallas::Base::from(fee)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use escanorr_note::Note;
    use escanorr_primitives::poseidon::{poseidon_hash_with_domain, DOMAIN_NULLIFIER};
    use escanorr_tree::IncrementalMerkleTree;
    use ff::Field;
    use halo2_proofs::dev::MockProver;

    /// Helper: compute a V1 nullifier natively for the given spending key and
    /// note commitment, matching `nullifier_gadget`.
    fn native_nullifier(sk: pallas::Base, cm: pallas::Base) -> pallas::Base {
        poseidon_hash_with_domain(DOMAIN_NULLIFIER, sk, cm)
    }

    /// Build a complete, valid transfer witness and run MockProver.
    fn build_and_verify(
        in_values: [u64; 2],
        out_values: [u64; 2],
        fee: u64,
        expect_ok: bool,
    ) {
        let sk0 = pallas::Base::from(111u64);
        let sk1 = pallas::Base::from(222u64);
        let owner0 = pallas::Base::from(10u64);
        let owner1 = pallas::Base::from(20u64);
        let out_owner0 = pallas::Base::from(30u64);
        let out_owner1 = pallas::Base::from(40u64);
        let asset_id = 0u64;

        let note0 = Note::with_blinding(owner0, in_values[0], asset_id, pallas::Base::from(1u64));
        let note1 = Note::with_blinding(owner1, in_values[1], asset_id, pallas::Base::from(2u64));
        let out_note0 = Note::with_blinding(out_owner0, out_values[0], asset_id, pallas::Base::from(3u64));
        let out_note1 = Note::with_blinding(out_owner1, out_values[1], asset_id, pallas::Base::from(4u64));

        let cm0 = note0.commitment().inner();
        let cm1 = note1.commitment().inner();
        let out_cm0 = out_note0.commitment().inner();
        let out_cm1 = out_note1.commitment().inner();

        // Build Merkle tree and get auth paths
        let mut tree = IncrementalMerkleTree::new();
        let idx0 = tree.insert(cm0);
        let idx1 = tree.insert(cm1);
        let root = tree.root();

        let (sibs_0, idx_0) = tree.auth_path(idx0).expect("auth path 0");
        let (sibs_1, idx_1) = tree.auth_path(idx1).expect("auth path 1");

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
            in_values,
            [asset_id, asset_id],
            [pallas::Base::from(1u64), pallas::Base::from(2u64)],
            [path_0, path_1],
            [pos_0, pos_1],
            [out_owner0, out_owner1],
            out_values,
            [asset_id, asset_id],
            [pallas::Base::from(3u64), pallas::Base::from(4u64)],
            fee,
        );

        let public_inputs = vec![root, nf0, nf1, out_cm0, out_cm1];
        let prover = MockProver::run(
            crate::K_TRANSFER,
            &circuit,
            vec![public_inputs],
        ).unwrap();

        if expect_ok {
            assert_eq!(prover.verify(), Ok(()), "circuit should verify");
        } else {
            assert!(prover.verify().is_err(), "circuit should fail");
        }
    }

    #[test]
    fn transfer_circuit_valid() {
        // 100 + 50 = 80 + 60 + 10
        build_and_verify([100, 50], [80, 60], 10, true);
    }

    #[test]
    fn transfer_circuit_invalid_balance() {
        // 100 + 50 ≠ 80 + 80 + 10
        build_and_verify([100, 50], [80, 80], 10, false);
    }

    #[test]
    fn transfer_circuit_zero_fee() {
        // 100 + 50 = 100 + 50 + 0
        build_and_verify([100, 50], [100, 50], 0, true);
    }
}
