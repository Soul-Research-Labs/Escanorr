//! Withdraw circuit — proves a valid spend with a public exit amount.
//!
//! Public inputs (instance column):
//!   [0] merkle_root
//!   [1] nullifier
//!   [2] change_cm  (commitment to the change output note)
//!   [3] exit_value (publicly revealed for on-chain settlement)
//!
//! The circuit proves:
//! 1. Input note commitment matches Merkle tree at the claimed path
//! 2. Nullifier = Poseidon_domain(sk, cm)
//! 3. Balance: input_value == change_value + exit_value + fee
//! 4. All values are non-negative (64-bit range check)
//! 5. Change commitment is correctly derived

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

/// Number of public inputs for the withdraw circuit.
pub const WITHDRAW_PUBLIC_INPUTS: usize = 4;
/// Number of bits for value range checks (u64).
const VALUE_BITS: usize = 64;

/// Withdraw circuit: proves a valid spend with a public exit amount.
#[derive(Clone, Debug)]
pub struct WithdrawCircuit {
    // Spending key
    pub spending_key: Value<pallas::Base>,

    // Input note
    pub input_owner: Value<pallas::Base>,
    pub input_value: Value<pallas::Base>,
    pub input_asset_id: Value<pallas::Base>,
    pub input_blinding: Value<pallas::Base>,
    pub input_path: [Value<pallas::Base>; TREE_DEPTH],
    pub input_position: [Value<pallas::Base>; TREE_DEPTH],

    // Change output note
    pub change_owner: Value<pallas::Base>,
    pub change_value: Value<pallas::Base>,
    pub change_asset_id: Value<pallas::Base>,
    pub change_blinding: Value<pallas::Base>,

    // Public exit value
    pub exit_value: Value<pallas::Base>,

    // Fee
    pub fee: Value<pallas::Base>,
}

impl Default for WithdrawCircuit {
    fn default() -> Self {
        Self {
            spending_key: Value::unknown(),
            input_owner: Value::unknown(),
            input_value: Value::unknown(),
            input_asset_id: Value::unknown(),
            input_blinding: Value::unknown(),
            input_path: [Value::unknown(); TREE_DEPTH],
            input_position: [Value::unknown(); TREE_DEPTH],
            change_owner: Value::unknown(),
            change_value: Value::unknown(),
            change_asset_id: Value::unknown(),
            change_blinding: Value::unknown(),
            exit_value: Value::unknown(),
            fee: Value::unknown(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct WithdrawConfig {
    poseidon_config: PoseidonGadgetConfig,
    range_config: RangeCheckConfig,
    advice: [Column<Advice>; 5],
    instance: Column<Instance>,
    balance_sel: Selector,
}

impl Circuit<pallas::Base> for WithdrawCircuit {
    type Config = WithdrawConfig;
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

        let poseidon_config = configure_poseidon(
            meta,
            [advice[0], advice[1], advice[2]],
            advice[3],
            rc_a,
            rc_b,
        );

        let range_config = configure_range_check(meta, advice[0], advice[1]);

        // Balance: input == change + exit + fee
        // advice[0]=input, advice[1]=change, advice[2]=exit, advice[3]=fee
        let balance_sel = meta.selector();
        meta.create_gate("withdraw balance", |meta| {
            let s = meta.query_selector(balance_sel);
            let input = meta.query_advice(advice[0], Rotation::cur());
            let change = meta.query_advice(advice[1], Rotation::cur());
            let exit = meta.query_advice(advice[2], Rotation::cur());
            let fee = meta.query_advice(advice[3], Rotation::cur());
            vec![s * (input - change - exit - fee)]
        });

        WithdrawConfig {
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
        // ── Assign private witnesses ─────────────────────────────────

        let (in_owner, in_value, in_asset, in_blinding, sk) = layouter.assign_region(
            || "input witnesses",
            |mut region| {
                let o = region.assign_advice(|| "owner", config.advice[0], 0, || self.input_owner)?;
                let v = region.assign_advice(|| "value", config.advice[1], 0, || self.input_value)?;
                let a = region.assign_advice(|| "asset", config.advice[2], 0, || self.input_asset_id)?;
                let b = region.assign_advice(|| "blind", config.advice[3], 0, || self.input_blinding)?;
                let s = region.assign_advice(|| "sk", config.advice[4], 0, || self.spending_key)?;
                Ok((o, v, a, b, s))
            },
        )?;

        let (in_path, in_bits) = layouter.assign_region(
            || "merkle path",
            |mut region| {
                let mut path = Vec::with_capacity(TREE_DEPTH);
                let mut bits = Vec::with_capacity(TREE_DEPTH);
                for i in 0..TREE_DEPTH {
                    let sib = region.assign_advice(|| format!("sib_{i}"), config.advice[0], i, || self.input_path[i])?;
                    let bit = region.assign_advice(|| format!("bit_{i}"), config.advice[1], i, || self.input_position[i])?;
                    path.push(sib);
                    bits.push(bit);
                }
                Ok((path, bits))
            },
        )?;

        let (chg_owner, chg_value, chg_asset, chg_blinding) = layouter.assign_region(
            || "change witnesses",
            |mut region| {
                let o = region.assign_advice(|| "chg_owner", config.advice[0], 0, || self.change_owner)?;
                let v = region.assign_advice(|| "chg_value", config.advice[1], 0, || self.change_value)?;
                let a = region.assign_advice(|| "chg_asset", config.advice[2], 0, || self.change_asset_id)?;
                let b = region.assign_advice(|| "chg_blind", config.advice[3], 0, || self.change_blinding)?;
                Ok((o, v, a, b))
            },
        )?;

        let exit_cell = layouter.assign_region(
            || "exit witness",
            |mut region| {
                region.assign_advice(|| "exit", config.advice[0], 0, || self.exit_value)
            },
        )?;

        let fee_cell = layouter.assign_region(
            || "fee witness",
            |mut region| {
                region.assign_advice(|| "fee", config.advice[0], 0, || self.fee)
            },
        )?;

        // ── Note commitment ──────────────────────────────────────────

        let cm = note_commitment_gadget(
            &config.poseidon_config,
            layouter.namespace(|| "cm"),
            in_owner,
            in_value.clone(),
            in_asset,
            in_blinding,
        )?;

        // ── Nullifier ────────────────────────────────────────────────

        let nf = nullifier_gadget(
            &config.poseidon_config,
            layouter.namespace(|| "nf"),
            sk,
            cm.clone(),
        )?;

        // ── Merkle membership ────────────────────────────────────────

        let root = merkle_membership_gadget(
            &config.poseidon_config,
            layouter.namespace(|| "merkle"),
            cm,
            &in_path,
            &in_bits,
        )?;

        // ── Change commitment ────────────────────────────────────────

        let change_cm = note_commitment_gadget(
            &config.poseidon_config,
            layouter.namespace(|| "change_cm"),
            chg_owner,
            chg_value.clone(),
            chg_asset,
            chg_blinding,
        )?;

        // ── Balance check ────────────────────────────────────────────

        layouter.assign_region(
            || "balance check",
            |mut region| {
                config.balance_sel.enable(&mut region, 0)?;
                in_value.copy_advice(|| "input", &mut region, config.advice[0], 0)?;
                chg_value.copy_advice(|| "change", &mut region, config.advice[1], 0)?;
                exit_cell.copy_advice(|| "exit", &mut region, config.advice[2], 0)?;
                fee_cell.copy_advice(|| "fee", &mut region, config.advice[3], 0)?;
                Ok(())
            },
        )?;

        // ── Range checks (64-bit) ────────────────────────────────────

        range_check_gadget(&config.range_config, layouter.namespace(|| "range_in"), in_value, VALUE_BITS)?;
        range_check_gadget(&config.range_config, layouter.namespace(|| "range_chg"), chg_value, VALUE_BITS)?;
        range_check_gadget(&config.range_config, layouter.namespace(|| "range_exit"), exit_cell.clone(), VALUE_BITS)?;
        range_check_gadget(&config.range_config, layouter.namespace(|| "range_fee"), fee_cell, VALUE_BITS)?;

        // ── Expose public inputs ─────────────────────────────────────

        layouter.constrain_instance(root.cell(), config.instance, 0)?;
        layouter.constrain_instance(nf.cell(), config.instance, 1)?;
        layouter.constrain_instance(change_cm.cell(), config.instance, 2)?;
        layouter.constrain_instance(exit_cell.cell(), config.instance, 3)?;

        Ok(())
    }
}

impl WithdrawCircuit {
    /// Create a new withdraw circuit from concrete values.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        spending_key: pallas::Base,
        input_owner: pallas::Base,
        input_value: u64,
        input_asset_id: u64,
        input_blinding: pallas::Base,
        input_path: [pallas::Base; TREE_DEPTH],
        input_position: [pallas::Base; TREE_DEPTH],
        change_owner: pallas::Base,
        change_value: u64,
        change_asset_id: u64,
        change_blinding: pallas::Base,
        exit_value: u64,
        fee: u64,
    ) -> Self {
        Self {
            spending_key: Value::known(spending_key),
            input_owner: Value::known(input_owner),
            input_value: Value::known(pallas::Base::from(input_value)),
            input_asset_id: Value::known(pallas::Base::from(input_asset_id)),
            input_blinding: Value::known(input_blinding),
            input_path: input_path.map(|v| Value::known(v)),
            input_position: input_position.map(|v| Value::known(v)),
            change_owner: Value::known(change_owner),
            change_value: Value::known(pallas::Base::from(change_value)),
            change_asset_id: Value::known(pallas::Base::from(change_asset_id)),
            change_blinding: Value::known(change_blinding),
            exit_value: Value::known(pallas::Base::from(exit_value)),
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

    fn native_nullifier(sk: pallas::Base, cm: pallas::Base) -> pallas::Base {
        poseidon_hash_with_domain(DOMAIN_NULLIFIER, sk, cm)
    }

    fn build_withdraw_and_verify(
        input_value: u64,
        change_value: u64,
        exit_value: u64,
        fee: u64,
        expect_ok: bool,
    ) {
        let sk = pallas::Base::from(111u64);
        let owner = pallas::Base::from(10u64);
        let chg_owner = pallas::Base::from(20u64);
        let asset_id = 0u64;

        let note = Note::with_blinding(owner, input_value, asset_id, pallas::Base::from(1u64));
        let chg_note = Note::with_blinding(chg_owner, change_value, asset_id, pallas::Base::from(2u64));

        let cm = note.commitment().inner();
        let chg_cm = chg_note.commitment().inner();

        let mut tree = IncrementalMerkleTree::new();
        let idx = tree.insert(cm);
        let root = tree.root();
        let (sibs, idx_bits) = tree.auth_path(idx).expect("auth path");

        let path: [pallas::Base; TREE_DEPTH] = sibs.try_into().unwrap();
        let pos: [pallas::Base; TREE_DEPTH] = idx_bits.iter()
            .map(|&b| if b == 1 { pallas::Base::ONE } else { pallas::Base::ZERO })
            .collect::<Vec<_>>().try_into().unwrap();

        let nf = native_nullifier(sk, cm);

        let circuit = WithdrawCircuit::new(
            sk,
            owner,
            input_value,
            asset_id,
            pallas::Base::from(1u64),
            path,
            pos,
            chg_owner,
            change_value,
            asset_id,
            pallas::Base::from(2u64),
            exit_value,
            fee,
        );

        let exit_field = pallas::Base::from(exit_value);
        let public_inputs = vec![root, nf, chg_cm, exit_field];
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
    fn withdraw_circuit_valid() {
        // 1000 = 500 + 490 + 10
        build_withdraw_and_verify(1000, 500, 490, 10, true);
    }

    #[test]
    fn withdraw_circuit_invalid_balance() {
        // 1000 ≠ 600 + 490 + 10
        build_withdraw_and_verify(1000, 600, 490, 10, false);
    }

    #[test]
    fn withdraw_circuit_zero_fee() {
        // 1000 = 500 + 500 + 0
        build_withdraw_and_verify(1000, 500, 500, 0, true);
    }
}
