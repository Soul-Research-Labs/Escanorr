//! Wealth proof circuit — prove balance ≥ threshold without revealing balance.
//!
//! Public inputs (instance column):
//!   [0] merkle_root
//!   [1] nullifier      (binds proof to a specific note without spending it)
//!   [2] threshold       (minimum balance the prover claims to meet)
//!
//! The circuit proves:
//! 1. A note exists in the Merkle tree (commitment → root via auth path)
//! 2. The nullifier is correctly derived from (sk, cm)
//! 3. note.value ≥ threshold  (via range check on `value - threshold`)
//! 4. Value and threshold are non-negative (64-bit range check)
//!
//! The note is NOT spent — the nullifier is exposed so verifiers can
//! optionally check freshness ("note hasn't been spent yet").

use ff::Field;
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

/// Number of public inputs for the wealth proof circuit.
pub const WEALTH_PUBLIC_INPUTS: usize = 3;
/// Number of bits for value range checks (u64).
const VALUE_BITS: usize = 64;

/// Wealth proof circuit: proves note value ≥ threshold.
#[derive(Clone, Debug)]
pub struct WealthProofCircuit {
    // Spending key (owner of the note)
    pub spending_key: Value<pallas::Base>,

    // Note fields
    pub owner: Value<pallas::Base>,
    pub value: Value<pallas::Base>,
    pub asset_id: Value<pallas::Base>,
    pub blinding: Value<pallas::Base>,

    // Merkle authentication path
    pub path: [Value<pallas::Base>; TREE_DEPTH],
    pub position: [Value<pallas::Base>; TREE_DEPTH],

    // Threshold (public, but also assigned as witness for arithmetic)
    pub threshold: Value<pallas::Base>,
}

impl Default for WealthProofCircuit {
    fn default() -> Self {
        Self {
            spending_key: Value::unknown(),
            owner: Value::unknown(),
            value: Value::unknown(),
            asset_id: Value::unknown(),
            blinding: Value::unknown(),
            path: [Value::unknown(); TREE_DEPTH],
            position: [Value::unknown(); TREE_DEPTH],
            threshold: Value::unknown(),
        }
    }
}

/// Configuration for the wealth proof circuit.
#[derive(Clone, Debug)]
pub struct WealthConfig {
    poseidon_config: PoseidonGadgetConfig,
    range_config: RangeCheckConfig,
    advice: [Column<Advice>; 5],
    instance: Column<Instance>,
    /// Gate: advice[0] - advice[1] == advice[2]  (value - threshold == diff)
    diff_sel: Selector,
}

impl Circuit<pallas::Base> for WealthProofCircuit {
    type Config = WealthConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        let advice: [Column<Advice>; 5] = core::array::from_fn(|_| meta.advice_column());
        let instance = meta.instance_column();
        let rc_a: [Column<halo2_proofs::plonk::Fixed>; 3] =
            core::array::from_fn(|_| meta.fixed_column());
        let rc_b: [Column<halo2_proofs::plonk::Fixed>; 3] =
            core::array::from_fn(|_| meta.fixed_column());
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

        // Difference gate: value - threshold == diff
        let diff_sel = meta.selector();
        meta.create_gate("wealth_diff", |meta| {
            let s = meta.query_selector(diff_sel);
            let value = meta.query_advice(advice[0], Rotation::cur());
            let threshold = meta.query_advice(advice[1], Rotation::cur());
            let diff = meta.query_advice(advice[2], Rotation::cur());
            vec![s * (value - threshold - diff)]
        });

        WealthConfig {
            poseidon_config,
            range_config,
            advice,
            instance,
            diff_sel,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        // ── Step 1: Assign private witnesses ─────────────────────────

        let (note_owner, note_value, note_asset, note_blinding, sk) = layouter.assign_region(
            || "note witnesses",
            |mut region| {
                let o = region.assign_advice(|| "owner", config.advice[0], 0, || self.owner)?;
                let v = region.assign_advice(|| "value", config.advice[1], 0, || self.value)?;
                let a = region.assign_advice(|| "asset", config.advice[2], 0, || self.asset_id)?;
                let b = region.assign_advice(|| "blind", config.advice[3], 0, || self.blinding)?;
                let s = region.assign_advice(|| "sk", config.advice[4], 0, || self.spending_key)?;
                Ok((o, v, a, b, s))
            },
        )?;

        let (merkle_path, merkle_bits) = layouter.assign_region(
            || "merkle path",
            |mut region| {
                let mut path = Vec::with_capacity(TREE_DEPTH);
                let mut bits = Vec::with_capacity(TREE_DEPTH);
                for i in 0..TREE_DEPTH {
                    let sib = region.assign_advice(
                        || format!("sib_{i}"),
                        config.advice[0],
                        i,
                        || self.path[i],
                    )?;
                    let bit = region.assign_advice(
                        || format!("bit_{i}"),
                        config.advice[1],
                        i,
                        || self.position[i],
                    )?;
                    path.push(sib);
                    bits.push(bit);
                }
                Ok((path, bits))
            },
        )?;

        let threshold_cell = layouter.assign_region(
            || "threshold witness",
            |mut region| {
                region.assign_advice(|| "threshold", config.advice[0], 0, || self.threshold)
            },
        )?;

        // ── Step 2: Note commitment ──────────────────────────────────

        let cm = note_commitment_gadget(
            &config.poseidon_config,
            layouter.namespace(|| "note_cm"),
            note_owner,
            note_value.clone(),
            note_asset,
            note_blinding,
        )?;

        // ── Step 3: Nullifier ────────────────────────────────────────

        let nf = nullifier_gadget(
            &config.poseidon_config,
            layouter.namespace(|| "nullifier"),
            sk,
            cm.clone(),
        )?;

        // ── Step 4: Merkle membership ────────────────────────────────

        let root = merkle_membership_gadget(
            &config.poseidon_config,
            layouter.namespace(|| "merkle"),
            cm,
            &merkle_path,
            &merkle_bits,
        )?;

        // ── Step 5: Wealth check (value - threshold ≥ 0) ────────────
        //
        // Compute diff = value - threshold and range-check diff to 64 bits.
        // If value < threshold, diff would wrap to a huge field element
        // that cannot fit in 64 bits, causing the range check to fail.

        let diff = layouter.assign_region(
            || "wealth diff",
            |mut region| {
                config.diff_sel.enable(&mut region, 0)?;
                note_value.copy_advice(|| "value", &mut region, config.advice[0], 0)?;
                threshold_cell.copy_advice(|| "threshold", &mut region, config.advice[1], 0)?;
                let diff_val = note_value
                    .value()
                    .zip(threshold_cell.value())
                    .map(|(v, t)| *v - *t);
                region.assign_advice(|| "diff", config.advice[2], 0, || diff_val)
            },
        )?;

        // Range check: diff ∈ [0, 2^64)  →  value ≥ threshold
        range_check_gadget(
            &config.range_config,
            layouter.namespace(|| "range_diff"),
            diff,
            VALUE_BITS,
        )?;

        // Range check the value itself (ensures it's a valid u64)
        range_check_gadget(
            &config.range_config,
            layouter.namespace(|| "range_value"),
            note_value,
            VALUE_BITS,
        )?;

        // Range check threshold (ensures the public input is a valid u64)
        range_check_gadget(
            &config.range_config,
            layouter.namespace(|| "range_threshold"),
            threshold_cell.clone(),
            VALUE_BITS,
        )?;

        // ── Step 6: Expose public inputs ─────────────────────────────

        layouter.constrain_instance(root.cell(), config.instance, 0)?;
        layouter.constrain_instance(nf.cell(), config.instance, 1)?;
        layouter.constrain_instance(threshold_cell.cell(), config.instance, 2)?;

        Ok(())
    }
}

impl WealthProofCircuit {
    /// Create a new wealth proof circuit from concrete values.
    pub fn new(
        spending_key: pallas::Base,
        owner: pallas::Base,
        value: u64,
        asset_id: u64,
        blinding: pallas::Base,
        merkle_path: [pallas::Base; TREE_DEPTH],
        position_bits: [u8; TREE_DEPTH],
        threshold: u64,
    ) -> Self {
        let pos: [Value<pallas::Base>; TREE_DEPTH] = {
            let mut arr = [Value::unknown(); TREE_DEPTH];
            for (i, &b) in position_bits.iter().enumerate() {
                arr[i] = Value::known(if b == 1 {
                    pallas::Base::ONE
                } else {
                    pallas::Base::ZERO
                });
            }
            arr
        };
        let path: [Value<pallas::Base>; TREE_DEPTH] = {
            let mut arr = [Value::unknown(); TREE_DEPTH];
            for (i, &s) in merkle_path.iter().enumerate() {
                arr[i] = Value::known(s);
            }
            arr
        };

        Self {
            spending_key: Value::known(spending_key),
            owner: Value::known(owner),
            value: Value::known(pallas::Base::from(value)),
            asset_id: Value::known(pallas::Base::from(asset_id)),
            blinding: Value::known(blinding),
            path,
            position: pos,
            threshold: Value::known(pallas::Base::from(threshold)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::K_WEALTH;
    use escanorr_note::Note;
    use escanorr_primitives::poseidon::{poseidon_hash_with_domain, DOMAIN_NULLIFIER};
    use escanorr_tree::{IncrementalMerkleTree, TREE_DEPTH};
    use halo2_proofs::dev::MockProver;

    fn native_nullifier(sk: pallas::Base, cm: pallas::Base) -> pallas::Base {
        poseidon_hash_with_domain(DOMAIN_NULLIFIER, sk, cm)
    }

    #[test]
    fn wealth_proof_valid() {
        let sk = pallas::Base::from(42u64);
        let owner = pallas::Base::from(100u64);
        let value = 1000u64;
        let threshold = 500u64;
        let blinding = pallas::Base::from(7u64);

        let note = Note::with_blinding(owner, value, 0, blinding);
        let cm = note.commitment().inner();

        let mut tree = IncrementalMerkleTree::new();
        let idx = tree.insert(cm);
        let root = tree.root();

        let (sibs, pos) = tree.auth_path(idx).unwrap();
        let path: [pallas::Base; TREE_DEPTH] = sibs.try_into().unwrap();
        let pos_bits: [u8; TREE_DEPTH] = pos.try_into().unwrap();

        let nf = native_nullifier(sk, cm);

        let circuit = WealthProofCircuit::new(
            sk, owner, value, 0, blinding, path, pos_bits, threshold,
        );

        let public_inputs = vec![root, nf, pallas::Base::from(threshold)];
        let prover = MockProver::run(K_WEALTH, &circuit, vec![public_inputs]).unwrap();
        prover.verify().unwrap();
    }

    #[test]
    fn wealth_proof_exact_threshold() {
        // value == threshold should pass (≥, not just >)
        let sk = pallas::Base::from(99u64);
        let owner = pallas::Base::from(200u64);
        let value = 500u64;
        let threshold = 500u64;
        let blinding = pallas::Base::from(13u64);

        let note = Note::with_blinding(owner, value, 0, blinding);
        let cm = note.commitment().inner();

        let mut tree = IncrementalMerkleTree::new();
        let idx = tree.insert(cm);
        let root = tree.root();

        let (sibs, pos) = tree.auth_path(idx).unwrap();
        let path: [pallas::Base; TREE_DEPTH] = sibs.try_into().unwrap();
        let pos_bits: [u8; TREE_DEPTH] = pos.try_into().unwrap();

        let nf = native_nullifier(sk, cm);

        let circuit = WealthProofCircuit::new(
            sk, owner, value, 0, blinding, path, pos_bits, threshold,
        );

        let public_inputs = vec![root, nf, pallas::Base::from(threshold)];
        let prover = MockProver::run(K_WEALTH, &circuit, vec![public_inputs]).unwrap();
        prover.verify().unwrap();
    }

    #[test]
    fn wealth_proof_below_threshold_fails() {
        // value < threshold should fail the range check
        let sk = pallas::Base::from(55u64);
        let owner = pallas::Base::from(300u64);
        let value = 100u64;
        let threshold = 500u64;
        let blinding = pallas::Base::from(19u64);

        let note = Note::with_blinding(owner, value, 0, blinding);
        let cm = note.commitment().inner();

        let mut tree = IncrementalMerkleTree::new();
        let idx = tree.insert(cm);
        let root = tree.root();

        let (sibs, pos) = tree.auth_path(idx).unwrap();
        let path: [pallas::Base; TREE_DEPTH] = sibs.try_into().unwrap();
        let pos_bits: [u8; TREE_DEPTH] = pos.try_into().unwrap();

        let nf = native_nullifier(sk, cm);

        let circuit = WealthProofCircuit::new(
            sk, owner, value, 0, blinding, path, pos_bits, threshold,
        );

        let public_inputs = vec![root, nf, pallas::Base::from(threshold)];
        let prover = MockProver::run(K_WEALTH, &circuit, vec![public_inputs]).unwrap();
        // Should fail: value - threshold wraps in the field, range check fails
        assert!(prover.verify().is_err());
    }
}
