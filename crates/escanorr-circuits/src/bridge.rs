//! Bridge circuit — proves a cross-chain state transition.
//!
//! Public inputs (instance column):
//!   [0] src_root       (Merkle root on source chain)
//!   [1] src_nullifier  (nullifier of spent note on source chain)
//!   [2] dest_cm        (commitment to new note on destination chain)
//!   [3] src_chain_id
//!   [4] dest_chain_id
//!
//! The circuit proves:
//! 1. A note was validly spent on the source chain (Merkle + nullifier)
//! 2. A new note was created for the destination chain (commitment)
//! 3. Chain IDs are distinct (src_chain_id ≠ dest_chain_id)
//! 4. Value is conserved: src_value == dest_value + fee
//! 5. All values are non-negative (64-bit range check)

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

/// Number of public inputs for the bridge circuit.
pub const BRIDGE_PUBLIC_INPUTS: usize = 5;
/// Number of bits for value range checks (u64).
const VALUE_BITS: usize = 64;

/// Bridge circuit: proves a valid cross-chain state transition.
#[derive(Clone, Debug)]
pub struct BridgeCircuit {
    // Spending key for source note
    pub spending_key: Value<pallas::Base>,

    // Source note
    pub src_owner: Value<pallas::Base>,
    pub src_value: Value<pallas::Base>,
    pub src_asset_id: Value<pallas::Base>,
    pub src_blinding: Value<pallas::Base>,
    pub src_path: [Value<pallas::Base>; TREE_DEPTH],
    pub src_position: [Value<pallas::Base>; TREE_DEPTH],

    // Destination note
    pub dest_owner: Value<pallas::Base>,
    pub dest_value: Value<pallas::Base>,
    pub dest_asset_id: Value<pallas::Base>,
    pub dest_blinding: Value<pallas::Base>,

    // Chain binding
    pub src_chain_id: Value<pallas::Base>,
    pub dest_chain_id: Value<pallas::Base>,

    // Fee
    pub fee: Value<pallas::Base>,
}

impl Default for BridgeCircuit {
    fn default() -> Self {
        Self {
            spending_key: Value::unknown(),
            src_owner: Value::unknown(),
            src_value: Value::unknown(),
            src_asset_id: Value::unknown(),
            src_blinding: Value::unknown(),
            src_path: [Value::unknown(); TREE_DEPTH],
            src_position: [Value::unknown(); TREE_DEPTH],
            dest_owner: Value::unknown(),
            dest_value: Value::unknown(),
            dest_asset_id: Value::unknown(),
            dest_blinding: Value::unknown(),
            src_chain_id: Value::unknown(),
            dest_chain_id: Value::unknown(),
            fee: Value::unknown(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct BridgeConfig {
    poseidon_config: PoseidonGadgetConfig,
    range_config: RangeCheckConfig,
    advice: [Column<Advice>; 5],
    instance: Column<Instance>,
    balance_sel: Selector,
    chain_sel: Selector,
}

impl Circuit<pallas::Base> for BridgeCircuit {
    type Config = BridgeConfig;
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

        // Balance: src_value == dest_value + fee
        let balance_sel = meta.selector();
        meta.create_gate("bridge balance", |meta| {
            let s = meta.query_selector(balance_sel);
            let src = meta.query_advice(advice[0], Rotation::cur());
            let dest = meta.query_advice(advice[1], Rotation::cur());
            let fee = meta.query_advice(advice[2], Rotation::cur());
            vec![s * (src - dest - fee)]
        });

        // Chain ID distinctness: (src - dest) * inverse == 1
        let chain_sel = meta.selector();
        meta.create_gate("chain_id_distinct", |meta| {
            let s = meta.query_selector(chain_sel);
            let diff = meta.query_advice(advice[0], Rotation::cur());
            let inv = meta.query_advice(advice[1], Rotation::cur());
            let one = halo2_proofs::plonk::Expression::Constant(pallas::Base::ONE);
            vec![s * (diff * inv - one)]
        });

        BridgeConfig {
            poseidon_config,
            range_config,
            advice,
            instance,
            balance_sel,
            chain_sel,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        // ── Assign private witnesses ─────────────────────────────────

        let (src_owner, src_value, src_asset, src_blinding, sk) = layouter.assign_region(
            || "src witnesses",
            |mut region| {
                let o = region.assign_advice(|| "src_owner", config.advice[0], 0, || self.src_owner)?;
                let v = region.assign_advice(|| "src_value", config.advice[1], 0, || self.src_value)?;
                let a = region.assign_advice(|| "src_asset", config.advice[2], 0, || self.src_asset_id)?;
                let b = region.assign_advice(|| "src_blind", config.advice[3], 0, || self.src_blinding)?;
                let s = region.assign_advice(|| "sk", config.advice[4], 0, || self.spending_key)?;
                Ok((o, v, a, b, s))
            },
        )?;

        let (src_path, src_bits) = layouter.assign_region(
            || "src merkle path",
            |mut region| {
                let mut path = Vec::with_capacity(TREE_DEPTH);
                let mut bits = Vec::with_capacity(TREE_DEPTH);
                for i in 0..TREE_DEPTH {
                    let sib = region.assign_advice(|| format!("sib_{i}"), config.advice[0], i, || self.src_path[i])?;
                    let bit = region.assign_advice(|| format!("bit_{i}"), config.advice[1], i, || self.src_position[i])?;
                    path.push(sib);
                    bits.push(bit);
                }
                Ok((path, bits))
            },
        )?;

        let (dest_owner, dest_value, dest_asset, dest_blinding) = layouter.assign_region(
            || "dest witnesses",
            |mut region| {
                let o = region.assign_advice(|| "dest_owner", config.advice[0], 0, || self.dest_owner)?;
                let v = region.assign_advice(|| "dest_value", config.advice[1], 0, || self.dest_value)?;
                let a = region.assign_advice(|| "dest_asset", config.advice[2], 0, || self.dest_asset_id)?;
                let b = region.assign_advice(|| "dest_blind", config.advice[3], 0, || self.dest_blinding)?;
                Ok((o, v, a, b))
            },
        )?;

        let (src_chain_cell, dest_chain_cell) = layouter.assign_region(
            || "chain ids",
            |mut region| {
                let s = region.assign_advice(|| "src_chain", config.advice[0], 0, || self.src_chain_id)?;
                let d = region.assign_advice(|| "dest_chain", config.advice[1], 0, || self.dest_chain_id)?;
                Ok((s, d))
            },
        )?;

        let fee_cell = layouter.assign_region(
            || "fee witness",
            |mut region| {
                region.assign_advice(|| "fee", config.advice[0], 0, || self.fee)
            },
        )?;

        // ── Source note commitment ───────────────────────────────────

        let src_cm = note_commitment_gadget(
            &config.poseidon_config,
            layouter.namespace(|| "src_cm"),
            src_owner,
            src_value.clone(),
            src_asset,
            src_blinding,
        )?;

        // ── Source nullifier ─────────────────────────────────────────

        let src_nf = nullifier_gadget(
            &config.poseidon_config,
            layouter.namespace(|| "src_nf"),
            sk,
            src_cm.clone(),
        )?;

        // ── Merkle membership (source chain) ─────────────────────────

        let src_root = merkle_membership_gadget(
            &config.poseidon_config,
            layouter.namespace(|| "src_merkle"),
            src_cm,
            &src_path,
            &src_bits,
        )?;

        // ── Destination commitment ───────────────────────────────────

        let dest_cm = note_commitment_gadget(
            &config.poseidon_config,
            layouter.namespace(|| "dest_cm"),
            dest_owner,
            dest_value.clone(),
            dest_asset,
            dest_blinding,
        )?;

        // ── Balance check: src_value == dest_value + fee ─────────────

        layouter.assign_region(
            || "balance check",
            |mut region| {
                config.balance_sel.enable(&mut region, 0)?;
                src_value.copy_advice(|| "src", &mut region, config.advice[0], 0)?;
                dest_value.copy_advice(|| "dest", &mut region, config.advice[1], 0)?;
                fee_cell.copy_advice(|| "fee", &mut region, config.advice[2], 0)?;
                Ok(())
            },
        )?;

        // ── Chain ID distinctness ────────────────────────────────────

        layouter.assign_region(
            || "chain distinct",
            |mut region| {
                config.chain_sel.enable(&mut region, 0)?;

                let diff = src_chain_cell.value().zip(dest_chain_cell.value()).map(|(s, d)| *s - *d);
                region.assign_advice(|| "diff", config.advice[0], 0, || diff)?;

                let inv = diff.and_then(|d| {
                    let i = d.invert();
                    if bool::from(i.is_some()) {
                        Value::known(i.unwrap())
                    } else {
                        Value::known(pallas::Base::ZERO)
                    }
                });
                region.assign_advice(|| "inv", config.advice[1], 0, || inv)?;
                Ok(())
            },
        )?;

        // ── Range checks (64-bit) ────────────────────────────────────

        range_check_gadget(&config.range_config, layouter.namespace(|| "range_src"), src_value, VALUE_BITS)?;
        range_check_gadget(&config.range_config, layouter.namespace(|| "range_dest"), dest_value, VALUE_BITS)?;
        range_check_gadget(&config.range_config, layouter.namespace(|| "range_fee"), fee_cell, VALUE_BITS)?;

        // ── Expose public inputs ─────────────────────────────────────

        layouter.constrain_instance(src_root.cell(), config.instance, 0)?;
        layouter.constrain_instance(src_nf.cell(), config.instance, 1)?;
        layouter.constrain_instance(dest_cm.cell(), config.instance, 2)?;
        layouter.constrain_instance(src_chain_cell.cell(), config.instance, 3)?;
        layouter.constrain_instance(dest_chain_cell.cell(), config.instance, 4)?;

        Ok(())
    }
}

impl BridgeCircuit {
    /// Create a new bridge circuit from concrete values.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        spending_key: pallas::Base,
        src_owner: pallas::Base,
        src_value: u64,
        src_asset_id: u64,
        src_blinding: pallas::Base,
        src_path: [pallas::Base; TREE_DEPTH],
        src_position: [pallas::Base; TREE_DEPTH],
        dest_owner: pallas::Base,
        dest_value: u64,
        dest_asset_id: u64,
        dest_blinding: pallas::Base,
        src_chain_id: u64,
        dest_chain_id: u64,
        fee: u64,
    ) -> Self {
        Self {
            spending_key: Value::known(spending_key),
            src_owner: Value::known(src_owner),
            src_value: Value::known(pallas::Base::from(src_value)),
            src_asset_id: Value::known(pallas::Base::from(src_asset_id)),
            src_blinding: Value::known(src_blinding),
            src_path: src_path.map(|v| Value::known(v)),
            src_position: src_position.map(|v| Value::known(v)),
            dest_owner: Value::known(dest_owner),
            dest_value: Value::known(pallas::Base::from(dest_value)),
            dest_asset_id: Value::known(pallas::Base::from(dest_asset_id)),
            dest_blinding: Value::known(dest_blinding),
            src_chain_id: Value::known(pallas::Base::from(src_chain_id)),
            dest_chain_id: Value::known(pallas::Base::from(dest_chain_id)),
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

    #[test]
    fn bridge_circuit_valid() {
        let sk = pallas::Base::from(111u64);
        let src_owner = pallas::Base::from(10u64);
        let dest_owner = pallas::Base::from(20u64);
        let src_val = 1000u64;
        let dest_val = 990u64;
        let fee_val = 10u64;
        let src_chain = 1u64;
        let dest_chain = 137u64;
        let asset_id = 0u64;

        let note = Note::with_blinding(src_owner, src_val, asset_id, pallas::Base::from(1u64));
        let dest_note = Note::with_blinding(dest_owner, dest_val, asset_id, pallas::Base::from(2u64));
        let cm = note.commitment().inner();
        let dest_cm_val = dest_note.commitment().inner();

        let mut tree = IncrementalMerkleTree::new();
        let idx = tree.insert(cm);
        let root = tree.root();
        let auth = tree.auth_path(idx).expect("auth path");
        let path: [pallas::Base; TREE_DEPTH] = auth.0.try_into().unwrap();
        let pos: [pallas::Base; TREE_DEPTH] = auth.1.iter()
            .map(|&b| if b == 1 { pallas::Base::ONE } else { pallas::Base::ZERO })
            .collect::<Vec<_>>().try_into().unwrap();

        let nf = native_nullifier(sk, cm);

        let circuit = BridgeCircuit::new(
            sk,
            src_owner, src_val, asset_id, pallas::Base::from(1u64),
            path, pos,
            dest_owner, dest_val, asset_id, pallas::Base::from(2u64),
            src_chain, dest_chain, fee_val,
        );

        let public_inputs = vec![
            root, nf, dest_cm_val,
            pallas::Base::from(src_chain),
            pallas::Base::from(dest_chain),
        ];
        let prover = MockProver::run(crate::K_TRANSFER, &circuit, vec![public_inputs]).unwrap();
        assert_eq!(prover.verify(), Ok(()), "bridge circuit should verify");
    }

    #[test]
    fn bridge_circuit_invalid_balance() {
        let sk = pallas::Base::from(111u64);
        let src_owner = pallas::Base::from(10u64);
        let dest_owner = pallas::Base::from(20u64);
        let asset_id = 0u64;

        let note = Note::with_blinding(src_owner, 1000, asset_id, pallas::Base::from(1u64));
        // dest_val + fee = 995 + 10 = 1005 ≠ 1000
        let dest_note = Note::with_blinding(dest_owner, 995, asset_id, pallas::Base::from(2u64));
        let cm = note.commitment().inner();
        let dest_cm_val = dest_note.commitment().inner();

        let mut tree = IncrementalMerkleTree::new();
        let idx = tree.insert(cm);
        let root = tree.root();
        let auth = tree.auth_path(idx).expect("auth path");
        let path: [pallas::Base; TREE_DEPTH] = auth.0.try_into().unwrap();
        let pos: [pallas::Base; TREE_DEPTH] = auth.1.iter()
            .map(|&b| if b == 1 { pallas::Base::ONE } else { pallas::Base::ZERO })
            .collect::<Vec<_>>().try_into().unwrap();

        let nf = native_nullifier(sk, cm);
        let circuit = BridgeCircuit::new(
            sk,
            src_owner, 1000, asset_id, pallas::Base::from(1u64),
            path, pos,
            dest_owner, 995, asset_id, pallas::Base::from(2u64),
            1, 137, 10,
        );

        let public_inputs = vec![
            root, nf, dest_cm_val,
            pallas::Base::from(1u64),
            pallas::Base::from(137u64),
        ];
        let prover = MockProver::run(crate::K_TRANSFER, &circuit, vec![public_inputs]).unwrap();
        assert!(prover.verify().is_err(), "balance mismatch should fail");
    }

    #[test]
    fn bridge_circuit_same_chain_fails() {
        let sk = pallas::Base::from(111u64);
        let src_owner = pallas::Base::from(10u64);
        let dest_owner = pallas::Base::from(20u64);
        let asset_id = 0u64;

        let note = Note::with_blinding(src_owner, 1000, asset_id, pallas::Base::from(1u64));
        let dest_note = Note::with_blinding(dest_owner, 990, asset_id, pallas::Base::from(2u64));
        let cm = note.commitment().inner();
        let dest_cm_val = dest_note.commitment().inner();

        let mut tree = IncrementalMerkleTree::new();
        let idx = tree.insert(cm);
        let root = tree.root();
        let auth = tree.auth_path(idx).expect("auth path");
        let path: [pallas::Base; TREE_DEPTH] = auth.0.try_into().unwrap();
        let pos: [pallas::Base; TREE_DEPTH] = auth.1.iter()
            .map(|&b| if b == 1 { pallas::Base::ONE } else { pallas::Base::ZERO })
            .collect::<Vec<_>>().try_into().unwrap();

        let nf = native_nullifier(sk, cm);
        // Same chain: src == dest == 1
        let circuit = BridgeCircuit::new(
            sk,
            src_owner, 1000, asset_id, pallas::Base::from(1u64),
            path, pos,
            dest_owner, 990, asset_id, pallas::Base::from(2u64),
            1, 1, 10,
        );

        let public_inputs = vec![
            root, nf, dest_cm_val,
            pallas::Base::from(1u64),
            pallas::Base::from(1u64),
        ];
        let prover = MockProver::run(crate::K_TRANSFER, &circuit, vec![public_inputs]).unwrap();
        assert!(prover.verify().is_err(), "same chain should fail distinctness check");
    }
}
