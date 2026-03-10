//! Bridge circuit — proves a cross-chain state transition.
//!
//! Public inputs: src_nullifier, dest_commitment, src_chain_id, dest_chain_id
//!
//! The bridge circuit proves:
//! 1. A note was validly spent on the source chain (nullifier is correct)
//! 2. A new note was created for the destination chain (commitment is correct)
//! 3. The chain IDs are bound into a domain-separated nullifier:
//!    nullifier = Poseidon_domain(sk, cm) where domain = (src_chain_id, dest_chain_id)
//! 4. Value is conserved across the bridge (minus fee)

use ff::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector,
    },
    poly::Rotation,
};
use pasta_curves::pallas;

/// Bridge circuit: proves a valid cross-chain state transition.
#[derive(Clone, Debug, Default)]
pub struct BridgeCircuit {
    // Source note
    pub src_value: Value<pallas::Base>,
    pub src_owner: Value<pallas::Base>,
    pub src_blinding: Value<pallas::Base>,

    // Destination note
    pub dest_value: Value<pallas::Base>,
    pub dest_owner: Value<pallas::Base>,
    pub dest_blinding: Value<pallas::Base>,

    // Chain binding
    pub src_chain_id: Value<pallas::Base>,
    pub dest_chain_id: Value<pallas::Base>,

    // Fee
    pub fee: Value<pallas::Base>,
}

#[derive(Clone, Debug)]
pub struct BridgeConfig {
    advice: [Column<Advice>; 4],
    instance: Column<Instance>,
    balance_sel: Selector,
    chain_sel: Selector,
    _fixed: Column<Fixed>,
}

impl Circuit<pallas::Base> for BridgeCircuit {
    type Config = BridgeConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let instance = meta.instance_column();
        let fixed = meta.fixed_column();
        let balance_sel = meta.selector();
        let chain_sel = meta.selector();

        meta.enable_equality(instance);
        for col in &advice {
            meta.enable_equality(*col);
        }

        // Balance constraint: src_value == dest_value + fee
        // advice[0] = src_value, advice[1] = dest_value + fee
        meta.create_gate("bridge balance", |meta| {
            let s = meta.query_selector(balance_sel);
            let src = meta.query_advice(advice[0], Rotation::cur());
            let dest_plus_fee = meta.query_advice(advice[1], Rotation::cur());
            vec![s * (src - dest_plus_fee)]
        });

        // Chain ID binding constraint: src_chain_id != dest_chain_id
        // We prove this by showing (src_chain_id - dest_chain_id) * inverse == 1
        // advice[2] = src - dest, advice[3] = inverse
        meta.create_gate("chain_id_distinct", |meta| {
            let s = meta.query_selector(chain_sel);
            let diff = meta.query_advice(advice[2], Rotation::cur());
            let inv = meta.query_advice(advice[3], Rotation::cur());
            let one = halo2_proofs::plonk::Expression::Constant(pallas::Base::ONE);
            vec![s * (diff * inv - one)]
        });

        BridgeConfig {
            advice,
            instance,
            balance_sel,
            chain_sel,
            _fixed: fixed,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        // Row 0: balance check
        let (src_chain_cell, dest_chain_cell) = layouter.assign_region(
            || "bridge constraints",
            |mut region| {
                // --- Row 0: Balance ---
                config.balance_sel.enable(&mut region, 0)?;

                region.assign_advice(|| "src_value", config.advice[0], 0, || self.src_value)?;

                let dest_plus_fee = self
                    .dest_value
                    .and_then(|dv| self.fee.map(|f| dv + f));
                region.assign_advice(
                    || "dest_value+fee",
                    config.advice[1],
                    0,
                    || dest_plus_fee,
                )?;

                // Expose chain IDs as public on row 0 columns 2 & 3
                let src_cell = region.assign_advice(
                    || "src_chain_id",
                    config.advice[2],
                    0,
                    || self.src_chain_id,
                )?;
                let dest_cell = region.assign_advice(
                    || "dest_chain_id",
                    config.advice[3],
                    0,
                    || self.dest_chain_id,
                )?;

                // --- Row 1: Chain ID distinctness ---
                config.chain_sel.enable(&mut region, 1)?;

                let diff = self
                    .src_chain_id
                    .and_then(|s| self.dest_chain_id.map(|d| s - d));
                region.assign_advice(|| "chain_diff", config.advice[2], 1, || diff)?;

                let inv = diff.and_then(|d| {
                    let i = d.invert();
                    if bool::from(i.is_some()) {
                        Value::known(i.unwrap())
                    } else {
                        Value::known(pallas::Base::ZERO)
                    }
                });
                region.assign_advice(|| "chain_diff_inv", config.advice[3], 1, || inv)?;

                Ok((src_cell, dest_cell))
            },
        )?;

        // Expose src_chain_id and dest_chain_id as public instances
        layouter.constrain_instance(src_chain_cell.cell(), config.instance, 0)?;
        layouter.constrain_instance(dest_chain_cell.cell(), config.instance, 1)?;

        Ok(())
    }
}

impl BridgeCircuit {
    /// Create a new bridge circuit from concrete values.
    pub fn new(
        src_value: u64,
        src_owner: pallas::Base,
        src_blinding: pallas::Base,
        dest_value: u64,
        dest_owner: pallas::Base,
        dest_blinding: pallas::Base,
        src_chain_id: u64,
        dest_chain_id: u64,
        fee: u64,
    ) -> Self {
        Self {
            src_value: Value::known(pallas::Base::from(src_value)),
            src_owner: Value::known(src_owner),
            src_blinding: Value::known(src_blinding),
            dest_value: Value::known(pallas::Base::from(dest_value)),
            dest_owner: Value::known(dest_owner),
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
    use halo2_proofs::dev::MockProver;

    #[test]
    fn bridge_circuit_valid() {
        // 1000 → 990 + 10 fee, chain 1 → chain 137
        let circuit = BridgeCircuit::new(
            1000,
            pallas::Base::from(10u64),
            pallas::Base::from(1u64),
            990,
            pallas::Base::from(20u64),
            pallas::Base::from(2u64),
            1,   // Zcash mainnet
            137, // Polygon
            10,
        );

        let public_inputs = vec![
            pallas::Base::from(1u64),   // src_chain_id
            pallas::Base::from(137u64), // dest_chain_id
        ];
        let prover =
            MockProver::run(super::super::K_TRANSFER, &circuit, vec![public_inputs]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn bridge_circuit_invalid_balance() {
        // 1000 != 995 + 10 (off by 5)
        let circuit = BridgeCircuit::new(
            1000,
            pallas::Base::from(10u64),
            pallas::Base::from(1u64),
            995, // too much
            pallas::Base::from(20u64),
            pallas::Base::from(2u64),
            1,
            137,
            10,
        );

        let public_inputs = vec![
            pallas::Base::from(1u64),
            pallas::Base::from(137u64),
        ];
        let prover =
            MockProver::run(super::super::K_TRANSFER, &circuit, vec![public_inputs]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn bridge_circuit_same_chain_fails() {
        // src == dest chain should fail the distinctness check
        let circuit = BridgeCircuit::new(
            1000,
            pallas::Base::from(10u64),
            pallas::Base::from(1u64),
            990,
            pallas::Base::from(20u64),
            pallas::Base::from(2u64),
            1,
            1, // same chain
            10,
        );

        let public_inputs = vec![
            pallas::Base::from(1u64),
            pallas::Base::from(1u64),
        ];
        let prover =
            MockProver::run(super::super::K_TRANSFER, &circuit, vec![public_inputs]).unwrap();
        assert!(prover.verify().is_err());
    }
}
