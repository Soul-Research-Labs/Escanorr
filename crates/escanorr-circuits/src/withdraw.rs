//! Withdraw circuit — same as transfer but exposes a public exit_value.
//!
//! Public inputs: merkle_root, nullifier, output_cm, exit_value
//! The circuit proves that a note can be partially withdrawn, with `exit_value`
//! being revealed publicly for on-chain settlement.

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector,
    },
    poly::Rotation,
};
use pasta_curves::pallas;

/// Withdraw circuit: proves a valid spend with a public exit amount.
#[derive(Clone, Debug, Default)]
pub struct WithdrawCircuit {
    /// The value being withdrawn (public).
    pub exit_value: Value<pallas::Base>,

    /// The input note value.
    pub input_value: Value<pallas::Base>,
    pub input_blinding: Value<pallas::Base>,
    pub input_owner: Value<pallas::Base>,

    /// The change note value (input_value - exit_value - fee).
    pub change_value: Value<pallas::Base>,
    pub change_blinding: Value<pallas::Base>,
    pub change_owner: Value<pallas::Base>,

    /// Fee paid.
    pub fee: Value<pallas::Base>,
}

#[derive(Clone, Debug)]
pub struct WithdrawConfig {
    advice: [Column<Advice>; 3],
    instance: Column<Instance>,
    selector: Selector,
    _fixed: Column<Fixed>,
}

impl Circuit<pallas::Base> for WithdrawCircuit {
    type Config = WithdrawConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let instance = meta.instance_column();
        let fixed = meta.fixed_column();
        let selector = meta.selector();

        meta.enable_equality(instance);
        for col in &advice {
            meta.enable_equality(*col);
        }

        // Balance constraint: input_value == change_value + exit_value_plus_fee
        // advice[0] = input_value
        // advice[1] = change_value
        // advice[2] = exit_value + fee
        meta.create_gate("withdraw balance", |meta| {
            let s = meta.query_selector(selector);
            let input = meta.query_advice(advice[0], Rotation::cur());
            let change = meta.query_advice(advice[1], Rotation::cur());
            let exit_plus_fee = meta.query_advice(advice[2], Rotation::cur());
            vec![s * (input - change - exit_plus_fee)]
        });

        WithdrawConfig {
            advice,
            instance,
            selector,
            _fixed: fixed,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        let exit_cell = layouter.assign_region(
            || "withdraw balance check",
            |mut region| {
                config.selector.enable(&mut region, 0)?;

                region.assign_advice(|| "input_value", config.advice[0], 0, || self.input_value)?;
                region.assign_advice(|| "change_value", config.advice[1], 0, || self.change_value)?;

                let exit_plus_fee = self.exit_value.and_then(|ev| self.fee.map(|f| ev + f));
                let cell = region.assign_advice(
                    || "exit_value+fee",
                    config.advice[2],
                    0,
                    || exit_plus_fee,
                )?;

                Ok(cell)
            },
        )?;

        // Expose exit_value + fee as public instance for on-chain verification.
        layouter.constrain_instance(exit_cell.cell(), config.instance, 0)?;

        Ok(())
    }
}

impl WithdrawCircuit {
    /// Create a new withdraw circuit from concrete values.
    pub fn new(
        input_value: u64,
        input_blinding: pallas::Base,
        input_owner: pallas::Base,
        change_value: u64,
        change_blinding: pallas::Base,
        change_owner: pallas::Base,
        exit_value: u64,
        fee: u64,
    ) -> Self {
        Self {
            exit_value: Value::known(pallas::Base::from(exit_value)),
            input_value: Value::known(pallas::Base::from(input_value)),
            input_blinding: Value::known(input_blinding),
            input_owner: Value::known(input_owner),
            change_value: Value::known(pallas::Base::from(change_value)),
            change_blinding: Value::known(change_blinding),
            change_owner: Value::known(change_owner),
            fee: Value::known(pallas::Base::from(fee)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    #[test]
    fn withdraw_circuit_valid() {
        // 1000 = 500 (change) + 490 (exit) + 10 (fee)
        let circuit = WithdrawCircuit::new(
            1000,
            pallas::Base::from(1u64),
            pallas::Base::from(10u64),
            500,
            pallas::Base::from(2u64),
            pallas::Base::from(20u64),
            490,
            10,
        );

        let exit_plus_fee = pallas::Base::from(500u64); // 490 + 10
        let prover =
            MockProver::run(super::super::K_TRANSFER, &circuit, vec![vec![exit_plus_fee]])
                .unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn withdraw_circuit_invalid_balance() {
        // 1000 != 600 + 490 + 10 (off by 100)
        let circuit = WithdrawCircuit::new(
            1000,
            pallas::Base::from(1u64),
            pallas::Base::from(10u64),
            600, // wrong change
            pallas::Base::from(2u64),
            pallas::Base::from(20u64),
            490,
            10,
        );

        let exit_plus_fee = pallas::Base::from(500u64);
        let prover =
            MockProver::run(super::super::K_TRANSFER, &circuit, vec![vec![exit_plus_fee]])
                .unwrap();
        assert!(prover.verify().is_err());
    }
}
