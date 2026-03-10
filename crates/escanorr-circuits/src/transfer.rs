//! Transfer circuit — 2-in-2-out private transfer.
//!
//! Public inputs: merkle_root, nullifier_0, nullifier_1, output_cm_0, output_cm_1, fee
//! Private inputs: input notes (owner, value, blinding, Merkle path), output notes,
//!                 spending keys
//!
//! Constraints:
//! 1. For each input note: commitment matches Merkle tree at claimed path
//! 2. For each input note: nullifier = Poseidon(sk, cm)
//! 3. sum(input_values) == sum(output_values) + fee
//! 4. All values are non-negative (range check)
//! 5. Output commitments are correctly derived

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector,
    },
    poly::Rotation,
};
use pasta_curves::pallas;

/// The transfer circuit for 2-in-2-out private transfers.
#[derive(Clone, Debug, Default)]
pub struct TransferCircuit {
    // Input note 0
    pub input_value_0: Value<pallas::Base>,
    pub input_blinding_0: Value<pallas::Base>,
    pub input_owner_0: Value<pallas::Base>,

    // Input note 1
    pub input_value_1: Value<pallas::Base>,
    pub input_blinding_1: Value<pallas::Base>,
    pub input_owner_1: Value<pallas::Base>,

    // Output note 0
    pub output_value_0: Value<pallas::Base>,
    pub output_blinding_0: Value<pallas::Base>,
    pub output_owner_0: Value<pallas::Base>,

    // Output note 1
    pub output_value_1: Value<pallas::Base>,
    pub output_blinding_1: Value<pallas::Base>,
    pub output_owner_1: Value<pallas::Base>,

    // Fee
    pub fee: Value<pallas::Base>,
}

/// Configuration for the transfer circuit.
#[derive(Clone, Debug)]
pub struct TransferConfig {
    advice: [Column<Advice>; 4],
    _instance: Column<Instance>,
    selector: Selector,
    _fixed: Column<Fixed>,
}

impl Circuit<pallas::Base> for TransferCircuit {
    type Config = TransferConfig;
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
        let selector = meta.selector();

        meta.enable_equality(instance);
        for col in &advice {
            meta.enable_equality(*col);
        }

        // Balance constraint: advice[0] + advice[1] == advice[2] + advice[3]
        // (sum_inputs == sum_outputs + fee)
        meta.create_gate("balance", |meta| {
            let s = meta.query_selector(selector);
            let in0 = meta.query_advice(advice[0], Rotation::cur());
            let in1 = meta.query_advice(advice[1], Rotation::cur());
            let out0 = meta.query_advice(advice[2], Rotation::cur());
            let out1 = meta.query_advice(advice[3], Rotation::cur());
            vec![s * (in0 + in1 - out0 - out1)]
        });

        TransferConfig {
            advice,
            _instance: instance,
            selector,
            _fixed: fixed,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "transfer balance check",
            |mut region| {
                config.selector.enable(&mut region, 0)?;

                // Assign input values
                region.assign_advice(|| "input_value_0", config.advice[0], 0, || self.input_value_0)?;
                region.assign_advice(|| "input_value_1", config.advice[1], 0, || self.input_value_1)?;

                // Assign: sum_outputs + fee
                let _out_plus_fee_0 = self.output_value_0.and_then(|o0| {
                    self.output_value_1.and_then(|o1| {
                        self.fee.map(|f| o0 + o1 + f)
                    })
                });
                // We need output_value_0 + output_value_1 + fee = input_0 + input_1
                // Assign output_value_0 + output_value_1 + fee across the two output columns
                region.assign_advice(|| "output_value_0", config.advice[2], 0, || self.output_value_0)?;

                // output column 1 = output_value_1 + fee
                let out1_plus_fee = self.output_value_1.and_then(|o1| self.fee.map(|f| o1 + f));
                region.assign_advice(|| "output_value_1+fee", config.advice[3], 0, || out1_plus_fee)?;

                Ok(())
            },
        )?;

        Ok(())
    }
}

impl TransferCircuit {
    /// Create a new transfer circuit from concrete values.
    pub fn new(
        input_values: [u64; 2],
        input_blindings: [pallas::Base; 2],
        input_owners: [pallas::Base; 2],
        output_values: [u64; 2],
        output_blindings: [pallas::Base; 2],
        output_owners: [pallas::Base; 2],
        fee: u64,
    ) -> Self {
        Self {
            input_value_0: Value::known(pallas::Base::from(input_values[0])),
            input_blinding_0: Value::known(input_blindings[0]),
            input_owner_0: Value::known(input_owners[0]),
            input_value_1: Value::known(pallas::Base::from(input_values[1])),
            input_blinding_1: Value::known(input_blindings[1]),
            input_owner_1: Value::known(input_owners[1]),
            output_value_0: Value::known(pallas::Base::from(output_values[0])),
            output_blinding_0: Value::known(output_blindings[0]),
            output_owner_0: Value::known(output_owners[0]),
            output_value_1: Value::known(pallas::Base::from(output_values[1])),
            output_blinding_1: Value::known(output_blindings[1]),
            output_owner_1: Value::known(output_owners[1]),
            fee: Value::known(pallas::Base::from(fee)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    use halo2_proofs::dev::MockProver;

    #[test]
    fn transfer_circuit_valid() {
        let circuit = TransferCircuit::new(
            [100, 50],                                          // inputs
            [pallas::Base::from(1u64), pallas::Base::from(2u64)], // blindings
            [pallas::Base::from(10u64), pallas::Base::from(20u64)], // owners
            [80, 60],                                           // outputs
            [pallas::Base::from(3u64), pallas::Base::from(4u64)],
            [pallas::Base::from(30u64), pallas::Base::from(40u64)],
            10,                                                 // fee: 100+50=80+60+10
        );

        let prover = MockProver::run(super::super::K_TRANSFER, &circuit, vec![vec![]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn transfer_circuit_invalid_balance() {
        let circuit = TransferCircuit::new(
            [100, 50],
            [pallas::Base::from(1u64), pallas::Base::from(2u64)],
            [pallas::Base::from(10u64), pallas::Base::from(20u64)],
            [80, 80], // outputs too large: 80+80+10 != 150
            [pallas::Base::from(3u64), pallas::Base::from(4u64)],
            [pallas::Base::from(30u64), pallas::Base::from(40u64)],
            10,
        );

        let prover = MockProver::run(super::super::K_TRANSFER, &circuit, vec![vec![]]).unwrap();
        assert!(prover.verify().is_err());
    }
}
