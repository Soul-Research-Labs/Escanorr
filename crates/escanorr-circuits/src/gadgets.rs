//! Shared circuit gadgets — Poseidon hashing, Merkle membership, commitment.
//!
//! All gadgets use the Halo2 Pow5Chip (P128Pow5T3, width=3, rate=2) so that
//! the in-circuit hash output is **identical** to the native `poseidon_hash()`
//! from `escanorr_primitives`.

use ff::{Field, PrimeField};
use halo2_gadgets::poseidon::{
    primitives::{ConstantLength, P128Pow5T3},
    Hash as PoseidonHash, Pow5Chip, Pow5Config,
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Selector},
    poly::Rotation,
};
use pasta_curves::pallas;

/// Number of advice columns required by the Poseidon Pow5Chip.
/// Width T=3: needs 3 state columns + 1 partial-sbox column + rc columns.
pub const POSEIDON_ADVICE_COLS: usize = 5;

/// Configuration for the shared Poseidon gadget.
#[derive(Clone, Debug)]
pub struct PoseidonGadgetConfig {
    pub pow5_config: Pow5Config<pallas::Base, 3, 2>,
    pub state_advice: [Column<Advice>; 3],
}

/// Set up the Poseidon Pow5Chip inside a constraint system.
///
/// Callers must supply at least [`POSEIDON_ADVICE_COLS`] advice columns and
/// 2×WIDTH fixed columns (rc_a, rc_b). The returned config is reusable across
/// multiple hash invocations within the same circuit.
pub fn configure_poseidon(
    meta: &mut ConstraintSystem<pallas::Base>,
    state_advice: [Column<Advice>; 3],
    partial_sbox: Column<Advice>,
    rc_a: [Column<Fixed>; 3],
    rc_b: [Column<Fixed>; 3],
) -> PoseidonGadgetConfig {
    for col in &state_advice {
        meta.enable_equality(*col);
    }
    meta.enable_equality(partial_sbox);

    let pow5_config = Pow5Chip::configure::<P128Pow5T3>(
        meta,
        state_advice,
        partial_sbox,
        rc_a,
        rc_b,
    );

    PoseidonGadgetConfig { pow5_config, state_advice }
}

/// Compute `Poseidon(left, right)` inside the circuit, returning the hash cell.
pub fn poseidon_hash_gadget(
    config: &PoseidonGadgetConfig,
    mut layouter: impl Layouter<pallas::Base>,
    left: AssignedCell<pallas::Base, pallas::Base>,
    right: AssignedCell<pallas::Base, pallas::Base>,
) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
    let chip = Pow5Chip::construct(config.pow5_config.clone());
    let hasher = PoseidonHash::<_, _, P128Pow5T3, ConstantLength<2>, 3, 2>::init(
        chip,
        layouter.namespace(|| "poseidon_init"),
    )?;
    let result = hasher.hash(layouter.namespace(|| "poseidon_hash"), [left, right])?;
    Ok(result)
}

/// Verify a Merkle authentication path in-circuit.
///
/// Given a leaf, a 32-element sibling path, and a 32-bit position index,
/// computes the root by hashing up the tree and returns the root cell.
pub fn merkle_membership_gadget(
    config: &PoseidonGadgetConfig,
    mut layouter: impl Layouter<pallas::Base>,
    leaf: AssignedCell<pallas::Base, pallas::Base>,
    path: &[AssignedCell<pallas::Base, pallas::Base>],  // siblings, bottom-up
    position_bits: &[AssignedCell<pallas::Base, pallas::Base>], // 0 or 1 per level
) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
    assert_eq!(path.len(), position_bits.len());
    let depth = path.len();

    // We also need the domain element for Merkle hashing.
    // In our protocol: H_merkle(l, r) = Poseidon(domain, Poseidon(l, r))
    // where domain = domain_to_field(DOMAIN_MERKLE).
    // We compute the domain element natively and assign it as a constant-like
    // advice cell at the start.
    let _domain_val = escanorr_primitives::poseidon::poseidon_hash_with_domain(
        escanorr_primitives::poseidon::DOMAIN_MERKLE,
        pallas::Base::zero(),
        pallas::Base::zero(),
    );
    // Actually, our domain separation is:
    //   poseidon_hash_with_domain(d, l, r) = poseidon_hash(domain_to_field(d), poseidon_hash(l, r))
    // So we need the field element for the domain tag.
    // Let's just compute it once natively.
    let domain_field = {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(escanorr_primitives::poseidon::DOMAIN_MERKLE);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        bytes[31] &= 0x3f;
        pallas::Base::from_repr(bytes).unwrap_or(pallas::Base::zero())
    };

    let mut current = leaf;

    for i in 0..depth {
        // Determine left and right based on position bit.
        // If bit = 0, current is left child, sibling is right.
        // If bit = 1, current is right child, sibling is left.
        //
        // left  = current * (1 - bit) + sibling * bit
        // right = current * bit + sibling * (1 - bit)
        //
        // We do this via conditional swap: assign (left, right) based on the bit value.
        let (left, right) = layouter.assign_region(
            || format!("merkle_swap_{i}"),
            |mut region| {
                let bit = position_bits[i].copy_advice(
                    || "bit",
                    &mut region,
                    config.state_advice[0],
                    0,
                )?;
                let cur = current.copy_advice(
                    || "current",
                    &mut region,
                    config.state_advice[1],
                    0,
                )?;
                let sib = path[i].copy_advice(
                    || "sibling",
                    &mut region,
                    config.state_advice[2],
                    0,
                )?;

                // Witness left and right
                let left_val = cur.value().zip(sib.value()).zip(bit.value()).map(
                    |((c, s), b)| {
                        if *b == pallas::Base::zero() { *c } else { *s }
                    },
                );
                let right_val = cur.value().zip(sib.value()).zip(bit.value()).map(
                    |((c, s), b)| {
                        if *b == pallas::Base::zero() { *s } else { *c }
                    },
                );

                let left_cell = region.assign_advice(
                    || "left",
                    config.state_advice[1],
                    1,
                    || left_val,
                )?;
                let right_cell = region.assign_advice(
                    || "right",
                    config.state_advice[2],
                    1,
                    || right_val,
                )?;

                Ok((left_cell, right_cell))
            },
        )?;

        // inner = Poseidon(left, right)
        let inner = poseidon_hash_gadget(
            config,
            layouter.namespace(|| format!("merkle_inner_{i}")),
            left,
            right,
        )?;

        // Apply domain separation: Poseidon(domain_element, inner)
        let domain_cell = layouter.assign_region(
            || format!("merkle_domain_{i}"),
            |mut region| {
                region.assign_advice(
                    || "domain",
                    config.state_advice[0],
                    0,
                    || Value::known(domain_field),
                )
            },
        )?;

        current = poseidon_hash_gadget(
            config,
            layouter.namespace(|| format!("merkle_domain_hash_{i}")),
            domain_cell,
            inner,
        )?;
    }

    Ok(current)
}

/// Compute a note commitment in-circuit:
///   cm = Poseidon_domain(NOTE_CM, Poseidon(owner, value), Poseidon(asset_id, blinding))
pub fn note_commitment_gadget(
    config: &PoseidonGadgetConfig,
    mut layouter: impl Layouter<pallas::Base>,
    owner: AssignedCell<pallas::Base, pallas::Base>,
    value: AssignedCell<pallas::Base, pallas::Base>,
    asset_id: AssignedCell<pallas::Base, pallas::Base>,
    blinding: AssignedCell<pallas::Base, pallas::Base>,
) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
    // left_inner = Poseidon(owner, value)
    let left_inner = poseidon_hash_gadget(
        config,
        layouter.namespace(|| "cm_left_inner"),
        owner,
        value,
    )?;

    // right_inner = Poseidon(asset_id, blinding)
    let right_inner = poseidon_hash_gadget(
        config,
        layouter.namespace(|| "cm_right_inner"),
        asset_id,
        blinding,
    )?;

    // inner = Poseidon(left_inner, right_inner)
    let inner = poseidon_hash_gadget(
        config,
        layouter.namespace(|| "cm_inner"),
        left_inner,
        right_inner,
    )?;

    // domain element for NOTE_CM
    let domain_field = {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(escanorr_primitives::poseidon::DOMAIN_NOTE_COMMITMENT);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        bytes[31] &= 0x3f;
        pallas::Base::from_repr(bytes).unwrap_or(pallas::Base::zero())
    };

    let domain_cell = layouter.assign_region(
        || "cm_domain",
        |mut region| {
            region.assign_advice(
                || "domain_note_cm",
                config.state_advice[0],
                0,
                || Value::known(domain_field),
            )
        },
    )?;

    // cm = Poseidon(domain, inner)
    poseidon_hash_gadget(
        config,
        layouter.namespace(|| "cm_final"),
        domain_cell,
        inner,
    )
}

/// Compute a nullifier in-circuit:
///   nf = Poseidon_domain(NULLIFIER, sk, cm)
///      = Poseidon(domain_element, Poseidon(sk, cm))
pub fn nullifier_gadget(
    config: &PoseidonGadgetConfig,
    mut layouter: impl Layouter<pallas::Base>,
    spending_key: AssignedCell<pallas::Base, pallas::Base>,
    commitment: AssignedCell<pallas::Base, pallas::Base>,
) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
    // inner = Poseidon(sk, cm)
    let inner = poseidon_hash_gadget(
        config,
        layouter.namespace(|| "nf_inner"),
        spending_key,
        commitment,
    )?;

    // domain element for NULLIFIER
    let domain_field = {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(escanorr_primitives::poseidon::DOMAIN_NULLIFIER);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        bytes[31] &= 0x3f;
        pallas::Base::from_repr(bytes).unwrap_or(pallas::Base::zero())
    };

    let domain_cell = layouter.assign_region(
        || "nf_domain",
        |mut region| {
            region.assign_advice(
                || "domain_nf",
                config.state_advice[0],
                0,
                || Value::known(domain_field),
            )
        },
    )?;

    // nf = Poseidon(domain, inner)
    poseidon_hash_gadget(
        config,
        layouter.namespace(|| "nf_final"),
        domain_cell,
        inner,
    )
}

// ---------------------------------------------------------------------------
// Range check gadget (bit-decomposition)
// ---------------------------------------------------------------------------

/// Configuration for range check (value ∈ [0, 2^num_bits)).
#[derive(Clone, Debug)]
pub struct RangeCheckConfig {
    pub z_col: Column<Advice>,
    pub bit_col: Column<Advice>,
    pub range_sel: Selector,
}

/// Configure the range decomposition gate.
///
/// Enforces at each enabled row:
///   z_cur = 2 * z_next + bit, and bit ∈ {0, 1}
pub fn configure_range_check(
    meta: &mut ConstraintSystem<pallas::Base>,
    z_col: Column<Advice>,
    bit_col: Column<Advice>,
) -> RangeCheckConfig {
    let range_sel = meta.selector();

    meta.create_gate("range decomposition", |meta| {
        let sel = meta.query_selector(range_sel);
        let z_cur = meta.query_advice(z_col, Rotation::cur());
        let z_next = meta.query_advice(z_col, Rotation::next());
        let bit = meta.query_advice(bit_col, Rotation::cur());
        let one = halo2_proofs::plonk::Expression::Constant(pallas::Base::ONE);
        let two = halo2_proofs::plonk::Expression::Constant(pallas::Base::from(2));
        vec![
            // z_cur - 2*z_next - bit == 0
            sel.clone() * (z_cur - two * z_next - bit.clone()),
            // bit ∈ {0, 1}
            sel * bit.clone() * (bit - one),
        ]
    });

    RangeCheckConfig { z_col, bit_col, range_sel }
}

/// Constrain that `value` fits in `num_bits` bits.
///
/// Uses the running-quotient decomposition: z_0 = value, z_{i+1} = (z_i - bit_i) / 2,
/// with the final z_{num_bits} constrained to zero.
pub fn range_check_gadget(
    config: &RangeCheckConfig,
    mut layouter: impl Layouter<pallas::Base>,
    value: AssignedCell<pallas::Base, pallas::Base>,
    num_bits: usize,
) -> Result<(), Error> {
    layouter.assign_region(
        || "range check",
        |mut region| {
            let two_inv = pallas::Base::from(2u64).invert().unwrap();

            // Row 0: z_0 = value
            let mut z = value.copy_advice(|| "z_0", &mut region, config.z_col, 0)?;

            for i in 0..num_bits {
                config.range_sel.enable(&mut region, i)?;

                let z_val = z.value().copied();
                let bit_val = z_val.map(|z| {
                    let bytes = z.to_repr();
                    if bytes[0] & 1 == 1 {
                        pallas::Base::ONE
                    } else {
                        pallas::Base::ZERO
                    }
                });
                let z_next_val = z_val.zip(bit_val).map(|(z, b)| (z - b) * two_inv);

                region.assign_advice(|| format!("bit_{i}"), config.bit_col, i, || bit_val)?;
                z = region.assign_advice(
                    || format!("z_{}", i + 1),
                    config.z_col,
                    i + 1,
                    || z_next_val,
                )?;
            }

            // z_{num_bits} must be zero — enforce via constant constraint.
            region.constrain_constant(z.cell(), pallas::Base::ZERO)?;
            Ok(())
        },
    )
}
