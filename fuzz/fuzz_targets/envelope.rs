//! Fuzz target for ProofEnvelope seal/open roundtrip.

#![no_main]

use libfuzzer_sys::fuzz_target;
use escanorr_primitives::ProofEnvelope;

fuzz_target!(|data: &[u8]| {
    // Seal should either succeed (payload fits) or return error (too large).
    match ProofEnvelope::seal(data) {
        Ok(envelope) => {
            // If seal succeeds, open must return the exact original payload.
            let opened = envelope.open().expect("open should succeed after seal");
            assert_eq!(&opened[..], data, "roundtrip mismatch");
        }
        Err(_) => {
            // Payload too large — expected for inputs > ENVELOPE_SIZE - 4.
        }
    }
});
