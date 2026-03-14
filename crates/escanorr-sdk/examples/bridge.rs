//! Example: deposit funds and then bridge to another chain with ZK proof.

use escanorr_note::SpendingKey;
use escanorr_sdk::Escanorr;

fn main() {
    let mut esc = Escanorr::new();

    // Deposit 1000 units
    let (note, index) = esc.deposit(1000).expect("deposit failed");
    println!("Deposited {} at index {}", note.value, index);

    // Create a destination key on the target chain
    let dest_sk = SpendingKey::random();
    let dest_owner = dest_sk.to_full_viewing_key().viewing_key.to_owner();

    // Bridge to chain 1_000_001 (Ethereum) with fee 5
    let result = esc
        .bridge(dest_owner, 1, 1_000_001, 5)
        .expect("bridge failed");

    println!("Bridge lock complete!");
    println!("  Source chain: 1 (Zcash), Destination chain: 1000001 (Ethereum)");
    println!("  Destination note: value={}", result.dest_note.value);
    println!("  Proof size: {} bytes", result.proof.as_bytes().len());
    println!("  Remaining balance: {}", esc.balance());
}
