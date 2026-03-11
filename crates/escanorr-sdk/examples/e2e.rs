//! End-to-end example: deposit, send, check balance.

use escanorr_sdk::Escanorr;
use escanorr_note::SpendingKey;

fn main() {
    let mut esc = Escanorr::new();

    // Deposit 1000
    let (note, index) = esc.deposit(1000).expect("deposit failed");
    println!("Deposited {} at index {}", note.value, index);
    println!("Balance: {}", esc.balance());

    // Create recipient
    let recipient_sk = SpendingKey::random();
    let recipient_fvk = recipient_sk.to_full_viewing_key();
    let recipient_owner = recipient_fvk.viewing_key.to_owner();

    // Send 400 with 10 fee (generates ZK proof)
    let result = esc.send(recipient_owner, 400, 10).expect("send failed");
    println!("Sent 400 to recipient (fee: 10)");
    println!("Recipient note: value={}", result.output_notes[0].value);
    println!("Change note: value={}", result.output_notes[1].value);
    println!("Proof size: {} bytes", result.proof.as_bytes().len());
    println!("Final balance: {}", esc.balance());
}
