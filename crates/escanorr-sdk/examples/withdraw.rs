//! Example: deposit funds and then withdraw with ZK proof.

use escanorr_sdk::Escanorr;

fn main() {
    let mut esc = Escanorr::new();

    // Deposit 1000 units
    let (note, index) = esc.deposit(1000).expect("deposit failed");
    println!("Deposited {} at index {}", note.value, index);
    println!("Balance: {}", esc.balance());

    // Withdraw 400 with fee 10 (generates a ZK proof)
    let result = esc.withdraw(400, 10).expect("withdraw failed");
    println!("Withdrew {}", result.exit_value);

    if let Some(ref change) = result.change_note {
        println!("Change note: value={}", change.value);
    }

    println!("Proof size: {} bytes", result.proof.as_bytes().len());
    println!("Remaining balance: {}", esc.balance());
}
