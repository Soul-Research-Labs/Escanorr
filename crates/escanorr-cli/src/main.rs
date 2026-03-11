//! ESCANORR CLI — command-line interface for the privacy coprocessor.

use clap::{Parser, Subcommand};
use escanorr_sdk::Escanorr;
use ff::PrimeField;
use std::net::SocketAddr;

#[derive(Parser)]
#[command(
    name = "escanorr",
    about = "ESCANORR — Privacy Coprocessor & Cross-Chain Bridge for the Zcash Ecosystem",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the RPC server.
    Serve {
        /// Address to bind to.
        #[arg(short, long, default_value = "127.0.0.1:3030")]
        addr: SocketAddr,
    },
    /// Generate a new wallet.
    Keygen,
    /// Show wallet info.
    Info,
    /// Deposit funds into the privacy pool (local demo).
    Deposit {
        /// Value to deposit.
        #[arg(short, long)]
        value: u64,
    },
    /// Show current balance (local demo).
    Balance,
    /// Withdraw funds from the privacy pool with ZK proof.
    Withdraw {
        /// Value to withdraw.
        #[arg(short, long)]
        value: u64,
        /// Fee for the withdrawal.
        #[arg(short, long, default_value = "0")]
        fee: u64,
    },
    /// Private transfer to another user with ZK proof.
    Transfer {
        /// Recipient public key (hex, 64 chars).
        #[arg(short, long)]
        recipient: String,
        /// Value to transfer.
        #[arg(short, long)]
        value: u64,
        /// Fee for the transfer.
        #[arg(short, long, default_value = "0")]
        fee: u64,
    },
    /// Initiate a cross-chain bridge with ZK proof.
    Bridge {
        /// Destination chain ID (numeric).
        #[arg(long)]
        dest_chain_id: u64,
        /// Source chain ID (numeric).
        #[arg(long, default_value = "1")]
        src_chain_id: u64,
        /// Fee for the bridge.
        #[arg(short, long, default_value = "0")]
        fee: u64,
    },
}

fn hex_to_base(s: &str) -> Result<escanorr_primitives::Base, String> {
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", s.len()));
    }
    let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {e}"))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| "invalid length")?;
    Option::from(escanorr_primitives::Base::from_repr(arr))
        .ok_or_else(|| "invalid field element".to_string())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve { addr } => {
            if let Err(e) = escanorr_rpc::run_server(addr).await {
                eprintln!("Server error: {e}");
                std::process::exit(1);
            }
        }
        Commands::Keygen => {
            let wallet = escanorr_client::Wallet::random();
            let owner = wallet.owner().expect("wallet has key");
            println!("New wallet created.");
            println!("Owner: {}", hex::encode(owner.to_repr()));
        }
        Commands::Info => {
            let esc = Escanorr::new();
            let owner = esc.wallet().owner().expect("wallet has key");
            println!("Owner: {}", hex::encode(owner.to_repr()));
            println!("Balance: {}", esc.balance());
        }
        Commands::Deposit { value } => {
            let mut esc = Escanorr::new();
            let (note, index) = esc.deposit(value).expect("deposit failed");
            println!("Deposited {} at index {}", note.value, index);
            println!("New root: {}", hex::encode(esc.root().to_repr()));
        }
        Commands::Balance => {
            let esc = Escanorr::new();
            println!("Balance: {}", esc.balance());
        }
        Commands::Withdraw { value, fee } => {
            let mut esc = Escanorr::new();
            // In demo mode, deposit first so we have funds to withdraw
            esc.deposit(value + fee).expect("deposit failed");

            println!("Initializing prover (one-time IPA setup)...");
            let result = esc.withdraw(value, fee).expect("withdraw failed");
            println!("Withdrawal complete!");
            println!("  Exit value: {}", result.exit_value);
            if let Some(ref cn) = result.change_note {
                println!("  Change note: value={}", cn.value);
            }
            println!("  Proof size: {} bytes", result.proof.as_bytes().len());
            println!("  Proof (hex, first 64 chars): {}...", &hex::encode(&result.proof.as_bytes()[..32]));
        }
        Commands::Transfer { recipient, value, fee } => {
            let recipient_owner = hex_to_base(&recipient).unwrap_or_else(|e| {
                eprintln!("Invalid recipient: {e}");
                std::process::exit(1);
            });

            let mut esc = Escanorr::new();
            // In demo mode, deposit first so we have funds
            esc.deposit(value + fee).expect("deposit failed");

            println!("Initializing prover (one-time IPA setup)...");
            let result = esc.send(recipient_owner, value, fee).expect("transfer failed");
            println!("Transfer complete!");
            println!("  Recipient note: value={}", result.output_notes[0].value);
            println!("  Change note: value={}", result.output_notes[1].value);
            println!("  Proof size: {} bytes", result.proof.as_bytes().len());
            println!("  Proof (hex, first 64 chars): {}...", &hex::encode(&result.proof.as_bytes()[..32]));
        }
        Commands::Bridge { dest_chain_id, src_chain_id, fee } => {
            let mut esc = Escanorr::new();
            // In demo mode, deposit first
            esc.deposit(1000 + fee).expect("deposit failed");

            let dest_owner = esc.wallet().owner().expect("wallet has key");

            println!("Initializing prover (one-time IPA setup)...");
            let result = esc.bridge(dest_owner, src_chain_id, dest_chain_id, fee)
                .expect("bridge failed");
            println!("Bridge lock complete!");
            println!("  Source chain: {}, Destination chain: {}", src_chain_id, dest_chain_id);
            println!("  Destination note: value={}", result.dest_note.value);
            println!("  Proof size: {} bytes", result.proof.as_bytes().len());
            println!("  Proof (hex, first 64 chars): {}...", &hex::encode(&result.proof.as_bytes()[..32]));
        }
    }
}
