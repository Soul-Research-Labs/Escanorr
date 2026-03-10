//! ESCANORR CLI — command-line interface for the privacy coprocessor.

use clap::{Parser, Subcommand};
use escanorr_sdk::Escanorr;
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
    }
}

use ff::PrimeField;
