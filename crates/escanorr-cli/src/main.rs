//! ESCANORR CLI — command-line interface for the privacy coprocessor.

use clap::{Parser, Subcommand};
use escanorr_sdk::Escanorr;
use ff::PrimeField;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Default wallet file location.
fn default_wallet_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".escanorr")
        .join("wallet.enc")
}

#[derive(Parser)]
#[command(
    name = "escanorr",
    about = "ESCANORR — Privacy Coprocessor & Cross-Chain Bridge for the Zcash Ecosystem",
    version
)]
struct Cli {
    /// Path to the encrypted wallet file.
    #[arg(long, global = true, default_value_os_t = default_wallet_path())]
    wallet_file: PathBuf,

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
    /// Create a new wallet and save it encrypted.
    Init,
    /// Import a wallet from a BIP39 mnemonic phrase.
    Import {
        /// BIP39 mnemonic phrase (12 or 24 words). Prompted interactively if not given.
        #[arg(short, long)]
        mnemonic: Option<String>,
    },
    /// Export the wallet's BIP39-compatible spending key (hex) for backup.
    Export,
    /// Show wallet info (owner address, balance).
    Info,
    /// Deposit funds into the privacy pool.
    Deposit {
        /// Value to deposit.
        #[arg(short, long)]
        value: u64,
    },
    /// Show current balance.
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

/// Read password from terminal (no echo).
fn read_password(prompt: &str) -> String {
    eprint!("{prompt}");
    rpassword::read_password().unwrap_or_else(|_| {
        eprintln!("Failed to read password");
        std::process::exit(1);
    })
}

/// Load wallet from encrypted file, prompting for password.
fn load_wallet(path: &std::path::Path) -> escanorr_client::Wallet {
    if !path.exists() {
        eprintln!("No wallet found at {}. Run `escanorr init` first.", path.display());
        std::process::exit(1);
    }
    let password = read_password("Wallet password: ");
    escanorr_client::Wallet::load(path, password.as_bytes()).unwrap_or_else(|e| {
        eprintln!("Failed to load wallet: {e}");
        std::process::exit(1);
    })
}

/// Save wallet back to encrypted file after state changes.
fn save_wallet(wallet: &escanorr_client::Wallet, path: &std::path::Path, password: &str) {
    wallet.save(path, password.as_bytes()).unwrap_or_else(|e| {
        eprintln!("Failed to save wallet: {e}");
        std::process::exit(1);
    });
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "escanorr=info,tower_http=info".parse().unwrap()),
        )
        .with_target(true)
        .init();
    let cli = Cli::parse();
    let wallet_path = &cli.wallet_file;

    match cli.command {
        Commands::Serve { addr } => {
            if let Err(e) = escanorr_rpc::run_server(addr).await {
                eprintln!("Server error: {e}");
                std::process::exit(1);
            }
        }
        Commands::Init => {
            if wallet_path.exists() {
                eprintln!("Wallet already exists at {}. Delete it first to reinitialize.", wallet_path.display());
                std::process::exit(1);
            }
            let password = read_password("Choose wallet password: ");
            let confirm = read_password("Confirm password: ");
            if password != confirm {
                eprintln!("Passwords do not match.");
                std::process::exit(1);
            }
            let wallet = escanorr_client::Wallet::random();
            let owner = wallet.owner().expect("wallet has key");
            save_wallet(&wallet, wallet_path, &password);
            println!("Wallet created and saved to {}", wallet_path.display());
            println!("Owner: {}", hex::encode(owner.to_repr()));
        }
        Commands::Import { mnemonic } => {
            if wallet_path.exists() {
                eprintln!("Wallet already exists at {}. Delete it first to reimport.", wallet_path.display());
                std::process::exit(1);
            }
            let phrase = match mnemonic {
                Some(m) => m,
                None => {
                    eprint!("Enter BIP39 mnemonic: ");
                    let mut buf = String::new();
                    std::io::stdin().read_line(&mut buf).unwrap_or_else(|_| {
                        eprintln!("Failed to read mnemonic");
                        std::process::exit(1);
                    });
                    buf.trim().to_string()
                }
            };
            let wallet = escanorr_client::Wallet::from_mnemonic(&phrase).unwrap_or_else(|e| {
                eprintln!("Invalid mnemonic: {e}");
                std::process::exit(1);
            });
            let owner = wallet.owner().expect("wallet has key");
            let password = read_password("Choose wallet password: ");
            let confirm = read_password("Confirm password: ");
            if password != confirm {
                eprintln!("Passwords do not match.");
                std::process::exit(1);
            }
            save_wallet(&wallet, wallet_path, &password);
            println!("Wallet imported and saved to {}", wallet_path.display());
            println!("Owner: {}", hex::encode(owner.to_repr()));
        }
        Commands::Export => {
            let wallet = load_wallet(wallet_path);
            let sk = wallet.spending_key().expect("wallet has key");
            println!("Spending key (hex): {}", hex::encode(sk.inner().to_repr()));
            eprintln!("WARNING: Keep this secret. Anyone with this key can spend your funds.");
        }
        Commands::Info => {
            let wallet = load_wallet(wallet_path);
            let owner = wallet.owner().expect("wallet has key");
            println!("Wallet: {}", wallet_path.display());
            println!("Owner:  {}", hex::encode(owner.to_repr()));
            println!("Balance: {}", wallet.balance());
            println!("Unspent notes: {}", wallet.unspent_notes().len());
        }
        Commands::Deposit { value } => {
            let password = read_password("Wallet password: ");
            let wallet = escanorr_client::Wallet::load(wallet_path, password.as_bytes())
                .unwrap_or_else(|e| {
                    eprintln!("Failed to load wallet: {e}");
                    std::process::exit(1);
                });
            let mut esc = Escanorr::with_wallet(wallet);
            let (note, index) = esc.deposit(value).expect("deposit failed");
            println!("Deposited {} at index {}", note.value, index);
            println!("New root: {}", hex::encode(esc.root().to_repr()));
            // Save updated wallet (new note tracked)
            save_wallet(esc.wallet(), wallet_path, &password);
            println!("Wallet saved.");
        }
        Commands::Balance => {
            let wallet = load_wallet(wallet_path);
            println!("{}", wallet.balance());
        }
        Commands::Withdraw { value, fee } => {
            let password = read_password("Wallet password: ");
            let wallet = escanorr_client::Wallet::load(wallet_path, password.as_bytes())
                .unwrap_or_else(|e| {
                    eprintln!("Failed to load wallet: {e}");
                    std::process::exit(1);
                });
            let mut esc = Escanorr::with_wallet(wallet);

            println!("Initializing prover (one-time IPA setup, this may take a few minutes)...");
            esc.init_prover_async().await;
            println!("Prover ready.");
            let result = esc.withdraw(value, fee).expect("withdraw failed");
            println!("Withdrawal complete!");
            println!("  Exit value: {}", result.exit_value);
            if let Some(ref cn) = result.change_note {
                println!("  Change note: value={}", cn.value);
            }
            println!("  Proof size: {} bytes", result.proof.as_bytes().len());
            println!("  Proof (hex, first 64 chars): {}...", &hex::encode(&result.proof.as_bytes()[..32]));
            save_wallet(esc.wallet(), wallet_path, &password);
            println!("Wallet saved.");
        }
        Commands::Transfer { recipient, value, fee } => {
            let recipient_owner = hex_to_base(&recipient).unwrap_or_else(|e| {
                eprintln!("Invalid recipient: {e}");
                std::process::exit(1);
            });

            let password = read_password("Wallet password: ");
            let wallet = escanorr_client::Wallet::load(wallet_path, password.as_bytes())
                .unwrap_or_else(|e| {
                    eprintln!("Failed to load wallet: {e}");
                    std::process::exit(1);
                });
            let mut esc = Escanorr::with_wallet(wallet);

            println!("Initializing prover (one-time IPA setup, this may take a few minutes)...");
            esc.init_prover_async().await;
            println!("Prover ready.");
            let result = esc.send(recipient_owner, value, fee).expect("transfer failed");
            println!("Transfer complete!");
            println!("  Recipient note: value={}", result.output_notes[0].value);
            println!("  Change note: value={}", result.output_notes[1].value);
            println!("  Proof size: {} bytes", result.proof.as_bytes().len());
            println!("  Proof (hex, first 64 chars): {}...", &hex::encode(&result.proof.as_bytes()[..32]));
            save_wallet(esc.wallet(), wallet_path, &password);
            println!("Wallet saved.");
        }
        Commands::Bridge { dest_chain_id, src_chain_id, fee } => {
            let password = read_password("Wallet password: ");
            let wallet = escanorr_client::Wallet::load(wallet_path, password.as_bytes())
                .unwrap_or_else(|e| {
                    eprintln!("Failed to load wallet: {e}");
                    std::process::exit(1);
                });
            let mut esc = Escanorr::with_wallet(wallet);

            let dest_owner = esc.wallet().owner().expect("wallet has key");

            println!("Initializing prover (one-time IPA setup, this may take a few minutes)...");
            esc.init_prover_async().await;
            println!("Prover ready.");
            let result = esc.bridge(dest_owner, src_chain_id, dest_chain_id, fee)
                .expect("bridge failed");
            println!("Bridge lock complete!");
            println!("  Source chain: {}, Destination chain: {}", src_chain_id, dest_chain_id);
            println!("  Destination note: value={}", result.dest_note.value);
            println!("  Proof size: {} bytes", result.proof.as_bytes().len());
            println!("  Proof (hex, first 64 chars): {}...", &hex::encode(&result.proof.as_bytes()[..32]));
            save_wallet(esc.wallet(), wallet_path, &password);
            println!("Wallet saved.");
        }
    }
}
