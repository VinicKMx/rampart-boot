use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(
    name = "rampart",
    version,
    about = "Rampart Boot host tooling",
    long_about = "Host tooling for the Rampart Boot secure firmware lifecycle framework."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Check that the host tool is installed and runnable.
    SelfCheck(SelfCheckArgs),
    /// Create, inspect, sign, and verify single firmware images.
    Image(ImageArgs),
    /// Create, inspect, and verify multi-component bundles.
    Bundle(BundleArgs),
    /// Generate and inspect firmware signing keys.
    Key(KeyArgs),
    /// Manage trust manifests and key lifecycle metadata.
    Trust(TrustArgs),
    /// Inspect and validate standalone manifests.
    Manifest(ManifestArgs),
    /// Run host-side lifecycle and power-loss simulations.
    Simulate(SimulateArgs),
    /// Query attached devices when a probe transport is available.
    Device(DeviceArgs),
    /// Decode boot journal records.
    Journal(JournalArgs),
    /// Enter or operate authenticated recovery flows.
    Recovery(RecoveryArgs),
}

#[derive(Debug, Args)]
struct SelfCheckArgs {
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ImageArgs {
    #[command(subcommand)]
    command: ImageCommand,
}

#[derive(Debug, Subcommand)]
enum ImageCommand {
    /// Inspect a .rampart image artifact.
    Inspect { artifact: PathBuf },
    /// Verify a .rampart image artifact.
    Verify { artifact: PathBuf },
    /// Sign a payload and manifest into a .rampart image artifact.
    Sign {
        payload: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
}

#[derive(Debug, Args)]
struct BundleArgs {
    #[command(subcommand)]
    command: BundleCommand,
}

#[derive(Debug, Subcommand)]
enum BundleCommand {
    /// Create a multi-component bundle.
    Create { manifest: PathBuf },
    /// Inspect a bundle.
    Inspect { bundle: PathBuf },
    /// Verify a bundle.
    Verify { bundle: PathBuf },
}

#[derive(Debug, Args)]
struct KeyArgs {
    #[command(subcommand)]
    command: KeyCommand,
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    /// Generate a signing key.
    Generate {
        #[arg(long)]
        role: String,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Inspect a key.
    Inspect { key: PathBuf },
    /// Export public key material.
    Public {
        key: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
}

#[derive(Debug, Args)]
struct TrustArgs {
    #[command(subcommand)]
    command: TrustCommand,
}

#[derive(Debug, Subcommand)]
enum TrustCommand {
    /// Inspect a trust manifest.
    Inspect { manifest: PathBuf },
}

#[derive(Debug, Args)]
struct ManifestArgs {
    #[command(subcommand)]
    command: ManifestCommand,
}

#[derive(Debug, Subcommand)]
enum ManifestCommand {
    /// Inspect a manifest document.
    Inspect { manifest: PathBuf },
    /// Validate manifest structure.
    Validate { manifest: PathBuf },
}

#[derive(Debug, Args)]
struct SimulateArgs {
    #[command(subcommand)]
    command: SimulateCommand,
}

#[derive(Debug, Subcommand)]
enum SimulateCommand {
    /// Run a named simulation scenario.
    Run { scenario: String },
}

#[derive(Debug, Args)]
struct DeviceArgs {
    #[command(subcommand)]
    command: DeviceCommand,
}

#[derive(Debug, Subcommand)]
enum DeviceCommand {
    /// Show device lifecycle, slots, recovery, and epoch status.
    Info,
    /// Show application and boot-manager slots.
    Slots,
    /// Read device boot journal records.
    Journal,
    /// Show device trust metadata.
    Trust,
    /// Enter authenticated recovery mode.
    Recovery,
}

#[derive(Debug, Args)]
struct JournalArgs {
    #[command(subcommand)]
    command: JournalCommand,
}

#[derive(Debug, Subcommand)]
enum JournalCommand {
    /// Decode a journal dump from a file.
    Decode { journal: PathBuf },
}

#[derive(Debug, Args)]
struct RecoveryArgs {
    #[command(subcommand)]
    command: RecoveryCommand,
}

#[derive(Debug, Subcommand)]
enum RecoveryCommand {
    /// Inspect recovery capsule metadata.
    Inspect { capsule: PathBuf },
}

#[derive(Debug, Serialize)]
struct ToolStatus {
    tool: &'static str,
    status: &'static str,
    implemented_checkpoint: u8,
}

impl ToolStatus {
    fn current() -> Self {
        Self {
            tool: "rampart",
            status: "host tooling foundation available",
            implemented_checkpoint: 1,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::SelfCheck(args) => run_self_check(args),
        Command::Image(args) => planned("image", format!("{:?}", args.command)),
        Command::Bundle(args) => planned("bundle", format!("{:?}", args.command)),
        Command::Key(args) => planned("key", format!("{:?}", args.command)),
        Command::Trust(args) => planned("trust", format!("{:?}", args.command)),
        Command::Manifest(args) => planned("manifest", format!("{:?}", args.command)),
        Command::Simulate(args) => planned("simulate", format!("{:?}", args.command)),
        Command::Device(args) => planned("device", format!("{:?}", args.command)),
        Command::Journal(args) => planned("journal", format!("{:?}", args.command)),
        Command::Recovery(args) => planned("recovery", format!("{:?}", args.command)),
    }
}

fn run_self_check(args: SelfCheckArgs) -> Result<(), String> {
    let status = ToolStatus::current();

    if args.json {
        let encoded = serde_json::to_string_pretty(&status).map_err(|error| error.to_string())?;
        println!("{encoded}");
    } else {
        println!("Rampart host tooling foundation available");
    }

    Ok(())
}

fn planned(domain: &str, command: String) -> Result<(), String> {
    Err(format!(
        "{domain} command is defined for the final CLI but is not implemented yet: {command}"
    ))
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::{Cli, ToolStatus};

    #[test]
    fn cli_shape_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn self_check_status_serializes_to_json() {
        let encoded = serde_json::to_string(&ToolStatus::current()).expect("serialize status");

        assert!(encoded.contains("\"tool\":\"rampart\""));
        assert!(encoded.contains("\"implemented_checkpoint\":1"));
    }
}
