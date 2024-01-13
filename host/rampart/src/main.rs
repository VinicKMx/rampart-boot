use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use serde::Serialize;

mod format;
mod keys;

use format::{DeviceTarget, VerificationOptions};

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
    Verify(ImageVerifyArgs),
    /// Sign a payload and manifest into a .rampart image artifact.
    Sign(ImageSignArgs),
}

#[derive(Debug, Args)]
struct ImageVerifyArgs {
    artifact: PathBuf,
    /// Require at least this security epoch.
    #[arg(long, default_value_t = 0)]
    minimum_security_epoch: u32,
    /// Expected vendor ID for target binding checks.
    #[arg(long, value_parser = parse_u32_value)]
    vendor_id: Option<u32>,
    /// Expected product ID for target binding checks.
    #[arg(long, value_parser = parse_u32_value)]
    product_id: Option<u32>,
    /// Expected hardware family for target binding checks.
    #[arg(long, value_parser = parse_u32_value)]
    hardware_family: Option<u32>,
    /// Expected component ID for target binding checks.
    #[arg(long, value_parser = parse_u32_value)]
    component_id: Option<u32>,
}

#[derive(Debug, Args)]
struct ImageSignArgs {
    payload: PathBuf,
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    key: PathBuf,
    /// Override the derived signing key ID with an explicit 8-byte hex value.
    #[arg(long)]
    key_id: Option<String>,
    #[arg(short, long)]
    output: PathBuf,
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
        /// Logical role label recorded by users and release process metadata.
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
            status: "image format tooling available",
            implemented_checkpoint: 3,
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
        Command::Image(args) => run_image(args),
        Command::Bundle(args) => planned("bundle", format!("{:?}", args.command)),
        Command::Key(args) => run_key(args),
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
        println!("Rampart image format tooling available");
    }

    Ok(())
}

fn run_image(args: ImageArgs) -> Result<(), String> {
    match args.command {
        ImageCommand::Inspect { artifact } => {
            let bytes = std::fs::read(&artifact)
                .map_err(|error| format!("failed to read {}: {error}", artifact.display()))?;
            let report = format::inspect_image(&bytes)?;
            print!("{report}");
            Ok(())
        }
        ImageCommand::Verify(args) => {
            let bytes = std::fs::read(&args.artifact)
                .map_err(|error| format!("failed to read {}: {error}", args.artifact.display()))?;
            let options = VerificationOptions {
                device_target: image_verify_target(&args)?,
                minimum_security_epoch: args.minimum_security_epoch,
            };
            let report = format::verify_image(&bytes, &options)?;
            print!("{}", format::format_verification_report(&report));

            if report.is_valid() {
                Ok(())
            } else {
                Err("image verification failed".to_string())
            }
        }
        ImageCommand::Sign(args) => {
            let image = format::sign_image(
                &args.payload,
                &args.manifest,
                &args.key,
                &args.output,
                args.key_id.as_deref(),
            )?;
            println!(
                "wrote {}\nartifact_id {}\nkey_id 0x{}",
                args.output.display(),
                image.manifest.artifact_id,
                keys::key_id_hex(&image.manifest.key_id)
            );
            Ok(())
        }
    }
}

fn run_key(args: KeyArgs) -> Result<(), String> {
    match args.command {
        KeyCommand::Generate { role, output } => {
            validate_key_role_label(&role)?;
            let key_id = keys::generate_private_key(&output)?;
            println!(
                "wrote {}\nrole {}\nalgorithm ECDSA_P256_SHA256\nkey_id 0x{}",
                output.display(),
                role,
                key_id
            );
            Ok(())
        }
        KeyCommand::Inspect { key } => {
            let report = keys::inspect_private_key(&key)?;
            print!("{report}");
            Ok(())
        }
        KeyCommand::Public { key, output } => {
            let key_id = keys::export_public_key(&key, &output)?;
            println!("wrote {}\nkey_id 0x{}", output.display(), key_id);
            Ok(())
        }
    }
}

fn planned(domain: &str, command: String) -> Result<(), String> {
    Err(format!(
        "{domain} command is defined for the final CLI but is not implemented yet: {command}"
    ))
}

fn image_verify_target(args: &ImageVerifyArgs) -> Result<Option<DeviceTarget>, String> {
    let provided = [
        args.vendor_id.is_some(),
        args.product_id.is_some(),
        args.hardware_family.is_some(),
        args.component_id.is_some(),
    ]
    .into_iter()
    .filter(|value| *value)
    .count();

    if provided == 0 {
        return Ok(None);
    }

    if provided != 4 {
        return Err(
            "target binding verification requires --vendor-id, --product-id, --hardware-family, and --component-id".to_string(),
        );
    }

    Ok(Some(DeviceTarget {
        vendor_id: args.vendor_id.expect("checked above"),
        product_id: args.product_id.expect("checked above"),
        hardware_family: args.hardware_family.expect("checked above"),
        component_id: args.component_id.expect("checked above"),
    }))
}

fn validate_key_role_label(role: &str) -> Result<(), String> {
    match role {
        "RELEASE" | "SECURITY" | "BOOT_MANAGER" | "RECOVERY" | "FACTORY" | "DEVELOPMENT" => Ok(()),
        _ => Err(format!("unknown key role {role}")),
    }
}

fn parse_u32_value(value: &str) -> Result<u32, String> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return u32::from_str_radix(hex, 16)
            .map_err(|_| format!("invalid hexadecimal u32 value {value}"));
    }

    value
        .parse::<u32>()
        .map_err(|_| format!("invalid decimal u32 value {value}"))
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::{Cli, ToolStatus, parse_u32_value};

    #[test]
    fn cli_shape_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn self_check_status_serializes_to_json() {
        let encoded = serde_json::to_string(&ToolStatus::current()).expect("serialize status");

        assert!(encoded.contains("\"tool\":\"rampart\""));
        assert!(encoded.contains("\"implemented_checkpoint\":3"));
    }

    #[test]
    fn parses_decimal_and_hex_u32_values() {
        assert_eq!(parse_u32_value("123").expect("decimal"), 123);
        assert_eq!(parse_u32_value("0x00000585").expect("hex"), 0x585);
    }
}
