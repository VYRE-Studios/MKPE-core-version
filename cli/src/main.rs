//! MKPE Command-Line Interface
//!
//! The canonical CLI tool for the Morse-Kirby Provenance Engine

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use morse_kirby_core::{MkpeError, *};
use std::path::PathBuf;
use sha2::{Digest, Sha256};
use base64::Engine;

#[derive(Parser)]
#[command(name = "mkpe")]
#[command(author = "Morse-Kirby Provenance Engine")]
#[command(version = MKPE_VERSION)]
#[command(about = "Cryptographic provenance for creative and computational processes", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Output format for automation-friendly commands
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new cryptographic keypair
    Keygen {
        /// Output directory for keys
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
    },

    /// Sign a file or directory
    Sign {
        /// Path to file or directory to sign
        path: PathBuf,

        /// Private key file
        #[arg(short, long)]
        key: PathBuf,

        /// Output .mkpe file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Verify a .mkpe bundle
    Verify {
        /// Path to .mkpe file
        path: PathBuf,

        /// Show detailed verification results
        #[arg(short, long)]
        detailed: bool,
    },

    /// Create a proof bundle from a directory
    Bundle {
        /// Directory to bundle
        path: PathBuf,

        /// Private key file
        #[arg(short, long)]
        key: PathBuf,

        /// Output .mkpe file
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Inspect a .mkpe file
    Inspect {
        /// Path to .mkpe file
        path: PathBuf,

        /// Export manifest to JSON
        #[arg(short, long)]
        export_manifest: Option<PathBuf>,
    },

    /// Hash a file with SHA-256
    Hash {
        /// Path to file
        path: PathBuf,
    },

    /// Validate a C-DNA schema file
    ValidateCdna {
        /// Path to C-DNA JSON file
        path: PathBuf,

        /// Generate proof for the schema
        #[arg(short, long)]
        proof: bool,

        /// Private key file (required if --proof is used)
        #[arg(short, long)]
        key: Option<PathBuf>,
    },

    /// Show MKPE version and build information
    Version,

    /// DNA provenance commands for sidecar .mkpe proofs
    Dna {
        #[command(subcommand)]
        command: DnaCommands,
    },

    /// Build attestation commands for Layer 3 provenance
    Attest {
        #[command(subcommand)]
        command: AttestCommands,
    },

	/// DSSE envelope commands for industry-standard signing
	Dsse {
		#[command(subcommand)]
		command: DsseCommands,
	},

	/// Policy verification commands
	Policy {
		#[command(subcommand)]
		command: PolicyCommands,
	},

	/// Audit log integrity commands
	Audit {
		#[command(subcommand)]
		command: AuditCommands,
	},

	/// Multi-signature threshold commands
	Multisig {
		#[command(subcommand)]
		command: MultisigCommands,
	},

	/// Ownership transfer and provenance commands
	Ownership {
		#[command(subcommand)]
		command: OwnershipCommands,
	}
}

#[derive(Subcommand)]
enum OwnershipCommands {
    /// Create a signed ownership transfer manifest
    Transfer {
        /// Asset ID being transferred
        #[arg(short, long)]
        asset: String,

        /// Previous manifest ID (or genesis ID for first transfer)
        #[arg(short, long)]
        previous: String,

        /// Seller's private key file
        #[arg(short = 'f', long)]
        from_key: PathBuf,

        /// Buyer's public key file
        #[arg(short = 't', long)]
        to_key: PathBuf,

        /// Optional marketplace escrow key file
        #[arg(short, long)]
        marketplace_key: Option<PathBuf>,

        /// Nonce for replay protection
        #[arg(short, long)]
        nonce: u64,

        /// Output JSON file for the transfer manifest
        #[arg(short, long)]
        output: PathBuf,

        /// Price string (e.g. "1.5")
        #[arg(long)]
        price: Option<String>,

        /// Currency or token
        #[arg(long)]
        currency: Option<String>,

        /// Royalty percentage on resales (0-100)
        #[arg(long)]
        royalty: Option<u8>,

        /// Maximum number of resales allowed
        #[arg(long)]
        max_resales: Option<u32>,
    },

    /// Add a signature to an existing transfer manifest
    Sign {
        /// Path to the transfer manifest JSON
        #[arg(short, long)]
        manifest: PathBuf,

        /// Private key file of the signer
        #[arg(short, long)]
        key: PathBuf,

        /// Output path for the updated manifest
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Verify an ownership chain from a directory of transfer manifests
    VerifyChain {
        /// Asset ID
        #[arg(short, long)]
        asset: String,

        /// Genesis manifest ID
        #[arg(short, long)]
        genesis: String,

        /// Directory containing transfer manifest JSON files
        #[arg(short, long)]
        chain_dir: PathBuf,

        /// Directory or comma-separated list of trusted public key files
        #[arg(short, long)]
        public_keys: String,
    },

    /// Revoke a transfer manifest
    Revoke {
        /// Transfer manifest ID to revoke
        #[arg(short, long)]
        transfer_id: String,

        /// Revocation authority private key
        #[arg(short, long)]
        key: PathBuf,

        /// Reason for revocation
        #[arg(short, long)]
        reason: String,

        /// Output JSON file for the revocation entry
        #[arg(short, long)]
        output: PathBuf,
    },
}


#[derive(Subcommand)]
enum DnaCommands {
    /// Create a sidecar .mkpe DNA proof for a file or folder
    Create {
        /// Artifact file or folder to prove
        artifact: PathBuf,

        /// Private key file
        #[arg(short, long)]
        key: PathBuf,

        /// Output .mkpe sidecar path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Verify current artifact bytes against a .mkpe sidecar proof
    Verify {
        /// Artifact file or folder to verify
        artifact: PathBuf,

        /// .mkpe sidecar proof bundle
        #[arg(short, long)]
        bundle: PathBuf,

        /// Trusted public key expected to have signed the DNA proof
        #[arg(long)]
        public_key: Option<PathBuf>,
    },
    /// Embed a DNA provenance tag directly into a binary artifact
    Embed {
        /// Artifact file to tag
        artifact: PathBuf,

        /// Attestation JSON file whose hash will become the DNA payload
        #[arg(short, long)]
        attestation: PathBuf,

        /// Private key file (used to derive the DNA embedding secret)
        #[arg(short, long)]
        key: PathBuf,

        /// Output tagged artifact path (defaults to overwriting input)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Extract and verify a DNA tag from a binary artifact
    Extract {
        /// Tagged artifact file
        artifact: PathBuf,

        /// Private key file (used to derive the DNA embedding secret)
        #[arg(short, long)]
        key: PathBuf,

        /// Optional attestation JSON to compare against extracted DNA
        #[arg(short, long)]
        attestation: Option<PathBuf>,
    },

    /// Inspect a .mkpe DNA proof bundle
    Inspect {
        /// .mkpe sidecar proof bundle
        bundle: PathBuf,
    },
}

#[derive(Subcommand)]
enum AttestCommands {
    /// Generate a signed build attestation JSON document
    Generate {
        /// Artifact file or folder to attest
        subject: PathBuf,

        /// Private key file
        #[arg(short, long)]
        key: PathBuf,

        /// Output attestation JSON path
        #[arg(short, long)]
        output: PathBuf,

        /// Optional linked .mkpe sidecar bundle
        #[arg(long)]
        bundle: Option<PathBuf>,

        /// Operator or build system identity
        #[arg(long, default_value = "local")]
        attested_by: String,

        /// Build command to record in the attestation
        #[arg(long)]
        command: Option<String>,
    },

    /// Verify a signed build attestation JSON document
    Verify {
        /// Attestation JSON path
        attestation: PathBuf,

        /// Current subject file or folder to compare against the attestation
        #[arg(long)]
        subject: Option<PathBuf>,

        /// Trusted public key expected to have signed the attestation
        #[arg(long)]
        public_key: Option<PathBuf>,

        /// Optional linked .mkpe sidecar bundle
        #[arg(long)]
        bundle: Option<PathBuf>,
    },

    /// Inspect an attestation JSON document
    Inspect {
        /// Attestation JSON path
        attestation: PathBuf,
    },
}

#[derive(Subcommand)]
enum DsseCommands {
	/// Create a DSSE envelope from a manifest
	Create {
		/// Path to MKPE .mkpe file or manifest JSON
		manifest: PathBuf,
		/// Private key file
		#[arg(short, long)]
		key: PathBuf,
		/// Output DSSE envelope JSON path
		#[arg(short, long)]
		output: PathBuf,
	},
	/// Verify a DSSE envelope
	Verify {
		/// DSSE envelope JSON path
		envelope: PathBuf,
		/// Trusted public key file
		#[arg(short, long)]
		public_key: PathBuf,
	},
}

#[derive(Subcommand)]
enum PolicyCommands {
	/// Verify a manifest against a policy file
	Verify {
		/// Path to MKPE .mkpe file or manifest JSON
		manifest: PathBuf,
		/// Policy JSON file
		#[arg(short, long)]
		policy: PathBuf,
	},
}

#[derive(Subcommand)]
enum AuditCommands {
	/// Verify the chain integrity of an audit log
	VerifyChain {
		/// Path to audit log file
		log: PathBuf,
	},
	/// Compute the Merkle root of an audit log
	MerkleRoot {
		/// Path to audit log file
		log: PathBuf,
	},
}

#[derive(Subcommand)]
enum MultisigCommands {
	/// Create a multi-signature manifest from a single-signature manifest
	Create {
		/// Path to MKPE .mkpe file or manifest JSON
		manifest: PathBuf,
		/// Minimum signatures required
		#[arg(short, long)]
		threshold: usize,
		/// Output multi-signature manifest JSON path
		#[arg(short, long)]
		output: PathBuf,
	},
	/// Add a signature to a multi-signature manifest
	Add {
		/// Path to multi-signature manifest JSON
		manifest: PathBuf,
		/// Private key file
		#[arg(short, long)]
		key: PathBuf,
		/// Output path (defaults to overwriting input)
		#[arg(short, long)]
		output: Option<PathBuf>,
	},
	/// Verify a multi-signature manifest meets its threshold
	Verify {
		/// Path to multi-signature manifest JSON
		manifest: PathBuf,
		/// Trusted public key files (one or more)
		#[arg(short, long)]
		public_key: Vec<PathBuf>,
	},
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { output } => keygen_command(output, cli.verbose),
        Commands::Sign { path, key, output } => sign_command(path, key, output, cli.verbose),
        Commands::Verify { path, detailed } => verify_command(path, detailed, cli.verbose),
        Commands::Bundle { path, key, output } => bundle_command(path, key, output, cli.verbose),
        Commands::Inspect {
            path,
            export_manifest,
        } => inspect_command(path, export_manifest, cli.verbose),
        Commands::Hash { path } => hash_command(path, cli.verbose),
        Commands::ValidateCdna { path, proof, key } => {
            validate_cdna_command(path, proof, key, cli.verbose)
        }
        Commands::Version => version_command(),
        Commands::Dna { command } => dna_command(command, cli.verbose, cli.format),
        Commands::Attest { command } => attest_command(command, cli.format),
		Commands::Dsse { command } => dsse_command(command, cli.format),
		Commands::Policy { command } => policy_command(command, cli.format),
		Commands::Audit { command } => audit_command(command, cli.format),
		Commands::Multisig { command } => multisig_command(command, cli.format),
		Commands::Ownership { command } => ownership_command(command, cli.format),
    }
}

fn keygen_command(output: PathBuf, verbose: bool) -> Result<()> {
    println!("{}", "🔐 Generating Ed25519 keypair...".bold().cyan());

    let keypair = generate_keypair();

    std::fs::create_dir_all(&output).context("Failed to create key output directory")?;

    let private_key_path = output.join("mkpe_private.key");
    let public_key_path = output.join("mkpe_public.key");

    write_private_key(&private_key_path, &keypair.private_key)?;
    std::fs::write(&public_key_path, &keypair.public_key).context("Failed to write public key")?;

    println!("{}", "✓ Keypair generated successfully!".green().bold());
    println!("  {} {}", "Private key:".bold(), private_key_path.display());
    println!("  {} {}", "Public key:".bold(), public_key_path.display());
    println!("  {} {}", "Key ID:".bold(), keypair.key_id);

    if verbose {
        println!("\n{}", "WARNING:".yellow().bold());
        println!("Keep your private key secure. Anyone with access to it can sign on your behalf.");
    }

    Ok(())
}

#[cfg(unix)]
fn write_private_key(path: &PathBuf, private_key: &str) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .context("Failed to create private key with restricted permissions")?;
    file.write_all(private_key.as_bytes())
        .context("Failed to write private key")?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_key(path: &PathBuf, private_key: &str) -> Result<()> {
    use std::io::Write as _;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .context("Failed to create private key without overwriting an existing key")?;
    file.write_all(private_key.as_bytes())
        .context("Failed to write private key")?;
    Ok(())
}

fn sign_command(
    path: PathBuf,
    key_path: PathBuf,
    output: Option<PathBuf>,
    _verbose: bool,
) -> Result<()> {
    println!("{} {}", "🔏 Signing:".bold().cyan(), path.display());

    let private_key = std::fs::read_to_string(&key_path).context("Failed to read private key")?;

    let public_key_path = key_path.with_file_name("mkpe_public.key");
    let public_key = std::fs::read_to_string(&public_key_path)
        .context("Failed to read public key (expected mkpe_public.key in same directory)")?;

    let key_id = uuid::Uuid::new_v4().to_string();
    let keypair = KeyPair::new(
        private_key.trim().to_string(),
        public_key.trim().to_string(),
        key_id,
    );

    let output_path = output.unwrap_or_else(|| morse_kirby_core::default_sidecar_path(&path));

    let archive = create_mkpe_bundle(&path, &keypair, &output_path)
        .context("Failed to create MKPE bundle")?;

    let stats = archive.stats();

    println!("{}", "✓ Bundle created successfully!".green().bold());
    println!("  {} {}", "Output:".bold(), output_path.display());
    println!("  {} {}", "Bundles:".bold(), stats.bundle_count);
    println!("  {} {}", "Total proofs:".bold(), stats.total_proof_items);
    println!("  {} {}", "Root hash:".bold(), &stats.root_hash[..16]);
    println!("  {} {}", "Manifest ID:".bold(), stats.manifest_id);

    Ok(())
}

fn load_keypair(key_path: &PathBuf) -> Result<KeyPair> {
    let private_key = std::fs::read_to_string(key_path).context("Failed to read private key")?;

    let public_key_path = key_path.with_file_name("mkpe_public.key");
    let public_key = std::fs::read_to_string(&public_key_path)
        .context("Failed to read public key (expected mkpe_public.key in same directory)")?;

    let key_id = uuid::Uuid::new_v4().to_string();
    Ok(KeyPair::new(
        private_key.trim().to_string(),
        public_key.trim().to_string(),
        key_id,
    ))
}

fn verify_command(path: PathBuf, detailed: bool, verbose: bool) -> Result<()> {
    println!("{} {}", "🔍 Verifying:".bold().cyan(), path.display());

    let archive = MkpeArchive::load(&path).context("Failed to load MKPE archive")?;

    match archive.verify() {
        Ok(verified_archive) => {
            println!("{}", "✓ Verification PASSED".green().bold());

            if detailed || verbose {
                // Access inner archive from verified wrapper
                let archive = verified_archive.inner();
                let stats = archive.stats();
                println!("\n{}", "Bundle Information:".bold());
                println!("  {} {}", "Manifest ID:".bold(), stats.manifest_id);
                println!("  {} {}", "Root hash:".bold(), stats.root_hash);
                println!("  {} {}", "Bundle count:".bold(), stats.bundle_count);
                println!("  {} {}", "Total proofs:".bold(), stats.total_proof_items);
                println!(
                    "  {} {}",
                    "Created:".bold(),
                    stats.created_at.format("%Y-%m-%d %H:%M:%S UTC")
                );

                println!("\n{}", "System Fingerprint:".bold());
                let fingerprint = &archive.manifest.system_fingerprint;
                println!("  {} {}", "User:".bold(), fingerprint.user);
                println!("  {} {}", "Platform:".bold(), fingerprint.platform);
                println!("  {} {}", "Hostname:".bold(), fingerprint.hostname);
                println!("  {} {}", "MKPE version:".bold(), fingerprint.mkpe_version);
            }
        }
        Err(e) => {
            println!("{}", "✗ Verification FAILED".red().bold());
            println!("  Error: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}

fn bundle_command(path: PathBuf, key_path: PathBuf, output: PathBuf, verbose: bool) -> Result<()> {
    sign_command(path, key_path, Some(output), verbose)
}

fn inspect_command(path: PathBuf, export_manifest: Option<PathBuf>, _verbose: bool) -> Result<()> {
    println!("{} {}", "🔎 Inspecting:".bold().cyan(), path.display());

    let archive = MkpeArchive::load(&path).context("Failed to load MKPE archive")?;

    let stats = archive.stats();

    println!("\n{}", "Archive Statistics:".bold());
    println!("  {} {}", "Format version:".bold(), archive.format_version);
    println!(
        "  {} {}",
        "Schema version:".bold(),
        archive.manifest.schema_version
    );
    println!(
        "  {} {}",
        "Engine version:".bold(),
        archive.manifest.engine_version
    );
    println!("  {} {}", "Manifest ID:".bold(), stats.manifest_id);
    println!("  {} {}", "Bundle count:".bold(), stats.bundle_count);
    println!("  {} {}", "Total proofs:".bold(), stats.total_proof_items);
    println!(
        "  {} {}",
        "Created:".bold(),
        stats.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );

    println!("\n{}", "System Fingerprint:".bold());
    let fingerprint = &archive.manifest.system_fingerprint;
    println!("  {} {}", "User:".bold(), fingerprint.user);
    println!("  {} {}", "Platform:".bold(), fingerprint.platform);
    println!("  {} {}", "Hostname:".bold(), fingerprint.hostname);
    println!("  {} {}", "Process ID:".bold(), fingerprint.process_id);
    println!(
        "  {} {}",
        "Timestamp:".bold(),
        fingerprint.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
    );

    println!("\n{}", "Cryptographic Information:".bold());
    println!(
        "  {} {}",
        "Root hash:".bold(),
        archive.manifest.bundle_root_hash
    );
    println!(
        "  {} {}...",
        "Signature:".bold(),
        &archive.manifest.signature[..32]
    );
    println!(
        "  {} {}...",
        "Public key:".bold(),
        &archive.manifest.verifier_public_key[..32]
    );

    if let Some(export_path) = export_manifest {
        let manifest_json = serde_json::to_string_pretty(&archive.manifest)?;
        std::fs::write(&export_path, manifest_json)?;
        println!(
            "\n{} {}",
            "✓ Manifest exported to:".green(),
            export_path.display()
        );
    }

    Ok(())
}

fn hash_command(path: PathBuf, _verbose: bool) -> Result<()> {
    use sha2::{Digest, Sha256};

    let contents = std::fs::read(&path).context("Failed to read file")?;

    let mut hasher = Sha256::new();
    hasher.update(&contents);
    let hash = hex::encode(hasher.finalize());

    println!("{}", "SHA-256 Hash:".bold().cyan());
    println!("{}", hash);

    Ok(())
}

fn validate_cdna_command(
    path: PathBuf,
    generate_proof: bool,
    key_path: Option<PathBuf>,
    _verbose: bool,
) -> Result<()> {
    println!(
        "{} {}",
        "🧬 Validating C-DNA schema:".bold().cyan(),
        path.display()
    );

    let schema = CdnaSchema::from_file(&path).context("Failed to load C-DNA schema")?;

    println!("{}", "✓ Schema is valid JSON".green());
    println!("  {} {}", "C-DNA version:".bold(), schema.c_dna_version);
    println!("  {} {}", "Program ID:".bold(), schema.program_id);
    println!("  {} {}", "Intent:".bold(), schema.intent);
    println!("  {} {}", "Nodes:".bold(), schema.nodes.len());
    println!("  {} {}", "Edges:".bold(), schema.edges.len());

    let schema_hash = schema.calculate_hash();
    println!("  {} {}", "Schema hash:".bold(), schema_hash);

    if generate_proof {
        let key_path = key_path.context("--key is required when using --proof")?;

        let private_key =
            std::fs::read_to_string(&key_path).context("Failed to read private key")?;
        let public_key_path = key_path.with_file_name("mkpe_public.key");
        let public_key =
            std::fs::read_to_string(&public_key_path).context("Failed to read public key")?;

        let key_id = uuid::Uuid::new_v4().to_string();
        let keypair = KeyPair::new(
            private_key.trim().to_string(),
            public_key.trim().to_string(),
            key_id,
        );

        let proof = schema.create_proof(&keypair)?;

        let proof_path = path.with_extension("cdna.proof.json");
        let proof_json = serde_json::to_string_pretty(&proof)?;
        std::fs::write(&proof_path, proof_json)?;

        println!(
            "\n{} {}",
            "✓ Proof generated:".green().bold(),
            proof_path.display()
        );
        println!("  {} {}", "Proof ID:".bold(), proof.proof_id);
    }

    Ok(())
}

fn dna_command(command: DnaCommands, verbose: bool, format: OutputFormat) -> Result<()> {
    match command {
        DnaCommands::Create {
            artifact,
            key,
            output,
        } => {
            let output_path =
                output.unwrap_or_else(|| morse_kirby_core::default_sidecar_path(&artifact));
            let keypair = load_keypair(&key)?;
            let archive = create_mkpe_bundle(&artifact, &keypair, &output_path)
                .context("Failed to create MKPE DNA proof")?;
            let stats = archive.stats();

            if format == OutputFormat::Json {
                println!(
                    "{}",
                    serde_json::json!({
                        "status": "created",
                        "artifact": artifact,
                        "sidecar": output_path,
                        "byte_proofs": stats.total_proof_items,
                        "root_hash": stats.root_hash,
                        "manifest_id": stats.manifest_id,
                    })
                );
            } else {
                println!("{}", "DNA proof created".green().bold());
                println!("  {} {}", "Artifact:".bold(), artifact.display());
                println!("  {} {}", "Sidecar:".bold(), output_path.display());
                println!("  {} {}", "Byte proofs:".bold(), stats.total_proof_items);
                println!("  {} {}", "Root hash:".bold(), stats.root_hash);
                println!("  {} {}", "Manifest ID:".bold(), stats.manifest_id);
            }
        }
        DnaCommands::Verify {
            artifact,
            bundle,
            public_key,
        } => {
            let archive = match MkpeArchive::load(&bundle) {
                Ok(archive) => archive,
                Err(error) => {
                    emit_dna_verify_failure(&artifact, &bundle, &error, format);
                    std::process::exit(3);
                }
            };
            let trusted_public_key = match public_key
                .as_ref()
                .map(std::fs::read_to_string)
                .transpose()
            {
                Ok(public_key) => public_key,
                Err(error) => {
                    emit_dna_verify_failure(&artifact, &bundle, &MkpeError::IoError(error), format);
                    std::process::exit(3);
                }
            };

            let verification = match trusted_public_key.as_deref() {
                Some(public_key) => archive.verify_artifact_with_public_key(&artifact, public_key),
                None => archive.verify_artifact(&artifact),
            };

            match verification {
                Ok(report) => {
                    let trusted = trusted_public_key.is_some();
                    if format == OutputFormat::Json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "status": "verified",
                                "trusted_signer": trusted,
                                "artifact": artifact,
                                "sidecar": bundle,
                                "verified_proofs": report.verified_proofs,
                                "root_hash": report.root_hash,
                                "manifest_id": report.manifest_id,
                            })
                        );
                    } else {
                        if trusted {
                            println!(
                                "{}",
                                "DNA verification PASSED (trusted signer)".green().bold()
                            );
                        } else {
                            println!(
                                "{}",
                                "DNA integrity PASSED (signer not trust-pinned)"
                                    .yellow()
                                    .bold()
                            );
                        }
                        println!("  {} {}", "Artifact:".bold(), artifact.display());
                        println!("  {} {}", "Sidecar:".bold(), bundle.display());
                        println!("  {} {}", "Verified proofs:".bold(), report.verified_proofs);
                        println!("  {} {}", "Root hash:".bold(), report.root_hash);
                    }
                }
                Err(error) => {
                    let code = if matches!(error, MkpeError::VerificationFailed(_)) {
                        2
                    } else {
                        3
                    };
                    emit_dna_verify_failure(&artifact, &bundle, &error, format);
                    std::process::exit(code);
                }
            }
        }
        DnaCommands::Inspect { bundle } => {
            inspect_command(bundle, None, verbose)?;
        }
        DnaCommands::Embed { artifact, attestation, key, output } => {
            dna_embed_command(&artifact, &attestation, &key, output.as_ref(), format)?;
        }
        DnaCommands::Extract { artifact, key, attestation } => {
            dna_extract_command(&artifact, &key, attestation.as_ref(), format)?;
        }
    }

    Ok(())
}
/// Embed a DNA provenance tag into a binary artifact.
fn dna_embed_command(
    artifact: &PathBuf,
    attestation_path: &PathBuf,
    key_path: &PathBuf,
    output: Option<&PathBuf>,
    format: OutputFormat,
) -> Result<()> {
    let attestation_bytes = std::fs::read(attestation_path)
        .with_context(|| format!("Failed to read attestation: {}", attestation_path.display()))?;
    let payload: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(&attestation_bytes);
        hasher.finalize().into()
    };
    let tag = morse_kirby_core::DnaTag::from_payload(payload);

    let keypair = load_keypair(key_path)?;
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&keypair.private_key)
        .map_err(|e| anyhow::anyhow!("Failed to decode private key: {}", e))?;
    if key_bytes.len() != 32 {
        return Err(anyhow::anyhow!("Private key must be 32 bytes for DNA secret derivation"));
    }
    let secret = morse_kirby_core::derive_dna_secret(
        key_bytes.as_slice().try_into().unwrap()
    );

    let mut file_bytes = std::fs::read(artifact)
        .with_context(|| format!("Failed to read artifact: {}", artifact.display()))?;

    let modified = morse_kirby_core::embed_dna(&mut file_bytes, &tag, &secret,
    )
    .with_context(|| "DNA embedding failed")?;

    let out_path = output.unwrap_or(artifact);
    std::fs::write(out_path, &file_bytes)
        .with_context(|| format!("Failed to write tagged artifact: {}", out_path.display()))?;

    if format == OutputFormat::Json {
        println!(
            "{}",
            serde_json::json!({
                "status": "embedded",
                "artifact": artifact,
                "output": out_path,
                "attestation": attestation_path,
                "dna_payload": hex::encode(&payload),
                "modified_bytes": modified,
            })
        );
    } else {
        println!("{}", "DNA tag embedded".green().bold());
        println!("  {} {}", "Artifact:".bold(), artifact.display());
        println!("  {} {}", "Output:".bold(), out_path.display());
        println!("  {} {}", "Attestation:".bold(), attestation_path.display());
        println!("  {} {}", "DNA payload:".bold(), hex::encode(&payload));
        println!("  {} {}", "Modified bytes:".bold(), modified);
    }
    Ok(())
}

/// Extract and optionally verify a DNA tag from a binary artifact.
fn dna_extract_command(
    artifact: &PathBuf,
    key_path: &PathBuf,
    attestation_path: Option<&PathBuf>,
    format: OutputFormat,
) -> Result<()> {
    let keypair = load_keypair(key_path)?;
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&keypair.private_key)
        .map_err(|e| anyhow::anyhow!("Failed to decode private key: {}", e))?;
    if key_bytes.len() != 32 {
        return Err(anyhow::anyhow!("Private key must be 32 bytes for DNA secret derivation"));
    }
    let secret = morse_kirby_core::derive_dna_secret(
        key_bytes.as_slice().try_into().unwrap()
    );

    let file_bytes = std::fs::read(artifact)
        .with_context(|| format!("Failed to read artifact: {}", artifact.display()))?;

    let tag = morse_kirby_core::extract_dna(&file_bytes, &secret,
    )
    .with_context(|| "DNA extraction failed — tag may be missing or corrupted")?;

    let mut verified = false;
    if let Some(path) = attestation_path {
        let attestation_bytes = std::fs::read(path)
            .with_context(|| format!("Failed to read attestation: {}", path.display()))?;
        let expected: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(&attestation_bytes);
            hasher.finalize().into()
        };
        if tag.payload == expected {
            verified = true;
        } else {
            return Err(anyhow::anyhow!(
                "Extracted DNA payload does not match attestation hash\n  expected: {}\n  found:    {}",
                hex::encode(&expected),
                hex::encode(&tag.payload)
            ));
        }
    }

    if format == OutputFormat::Json {
        println!(
            "{}",
            serde_json::json!({
                "status": if verified { "verified" } else { "extracted" },
                "artifact": artifact,
                "dna_payload": hex::encode(&tag.payload),
                "verified": verified,
            })
        );
    } else {
        if verified {
            println!("{}", "DNA tag extracted and VERIFIED".green().bold());
        } else {
            println!("{}", "DNA tag extracted".green().bold());
        }
        println!("  {} {}", "Artifact:".bold(), artifact.display());
        println!("  {} {}", "DNA payload:".bold(), hex::encode(&tag.payload));
    }
    Ok(())
}

fn attest_command(command: AttestCommands, format: OutputFormat) -> Result<()> {
    match command {
        AttestCommands::Generate {
            subject,
            key,
            output,
            bundle,
            attested_by,
            command,
        } => {
            let keypair = load_keypair(&key)?;
            let attestation = create_build_attestation(
                &subject,
                &keypair,
                AttestationOptions {
                    attested_by,
                    command,
                    bundle_path: bundle,
                },
            )
            .context("Failed to create build attestation")?;
            let attestation_json = serde_json::to_string_pretty(&attestation)?;
            std::fs::write(&output, attestation_json).context("Failed to write attestation")?;

            if format == OutputFormat::Json {
                println!(
                    "{}",
                    serde_json::json!({
                        "status": "created",
                        "attestation": output,
                        "attestation_id": attestation.attestation_id,
                        "subject": subject,
                        "subject_sha256": attestation.subject_sha256,
                        "bundle_manifest_id": attestation.bundle_manifest_id,
                        "bundle_root_hash": attestation.bundle_root_hash,
                    })
                );
            } else {
                println!("{}", "Build attestation created".green().bold());
                println!("  {} {}", "Subject:".bold(), subject.display());
                println!("  {} {}", "Attestation:".bold(), output.display());
                println!(
                    "  {} {}",
                    "Attestation ID:".bold(),
                    attestation.attestation_id
                );
                println!(
                    "  {} {}",
                    "Subject SHA-256:".bold(),
                    attestation.subject_sha256
                );
                if let Some(root_hash) = attestation.bundle_root_hash {
                    println!("  {} {}", "Linked bundle root:".bold(), root_hash);
                }
            }
        }
        AttestCommands::Verify {
            attestation,
            subject,
            public_key,
            bundle,
        } => {
            let loaded = match load_attestation(&attestation) {
                Ok(attestation) => attestation,
                Err(error) => {
                    emit_attest_verify_failure(&attestation, &error, format);
                    std::process::exit(3);
                }
            };
            let Some(public_key) = public_key.as_ref() else {
                emit_attest_verify_failure(
                    &attestation,
                    &MkpeError::VerificationFailed(
                        "Trusted public key is required for attestation verification".to_string(),
                    ),
                    format,
                );
                std::process::exit(3);
            };
            let trusted_public_key = match std::fs::read_to_string(public_key) {
                Ok(public_key) => public_key,
                Err(error) => {
                    emit_attest_verify_failure(&attestation, &MkpeError::IoError(error), format);
                    std::process::exit(3);
                }
            };

            let verification = verify_build_attestation(
                &loaded,
                AttestationVerificationOptions {
                    subject_path: subject.clone(),
                    trusted_public_key: Some(trusted_public_key),
                    bundle_path: bundle,
                },
            );

            match verification {
                Ok(report) => {
                    if format == OutputFormat::Json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "status": "verified",
                                "attestation": attestation,
                                "attestation_id": report.attestation_id,
                                "subject_sha256": report.subject_sha256,
                                "trusted_signer": report.trusted_signer,
                                "signer_public_key": report.signer_public_key,
                                "bundle_manifest_id": report.bundle_manifest_id,
                                "bundle_root_hash": report.bundle_root_hash,
                            })
                        );
                    } else {
                        if report.trusted_signer {
                            println!(
                                "{}",
                                "Attestation verification PASSED (trusted signer)"
                                    .green()
                                    .bold()
                            );
                        } else {
                            println!(
                                "{}",
                                "Attestation integrity PASSED (signer not trust-pinned)"
                                    .yellow()
                                    .bold()
                            );
                        }
                        println!("  {} {}", "Attestation:".bold(), attestation.display());
                        if let Some(subject) = subject {
                            println!("  {} {}", "Subject:".bold(), subject.display());
                        }
                        println!("  {} {}", "Subject SHA-256:".bold(), report.subject_sha256);
                    }
                }
                Err(error) => {
                    let code = if matches!(error, MkpeError::VerificationFailed(_)) {
                        2
                    } else {
                        3
                    };
                    emit_attest_verify_failure(&attestation, &error, format);
                    std::process::exit(code);
                }
            }
        }
        AttestCommands::Inspect { attestation } => {
            let loaded = load_attestation(&attestation)?;
            if format == OutputFormat::Json {
                println!("{}", serde_json::to_string(&loaded)?);
            } else {
                println!(
                    "{} {}",
                    "Inspecting attestation:".bold().cyan(),
                    attestation.display()
                );
                println!("  {} {}", "Attestation ID:".bold(), loaded.attestation_id);
                println!("  {} {}", "Subject:".bold(), loaded.subject_path);
                println!("  {} {:?}", "Subject kind:".bold(), loaded.subject_kind);
                println!("  {} {}", "Subject SHA-256:".bold(), loaded.subject_sha256);
                println!("  {} {}", "Attested by:".bold(), loaded.attested_by);
                println!(
                    "  {} {}",
                    "Signer public key:".bold(),
                    loaded.signer_public_key
                );
                if let Some(root_hash) = loaded.bundle_root_hash {
                    println!("  {} {}", "Linked bundle root:".bold(), root_hash);
                }
            }
        }
    }

    Ok(())
}

fn load_attestation(path: &PathBuf) -> morse_kirby_core::Result<BuildAttestation> {
    let content = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}

fn emit_attest_verify_failure(attestation: &PathBuf, error: &MkpeError, format: OutputFormat) {
    if format == OutputFormat::Json {
        println!(
            "{}",
            serde_json::json!({
                "status": "failed",
                "attestation": attestation,
                "reason": error.to_string(),
            })
        );
        return;
    }

    println!("{}", "Attestation verification FAILED".red().bold());
    println!("  {} {}", "Attestation:".bold(), attestation.display());
    println!("  {} {}", "Reason:".bold(), error);
}

fn emit_dna_verify_failure(
    artifact: &PathBuf,
    bundle: &PathBuf,
    error: &MkpeError,
    format: OutputFormat,
) {
    if format == OutputFormat::Json {
        println!(
            "{}",
            serde_json::json!({
                "status": "failed",
                "artifact": artifact,
                "sidecar": bundle,
                "reason": error.to_string(),
            })
        );
        return;
    }

    println!("{}", "DNA verification FAILED".red().bold());
    println!("  {} {}", "Artifact:".bold(), artifact.display());
    println!("  {} {}", "Sidecar:".bold(), bundle.display());
    println!("  {} {}", "Reason:".bold(), error);
}

fn version_command() -> Result<()> {
    println!("{}", "Morse-Kirby Provenance Engine (MKPE)".bold().cyan());
    println!("Version: {}", MKPE_VERSION.bold());
    println!("Schema Version: {}", SCHEMA_VERSION);
    println!("\n{}", "Lineage:".bold());
    println!("  ADNA → Structural mapping");
    println!("  CDNA → Component identity");
    println!("  MKPE → Cryptographic provenance");
    println!("\n{}", "Core Principle:".italic());
    println!("  \"Every verified object carries its own truth.\"");

    Ok(())
}

fn load_manifest(path: &PathBuf) -> Result<Manifest> {
	let content = std::fs::read_to_string(path).context("Failed to read manifest file")?;
	serde_json::from_str(&content).context("Failed to parse manifest JSON")
}

fn dsse_command(command: DsseCommands, format: OutputFormat) -> Result<()> {
	match command {
		DsseCommands::Create { manifest: manifest_path, key, output } => {
			let keypair = load_keypair(&key)?;
			let manifest = load_manifest(&manifest_path)?;
			let envelope = DSSEEnvelope::from_manifest(&manifest, &keypair)
				.map_err(|e| anyhow::anyhow!("Failed to create DSSE envelope: {}", e))?;
			let json = envelope.to_json()
				.map_err(|e| anyhow::anyhow!("Failed to serialize DSSE envelope: {}", e))?;
			std::fs::write(&output, json).context("Failed to write DSSE envelope")?;
			if format == OutputFormat::Json {
				println!("{}", serde_json::json!({"status": "created", "envelope": output }));
			} else {
				println!("{}", "DSSE envelope created".green().bold());
				println!("  {} {}", "Envelope:".bold(), output.display());
			}
		}
		DsseCommands::Verify { envelope: envelope_path, public_key } => {
			let public_key = std::fs::read_to_string(&public_key).context("Failed to read public key")?;
			let envelope_str = std::fs::read_to_string(&envelope_path).context("Failed to read DSSE envelope")?;
			let envelope = DSSEEnvelope::from_json(&envelope_str)
				.map_err(|e| anyhow::anyhow!("Failed to parse DSSE envelope: {}", e))?;
			if envelope.verify(public_key.trim())
				.map_err(|e| anyhow::anyhow!("Verification error: {}", e))? {
				if format == OutputFormat::Json {
					println!("{}", serde_json::json!({"status": "verified", "envelope": envelope_path, "trusted_signer": true }));
				} else {
					println!("{}", "DSSE envelope verification PASSED".green().bold());
					println!("  {} {}", "Envelope:".bold(), envelope_path.display());
				}
			} else {
				if format == OutputFormat::Json {
					println!("{}", serde_json::json!({"status": "failed", "envelope": envelope_path, "reason": "signature invalid" }));
				} else {
					println!("{}", "DSSE envelope verification FAILED".red().bold());
				}
				std::process::exit(2);
			}
		}
	}
	Ok(())
}

fn policy_command(command: PolicyCommands, format: OutputFormat) -> Result<()> {
	match command {
		PolicyCommands::Verify { manifest: manifest_path, policy } => {
			let manifest = load_manifest(&manifest_path)?;
			let engine = PolicyEngine::load_from_json(&policy)
				.map_err(|e| anyhow::anyhow!("Failed to load policy: {}", e))?;
			match engine.verify(&manifest) {
				Ok(true) => {
					if format == OutputFormat::Json {
						println!("{}", serde_json::json!({"status": "verified", "manifest": manifest_path, "policy": policy }));
					} else {
						println!("{}", "Policy verification PASSED".green().bold());
					}
				}
				Ok(false) => {
					if format == OutputFormat::Json {
						println!("{}", serde_json::json!({"status": "failed", "manifest": manifest_path, "policy": policy, "reason": "policy conditions not met" }));
					} else {
						println!("{}", "Policy verification FAILED".red().bold());
					}
					std::process::exit(2);
				}
				Err(e) => {
					if format == OutputFormat::Json {
						println!("{}", serde_json::json!({"status": "error", "reason": e.to_string() }));
					} else {
						println!("{}", format!("Policy verification error: {}", e).red().bold());
					}
					std::process::exit(3);
				}
			}
		}
	}
	Ok(())
}

fn audit_command(command: AuditCommands, _format: OutputFormat) -> Result<()> {
	match command {
		AuditCommands::VerifyChain { log } => {
			let audit_log = AuditLog::new(&log)?;
			match audit_log.verify_chain() {
				Ok(true) => println!("{}", "Audit chain integrity PASSED".green().bold()),
				Ok(false) => {
					println!("{}", "Audit chain integrity FAILED".red().bold());
					std::process::exit(2);
				}
				Err(e) => {
					println!("{}", format!("Audit chain error: {}", e).red().bold());
					std::process::exit(3);
				}
			}
		}
		AuditCommands::MerkleRoot { log } => {
			let audit_log = AuditLog::new(&log)?;
			match audit_log.compute_merkle_root() {
				Ok(Some(root)) => {
					println!("{}", "Audit log Merkle root:".bold().cyan());
					println!("{}", root);
				}
				Ok(None) => println!("{}", "Audit log is empty (no Merkle root)".yellow().bold()),
				Err(e) => {
					println!("{}", format!("Merkle root error: {}", e).red().bold());
					std::process::exit(3);
				}
			}
		}
	}
	Ok(())
}

fn multisig_command(command: MultisigCommands, format: OutputFormat) -> Result<()> {
	match command {
		MultisigCommands::Create { manifest: manifest_path, threshold, output } => {
			let manifest = load_manifest(&manifest_path)?;
			let msm = MultiSignatureManifest::new(manifest, threshold);
			let json = serde_json::to_string_pretty(&msm)?;
			std::fs::write(&output, json).context("Failed to write multi-signature manifest")?;
			if format == OutputFormat::Json {
				println!("{}", serde_json::json!({"status": "created", "output": output, "threshold": threshold }));
			} else {
				println!("{}", "Multi-signature manifest created".green().bold());
				println!("  {} {}", "Output:".bold(), output.display());
				println!("  {} {}", "Threshold:".bold(), threshold);
			}
		}
		MultisigCommands::Add { manifest: manifest_path, key, output } => {
			let keypair = load_keypair(&key)?;
			let content = std::fs::read_to_string(&manifest_path).context("Failed to read manifest")?;
			let mut msm: MultiSignatureManifest = serde_json::from_str(&content).context("Failed to parse multi-signature manifest")?;
			msm.add_signature(&keypair)
				.map_err(|e| anyhow::anyhow!("Failed to add signature: {}", e))?;
			let out_path = output.unwrap_or(manifest_path);
			let json = serde_json::to_string_pretty(&msm)?;
			std::fs::write(&out_path, json).context("Failed to write multi-signature manifest")?;
			if format == OutputFormat::Json {
				println!("{}", serde_json::json!({"status": "signature_added", "signatures": msm.multisig.signatures.len(), "output": out_path }));
			} else {
				println!("{}", "Signature added to multi-signature manifest".green().bold());
				println!("  {} {}", "Signatures:".bold(), msm.multisig.signatures.len());
			}
		}
		MultisigCommands::Verify { manifest: manifest_path, public_key } => {
			let content = std::fs::read_to_string(&manifest_path).context("Failed to read manifest")?;
			let msm: MultiSignatureManifest = serde_json::from_str(&content).context("Failed to parse multi-signature manifest")?;
			let mut trusted = Vec::new();
			for pk_path in &public_key {
				let pk = std::fs::read_to_string(pk_path).context("Failed to read public key")?;
				trusted.push(pk.trim().to_string());
			}
			match msm.verify(&trusted) {
				Ok(true) => {
					if format == OutputFormat::Json {
						println!("{}", serde_json::json!({"status": "verified", "manifest": manifest_path, "threshold_met": true }));
					} else {
						println!("{}", "Multi-signature verification PASSED".green().bold());
						println!("  {} {}", "Signatures:".bold(), msm.multisig.signatures.len());
						println!("  {} {}", "Threshold:".bold(), msm.multisig.threshold);
					}
				}
				Ok(false) => {
					if format == OutputFormat::Json {
						println!("{}", serde_json::json!({"status": "failed", "manifest": manifest_path, "reason": "threshold not met" }));
					} else {
						println!("{}", "Multi-signature verification FAILED (threshold not met)".red().bold());
					}
					std::process::exit(2);
				}
				Err(e) => {
					if format == OutputFormat::Json {
						println!("{}", serde_json::json!({"status": "error", "reason": e.to_string() }));
					} else {
						println!("{}", format!("Multi-signature verification error: {}", e).red().bold());
					}
					std::process::exit(3);
				}
			}
		}
	}
	Ok(())
}

fn ownership_command(command: OwnershipCommands, format: OutputFormat) -> Result<()> {
    match command {
        OwnershipCommands::Transfer {
            asset,
            previous,
            from_key,
            to_key,
            marketplace_key,
            nonce,
            output,
            price,
            currency,
            royalty,
            max_resales,
        } => {
            ownership_transfer_command(
                asset, previous, from_key, to_key, marketplace_key, nonce,
                output, price, currency, royalty, max_resales, format,
            )?
        }
        OwnershipCommands::Sign { manifest, key, output } => {
            ownership_sign_command(&manifest, &key, &output, format)?
        }
        OwnershipCommands::VerifyChain {
            asset,
            genesis,
            chain_dir,
            public_keys,
        } => {
            ownership_verify_chain_command(&asset, &genesis, &chain_dir, &public_keys, format)?
        }
        OwnershipCommands::Revoke {
            transfer_id,
            key,
            reason,
            output,
        } => {
            ownership_revoke_command(&transfer_id, &key, &reason, &output, format)?
        }
    }
    Ok(())
}

fn ownership_transfer_command(
    asset: String,
    previous: String,
    from_key: PathBuf,
    to_key: PathBuf,
    marketplace_key: Option<PathBuf>,
    nonce: u64,
    output: PathBuf,
    price: Option<String>,
    currency: Option<String>,
    royalty: Option<u8>,
    max_resales: Option<u32>,
    format: OutputFormat,
) -> Result<()> {
    let mut seller = load_keypair(&from_key)?;
    seller.key_id = public_key_to_key_id(&seller.public_key);

    let buyer_pubkey = std::fs::read_to_string(&to_key)
        .with_context(|| format!("Failed to read buyer public key: {}", to_key.display()))?;
    let buyer_pubkey = buyer_pubkey.trim().to_string();
    let buyer_key_id = public_key_to_key_id(&buyer_pubkey);

    let marketplace_key_id = marketplace_key.as_ref().map(|path| {
        let pk = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read marketplace public key: {}", path.display()))
            .unwrap();
        public_key_to_key_id(pk.trim())
    });

    let terms = morse_kirby_core::TransferTerms {
        price,
        currency,
        royalty_percentage: royalty,
        max_resale_count: max_resales,
        custom: std::collections::HashMap::new(),
    };

    let mut required_signers = vec![seller.key_id.clone(), buyer_key_id.clone()];
    if let Some(ref mkid) = marketplace_key_id {
        required_signers.push(mkid.clone());
    }

    let mut manifest = morse_kirby_core::TransferManifest::new(
        asset.clone(),
        Some(previous.clone()),
        seller.key_id.clone(),
        buyer_key_id,
        marketplace_key_id,
        nonce,
        terms,
        required_signers,
    );

    // Seller signs first
    manifest.sign(&seller)
        .with_context(|| "Seller failed to sign transfer manifest")?;

    // Marketplace signs if provided
    if let Some(ref path) = marketplace_key {
        let mut market_keypair = load_keypair(path)
            .with_context(|| "Failed to load marketplace keypair for signing")?;
        market_keypair.key_id = public_key_to_key_id(&market_keypair.public_key);
        manifest.sign(&market_keypair)
            .with_context(|| "Marketplace failed to sign transfer manifest")?;
    }

    let json = serde_json::to_string_pretty(&manifest)
        .with_context(|| "Failed to serialize transfer manifest")?;
    std::fs::write(&output, json)
        .with_context(|| format!("Failed to write transfer manifest: {}", output.display()))?;

    if format == OutputFormat::Json {
        println!(
            "{}",
            serde_json::json!({
                "status": "created",
                "transfer_id": manifest.transfer_id,
                "asset": asset,
                "previous": previous,
                "from": seller.key_id,
                "to": manifest.to_key_id,
                "output": output,
                "executed": manifest.is_valid(),
            })
        );
    } else {
        println!("{}", "Ownership transfer manifest created".green().bold());
        println!("  {} {}", "Transfer ID:".bold(), manifest.transfer_id);
        println!("  {} {}", "Asset:".bold(), asset);
        println!("  {} {}", "From:".bold(), seller.key_id);
        println!("  {} {}", "To:".bold(), manifest.to_key_id);
        println!("  {} {}", "Output:".bold(), output.display());
        if manifest.is_valid() {
            println!("  {}", "Status: Executed (all signatures present)".green().bold());
        } else {
            println!("  {}", "Status: Proposed (awaiting buyer signature)".yellow().bold());
        }
    }
    Ok(())
}

fn ownership_sign_command(
    manifest_path: &PathBuf,
    key_path: &PathBuf,
    output: &PathBuf,
    format: OutputFormat,
) -> Result<()> {
    let json = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("Failed to read manifest: {}", manifest_path.display()))?;
    let mut manifest: morse_kirby_core::TransferManifest = serde_json::from_str(&json)
        .with_context(|| "Failed to parse transfer manifest JSON")?;

    let mut keypair = load_keypair(key_path)?;
    keypair.key_id = public_key_to_key_id(&keypair.public_key);
    manifest
        .sign(&keypair)
        .with_context(|| format!("Failed to sign manifest with key {}", keypair.key_id))?;

    let updated = serde_json::to_string_pretty(&manifest)
        .with_context(|| "Failed to serialize updated manifest")?;
    std::fs::write(output, updated)
        .with_context(|| format!("Failed to write updated manifest: {}", output.display()))?;

    if format == OutputFormat::Json {
        println!(
            "{}",
            serde_json::json!({
                "status": "signed",
                "transfer_id": manifest.transfer_id,
                "signer": keypair.key_id,
                "executed": manifest.is_valid(),
                "output": output,
            })
        );
    } else {
        println!("{}", "Transfer manifest signed".green().bold());
        println!("  {} {}", "Transfer ID:".bold(), manifest.transfer_id);
        println!("  {} {}", "Signer:".bold(), keypair.key_id);
        if manifest.is_valid() {
            println!("  {}", "Status: Executed (all required signatures present)".green().bold());
        } else {
            println!("  {}", "Status: Proposed (awaiting more signatures)".yellow().bold());
        }
    }
    Ok(())
}

fn ownership_verify_chain_command(
    asset: &str,
    genesis: &str,
    chain_dir: &PathBuf,
    public_keys: &str,
    format: OutputFormat,
) -> Result<()> {
    let mut chain = morse_kirby_core::OwnershipChain::new(asset.to_string(), genesis.to_string());

    // Load trusted public keys
    let pk_map = load_public_keys(public_keys)?;

    // Read all manifest JSON files in chain_dir
    let entries = std::fs::read_dir(chain_dir)
        .with_context(|| format!("Failed to read chain directory: {}", chain_dir.display()))?;

    let mut manifests: Vec<morse_kirby_core::TransferManifest> = Vec::new();
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            let json = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read manifest: {}", path.display()))?;
            let manifest: morse_kirby_core::TransferManifest = serde_json::from_str(&json)
                .with_context(|| format!("Failed to parse manifest: {}", path.display()))?;
            manifests.push(manifest);
        }
    }

    // Sort manifests into chain order by following previous_manifest_id links
    // from genesis onward
    let mut ordered = Vec::new();
    let mut expected_prev = Some(genesis.to_string());
    while let Some(ref target) = expected_prev {
        let pos = manifests.iter().position(|m| {
            m.previous_manifest_id.as_ref() == Some(target)
        });
        if let Some(idx) = pos {
            let m = manifests.remove(idx);
            expected_prev = Some(m.transfer_id.clone());
            ordered.push(m);
        } else {
            break;
        }
    }

    // Append each in order
    for manifest in ordered {
        if let Err(e) = chain.append(manifest, &pk_map) {
            if format == OutputFormat::Json {
                println!(
                    "{}",
                    serde_json::json!({
                        "status": "invalid",
                        "asset": asset,
                        "genesis": genesis,
                        "reason": e.to_string(),
                    })
                );
            } else {
                println!("{}", "Ownership chain verification FAILED".red().bold());
                println!("  {} {}", "Reason:".bold(), e);
            }
            std::process::exit(2);
        }
    }

    if format == OutputFormat::Json {
        println!(
            "{}",
            serde_json::json!({
                "status": if chain.is_valid() { "valid" } else { "invalid" },
                "asset": asset,
                "genesis": genesis,
                "transfer_count": chain.transfer_count(),
                "current_owner": chain.current_owner(),
                "valid": chain.is_valid(),
            })
        );
    } else {
        println!("{}", "Ownership chain verified".green().bold());
        println!("  {} {}", "Asset:".bold(), asset);
        println!("  {} {}", "Genesis:".bold(), genesis);
        println!("  {} {}", "Transfers:".bold(), chain.transfer_count());
        if let Some(owner) = chain.current_owner() {
            println!("  {} {}", "Current owner:".bold(), owner);
        } else {
            println!("  {}", "Current owner: (genesis only)".bold());
        }
        if chain.is_valid() {
            println!("  {}", "Chain status: VALID".green().bold());
        } else {
            println!("  {}", "Chain status: INVALID".red().bold());
        }
    }
    Ok(())
}

fn ownership_revoke_command(
    transfer_id: &str,
    key_path: &PathBuf,
    reason: &str,
    output: &PathBuf,
    format: OutputFormat,
) -> Result<()> {
    let mut keypair = load_keypair(key_path)?;
    keypair.key_id = public_key_to_key_id(&keypair.public_key);
    let revocation = morse_kirby_core::RevocationEntry::new(
        transfer_id.to_string(),
        reason.to_string(),
        &keypair,
    )
    .with_context(|| "Failed to create revocation entry")?;

    let json = serde_json::to_string_pretty(&revocation)
        .with_context(|| "Failed to serialize revocation entry")?;
    std::fs::write(output, json)
        .with_context(|| format!("Failed to write revocation: {}", output.display()))?;

    if format == OutputFormat::Json {
        println!(
            "{}",
            serde_json::json!({
                "status": "revoked",
                "transfer_id": transfer_id,
                "revoked_by": keypair.key_id,
                "reason": reason,
                "output": output,
            })
        );
    } else {
        println!("{}", "Revocation entry created".green().bold());
        println!("  {} {}", "Transfer ID:".bold(), transfer_id);
        println!("  {} {}", "Revoked by:".bold(), keypair.key_id);
        println!("  {} {}", "Reason:".bold(), reason);
        println!("  {} {}", "Output:".bold(), output.display());
    }
    Ok(())
}

/// Derive a deterministic key ID from a base64-encoded public key.
fn public_key_to_key_id(pubkey: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pubkey.trim().as_bytes());
    hex::encode(&hasher.finalize()[..8])
}

/// Load a map of key_id -> public_key from a comma-separated list of
/// file paths, or from all `.pub` / `.key` files in a directory.
fn load_public_keys(spec: &str) -> Result<std::collections::HashMap<String, String>> {
    let mut map = std::collections::HashMap::new();
    let path = std::path::Path::new(spec);

    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let p = entry.path();
            let ext = p.extension().and_then(|s| s.to_str());
            if ext == Some("pub") || ext == Some("key") {
                let content = std::fs::read_to_string(&p)?;
                let pk = content.trim().to_string();
                let key_id = public_key_to_key_id(&pk);
                map.insert(key_id, pk);
            }
        }
    } else {
        // Treat as comma-separated file paths
        for piece in spec.split(',') {
            let piece = piece.trim();
            if piece.is_empty() {
                continue;
            }
            let content = std::fs::read_to_string(piece)?;
            let pk = content.trim().to_string();
            let key_id = public_key_to_key_id(&pk);
            map.insert(key_id, pk);
        }
    }

    Ok(map)
}
