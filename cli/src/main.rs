//! MKPE Command-Line Interface
//!
//! The canonical CLI tool for the Morse-Kirby Provenance Engine

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use morse_kirby_core::{MkpeError, *};
use std::path::PathBuf;

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
            let trusted_public_key = match public_key
                .as_ref()
                .map(std::fs::read_to_string)
                .transpose()
            {
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
                    trusted_public_key: trusted_public_key,
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
