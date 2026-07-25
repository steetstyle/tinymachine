//! TinyMachine CLI — minimal code execution sandbox.
//!
//! # Usage
//!
//! ```text
//! tinymachine exec --lang python 'print(1)'
//! tinymachine exec --lang wasm '(module (func (export "_start")))'
//! tinymachine template build python --variant minimal
//! tinymachine template list
//! tinymachine version
//! ```

use std::path::PathBuf;
use clap::{Parser, Subcommand, Args};

// ─── CLI Entrypoint ─────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "tinymachine", version, about = "Ultra-fast KVM sandbox for code execution")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Execute code in a sandbox
    Exec(ExecArgs),
    /// Manage templates (snapshots)
    Template(TemplateArgs),
    /// List layers
    Layer(LayerArgs),
    /// Show version information
    Version,
}

// ─── Exec ───────────────────────────────────────────────────────────────

#[derive(Args)]
struct ExecArgs {
    /// Language (python, wasm, node, etc.)
    #[arg(long, default_value = "python")]
    lang: String,

    /// Code to execute
    code: String,

    /// Variant override (minimal, numpy, pytorch, etc.)
    #[arg(long)]
    variant: Option<String>,

    /// Dependency specification (e.g. numpy@1.26.4)
    #[arg(long = "dep", short = 'd')]
    deps: Vec<String>,
}

fn home_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home)
}

fn tinymachine_dir() -> PathBuf {
    home_dir().join(".tinymachine")
}

fn cmd_exec(args: ExecArgs) -> Result<(), Box<dyn std::error::Error>> {
    let lang = args.lang.trim().to_lowercase();

    match lang.as_str() {
        "wasm" => {
            #[cfg(feature = "wasm")]
            {
                let result = tinymachine_fork::wasm::eval_wat(&args.code)?;
                println!("{result}");
                return Ok(());
            }
            #[cfg(not(feature = "wasm"))]
            {
                eprintln!("Wasm support not enabled. Rebuild with --features wasm");
                std::process::exit(1);
            }
        }
        _ => {
            // Python / Node / Shell
            tinymachine_fork::register_all_backends();

            let api_variant = match &args.variant {
                Some(v) => tinymachine_api::Variant::new(&lang, v, "base"),
                None => {
                    tinymachine_api::Variant::detect(&lang, &args.code)
                        .unwrap_or_else(|| tinymachine_api::Variant::new(&lang, "minimal", "base"))
                }
            };

            let fork_variant = tinymachine_fork::variant::Variant::from_api(&api_variant)
                .ok_or_else(|| format!("Unknown variant: {}", api_variant))?;

            // Try ForkEngine via template snapshot
            let templates_dir = tinymachine_dir().join("templates");
            let registry = tinymachine_fork::template_registry::TemplateRegistry::open(Some(templates_dir))?;

            if !registry.has_snapshot(&fork_variant) {
                eprintln!(
                    "No template found for {}. Run: tinymachine template build {} --variant {}",
                    fork_variant.id(), lang, fork_variant.name
                );
                std::process::exit(1);
            }

            let snapshot = registry.load_snapshot(&fork_variant)?;
            let kvm = tinymachine_fork::kvm::Kvm::new()?;
            let vcpu_mmap_size = kvm.vcpu_mmap_size()?;
            let engine = tinymachine_fork::fork::ForkEngine::new(kvm, snapshot, vcpu_mmap_size);
            let mut forked = engine.fork()?;
            let result = unsafe { forked.run_code(&args.code) }
                .map_err(|e| format!("Execution failed: {e}"))?;
            println!("{result}");
            Ok(())
        }
    }
}

// ─── Template ───────────────────────────────────────────────────────────

#[derive(Args)]
struct TemplateArgs {
    #[command(subcommand)]
    command: TemplateCommand,
}

#[derive(Subcommand)]
enum TemplateCommand {
    /// Build a new template
    Build(TemplateBuildArgs),
    /// List available templates
    List,
    /// Remove a template
    Remove(TemplateRemoveArgs),
}

#[derive(Args)]
struct TemplateBuildArgs {
    /// Language (python, node, etc.)
    lang: String,
    /// Variant name (minimal, numpy, pytorch, etc.)
    #[arg(long)]
    variant: String,
    /// Kernel profile
    #[arg(long, default_value = "base")]
    kernel_profile: String,
    /// Guest memory in MB
    #[arg(long, default_value = "64")]
    memory_mb: u64,
}

#[derive(Args)]
struct TemplateRemoveArgs {
    /// Language
    lang: String,
    /// Variant name
    #[arg(long)]
    variant: String,
}

fn cmd_template(args: TemplateArgs) -> Result<(), Box<dyn std::error::Error>> {
    match args.command {
        TemplateCommand::Build(b) => cmd_template_build(b),
        TemplateCommand::List => cmd_template_list(),
        TemplateCommand::Remove(r) => cmd_template_remove(r),
    }
}

fn cmd_template_build(args: TemplateBuildArgs) -> Result<(), Box<dyn std::error::Error>> {
    use tinymachine_fork::boot::{self, BootConfig};
    use tinymachine_fork::kvm::Kvm;
    use tinymachine_fork::variant::KernelProfile;

    let tdir = tinymachine_dir();
    let templates_dir = tdir.join("templates");

    let api_variant = tinymachine_api::Variant::new(&args.lang, &args.variant, &args.kernel_profile);
    let variant = tinymachine_fork::variant::Variant::from_api(&api_variant)
        .ok_or_else(|| format!("Invalid variant: {}", api_variant))?;

    // Find kernel
    let registry = tinymachine_fork::template_registry::TemplateRegistry::open(Some(templates_dir.clone()))?;
    let kernel_path = registry.kernel_path(&variant.kernel_profile);
    if !kernel_path.exists() {
        eprintln!("Kernel not found at: {}", kernel_path.display());
        std::process::exit(1);
    }

    // Find initrd
    let initrd_path = find_initrd(&tdir, &args.lang, &args.variant);
    if initrd_path.is_none() {
        eprintln!(
            "No initrd found. Place at: {}/templates/{}/v1/{}/initrd.gz",
            tdir.display(), args.lang, args.variant
        );
        std::process::exit(1);
    }

    let requires_gpu = matches!(variant.kernel_profile,
        KernelProfile::GpuNvidia | KernelProfile::GpuVfio | KernelProfile::GpuVk);
    let loglevel = if requires_gpu { 4 } else { 3 };
    let profile_suffix = if requires_gpu { "pci=realloc" } else { "" };
    let cmdline = boot::build_kernel_cmdline(loglevel, profile_suffix);

    let config = BootConfig {
        kernel_path,
        initrd_path,
        memory_size: args.memory_mb * 1024 * 1024,
        load_addr: tinymachine_fork::arch::DEFAULT_LOAD_ADDR,
        pvh_boot: false,
        irqchip: true,
        cmdline: Some(cmdline),
        reserved_regions: Vec::new(),
        kernel_version: String::new(),
        kernel_hash: String::new(),
        vbios_data: None,
    };

    let kvm = Kvm::new()?;
    tracing::info!("Booting kernel to build template for {}...", variant.id());
    let booted = unsafe { boot::boot_linux(&kvm, &config) }?;
    booted.create_irqchip()?;
    unsafe { booted.run_until_ready() }?;
    tracing::info!("Guest READY — capturing snapshot...");

    // Use the built-in capture_snapshot() method
    let snapshot = booted.capture_snapshot()?;
    let mem_mb = snapshot.memory_size / (1024 * 1024);

    let mut registry = tinymachine_fork::template_registry::TemplateRegistry::open(Some(templates_dir.clone()))?;
    registry.store_snapshot(&variant, &snapshot)?;
    tracing::info!("Template built: {} ({} MB)", variant.id(), mem_mb);
    Ok(())
}

fn cmd_template_list() -> Result<(), Box<dyn std::error::Error>> {
    let registry = tinymachine_fork::template_registry::TemplateRegistry::open(
        Some(tinymachine_dir().join("templates")),
    )?;
    let templates = registry.list_templates();

    if templates.is_empty() {
        println!("No templates found.");
        return Ok(());
    }

    println!("Available templates:");
    for t in &templates {
        println!(
            "  {}:{} v{} ({} MB, kernel: {})",
            t.lang,
            t.variant,
            t.version,
            t.memory_size / (1024 * 1024),
            t.kernel_profile
        );
    }
    Ok(())
}

fn cmd_template_remove(args: TemplateRemoveArgs) -> Result<(), Box<dyn std::error::Error>> {
    let tdir = tinymachine_dir();
    let templates_dir = tdir.join("templates");
    let registry = tinymachine_fork::template_registry::TemplateRegistry::open(Some(templates_dir.clone()))?;
    let api_variant = tinymachine_api::Variant::new(&args.lang, &args.variant, "base");
    let variant = tinymachine_fork::variant::Variant::from_api(&api_variant)
        .ok_or_else(|| format!("Invalid variant: {}", api_variant))?;

    if let Some(version) = registry.latest_version(&variant) {
        let variant_dir = templates_dir
            .join(&args.lang)
            .join(format!("v{}", version))
            .join(&args.variant);
        if variant_dir.exists() {
            std::fs::remove_dir_all(&variant_dir)?;
        }
        println!("Removed {}:{} v{}", args.lang, args.variant, version);
    } else {
        eprintln!("Template {}:{} not found", args.lang, args.variant);
    }
    Ok(())
}

// ─── Layer ──────────────────────────────────────────────────────────────

#[derive(Args)]
struct LayerArgs {
    #[command(subcommand)]
    command: LayerCommand,
}

#[derive(Subcommand)]
enum LayerCommand {
    /// List available layers
    List,
}

fn cmd_layer(args: LayerArgs) -> Result<(), Box<dyn std::error::Error>> {
    match args.command {
        LayerCommand::List => cmd_layer_list(),
    }
}

fn cmd_layer_list() -> Result<(), Box<dyn std::error::Error>> {
    let layers_dir = tinymachine_dir().join("layers");
    if !layers_dir.exists() {
        println!("No layers found.");
        return Ok(());
    }

    let registry = tinymachine_fork::layer_registry::LayerRegistry::load_from(&layers_dir)?;
    let layers = registry.list_layers(None);

    if layers.is_empty() {
        println!("No layers found.");
        return Ok(());
    }

    println!("Available layers:");
    for l in &layers {
        println!("  {}/{}@{}", l.layer_type.dirname(), l.name, l.version);
    }
    Ok(())
}

// ─── Helpers ────────────────────────────────────────────────────────────

fn find_initrd(tinymachine_dir: &PathBuf, lang: &str, variant: &str) -> Option<PathBuf> {
    let candidates = [
        tinymachine_dir
            .join("templates")
            .join(lang)
            .join("v1")
            .join(variant)
            .join("initrd.gz"),
        tinymachine_dir
            .join("templates")
            .join(lang)
            .join("v1")
            .join(variant)
            .join("initrd"),
        tinymachine_dir
            .join("templates")
            .join(lang)
            .join("v1")
            .join(variant)
            .join("initrd.cpio.zst"),
    ];
    candidates.iter().find(|c| c.exists()).cloned()
}

// ─── Main ───────────────────────────────────────────────────────────────

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    let result = match cli.command {
        Command::Exec(args) => cmd_exec(args),
        Command::Template(args) => cmd_template(args),
        Command::Layer(args) => cmd_layer(args),
        Command::Version => {
            println!("TinyMachine {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
