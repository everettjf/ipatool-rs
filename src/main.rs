use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use ipatool_rs::fairplay::{doctor_fairplay, write_doctor_report};
use ipatool_rs::{App, CatalogClient, Platform, SearchOutput};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "ipatool",
    version,
    about = "Rust port of ipatool-fairplay (in progress)"
)]
struct Cli {
    #[arg(long, global = true, value_enum, default_value_t = Format::Text)]
    format: Format,
    #[arg(long, global = true)]
    verbose: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Search the public App Store catalog.
    Search {
        term: String,
        #[arg(short, long, default_value_t = 5)]
        limit: i64,
        #[arg(long)]
        platform: Option<String>,
        #[arg(long, default_value = "US")]
        country: String,
    },
    /// Look up an app by numeric ID or bundle identifier.
    Lookup {
        #[arg(long, conflicts_with = "bundle_identifier")]
        app_id: Option<i64>,
        #[arg(long, conflicts_with = "app_id")]
        bundle_identifier: Option<String>,
        #[arg(long)]
        platform: Option<String>,
        #[arg(long, default_value = "US")]
        country: String,
    },
    /// Resolve the latest external version ID from the public platform catalog.
    LatestVersionId {
        #[arg(long)]
        app_id: i64,
        #[arg(long)]
        bundle_identifier: Option<String>,
        #[arg(long, default_value = "iphone")]
        platform: String,
        #[arg(long, default_value = "US")]
        country: String,
    },
    /// Diagnose IPA SINF and enrollment model compatibility.
    FairplayDoctor {
        #[arg(long)]
        capture: Option<PathBuf>,
        #[arg(long)]
        ipa: Option<PathBuf>,
        #[arg(long)]
        model: Option<PathBuf>,
        #[arg(long)]
        report: Option<PathBuf>,
    },
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let client = CatalogClient::new()?;
    match cli.command {
        Command::Search {
            term,
            limit,
            platform,
            country,
        } => {
            let platform = parse_platform(platform.as_deref())?;
            let output = client.search(&term, &country, limit, platform)?;
            print_search(&output, cli.format)?;
        }
        Command::Lookup {
            app_id,
            bundle_identifier,
            platform,
            country,
        } => {
            if app_id.is_none() && bundle_identifier.is_none() {
                bail!("an app ID or bundle identifier is required");
            }
            let platform = parse_platform(platform.as_deref())?;
            let app = client.lookup(app_id, bundle_identifier.as_deref(), &country, platform)?;
            print_app(&app, cli.format)?;
        }
        Command::LatestVersionId {
            app_id,
            bundle_identifier,
            platform,
            country,
        } => {
            let platform = Platform::parse(&platform)?.context("platform is required")?;
            let app = App {
                id: app_id,
                bundle_id: bundle_identifier.unwrap_or_default(),
                ..App::default()
            };
            let id = client.latest_external_version_id(&app, &country, platform)?;
            match cli.format {
                Format::Text => println!("{id}"),
                Format::Json => println!("{}", serde_json::json!({ "externalVersionID": id })),
            }
        }
        Command::FairplayDoctor {
            capture,
            ipa,
            model,
            report,
        } => {
            let output = doctor_fairplay(capture.as_deref(), ipa.as_deref(), model.as_deref());
            if let Some(path) = report.as_deref() {
                write_doctor_report(path, &output)?;
            }
            println!("{}", serde_json::to_string_pretty(&output)?);
            if !output.ready {
                bail!("FairPlay diagnostics are not ready; see errors and next_actions");
            }
        }
    }
    if cli.verbose {
        // Accepted for CLI compatibility. HTTP diagnostics will be added with the transport port.
    }
    Ok(())
}

fn parse_platform(value: Option<&str>) -> Result<Option<Platform>> {
    Platform::parse(value.unwrap_or_default())
}

fn print_search(output: &SearchOutput, format: Format) -> Result<()> {
    match format {
        Format::Json => println!(
            "{}",
            serde_json::to_string(output).context("failed to encode output")?
        ),
        Format::Text => {
            println!("{} result(s)", output.count);
            for app in &output.apps {
                print_app(app, Format::Text)?;
            }
        }
    }
    Ok(())
}

fn print_app(app: &App, format: Format) -> Result<()> {
    match format {
        Format::Json => println!(
            "{}",
            serde_json::to_string(app).context("failed to encode app")?
        ),
        Format::Text => println!(
            "{}\t{}\t{}\t{}",
            app.id, app.name, app.bundle_id, app.version
        ),
    }
    Ok(())
}
