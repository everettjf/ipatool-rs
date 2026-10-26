use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
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
