use clap::{arg, command, Parser, Subcommand};
use puffin_build::{library, vendor_dir};
use regex::Regex;

#[derive(Debug, Parser)]
#[command(about = "helper script to build vendor libraries for tlspuffin", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// `mk_vendor make [--force] [--name=<name>] <config>`
    #[command(arg_required_else_help = true)]
    Make {
        /// The configuration to build (e.g. 'openssl:openssl312')
        #[arg(value_name = "CONFIG")]
        #[arg(value_parser = parse_config_arg)]
        config: (String, String),

        /// Override the preset's name
        #[arg(short, long)]
        name: Option<String>,

        /// Force configuration rebuild if it already exists
        #[arg(short, long)]
        #[arg(default_value_t = false)]
        force: bool,
    },
}

pub fn main() -> std::process::ExitCode {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .parse_env(
            env_logger::Env::default()
                .filter("MK_VENDOR_LOG")
                .write_style("MK_VENDOR_LOG_STYLE"),
        )
        .init();

    let Cli { command } = Cli::parse();

    match command {
        Commands::Make {
            config: (vendor, preset),
            name,
            force,
        } => {
            let Some(config) = library::Config::preset(&vendor, &preset) else {
                log::error!("configuration preset '{preset}' not found");
                return std::process::ExitCode::FAILURE;
            };

            let name = name.unwrap_or(preset);

            if let Err(e) = vendor_dir::VendorDir::default()
                .library_dir(&name)
                .and_then(|library_dir| {
                    if force {
                        library_dir.remove()?
                    }

                    library_dir.make(config, true)
                })
            {
                log::error!("Error while building vendor library '{name}': {e}");
                return std::process::ExitCode::FAILURE;
            }

            std::process::ExitCode::SUCCESS
        }
    }
}

fn parse_config_arg(s: &str) -> Result<(String, String), String> {
    let s = s.trim();

    let Some(captures) = Regex::new(r"^(?<vendor>[^:]+):(?<name>[^:]+)$")
        .unwrap()
        .captures(s)
    else {
        return Err("invalid config format (expected '<vendor>:<name>')".to_string());
    };

    Ok((captures["vendor"].to_string(), captures["name"].to_string()))
}
