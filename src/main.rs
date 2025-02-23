use std::io::Write;
use clap::{
    Arg, Command,
    ColorChoice,
};
use colored::Colorize;
use tokio::runtime::*;
use dotenv::dotenv;

use env_logger::{Builder, WriteStyle};
use env_logger::fmt::Formatter;
use log::{error, Level, LevelFilter, Record};

mod cli;
pub mod auth;

fn main() {
    dotenv().ok();
    Builder::new()
        .format(|buf: &mut Formatter, record: &Record| {
            let module = record.module_path().unwrap_or("unknown");
            let level_str = match record.level() {
                Level::Info => "INFO".bright_cyan(),
                Level::Warn => "WARN".bright_yellow(),
                Level::Error => "ERROR".bright_red(),
                Level::Debug => "DEBUG".magenta(),
                Level::Trace => "TRACE".blue(),
            };
            writeln!(buf, "[{} {}] {}", level_str, module, record.args())
        })
        .filter(None, LevelFilter::Info)
        .filter_module("reqwest", LevelFilter::Warn)
        .write_style(WriteStyle::Always)
        .init();

    let matches = Command::new("rush")
        .version("1.0").author("no-time!")
        .about("Package Manager inspired by Wally")
        .color(ColorChoice::Always)
        .arg_required_else_help(true)

        .subcommand(
            Command::new("init")
                .about("Initializes a new manager")
                .arg(Arg::new("project")
                .help("The name of the project")
                .required(false)),
        )
        .subcommand(
            Command::new("install")
                .about("Installs a package from a private repository")
                .arg(Arg::new("package").required(true).help("The package to install")),
        )
        .get_matches();

    let rt = Runtime::new().expect("Failed to create runtime");
    match matches.subcommand() {
        Some(("init", sub_m)) => {
            let project_name = sub_m.get_one::<String>("project").cloned();
            if let Err(e) = cli::init::init(project_name) {
                error!("{}", e);
            }
        }
        Some(("install", sub_m)) => {
            if let Some(package) = sub_m.get_one::<String>("package") {
                let package = package.clone();
                rt.block_on(async {
                    if let Err(e) = cli::install::install(&package).await {
                        error!("{}", e);
                    }
                });
            }
        }
        _ => unreachable!()
    }
}
