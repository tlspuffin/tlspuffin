#[macro_use]
extern crate log;

use std::{env, io::Write, path::PathBuf};

use env_logger::{fmt, Builder, Env};
use log::Level;
use clap::{Arg, App, value_t, crate_version, crate_authors, crate_name};

use crate::fuzzer::start;

mod agent;
mod debug;
mod fuzzer;
mod io;
mod openssl_binding;
mod term;
mod tests;
mod trace;
mod variable_data;

fn main() {
    fn init_logger() {
        let env = Env::default().filter("RUST_LOG");

        Builder::from_env(env)
            .format(|buf, record| {
                let mut style = buf.style();
                match record.level() {
                    Level::Error => {
                        style.set_color(fmt::Color::Red).set_bold(true);
                    }
                    Level::Warn => {
                        style.set_color(fmt::Color::Yellow).set_bold(true);
                    }
                    Level::Info => {
                        style.set_color(fmt::Color::Blue).set_bold(true);
                    }
                    Level::Debug => {}
                    Level::Trace => {}
                };

                let timestamp = buf.timestamp();

                writeln!(buf, "{} {}", timestamp, style.value(record.args()))
            })
            .init();
    }

    init_logger();

    let matches = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about("Fuzzes OpenSSL on a symbolic level")
        .args_from_usage(
            "-n, --num-cores=[n] 'Sets the amount of cores to use to fuzz'",
        )
        .get_matches();

    let num_cores = value_t!(matches, "n", usize).unwrap_or(1);

    info!("{}", openssl_binding::openssl_version());

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );
    start(
        num_cores,
        &[PathBuf::from("./corpus")],
        PathBuf::from("./crashes"),
        1337,
    );
}
