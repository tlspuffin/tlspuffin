#[macro_use]
extern crate log;

use std::{env, io::Write, path::PathBuf};

use env_logger::{fmt, Builder, Env};
use log::Level;

use crate::fuzzer::fuzz;

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
    //pretty_env_logger::formatted_builder().target(Target::Stdout).filter_level(LevelFilter::Trace).init();

    info!("{}", openssl_binding::openssl_version());

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );
    fuzz(
        &[PathBuf::from("./corpus")],
        PathBuf::from("./crashes"),
        1337,
    )
    .expect("An error occurred while fuzzing");

    /*
    use libafl_targets::{EDGES_MAP, MAX_EDGES_NUM};
    unsafe {
        println!("{:?}", EDGES_MAP);
        println!("{}", MAX_EDGES_NUM);
    }*/
}
