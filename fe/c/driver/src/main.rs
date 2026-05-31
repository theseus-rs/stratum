#![doc = include_str!("../README.md")]

//! Command-line entry point for the Stratum C frontend driver.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match stratum_c_driver::parse_args(&args) {
        Ok(options) => {
            let code = stratum_c_driver::run(&options);
            ExitCode::from(u8::try_from(code).unwrap_or(1))
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}
