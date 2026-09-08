//! Shared frontend request mapping and executable bootstrap.

/// Bootstrap only: no email operations are exposed until their slices land.
pub fn run(name: &'static str, description: &'static str) {
    clap::Command::new(name)
        .version(env!("CARGO_PKG_VERSION"))
        .about(description)
        .get_matches();
    eprintln!("{name}: email operations are not implemented yet; use --help");
    std::process::exit(2);
}
