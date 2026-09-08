//! Development-only, exclusively owned GreenMail fixture.
//! No helper opens a provider account or uses the production email adapter.
#![cfg(feature = "docker")]

mod api;
mod container;
mod fixtures;

pub use container::Fixture;
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Run an integration suite with a finite deadline and actionable prerequisite errors.
pub fn run(suite: impl std::future::Future<Output = Result<()>>) {
    let runtime = tokio::runtime::Runtime::new().expect("create fixture runtime");
    runtime.block_on(async {
        match tokio::time::timeout(std::time::Duration::from_secs(240), suite).await {
            Ok(Ok(())) => (),
            Ok(Err(error)) => {
                panic!("GreenMail integration failed: {error}")
            }
            Err(_) => {
                panic!("GreenMail suite exceeded 240 seconds; check Docker and image availability")
            }
        }
    });
}
