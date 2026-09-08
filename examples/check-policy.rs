//! Repository invariants not covered by cargo-deny. Run with `cargo run --example check-policy`.
use cargo_metadata::{CargoOpt, DependencyKind, MetadataCommand};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    error::Error,
    fs,
    path::Path,
};

fn main() -> Result<(), Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest: toml::Value = toml::from_str(&fs::read_to_string(root.join("Cargo.toml"))?)?;
    let toolchain: toml::Value =
        toml::from_str(&fs::read_to_string(root.join("rust-toolchain.toml"))?)?;
    let version = toolchain["toolchain"]["channel"]
        .as_str()
        .ok_or("missing toolchain pin")?;
    if manifest["workspace"]["package"]["rust-version"].as_str() != Some(version) {
        return Err("The scaffold MSRV must match the pinned toolchain".into());
    }

    let specs = root.join("tests/specs");
    let checksums: BTreeMap<String, String> =
        serde_json::from_slice(&fs::read(specs.join("checksums.json"))?)?;
    for (name, checksum) in checksums {
        let actual: String = Sha256::digest(fs::read(specs.join(&name))?)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        if actual != checksum {
            return Err(format!("Vendored GreenMail input checksum mismatch: {name}").into());
        }
    }

    let metadata = MetadataCommand::new()
        .current_dir(root)
        .features(CargoOpt::AllFeatures)
        .other_options(vec!["--locked".into()])
        .exec()?;
    let nodes: HashMap<_, _> = metadata
        .resolve
        .as_ref()
        .ok_or("missing dependency graph")?
        .nodes
        .iter()
        .map(|node| (&node.id, node))
        .collect();
    let mut pending: Vec<_> = metadata
        .workspace_members
        .iter()
        .filter(|id| metadata[id].name != "greenmail-support")
        .collect();
    let mut visited = HashSet::new();
    while let Some(id) = pending.pop() {
        if !visited.insert(id) {
            continue;
        }
        let package = &metadata[id];
        let node = nodes[id];
        let name = package.name.as_str();
        if [
            "greenmail-support",
            "testcontainers",
            "lettre",
            "smtp",
            "io-smtp",
            "io-pop3",
            "io-jmap",
        ]
        .contains(&name)
        {
            return Err(format!("Forbidden production dependency: {name}").into());
        }
        for feature in &node.features {
            if ["smtp", "sendmail", "pop3", "jmap", "gmail", "outlook"]
                .iter()
                .any(|forbidden| feature.to_lowercase().contains(forbidden))
            {
                return Err(format!("Forbidden production feature: {name}/{feature}").into());
            }
        }
        let dependencies: Vec<_> = package
            .dependencies
            .iter()
            .filter(|dep| dep.kind != DependencyKind::Development)
            .collect();
        for dependency in &dependencies {
            if ["io-email", "io-imap"].contains(&dependency.name.as_str())
                && dependency.uses_default_features
            {
                return Err(format!(
                    "Disable defaults for {name}'s {} dependency",
                    dependency.name
                )
                .into());
            }
        }
        if dependencies.iter().any(|dep| dep.name == "io-email")
            && !dependencies.iter().any(|dep| dep.name == "io-imap")
        {
            return Err(format!("{name} must declare its direct io-imap dependency").into());
        }
        pending.extend(
            node.deps
                .iter()
                .filter(|dep| {
                    dep.dep_kinds
                        .iter()
                        .any(|kind| kind.kind != DependencyKind::Development)
                })
                .map(|dep| &dep.pkg),
        );
    }
    println!("Toolchain, fixture checksums and production dependency features passed.");
    Ok(())
}
