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
        return Err("The workspace MSRV must match the pinned toolchain".into());
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

    check_dependencies(root, CargoOpt::AllFeatures, false)?;
    check_dependencies(root, CargoOpt::SomeFeatures(vec!["cli".into()]), true)?;
    println!("Toolchain, fixture checksums and production dependency features passed.");
    Ok(())
}

fn check_dependencies(
    root: &Path,
    features: CargoOpt,
    cli_only: bool,
) -> Result<(), Box<dyn Error>> {
    let metadata = MetadataCommand::new()
        .current_dir(root)
        .features(CargoOpt::NoDefaultFeatures)
        .features(features)
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
        if cli_only && name == "rmcp" {
            return Err("CLI-only production graph contains MCP dependencies".into());
        }
        let dependencies: Vec<_> = package
            .dependencies
            .iter()
            .filter(|dep| dep.kind != DependencyKind::Development)
            .collect();
        for dependency in &dependencies {
            if ["io-imap", "tokio-rustls"].contains(&dependency.name.as_str())
                && dependency.uses_default_features
            {
                return Err(format!(
                    "Disable defaults for {name}'s {} dependency",
                    dependency.name
                )
                .into());
            }
        }
        if name == "io-imap"
            && (!node.features.is_empty() || package.version.to_string() != "0.6.0")
        {
            return Err(
                "Use pinned io-imap 0.6.0 coroutines without client, TLS, or SASL extensions"
                    .into(),
            );
        }
        if name == "tokio-rustls"
            && (package.version.to_string() != "0.26.5"
                || node
                    .features
                    .iter()
                    .any(|feature| !["ring", "tls12"].contains(&feature.as_str())))
        {
            return Err("Use pinned tokio-rustls 0.26.5 with only ring and tls12".into());
        }
        if name == "mailctl" {
            for (dependency_name, version) in [
                ("io-imap", "=0.6.0"),
                ("tokio", "=1.53.1"),
                ("tokio-rustls", "=0.26.5"),
            ] {
                if !dependencies.iter().any(|dependency| {
                    dependency.name == dependency_name && dependency.req.to_string() == version
                }) {
                    return Err(format!(
                        "Pin the direct {dependency_name} dependency to {version}"
                    )
                    .into());
                }
            }
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
    Ok(())
}
