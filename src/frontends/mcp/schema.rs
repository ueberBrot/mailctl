//! Compact standalone output contracts while retaining constraints and guidance.
use crate::domain::Envelope;
use rmcp::model::JsonObject;
use schemars::{
    JsonSchema, Schema,
    transform::{RecursiveTransform, Transform},
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

pub(super) fn output<T: JsonSchema + 'static>() -> Arc<JsonObject> {
    let raw = rmcp::handler::server::tool::schema_for_output::<Envelope<T>>();
    let mut schema = Schema::from(raw.as_ref().clone());
    inline_single_use(&mut schema);
    // The negotiated 2025-11-25 protocol requires an explicit object root.
    schema.insert("type".into(), json!("object"));
    let Value::Object(schema) = schema.into() else {
        unreachable!("envelope output schemas remain objects")
    };
    Arc::new(schema)
}

fn inline_single_use(schema: &mut Schema) {
    loop {
        let mut references = BTreeMap::new();
        let has_scoped_references = count_references(schema.as_value(), &mut references);
        if has_scoped_references {
            return;
        }
        let Some(definitions) = schema.get("$defs").and_then(Value::as_object) else {
            return;
        };
        let definitions: BTreeMap<_, _> = definitions
            .iter()
            .filter_map(|(name, definition)| {
                let reference = format!("#/$defs/{}", name.replace('~', "~0").replace('/', "~1"));
                (references.get(&reference) == Some(&1))
                    .then(|| {
                        definition
                            .as_object()
                            .map(|value| (reference, (name.clone(), value.clone())))
                    })
                    .flatten()
            })
            .collect();
        let mut inlined = BTreeSet::new();
        RecursiveTransform(|child: &mut Schema| {
            let Some(object) = child.as_object_mut() else {
                return;
            };
            let Some((name, definition)) = object
                .get("$ref")
                .and_then(Value::as_str)
                .and_then(|reference| definitions.get(reference))
            else {
                return;
            };
            // Validation siblings may depend on a separate evaluation of $ref.
            if object.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "$ref"
                        | "$schema"
                        | "$defs"
                        | "$comment"
                        | "title"
                        | "description"
                        | "default"
                        | "examples"
                        | "deprecated"
                        | "readOnly"
                        | "writeOnly"
                )
            }) {
                return;
            }
            // Conflicting annotations also retain their original locations.
            if definition.iter().any(|(key, value)| {
                key != "$ref" && object.get(key).is_some_and(|existing| existing != value)
            }) {
                return;
            }
            object.remove("$ref");
            object.extend(definition.clone());
            inlined.insert(name.clone());
        })
        .transform(schema);
        if inlined.is_empty() {
            return;
        }
        if let Some(definitions) = schema.get_mut("$defs").and_then(Value::as_object_mut) {
            for name in inlined {
                definitions.remove(&name);
            }
            if definitions.is_empty() {
                schema.remove("$defs");
            }
        }
    }
}

/// Count literal references too, so annotations can only prevent an optimization.
/// Scope-changing schemas keep their original definitions and reference locations.
fn count_references(value: &Value, references: &mut BTreeMap<String, usize>) -> bool {
    match value {
        Value::Object(object) => {
            if object.keys().any(|key| {
                matches!(
                    key.as_str(),
                    "$id"
                        | "$anchor"
                        | "$dynamicAnchor"
                        | "$dynamicRef"
                        | "$recursiveAnchor"
                        | "$recursiveRef"
                )
            }) {
                return true;
            }
            if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                *references.entry(reference.into()).or_default() += 1;
            }
            object
                .values()
                .any(|value| count_references(value, references))
        }
        Value::Array(values) => values
            .iter()
            .any(|value| count_references(value, references)),
        _ => false,
    }
}
