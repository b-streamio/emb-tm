// SPDX-License-Identifier: GPL-2.0-only
//! The component library and the block types a project defines itself.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A block type defined in the project (left rail, "New custom block").
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CustomType {
    #[serde(rename = "type")]
    pub kind: String,
    pub name: String,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub hint: String,
    #[serde(default)]
    pub base: Vec<String>,
    #[serde(default)]
    pub threats: Vec<CustomThreat>,
    /// Questionnaire, as in the library.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub questions: Vec<Question>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub external: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CustomThreat {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub desc: String,
    #[serde(default)]
    pub cms: Vec<CustomCm>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CustomCm {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub desc: String,
}

/// `library/components.json`: the component palette and its questionnaires.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
pub struct Library {
    /// Rail order; a library file to import may leave it out.
    #[serde(default)]
    pub groups: Vec<String>,
    pub components: Vec<TypeDef>,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
pub struct TypeDef {
    #[serde(rename = "type")]
    pub kind: String,
    pub name: String,
    pub group: String,
    pub tag: String,
    #[serde(default)]
    pub hint: String,
    #[serde(default)]
    pub base: Vec<String>,
    #[serde(default)]
    pub questions: Vec<Question>,
    #[serde(default)]
    pub external: bool,
    /// Holds a page (the device box).
    #[serde(default)]
    pub container: bool,
    /// Set for project custom types.
    #[serde(skip)]
    pub custom: bool,
    #[serde(skip)]
    pub threats: Vec<CustomThreat>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Question {
    pub id: String,
    pub text: String,
    /// `bool` or `choice`.
    pub kind: String,
    pub default: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<Choice>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Choice {
    pub value: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pids: Vec<String>,
}
