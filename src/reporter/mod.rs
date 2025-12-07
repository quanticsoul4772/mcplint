//! Reporter - Output formatting and reporting

pub mod sarif;

use serde::Serialize;

/// Format results for output
#[allow(dead_code)]
pub trait Reportable {
    fn to_text(&self) -> String;
    fn to_json(&self) -> anyhow::Result<String>;
    fn to_sarif(&self) -> anyhow::Result<String>;
}

/// Generic report wrapper
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct Report<T: Serialize> {
    pub tool: String,
    pub version: String,
    pub timestamp: String,
    pub data: T,
}

#[allow(dead_code)]
impl<T: Serialize> Report<T> {
    pub fn new(data: T) -> Self {
        Self {
            tool: "mcplint".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            data,
        }
    }
}
