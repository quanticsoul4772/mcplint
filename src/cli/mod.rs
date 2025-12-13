//! CLI module - Command implementations

pub mod commands;
pub mod completions;
pub mod config;
pub mod help;
pub mod interactive;
pub mod server;

/// Output format for CLI commands
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    Sarif,
    Junit,
    Gitlab,
}

/// Scan profile for CLI commands (wrapper around scanner::ScanProfile)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum ScanProfile {
    Quick,
    #[default]
    Standard,
    Full,
    Enterprise,
}

impl ScanProfile {
    /// Get the string representation of the profile
    pub fn as_str(&self) -> &'static str {
        match self {
            ScanProfile::Quick => "quick",
            ScanProfile::Standard => "standard",
            ScanProfile::Full => "full",
            ScanProfile::Enterprise => "enterprise",
        }
    }
}

impl From<ScanProfile> for crate::scanner::ScanProfile {
    fn from(profile: ScanProfile) -> Self {
        match profile {
            ScanProfile::Quick => crate::scanner::ScanProfile::Quick,
            ScanProfile::Standard => crate::scanner::ScanProfile::Standard,
            ScanProfile::Full => crate::scanner::ScanProfile::Full,
            ScanProfile::Enterprise => crate::scanner::ScanProfile::Enterprise,
        }
    }
}
