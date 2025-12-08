//! Cache Command - Manage MCPLint cache storage
//!
//! Provides subcommands for cache management:
//! - stats: View cache statistics
//! - clear: Clear cache entries
//! - prune: Remove expired entries
//! - export: Export cache to file
//! - import: Import cache from file

use anyhow::{Context, Result};
use colored::Colorize;
use std::path::PathBuf;

use crate::cache::{CacheCategory, CacheConfig, CacheKey, CacheManager, CacheStats};

/// Run the cache stats subcommand
pub async fn run_stats(json_output: bool) -> Result<()> {
    let config = CacheConfig::default();
    let cache = CacheManager::new(config)
        .await
        .context("Failed to initialize cache")?;

    let stats = cache.stats().await.context("Failed to get cache stats")?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&stats)?);
    } else {
        print_stats(&stats);
    }

    Ok(())
}

/// Run the cache clear subcommand
pub async fn run_clear(category: Option<String>, force: bool) -> Result<()> {
    // Parse category if provided
    let cat = match &category {
        Some(s) => Some(
            CacheCategory::from_str(s)
                .ok_or_else(|| anyhow::anyhow!("Unknown category: {}", s))?,
        ),
        None => None,
    };

    if !force {
        let prompt = match &category {
            Some(c) => format!("Clear all '{}' cache entries?", c),
            None => "Clear ALL cache entries?".to_string(),
        };
        println!("{} {}", "⚠".yellow(), prompt);
        println!("Use --force to skip this prompt.");
        return Ok(());
    }

    let config = CacheConfig::default();
    let cache = CacheManager::new(config)
        .await
        .context("Failed to initialize cache")?;

    let cleared = cache
        .clear(cat)
        .await
        .context("Failed to clear cache")?;

    match &category {
        Some(c) => println!(
            "{} Cleared {} entries from '{}' category",
            "✓".green(),
            cleared,
            c
        ),
        None => println!("{} Cleared {} entries from all categories", "✓".green(), cleared),
    }

    Ok(())
}

/// Run the cache prune subcommand
pub async fn run_prune(json_output: bool) -> Result<()> {
    let config = CacheConfig::default();
    let cache = CacheManager::new(config)
        .await
        .context("Failed to initialize cache")?;

    let pruned = cache
        .prune_expired()
        .await
        .context("Failed to prune expired entries")?;

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "pruned": pruned,
                "status": "success"
            })
        );
    } else {
        println!("{} Pruned {} expired entries", "✓".green(), pruned);
    }

    Ok(())
}

/// Run the cache export subcommand
pub async fn run_export(output: PathBuf, category: Option<String>) -> Result<()> {
    // Parse category if provided
    let cat = match &category {
        Some(s) => Some(
            CacheCategory::from_str(s)
                .ok_or_else(|| anyhow::anyhow!("Unknown category: {}", s))?,
        ),
        None => None,
    };

    let config = CacheConfig::default();
    let cache = CacheManager::new(config)
        .await
        .context("Failed to initialize cache")?;

    // Get all keys for the category
    let keys = cache.keys(cat).await.context("Failed to list cache keys")?;

    // Export structure
    #[derive(serde::Serialize)]
    struct ExportEntry {
        key: CacheKey,
        data: serde_json::Value,
    }

    let mut entries = Vec::new();

    for key in &keys {
        if let Ok(Some(value)) = cache.get::<serde_json::Value>(key).await {
            entries.push(ExportEntry {
                key: key.clone(),
                data: value,
            });
        }
    }

    let export_data = serde_json::json!({
        "version": 1,
        "exported_at": chrono::Utc::now().to_rfc3339(),
        "entries_count": entries.len(),
        "entries": entries
    });

    std::fs::write(&output, serde_json::to_string_pretty(&export_data)?)
        .context("Failed to write export file")?;

    println!(
        "{} Exported {} entries to {}",
        "✓".green(),
        entries.len(),
        output.display()
    );

    Ok(())
}

/// Run the cache import subcommand
pub async fn run_import(input: PathBuf, merge: bool) -> Result<()> {
    let config = CacheConfig::default();
    let cache = CacheManager::new(config)
        .await
        .context("Failed to initialize cache")?;

    // Read and parse import file
    let content = std::fs::read_to_string(&input).context("Failed to read import file")?;

    let import_data: serde_json::Value =
        serde_json::from_str(&content).context("Failed to parse import file")?;

    // Validate version
    let version = import_data
        .get("version")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    if version != 1 {
        anyhow::bail!("Unsupported cache export version: {}", version);
    }

    // Clear existing if not merging
    if !merge {
        let cleared = cache.clear(None).await?;
        println!("{} Cleared {} existing entries", "ℹ".blue(), cleared);
    }

    // Import entries
    let entries = import_data
        .get("entries")
        .and_then(|e| e.as_array())
        .ok_or_else(|| anyhow::anyhow!("Invalid import file format"))?;

    let mut imported = 0;
    let mut skipped = 0;

    for entry in entries {
        let key_value = entry.get("key");
        let data = entry.get("data");

        if let (Some(key_json), Some(data)) = (key_value, data) {
            if let Ok(key) = serde_json::from_value::<CacheKey>(key_json.clone()) {
                if merge {
                    // Check if key exists
                    if cache.exists(&key).await.unwrap_or(false) {
                        skipped += 1;
                        continue;
                    }
                }

                if cache.set(&key, data).await.is_ok() {
                    imported += 1;
                }
            }
        }
    }

    println!(
        "{} Imported {} entries from {} (skipped {})",
        "✓".green(),
        imported,
        input.display(),
        skipped
    );

    Ok(())
}

/// Run the cache keys subcommand (list keys)
pub async fn run_keys(category: Option<String>, json_output: bool) -> Result<()> {
    // Parse category if provided
    let cat = match &category {
        Some(s) => Some(
            CacheCategory::from_str(s)
                .ok_or_else(|| anyhow::anyhow!("Unknown category: {}", s))?,
        ),
        None => None,
    };

    let config = CacheConfig::default();
    let cache = CacheManager::new(config)
        .await
        .context("Failed to initialize cache")?;

    let keys = cache.keys(cat).await.context("Failed to list cache keys")?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&keys)?);
    } else {
        if keys.is_empty() {
            println!("{} No cache entries found", "ℹ".blue());
        } else {
            println!("{} Cache entries:", "📦".cyan());
            for key in &keys {
                println!("  {} {}", "•".dimmed(), key);
            }
            println!("\nTotal: {} entries", keys.len());
        }
    }

    Ok(())
}

/// Print cache statistics in human-readable format
fn print_stats(stats: &CacheStats) {
    println!("\n{}", "📊 Cache Statistics".cyan().bold());
    println!("{}", "═".repeat(40));

    // Overall stats
    println!("\n{}", "Overall".bold());
    println!(
        "  {} Total entries:  {}",
        "•".dimmed(),
        stats.total_entries
    );
    println!(
        "  {} Total size:     {}",
        "•".dimmed(),
        format_bytes(stats.total_size_bytes)
    );
    println!(
        "  {} Expired:        {}",
        "•".dimmed(),
        stats.expired_entries
    );

    // Hit/miss stats
    println!("\n{}", "Performance".bold());
    println!("  {} Cache hits:     {}", "•".dimmed(), stats.hits);
    println!("  {} Cache misses:   {}", "•".dimmed(), stats.misses);
    println!(
        "  {} Hit ratio:      {:.1}%",
        "•".dimmed(),
        stats.hit_ratio * 100.0
    );

    // Per-category stats
    if !stats.by_category.is_empty() {
        println!("\n{}", "By Category".bold());
        for (category, cat_stats) in &stats.by_category {
            println!(
                "  {} {} entries ({}) {}",
                "•".dimmed(),
                cat_stats.entries,
                format_bytes(cat_stats.size_bytes),
                category.cyan()
            );
        }
    }

    // Timestamps
    if let Some(oldest) = stats.oldest_entry {
        println!("\n{}", "Timeline".bold());
        println!("  {} Oldest entry:   {}", "•".dimmed(), oldest);
        if let Some(newest) = stats.newest_entry {
            println!("  {} Newest entry:   {}", "•".dimmed(), newest);
        }
    }

    println!();
}

/// Format bytes as human-readable string
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_bytes_display() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
        assert_eq!(format_bytes(1073741824), "1.00 GB");
    }
}
