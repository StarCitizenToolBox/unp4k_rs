//! General utility functions for unp4k
//!
//! This module contains common helper functions used across the library.

use anyhow::{Context, Result};
use globset::{Glob, GlobMatcher};
use std::fs;
use std::path::{Path, PathBuf};

/// Format a file size in human-readable form (B, KB, MB, GB)
pub fn format_size(size: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if size >= GB {
        format!("{:.2} GB", size as f64 / GB as f64)
    } else if size >= MB {
        format!("{:.2} MB", size as f64 / MB as f64)
    } else if size >= KB {
        format!("{:.2} KB", size as f64 / KB as f64)
    } else {
        format!("{} B", size)
    }
}

/// Create a glob matcher from a pattern string
///
/// Handles common patterns:
/// - `*.ext` becomes `**/*.ext` (match in any directory)
/// - Plain text without wildcards becomes `**/*text*` (substring search)
pub fn create_glob_matcher(pattern: &str) -> Result<GlobMatcher> {
    // Handle common patterns
    let pattern = if pattern.starts_with("*.") {
        format!("**/{}", pattern)
    } else if !pattern.contains('*') && !pattern.contains('?') {
        // Treat as substring search
        format!("**/*{}*", pattern)
    } else {
        pattern.to_string()
    };

    let glob = Glob::new(&pattern).with_context(|| format!("Invalid pattern: {}", pattern))?;
    Ok(glob.compile_matcher())
}

/// Check if a name matches the optional filter
pub fn matches_filter(name: &str, matcher: Option<&GlobMatcher>) -> bool {
    match matcher {
        Some(m) => m.is_match(name),
        None => true,
    }
}

/// Recursively collect all files in a directory
pub fn collect_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_files_recursive(dir, &mut files)?;
    Ok(files)
}

/// Helper function for recursive file collection
pub fn collect_files_recursive(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                collect_files_recursive(&path, files)?;
            } else {
                files.push(path);
            }
        }
    }
    Ok(())
}
