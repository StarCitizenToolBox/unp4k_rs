//! DataForge/DCB utility functions
//!
//! This module contains functions for DCB file conversion and export.

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::DataForge;

/// Convert a DCB file to XML
///
/// If `merge` is true, all records are merged into a single XML file.
/// Otherwise, each record is exported to a separate file.
pub fn convert_dcb(
    dcb_path: &Path,
    output: Option<&Path>,
    merge: bool,
    info_only: bool,
) -> Result<()> {
    println!("Loading DataForge file: {}", dcb_path.display());

    let data =
        fs::read(dcb_path).with_context(|| format!("Failed to read {}", dcb_path.display()))?;

    let df = DataForge::parse(&data).with_context(|| "Failed to parse DataForge file")?;

    // Show info
    show_dcb_info(&df);

    if info_only {
        // Just list some record paths
        println!("\nRecord paths (first 20):");
        for (i, path) in df.record_paths().take(20).enumerate() {
            println!("  {}. {}", i + 1, path);
        }
        if df.record_count() > 20 {
            println!("  ... and {} more", df.record_count() - 20);
        }
        return Ok(());
    }

    if merge {
        export_merged(&df, dcb_path, output)?;
    } else {
        export_separate(&df, dcb_path, output)?;
    }

    Ok(())
}

/// Display DCB file information
pub fn show_dcb_info(df: &DataForge) {
    println!("\nDataForge Info:");
    println!("  Version: {}", df.header.file_version);
    println!("  Legacy format: {}", df.header.is_legacy);
    println!(
        "  Struct definitions: {}",
        df.header.struct_definition_count
    );
    println!(
        "  Property definitions: {}",
        df.header.property_definition_count
    );
    println!("  Enum definitions: {}", df.header.enum_definition_count);
    println!("  Records: {}", df.header.record_definition_count);
    println!("  Text length: {} bytes", df.header.text_length);
    println!("  Blob length: {} bytes", df.header.blob_length);
}

/// Export all records to a single merged XML file
pub fn export_merged(df: &DataForge, dcb_path: &Path, output: Option<&Path>) -> Result<()> {
    let output_path = output.map(PathBuf::from).unwrap_or_else(|| {
        let mut p = dcb_path.to_path_buf();
        p.set_extension("xml");
        p
    });

    println!("\nConverting to single XML file (merged mode)...");

    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    xml.push_str("<DataForge>\n");

    let pb = ProgressBar::new(df.record_count() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .unwrap()
            .progress_chars("#>-"),
    );

    let mut success = 0u64;

    for idx in 0..df.record_count() {
        pb.inc(1);

        match df.record_to_xml_by_index(idx, false) {
            Ok(record_xml) => {
                // Skip XML declaration from each record
                let content = record_xml
                    .strip_prefix("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")
                    .unwrap_or(&record_xml);
                xml.push_str("  ");
                xml.push_str(content);
                xml.push('\n');
                success += 1;
            }
            Err(e) => {
                eprintln!("Warning: Failed to convert record {}: {}", idx, e);
            }
        }
    }

    pb.finish_with_message("Done");

    xml.push_str("</DataForge>\n");

    fs::write(&output_path, &xml)?;
    println!("\nSaved {} records to {}", success, output_path.display());

    Ok(())
}

/// Export each record to a separate XML file
pub fn export_separate(df: &DataForge, dcb_path: &Path, output: Option<&Path>) -> Result<()> {
    let output_dir = output.map(PathBuf::from).unwrap_or_else(|| {
        // Use DCB filename without extension as output directory
        let stem = dcb_path.file_stem().unwrap_or_default();
        PathBuf::from(stem)
    });
    fs::create_dir_all(&output_dir)?;

    println!(
        "\nExporting {} records to separate files in {}...",
        df.record_count(),
        output_dir.display()
    );
    let pb = ProgressBar::new(df.record_count() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .unwrap()
            .progress_chars("#>-"),
    );

    let mut success = 0u64;
    let mut failed = 0u64;

    for (path, &idx) in df.path_to_record() {
        pb.inc(1);

        match df.record_to_xml_by_index(idx, false) {
            Ok(xml) => {
                // Create directory structure based on record path
                let out_path = output_dir.join(format!("{}.xml", path));
                if let Some(parent) = out_path.parent() {
                    fs::create_dir_all(parent)?;
                }

                fs::write(&out_path, xml)?;
                success += 1;
            }
            Err(e) => {
                eprintln!("Warning: Failed to convert {}: {}", path, e);
                failed += 1;
            }
        }
    }

    pb.finish_with_message("Done");
    println!(
        "\nExported {} records ({} failed) to {}",
        success,
        failed,
        output_dir.display()
    );

    Ok(())
}

/// Get a list of all record paths in the DataForge file
pub fn get_record_list(df: &DataForge) -> Vec<String> {
    df.record_paths().cloned().collect()
}

/// Extract a single record to memory (XML string)
///
/// # Arguments
/// * `df` - The DataForge instance
/// * `path` - The record path to extract
/// * `format_xml` - If true, format XML with indentation for human readability (default: true)
pub fn extract_to_memory(df: &DataForge, path: &str, format_xml: bool) -> Result<String> {
    Ok(df.record_to_xml(path, format_xml)?)
}

/// Extract all records to memory (HashMap of path -> XML string)
///
/// # Arguments
/// * `df` - The DataForge instance  
/// * `format_xml` - If true, format XML with indentation for human readability (default: true)
pub fn extract_all_to_memory(df: &DataForge, format_xml: bool) -> Result<HashMap<String, String>> {
    Ok(df.extract_all_to_memory(format_xml)?)
}

/// A single match within a DCB record
#[derive(Debug, Clone)]
pub struct DcbSearchMatch {
    /// Line number where the match was found (1-indexed)
    pub line_number: usize,
    /// Content of the matching line (truncated if too long)
    pub line_content: String,
}

/// Search result for a single DCB record
#[derive(Debug, Clone)]
pub struct DcbSearchResult {
    /// The record path
    pub path: String,
    /// The record index
    pub index: usize,
    /// List of matches within this record
    pub matches: Vec<DcbSearchMatch>,
}

/// Full-text search across all DCB records
///
/// Searches both record paths and their XML content for the given query.
/// Uses parallel processing for performance.
///
/// # Arguments
/// * `df` - The DataForge instance
/// * `query` - The search query (case-insensitive)
///
/// # Returns
/// A vector of search results, sorted by path. Each record can have up to 11 matches
/// (allowing applications to display "10+").
pub fn search_records(df: &DataForge, query: &str) -> Vec<DcbSearchResult> {
    use rayon::prelude::*;

    let query_lower = query.to_lowercase();

    // Collect all record paths and indices
    let records: Vec<(String, usize)> = df
        .path_to_record()
        .iter()
        .map(|(path, &index)| (path.clone(), index))
        .collect();

    // Use rayon for parallel search
    let mut results: Vec<DcbSearchResult> = records
        .par_iter()
        .filter_map(|(path, index)| {
            // First check if path matches
            let path_matches = path.to_lowercase().contains(&query_lower);

            // Try to get XML and search content
            if let Ok(xml) = df.record_to_xml_by_index(*index, true) {
                let mut matches = Vec::new();

                for (line_num, line) in xml.lines().enumerate() {
                    if line.to_lowercase().contains(&query_lower) {
                        let line_content = if line.len() > 200 {
                            format!("{}...", &line[..200])
                        } else {
                            line.to_string()
                        };
                        matches.push(DcbSearchMatch {
                            line_number: line_num + 1,
                            line_content,
                        });

                        // Keep up to 11 matches per record (for "10+" display)
                        if matches.len() >= 11 {
                            break;
                        }
                    }
                }

                if path_matches || !matches.is_empty() {
                    return Some(DcbSearchResult {
                        path: path.clone(),
                        index: *index,
                        matches,
                    });
                }
            }
            None
        })
        .collect();

    // Sort by path for stable results
    results.sort_by(|a, b| a.path.cmp(&b.path));

    results
}
