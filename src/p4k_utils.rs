//! P4K file utility functions
//!
//! This module contains functions for P4K archive operations like listing,
//! extracting, packing, patching, and modifying files.

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use crate::{
    utils::{collect_files, create_glob_matcher, format_size, matches_filter},
    CompressionMethod, CryXmlReader, P4kEntry, P4kFile, P4kModifier, P4kWriteEntry,
    P4kWriteOptions, P4kWriter,
};

/// List files in a P4K archive with optional filtering
pub fn list_files(p4k_path: &Path, filter: Option<&str>) -> Result<()> {
    println!("Opening {}...", p4k_path.display());

    let p4k = P4kFile::open(p4k_path)
        .with_context(|| format!("Failed to open {}", p4k_path.display()))?;

    let matcher = filter.map(create_glob_matcher).transpose()?;

    let mut count = 0u64;
    let mut total_size = 0u64;
    let mut compressed_size = 0u64;

    for entry in p4k.entries() {
        if matches_filter(&entry.name, matcher.as_ref()) {
            let method = match entry.compression_method {
                CompressionMethod::Store => "Store",
                CompressionMethod::Deflate => "Deflate",
                CompressionMethod::Zstd => "Zstd",
                CompressionMethod::Unknown(m) => {
                    println!("{} (Unknown method {})", entry.name, m);
                    continue;
                }
            };

            let encrypted = if entry.is_encrypted {
                "Encrypted"
            } else {
                "Plain"
            };

            println!(
                "{:>10} {:>10} {:>8} {:>9} {}",
                format_size(entry.uncompressed_size),
                format_size(entry.compressed_size),
                method,
                encrypted,
                entry.name
            );

            count += 1;
            total_size += entry.uncompressed_size;
            compressed_size += entry.compressed_size;
        }
    }

    println!();
    println!(
        "Total: {} files, {} ({} compressed)",
        count,
        format_size(total_size),
        format_size(compressed_size)
    );

    Ok(())
}

/// Extract files from a P4K archive with optional filtering and CryXML conversion
pub fn extract_files(
    p4k_path: &Path,
    filter: Option<&str>,
    output: &Path,
    convert_xml: bool,
) -> Result<()> {
    println!("Opening {}...", p4k_path.display());

    let mut p4k = P4kFile::open(p4k_path)
        .with_context(|| format!("Failed to open {}", p4k_path.display()))?;

    let matcher = filter.map(create_glob_matcher).transpose()?;

    // Collect matching entries
    let entries: Vec<_> = p4k
        .entries()
        .into_iter()
        .filter(|e| matches_filter(&e.name, matcher.as_ref()))
        .cloned()
        .collect();

    if entries.is_empty() {
        println!("No files match the filter");
        return Ok(());
    }

    println!("Extracting {} files...", entries.len());

    // Create progress bar
    let pb = ProgressBar::new(entries.len() as u64);
    pb.set_style(ProgressStyle::with_template(
        "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
    )?);

    let mut extracted = 0u64;
    let mut failed = 0u64;

    for entry in &entries {
        pb.set_message(entry.name.clone());

        match extract_single_file(&mut p4k, entry, output, convert_xml) {
            Ok(_) => extracted += 1,
            Err(e) => {
                pb.println(format!("Error extracting {}: {}", entry.name, e));
                failed += 1;
            }
        }

        pb.inc(1);
    }

    pb.finish_with_message("Done");

    println!();
    println!("Extracted: {} files", extracted);
    if failed > 0 {
        println!("Failed: {} files", failed);
    }

    Ok(())
}

/// Extract a single file from a P4K archive
pub fn extract_single_file(
    p4k: &mut P4kFile,
    entry: &P4kEntry,
    output: &Path,
    convert_xml: bool,
) -> Result<()> {
    let mut data = p4k.extract_entry(entry)?;

    // Convert CryXML if requested
    let output_name = entry.name.clone();
    if convert_xml
        && (entry.name.ends_with(".xml") || entry.name.ends_with(".mtl"))
        && CryXmlReader::is_cryxml(&data)
    {
        match CryXmlReader::parse(&data) {
            Ok(xml) => {
                data = xml.into_bytes();
            }
            Err(e) => {
                eprintln!("Warning: Failed to convert CryXML {}: {}", entry.name, e);
            }
        }
    }

    // Create output path
    let output_path = output.join(&output_name);

    // Create parent directories
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Write file
    let mut file = File::create(&output_path)?;
    file.write_all(&data)?;

    Ok(())
}

/// Show P4K archive information
pub fn show_info(p4k_path: &Path) -> Result<()> {
    println!("Opening {}...", p4k_path.display());

    let p4k = P4kFile::open(p4k_path)
        .with_context(|| format!("Failed to open {}", p4k_path.display()))?;

    let entries = p4k.entries();
    let eocd_comment = p4k.eocd_comment();

    let mut total_size = 0u64;
    let mut compressed_size = 0u64;
    let mut store_count = 0u64;
    let mut deflate_count = 0u64;
    let mut zstd_count = 0u64;
    let mut encrypted_count = 0u64;

    for entry in &entries {
        total_size += entry.uncompressed_size;
        compressed_size += entry.compressed_size;

        match entry.compression_method {
            CompressionMethod::Store => store_count += 1,
            CompressionMethod::Deflate => deflate_count += 1,
            CompressionMethod::Zstd => zstd_count += 1,
            CompressionMethod::Unknown(_) => {}
        }

        if entry.is_encrypted {
            encrypted_count += 1;
        }
    }

    let ratio = if total_size > 0 {
        (compressed_size as f64 / total_size as f64) * 100.0
    } else {
        0.0
    };

    println!();
    println!("Archive Information:");
    println!("  File: {}", p4k_path.display());
    println!("  Total files: {}", entries.len());
    println!("  Uncompressed size: {}", format_size(total_size));
    println!(
        "  Compressed size: {} ({:.1}%)",
        format_size(compressed_size),
        ratio
    );
    println!();
    println!("Compression Methods:");
    println!("  Store: {} files", store_count);
    println!("  Deflate: {} files", deflate_count);
    println!("  ZSTD: {} files", zstd_count);
    println!();
    println!("Encryption:");
    println!("  Encrypted: {} files", encrypted_count);
    println!("  Plain: {} files", entries.len() as u64 - encrypted_count);
    println!();
    println!("EOCD Comment ({} bytes):", eocd_comment.len());
    if eocd_comment.is_empty() {
        println!("  (none)");
    } else {
        // Display hex dump
        print!("  Hex: ");
        for byte in eocd_comment {
            print!("{:02X} ", byte);
        }
        println!();
        // Display ASCII (printable chars only)
        let ascii: String = eocd_comment
            .iter()
            .map(|&b| {
                if b >= 0x20 && b < 0x7F {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        println!("  ASCII: {}", ascii);
    }

    Ok(())
}

/// Create a new P4K archive from a directory
pub fn pack_directory(
    output: &Path,
    source_dir: &Path,
    compression: CompressionMethod,
    encrypt: bool,
    base_path: Option<&str>,
) -> Result<()> {
    println!("Creating P4K from {}...", source_dir.display());

    // Collect all files
    let files = collect_files(source_dir)?;

    if files.is_empty() {
        println!("No files found in source directory");
        return Ok(());
    }

    println!("Found {} files", files.len());

    let options = P4kWriteOptions {
        compression,
        encrypt,
        zstd_level: 3,
        deflate_level: 6,
    };

    let mut writer = P4kWriter::create_with_options(output, options)?;

    let pb = ProgressBar::new(files.len() as u64);
    pb.set_style(ProgressStyle::with_template(
        "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
    )?);

    for file_path in &files {
        let relative_path = file_path.strip_prefix(source_dir)?;
        let archive_path = if let Some(base) = base_path {
            format!(
                "{}/{}",
                base,
                relative_path.to_string_lossy().replace('\\', "/")
            )
        } else {
            relative_path.to_string_lossy().replace('\\', "/")
        };

        pb.set_message(archive_path.clone());

        let mut data = Vec::new();
        File::open(file_path)?.read_to_end(&mut data)?;

        let entry = P4kWriteEntry::new(archive_path, data);

        writer.add_entry(entry)?;
        pb.inc(1);
    }

    writer.finish()?;
    pb.finish_with_message("Done");

    println!("\nCreated: {}", output.display());

    Ok(())
}

/// Patch an existing P4K with files from a directory
pub fn patch_p4k(
    p4k_path: &Path,
    patch_dir: &Path,
    base_path: Option<&str>,
    compression: CompressionMethod,
) -> Result<()> {
    println!(
        "Patching {} with files from {}...",
        p4k_path.display(),
        patch_dir.display()
    );
    if let Some(bp) = base_path {
        println!("Base path: {}", bp);
    }

    // Collect patch files
    let files = collect_files(patch_dir)?;

    if files.is_empty() {
        println!("No files found in patch directory");
        return Ok(());
    }

    println!("Found {} patch files", files.len());

    let options = P4kWriteOptions {
        compression,
        encrypt: true,
        zstd_level: 3,
        deflate_level: 6,
    };

    let mut modifier = P4kModifier::open(p4k_path)?.with_options(options);

    let pb = ProgressBar::new(files.len() as u64);
    pb.set_style(ProgressStyle::with_template(
        "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
    )?);

    for file_path in &files {
        let relative_path = file_path.strip_prefix(patch_dir)?;
        let relative_str = relative_path.to_string_lossy().replace('\\', "/");

        // Combine base_path with relative path
        let archive_path = match base_path {
            Some(bp) => {
                let bp = bp.trim_end_matches('/');
                format!("{}/{}", bp, relative_str)
            }
            None => relative_str,
        };

        pb.set_message(archive_path.clone());

        let mut data = Vec::new();
        File::open(file_path)?.read_to_end(&mut data)?;

        let entry = P4kWriteEntry::new(archive_path, data);

        modifier.add(entry);
        pb.inc(1);
    }

    modifier.save_incremental()?;
    pb.finish_with_message("Done");

    println!("\nPatched {} files (incremental mode)", files.len());

    Ok(())
}

/// Add a single file to an existing P4K
pub fn add_file(p4k_path: &Path, file: &Path, archive_path: Option<&str>) -> Result<()> {
    let archive_name = archive_path
        .map(|s| s.to_string())
        .unwrap_or_else(|| file.file_name().unwrap().to_string_lossy().to_string());

    println!("Adding {} as {}...", file.display(), archive_name);

    let mut modifier = P4kModifier::open(p4k_path)?;

    let mut data = Vec::new();
    File::open(file)?.read_to_end(&mut data)?;

    let entry = P4kWriteEntry::new(archive_name.clone(), data);

    modifier.add(entry);
    modifier.save_incremental()?;

    println!("Added: {} (incremental mode)", archive_name);

    Ok(())
}

/// Replace a single file in a P4K (minimal impact)
pub fn replace_file(
    p4k_path: &Path,
    file: &Path,
    archive_path: &str,
    keep_compression: bool,
) -> Result<()> {
    println!("Replacing {} in {}...", archive_path, p4k_path.display());

    // Open source to get original entry info
    let original_entry = {
        let source = P4kFile::open(p4k_path)?;
        source
            .entries()
            .into_iter()
            .find(|e| e.name == archive_path)
            .cloned()
    };

    match original_entry {
        Some(entry) => {
            // Read replacement file data
            let mut data = Vec::new();
            File::open(file)?.read_to_end(&mut data)?;

            // Create write entry with original settings if keep_compression is true
            let mut write_entry = P4kWriteEntry::new(archive_path.to_string(), data);

            if keep_compression {
                write_entry = write_entry
                    .with_compression(entry.compression_method)
                    .with_encryption(entry.is_encrypted);
                println!(
                    "  Using original compression: {:?}, encrypted: {}",
                    entry.compression_method, entry.is_encrypted
                );
            }

            let mut modifier = P4kModifier::open(p4k_path)?;
            modifier.add(write_entry);
            modifier.save_incremental()?;

            println!("Replaced: {} (incremental mode)", archive_path);
        }
        None => {
            println!(
                "Warning: {} not found in archive, adding as new file",
                archive_path
            );

            let mut data = Vec::new();
            File::open(file)?.read_to_end(&mut data)?;

            let entry = P4kWriteEntry::new(archive_path.to_string(), data);

            let mut modifier = P4kModifier::open(p4k_path)?;
            modifier.add(entry);
            modifier.save_incremental()?;

            println!("Added: {} (incremental mode)", archive_path);
        }
    }

    Ok(())
}

/// Delete files from a P4K matching the given patterns
pub fn delete_files(p4k_path: &Path, patterns: &[String]) -> Result<()> {
    println!("Deleting files matching: {:?}", patterns);

    let source = P4kFile::open(p4k_path)?;
    let entries: Vec<_> = source.entries().iter().map(|e| e.name.clone()).collect();
    drop(source);

    let mut modifier = P4kModifier::open(p4k_path)?;

    // Create matchers for all patterns
    let matchers: Vec<_> = patterns
        .iter()
        .map(|p| create_glob_matcher(p))
        .collect::<Result<Vec<_>>>()?;

    // Find matching files to delete
    let mut deleted = 0u64;

    for name in entries {
        if matchers.iter().any(|m| m.is_match(&name)) {
            modifier.delete(&name);
            println!("  Deleted: {}", name);
            deleted += 1;
        }
    }

    if deleted > 0 {
        modifier.save_incremental()?;
        println!("\nDeleted {} files (incremental mode)", deleted);
    } else {
        println!("\nNo files matched the patterns");
    }

    Ok(())
}
