//! Sopack (`.socpak`) file format handling
//!
//! Sopack files are standard ZIP archives used by Star Citizen.
//! This module provides extraction capabilities for `.socpak` files.

use crate::error::{Error, Result};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zip::ZipArchive;

/// Extract a single `.socpak` file to a directory
///
/// # Arguments
/// * `socpak_path` - Path to the `.socpak` file
/// * `output_dir` - Directory to extract files to (defaults to same directory as socpak)
/// * `overwrite` - Whether to overwrite existing files
///
/// # Returns
/// Number of entries extracted
///
/// # Example
/// ```no_run
/// use unp4k::sopack::extract_sopack;
/// let extracted = extract_sopack("file.socpak", None, false)?;
/// println!("Extracted {} files", extracted);
/// # Ok::<(), unp4k::Error>(())
/// ```
pub fn extract_sopack<P: AsRef<Path>>(
    socpak_path: P,
    output_dir: Option<P>,
    overwrite: bool,
) -> Result<usize> {
    let socpak_path = socpak_path.as_ref();

    // Determine output directory
    let output_dir = if let Some(dir) = output_dir {
        dir.as_ref().to_path_buf()
    } else {
        socpak_path
            .parent()
            .ok_or_else(|| {
                Error::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Cannot determine parent directory",
                ))
            })?
            .to_path_buf()
    };

    // Open the ZIP archive
    let file = File::open(socpak_path).map_err(|e| Error::Io(e))?;
    let mut archive = ZipArchive::new(file)
        .map_err(|e| Error::InvalidP4k(format!("Invalid socpak file: {}", e)))?;

    let mut extracted_count = 0;
    let mut buffer = vec![0u8; 8192];

    // Extract each entry
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| Error::InvalidP4k(format!("Failed to read entry: {}", e)))?;

        // Skip directories
        if entry.is_dir() {
            continue;
        }

        let entry_name = entry.name().to_string();
        if entry_name.is_empty() {
            continue;
        }

        let destination_path = output_dir.join(&entry_name);

        // Create parent directories
        if let Some(parent) = destination_path.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::Io(e))?;
        }

        // Check if file exists
        if destination_path.exists() && !overwrite {
            continue;
        }

        // Extract file
        let mut output_file = File::create(&destination_path).map_err(|e| Error::Io(e))?;

        loop {
            let bytes_read = entry.read(&mut buffer).map_err(|e| Error::Io(e))?;
            if bytes_read == 0 {
                break;
            }
            output_file
                .write_all(&buffer[..bytes_read])
                .map_err(|e| Error::Io(e))?;
        }

        extracted_count += 1;
    }

    Ok(extracted_count)
}

/// Extract a `.socpak` file from memory and return its contents as a map
///
/// # Arguments
/// * `data` - The `.socpak` (ZIP) file data
///
/// # Returns
/// A HashMap mapping entry names to their extracted data
///
/// # Example
/// ```no_run
/// use unp4k::sopack::extract_sopack_from_memory;
/// let socpak_data = std::fs::read("file.socpak")?;
/// let contents = extract_sopack_from_memory(&socpak_data)?;
/// for (name, data) in contents {
///     println!("Extracted: {} ({} bytes)", name, data.len());
/// }
/// # Ok::<(), unp4k::Error>(())
/// ```
pub fn extract_sopack_from_memory(
    data: &[u8],
) -> Result<std::collections::HashMap<String, Vec<u8>>> {
    use std::collections::HashMap;

    // Open the ZIP archive from memory
    let cursor = std::io::Cursor::new(data);
    let mut archive = ZipArchive::new(cursor)
        .map_err(|e| Error::InvalidP4k(format!("Invalid socpak data: {}", e)))?;

    let mut contents = HashMap::new();
    let mut buffer = vec![0u8; 8192];

    // Extract each entry
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| Error::InvalidP4k(format!("Failed to read entry: {}", e)))?;

        // Skip directories
        if entry.is_dir() {
            continue;
        }

        let entry_name = entry.name().to_string();
        if entry_name.is_empty() {
            continue;
        }

        // Extract file data
        let mut file_data = Vec::new();
        loop {
            let bytes_read = entry.read(&mut buffer).map_err(|e| Error::Io(e))?;
            if bytes_read == 0 {
                break;
            }
            file_data.extend_from_slice(&buffer[..bytes_read]);
        }

        contents.insert(entry_name, file_data);
    }

    Ok(contents)
}

/// Entry information from a sopack file
#[derive(Debug, Clone)]
pub struct SopackEntryInfo {
    /// Entry name/path within the sopack
    pub name: String,
    /// Uncompressed size in bytes
    pub size: u64,
}

/// List entries in a `.socpak` file from memory without extracting
///
/// # Arguments
/// * `data` - The `.socpak` (ZIP) file data
///
/// # Returns
/// A Vec of entry information
///
/// # Example
/// ```no_run
/// use unp4k::sopack::list_sopack_entries_from_memory;
/// let socpak_data = std::fs::read("file.socpak")?;
/// let entries = list_sopack_entries_from_memory(&socpak_data)?;
/// for entry in entries {
///     println!("{}: {} bytes", entry.name, entry.size);
/// }
/// # Ok::<(), unp4k::Error>(())
/// ```
pub fn list_sopack_entries_from_memory(data: &[u8]) -> Result<Vec<SopackEntryInfo>> {
    // Open the ZIP archive from memory
    let cursor = std::io::Cursor::new(data);
    let mut archive = ZipArchive::new(cursor)
        .map_err(|e| Error::InvalidP4k(format!("Invalid socpak data: {}", e)))?;

    let mut entries = Vec::new();

    // List each entry
    for i in 0..archive.len() {
        let entry = archive
            .by_index(i)
            .map_err(|e| Error::InvalidP4k(format!("Failed to read entry: {}", e)))?;

        // Skip directories
        if entry.is_dir() {
            continue;
        }

        let entry_name = entry.name().to_string();
        if entry_name.is_empty() {
            continue;
        }

        entries.push(SopackEntryInfo {
            name: entry_name,
            size: entry.size(),
        });
    }

    Ok(entries)
}

/// Extract a single file from a `.socpak` file in memory
///
/// # Arguments
/// * `data` - The `.socpak` (ZIP) file data
/// * `file_name` - Name of the file to extract
///
/// # Returns
/// The extracted file data
pub fn extract_single_from_memory(data: &[u8], file_name: &str) -> Result<Vec<u8>> {
    // Open the ZIP archive from memory
    let cursor = std::io::Cursor::new(data);
    let mut archive = ZipArchive::new(cursor)
        .map_err(|e| Error::InvalidP4k(format!("Invalid socpak data: {}", e)))?;

    // Find and extract the specific file
    let mut entry = archive
        .by_name(file_name)
        .map_err(|e| Error::EntryNotFound(format!("File not found in socpak: {}", e)))?;

    let mut file_data = Vec::with_capacity(entry.size() as usize);
    entry
        .read_to_end(&mut file_data)
        .map_err(|e| Error::Io(e))?;

    Ok(file_data)
}

/// Check if a file is a `.socpak` file based on its extension
pub fn is_sopack<P: AsRef<Path>>(path: P) -> bool {
    path.as_ref()
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("socpak"))
        .unwrap_or(false)
}

/// Extract all `.socpak` files in a directory (recursively)
///
/// # Arguments
/// * `dir_path` - Directory to search for `.socpak` files
/// * `recursive` - Whether to search recursively
/// * `overwrite` - Whether to overwrite existing files
///
/// # Returns
/// Total number of entries extracted from all `.socpak` files
pub fn extract_all_sopacks<P: AsRef<Path>>(
    dir_path: P,
    recursive: bool,
    overwrite: bool,
) -> Result<usize> {
    let dir_path = dir_path.as_ref();
    let mut total_extracted = 0;

    let entries: Vec<PathBuf> = if recursive {
        walkdir::WalkDir::new(dir_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.path().to_path_buf())
            .collect()
    } else {
        fs::read_dir(dir_path)
            .map_err(|e| Error::Io(e))?
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
            .map(|e| e.path())
            .collect()
    };

    let sopack_files: Vec<_> = entries.into_iter().filter(|path| is_sopack(path)).collect();

    for sopack_file in sopack_files {
        match extract_sopack(&sopack_file, None, overwrite) {
            Ok(count) => {
                total_extracted += count;
            }
            Err(e) => {
                eprintln!("Failed to extract {:?}: {}", sopack_file, e);
            }
        }
    }

    Ok(total_extracted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_sopack() {
        assert!(is_sopack("file.socpak"));
        assert!(is_sopack("file.SOCPAK"));
        assert!(!is_sopack("file.zip"));
        assert!(!is_sopack("file.p4k"));
    }
}
