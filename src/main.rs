//! unp4k - A tool for extracting and modifying Star Citizen .p4k files
//!
//! Usage:
//!   unp4k <p4k_file> [filter]        - Extract files matching filter (default: *.*)
//!   unp4k list <p4k_file> [filter]   - List files matching filter
//!   unp4k extract <p4k_file> <file>  - Extract a specific file
//!   unp4k info <p4k_file>            - Show archive information
//!   unp4k pack <output> <dir>        - Create a new P4K from directory
//!   unp4k patch <p4k_file> <dir>     - Patch a P4K with files from directory

use clap::{Parser, Subcommand, ValueEnum};
use indicatif::{ProgressBar, ProgressStyle};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use globset::{Glob, GlobMatcher};
use anyhow::{Context, Result};

use unp4k::{P4kFile, P4kWriter, P4kWriteEntry, P4kWriteOptions, P4kModifier, CryXmlReader, CompressionMethod};

#[derive(Parser)]
#[command(name = "unp4k")]
#[command(author = "xkeyC")]
#[command(version = "0.1.0")]
#[command(about = "Extract and modify Star Citizen .p4k files", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to the .p4k file (for quick extract mode)
    #[arg(global = true)]
    p4k_file: Option<PathBuf>,

    /// Filter pattern (e.g., *.xml, Data/*)
    #[arg(global = true)]
    filter: Option<String>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Compression {
    Store,
    Deflate,
    Zstd,
}

impl From<Compression> for CompressionMethod {
    fn from(c: Compression) -> Self {
        match c {
            Compression::Store => CompressionMethod::Store,
            Compression::Deflate => CompressionMethod::Deflate,
            Compression::Zstd => CompressionMethod::Zstd,
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// List files in the archive
    List {
        /// Path to the .p4k file
        p4k_file: PathBuf,
        /// Filter pattern
        filter: Option<String>,
    },
    /// Extract files from the archive
    Extract {
        /// Path to the .p4k file
        p4k_file: PathBuf,
        /// Filter pattern or specific file path
        filter: Option<String>,
        /// Output directory
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
        /// Convert CryXML files to XML
        #[arg(short, long)]
        convert_xml: bool,
    },
    /// Show archive information
    Info {
        /// Path to the .p4k file
        p4k_file: PathBuf,
    },
    /// Create a new P4K archive from a directory
    Pack {
        /// Output P4K file path
        output: PathBuf,
        /// Source directory
        source_dir: PathBuf,
        /// Compression method
        #[arg(short, long, value_enum, default_value = "zstd")]
        compression: Compression,
        /// Encrypt entries
        #[arg(short, long, default_value = "true")]
        encrypt: bool,
        /// Base path prefix for files in archive
        #[arg(short, long)]
        base_path: Option<String>,
    },
    /// Patch an existing P4K with files from a directory
    Patch {
        /// Source P4K file
        p4k_file: PathBuf,
        /// Directory containing patch files
        patch_dir: PathBuf,
        /// Output P4K file (default: overwrite source)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Compression method
        #[arg(short, long, value_enum, default_value = "zstd")]
        compression: Compression,
    },
    /// Add a single file to an existing P4K
    Add {
        /// Source P4K file
        p4k_file: PathBuf,
        /// File to add
        file: PathBuf,
        /// Path in archive
        #[arg(short, long)]
        archive_path: Option<String>,
        /// Output P4K file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Delete files from a P4K
    Delete {
        /// Source P4K file
        p4k_file: PathBuf,
        /// Files to delete (patterns supported)
        patterns: Vec<String>,
        /// Output P4K file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::List { p4k_file, filter }) => {
            list_files(&p4k_file, filter.as_deref())?;
        }
        Some(Commands::Extract { p4k_file, filter, output, convert_xml }) => {
            extract_files(&p4k_file, filter.as_deref(), &output, convert_xml)?;
        }
        Some(Commands::Info { p4k_file }) => {
            show_info(&p4k_file)?;
        }
        Some(Commands::Pack { output, source_dir, compression, encrypt, base_path }) => {
            pack_directory(&output, &source_dir, compression.into(), encrypt, base_path.as_deref())?;
        }
        Some(Commands::Patch { p4k_file, patch_dir, output, compression }) => {
            patch_p4k(&p4k_file, &patch_dir, output.as_deref(), compression.into())?;
        }
        Some(Commands::Add { p4k_file, file, archive_path, output }) => {
            add_file(&p4k_file, &file, archive_path.as_deref(), output.as_deref())?;
        }
        Some(Commands::Delete { p4k_file, patterns, output }) => {
            delete_files(&p4k_file, &patterns, output.as_deref())?;
        }
        None => {
            // Quick extract mode (like original unp4k)
            if let Some(p4k_file) = cli.p4k_file {
                let filter = cli.filter.as_deref().unwrap_or("*.*");
                extract_files(&p4k_file, Some(filter), Path::new("."), false)?;
            } else {
                eprintln!("Usage: unp4k <p4k_file> [filter]");
                eprintln!("       unp4k list <p4k_file> [filter]");
                eprintln!("       unp4k extract <p4k_file> [filter] [-o output]");
                eprintln!("       unp4k info <p4k_file>");
                eprintln!("       unp4k pack <output> <dir> [-c compression]");
                eprintln!("       unp4k patch <p4k_file> <patch_dir> [-o output]");
                eprintln!("       unp4k add <p4k_file> <file> [-a archive_path]");
                eprintln!("       unp4k delete <p4k_file> <patterns...>");
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

fn create_glob_matcher(pattern: &str) -> Result<GlobMatcher> {
    // Handle common patterns
    let pattern = if pattern.starts_with("*.") {
        format!("**/{}", pattern)
    } else if !pattern.contains('*') && !pattern.contains('?') {
        // Treat as substring search
        format!("**/*{}*", pattern)
    } else {
        pattern.to_string()
    };
    
    let glob = Glob::new(&pattern)
        .with_context(|| format!("Invalid pattern: {}", pattern))?;
    Ok(glob.compile_matcher())
}

fn matches_filter(name: &str, matcher: Option<&GlobMatcher>) -> bool {
    match matcher {
        Some(m) => m.is_match(name),
        None => true,
    }
}

fn list_files(p4k_path: &Path, filter: Option<&str>) -> Result<()> {
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
                unp4k::p4k::CompressionMethod::Store => "Store",
                unp4k::p4k::CompressionMethod::Deflate => "Deflate",
                unp4k::p4k::CompressionMethod::Zstd => "Zstd",
                unp4k::p4k::CompressionMethod::Unknown(m) => {
                    println!("{} (Unknown method {})", entry.name, m);
                    continue;
                }
            };
            
            let encrypted = if entry.is_encrypted { "Encrypted" } else { "Plain" };
            
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
    println!("Total: {} files, {} ({} compressed)",
        count,
        format_size(total_size),
        format_size(compressed_size)
    );
    
    Ok(())
}

fn extract_files(p4k_path: &Path, filter: Option<&str>, output: &Path, convert_xml: bool) -> Result<()> {
    println!("Opening {}...", p4k_path.display());
    
    let mut p4k = P4kFile::open(p4k_path)
        .with_context(|| format!("Failed to open {}", p4k_path.display()))?;
    
    let matcher = filter.map(create_glob_matcher).transpose()?;
    
    // Collect matching entries
    let entries: Vec<_> = p4k.entries()
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
        "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})"
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

fn extract_single_file(
    p4k: &mut P4kFile,
    entry: &unp4k::P4kEntry,
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

fn show_info(p4k_path: &Path) -> Result<()> {
    println!("Opening {}...", p4k_path.display());
    
    let p4k = P4kFile::open(p4k_path)
        .with_context(|| format!("Failed to open {}", p4k_path.display()))?;
    
    let entries = p4k.entries();
    
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
            unp4k::p4k::CompressionMethod::Store => store_count += 1,
            unp4k::p4k::CompressionMethod::Deflate => deflate_count += 1,
            unp4k::p4k::CompressionMethod::Zstd => zstd_count += 1,
            unp4k::p4k::CompressionMethod::Unknown(_) => {}
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
    println!("  Compressed size: {} ({:.1}%)", format_size(compressed_size), ratio);
    println!();
    println!("Compression Methods:");
    println!("  Store: {} files", store_count);
    println!("  Deflate: {} files", deflate_count);
    println!("  ZSTD: {} files", zstd_count);
    println!();
    println!("Encryption:");
    println!("  Encrypted: {} files", encrypted_count);
    println!("  Plain: {} files", entries.len() as u64 - encrypted_count);
    
    Ok(())
}

fn format_size(size: u64) -> String {
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

fn pack_directory(
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
        "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})"
    )?);
    
    for file_path in &files {
        let relative_path = file_path.strip_prefix(source_dir)?;
        let archive_path = if let Some(base) = base_path {
            format!("{}/{}", base, relative_path.to_string_lossy().replace('\\', "/"))
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

fn collect_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_files_recursive(dir, &mut files)?;
    Ok(files)
}

fn collect_files_recursive(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
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

fn patch_p4k(
    p4k_path: &Path,
    patch_dir: &Path,
    output: Option<&Path>,
    compression: CompressionMethod,
) -> Result<()> {
    println!("Patching {} with files from {}...", p4k_path.display(), patch_dir.display());
    
    // Collect patch files
    let files = collect_files(patch_dir)?;
    
    if files.is_empty() {
        println!("No files found in patch directory");
        return Ok(());
    }
    
    println!("Found {} patch files", files.len());
    
    let output_path = output.unwrap_or(p4k_path);
    let temp_output = if output_path == p4k_path {
        let mut temp = p4k_path.to_path_buf();
        temp.set_extension("p4k.tmp");
        Some(temp)
    } else {
        None
    };
    
    let actual_output = temp_output.as_deref().unwrap_or(output_path);
    
    let options = P4kWriteOptions {
        compression,
        encrypt: true,
        zstd_level: 3,
        deflate_level: 6,
    };
    
    let mut modifier = P4kModifier::open(p4k_path)?.with_options(options);
    
    let pb = ProgressBar::new(files.len() as u64);
    pb.set_style(ProgressStyle::with_template(
        "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})"
    )?);
    
    for file_path in &files {
        let relative_path = file_path.strip_prefix(patch_dir)?;
        let archive_path = relative_path.to_string_lossy().replace('\\', "/");
        
        pb.set_message(archive_path.clone());
        
        let mut data = Vec::new();
        File::open(file_path)?.read_to_end(&mut data)?;
        
        let entry = P4kWriteEntry::new(archive_path, data);
        
        modifier.add(entry);
        pb.inc(1);
    }
    
    modifier.save(actual_output)?;
    pb.finish_with_message("Done");
    
    // Replace original if needed
    if let Some(temp) = temp_output {
        fs::rename(&temp, p4k_path)?;
    }
    
    println!("\nPatched: {}", output_path.display());
    
    Ok(())
}

fn add_file(
    p4k_path: &Path,
    file: &Path,
    archive_path: Option<&str>,
    output: Option<&Path>,
) -> Result<()> {
    let archive_name = archive_path
        .map(|s| s.to_string())
        .unwrap_or_else(|| file.file_name().unwrap().to_string_lossy().to_string());
    
    println!("Adding {} as {}...", file.display(), archive_name);
    
    let output_path = output.unwrap_or(p4k_path);
    let temp_output = if output_path == p4k_path {
        let mut temp = p4k_path.to_path_buf();
        temp.set_extension("p4k.tmp");
        Some(temp)
    } else {
        None
    };
    
    let actual_output = temp_output.as_deref().unwrap_or(output_path);
    
    let mut modifier = P4kModifier::open(p4k_path)?;
    
    let mut data = Vec::new();
    File::open(file)?.read_to_end(&mut data)?;
    
    let entry = P4kWriteEntry::new(archive_name.clone(), data);
    
    modifier.add(entry);
    modifier.save(actual_output)?;
    
    if let Some(temp) = temp_output {
        fs::rename(&temp, p4k_path)?;
    }
    
    println!("Added: {}", archive_name);
    
    Ok(())
}

fn delete_files(
    p4k_path: &Path,
    patterns: &[String],
    output: Option<&Path>,
) -> Result<()> {
    println!("Deleting files matching: {:?}", patterns);
    
    let output_path = output.unwrap_or(p4k_path);
    let temp_output = if output_path == p4k_path {
        let mut temp = p4k_path.to_path_buf();
        temp.set_extension("p4k.tmp");
        Some(temp)
    } else {
        None
    };
    
    let actual_output = temp_output.as_deref().unwrap_or(output_path);
    
    // First, open the source to get file list
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
    
    modifier.save(actual_output)?;
    
    if let Some(temp) = temp_output {
        fs::rename(&temp, p4k_path)?;
    }
    
    println!("\nDeleted {} files", deleted);
    
    Ok(())
}