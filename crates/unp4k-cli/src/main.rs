//! unp4k - A tool for extracting and modifying Star Citizen .p4k files
//!
//! Usage:
//!   unp4k <p4k_file> [filter]        - Extract files matching filter (default: *.*)
//!   unp4k list <p4k_file> [filter]   - List files matching filter
//!   unp4k extract <p4k_file> <file>  - Extract a specific file
//!   unp4k info <p4k_file>            - Show archive information
//!   unp4k pack <output> <dir>        - Create a new P4K from directory
//!   unp4k patch <p4k_file> <dir>     - Patch a P4K with files from directory
//!   unp4k mcp <dcb_file>             - Start MCP server for DataForge data

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::{Path, PathBuf};

use unp4k::dataforge::utils::convert_dcb;
use unp4k::p4k_utils::{
    add_file, delete_files, extract_files, extract_files_ex, list_files, pack_directory, patch_p4k,
    replace_file, show_info,
};
use unp4k::CompressionMethod;

#[derive(Parser)]
#[command(name = "unp4k")]
#[command(author = "xkeyC")]
#[command(version = "0.1.0")]
#[command(about = "Extract and modify Star Citizen .p4k files", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to the .p4k file (for quick extract mode)
    p4k_file: Option<PathBuf>,

    /// Filter pattern (e.g., *.xml, Data/*)
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
        /// Extract .socpak files as directories
        #[arg(long)]
        socpak_to_dir: bool,
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
        /// Base path prefix for files in archive (e.g., "Data/Localization")
        #[arg(short, long)]
        base_path: Option<String>,
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
        /// Full path in archive (e.g., "Data/Localization/chinese_(simplified)/global.ini")
        #[arg(short, long)]
        archive_path: Option<String>,
    },
    /// Delete files from a P4K
    Delete {
        /// Source P4K file
        p4k_file: PathBuf,
        /// Files to delete (patterns supported)
        #[arg(required = true, num_args = 1..)]
        patterns: Vec<String>,
    },
    /// Replace a single file in P4K (minimal impact)
    Replace {
        /// Source P4K file
        p4k_file: PathBuf,
        /// File to use as replacement
        file: PathBuf,
        /// Full path in archive to replace (e.g., "Data/Localization/chinese_(simplified)/global.ini")
        archive_path: String,
        /// Use original compression method (default: true)
        #[arg(long, default_value = "true")]
        keep_compression: bool,
    },
    /// Convert DataForge/DCB file to XML
    Dcb {
        /// Path to the .dcb file
        dcb_file: PathBuf,
        /// Output directory (default: same name as input file)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Merge all records into a single XML file (default: separate files like upstream)
        #[arg(short, long)]
        merge: bool,
        /// Show DCB info only (don't convert)
        #[arg(long)]
        info: bool,
    },
    /// Extract .socpak files
    Unsocpak {
        /// Path to the .socpak file or directory containing .socpak files
        input: PathBuf,
        /// Output directory (default: same directory as input)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Overwrite existing files
        #[arg(short = 'w', long)]
        overwrite: bool,
        /// Recursively search for .socpak files in directory
        #[arg(short, long)]
        recursive: bool,
    },
    /// Start MCP (Model Context Protocol) server for DataForge/DCB data
    #[cfg(feature = "mcp")]
    Mcp {
        /// Path to the .dcb file
        dcb_file: PathBuf,
        /// HTTP port to listen on
        #[arg(short, long, default_value = "3721")]
        port: u16,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::List { p4k_file, filter }) => {
            list_files(&p4k_file, filter.as_deref())?;
        }
        Some(Commands::Extract {
            p4k_file,
            filter,
            output,
            convert_xml,
            socpak_to_dir,
        }) => {
            extract_files_ex(
                &p4k_file,
                filter.as_deref(),
                &output,
                convert_xml,
                socpak_to_dir,
            )?;
        }
        Some(Commands::Info { p4k_file }) => {
            show_info(&p4k_file)?;
        }
        Some(Commands::Pack {
            output,
            source_dir,
            compression,
            encrypt,
            base_path,
        }) => {
            pack_directory(
                &output,
                &source_dir,
                compression.into(),
                encrypt,
                base_path.as_deref(),
            )?;
        }
        Some(Commands::Patch {
            p4k_file,
            patch_dir,
            base_path,
            compression,
        }) => {
            patch_p4k(
                &p4k_file,
                &patch_dir,
                base_path.as_deref(),
                compression.into(),
            )?;
        }
        Some(Commands::Add {
            p4k_file,
            file,
            archive_path,
        }) => {
            add_file(&p4k_file, &file, archive_path.as_deref())?;
        }
        Some(Commands::Delete { p4k_file, patterns }) => {
            delete_files(&p4k_file, &patterns)?;
        }
        Some(Commands::Replace {
            p4k_file,
            file,
            archive_path,
            keep_compression,
        }) => {
            replace_file(&p4k_file, &file, &archive_path, keep_compression)?;
        }
        Some(Commands::Dcb {
            dcb_file,
            output,
            merge,
            info,
        }) => {
            convert_dcb(&dcb_file, output.as_deref(), merge, info)?;
        }
        Some(Commands::Unsocpak {
            input,
            output,
            overwrite,
            recursive,
        }) => {
            if input.is_file() {
                // Extract single .socpak file
                let extracted = unp4k::socpak::extract_socpak(&input, output.as_ref(), overwrite)?;
                println!("Extracted {} entries from {}", extracted, input.display());
            } else if input.is_dir() {
                // Extract all .socpak files in directory
                let extracted = unp4k::socpak::extract_all_socpaks(&input, recursive, overwrite)?;
                println!(
                    "Extracted {} total entries from .socpak files in {}",
                    extracted,
                    input.display()
                );
            } else {
                eprintln!(
                    "Error: {} is not a valid file or directory",
                    input.display()
                );
                std::process::exit(1);
            }
        }
        #[cfg(feature = "mcp")]
        Some(Commands::Mcp { dcb_file, port }) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                dataforge_mcp::start_mcp_server(dcb_file.to_str().unwrap(), port).await
            })?;
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
                eprintln!(
                    "       unp4k patch <p4k_file> <patch_dir> [-b base_path] [-c compression]"
                );
                eprintln!("       unp4k add <p4k_file> <file> [-a archive_path]");
                eprintln!("       unp4k delete <p4k_file> <patterns...>");
                eprintln!("       unp4k replace <p4k_file> <file> <archive_path>");
                eprintln!("       unp4k dcb <dcb_file> [-o output] [-s]");
                eprintln!("       unp4k unsocpak <socpak_file|dir> [-o output] [-w] [-r]");
                #[cfg(feature = "mcp")]
                eprintln!("       unp4k mcp <dcb_file> [-p port]");
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
