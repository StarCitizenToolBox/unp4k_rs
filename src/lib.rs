//! # unp4k
//!
//! A Rust library for extracting and modifying Star Citizen `.p4k` files.
//!
//! ## Overview
//!
//! The `.p4k` files used by Star Citizen are encrypted ZIP archives with custom
//! compression support (ZSTD). This library provides:
//!
//! - Reading and extracting files from `.p4k` archives
//! - Creating new `.p4k` archives
//! - Modifying existing archives (add/replace/delete entries)
//! - AES-128-CBC encryption/decryption with the standard CryEngine key
//! - Support for STORE, DEFLATE, and ZSTD compression methods
//! - CryXML binary format to XML conversion
//!
//! ## Example - Reading
//!
//! ```rust,no_run
//! use unp4k::P4kFile;
//!
//! fn main() -> anyhow::Result<()> {
//!     let mut p4k = P4kFile::open("Data.p4k")?;
//!     
//!     // List all entries
//!     for entry in p4k.entries() {
//!         println!("{}", entry.name);
//!     }
//!     
//!     // Extract a specific file
//!     let data = p4k.extract("Data/path/to/file.xml")?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Example - Writing
//!
//! ```rust,no_run
//! use unp4k::{P4kWriter, P4kWriteEntry};
//!
//! fn main() -> anyhow::Result<()> {
//!     let mut writer = P4kWriter::create("output.p4k")?;
//!     
//!     writer.add_entry(P4kWriteEntry::new(
//!         "Data/test.txt",
//!         b"Hello World".to_vec(),
//!     ))?;
//!     
//!     writer.finish()?;
//!     Ok(())
//! }
//! ```
//!
//! ## Example - Modifying
//!
//! ```rust,no_run
//! use unp4k::{P4kModifier, P4kWriteEntry};
//!
//! fn main() -> anyhow::Result<()> {
//!     let mut modifier = P4kModifier::open("Data.p4k")?;
//!     
//!     // Add or replace a file
//!     modifier.add(P4kWriteEntry::new(
//!         "Data/modified.txt",
//!         b"Modified content".to_vec(),
//!     ));
//!     
//!     // Delete a file
//!     modifier.delete("Data/unwanted.txt");
//!     
//!     // Save to new file
//!     modifier.save("Data_modified.p4k")?;
//!     Ok(())
//! }
//! ```

pub mod crypto;
pub mod cryxml;
pub mod dataforge;
pub mod error;
pub mod p4k;
pub mod p4k_utils;
pub mod p4k_writer;
pub mod socpak;
pub mod utils;

pub use cryxml::CryXmlReader;
pub use dataforge::DataForge;
pub use error::{Error, Result};
pub use p4k::{CompressionMethod, EntrySource, P4kEntry, P4kFile, P4kOpenOptions};
pub use p4k_writer::{P4kModifier, P4kWriteEntry, P4kWriteOptions, P4kWriter};
pub use utils::{collect_files, create_glob_matcher, format_size, matches_filter};
