//! DataForge/DCB binary format parser
//!
//! DataForge is the binary format used by Star Citizen to store game data configuration.
//! Files with `.dcb` extension contain structured data that can be converted to XML.
//!
//! ## Format Overview
//!
//! A DataForge file consists of:
//! - File header with version and counts
//! - Definition tables (structs, properties, enums, data mappings, records)
//! - Value arrays (integers, floats, strings, GUIDs, pointers, etc.)
//! - String tables (text and blob data)
//! - Actual data section
//!
//! ## Example
//!
//! ```rust,no_run
//! use unp4k::dataforge::DataForge;
//!
//! let data = std::fs::read("Game.dcb")?;
//! let df = DataForge::parse(&data)?;
//!
//! // Get all record paths
//! for path in df.record_paths() {
//!     println!("{}", path);
//! }
//!
//! // Convert a specific record to XML
//! let xml = df.record_to_xml("path/to/record")?;
//! # Ok::<(), unp4k::Error>(())
//! ```

mod definitions;
mod header;
mod reader;
mod types;
pub mod utils;
mod xml;

pub use header::DataForgeHeader;
pub use reader::DataForge;
pub use types::*;
pub use utils::{
    convert_dcb, export_merged, export_separate, extract_all_to_memory, extract_to_memory,
    get_record_list, search_records, show_dcb_info, DcbSearchMatch, DcbSearchResult,
};
