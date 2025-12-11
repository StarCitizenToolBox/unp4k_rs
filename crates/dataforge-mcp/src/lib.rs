//! dataforge-mcp - MCP Server for Star Citizen DataForge/DCB data
//!
//! This crate provides an MCP (Model Context Protocol) server that exposes
//! DataForge/DCB data for AI model consumption.
//!
//! ## Features
//!
//! - Full-text search across all DCB records
//! - Path-based filtering with pagination
//! - Regex pattern matching support
//! - Pre-search for getting total counts before fetching data
//! - Content retrieval by path with line range support
//! - Line number indexing for all search results
//!
//! ## Usage
//!
//! ### From file path
//!
//! ```rust,no_run
//! use dataforge_mcp::start_mcp_server;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     start_mcp_server("path/to/Game.dcb", 3721).await
//! }
//! ```
//!
//! ### From bytes (e.g., Uint8List in Dart/Flutter)
//!
//! ```rust,no_run
//! use dataforge_mcp::start_mcp_server_with_bytes;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let data: Vec<u8> = std::fs::read("path/to/Game.dcb")?;
//!     start_mcp_server_with_bytes(&data, 3000, true).await
//! }
//! ```

mod server;
mod tools;

pub use server::start_mcp_server;
pub use server::start_mcp_server_with_bytes;
pub use server::DataForgeServer;
