//! Tool definitions and request/response types for the MCP server

use rmcp::schemars::{self, JsonSchema};
use serde::{Deserialize, Serialize};

/// Pagination parameters for list operations
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PaginationParams {
    /// Page number (1-indexed)
    #[serde(default = "default_page")]
    pub page: usize,
    /// Number of items per page (max 100)
    #[serde(default = "default_page_size")]
    pub page_size: usize,
}

fn default_page() -> usize {
    1
}

fn default_page_size() -> usize {
    20
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self {
            page: 1,
            page_size: 20,
        }
    }
}

/// Response with DataForge statistics
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StatsResponse {
    /// Total number of records
    pub total_records: usize,
    /// DataForge file version
    pub version: u32,
    /// Whether this is a legacy format file
    pub is_legacy: bool,
    /// Number of struct definitions
    pub struct_count: u32,
    /// Number of property definitions
    pub property_count: u32,
    /// Number of enum definitions
    pub enum_count: u32,
    /// Important note about data size
    pub note: String,
}

/// Request for listing record paths
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ListPathsRequest {
    /// Optional keyword filter (case-insensitive substring match)
    #[serde(default)]
    pub keyword: Option<String>,
    /// Use regex pattern matching instead of substring
    #[serde(default)]
    pub use_regex: bool,
    /// Only count matching records, don't return paths
    #[serde(default)]
    pub count_only: bool,
    /// Pagination parameters
    #[serde(flatten, default)]
    pub pagination: PaginationParams,
}

/// Response for path listing
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ListPathsResponse {
    /// List of matching paths (empty if count_only is true)
    pub paths: Vec<String>,
    /// Total count of matching records
    pub total_count: usize,
    /// Current page number
    pub page: usize,
    /// Page size
    pub page_size: usize,
    /// Total number of pages
    pub total_pages: usize,
}

/// Request for getting record content
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetContentRequest {
    /// Exact path of the record to retrieve
    pub path: String,
    /// Whether to format the XML output (default: true, recommended for line indexing)
    #[serde(default = "default_format_xml")]
    pub format_xml: bool,
    /// Start line number (1-indexed, inclusive). If specified, only returns lines from this line.
    #[serde(default)]
    pub start_line: Option<usize>,
    /// End line number (1-indexed, inclusive). If specified, only returns lines up to this line.
    #[serde(default)]
    pub end_line: Option<usize>,
}

fn default_format_xml() -> bool {
    true
}

/// Response with record content
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ContentResponse {
    /// The record path
    pub path: String,
    /// XML content of the record (or selected lines if line range specified)
    pub content: String,
    /// Content size in bytes
    pub size: usize,
    /// Total number of lines in the full content
    pub total_lines: usize,
    /// Start line number of the returned content (1-indexed)
    pub start_line: usize,
    /// End line number of the returned content (1-indexed)
    pub end_line: usize,
}

/// Request for searching within specific paths
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SearchInPathsRequest {
    /// Path keyword filter (matches record paths)
    #[serde(default)]
    pub path_keyword: Option<String>,
    /// Content keyword filter (matches XML content)
    pub content_keyword: String,
    /// Use regex pattern matching
    #[serde(default)]
    pub use_regex: bool,
    /// Only count matching records
    #[serde(default)]
    pub count_only: bool,
    /// Maximum matches per record (default: 5)
    #[serde(default = "default_max_matches_per_record")]
    pub max_matches_per_record: usize,
    /// Pagination parameters
    #[serde(flatten, default)]
    pub pagination: PaginationParams,
}

fn default_max_matches_per_record() -> usize {
    5
}

/// A single match within content
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ContentMatch {
    /// Line number (1-indexed)
    pub line_number: usize,
    /// Content of the matching line (truncated if too long)
    pub line_content: String,
}

/// Search result for a single record
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SearchResult {
    /// The record path
    pub path: String,
    /// Total number of lines in this record (for reference when using get_content with line range)
    pub total_lines: usize,
    /// Matches within this record
    pub matches: Vec<ContentMatch>,
    /// Whether there are more matches than shown
    pub has_more_matches: bool,
}

/// Response for search operations
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SearchResponse {
    /// Search results (empty if count_only is true)
    pub results: Vec<SearchResult>,
    /// Total count of matching records
    pub total_count: usize,
    /// Current page number
    pub page: usize,
    /// Page size
    pub page_size: usize,
    /// Total number of pages
    pub total_pages: usize,
}

/// Request for full-text search
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FullTextSearchRequest {
    /// Search query
    pub query: String,
    /// Use regex pattern matching
    #[serde(default)]
    pub use_regex: bool,
    /// Only count matching records
    #[serde(default)]
    pub count_only: bool,
    /// Maximum matches per record (default: 5)
    #[serde(default = "default_max_matches_per_record")]
    pub max_matches_per_record: usize,
    /// Pagination parameters
    #[serde(flatten, default)]
    pub pagination: PaginationParams,
}

/// Request for getting multiple records by paths
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BatchGetContentRequest {
    /// List of exact paths to retrieve (max 10)
    pub paths: Vec<String>,
    /// Whether to format the XML output (default: true)
    #[serde(default = "default_format_xml")]
    pub format_xml: bool,
}

/// Response with multiple record contents
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BatchContentResponse {
    /// Successfully retrieved records
    pub records: Vec<ContentResponse>,
    /// Paths that were not found
    pub not_found: Vec<String>,
}

/// Request for getting suggested paths based on prefix
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SuggestPathsRequest {
    /// Path prefix to match
    pub prefix: String,
    /// Maximum number of suggestions (default: 10, max: 50)
    #[serde(default = "default_suggestion_limit")]
    pub limit: usize,
}

fn default_suggestion_limit() -> usize {
    10
}

/// Response with path suggestions
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SuggestPathsResponse {
    /// Suggested paths
    pub suggestions: Vec<String>,
    /// Whether there are more suggestions available
    pub has_more: bool,
}

/// Request for listing directories
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ListDirectoriesRequest {
    /// Directory depth (0 = top level)
    #[serde(default)]
    pub depth: Option<usize>,
    /// Parent path prefix filter
    #[serde(default)]
    pub parent: Option<String>,
}

/// Response with directory listing
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ListDirectoriesResponse {
    /// List of directories at the specified depth
    pub directories: Vec<String>,
    /// The depth that was queried
    pub depth: usize,
    /// The parent filter that was applied
    pub parent: Option<String>,
}
