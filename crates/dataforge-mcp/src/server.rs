//! MCP Server implementation for DataForge/DCB data

use std::sync::Arc;

use anyhow::{Context, Result};
use regex::Regex;
use rmcp::{
    handler::server::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::*,
    tool, tool_router,
    ErrorData as McpError, ServerHandler,
};
use tokio::sync::RwLock;
use tracing::info;
use unp4k::dataforge::DataForge;

use crate::tools::*;

/// DataForge MCP Server
///
/// Provides MCP tools for querying and searching DataForge/DCB data.
#[derive(Clone)]
pub struct DataForgeServer {
    /// The DataForge instance
    dataforge: Arc<RwLock<DataForge>>,
    /// Tool router for MCP
    tool_router: ToolRouter<Self>,
    /// Cached record paths for performance
    pub cached_paths: Arc<RwLock<Vec<String>>>,
}

#[tool_router]
impl DataForgeServer {
    /// Create a new DataForge MCP server from DCB file path
    pub fn new(dcb_path: &str) -> Result<Self> {
        let data = std::fs::read(dcb_path)
            .with_context(|| format!("Failed to read DCB file: {}", dcb_path))?;

        Self::from_bytes(&data)
    }

    /// Create a new DataForge MCP server from raw bytes
    ///
    /// This is useful when the DCB data is already loaded in memory
    /// (e.g., from a Uint8List in Dart/Flutter or extracted from a P4K archive)
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let df = DataForge::parse(data).with_context(|| "Failed to parse DataForge data")?;

        // Pre-cache all paths
        let paths: Vec<String> = df.record_paths().cloned().collect();

        Ok(Self {
            dataforge: Arc::new(RwLock::new(df)),
            tool_router: Self::tool_router(),
            cached_paths: Arc::new(RwLock::new(paths)),
        })
    }

    /// Get DataForge statistics and metadata
    #[tool(
        name = "get_stats",
        description = "Get DataForge statistics and metadata. IMPORTANT: DataForge files can contain GB-level text data (100,000+ records). Always call this first to understand data size. Use count_only=true in search operations to preview result counts before fetching data."
    )]
    async fn get_stats(&self) -> Result<CallToolResult, McpError> {
        let df = self.dataforge.read().await;

        let response = StatsResponse {
            total_records: df.record_count(),
            version: df.header.file_version as u32,
            is_legacy: df.header.is_legacy,
            struct_count: df.header.struct_definition_count as u32,
            property_count: df.header.property_definition_count as u32,
            enum_count: df.header.enum_definition_count as u32,
            note: format!(
                "This DataForge file contains {} records. Each record can be several KB of XML. \
                 Use pagination (page, page_size) and count_only=true to manage data volume. \
                 Recommended workflow: 1) get_stats, 2) list_paths with count_only, 3) list_paths with pagination, 4) get_content for specific records.",
                df.record_count()
            ),
        };

        Ok(CallToolResult::success(vec![Content::json(response)?]))
    }

    /// List record paths with optional filtering
    #[tool(
        name = "list_paths",
        description = "List record paths with optional keyword/regex filtering and pagination. Use count_only=true first to get total count before fetching data. Parameters: keyword (optional filter), use_regex (bool), count_only (bool), page (1-indexed), page_size (max 100)."
    )]
    async fn list_paths(
        &self,
        Parameters(request): Parameters<ListPathsRequest>,
    ) -> Result<CallToolResult, McpError> {
        let paths = self.cached_paths.read().await;

        let page_size = request.pagination.page_size.min(100).max(1);
        let page = request.pagination.page.max(1);

        // Filter paths
        let filtered: Vec<&String> = if let Some(keyword) = &request.keyword {
            if request.use_regex {
                let re = Regex::new(keyword).map_err(|e| {
                    McpError::invalid_params(format!("Invalid regex pattern: {}", e), None)
                })?;
                paths.iter().filter(|p| re.is_match(p)).collect()
            } else {
                let keyword_lower = keyword.to_lowercase();
                paths
                    .iter()
                    .filter(|p| p.to_lowercase().contains(&keyword_lower))
                    .collect()
            }
        } else {
            paths.iter().collect()
        };

        let total_count = filtered.len();
        let total_pages = (total_count + page_size - 1) / page_size;

        let result_paths = if request.count_only {
            Vec::new()
        } else {
            let start = (page - 1) * page_size;
            filtered
                .into_iter()
                .skip(start)
                .take(page_size)
                .cloned()
                .collect()
        };

        let response = ListPathsResponse {
            paths: result_paths,
            total_count,
            page,
            page_size,
            total_pages,
        };

        Ok(CallToolResult::success(vec![Content::json(response)?]))
    }

    /// Get content of a specific record by path
    #[tool(
        name = "get_content",
        description = "Get the XML content of a specific record by its exact path. Supports line range extraction with start_line and end_line parameters (1-indexed). XML is always formatted for consistent line indexing. Use list_paths or suggest_paths first to find valid paths."
    )]
    async fn get_content(
        &self,
        Parameters(request): Parameters<GetContentRequest>,
    ) -> Result<CallToolResult, McpError> {
        let df = self.dataforge.read().await;

        // Always format XML for consistent line indexing
        let xml = df
            .record_to_xml(&request.path, true)
            .map_err(|e| {
                McpError::invalid_params(
                    format!("Failed to get record '{}': {}", request.path, e),
                    None,
                )
            })?;

        let lines: Vec<&str> = xml.lines().collect();
        let total_lines = lines.len();

        // Handle line range extraction
        let start_line = request.start_line.unwrap_or(1).max(1);
        let end_line = request.end_line.unwrap_or(total_lines).min(total_lines);

        // Validate range
        if start_line > end_line {
            return Err(McpError::invalid_params(
                format!("start_line ({}) cannot be greater than end_line ({})", start_line, end_line),
                None,
            ));
        }

        if start_line > total_lines {
            return Err(McpError::invalid_params(
                format!("start_line ({}) exceeds total lines ({})", start_line, total_lines),
                None,
            ));
        }

        // Extract the requested line range (convert to 0-indexed)
        let selected_lines: Vec<&str> = lines[(start_line - 1)..end_line].to_vec();
        let content = selected_lines.join("\n");

        let response = ContentResponse {
            path: request.path,
            size: content.len(),
            content,
            total_lines,
            start_line,
            end_line,
        };

        Ok(CallToolResult::success(vec![Content::json(response)?]))
    }

    /// Batch get content for multiple records
    #[tool(
        name = "batch_get_content",
        description = "Get XML content for multiple records at once (max 10 paths). XML is always formatted for consistent line indexing. Returns successfully retrieved records with line count info and list of not found paths."
    )]
    async fn batch_get_content(
        &self,
        Parameters(request): Parameters<BatchGetContentRequest>,
    ) -> Result<CallToolResult, McpError> {
        if request.paths.len() > 10 {
            return Err(McpError::invalid_params(
                "Maximum 10 paths allowed per batch request",
                None,
            ));
        }

        let df = self.dataforge.read().await;

        let mut records = Vec::new();
        let mut not_found = Vec::new();

        for path in request.paths {
            // Always format XML for consistent line indexing
            match df.record_to_xml(&path, true) {
                Ok(xml) => {
                    let total_lines = xml.lines().count();
                    records.push(ContentResponse {
                        path,
                        size: xml.len(),
                        content: xml,
                        total_lines,
                        start_line: 1,
                        end_line: total_lines,
                    });
                }
                Err(_) => {
                    not_found.push(path);
                }
            }
        }

        let response = BatchContentResponse { records, not_found };

        Ok(CallToolResult::success(vec![Content::json(response)?]))
    }

    /// Search within paths matching a keyword
    #[tool(
        name = "search_in_paths",
        description = "Search for content within records whose paths match a keyword. Two-level filtering: first by path keyword, then by content keyword. Returns line numbers (1-indexed) and total_lines for each match. Use get_content with start_line/end_line to fetch context around matches."
    )]
    async fn search_in_paths(
        &self,
        Parameters(request): Parameters<SearchInPathsRequest>,
    ) -> Result<CallToolResult, McpError> {
        let df = self.dataforge.read().await;
        let paths = self.cached_paths.read().await;

        let page_size = request.pagination.page_size.min(100).max(1);
        let page = request.pagination.page.max(1);
        let max_matches = request.max_matches_per_record.min(20).max(1);

        // Compile regex if needed
        let content_regex = if request.use_regex {
            Some(Regex::new(&request.content_keyword).map_err(|e| {
                McpError::invalid_params(format!("Invalid content regex: {}", e), None)
            })?)
        } else {
            None
        };

        let path_regex = if request.use_regex {
            request
                .path_keyword
                .as_ref()
                .map(|k| {
                    Regex::new(k).map_err(|e| {
                        McpError::invalid_params(format!("Invalid path regex: {}", e), None)
                    })
                })
                .transpose()?
        } else {
            None
        };

        // Filter paths first
        let filtered_paths: Vec<&String> = if let Some(path_kw) = &request.path_keyword {
            if let Some(ref re) = path_regex {
                paths.iter().filter(|p| re.is_match(p)).collect()
            } else {
                let kw_lower = path_kw.to_lowercase();
                paths
                    .iter()
                    .filter(|p| p.to_lowercase().contains(&kw_lower))
                    .collect()
            }
        } else {
            paths.iter().collect()
        };

        // Search content
        let content_kw_lower = request.content_keyword.to_lowercase();
        let mut all_results: Vec<SearchResult> = Vec::new();

        for path in filtered_paths {
            if let Some(idx) = df.path_to_record().get(path) {
                if let Ok(xml) = df.record_to_xml_by_index(*idx, true) {
                    let lines_vec: Vec<&str> = xml.lines().collect();
                    let total_lines = lines_vec.len();
                    let mut matches = Vec::new();

                    for (line_num, line) in lines_vec.iter().enumerate() {
                        let is_match = if let Some(ref re) = content_regex {
                            re.is_match(line)
                        } else {
                            line.to_lowercase().contains(&content_kw_lower)
                        };

                        if is_match {
                            let line_content = if line.len() > 200 {
                                format!("{}...", &line[..200])
                            } else {
                                line.to_string()
                            };
                            matches.push(ContentMatch {
                                line_number: line_num + 1,
                                line_content,
                            });

                            if matches.len() >= max_matches + 1 {
                                break;
                            }
                        }
                    }

                    if !matches.is_empty() {
                        let has_more = matches.len() > max_matches;
                        if has_more {
                            matches.pop();
                        }
                        all_results.push(SearchResult {
                            path: path.clone(),
                            total_lines,
                            matches,
                            has_more_matches: has_more,
                        });
                    }
                }
            }
        }

        let total_count = all_results.len();
        let total_pages = (total_count + page_size - 1) / page_size;

        let results = if request.count_only {
            Vec::new()
        } else {
            let start = (page - 1) * page_size;
            all_results.into_iter().skip(start).take(page_size).collect()
        };

        let response = SearchResponse {
            results,
            total_count,
            page,
            page_size,
            total_pages,
        };

        Ok(CallToolResult::success(vec![Content::json(response)?]))
    }

    /// Full-text search across all records
    #[tool(
        name = "full_text_search",
        description = "Search for a query string across all record paths and XML content. Returns line numbers (1-indexed) and total_lines for each match. Use get_content with start_line/end_line to fetch context around matches. Supports regex patterns and count_only for previewing result count."
    )]
    async fn full_text_search(
        &self,
        Parameters(request): Parameters<FullTextSearchRequest>,
    ) -> Result<CallToolResult, McpError> {
        let df = self.dataforge.read().await;
        let paths = self.cached_paths.read().await;

        let page_size = request.pagination.page_size.min(100).max(1);
        let page = request.pagination.page.max(1);
        let max_matches = request.max_matches_per_record.min(20).max(1);

        let regex = if request.use_regex {
            Some(Regex::new(&request.query).map_err(|e| {
                McpError::invalid_params(format!("Invalid regex pattern: {}", e), None)
            })?)
        } else {
            None
        };

        let query_lower = request.query.to_lowercase();
        let mut all_results: Vec<SearchResult> = Vec::new();

        for path in paths.iter() {
            let path_matches = if let Some(ref re) = regex {
                re.is_match(path)
            } else {
                path.to_lowercase().contains(&query_lower)
            };

            if let Some(idx) = df.path_to_record().get(path) {
                if let Ok(xml) = df.record_to_xml_by_index(*idx, true) {
                    let lines_vec: Vec<&str> = xml.lines().collect();
                    let total_lines = lines_vec.len();
                    let mut matches = Vec::new();

                    for (line_num, line) in lines_vec.iter().enumerate() {
                        let is_match = if let Some(ref re) = regex {
                            re.is_match(line)
                        } else {
                            line.to_lowercase().contains(&query_lower)
                        };

                        if is_match {
                            let line_content = if line.len() > 200 {
                                format!("{}...", &line[..200])
                            } else {
                                line.to_string()
                            };
                            matches.push(ContentMatch {
                                line_number: line_num + 1,
                                line_content,
                            });

                            if matches.len() >= max_matches + 1 {
                                break;
                            }
                        }
                    }

                    if path_matches || !matches.is_empty() {
                        let has_more = matches.len() > max_matches;
                        if has_more {
                            matches.pop();
                        }
                        all_results.push(SearchResult {
                            path: path.clone(),
                            total_lines,
                            matches,
                            has_more_matches: has_more,
                        });
                    }
                }
            }
        }

        let total_count = all_results.len();
        let total_pages = (total_count + page_size - 1) / page_size;

        let results = if request.count_only {
            Vec::new()
        } else {
            let start = (page - 1) * page_size;
            all_results.into_iter().skip(start).take(page_size).collect()
        };

        let response = SearchResponse {
            results,
            total_count,
            page,
            page_size,
            total_pages,
        };

        Ok(CallToolResult::success(vec![Content::json(response)?]))
    }

    /// Get path suggestions based on a prefix
    #[tool(
        name = "suggest_paths",
        description = "Get path suggestions based on a prefix. Useful for path auto-completion. Returns up to 50 matching paths."
    )]
    async fn suggest_paths(
        &self,
        Parameters(request): Parameters<SuggestPathsRequest>,
    ) -> Result<CallToolResult, McpError> {
        let paths = self.cached_paths.read().await;

        let limit = request.limit.min(50).max(1);
        let prefix_lower = request.prefix.to_lowercase();

        let mut suggestions: Vec<String> = paths
            .iter()
            .filter(|p| p.to_lowercase().starts_with(&prefix_lower))
            .take(limit + 1)
            .cloned()
            .collect();

        let has_more = suggestions.len() > limit;
        if has_more {
            suggestions.pop();
        }

        let response = SuggestPathsResponse {
            suggestions,
            has_more,
        };

        Ok(CallToolResult::success(vec![Content::json(response)?]))
    }

    /// Get unique path prefixes (directories)
    #[tool(
        name = "list_directories",
        description = "List unique directory prefixes at a given depth. Useful for exploring the record hierarchy. Depth 0 shows top-level directories."
    )]
    async fn list_directories(
        &self,
        Parameters(request): Parameters<ListDirectoriesRequest>,
    ) -> Result<CallToolResult, McpError> {
        let paths = self.cached_paths.read().await;
        let depth = request.depth.unwrap_or(0);

        let mut dirs: std::collections::HashSet<String> = std::collections::HashSet::new();

        for path in paths.iter() {
            // Filter by parent if specified
            if let Some(ref p) = request.parent {
                if !path.starts_with(p) {
                    continue;
                }
            }

            let parts: Vec<&str> = path.split('/').collect();
            if parts.len() > depth {
                let dir = parts[..=depth].join("/");
                dirs.insert(dir);
            }
        }

        let mut directories: Vec<String> = dirs.into_iter().collect();
        directories.sort();

        let response = ListDirectoriesResponse {
            directories,
            depth,
            parent: request.parent,
        };

        Ok(CallToolResult::success(vec![Content::json(response)?]))
    }
}

impl ServerHandler for DataForgeServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "Star Citizen DataForge/DCB MCP Server. \
                \n\nIMPORTANT: DataForge files contain GB-level data (100,000+ records). \
                \n\nRecommended workflow: \
                \n1. Call get_stats first to understand data size \
                \n2. Use list_paths with count_only=true to preview filter results \
                \n3. Use pagination (page, page_size) for large result sets \
                \n4. Use list_directories to explore the record hierarchy \
                \n5. Use suggest_paths for path auto-completion \
                \n6. Use get_content or batch_get_content for specific records \
                \n7. Use search_in_paths for two-level filtering (path + content) \
                \n8. Use full_text_search for broad searches \
                \n\nAll search operations support: \
                \n- count_only: preview result count without fetching data \
                \n- use_regex: enable regex pattern matching \
                \n- pagination: page (1-indexed) and page_size (max 100)"
                    .into(),
            ),
        }
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, McpError>> + Send + '_ {
        let tools = self.tool_router.list_all();
        std::future::ready(Ok(ListToolsResult {
            tools,
            next_cursor: None,
            meta: None,
        }))
    }

    fn call_tool(
        &self,
        request: CallToolRequestParam,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResult, McpError>> + Send + '_ {
        use rmcp::handler::server::tool::ToolCallContext;
        let tool_context = ToolCallContext::new(self, request, context);
        async move { self.tool_router.call(tool_context).await }
    }
}

/// Start the MCP server with Streamable HTTP transport
///
/// # Arguments
/// * `dcb_path` - Path to the DCB file
/// * `port` - HTTP port to listen on
pub async fn start_mcp_server(dcb_path: &str, port: u16) -> Result<()> {
    use hyper::server::conn::http1;
    use hyper_util::rt::{TokioIo, TokioTimer};
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    };
    use std::net::SocketAddr;
    use tokio::net::TcpListener;


    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("Loading DataForge file: {}", dcb_path);
    let server = DataForgeServer::new(dcb_path)?;
    let record_count = server.cached_paths.read().await.len();
    info!("Loaded {} records", record_count);

    // Bind to 0.0.0.0 to support remote connections and avoid localhost resolution issues
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Starting MCP server on http://{}/mcp", addr);

    let listener = TcpListener::bind(addr).await?;

    let config = StreamableHttpServerConfig::default();
    let session_manager = Arc::new(LocalSessionManager::default());

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        let server_clone = server.clone();
        let session_manager_clone = session_manager.clone();
        let config_clone = config.clone();

        tokio::spawn(async move {
            let service = StreamableHttpService::new(
                move || Ok(server_clone.clone()),
                session_manager_clone,
                config_clone,
            );

            // Use TowerToHyperService adapter
            let hyper_service = hyper_util::service::TowerToHyperService::new(service);

            // Use http1 builder (more stable for SSE than auto/h2)
            if let Err(err) = http1::Builder::new()
                .timer(TokioTimer::new())
                .keep_alive(true)
                .serve_connection(io, hyper_service)
                .await 
            {
                let err_debug = format!("{:?}", err);
                tracing::error!("Error serving connection: {:?}", err_debug);
            }
        });
    }
}

/// Start the MCP server with raw bytes data
///
/// This is useful when the DCB data is already loaded in memory
/// (e.g., from a Uint8List in Dart/Flutter or extracted from a P4K archive)
///
/// # Arguments
/// * `data` - Raw DCB file bytes
/// * `port` - HTTP port to listen on
/// * `init_tracing` - Whether to initialize tracing (set to false if already initialized)
pub async fn start_mcp_server_with_bytes(data: &[u8], port: u16, init_tracing: bool) -> Result<()> {
    use hyper::server::conn::http1;
    use hyper_util::rt::{TokioIo, TokioTimer};
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    };
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    // Initialize tracing if requested
    if init_tracing {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .init();
    }

    info!("Parsing DataForge data ({} bytes)", data.len());
    let server = DataForgeServer::from_bytes(data)?;
    let record_count = server.cached_paths.read().await.len();
    info!("Loaded {} records", record_count);

    // Bind to 0.0.0.0 to support remote connections and avoid localhost resolution issues
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Starting MCP server on http://{}/mcp", addr);

    let listener = TcpListener::bind(addr).await?;

    let config = StreamableHttpServerConfig::default();
    let session_manager = Arc::new(LocalSessionManager::default());

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        let server_clone = server.clone();
        let session_manager_clone = session_manager.clone();
        let config_clone = config.clone();

        tokio::spawn(async move {
            let service = StreamableHttpService::new(
                move || Ok(server_clone.clone()),
                session_manager_clone,
                config_clone,
            );

            // Use TowerToHyperService adapter
            let hyper_service = hyper_util::service::TowerToHyperService::new(service);

            // Use http1 builder (more stable for SSE than auto/h2)
            if let Err(err) = http1::Builder::new()
                .timer(TokioTimer::new())
                .keep_alive(true)
                .serve_connection(io, hyper_service)
                .await 
            {
                // Ignore IncompleteMessage and HeaderTimeout errors which are common in SSE/Keep-Alive
                let err_debug = format!("{:?}", err);
                if !err_debug.contains("IncompleteMessage") && !err_debug.contains("HeaderTimeout") {
                    tracing::error!("Error serving connection: {:?}", err);
                }
            }
        });
    }
}
