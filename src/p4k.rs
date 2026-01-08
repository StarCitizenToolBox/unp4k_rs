//! P4K file format handling
//!
//! P4K files are ZIP archives with custom encryption and compression support.
//! This module provides reading and extraction capabilities.
//!
//! ## P4K Format Details (from unp4k issue #49)
//!
//! - Compression methods: Store (0), Deflate (8), ZStd (100)
//! - Encryption: AES-128-CBC with CryEngine public key
//! - Local header signature for encrypted entries: `PK\x03\x14` (vs `PK\x03\x04` for normal)
//! - ExtraData field 168 indicates encrypted content

use crate::crypto::{decrypt_aes_cbc, is_zstd_stream};
use crate::error::{Error, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom};
use std::path::Path;

/// Standard local file header signature: PK\x03\x04
const LOCAL_HEADER_SIGNATURE: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];

/// Encrypted local file header signature: PK\x03\x14 (used by CryEngine/Star Citizen)
const ENCRYPTED_HEADER_SIGNATURE: [u8; 4] = [0x50, 0x4B, 0x03, 0x14];

/// Central directory header signature: PK\x01\x02
const CENTRAL_HEADER_SIGNATURE: [u8; 4] = [0x50, 0x4B, 0x01, 0x02];

/// Compression methods used in P4K files
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionMethod {
    /// No compression (stored as-is)
    Store,
    /// Standard DEFLATE compression
    Deflate,
    /// ZStandard compression (custom to Star Citizen)
    Zstd,
    /// Unknown/unsupported method
    Unknown(u16),
}

impl From<u16> for CompressionMethod {
    fn from(value: u16) -> Self {
        match value {
            0 => CompressionMethod::Store,
            8 => CompressionMethod::Deflate,
            100 => CompressionMethod::Zstd,
            other => CompressionMethod::Unknown(other),
        }
    }
}

/// Represents a single entry in a P4K archive
#[derive(Debug, Clone)]
pub struct P4kEntry {
    /// File name/path within the archive
    pub name: String,
    /// Compressed size in bytes
    pub compressed_size: u64,
    /// Uncompressed size in bytes
    pub uncompressed_size: u64,
    /// Compression method used
    pub compression_method: CompressionMethod,
    /// Whether the entry is encrypted
    pub is_encrypted: bool,
    /// CRC32 checksum
    pub crc32: u32,
    /// Offset to local file header in the archive
    pub header_offset: u64,
    /// Offset to file data in the archive
    pub data_offset: u64,
    /// Original extra data from central directory (for incremental writes)
    pub extra_data: Vec<u8>,
    /// General purpose bit flags
    pub flags: u16,
    /// Version made by
    pub version_made: u16,
    /// Version needed to extract
    pub version_needed: u16,
    /// Modification time (DOS format)
    pub mod_time: u16,
    /// Modification date (DOS format)
    pub mod_date: u16,
    /// External file attributes
    pub external_attrs: u32,
    /// SHA256 hash of uncompressed content (32 bytes, extracted from extra field offset 16)
    /// Used by Star Citizen launcher for validation
    pub content_hash: Option<[u8; 32]>,
    /// Validation QWORD from extra field offset 12-20 (used in 12-byte table)
    pub validation_qword: Option<u64>,
    /// Source of this entry data
    pub source: EntrySource,
}

/// Options for opening a P4K file
#[derive(Debug, Clone)]
pub struct P4kOpenOptions {
    /// Whether to automatically extract .socpak files as directories
    pub sopack_to_dir: bool,
}

impl Default for P4kOpenOptions {
    fn default() -> Self {
        Self {
            sopack_to_dir: false,
        }
    }
}

/// Source of entry data
#[derive(Debug, Clone)]
pub enum EntrySource {
    /// Regular P4K entry
    P4k,
    /// Virtual entry from extracted sopack (stores parent sopack name and path within sopack)
    Sopack {
        /// Name of the parent .socpak file
        parent_sopack: String,
        /// Path within the sopack archive
        inner_path: String,
    },
}

/// A P4K archive reader
pub struct P4kFile {
    reader: BufReader<File>,
    entries: HashMap<String, P4kEntry>,
    entry_list: Vec<String>,
    /// Offset to the central directory
    cd_offset: u64,
    /// Original EOCD comment (for Star Citizen validation)
    eocd_comment: Vec<u8>,
    /// Options for P4K file operations
    options: P4kOpenOptions,
    /// Cache for small extracted sopack contents (path -> data)
    /// Only files smaller than SOPACK_CACHE_SIZE_LIMIT are cached
    sopack_cache: HashMap<String, Vec<u8>>,
}

/// Maximum size (in bytes) for caching sopack file contents (10MB)
const SOPACK_CACHE_SIZE_LIMIT: usize = 10 * 1024 * 1024;

impl P4kFile {
    /// Open a P4K file for reading
    ///
    /// # Arguments
    /// * `path` - Path to the P4K file
    ///
    /// # Example
    /// ```no_run
    /// use unp4k::P4kFile;
    /// let p4k = P4kFile::open("Data.p4k")?;
    /// # Ok::<(), unp4k::Error>(())
    /// ```
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::open_with_options(path, P4kOpenOptions::default())
    }

    /// Open a P4K file for reading with custom options
    ///
    /// # Arguments
    /// * `path` - Path to the P4K file
    /// * `options` - Opening options
    ///
    /// # Example
    /// ```no_run
    /// use unp4k::{P4kFile, P4kOpenOptions};
    /// let options = P4kOpenOptions { sopack_to_dir: true };
    /// let p4k = P4kFile::open_with_options("Data.p4k", options)?;
    /// # Ok::<(), unp4k::Error>(())
    /// ```
    pub fn open_with_options<P: AsRef<Path>>(path: P, options: P4kOpenOptions) -> Result<Self> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);

        // Read central directory
        let (entries, entry_list, cd_offset, eocd_comment) =
            Self::read_central_directory(&mut reader)?;

        let mut p4k = P4kFile {
            reader,
            entries,
            entry_list,
            cd_offset,
            eocd_comment,
            options: options.clone(),
            sopack_cache: HashMap::new(),
        };

        // Process sopack files if sopack_to_dir is enabled
        if options.sopack_to_dir {
            p4k.process_sopack_files()?;
        }

        Ok(p4k)
    }

    /// Get an iterator over all entry names
    pub fn entry_names(&self) -> impl Iterator<Item = &str> {
        self.entry_list.iter().map(|s| s.as_str())
    }

    /// Get all entries as a slice (unordered)
    pub fn entries(&self) -> Vec<&P4kEntry> {
        self.entries.values().collect()
    }

    /// Get all entries in their original order (as they appear in the central directory)
    /// This is important for P4K validation tables which depend on entry order
    pub fn entries_ordered(&self) -> Vec<&P4kEntry> {
        self.entry_list
            .iter()
            .filter_map(|name| self.entries.get(name))
            .collect()
    }

    /// Get the number of entries in the archive
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the archive is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get the offset to the central directory
    pub fn central_directory_offset(&self) -> u64 {
        self.cd_offset
    }

    /// Get the EOCD comment (contains Star Citizen "CIG" validation data)
    pub fn eocd_comment(&self) -> &[u8] {
        &self.eocd_comment
    }

    /// Get a specific entry by name
    pub fn get_entry(&self, name: &str) -> Option<&P4kEntry> {
        self.entries.get(name)
    }

    /// Get the open options
    pub fn options(&self) -> &P4kOpenOptions {
        &self.options
    }

    /// Extract a file by name and return its contents
    ///
    /// # Arguments
    /// * `name` - The file path within the archive
    ///
    /// # Returns
    /// The decompressed and decrypted file contents
    pub fn extract(&mut self, name: &str) -> Result<Vec<u8>> {
        let entry = self
            .entries
            .get(name)
            .ok_or_else(|| Error::EntryNotFound(name.to_string()))?
            .clone();

        self.extract_entry(&entry)
    }

    /// Extract an entry and return its contents
    pub fn extract_entry(&mut self, entry: &P4kEntry) -> Result<Vec<u8>> {
        // Handle virtual sopack entries (lazy load)
        match &entry.source {
            EntrySource::Sopack {
                parent_sopack,
                inner_path,
            } => {
                // Check cache first (for files < 10MB)
                let cache_key = format!("{}/{}", parent_sopack, inner_path);
                if let Some(cached_data) = self.sopack_cache.get(&cache_key) {
                    return Ok(cached_data.clone());
                }

                // Not in cache, need to extract from parent sopack
                // Get the parent sopack data
                let parent_entry = self
                    .entries
                    .get(parent_sopack)
                    .ok_or_else(|| Error::EntryNotFound(parent_sopack.clone()))?
                    .clone();

                // Extract parent sopack as P4K entry
                let sopack_data = if matches!(parent_entry.source, EntrySource::P4k) {
                    // Read from P4K file
                    let data_offset = self.read_local_header_offset(&parent_entry)?;
                    self.reader.seek(SeekFrom::Start(data_offset))?;
                    let mut compressed_data = vec![0u8; parent_entry.compressed_size as usize];
                    self.reader.read_exact(&mut compressed_data)?;

                    let decrypted_data = if parent_entry.is_encrypted {
                        decrypt_aes_cbc(&compressed_data)?
                    } else {
                        compressed_data
                    };

                    self.decompress(&decrypted_data, &parent_entry)?
                } else {
                    return Err(Error::InvalidP4k("Nested sopack not supported".to_string()));
                };

                // Extract single file from sopack
                let file_data =
                    crate::sopack::extract_single_from_memory(&sopack_data, inner_path)?;

                // Cache if smaller than limit
                if file_data.len() < SOPACK_CACHE_SIZE_LIMIT {
                    self.sopack_cache.insert(cache_key, file_data.clone());
                }

                return Ok(file_data);
            }
            EntrySource::P4k => {
                // Regular P4K entry extraction
            }
        }

        // Read the local file header to get the actual data offset
        // (local header's extra field length may differ from central directory's)
        let data_offset = self.read_local_header_offset(entry)?;

        // Seek to data offset
        self.reader.seek(SeekFrom::Start(data_offset))?;

        // Read compressed data
        let mut compressed_data = vec![0u8; entry.compressed_size as usize];
        self.reader.read_exact(&mut compressed_data)?;

        // Decrypt if necessary
        let decrypted_data = if entry.is_encrypted {
            decrypt_aes_cbc(&compressed_data)?
        } else {
            compressed_data
        };

        // Decompress
        let decompressed = self.decompress(&decrypted_data, entry)?;

        Ok(decompressed)
    }

    /// Extract and verify an entry's content hash
    ///
    /// This validates the extracted content against the SHA256 hash stored
    /// in the entry's extra field (used by Star Citizen launcher for validation).
    ///
    /// # Arguments
    /// * `entry` - The entry to extract and verify
    ///
    /// # Returns
    /// * `Ok((data, true))` - Data extracted and hash matches
    /// * `Ok((data, false))` - Data extracted but hash doesn't match or no hash stored
    /// * `Err(...)` - Extraction failed
    pub fn extract_and_verify(&mut self, entry: &P4kEntry) -> Result<(Vec<u8>, bool)> {
        let data = self.extract_entry(entry)?;

        if let Some(expected_hash) = &entry.content_hash {
            let verified = crate::crypto::verify_sha256(&data, expected_hash);
            Ok((data, verified))
        } else {
            // No hash stored, can't verify
            Ok((data, false))
        }
    }

    /// Verify an entry's content hash without extracting
    ///
    /// # Returns
    /// * `Ok(true)` - Hash matches
    /// * `Ok(false)` - Hash doesn't match or no hash stored
    pub fn verify_entry(&mut self, entry: &P4kEntry) -> Result<bool> {
        let (_, verified) = self.extract_and_verify(entry)?;
        Ok(verified)
    }

    /// Process .socpak files and create virtual directory entries (lazy load)
    fn process_sopack_files(&mut self) -> Result<()> {
        // Find all .socpak entries
        let sopack_entries: Vec<_> = self
            .entries
            .values()
            .filter(|e| crate::sopack::is_sopack(&e.name))
            .cloned()
            .collect();

        for sopack_entry in sopack_entries {
            // Extract the sopack file data (only once at open time)
            let sopack_data = self.extract_entry(&sopack_entry)?;

            // List entries without extracting (lazy load)
            let sopack_file_list = crate::sopack::list_sopack_entries_from_memory(&sopack_data)?;

            // Create virtual directory entry (xxx.socpak -> xxx.unsocpak/)
            let base_name = sopack_entry
                .name
                .strip_suffix(".socpak")
                .unwrap_or(&sopack_entry.name);
            let virtual_dir_name = format!("{}.unsocpak", base_name);

            // Create virtual entries for each file in the sopack
            for file_info in sopack_file_list {
                let virtual_path = format!("{}/{}", virtual_dir_name, file_info.name);

                let virtual_entry = P4kEntry {
                    name: virtual_path.clone(),
                    compressed_size: file_info.size,
                    uncompressed_size: file_info.size,
                    compression_method: CompressionMethod::Store,
                    is_encrypted: false,
                    crc32: 0,
                    header_offset: 0,
                    data_offset: 0,
                    extra_data: Vec::new(),
                    flags: 0,
                    version_made: 0,
                    version_needed: 0,
                    mod_time: 0,
                    mod_date: 0,
                    external_attrs: 0,
                    content_hash: None,
                    validation_qword: None,
                    source: EntrySource::Sopack {
                        parent_sopack: sopack_entry.name.clone(),
                        inner_path: file_info.name,
                    },
                };

                self.entries.insert(virtual_path.clone(), virtual_entry);
                self.entry_list.push(virtual_path);
            }
        }

        Ok(())
    }

    /// Decompress data based on the compression method
    fn decompress(&self, data: &[u8], entry: &P4kEntry) -> Result<Vec<u8>> {
        match entry.compression_method {
            CompressionMethod::Store => Ok(data.to_vec()),

            CompressionMethod::Deflate => {
                use flate2::read::DeflateDecoder;
                let mut decoder = DeflateDecoder::new(data);
                let mut decompressed = Vec::with_capacity(entry.uncompressed_size as usize);
                decoder
                    .read_to_end(&mut decompressed)
                    .map_err(|e| Error::Decompression(format!("Deflate error: {}", e)))?;
                Ok(decompressed)
            }

            CompressionMethod::Zstd => {
                // Check if it's actually ZSTD or encrypted ZSTD
                if is_zstd_stream(data) {
                    let mut decoder = zstd::stream::Decoder::new(data)
                        .map_err(|e| Error::Decompression(format!("ZSTD init error: {}", e)))?;
                    let mut decompressed = Vec::with_capacity(entry.uncompressed_size as usize);
                    decoder
                        .read_to_end(&mut decompressed)
                        .map_err(|e| Error::Decompression(format!("ZSTD error: {}", e)))?;
                    Ok(decompressed)
                } else {
                    // Try AES decryption first, then ZSTD
                    let decrypted = decrypt_aes_cbc(data)?;
                    if is_zstd_stream(&decrypted) {
                        let mut decoder = zstd::stream::Decoder::new(decrypted.as_slice())
                            .map_err(|e| Error::Decompression(format!("ZSTD init error: {}", e)))?;
                        let mut decompressed = Vec::with_capacity(entry.uncompressed_size as usize);
                        decoder
                            .read_to_end(&mut decompressed)
                            .map_err(|e| Error::Decompression(format!("ZSTD error: {}", e)))?;
                        Ok(decompressed)
                    } else {
                        // Not ZSTD, return as-is or as decrypted
                        Ok(decrypted)
                    }
                }
            }

            CompressionMethod::Unknown(method) => Err(Error::UnsupportedCompression(method)),
        }
    }

    /// Read the central directory to build the entry index
    /// Returns (entries, entry_order, cd_offset, eocd_comment)
    fn read_central_directory(
        reader: &mut BufReader<File>,
    ) -> Result<(HashMap<String, P4kEntry>, Vec<String>, u64, Vec<u8>)> {
        // Find End of Central Directory record
        let file_len = reader.seek(SeekFrom::End(0))?;

        // EOCD is at least 22 bytes, search backwards for signature
        let search_start = file_len.saturating_sub(65557);

        reader.seek(SeekFrom::Start(search_start))?;
        let mut buffer = vec![0u8; (file_len - search_start) as usize];
        reader.read_exact(&mut buffer)?;

        // Search for EOCD signature (0x06054b50)
        let eocd_offset = buffer
            .windows(4)
            .rposition(|w| w == [0x50, 0x4B, 0x05, 0x06])
            .ok_or_else(|| Error::InvalidP4k("Cannot find End of Central Directory".to_string()))?;

        let eocd_pos = search_start + eocd_offset as u64;

        // Check for ZIP64 EOCD locator
        let (cd_offset, cd_size, total_entries) = if eocd_pos >= 20 {
            reader.seek(SeekFrom::Start(eocd_pos - 20))?;
            let mut locator_sig = [0u8; 4];
            reader.read_exact(&mut locator_sig)?;

            if locator_sig == [0x50, 0x4B, 0x06, 0x07] {
                // ZIP64 EOCD locator found
                let _disk_number = reader.read_u32::<LittleEndian>()?;
                let zip64_eocd_offset = reader.read_u64::<LittleEndian>()?;

                // Read ZIP64 EOCD
                reader.seek(SeekFrom::Start(zip64_eocd_offset))?;
                let mut sig = [0u8; 4];
                reader.read_exact(&mut sig)?;

                if sig != [0x50, 0x4B, 0x06, 0x06] {
                    return Err(Error::InvalidP4k(
                        "Invalid ZIP64 EOCD signature".to_string(),
                    ));
                }

                let _eocd_size = reader.read_u64::<LittleEndian>()?;
                let _version_made = reader.read_u16::<LittleEndian>()?;
                let _version_needed = reader.read_u16::<LittleEndian>()?;
                let _disk_number = reader.read_u32::<LittleEndian>()?;
                let _disk_cd = reader.read_u32::<LittleEndian>()?;
                let _entries_on_disk = reader.read_u64::<LittleEndian>()?;
                let total_entries = reader.read_u64::<LittleEndian>()?;
                let cd_size = reader.read_u64::<LittleEndian>()?;
                let cd_offset = reader.read_u64::<LittleEndian>()?;

                (cd_offset, cd_size, total_entries)
            } else {
                // Standard EOCD
                Self::read_standard_eocd(reader, eocd_pos)?
            }
        } else {
            // Standard EOCD
            Self::read_standard_eocd(reader, eocd_pos)?
        };

        // Read central directory entries
        let mut entries = HashMap::with_capacity(total_entries as usize);
        let mut entry_order = Vec::with_capacity(total_entries as usize);
        reader.seek(SeekFrom::Start(cd_offset))?;

        let mut pos = 0u64;
        while pos < cd_size {
            let entry = Self::read_central_directory_entry(reader)?;
            if let Some(entry) = entry {
                entry_order.push(entry.name.clone());
                entries.insert(entry.name.clone(), entry);
            }
            pos = reader.stream_position()? - cd_offset;
        }

        // Read EOCD comment
        // EOCD structure: signature(4) + disk_num(2) + disk_cd(2) + entries_on_disk(2) +
        //                 total_entries(2) + cd_size(4) + cd_offset(4) + comment_len(2) + comment
        reader.seek(SeekFrom::Start(eocd_pos + 20))?;
        let comment_len = reader.read_u16::<LittleEndian>()?;
        let mut eocd_comment = vec![0u8; comment_len as usize];
        if comment_len > 0 {
            reader.read_exact(&mut eocd_comment)?;
        }

        Ok((entries, entry_order, cd_offset, eocd_comment))
    }

    fn read_standard_eocd(reader: &mut BufReader<File>, eocd_pos: u64) -> Result<(u64, u64, u64)> {
        reader.seek(SeekFrom::Start(eocd_pos + 4))?;

        let _disk_number = reader.read_u16::<LittleEndian>()?;
        let _disk_cd = reader.read_u16::<LittleEndian>()?;
        let _entries_on_disk = reader.read_u16::<LittleEndian>()?;
        let total_entries = reader.read_u16::<LittleEndian>()? as u64;
        let cd_size = reader.read_u32::<LittleEndian>()? as u64;
        let cd_offset = reader.read_u32::<LittleEndian>()? as u64;

        Ok((cd_offset, cd_size, total_entries))
    }

    fn read_central_directory_entry(reader: &mut BufReader<File>) -> Result<Option<P4kEntry>> {
        // Read signature
        let mut sig = [0u8; 4];
        if reader.read_exact(&mut sig).is_err() {
            return Ok(None);
        }

        if sig != CENTRAL_HEADER_SIGNATURE {
            return Ok(None);
        }

        let version_made = reader.read_u16::<LittleEndian>()?;
        let version_needed = reader.read_u16::<LittleEndian>()?;
        let flags = reader.read_u16::<LittleEndian>()?;
        let compression = reader.read_u16::<LittleEndian>()?;
        let mod_time = reader.read_u16::<LittleEndian>()?;
        let mod_date = reader.read_u16::<LittleEndian>()?;
        let crc32 = reader.read_u32::<LittleEndian>()?;
        let mut compressed_size = reader.read_u32::<LittleEndian>()? as u64;
        let mut uncompressed_size = reader.read_u32::<LittleEndian>()? as u64;
        let name_len = reader.read_u16::<LittleEndian>()?;
        let extra_len = reader.read_u16::<LittleEndian>()?;
        let comment_len = reader.read_u16::<LittleEndian>()?;
        let _disk_start = reader.read_u16::<LittleEndian>()?;
        let _internal_attrs = reader.read_u16::<LittleEndian>()?;
        let external_attrs = reader.read_u32::<LittleEndian>()?;
        let mut header_offset = reader.read_u32::<LittleEndian>()? as u64;

        // Read name
        let mut name_bytes = vec![0u8; name_len as usize];
        reader.read_exact(&mut name_bytes)?;
        let name = String::from_utf8_lossy(&name_bytes).to_string();

        // Read extra field
        let mut extra = vec![0u8; extra_len as usize];
        reader.read_exact(&mut extra)?;

        // Parse extra field for ZIP64 info
        let mut extra_cursor = Cursor::new(&extra);
        while extra_cursor.position() < extra.len() as u64 {
            let header_id = match extra_cursor.read_u16::<LittleEndian>() {
                Ok(id) => id,
                Err(_) => break,
            };
            let data_size = match extra_cursor.read_u16::<LittleEndian>() {
                Ok(size) => size,
                Err(_) => break,
            };

            if header_id == 0x0001 {
                // ZIP64 extended information
                if uncompressed_size == 0xFFFFFFFF {
                    uncompressed_size = extra_cursor.read_u64::<LittleEndian>()?;
                }
                if compressed_size == 0xFFFFFFFF {
                    compressed_size = extra_cursor.read_u64::<LittleEndian>()?;
                }
                if header_offset == 0xFFFFFFFF {
                    header_offset = extra_cursor.read_u64::<LittleEndian>()?;
                }
            } else {
                // Skip unknown extra field
                extra_cursor.seek(SeekFrom::Current(data_size as i64))?;
            }
        }

        // Skip comment
        let mut comment = vec![0u8; comment_len as usize];
        reader.read_exact(&mut comment)?;

        // Check encryption:
        // 1. Standard ZIP encryption flag (bit 0)
        // 2. Strong encryption flag (bit 6)
        // 3. CryEngine/Star Citizen specific: ExtraData[168] > 0 (from unp4k)
        let mut is_encrypted = (flags & 0x0001) != 0 || (flags & 0x0040) != 0;

        // Check for CryEngine AES encryption marker in extra data
        // As per unp4k C# implementation: this.ExtraData.Length >= 168 && this.ExtraData[168] > 0x00
        if extra.len() > 168 && extra[168] > 0 {
            is_encrypted = true;
        }

        // Extract validation data from extra field (Star Citizen launcher verification)
        // Based on IDA analysis (p4k_extracted.c LoadPakFile_v1):
        // - Offset 4 (8 bytes): v110
        // - Offset 12-20 (8 bytes): v109 - Validation QWORD used in 12-byte table
        // - Offset 20 (8 bytes): v111
        // - Offset 168 (2 bytes): v117 - encryption marker
        // - Offset 174 (0xAE) (32 bytes): SHA256 hash of uncompressed content
        let validation_qword = if extra.len() >= 20 {
            Some(u64::from_le_bytes([
                extra[12], extra[13], extra[14], extra[15], extra[16], extra[17], extra[18],
                extra[19],
            ]))
        } else {
            None
        };

        // SHA256 hash is at offset 174 (0xAE) in the extra field
        let content_hash = if extra.len() >= 206 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&extra[174..206]);
            Some(hash)
        } else {
            None
        };

        // Note: data_offset will be calculated later by reading the local file header
        // because the local header's extra field length may differ from the central directory's
        // We store 0 here as a placeholder, it will be updated in extract_entry
        let data_offset = 0;

        Ok(Some(P4kEntry {
            name,
            compressed_size,
            uncompressed_size,
            compression_method: CompressionMethod::from(compression),
            is_encrypted,
            crc32,
            header_offset,
            data_offset,
            extra_data: extra,
            flags,
            version_made,
            version_needed,
            mod_time,
            mod_date,
            external_attrs,
            content_hash,
            validation_qword,
            source: EntrySource::P4k,
        }))
    }

    /// Read local file header to get accurate data offset
    ///
    /// P4K files may use either standard local header signature (PK\x03\x04)
    /// or encrypted header signature (PK\x03\x14) as per CryEngine format.
    pub fn read_local_header_offset(&mut self, entry: &P4kEntry) -> Result<u64> {
        self.reader.seek(SeekFrom::Start(entry.header_offset))?;

        // Read local file header
        let mut sig = [0u8; 4];
        self.reader.read_exact(&mut sig)?;

        // Accept both standard and encrypted header signatures
        if sig != LOCAL_HEADER_SIGNATURE && sig != ENCRYPTED_HEADER_SIGNATURE {
            return Err(Error::InvalidP4k(format!(
                "Invalid local file header signature: {:02X?} (expected PK\\x03\\x04 or PK\\x03\\x14)", 
                sig
            )));
        }

        let _version = self.reader.read_u16::<LittleEndian>()?;
        let _flags = self.reader.read_u16::<LittleEndian>()?;
        let _compression = self.reader.read_u16::<LittleEndian>()?;
        let _mod_time = self.reader.read_u16::<LittleEndian>()?;
        let _mod_date = self.reader.read_u16::<LittleEndian>()?;
        let _crc32 = self.reader.read_u32::<LittleEndian>()?;
        let _compressed_size = self.reader.read_u32::<LittleEndian>()?;
        let _uncompressed_size = self.reader.read_u32::<LittleEndian>()?;
        let name_len = self.reader.read_u16::<LittleEndian>()?;
        let extra_len = self.reader.read_u16::<LittleEndian>()?;

        // Data starts after local header + name + extra
        let data_offset = entry.header_offset + 30 + name_len as u64 + extra_len as u64;

        Ok(data_offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_method_from() {
        assert_eq!(CompressionMethod::from(0), CompressionMethod::Store);
        assert_eq!(CompressionMethod::from(8), CompressionMethod::Deflate);
        assert_eq!(CompressionMethod::from(100), CompressionMethod::Zstd);
        assert_eq!(CompressionMethod::from(99), CompressionMethod::Unknown(99));
    }
}
