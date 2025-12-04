//! P4K file writing and modification
//!
//! This module provides functionality to create, modify, and repack P4K archives.

use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::collections::HashMap;
use byteorder::{LittleEndian, WriteBytesExt};
use crate::crypto::encrypt_aes_cbc;
use crate::error::{Error, Result};
use crate::p4k::{P4kFile, CompressionMethod};

/// Options for creating/modifying P4K files
#[derive(Debug, Clone)]
pub struct P4kWriteOptions {
    /// Default compression method for new entries
    pub compression: CompressionMethod,
    /// Whether to encrypt entries
    pub encrypt: bool,
    /// Compression level for ZSTD (1-22, default 3)
    pub zstd_level: i32,
    /// Compression level for Deflate (0-9, default 6)
    pub deflate_level: u32,
}

impl Default for P4kWriteOptions {
    fn default() -> Self {
        Self {
            compression: CompressionMethod::Zstd,
            encrypt: true,
            zstd_level: 3,
            deflate_level: 6,
        }
    }
}

/// Entry to be written to P4K
pub struct P4kWriteEntry {
    /// Path within the archive
    pub name: String,
    /// Uncompressed data
    pub data: Vec<u8>,
    /// Compression method (overrides default)
    pub compression: Option<CompressionMethod>,
    /// Whether to encrypt (overrides default)
    pub encrypt: Option<bool>,
}

impl P4kWriteEntry {
    /// Create a new entry from raw data
    pub fn new(name: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            data,
            compression: None,
            encrypt: None,
        }
    }

    /// Set compression method
    pub fn with_compression(mut self, method: CompressionMethod) -> Self {
        self.compression = Some(method);
        self
    }

    /// Set encryption
    pub fn with_encryption(mut self, encrypt: bool) -> Self {
        self.encrypt = Some(encrypt);
        self
    }
}

/// P4K file writer for creating new archives
pub struct P4kWriter {
    writer: BufWriter<File>,
    entries: Vec<WrittenEntry>,
    options: P4kWriteOptions,
}

/// Information about a written entry (for central directory)
#[derive(Clone)]
struct WrittenEntry {
    name: String,
    compression_method: u16,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    header_offset: u64,
    is_encrypted: bool,
    /// Original extra data (for kept entries)
    extra_data: Option<Vec<u8>>,
    /// Original flags (for kept entries)
    flags: Option<u16>,
    /// Original version made by (for kept entries)
    version_made: Option<u16>,
    /// Original mod time (for kept entries)
    mod_time: Option<u16>,
    /// Original mod date (for kept entries)
    mod_date: Option<u16>,
    /// Original external attributes (for kept entries)
    external_attrs: Option<u32>,
}

impl P4kWriter {
    /// Create a new P4K file for writing
    pub fn create<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::create_with_options(path, P4kWriteOptions::default())
    }

    /// Create a new P4K file with custom options
    pub fn create_with_options<P: AsRef<Path>>(path: P, options: P4kWriteOptions) -> Result<Self> {
        let file = File::create(path)?;
        let writer = BufWriter::new(file);

        Ok(Self {
            writer,
            entries: Vec::new(),
            options,
        })
    }

    /// Add an entry to the archive
    pub fn add_entry(&mut self, entry: P4kWriteEntry) -> Result<()> {
        let compression = entry.compression.unwrap_or(self.options.compression);
        let encrypt = entry.encrypt.unwrap_or(self.options.encrypt);

        // Calculate CRC32 of uncompressed data
        let crc32 = crc32fast::hash(&entry.data);
        let uncompressed_size = entry.data.len() as u64;

        // Compress data
        let compressed_data = self.compress(&entry.data, compression)?;
        
        // Encrypt if needed
        let final_data = if encrypt {
            encrypt_aes_cbc(&compressed_data)?
        } else {
            compressed_data
        };

        let compressed_size = final_data.len() as u64;

        // Record header offset
        let header_offset = self.writer.stream_position()?;

        // Write local file header
        self.write_local_header(
            &entry.name,
            compression,
            crc32,
            compressed_size,
            uncompressed_size,
            encrypt,
        )?;

        // Write file data
        self.writer.write_all(&final_data)?;

        // Store entry info for central directory
        self.entries.push(WrittenEntry {
            name: entry.name,
            compression_method: compression.to_u16(),
            crc32,
            compressed_size,
            uncompressed_size,
            header_offset,
            is_encrypted: encrypt,
            extra_data: None,
            flags: None,
            version_made: None,
            mod_time: None,
            mod_date: None,
            external_attrs: None,
        });

        Ok(())
    }

    /// Add a file from disk
    pub fn add_file<P: AsRef<Path>>(&mut self, path: P, archive_name: &str) -> Result<()> {
        let mut file = File::open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        self.add_entry(P4kWriteEntry::new(archive_name, data))
    }

    /// Finalize and close the archive
    pub fn finish(mut self) -> Result<()> {
        // Write central directory
        let cd_offset = self.writer.stream_position()?;
        
        // Clone entries to avoid borrow conflict
        let entries: Vec<_> = self.entries.to_vec();
        for entry in &entries {
            self.write_central_directory_entry(entry)?;
        }

        let cd_size = self.writer.stream_position()? - cd_offset;

        // Check if ZIP64 is needed
        let use_zip64 = cd_offset > 0xFFFFFFFF 
            || cd_size > 0xFFFFFFFF 
            || self.entries.len() > 0xFFFF;

        if use_zip64 {
            self.write_zip64_end(cd_offset, cd_size)?;
        }

        // Write end of central directory
        self.write_end_of_central_directory(cd_offset, cd_size, use_zip64)?;

        self.writer.flush()?;
        Ok(())
    }

    fn compress(&self, data: &[u8], method: CompressionMethod) -> Result<Vec<u8>> {
        match method {
            CompressionMethod::Store => Ok(data.to_vec()),
            
            CompressionMethod::Deflate => {
                use flate2::write::DeflateEncoder;
                use flate2::Compression;
                
                let mut encoder = DeflateEncoder::new(
                    Vec::new(),
                    Compression::new(self.options.deflate_level),
                );
                encoder.write_all(data)?;
                encoder.finish()
                    .map_err(|e| Error::Decompression(format!("Deflate compression failed: {}", e)))
            }
            
            CompressionMethod::Zstd => {
                let compressed = zstd::encode_all(
                    data,
                    self.options.zstd_level,
                ).map_err(|e| Error::Decompression(format!("ZSTD compression failed: {}", e)))?;
                Ok(compressed)
            }
            
            CompressionMethod::Unknown(m) => {
                Err(Error::UnsupportedCompression(m))
            }
        }
    }

    fn write_local_header(
        &mut self,
        name: &str,
        compression: CompressionMethod,
        crc32: u32,
        compressed_size: u64,
        uncompressed_size: u64,
        is_encrypted: bool,
    ) -> Result<()> {
        let name_bytes = name.as_bytes();
        let needs_zip64 = compressed_size > 0xFFFFFFFF || uncompressed_size > 0xFFFFFFFF;

        // Build extra field
        let mut extra = Vec::new();
        
        // ZIP64 extra field if needed
        if needs_zip64 {
            extra.extend_from_slice(&0x0001u16.to_le_bytes()); // ZIP64 header ID
            extra.extend_from_slice(&16u16.to_le_bytes()); // Data size
            extra.extend_from_slice(&uncompressed_size.to_le_bytes());
            extra.extend_from_slice(&compressed_size.to_le_bytes());
        }
        
        // P4K encryption marker - extra data must have byte at offset 168 > 0 for encrypted entries
        if is_encrypted {
            if extra.len() < 169 {
                extra.resize(169, 0);
            }
            extra[168] = 0x01;
        }

        // Local file header signature
        // Use PK\x03\x14 for encrypted entries (CryEngine/Star Citizen specific)
        if is_encrypted {
            self.writer.write_all(&[0x50, 0x4B, 0x03, 0x14])?;
        } else {
            self.writer.write_all(&[0x50, 0x4B, 0x03, 0x04])?;
        }
        
        // Version needed (4.5 for ZIP64, 2.0 otherwise)
        let version = if needs_zip64 { 45u16 } else { 20u16 };
        self.writer.write_u16::<LittleEndian>(version)?;
        
        // General purpose bit flag
        let mut flags = 0u16;
        if is_encrypted {
            flags |= 0x0001; // Encrypted
        }
        self.writer.write_u16::<LittleEndian>(flags)?;
        
        // Compression method
        self.writer.write_u16::<LittleEndian>(compression.to_u16())?;
        
        // Modification time/date (use current time)
        let (time, date) = dos_datetime_now();
        self.writer.write_u16::<LittleEndian>(time)?;
        self.writer.write_u16::<LittleEndian>(date)?;
        
        // CRC-32
        self.writer.write_u32::<LittleEndian>(crc32)?;
        
        // Compressed/uncompressed size (use 0xFFFFFFFF if ZIP64)
        if needs_zip64 {
            self.writer.write_u32::<LittleEndian>(0xFFFFFFFF)?;
            self.writer.write_u32::<LittleEndian>(0xFFFFFFFF)?;
        } else {
            self.writer.write_u32::<LittleEndian>(compressed_size as u32)?;
            self.writer.write_u32::<LittleEndian>(uncompressed_size as u32)?;
        }
        
        // File name length
        self.writer.write_u16::<LittleEndian>(name_bytes.len() as u16)?;
        
        // Extra field length
        self.writer.write_u16::<LittleEndian>(extra.len() as u16)?;
        
        // File name
        self.writer.write_all(name_bytes)?;
        
        // Extra field
        self.writer.write_all(&extra)?;

        Ok(())
    }

    fn write_central_directory_entry(&mut self, entry: &WrittenEntry) -> Result<()> {
        let name_bytes = entry.name.as_bytes();
        let needs_zip64 = entry.compressed_size > 0xFFFFFFFF 
            || entry.uncompressed_size > 0xFFFFFFFF
            || entry.header_offset > 0xFFFFFFFF;

        // Build extra field
        let mut extra = Vec::new();
        
        // ZIP64 extra field if needed
        if needs_zip64 {
            extra.extend_from_slice(&0x0001u16.to_le_bytes()); // ZIP64 header ID
            let mut data_size = 0u16;
            
            let mut zip64_data = Vec::new();
            if entry.uncompressed_size > 0xFFFFFFFF {
                zip64_data.extend_from_slice(&entry.uncompressed_size.to_le_bytes());
                data_size += 8;
            }
            if entry.compressed_size > 0xFFFFFFFF {
                zip64_data.extend_from_slice(&entry.compressed_size.to_le_bytes());
                data_size += 8;
            }
            if entry.header_offset > 0xFFFFFFFF {
                zip64_data.extend_from_slice(&entry.header_offset.to_le_bytes());
                data_size += 8;
            }
            
            extra.extend_from_slice(&data_size.to_le_bytes());
            extra.extend_from_slice(&zip64_data);
        }
        
        // P4K encryption marker - extra data must have byte at offset 168 > 0 for encrypted entries
        if entry.is_encrypted {
            if extra.len() < 169 {
                extra.resize(169, 0);
            }
            extra[168] = 0x01;
        }

        // Central directory signature
        self.writer.write_all(&[0x50, 0x4B, 0x01, 0x02])?;
        
        // Version made by (Unix, 4.5)
        self.writer.write_u16::<LittleEndian>(0x0300 | 45)?;
        
        // Version needed
        let version = if needs_zip64 { 45u16 } else { 20u16 };
        self.writer.write_u16::<LittleEndian>(version)?;
        
        // General purpose bit flag
        let mut flags = 0u16;
        if entry.is_encrypted {
            flags |= 0x0001;
        }
        self.writer.write_u16::<LittleEndian>(flags)?;
        
        // Compression method
        self.writer.write_u16::<LittleEndian>(entry.compression_method)?;
        
        // Modification time/date
        let (time, date) = dos_datetime_now();
        self.writer.write_u16::<LittleEndian>(time)?;
        self.writer.write_u16::<LittleEndian>(date)?;
        
        // CRC-32
        self.writer.write_u32::<LittleEndian>(entry.crc32)?;
        
        // Sizes
        if entry.compressed_size > 0xFFFFFFFF {
            self.writer.write_u32::<LittleEndian>(0xFFFFFFFF)?;
        } else {
            self.writer.write_u32::<LittleEndian>(entry.compressed_size as u32)?;
        }
        if entry.uncompressed_size > 0xFFFFFFFF {
            self.writer.write_u32::<LittleEndian>(0xFFFFFFFF)?;
        } else {
            self.writer.write_u32::<LittleEndian>(entry.uncompressed_size as u32)?;
        }
        
        // File name length
        self.writer.write_u16::<LittleEndian>(name_bytes.len() as u16)?;
        
        // Extra field length
        self.writer.write_u16::<LittleEndian>(extra.len() as u16)?;
        
        // Comment length
        self.writer.write_u16::<LittleEndian>(0)?;
        
        // Disk number start
        self.writer.write_u16::<LittleEndian>(0)?;
        
        // Internal file attributes
        self.writer.write_u16::<LittleEndian>(0)?;
        
        // External file attributes
        self.writer.write_u32::<LittleEndian>(0)?;
        
        // Relative offset of local header
        if entry.header_offset > 0xFFFFFFFF {
            self.writer.write_u32::<LittleEndian>(0xFFFFFFFF)?;
        } else {
            self.writer.write_u32::<LittleEndian>(entry.header_offset as u32)?;
        }
        
        // File name
        self.writer.write_all(name_bytes)?;
        
        // Extra field
        self.writer.write_all(&extra)?;

        Ok(())
    }

    fn write_zip64_end(&mut self, cd_offset: u64, cd_size: u64) -> Result<()> {
        let zip64_eocd_offset = self.writer.stream_position()?;

        // ZIP64 End of Central Directory Record
        self.writer.write_all(&[0x50, 0x4B, 0x06, 0x06])?;
        
        // Size of ZIP64 EOCD record
        self.writer.write_u64::<LittleEndian>(44)?;
        
        // Version made by
        self.writer.write_u16::<LittleEndian>(45)?;
        
        // Version needed
        self.writer.write_u16::<LittleEndian>(45)?;
        
        // Disk number
        self.writer.write_u32::<LittleEndian>(0)?;
        
        // Disk with CD
        self.writer.write_u32::<LittleEndian>(0)?;
        
        // Entries on this disk
        self.writer.write_u64::<LittleEndian>(self.entries.len() as u64)?;
        
        // Total entries
        self.writer.write_u64::<LittleEndian>(self.entries.len() as u64)?;
        
        // CD size
        self.writer.write_u64::<LittleEndian>(cd_size)?;
        
        // CD offset
        self.writer.write_u64::<LittleEndian>(cd_offset)?;

        // ZIP64 End of Central Directory Locator
        self.writer.write_all(&[0x50, 0x4B, 0x06, 0x07])?;
        
        // Disk with ZIP64 EOCD
        self.writer.write_u32::<LittleEndian>(0)?;
        
        // Offset of ZIP64 EOCD
        self.writer.write_u64::<LittleEndian>(zip64_eocd_offset)?;
        
        // Total disks
        self.writer.write_u32::<LittleEndian>(1)?;

        Ok(())
    }

    fn write_end_of_central_directory(&mut self, cd_offset: u64, cd_size: u64, use_zip64: bool) -> Result<()> {
        // End of Central Directory signature
        self.writer.write_all(&[0x50, 0x4B, 0x05, 0x06])?;
        
        // Disk number
        self.writer.write_u16::<LittleEndian>(0)?;
        
        // Disk with CD
        self.writer.write_u16::<LittleEndian>(0)?;
        
        // Entries on this disk
        let entries_count = if use_zip64 || self.entries.len() > 0xFFFF {
            0xFFFF
        } else {
            self.entries.len() as u16
        };
        self.writer.write_u16::<LittleEndian>(entries_count)?;
        
        // Total entries
        self.writer.write_u16::<LittleEndian>(entries_count)?;
        
        // CD size
        if use_zip64 || cd_size > 0xFFFFFFFF {
            self.writer.write_u32::<LittleEndian>(0xFFFFFFFF)?;
        } else {
            self.writer.write_u32::<LittleEndian>(cd_size as u32)?;
        }
        
        // CD offset
        if use_zip64 || cd_offset > 0xFFFFFFFF {
            self.writer.write_u32::<LittleEndian>(0xFFFFFFFF)?;
        } else {
            self.writer.write_u32::<LittleEndian>(cd_offset as u32)?;
        }
        
        // Comment length
        self.writer.write_u16::<LittleEndian>(0)?;

        Ok(())
    }
}

/// Get current time as DOS datetime
fn dos_datetime_now() -> (u16, u16) {
    use std::time::{SystemTime, UNIX_EPOCH};
    
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    // Convert to DOS format (simplified)
    let time = ((now / 2) % 30) as u16 // seconds/2
        | (((now / 60) % 60) << 5) as u16 // minutes
        | (((now / 3600) % 24) << 11) as u16; // hours
    
    let days = (now / 86400) as u16;
    let year = 1970 + days / 365;
    let date = 1 // day
        | (1 << 5) // month
        | (((year.saturating_sub(1980)) & 0x7F) << 9); // year since 1980
    
    (time, date)
}

impl CompressionMethod {
    /// Convert to ZIP compression method number
    pub fn to_u16(self) -> u16 {
        match self {
            CompressionMethod::Store => 0,
            CompressionMethod::Deflate => 8,
            CompressionMethod::Zstd => 100,
            CompressionMethod::Unknown(m) => m,
        }
    }
}

/// P4K modifier for updating existing archives
pub struct P4kModifier {
    /// Source P4K file path
    source_path: std::path::PathBuf,
    /// Source P4K file
    source: P4kFile,
    /// Entries to add/replace
    modifications: HashMap<String, P4kWriteEntry>,
    /// Entries to delete
    deletions: Vec<String>,
    /// Write options
    options: P4kWriteOptions,
}

impl P4kModifier {
    /// Open an existing P4K for modification
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let source_path = path.as_ref().to_path_buf();
        let source = P4kFile::open(path)?;
        Ok(Self {
            source_path,
            source,
            modifications: HashMap::new(),
            deletions: Vec::new(),
            options: P4kWriteOptions::default(),
        })
    }

    /// Set write options
    pub fn with_options(mut self, options: P4kWriteOptions) -> Self {
        self.options = options;
        self
    }

    /// Add or replace a file
    pub fn add(&mut self, entry: P4kWriteEntry) {
        self.modifications.insert(entry.name.clone(), entry);
    }

    /// Delete a file from the archive
    pub fn delete(&mut self, name: &str) {
        self.deletions.push(name.to_string());
        self.modifications.remove(name);
    }

    /// Write the modified archive to a new file (full rewrite)
    pub fn save<P: AsRef<Path>>(mut self, output: P) -> Result<()> {
        let mut writer = P4kWriter::create_with_options(output, self.options.clone())?;

        // Copy existing entries (except deleted/modified ones)
        let entries: Vec<_> = self.source.entries().into_iter().cloned().collect();
        
        for entry in entries {
            // Skip deleted entries
            if self.deletions.contains(&entry.name) {
                continue;
            }

            // Skip entries that will be replaced
            if self.modifications.contains_key(&entry.name) {
                continue;
            }

            // Copy existing entry
            let data = self.source.extract_entry(&entry)?;
            writer.add_entry(P4kWriteEntry {
                name: entry.name,
                data,
                compression: Some(entry.compression_method),
                encrypt: Some(entry.is_encrypted),
            })?;
        }

        // Add new/modified entries
        for (_, entry) in self.modifications {
            writer.add_entry(entry)?;
        }

        writer.finish()
    }

    /// Incrementally modify the archive in-place
    /// 
    /// This is much faster than full rewrite for delete-only operations,
    /// as it only rewrites the central directory.
    /// 
    /// For add/replace operations, new data is appended before the central directory.
    pub fn save_incremental(self) -> Result<()> {
        use std::fs::OpenOptions;
        use std::io::{BufWriter, Write};
        
        // Get central directory info from source
        let cd_offset = self.source.central_directory_offset();
        
        // Collect entries to keep
        let entries: Vec<_> = self.source.entries().into_iter().cloned().collect();
        let mut kept_entries: Vec<WrittenEntry> = Vec::new();
        
        for entry in &entries {
            // Skip deleted entries
            if self.deletions.contains(&entry.name) {
                continue;
            }
            
            // Skip entries that will be replaced (we'll add them later)
            if self.modifications.contains_key(&entry.name) {
                continue;
            }
            
            // Keep this entry's metadata with original extra data
            kept_entries.push(WrittenEntry {
                name: entry.name.clone(),
                compression_method: entry.compression_method.to_u16(),
                crc32: entry.crc32,
                compressed_size: entry.compressed_size,
                uncompressed_size: entry.uncompressed_size,
                header_offset: entry.header_offset,
                is_encrypted: entry.is_encrypted,
                extra_data: Some(entry.extra_data.clone()),
                flags: Some(entry.flags),
                version_made: Some(entry.version_made),
                mod_time: Some(entry.mod_time),
                mod_date: Some(entry.mod_date),
                external_attrs: Some(entry.external_attrs),
            });
        }
        
        // Drop the source to release the file handle
        drop(self.source);
        
        // Open file for writing (append mode)
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.source_path)?;
        let mut writer = BufWriter::new(file);
        
        // Seek to where central directory was (this is where we'll write new data)
        writer.seek(SeekFrom::Start(cd_offset))?;
        
        // If there are modifications, write new entries
        let mut new_entries: Vec<WrittenEntry> = Vec::new();
        for (_, entry) in self.modifications {
            let compression = entry.compression.unwrap_or(self.options.compression);
            let encrypt = entry.encrypt.unwrap_or(self.options.encrypt);
            
            // Calculate CRC32 of uncompressed data
            let crc32 = crc32fast::hash(&entry.data);
            let uncompressed_size = entry.data.len() as u64;
            
            // Compress data
            let compressed_data = compress_data(&entry.data, compression, &self.options)?;
            
            // Encrypt if needed
            let final_data = if encrypt {
                crate::crypto::encrypt_aes_cbc(&compressed_data)?
            } else {
                compressed_data
            };
            
            let compressed_size = final_data.len() as u64;
            let header_offset = writer.stream_position()?;
            
            // Write local file header
            write_local_header(
                &mut writer,
                &entry.name,
                compression,
                crc32,
                compressed_size,
                uncompressed_size,
                encrypt,
            )?;
            
            // Write file data
            writer.write_all(&final_data)?;
            
            new_entries.push(WrittenEntry {
                name: entry.name,
                compression_method: compression.to_u16(),
                crc32,
                compressed_size,
                uncompressed_size,
                header_offset,
                is_encrypted: encrypt,
                extra_data: None,
                flags: None,
                version_made: None,
                mod_time: None,
                mod_date: None,
                external_attrs: None,
            });
        }
        
        // Combine all entries
        kept_entries.extend(new_entries);
        
        // Write new central directory
        let new_cd_offset = writer.stream_position()?;
        for entry in &kept_entries {
            write_central_directory_entry(&mut writer, entry)?;
        }
        let new_cd_size = writer.stream_position()? - new_cd_offset;
        
        // Check if ZIP64 is needed
        let use_zip64 = new_cd_offset > 0xFFFFFFFF 
            || new_cd_size > 0xFFFFFFFF 
            || kept_entries.len() > 0xFFFF;
        
        if use_zip64 {
            write_zip64_end(&mut writer, new_cd_offset, new_cd_size, kept_entries.len())?;
        }
        
        // Write end of central directory
        write_end_of_central_directory(&mut writer, new_cd_offset, new_cd_size, kept_entries.len(), use_zip64)?;
        
        // Truncate file to current position (remove old data after new EOCD)
        let final_pos = writer.stream_position()?;
        writer.flush()?;
        drop(writer);
        
        // Truncate the file
        let file = OpenOptions::new()
            .write(true)
            .open(&self.source_path)?;
        file.set_len(final_pos)?;
        
        Ok(())
    }
}

// Helper functions for incremental writing

fn compress_data(data: &[u8], method: CompressionMethod, options: &P4kWriteOptions) -> Result<Vec<u8>> {
    match method {
        CompressionMethod::Store => Ok(data.to_vec()),
        
        CompressionMethod::Deflate => {
            use flate2::write::DeflateEncoder;
            use flate2::Compression;
            
            let mut encoder = DeflateEncoder::new(
                Vec::new(),
                Compression::new(options.deflate_level),
            );
            encoder.write_all(data)?;
            encoder.finish()
                .map_err(|e| Error::Decompression(format!("Deflate compression failed: {}", e)))
        }
        
        CompressionMethod::Zstd => {
            let compressed = zstd::encode_all(
                data,
                options.zstd_level,
            ).map_err(|e| Error::Decompression(format!("ZSTD compression failed: {}", e)))?;
            Ok(compressed)
        }
        
        CompressionMethod::Unknown(m) => {
            Err(Error::UnsupportedCompression(m))
        }
    }
}

fn write_local_header<W: Write + Seek>(
    writer: &mut W,
    name: &str,
    compression: CompressionMethod,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    is_encrypted: bool,
) -> Result<()> {
    let name_bytes = name.as_bytes();
    let needs_zip64 = compressed_size > 0xFFFFFFFF || uncompressed_size > 0xFFFFFFFF;

    // Build extra field
    // P4K format requires extra data with encryption marker at offset 168
    let mut extra = Vec::new();
    
    // ZIP64 extra field if needed
    if needs_zip64 {
        extra.extend_from_slice(&0x0001u16.to_le_bytes()); // ZIP64 header ID
        extra.extend_from_slice(&16u16.to_le_bytes());      // Data size
        extra.extend_from_slice(&uncompressed_size.to_le_bytes());
        extra.extend_from_slice(&compressed_size.to_le_bytes());
    }
    
    // P4K encryption marker - extra data must have byte at offset 168 > 0 for encrypted entries
    if is_encrypted {
        // Pad extra to at least 169 bytes and set encryption marker
        if extra.len() < 169 {
            extra.resize(169, 0);
        }
        extra[168] = 0x01; // Encryption marker
    }

    // Local file header signature
    // Use PK\x03\x14 for encrypted entries (CryEngine/Star Citizen specific)
    if is_encrypted {
        writer.write_all(&[0x50, 0x4B, 0x03, 0x14])?;
    } else {
        writer.write_all(&[0x50, 0x4B, 0x03, 0x04])?;
    }
    
    let version = if needs_zip64 { 45u16 } else { 20u16 };
    writer.write_u16::<LittleEndian>(version)?;
    
    let mut flags = 0u16;
    if is_encrypted {
        flags |= 0x0001;
    }
    writer.write_u16::<LittleEndian>(flags)?;
    writer.write_u16::<LittleEndian>(compression.to_u16())?;
    
    let (time, date) = dos_datetime_now();
    writer.write_u16::<LittleEndian>(time)?;
    writer.write_u16::<LittleEndian>(date)?;
    writer.write_u32::<LittleEndian>(crc32)?;
    
    if needs_zip64 {
        writer.write_u32::<LittleEndian>(0xFFFFFFFF)?;
        writer.write_u32::<LittleEndian>(0xFFFFFFFF)?;
    } else {
        writer.write_u32::<LittleEndian>(compressed_size as u32)?;
        writer.write_u32::<LittleEndian>(uncompressed_size as u32)?;
    }
    
    writer.write_u16::<LittleEndian>(name_bytes.len() as u16)?;
    writer.write_u16::<LittleEndian>(extra.len() as u16)?;
    writer.write_all(name_bytes)?;
    writer.write_all(&extra)?;

    Ok(())
}

fn write_central_directory_entry<W: Write + Seek>(writer: &mut W, entry: &WrittenEntry) -> Result<()> {
    let name_bytes = entry.name.as_bytes();
    let needs_zip64 = entry.compressed_size > 0xFFFFFFFF 
        || entry.uncompressed_size > 0xFFFFFFFF
        || entry.header_offset > 0xFFFFFFFF;

    // Use original extra data if available (for kept entries), otherwise build new
    let extra = if let Some(ref original_extra) = entry.extra_data {
        // For kept entries, use original extra data to maintain compatibility
        original_extra.clone()
    } else {
        // Build extra field for new entries
        let mut extra = Vec::new();
        
        // ZIP64 extra field if needed
        if needs_zip64 {
            extra.extend_from_slice(&0x0001u16.to_le_bytes());
            let mut data_size = 0u16;
            let mut zip64_data = Vec::new();
            
            if entry.uncompressed_size > 0xFFFFFFFF {
                zip64_data.extend_from_slice(&entry.uncompressed_size.to_le_bytes());
                data_size += 8;
            }
            if entry.compressed_size > 0xFFFFFFFF {
                zip64_data.extend_from_slice(&entry.compressed_size.to_le_bytes());
                data_size += 8;
            }
            if entry.header_offset > 0xFFFFFFFF {
                zip64_data.extend_from_slice(&entry.header_offset.to_le_bytes());
                data_size += 8;
            }
            
            extra.extend_from_slice(&data_size.to_le_bytes());
            extra.extend_from_slice(&zip64_data);
        }
        
        // P4K encryption marker - extra data must have byte at offset 168 > 0 for encrypted entries
        if entry.is_encrypted {
            if extra.len() < 169 {
                extra.resize(169, 0);
            }
            extra[168] = 0x01;
        }
        extra
    };

    // Use original values if available, otherwise use defaults
    let version_made = entry.version_made.unwrap_or(0x0300 | 45);
    let version_needed = if needs_zip64 { 45u16 } else { 20u16 };
    let flags = entry.flags.unwrap_or(if entry.is_encrypted { 0x0001 } else { 0 });
    let (time, date) = if let (Some(t), Some(d)) = (entry.mod_time, entry.mod_date) {
        (t, d)
    } else {
        dos_datetime_now()
    };
    let external_attrs = entry.external_attrs.unwrap_or(0);

    writer.write_all(&[0x50, 0x4B, 0x01, 0x02])?;
    writer.write_u16::<LittleEndian>(version_made)?;
    writer.write_u16::<LittleEndian>(version_needed)?;
    writer.write_u16::<LittleEndian>(flags)?;
    writer.write_u16::<LittleEndian>(entry.compression_method)?;
    writer.write_u16::<LittleEndian>(time)?;
    writer.write_u16::<LittleEndian>(date)?;
    writer.write_u32::<LittleEndian>(entry.crc32)?;
    
    if entry.compressed_size > 0xFFFFFFFF {
        writer.write_u32::<LittleEndian>(0xFFFFFFFF)?;
    } else {
        writer.write_u32::<LittleEndian>(entry.compressed_size as u32)?;
    }
    if entry.uncompressed_size > 0xFFFFFFFF {
        writer.write_u32::<LittleEndian>(0xFFFFFFFF)?;
    } else {
        writer.write_u32::<LittleEndian>(entry.uncompressed_size as u32)?;
    }
    
    writer.write_u16::<LittleEndian>(name_bytes.len() as u16)?;
    writer.write_u16::<LittleEndian>(extra.len() as u16)?;
    writer.write_u16::<LittleEndian>(0)?; // comment length
    writer.write_u16::<LittleEndian>(0)?; // disk number start
    writer.write_u16::<LittleEndian>(0)?; // internal attrs
    writer.write_u32::<LittleEndian>(external_attrs)?;
    
    if entry.header_offset > 0xFFFFFFFF {
        writer.write_u32::<LittleEndian>(0xFFFFFFFF)?;
    } else {
        writer.write_u32::<LittleEndian>(entry.header_offset as u32)?;
    }
    
    writer.write_all(name_bytes)?;
    writer.write_all(&extra)?;

    Ok(())
}

fn write_zip64_end<W: Write + Seek>(writer: &mut W, cd_offset: u64, cd_size: u64, entry_count: usize) -> Result<()> {
    let zip64_eocd_offset = writer.stream_position()?;

    writer.write_all(&[0x50, 0x4B, 0x06, 0x06])?;
    writer.write_u64::<LittleEndian>(44)?;
    writer.write_u16::<LittleEndian>(45)?;
    writer.write_u16::<LittleEndian>(45)?;
    writer.write_u32::<LittleEndian>(0)?;
    writer.write_u32::<LittleEndian>(0)?;
    writer.write_u64::<LittleEndian>(entry_count as u64)?;
    writer.write_u64::<LittleEndian>(entry_count as u64)?;
    writer.write_u64::<LittleEndian>(cd_size)?;
    writer.write_u64::<LittleEndian>(cd_offset)?;

    writer.write_all(&[0x50, 0x4B, 0x06, 0x07])?;
    writer.write_u32::<LittleEndian>(0)?;
    writer.write_u64::<LittleEndian>(zip64_eocd_offset)?;
    writer.write_u32::<LittleEndian>(1)?;

    Ok(())
}

fn write_end_of_central_directory<W: Write + Seek>(
    writer: &mut W, 
    cd_offset: u64, 
    cd_size: u64, 
    entry_count: usize,
    use_zip64: bool
) -> Result<()> {
    writer.write_all(&[0x50, 0x4B, 0x05, 0x06])?;
    writer.write_u16::<LittleEndian>(0)?;
    writer.write_u16::<LittleEndian>(0)?;
    
    let entries_count = if use_zip64 || entry_count > 0xFFFF {
        0xFFFF
    } else {
        entry_count as u16
    };
    writer.write_u16::<LittleEndian>(entries_count)?;
    writer.write_u16::<LittleEndian>(entries_count)?;
    
    if use_zip64 || cd_size > 0xFFFFFFFF {
        writer.write_u32::<LittleEndian>(0xFFFFFFFF)?;
    } else {
        writer.write_u32::<LittleEndian>(cd_size as u32)?;
    }
    
    if use_zip64 || cd_offset > 0xFFFFFFFF {
        writer.write_u32::<LittleEndian>(0xFFFFFFFF)?;
    } else {
        writer.write_u32::<LittleEndian>(cd_offset as u32)?;
    }
    
    writer.write_u16::<LittleEndian>(0)?; // comment length

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_method_to_u16() {
        assert_eq!(CompressionMethod::Store.to_u16(), 0);
        assert_eq!(CompressionMethod::Deflate.to_u16(), 8);
        assert_eq!(CompressionMethod::Zstd.to_u16(), 100);
    }
}
