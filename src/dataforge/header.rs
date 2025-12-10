//! DataForge file header parsing

use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Seek, SeekFrom};
use crate::error::{Error, Result};

/// DataForge file header containing counts and metadata
#[derive(Debug, Clone)]
pub struct DataForgeHeader {
    /// File format version
    pub file_version: i32,
    /// Whether this is a legacy format file
    pub is_legacy: bool,

    // Definition counts
    pub struct_definition_count: i32,
    pub property_definition_count: i32,
    pub enum_definition_count: i32,
    pub data_mapping_count: i32,
    pub record_definition_count: i32,

    // Value counts
    pub boolean_value_count: i32,
    pub int8_value_count: i32,
    pub int16_value_count: i32,
    pub int32_value_count: i32,
    pub int64_value_count: i32,
    pub uint8_value_count: i32,
    pub uint16_value_count: i32,
    pub uint32_value_count: i32,
    pub uint64_value_count: i32,
    pub single_value_count: i32,
    pub double_value_count: i32,
    pub guid_value_count: i32,
    pub string_value_count: i32,
    pub locale_value_count: i32,
    pub enum_value_count: i32,
    pub strong_value_count: i32,
    pub weak_value_count: i32,
    pub reference_value_count: i32,
    pub enum_option_count: i32,

    // String table lengths
    pub text_length: u32,
    pub blob_length: u32,
}

impl DataForgeHeader {
    /// Parse header from data
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 0x78 {
            return Err(Error::InvalidDataForge("File too small for header".into()));
        }

        let mut cursor = Cursor::new(data);

        // Skip temp00 (2 bytes) + unknown (2 bytes)
        cursor.seek(SeekFrom::Start(0))?;
        let _temp00 = cursor.read_u16::<LittleEndian>()?;
        let _unknown = cursor.read_u16::<LittleEndian>()?;

        // File version
        let file_version = cursor.read_i32::<LittleEndian>()?;

        // Determine if legacy format
        // Legacy files are smaller and have version < 6
        let is_legacy = data.len() < 0x0e2e00 && file_version < 6;

        // Skip 4 extra u16 fields in non-legacy files
        if !is_legacy {
            cursor.read_u16::<LittleEndian>()?;
            cursor.read_u16::<LittleEndian>()?;
            cursor.read_u16::<LittleEndian>()?;
            cursor.read_u16::<LittleEndian>()?;
        }

        // Read definition counts
        let struct_definition_count = cursor.read_i32::<LittleEndian>()?;
        let property_definition_count = cursor.read_i32::<LittleEndian>()?;
        let enum_definition_count = cursor.read_i32::<LittleEndian>()?;
        let data_mapping_count = cursor.read_i32::<LittleEndian>()?;
        let record_definition_count = cursor.read_i32::<LittleEndian>()?;

        // Read value counts
        let boolean_value_count = cursor.read_i32::<LittleEndian>()?;
        let int8_value_count = cursor.read_i32::<LittleEndian>()?;
        let int16_value_count = cursor.read_i32::<LittleEndian>()?;
        let int32_value_count = cursor.read_i32::<LittleEndian>()?;
        let int64_value_count = cursor.read_i32::<LittleEndian>()?;
        let uint8_value_count = cursor.read_i32::<LittleEndian>()?;
        let uint16_value_count = cursor.read_i32::<LittleEndian>()?;
        let uint32_value_count = cursor.read_i32::<LittleEndian>()?;
        let uint64_value_count = cursor.read_i32::<LittleEndian>()?;
        let single_value_count = cursor.read_i32::<LittleEndian>()?;
        let double_value_count = cursor.read_i32::<LittleEndian>()?;
        let guid_value_count = cursor.read_i32::<LittleEndian>()?;
        let string_value_count = cursor.read_i32::<LittleEndian>()?;
        let locale_value_count = cursor.read_i32::<LittleEndian>()?;
        let enum_value_count = cursor.read_i32::<LittleEndian>()?;
        let strong_value_count = cursor.read_i32::<LittleEndian>()?;
        let weak_value_count = cursor.read_i32::<LittleEndian>()?;
        let reference_value_count = cursor.read_i32::<LittleEndian>()?;
        let enum_option_count = cursor.read_i32::<LittleEndian>()?;

        // String table lengths
        let text_length = cursor.read_u32::<LittleEndian>()?;
        let blob_length = if is_legacy {
            0
        } else {
            cursor.read_u32::<LittleEndian>()?
        };

        Ok(DataForgeHeader {
            file_version,
            is_legacy,
            struct_definition_count,
            property_definition_count,
            enum_definition_count,
            data_mapping_count,
            record_definition_count,
            boolean_value_count,
            int8_value_count,
            int16_value_count,
            int32_value_count,
            int64_value_count,
            uint8_value_count,
            uint16_value_count,
            uint32_value_count,
            uint64_value_count,
            single_value_count,
            double_value_count,
            guid_value_count,
            string_value_count,
            locale_value_count,
            enum_value_count,
            strong_value_count,
            weak_value_count,
            reference_value_count,
            enum_option_count,
            text_length,
            blob_length,
        })
    }

    /// Get the header size based on legacy status
    pub fn header_size(&self) -> u64 {
        if self.is_legacy { 0x74 } else { 0x78 }
    }
}
