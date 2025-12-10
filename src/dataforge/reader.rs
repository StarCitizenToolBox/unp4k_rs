//! Main DataForge parser/reader

use byteorder::{LittleEndian, ReadBytesExt};
use std::collections::HashMap;
use std::io::{Cursor, Seek, SeekFrom};

use crate::error::{Error, Result};
use crate::dataforge::header::DataForgeHeader;
use crate::dataforge::definitions::*;
use crate::dataforge::types::*;

/// Main DataForge reader structure
pub struct DataForge {
    /// Raw data buffer
    data: Vec<u8>,
    /// Parsed header
    pub header: DataForgeHeader,

    // Offset calculations
    struct_definition_offset: u64,
    property_definition_offset: u64,
    enum_definition_offset: u64,
    data_mapping_offset: u64,
    record_definition_offset: u64,
    
    // Value offsets
    int8_value_offset: u64,
    int16_value_offset: u64,
    int32_value_offset: u64,
    int64_value_offset: u64,
    uint8_value_offset: u64,
    uint16_value_offset: u64,
    uint32_value_offset: u64,
    uint64_value_offset: u64,
    boolean_value_offset: u64,
    single_value_offset: u64,
    double_value_offset: u64,
    guid_value_offset: u64,
    string_value_offset: u64,
    locale_value_offset: u64,
    enum_value_offset: u64,
    strong_value_offset: u64,
    weak_value_offset: u64,
    reference_value_offset: u64,
    #[allow(dead_code)]
    enum_option_offset: u64,
    
    // String table offsets
    text_offset: u64,
    blob_offset: u64,
    data_offset: u64,

    // Caches
    struct_definitions: Vec<StructDefinition>,
    property_definitions: Vec<PropertyDefinition>,
    enum_definitions: Vec<EnumDefinition>,
    data_mappings: Vec<DataMapping>,
    record_definitions: Vec<RecordDefinition>,

    // Maps
    path_to_record: HashMap<String, usize>,
    reference_to_record: HashMap<[u8; 16], usize>,
    struct_to_data_offset: HashMap<u32, u64>,
}

impl DataForge {
    /// Check if data is a DataForge/DCB file
    pub fn is_dataforge(data: &[u8]) -> bool {
        if data.len() < 8 {
            return false;
        }
        // Check for reasonable file version (usually 5-7 for Star Citizen)
        let version = i32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        version >= 1 && version <= 10
    }

    /// Parse DataForge data
    pub fn parse(data: &[u8]) -> Result<Self> {
        let header = DataForgeHeader::parse(data)?;
        
        // Calculate offsets
        let struct_definition_offset = header.header_size();
        let property_definition_offset = struct_definition_offset 
            + header.struct_definition_count as u64 * StructDefinition::RECORD_SIZE as u64;
        let enum_definition_offset = property_definition_offset 
            + header.property_definition_count as u64 * PropertyDefinition::RECORD_SIZE as u64;
        
        let data_mapping_size = if header.is_legacy {
            DataMapping::RECORD_SIZE_LEGACY
        } else {
            DataMapping::RECORD_SIZE_V6
        };
        let data_mapping_offset = enum_definition_offset 
            + header.enum_definition_count as u64 * EnumDefinition::RECORD_SIZE as u64;
        
        let record_definition_offset = data_mapping_offset 
            + header.data_mapping_count as u64 * data_mapping_size as u64;

        // Value offsets (after record definitions)
        // Record size depends on legacy format
        let record_def_size = if header.is_legacy {
            RecordDefinition::RECORD_SIZE_LEGACY
        } else {
            RecordDefinition::RECORD_SIZE
        };
        let int8_value_offset = record_definition_offset 
            + header.record_definition_count as u64 * record_def_size as u64;
        let int16_value_offset = int8_value_offset + header.int8_value_count as u64;
        let int32_value_offset = int16_value_offset + header.int16_value_count as u64 * 2;
        let int64_value_offset = int32_value_offset + header.int32_value_count as u64 * 4;
        let uint8_value_offset = int64_value_offset + header.int64_value_count as u64 * 8;
        let uint16_value_offset = uint8_value_offset + header.uint8_value_count as u64;
        let uint32_value_offset = uint16_value_offset + header.uint16_value_count as u64 * 2;
        let uint64_value_offset = uint32_value_offset + header.uint32_value_count as u64 * 4;
        let boolean_value_offset = uint64_value_offset + header.uint64_value_count as u64 * 8;
        let single_value_offset = boolean_value_offset + header.boolean_value_count as u64;
        let double_value_offset = single_value_offset + header.single_value_count as u64 * 4;
        let guid_value_offset = double_value_offset + header.double_value_count as u64 * 8;
        let string_value_offset = guid_value_offset + header.guid_value_count as u64 * 16;
        let locale_value_offset = string_value_offset + header.string_value_count as u64 * 4;
        let enum_value_offset = locale_value_offset + header.locale_value_count as u64 * 4;
        let strong_value_offset = enum_value_offset + header.enum_value_count as u64 * 4;
        let weak_value_offset = strong_value_offset + header.strong_value_count as u64 * 8;
        let reference_value_offset = weak_value_offset + header.weak_value_count as u64 * 8;
        let enum_option_offset = reference_value_offset + header.reference_value_count as u64 * 20;
        let text_offset = enum_option_offset + header.enum_option_count as u64 * 4;
        let blob_offset = text_offset + header.text_length as u64;
        let data_offset = blob_offset + header.blob_length as u64;

        let mut df = DataForge {
            data: data.to_vec(),
            header,
            struct_definition_offset,
            property_definition_offset,
            enum_definition_offset,
            data_mapping_offset,
            record_definition_offset,
            int8_value_offset,
            int16_value_offset,
            int32_value_offset,
            int64_value_offset,
            uint8_value_offset,
            uint16_value_offset,
            uint32_value_offset,
            uint64_value_offset,
            boolean_value_offset,
            single_value_offset,
            double_value_offset,
            guid_value_offset,
            string_value_offset,
            locale_value_offset,
            enum_value_offset,
            strong_value_offset,
            weak_value_offset,
            reference_value_offset,
            enum_option_offset,
            text_offset,
            blob_offset,
            data_offset,
            struct_definitions: Vec::new(),
            property_definitions: Vec::new(),
            enum_definitions: Vec::new(),
            data_mappings: Vec::new(),
            record_definitions: Vec::new(),
            path_to_record: HashMap::new(),
            reference_to_record: HashMap::new(),
            struct_to_data_offset: HashMap::new(),
        };

        // Parse all definitions
        df.parse_definitions()?;

        Ok(df)
    }

    fn parse_definitions(&mut self) -> Result<()> {
        // Parse struct definitions
        self.struct_definitions = self.read_struct_definitions()?;
        
        // Parse property definitions
        self.property_definitions = self.read_property_definitions()?;
        
        // Parse enum definitions
        self.enum_definitions = self.read_enum_definitions()?;
        
        // Parse data mappings
        self.data_mappings = self.read_data_mappings()?;
        
        // Parse record definitions and build maps
        self.record_definitions = self.read_record_definitions()?;
        
        // Build path and reference maps
        for (idx, record) in self.record_definitions.iter().enumerate() {
            let filename = self.read_text_at_offset(record.file_name_offset as u64)?;
            self.path_to_record.insert(filename, idx);
            self.reference_to_record.insert(record.hash.bytes, idx);
        }

        // Build struct to data offset map
        // C# code uses dataMappingIndex to read StructDefinition, but dataMapping.StructIndex as map key
        let mut last_offset: u64 = 0;
        for (idx, mapping) in self.data_mappings.iter().enumerate() {
            // Use loop index to get struct definition (matching C# behavior)
            let struct_def = &self.struct_definitions[idx];
            
            // Use mapping.struct_index as the key (matching C# behavior)
            if !self.struct_to_data_offset.contains_key(&mapping.struct_index) {
                self.struct_to_data_offset.insert(mapping.struct_index, last_offset);
            }
            last_offset += mapping.struct_count as u64 * struct_def.record_size as u64;
        }

        Ok(())
    }

    fn read_struct_definitions(&self) -> Result<Vec<StructDefinition>> {
        let mut cursor = Cursor::new(&self.data);
        cursor.seek(SeekFrom::Start(self.struct_definition_offset))?;
        
        let mut defs = Vec::with_capacity(self.header.struct_definition_count as usize);
        for _ in 0..self.header.struct_definition_count {
            defs.push(StructDefinition {
                name_offset: cursor.read_u32::<LittleEndian>()?,
                parent_type_index: cursor.read_u32::<LittleEndian>()?,
                property_count: cursor.read_u16::<LittleEndian>()?,
                first_property_index: cursor.read_u16::<LittleEndian>()?,
                record_size: cursor.read_u32::<LittleEndian>()?,
            });
        }
        Ok(defs)
    }

    fn read_property_definitions(&self) -> Result<Vec<PropertyDefinition>> {
        let mut cursor = Cursor::new(&self.data);
        cursor.seek(SeekFrom::Start(self.property_definition_offset))?;
        
        let mut defs = Vec::with_capacity(self.header.property_definition_count as usize);
        for _ in 0..self.header.property_definition_count {
            defs.push(PropertyDefinition {
                name_offset: cursor.read_u32::<LittleEndian>()?,
                index: cursor.read_u16::<LittleEndian>()?,
                data_type: DataType::from(cursor.read_u16::<LittleEndian>()?),
                conversion_type: ConversionType::from(cursor.read_u16::<LittleEndian>()?),
                variant_index: cursor.read_u16::<LittleEndian>()?,
            });
        }
        Ok(defs)
    }

    fn read_enum_definitions(&self) -> Result<Vec<EnumDefinition>> {
        let mut cursor = Cursor::new(&self.data);
        cursor.seek(SeekFrom::Start(self.enum_definition_offset))?;
        
        let mut defs = Vec::with_capacity(self.header.enum_definition_count as usize);
        for _ in 0..self.header.enum_definition_count {
            defs.push(EnumDefinition {
                name_offset: cursor.read_u32::<LittleEndian>()?,
                value_count: cursor.read_u16::<LittleEndian>()?,
                first_value_index: cursor.read_u16::<LittleEndian>()?,
            });
        }
        Ok(defs)
    }

    fn read_data_mappings(&self) -> Result<Vec<DataMapping>> {
        let mut cursor = Cursor::new(&self.data);
        cursor.seek(SeekFrom::Start(self.data_mapping_offset))?;
        
        let mut mappings = Vec::with_capacity(self.header.data_mapping_count as usize);
        for _ in 0..self.header.data_mapping_count {
            let (struct_count, struct_index) = if self.header.file_version >= 5 {
                (cursor.read_u32::<LittleEndian>()?, cursor.read_u32::<LittleEndian>()?)
            } else {
                (cursor.read_u16::<LittleEndian>()? as u32, cursor.read_u16::<LittleEndian>()? as u32)
            };
            mappings.push(DataMapping { struct_index, struct_count });
        }
        Ok(mappings)
    }

    fn read_record_definitions(&self) -> Result<Vec<RecordDefinition>> {
        let mut cursor = Cursor::new(&self.data);
        cursor.seek(SeekFrom::Start(self.record_definition_offset))?;
        
        let mut defs = Vec::with_capacity(self.header.record_definition_count as usize);
        for _ in 0..self.header.record_definition_count {
            let name_offset = cursor.read_u32::<LittleEndian>()?;
            let file_name_offset = if self.header.is_legacy {
                0
            } else {
                cursor.read_u32::<LittleEndian>()?
            };
            let struct_index = cursor.read_u32::<LittleEndian>()?;
            
            // Read GUID (CryEngine format)
            let hash = self.read_guid_from_cursor(&mut cursor)?;
            
            let variant_index = cursor.read_u16::<LittleEndian>()?;
            let other_index = cursor.read_u16::<LittleEndian>()?;
            
            defs.push(RecordDefinition {
                name_offset,
                file_name_offset,
                struct_index,
                hash,
                variant_index,
                other_index,
            });
        }
        Ok(defs)
    }

    fn read_guid_from_cursor(&self, cursor: &mut Cursor<&Vec<u8>>) -> Result<DataForgeGuid> {
        // CryEngine GUID format (16 bytes but in specific order)
        let c = cursor.read_i16::<LittleEndian>()?;
        let b = cursor.read_i16::<LittleEndian>()?;
        let a = cursor.read_i32::<LittleEndian>()?;
        let k = cursor.read_u8()?;
        let j = cursor.read_u8()?;
        let i = cursor.read_u8()?;
        let h = cursor.read_u8()?;
        let g = cursor.read_u8()?;
        let f = cursor.read_u8()?;
        let e = cursor.read_u8()?;
        let d = cursor.read_u8()?;

        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&a.to_le_bytes());
        bytes[4..6].copy_from_slice(&b.to_le_bytes());
        bytes[6..8].copy_from_slice(&c.to_le_bytes());
        bytes[8] = d;
        bytes[9] = e;
        bytes[10] = f;
        bytes[11] = g;
        bytes[12] = h;
        bytes[13] = i;
        bytes[14] = j;
        bytes[15] = k;

        Ok(DataForgeGuid { bytes })
    }

    // String reading methods
    pub fn read_text_at_offset(&self, offset: u64) -> Result<String> {
        self.read_cstring_at(self.text_offset + offset)
    }

    pub fn read_blob_at_offset(&self, offset: u64) -> Result<String> {
        if self.header.file_version < 6 {
            self.read_text_at_offset(offset)
        } else {
            self.read_cstring_at(self.blob_offset + offset)
        }
    }

    fn read_cstring_at(&self, offset: u64) -> Result<String> {
        let start = offset as usize;
        if start >= self.data.len() {
            return Ok(String::new());
        }
        
        let end = self.data[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| start + p)
            .unwrap_or(self.data.len());
        
        Ok(String::from_utf8_lossy(&self.data[start..end]).to_string())
    }

    // Public accessors
    pub fn record_paths(&self) -> impl Iterator<Item = &String> {
        self.path_to_record.keys()
    }

    pub fn record_count(&self) -> usize {
        self.record_definitions.len()
    }

    pub fn get_struct_name(&self, index: usize) -> Result<String> {
        if index >= self.struct_definitions.len() {
            return Err(Error::InvalidDataForge(format!("Struct index {} out of range", index)));
        }
        self.read_blob_at_offset(self.struct_definitions[index].name_offset as u64)
    }

    pub fn get_property_name(&self, index: usize) -> Result<String> {
        if index >= self.property_definitions.len() {
            return Err(Error::InvalidDataForge(format!("Property index {} out of range", index)));
        }
        self.read_blob_at_offset(self.property_definitions[index].name_offset as u64)
    }

    pub fn get_enum_name(&self, index: usize) -> Result<String> {
        if index >= self.enum_definitions.len() {
            return Err(Error::InvalidDataForge(format!("Enum index {} out of range", index)));
        }
        self.read_blob_at_offset(self.enum_definitions[index].name_offset as u64)
    }

    // Getters for definitions
    pub fn struct_definitions(&self) -> &[StructDefinition] {
        &self.struct_definitions
    }

    pub fn property_definitions(&self) -> &[PropertyDefinition] {
        &self.property_definitions
    }

    pub fn enum_definitions(&self) -> &[EnumDefinition] {
        &self.enum_definitions
    }

    pub fn record_definitions(&self) -> &[RecordDefinition] {
        &self.record_definitions
    }

    pub fn data_mappings(&self) -> &[DataMapping] {
        &self.data_mappings
    }

    // Internal offset accessors for XML generation
    pub(crate) fn data_offset(&self) -> u64 {
        self.data_offset
    }

    pub(crate) fn struct_to_data_offset(&self) -> &HashMap<u32, u64> {
        &self.struct_to_data_offset
    }

    pub(crate) fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the path to record index map
    pub fn path_to_record(&self) -> &HashMap<String, usize> {
        &self.path_to_record
    }

    // Value reading methods
    pub(crate) fn read_value_at<T: ReadValue>(&self, offset: u64) -> Result<T> {
        if offset as usize >= self.data.len() {
            return Err(Error::InvalidDataForge(format!(
                "read_value_at: offset {} exceeds data length {}",
                offset, self.data.len()
            )));
        }
        T::read_at(&self.data, offset)
    }

    pub(crate) fn int8_value_offset(&self) -> u64 { self.int8_value_offset }
    pub(crate) fn int16_value_offset(&self) -> u64 { self.int16_value_offset }
    pub(crate) fn int32_value_offset(&self) -> u64 { self.int32_value_offset }
    pub(crate) fn int64_value_offset(&self) -> u64 { self.int64_value_offset }
    pub(crate) fn uint8_value_offset(&self) -> u64 { self.uint8_value_offset }
    pub(crate) fn uint16_value_offset(&self) -> u64 { self.uint16_value_offset }
    pub(crate) fn uint32_value_offset(&self) -> u64 { self.uint32_value_offset }
    pub(crate) fn uint64_value_offset(&self) -> u64 { self.uint64_value_offset }
    pub(crate) fn boolean_value_offset(&self) -> u64 { self.boolean_value_offset }
    pub(crate) fn single_value_offset(&self) -> u64 { self.single_value_offset }
    pub(crate) fn double_value_offset(&self) -> u64 { self.double_value_offset }
    pub(crate) fn guid_value_offset(&self) -> u64 { self.guid_value_offset }
    pub(crate) fn string_value_offset(&self) -> u64 { self.string_value_offset }
    pub(crate) fn locale_value_offset(&self) -> u64 { self.locale_value_offset }
    pub(crate) fn enum_value_offset(&self) -> u64 { self.enum_value_offset }
    pub(crate) fn strong_value_offset(&self) -> u64 { self.strong_value_offset }
    pub(crate) fn weak_value_offset(&self) -> u64 { self.weak_value_offset }
    pub(crate) fn reference_value_offset(&self) -> u64 { self.reference_value_offset }
}

/// Trait for reading values from byte buffer
pub trait ReadValue: Sized {
    fn read_at(data: &[u8], offset: u64) -> Result<Self>;
}

impl ReadValue for i8 {
    fn read_at(data: &[u8], offset: u64) -> Result<Self> {
        Ok(data[offset as usize] as i8)
    }
}

impl ReadValue for u8 {
    fn read_at(data: &[u8], offset: u64) -> Result<Self> {
        Ok(data[offset as usize])
    }
}

impl ReadValue for i16 {
    fn read_at(data: &[u8], offset: u64) -> Result<Self> {
        let mut cursor = Cursor::new(&data[offset as usize..]);
        Ok(cursor.read_i16::<LittleEndian>()?)
    }
}

impl ReadValue for u16 {
    fn read_at(data: &[u8], offset: u64) -> Result<Self> {
        let mut cursor = Cursor::new(&data[offset as usize..]);
        Ok(cursor.read_u16::<LittleEndian>()?)
    }
}

impl ReadValue for i32 {
    fn read_at(data: &[u8], offset: u64) -> Result<Self> {
        let mut cursor = Cursor::new(&data[offset as usize..]);
        Ok(cursor.read_i32::<LittleEndian>()?)
    }
}

impl ReadValue for u32 {
    fn read_at(data: &[u8], offset: u64) -> Result<Self> {
        let mut cursor = Cursor::new(&data[offset as usize..]);
        Ok(cursor.read_u32::<LittleEndian>()?)
    }
}

impl ReadValue for i64 {
    fn read_at(data: &[u8], offset: u64) -> Result<Self> {
        let mut cursor = Cursor::new(&data[offset as usize..]);
        Ok(cursor.read_i64::<LittleEndian>()?)
    }
}

impl ReadValue for u64 {
    fn read_at(data: &[u8], offset: u64) -> Result<Self> {
        let mut cursor = Cursor::new(&data[offset as usize..]);
        Ok(cursor.read_u64::<LittleEndian>()?)
    }
}

impl ReadValue for f32 {
    fn read_at(data: &[u8], offset: u64) -> Result<Self> {
        let mut cursor = Cursor::new(&data[offset as usize..]);
        Ok(cursor.read_f32::<LittleEndian>()?)
    }
}

impl ReadValue for f64 {
    fn read_at(data: &[u8], offset: u64) -> Result<Self> {
        let mut cursor = Cursor::new(&data[offset as usize..]);
        Ok(cursor.read_f64::<LittleEndian>()?)
    }
}

impl ReadValue for bool {
    fn read_at(data: &[u8], offset: u64) -> Result<Self> {
        Ok(data[offset as usize] != 0)
    }
}
