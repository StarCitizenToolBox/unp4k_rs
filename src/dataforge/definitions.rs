//! Definition table structures for DataForge format

use crate::dataforge::types::{ConversionType, DataType, DataForgeGuid};

/// Struct definition entry
#[derive(Debug, Clone)]
pub struct StructDefinition {
    /// Offset into blob string table for struct name
    pub name_offset: u32,
    /// Index of parent struct or 0xFFFFFFFF if none
    pub parent_type_index: u32,
    /// Number of properties in this struct
    pub property_count: u16,
    /// Index of first property in property table
    pub first_property_index: u16,
    /// Size of struct data in bytes
    pub record_size: u32,
}

impl StructDefinition {
    pub const RECORD_SIZE: usize = 16;

    pub fn has_parent(&self) -> bool {
        self.parent_type_index != 0xFFFFFFFF
    }
}

/// Property definition entry
#[derive(Debug, Clone)]
pub struct PropertyDefinition {
    /// Offset into blob string table for property name
    pub name_offset: u32,
    /// Struct/enum index for complex types
    pub index: u16,
    /// Data type of this property
    pub data_type: DataType,
    /// How the property is stored (attribute vs array)
    pub conversion_type: ConversionType,
    /// Variant index (for polymorphic types)
    pub variant_index: u16,
}

impl PropertyDefinition {
    pub const RECORD_SIZE: usize = 12;
}

/// Enum definition entry
#[derive(Debug, Clone)]
pub struct EnumDefinition {
    /// Offset into blob string table for enum name
    pub name_offset: u32,
    /// Number of enum values
    pub value_count: u16,
    /// Index of first value in enum option table
    pub first_value_index: u16,
}

impl EnumDefinition {
    pub const RECORD_SIZE: usize = 8;
}

/// Data mapping entry - maps struct definitions to data instances
#[derive(Debug, Clone)]
pub struct DataMapping {
    /// Index into struct table
    pub struct_index: u32,
    /// Number of instances
    pub struct_count: u32,
}

impl DataMapping {
    pub const RECORD_SIZE_LEGACY: usize = 4;
    pub const RECORD_SIZE_V6: usize = 8;
}

/// Record definition entry - top-level data records
#[derive(Debug, Clone)]
pub struct RecordDefinition {
    /// Offset for record name in blob table
    pub name_offset: u32,
    /// Offset for file path in text table (absent in legacy)
    pub file_name_offset: u32,
    /// Struct type index
    pub struct_index: u32,
    /// GUID reference hash
    pub hash: DataForgeGuid,
    /// Instance index within the struct array
    pub variant_index: u16,
    /// Additional index
    pub other_index: u16,
}

impl RecordDefinition {
    pub const RECORD_SIZE: usize = 32;
    pub const RECORD_SIZE_LEGACY: usize = 28; // Without file_name_offset
}
