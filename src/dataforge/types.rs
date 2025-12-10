//! Data types and enumerations for DataForge format

/// Data type enumeration for property values
/// 
/// Corresponds to EDataType in the C# implementation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DataType {
    Boolean = 0x0001,
    Int8 = 0x0002,
    Int16 = 0x0003,
    Int32 = 0x0004,
    Int64 = 0x0005,
    UInt8 = 0x0006,
    UInt16 = 0x0007,
    UInt32 = 0x0008,
    UInt64 = 0x0009,
    String = 0x000A,
    Single = 0x000B,
    Double = 0x000C,
    Locale = 0x000D,
    Guid = 0x000E,
    Enum = 0x000F,
    Class = 0x0010,
    StrongPointer = 0x0110,
    WeakPointer = 0x0210,
    Reference = 0x0310,
    Unknown(u16),
}

impl From<u16> for DataType {
    fn from(value: u16) -> Self {
        match value {
            0x0001 => DataType::Boolean,
            0x0002 => DataType::Int8,
            0x0003 => DataType::Int16,
            0x0004 => DataType::Int32,
            0x0005 => DataType::Int64,
            0x0006 => DataType::UInt8,
            0x0007 => DataType::UInt16,
            0x0008 => DataType::UInt32,
            0x0009 => DataType::UInt64,
            0x000A => DataType::String,
            0x000B => DataType::Single,
            0x000C => DataType::Double,
            0x000D => DataType::Locale,
            0x000E => DataType::Guid,
            0x000F => DataType::Enum,
            0x0010 => DataType::Class,
            0x0110 => DataType::StrongPointer,
            0x0210 => DataType::WeakPointer,
            0x0310 => DataType::Reference,
            v => DataType::Unknown(v),
        }
    }
}

/// Conversion type for how properties are stored
/// 
/// Corresponds to EConversionType in the C# implementation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ConversionType {
    /// Direct attribute value
    Attribute = 0x00,
    /// Complex array
    ComplexArray = 0x01,
    /// Simple array
    SimpleArray = 0x02,
    /// Class array
    ClassArray = 0x03,
    Unknown(u16),
}

impl From<u16> for ConversionType {
    fn from(value: u16) -> Self {
        match value & 0xFF {
            0x00 => ConversionType::Attribute,
            0x01 => ConversionType::ComplexArray,
            0x02 => ConversionType::SimpleArray,
            0x03 => ConversionType::ClassArray,
            v => ConversionType::Unknown(v as u16),
        }
    }
}

/// A GUID value with custom byte ordering as used by CryEngine
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DataForgeGuid {
    pub bytes: [u8; 16],
}

impl DataForgeGuid {
    pub const EMPTY: DataForgeGuid = DataForgeGuid { bytes: [0; 16] };

    pub fn is_empty(&self) -> bool {
        self.bytes == [0; 16]
    }

    /// Format as standard GUID string
    pub fn to_string(&self) -> String {
        // CryEngine GUID byte order is different from standard
        // a(4) b(2) c(2) d e f g h i j k
        let a = u32::from_le_bytes([self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3]]);
        let b = u16::from_le_bytes([self.bytes[4], self.bytes[5]]);
        let c = u16::from_le_bytes([self.bytes[6], self.bytes[7]]);
        
        format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            a, b, c,
            self.bytes[8], self.bytes[9],
            self.bytes[10], self.bytes[11], self.bytes[12], 
            self.bytes[13], self.bytes[14], self.bytes[15]
        )
    }
}

/// A pointer to another struct instance
#[derive(Debug, Clone, Copy, Default)]
pub struct DataForgePointer {
    pub struct_index: u32,
    pub variant_index: u16,
    pub padding: u16,
}

impl DataForgePointer {
    pub const RECORD_SIZE: usize = 8;

    pub fn is_null(&self) -> bool {
        self.struct_index == 0xFFFFFFFF && self.variant_index == 0xFFFF
    }
}

/// A reference to another record
#[derive(Debug, Clone, Copy, Default)]
pub struct DataForgeReference {
    pub item1: u32,
    pub value: DataForgeGuid,
}

impl DataForgeReference {
    pub const RECORD_SIZE: usize = 20;

    pub fn is_null(&self) -> bool {
        self.value.is_empty()
    }
}

/// String lookup entry (offset into string table)
#[derive(Debug, Clone, Copy, Default)]
pub struct StringLookup {
    pub offset: u32,
}

impl StringLookup {
    pub const RECORD_SIZE: usize = 4;
}
