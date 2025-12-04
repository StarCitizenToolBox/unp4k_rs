//! CryXML binary format parser
//!
//! CryXML is a binary XML format used by CryEngine-based games like Star Citizen.
//! This module provides functionality to convert CryXML binary data to standard XML.
//!
//! ## Format Overview
//!
//! CryXML files start with a header ("CryXml", "CryXmlB", or "CRY3SDK") followed by:
//! - File metadata (length, offsets, counts)
//! - Node table
//! - Attribute table
//! - Child/parent relationship table
//! - String data table
//!
//! The format supports both big-endian and little-endian byte ordering.

use std::io::{Read, Seek, SeekFrom, Cursor};
use std::collections::HashMap;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use crate::error::{Error, Result};

/// Byte order for CryXML files
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteOrder {
    BigEndian,
    LittleEndian,
}

/// A CryXML node
#[derive(Debug, Clone)]
struct CryXmlNode {
    node_id: i32,
    node_name_offset: i32,
    content_offset: i32,
    attribute_count: i16,
    child_count: i16,
    parent_node_id: i32,
    #[allow(dead_code)]
    first_attribute_index: i32,
    #[allow(dead_code)]
    first_child_index: i32,
    _reserved: i32,
}

/// A CryXML attribute
#[derive(Debug, Clone)]
struct CryXmlAttribute {
    name_offset: i32,
    value_offset: i32,
}

/// CryXML reader for parsing binary CryXML files
pub struct CryXmlReader;

impl CryXmlReader {
    /// Check if data is a CryXML file
    pub fn is_cryxml(data: &[u8]) -> bool {
        if data.len() < 7 {
            return false;
        }
        
        // Check for known headers
        data.starts_with(b"CryXml") || 
        data.starts_with(b"CryXmlB") || 
        data.starts_with(b"CRY3SDK")
    }

    /// Check if data is already plain XML
    pub fn is_plain_xml(data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        // Check for XML declaration or root element
        data.starts_with(b"<?xml") || data.starts_with(b"<")
    }

    /// Parse CryXML binary data and convert to XML string
    pub fn parse(data: &[u8]) -> Result<String> {
        if data.is_empty() {
            return Err(Error::InvalidCryXml("Empty data".to_string()));
        }

        // Check if already XML
        if Self::is_plain_xml(data) {
            return Ok(String::from_utf8_lossy(data).to_string());
        }

        let mut cursor = Cursor::new(data);
        
        // Read and validate header
        let mut header = [0u8; 7];
        cursor.read_exact(&mut header)?;
        
        let header_str = String::from_utf8_lossy(&header);
        
        let header_len = if header_str.starts_with("CryXml") || header_str.starts_with("CryXmlB") {
            // Read null terminator
            Self::read_cstring(&mut cursor)?;
            cursor.position()
        } else if header_str.starts_with("CRY3SDK") {
            // Skip additional bytes
            cursor.seek(SeekFrom::Current(2))?;
            cursor.position()
        } else {
            return Err(Error::InvalidCryXml(format!("Unknown header: {}", header_str)));
        };

        // Detect byte order
        let byte_order = Self::detect_byte_order(&mut cursor, header_len as i64)?;
        
        // Read file structure info
        cursor.seek(SeekFrom::Start(header_len))?;
        
        let _file_length = Self::read_i32(&mut cursor, byte_order)?;
        let node_table_offset = Self::read_i32(&mut cursor, byte_order)?;
        let node_table_count = Self::read_i32(&mut cursor, byte_order)?;
        let attribute_table_offset = Self::read_i32(&mut cursor, byte_order)?;
        let attribute_table_count = Self::read_i32(&mut cursor, byte_order)?;
        let child_table_offset = Self::read_i32(&mut cursor, byte_order)?;
        let child_table_count = Self::read_i32(&mut cursor, byte_order)?;
        let string_table_offset = Self::read_i32(&mut cursor, byte_order)?;
        let _string_table_count = Self::read_i32(&mut cursor, byte_order)?;

        // Read node table
        cursor.seek(SeekFrom::Start(node_table_offset as u64))?;
        let mut nodes = Vec::with_capacity(node_table_count as usize);
        
        for i in 0..node_table_count {
            let node = CryXmlNode {
                node_id: i,
                node_name_offset: Self::read_i32(&mut cursor, byte_order)?,
                content_offset: Self::read_i32(&mut cursor, byte_order)?,
                attribute_count: Self::read_i16(&mut cursor, byte_order)?,
                child_count: Self::read_i16(&mut cursor, byte_order)?,
                parent_node_id: Self::read_i32(&mut cursor, byte_order)?,
                first_attribute_index: Self::read_i32(&mut cursor, byte_order)?,
                first_child_index: Self::read_i32(&mut cursor, byte_order)?,
                _reserved: Self::read_i32(&mut cursor, byte_order)?,
            };
            nodes.push(node);
        }

        // Read attribute table
        cursor.seek(SeekFrom::Start(attribute_table_offset as u64))?;
        let mut attributes = Vec::with_capacity(attribute_table_count as usize);
        
        for _ in 0..attribute_table_count {
            let attr = CryXmlAttribute {
                name_offset: Self::read_i32(&mut cursor, byte_order)?,
                value_offset: Self::read_i32(&mut cursor, byte_order)?,
            };
            attributes.push(attr);
        }

        // Read child/parent table (not used directly, relationships are in nodes)
        cursor.seek(SeekFrom::Start(child_table_offset as u64))?;
        let mut _parent_table = Vec::with_capacity(child_table_count as usize);
        for _ in 0..child_table_count {
            _parent_table.push(Self::read_i32(&mut cursor, byte_order)?);
        }

        // Read string table
        cursor.seek(SeekFrom::Start(string_table_offset as u64))?;
        let mut string_data = HashMap::new();
        
        while cursor.position() < data.len() as u64 {
            let offset = (cursor.position() - string_table_offset as u64) as i32;
            let string_value = Self::read_cstring(&mut cursor)?;
            if !string_value.is_empty() {
                string_data.insert(offset, string_value);
            }
        }

        // Build XML
        Self::build_xml(&nodes, &attributes, &string_data)
    }

    fn detect_byte_order(cursor: &mut Cursor<&[u8]>, header_len: i64) -> Result<ByteOrder> {
        cursor.seek(SeekFrom::Start(header_len as u64))?;
        
        // Read file length in big endian
        let file_length_be = cursor.read_i32::<BigEndian>()?;
        
        // Compare with actual data length
        let data_len = cursor.get_ref().len() as i32;
        
        if file_length_be == data_len {
            Ok(ByteOrder::BigEndian)
        } else {
            // Try little endian
            cursor.seek(SeekFrom::Start(header_len as u64))?;
            let file_length_le = cursor.read_i32::<LittleEndian>()?;
            
            if file_length_le == data_len {
                Ok(ByteOrder::LittleEndian)
            } else {
                // Default to big endian if neither matches exactly
                Ok(ByteOrder::BigEndian)
            }
        }
    }

    fn read_i32(cursor: &mut Cursor<&[u8]>, byte_order: ByteOrder) -> Result<i32> {
        Ok(match byte_order {
            ByteOrder::BigEndian => cursor.read_i32::<BigEndian>()?,
            ByteOrder::LittleEndian => cursor.read_i32::<LittleEndian>()?,
        })
    }

    fn read_i16(cursor: &mut Cursor<&[u8]>, byte_order: ByteOrder) -> Result<i16> {
        Ok(match byte_order {
            ByteOrder::BigEndian => cursor.read_i16::<BigEndian>()?,
            ByteOrder::LittleEndian => cursor.read_i16::<LittleEndian>()?,
        })
    }

    fn read_cstring(cursor: &mut Cursor<&[u8]>) -> Result<String> {
        let mut bytes = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            if cursor.read_exact(&mut byte).is_err() {
                break;
            }
            if byte[0] == 0 {
                break;
            }
            bytes.push(byte[0]);
        }
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }

    fn build_xml(
        nodes: &[CryXmlNode],
        attributes: &[CryXmlAttribute],
        string_data: &HashMap<i32, String>,
    ) -> Result<String> {
        if nodes.is_empty() {
            return Ok(String::new());
        }

        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
        let mut xml_elements: HashMap<i32, String> = HashMap::new();
        let mut attribute_index = 0;

        // First pass: create all elements with their attributes
        for node in nodes {
            let element_name = string_data
                .get(&node.node_name_offset)
                .cloned()
                .unwrap_or_else(|| format!("unknown_{}", node.node_id));

            let mut element = format!("<{}", Self::escape_xml_name(&element_name));

            // Add attributes
            for _ in 0..node.attribute_count {
                if attribute_index < attributes.len() {
                    let attr = &attributes[attribute_index];
                    let attr_name = string_data
                        .get(&attr.name_offset)
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string());
                    let attr_value = string_data
                        .get(&attr.value_offset)
                        .cloned()
                        .unwrap_or_default();
                    
                    element.push_str(&format!(
                        " {}=\"{}\"",
                        Self::escape_xml_name(&attr_name),
                        Self::escape_xml_value(&attr_value)
                    ));
                    attribute_index += 1;
                }
            }

            // Add content if present
            let content = if node.content_offset >= 0 {
                string_data.get(&node.content_offset).cloned()
            } else {
                None
            };

            if node.child_count == 0 && content.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                element.push_str("/>");
            } else {
                element.push('>');
                if let Some(ref c) = content {
                    if !c.is_empty() {
                        element.push_str(&Self::escape_xml_content(c));
                    }
                }
            }

            xml_elements.insert(node.node_id, element);
        }

        // Build tree structure
        let mut children: HashMap<i32, Vec<i32>> = HashMap::new();
        for node in nodes {
            if node.parent_node_id >= 0 {
                children
                    .entry(node.parent_node_id)
                    .or_default()
                    .push(node.node_id);
            }
        }

        // Recursive function to build XML tree
        fn build_node(
            node_id: i32,
            nodes: &[CryXmlNode],
            xml_elements: &HashMap<i32, String>,
            children: &HashMap<i32, Vec<i32>>,
            string_data: &HashMap<i32, String>,
            indent: usize,
        ) -> String {
            let node = &nodes[node_id as usize];
            let element = xml_elements.get(&node_id).unwrap();
            let indent_str = "  ".repeat(indent);
            
            let element_name = string_data
                .get(&node.node_name_offset)
                .cloned()
                .unwrap_or_else(|| format!("unknown_{}", node.node_id));

            if element.ends_with("/>") {
                return format!("{}{}\n", indent_str, element);
            }

            let mut result = format!("{}{}", indent_str, element);

            if let Some(child_ids) = children.get(&node_id) {
                result.push('\n');
                for child_id in child_ids {
                    result.push_str(&build_node(
                        *child_id,
                        nodes,
                        xml_elements,
                        children,
                        string_data,
                        indent + 1,
                    ));
                }
                result.push_str(&format!("{}</{}>\n", indent_str, CryXmlReader::escape_xml_name(&element_name)));
            } else {
                result.push_str(&format!("</{}>\n", CryXmlReader::escape_xml_name(&element_name)));
            }

            result
        }

        // Find root nodes (nodes with no parent or parent = -1)
        for node in nodes {
            if node.parent_node_id < 0 {
                xml.push_str(&build_node(
                    node.node_id,
                    nodes,
                    &xml_elements,
                    &children,
                    string_data,
                    0,
                ));
            }
        }

        Ok(xml)
    }

    fn escape_xml_name(s: &str) -> String {
        // XML element/attribute names can't start with numbers
        // Replace invalid characters
        let mut result = String::with_capacity(s.len());
        for (i, c) in s.chars().enumerate() {
            if i == 0 && c.is_ascii_digit() {
                result.push('_');
            }
            if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' {
                result.push(c);
            } else {
                result.push('_');
            }
        }
        if result.is_empty() {
            result.push_str("_unnamed");
        }
        result
    }

    fn escape_xml_value(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }

    fn escape_xml_content(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_cryxml() {
        assert!(CryXmlReader::is_cryxml(b"CryXml\x00test"));
        assert!(CryXmlReader::is_cryxml(b"CryXmlB\x00test"));
        assert!(CryXmlReader::is_cryxml(b"CRY3SDKtest"));
        assert!(!CryXmlReader::is_cryxml(b"<?xml"));
        assert!(!CryXmlReader::is_cryxml(b"<root>"));
    }

    #[test]
    fn test_is_plain_xml() {
        assert!(CryXmlReader::is_plain_xml(b"<?xml version=\"1.0\"?>"));
        assert!(CryXmlReader::is_plain_xml(b"<root>"));
        assert!(!CryXmlReader::is_plain_xml(b"CryXml"));
    }

    #[test]
    fn test_escape_xml_value() {
        assert_eq!(
            CryXmlReader::escape_xml_value("test & <value>"),
            "test &amp; &lt;value&gt;"
        );
    }
}
