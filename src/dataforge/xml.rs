//! XML output generation for DataForge records
//!
//! Uses quick-xml library for proper XML construction.

use byteorder::{LittleEndian, ReadBytesExt};
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read, Seek, SeekFrom};

use crate::dataforge::definitions::*;
use crate::dataforge::reader::DataForge;
use crate::dataforge::types::*;
use crate::error::{Error, Result};

/// Maximum depth for following pointers (prevent infinite loops)
const MAX_POINTER_DEPTH: usize = 100;

/// Maximum nodes to output (prevent huge files)
const MAX_NODES: usize = 100000;

/// XML Element representation
#[derive(Debug, Clone)]
struct XmlElement {
    name: String,
    attributes: Vec<(String, String)>,
    children: Vec<XmlNode>,
}

/// XML Node - can be an element or text
#[derive(Debug, Clone)]
enum XmlNode {
    Element(XmlElement),
    Text(String),
}

impl XmlElement {
    fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            attributes: Vec::new(),
            children: Vec::new(),
        }
    }

    #[allow(unused)]
    fn with_attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.push((key.into(), value.into()));
        self
    }

    fn add_attr(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.attributes.push((key.into(), value.into()));
    }

    fn add_child(&mut self, child: XmlNode) {
        self.children.push(child);
    }

    fn add_element(&mut self, element: XmlElement) {
        self.children.push(XmlNode::Element(element));
    }

    #[allow(unused)]
    fn is_empty(&self) -> bool {
        self.attributes.is_empty() && self.children.is_empty()
    }

    #[allow(unused)]
    fn has_children(&self) -> bool {
        !self.children.is_empty()
    }
}

impl DataForge {
    /// Convert a record to XML by path
    ///
    /// # Arguments
    /// * `path` - The record path to convert
    /// * `format_xml` - If true, format XML with indentation for human readability (default: false)
    pub fn record_to_xml(&self, path: &str, format_xml: bool) -> Result<String> {
        let record_idx = self
            .path_to_record()
            .get(path)
            .ok_or_else(|| Error::InvalidDataForge(format!("Record not found: {}", path)))?;

        self.record_to_xml_by_index(*record_idx, format_xml)
    }

    /// Convert a record to XML by index
    ///
    /// # Arguments
    /// * `index` - The record index to convert
    /// * `format_xml` - If true, format XML with indentation for human readability (default: false)
    pub fn record_to_xml_by_index(&self, index: usize, format_xml: bool) -> Result<String> {
        if index >= self.record_definitions().len() {
            return Err(Error::InvalidDataForge(format!(
                "Record index {} out of range",
                index
            )));
        }

        let record = &self.record_definitions()[index];
        let struct_def = &self.struct_definitions()[record.struct_index as usize];

        let record_name = self.read_blob_at_offset(record.name_offset as u64)?;
        let struct_name = self.read_blob_at_offset(struct_def.name_offset as u64)?;
        let file_name = self.read_text_at_offset(record.file_name_offset as u64)?;

        let mut ctx = XmlContext::new(self);

        // Build root element
        let mut root = XmlElement::new(&record_name);
        root.add_attr("__type", &struct_name);
        root.add_attr("__ref", record.hash.to_string());
        root.add_attr("__path", &file_name);

        // Add struct content (attributes and children)
        ctx.build_struct_content(&mut root, record.struct_index, record.variant_index as u32)?;

        // Serialize to XML string
        let xml = Self::serialize_xml(&root, format_xml)?;
        Ok(xml)
    }

    /// Convert all records to XML (returns a map of path -> XML)
    ///
    /// # Arguments
    /// * `format_xml` - If true, format XML with indentation for human readability (default: false)
    pub fn extract_all_to_memory(&self, format_xml: bool) -> Result<HashMap<String, String>> {
        let mut results = HashMap::new();

        for (path, &idx) in self.path_to_record() {
            match self.record_to_xml_by_index(idx, format_xml) {
                Ok(xml) => {
                    results.insert(path.clone(), xml);
                }
                Err(e) => {
                    // Log error but continue with other records
                    eprintln!("Warning: Failed to convert {}: {}", path, e);
                }
            }
        }

        Ok(results)
    }

    /// Serialize an XmlElement to string using quick-xml
    fn serialize_xml(element: &XmlElement, format: bool) -> Result<String> {
        let mut buffer = Vec::new();

        {
            let mut writer = if format {
                Writer::new_with_indent(&mut buffer, b' ', 2)
            } else {
                Writer::new(&mut buffer)
            };

            // Write XML declaration
            writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("utf-8"), None)))?;
            if format {
                writer.write_event(Event::Text(BytesText::new("\n")))?;
            }

            // Write root element
            Self::write_element(&mut writer, element)?;
        }

        String::from_utf8(buffer).map_err(|e| Error::InvalidDataForge(e.to_string()))
    }

    /// Write an XmlElement to the writer
    fn write_element<W: std::io::Write>(
        writer: &mut Writer<W>,
        element: &XmlElement,
    ) -> Result<()> {
        let mut start = BytesStart::new(&element.name);

        // Add attributes
        for (key, value) in &element.attributes {
            start.push_attribute((key.as_str(), value.as_str()));
        }

        if element.children.is_empty() {
            // Self-closing tag
            writer.write_event(Event::Empty(start))?;
        } else {
            // Opening tag
            writer.write_event(Event::Start(start))?;

            // Write children
            for child in &element.children {
                match child {
                    XmlNode::Element(elem) => {
                        Self::write_element(writer, elem)?;
                    }
                    XmlNode::Text(text) => {
                        writer.write_event(Event::Text(BytesText::new(text)))?;
                    }
                }
            }

            // Closing tag
            writer.write_event(Event::End(BytesEnd::new(&element.name)))?;
        }

        Ok(())
    }
}

/// Context for XML generation (tracks visited structs to prevent loops)
struct XmlContext<'a> {
    df: &'a DataForge,
    struct_stack: HashSet<(u32, u32)>,
    node_count: usize,
}

impl<'a> XmlContext<'a> {
    fn new(df: &'a DataForge) -> Self {
        Self {
            df,
            struct_stack: HashSet::new(),
            node_count: 0,
        }
    }

    /// Build struct content and add to parent element
    fn build_struct_content(
        &mut self,
        parent: &mut XmlElement,
        struct_index: u32,
        variant_index: u32,
    ) -> Result<()> {
        // Check for recursion
        let key = (struct_index, variant_index);
        if self.struct_stack.contains(&key) || self.struct_stack.len() > MAX_POINTER_DEPTH {
            return Ok(());
        }
        self.struct_stack.insert(key);

        // Get struct definition and data offset
        let struct_def = &self.df.struct_definitions()[struct_index as usize];

        let data_offset = match self.df.struct_to_data_offset().get(&struct_index) {
            Some(&offset) => {
                self.df.data_offset()
                    + offset
                    + (struct_def.record_size as u64 * variant_index as u64)
            }
            None => {
                self.struct_stack.remove(&key);
                return Ok(());
            }
        };

        // Read all properties
        let mut cursor = Cursor::new(self.df.data());
        cursor.seek(SeekFrom::Start(data_offset))?;

        // Get all properties including inherited ones
        let properties = self.get_all_properties(struct_index)?;

        for prop_idx in properties {
            if self.node_count >= MAX_NODES {
                break;
            }

            let prop = &self.df.property_definitions()[prop_idx];
            let prop_name = self.df.read_blob_at_offset(prop.name_offset as u64)?;

            match prop.conversion_type {
                ConversionType::Attribute => {
                    self.read_attribute_value(parent, &mut cursor, prop, &prop_name)?;
                    self.node_count += 1;
                }
                _ => {
                    self.read_array_value(parent, &mut cursor, prop, &prop_name)?;
                }
            }
        }

        self.struct_stack.remove(&key);
        Ok(())
    }

    /// Build struct and return as XmlElement
    fn build_struct_element(
        &mut self,
        name: &str,
        struct_index: u32,
        variant_index: u32,
    ) -> Result<XmlElement> {
        let mut element = XmlElement::new(name);
        self.build_struct_content(&mut element, struct_index, variant_index)?;
        Ok(element)
    }

    /// Build inline struct content at current cursor position
    fn build_inline_struct_content(
        &mut self,
        parent: &mut XmlElement,
        cursor: &mut Cursor<&[u8]>,
        struct_index: u32,
    ) -> Result<()> {
        // Check for recursion
        let key = (struct_index, 0xFFFFFFFF);
        if self.struct_stack.contains(&key) || self.struct_stack.len() > MAX_POINTER_DEPTH {
            return Ok(());
        }
        self.struct_stack.insert(key);

        // Get all properties including inherited ones
        let properties = self.get_all_properties(struct_index)?;

        for prop_idx in properties {
            if self.node_count >= MAX_NODES {
                break;
            }

            let prop = &self.df.property_definitions()[prop_idx];
            let prop_name = self.df.read_blob_at_offset(prop.name_offset as u64)?;

            match prop.conversion_type {
                ConversionType::Attribute => {
                    self.read_attribute_value(parent, cursor, prop, &prop_name)?;
                    self.node_count += 1;
                }
                _ => {
                    self.read_array_value(parent, cursor, prop, &prop_name)?;
                }
            }
        }

        self.struct_stack.remove(&key);
        Ok(())
    }

    fn get_all_properties(&self, struct_index: u32) -> Result<Vec<usize>> {
        let mut props = Vec::new();
        let mut indices = Vec::new();

        // Collect struct hierarchy
        let mut current_idx = Some(struct_index);
        while let Some(idx) = current_idx {
            indices.push(idx);
            let struct_def = &self.df.struct_definitions()[idx as usize];
            current_idx = if struct_def.has_parent() {
                Some(struct_def.parent_type_index)
            } else {
                None
            };
        }

        // Reverse to get parent-first order
        indices.reverse();

        // Collect all properties
        for idx in indices {
            let struct_def = &self.df.struct_definitions()[idx as usize];
            for i in 0..struct_def.property_count {
                props.push((struct_def.first_property_index + i) as usize);
            }
        }

        Ok(props)
    }

    /// Read an attribute value and add to parent element
    fn read_attribute_value(
        &mut self,
        parent: &mut XmlElement,
        cursor: &mut Cursor<&[u8]>,
        prop: &PropertyDefinition,
        name: &str,
    ) -> Result<()> {
        match prop.data_type {
            DataType::Boolean => {
                let val = cursor.read_u8()? != 0;
                parent.add_attr(name, if val { "1" } else { "0" });
            }
            DataType::Int8 => {
                let val = cursor.read_i8()?;
                parent.add_attr(name, val.to_string());
            }
            DataType::Int16 => {
                let val = cursor.read_i16::<LittleEndian>()?;
                parent.add_attr(name, val.to_string());
            }
            DataType::Int32 => {
                let val = cursor.read_i32::<LittleEndian>()?;
                parent.add_attr(name, val.to_string());
            }
            DataType::Int64 => {
                let val = cursor.read_i64::<LittleEndian>()?;
                parent.add_attr(name, val.to_string());
            }
            DataType::UInt8 => {
                let val = cursor.read_u8()?;
                parent.add_attr(name, val.to_string());
            }
            DataType::UInt16 => {
                let val = cursor.read_u16::<LittleEndian>()?;
                parent.add_attr(name, val.to_string());
            }
            DataType::UInt32 => {
                let val = cursor.read_u32::<LittleEndian>()?;
                parent.add_attr(name, val.to_string());
            }
            DataType::UInt64 => {
                let val = cursor.read_u64::<LittleEndian>()?;
                parent.add_attr(name, val.to_string());
            }
            DataType::Single => {
                let val = cursor.read_f32::<LittleEndian>()?;
                parent.add_attr(name, val.to_string());
            }
            DataType::Double => {
                let val = cursor.read_f64::<LittleEndian>()?;
                parent.add_attr(name, val.to_string());
            }
            DataType::Guid => {
                let mut bytes = [0u8; 16];
                cursor.read_exact(&mut bytes)?;
                let guid = DataForgeGuid { bytes };
                parent.add_attr(name, guid.to_string());
            }
            DataType::String => {
                let offset = cursor.read_u32::<LittleEndian>()?;
                let val = self.df.read_text_at_offset(offset as u64)?;
                parent.add_attr(name, val);
            }
            DataType::Locale => {
                let offset = cursor.read_u32::<LittleEndian>()?;
                let val = self.df.read_text_at_offset(offset as u64)?;
                parent.add_attr(name, val);
            }
            DataType::Enum => {
                let offset = cursor.read_u32::<LittleEndian>()?;
                let val = self.df.read_text_at_offset(offset as u64)?;
                parent.add_attr(name, val);
            }
            DataType::Reference => {
                let _item1 = cursor.read_u32::<LittleEndian>()?;
                let mut bytes = [0u8; 16];
                cursor.read_exact(&mut bytes)?;
                let guid = DataForgeGuid { bytes };
                if guid.is_empty() {
                    parent.add_attr(name, "null");
                } else {
                    parent.add_attr(name, guid.to_string());
                }
            }
            DataType::StrongPointer | DataType::WeakPointer => {
                let struct_idx = cursor.read_u32::<LittleEndian>()?;
                let variant_idx = cursor.read_u16::<LittleEndian>()?;
                let _padding = cursor.read_u16::<LittleEndian>()?;

                if struct_idx == 0xFFFFFFFF {
                    parent.add_attr(name, "null");
                } else {
                    let struct_name = self.df.get_struct_name(struct_idx as usize)?;
                    parent.add_attr(name, format!("{}[{:04X}]", struct_name, variant_idx));
                }
            }
            DataType::Class => {
                // Inline class - add as child element
                let mut child = XmlElement::new(name);
                self.build_inline_struct_content(&mut child, cursor, prop.index as u32)?;
                parent.add_element(child);
            }
            DataType::Unknown(t) => {
                parent.add_attr(name, format!("Unknown type {}", t));
            }
        }

        Ok(())
    }

    /// Read an array value and add to parent element
    fn read_array_value(
        &mut self,
        parent: &mut XmlElement,
        cursor: &mut Cursor<&[u8]>,
        prop: &PropertyDefinition,
        name: &str,
    ) -> Result<()> {
        let array_count = cursor.read_u32::<LittleEndian>()?;
        let first_index = cursor.read_u32::<LittleEndian>()?;

        if array_count == 0 {
            return Ok(());
        }

        let mut container = XmlElement::new(name);

        for i in 0..array_count.min(MAX_NODES as u32) {
            if self.node_count >= MAX_NODES {
                break;
            }

            let item = self.read_array_item(prop, first_index, i as u16)?;
            container.add_child(item);
            self.node_count += 1;
        }

        parent.add_element(container);
        Ok(())
    }

    fn read_array_item(
        &mut self,
        prop: &PropertyDefinition,
        first_index: u32,
        offset: u16,
    ) -> Result<XmlNode> {
        let index = first_index as u64 + offset as u64;

        match prop.data_type {
            DataType::Boolean => {
                let val: bool = self
                    .df
                    .read_value_at(self.df.boolean_value_offset() + index)?;
                let mut elem = XmlElement::new("Boolean");
                elem.add_child(XmlNode::Text(if val { "1" } else { "0" }.to_string()));
                Ok(XmlNode::Element(elem))
            }
            DataType::Int8 => {
                let val: i8 = self.df.read_value_at(self.df.int8_value_offset() + index)?;
                let mut elem = XmlElement::new("Int8");
                elem.add_child(XmlNode::Text(val.to_string()));
                Ok(XmlNode::Element(elem))
            }
            DataType::Int16 => {
                let val: i16 = self
                    .df
                    .read_value_at(self.df.int16_value_offset() + index * 2)?;
                let mut elem = XmlElement::new("Int16");
                elem.add_child(XmlNode::Text(val.to_string()));
                Ok(XmlNode::Element(elem))
            }
            DataType::Int32 => {
                let val: i32 = self
                    .df
                    .read_value_at(self.df.int32_value_offset() + index * 4)?;
                let mut elem = XmlElement::new("Int32");
                elem.add_child(XmlNode::Text(val.to_string()));
                Ok(XmlNode::Element(elem))
            }
            DataType::Int64 => {
                let val: i64 = self
                    .df
                    .read_value_at(self.df.int64_value_offset() + index * 8)?;
                let mut elem = XmlElement::new("Int64");
                elem.add_child(XmlNode::Text(val.to_string()));
                Ok(XmlNode::Element(elem))
            }
            DataType::UInt8 => {
                let val: u8 = self
                    .df
                    .read_value_at(self.df.uint8_value_offset() + index)?;
                let mut elem = XmlElement::new("UInt8");
                elem.add_child(XmlNode::Text(val.to_string()));
                Ok(XmlNode::Element(elem))
            }
            DataType::UInt16 => {
                let val: u16 = self
                    .df
                    .read_value_at(self.df.uint16_value_offset() + index * 2)?;
                let mut elem = XmlElement::new("UInt16");
                elem.add_child(XmlNode::Text(val.to_string()));
                Ok(XmlNode::Element(elem))
            }
            DataType::UInt32 => {
                let val: u32 = self
                    .df
                    .read_value_at(self.df.uint32_value_offset() + index * 4)?;
                let mut elem = XmlElement::new("UInt32");
                elem.add_child(XmlNode::Text(val.to_string()));
                Ok(XmlNode::Element(elem))
            }
            DataType::UInt64 => {
                let val: u64 = self
                    .df
                    .read_value_at(self.df.uint64_value_offset() + index * 8)?;
                let mut elem = XmlElement::new("UInt64");
                elem.add_child(XmlNode::Text(val.to_string()));
                Ok(XmlNode::Element(elem))
            }
            DataType::Single => {
                let val: f32 = self
                    .df
                    .read_value_at(self.df.single_value_offset() + index * 4)?;
                let mut elem = XmlElement::new("Single");
                elem.add_child(XmlNode::Text(val.to_string()));
                Ok(XmlNode::Element(elem))
            }
            DataType::Double => {
                let val: f64 = self
                    .df
                    .read_value_at(self.df.double_value_offset() + index * 8)?;
                let mut elem = XmlElement::new("Double");
                elem.add_child(XmlNode::Text(val.to_string()));
                Ok(XmlNode::Element(elem))
            }
            DataType::String => {
                let str_offset: u32 = self
                    .df
                    .read_value_at(self.df.string_value_offset() + index * 4)?;
                let val = self.df.read_text_at_offset(str_offset as u64)?;
                let mut elem = XmlElement::new("String");
                elem.add_child(XmlNode::Text(val));
                Ok(XmlNode::Element(elem))
            }
            DataType::Locale => {
                let str_offset: u32 = self
                    .df
                    .read_value_at(self.df.locale_value_offset() + index * 4)?;
                let val = self.df.read_text_at_offset(str_offset as u64)?;
                let mut elem = XmlElement::new("Locale");
                elem.add_child(XmlNode::Text(val));
                Ok(XmlNode::Element(elem))
            }
            DataType::Enum => {
                let str_offset: u32 = self
                    .df
                    .read_value_at(self.df.enum_value_offset() + index * 4)?;
                let val = self.df.read_text_at_offset(str_offset as u64)?;
                let mut elem = XmlElement::new("Enum");
                elem.add_child(XmlNode::Text(val));
                Ok(XmlNode::Element(elem))
            }
            DataType::Guid => {
                let offset = self.df.guid_value_offset() + index * 16;
                let bytes: [u8; 16] = [
                    self.df.data()[offset as usize],
                    self.df.data()[offset as usize + 1],
                    self.df.data()[offset as usize + 2],
                    self.df.data()[offset as usize + 3],
                    self.df.data()[offset as usize + 4],
                    self.df.data()[offset as usize + 5],
                    self.df.data()[offset as usize + 6],
                    self.df.data()[offset as usize + 7],
                    self.df.data()[offset as usize + 8],
                    self.df.data()[offset as usize + 9],
                    self.df.data()[offset as usize + 10],
                    self.df.data()[offset as usize + 11],
                    self.df.data()[offset as usize + 12],
                    self.df.data()[offset as usize + 13],
                    self.df.data()[offset as usize + 14],
                    self.df.data()[offset as usize + 15],
                ];
                let guid = DataForgeGuid { bytes };
                let mut elem = XmlElement::new("Guid");
                elem.add_child(XmlNode::Text(guid.to_string()));
                Ok(XmlNode::Element(elem))
            }
            DataType::Class => {
                // Array of structs
                let mapping = &self.df.data_mappings()[prop.index as usize];
                let struct_name = self.df.get_struct_name(mapping.struct_index as usize)?;
                let element = self.build_struct_element(
                    &struct_name,
                    prop.index as u32,
                    first_index + offset as u32,
                )?;
                Ok(XmlNode::Element(element))
            }
            DataType::StrongPointer => {
                let offset = self.df.strong_value_offset() + index * 8;
                let struct_idx: u32 = self.df.read_value_at(offset)?;
                let variant_idx: u16 = self.df.read_value_at(offset + 4)?;

                if struct_idx == 0xFFFFFFFF {
                    let mut elem = XmlElement::new("StrongPointer");
                    elem.add_child(XmlNode::Text("null".to_string()));
                    Ok(XmlNode::Element(elem))
                } else {
                    let struct_name = self.df.get_struct_name(struct_idx as usize)?;
                    let element =
                        self.build_struct_element(&struct_name, struct_idx, variant_idx as u32)?;
                    Ok(XmlNode::Element(element))
                }
            }
            DataType::WeakPointer => {
                let offset = self.df.weak_value_offset() + index * 8;
                let struct_idx: u32 = self.df.read_value_at(offset)?;
                let variant_idx: u16 = self.df.read_value_at(offset + 4)?;

                let mut elem = XmlElement::new("WeakPointer");
                if struct_idx == 0xFFFFFFFF {
                    elem.add_child(XmlNode::Text("null".to_string()));
                } else {
                    let struct_name = self.df.get_struct_name(struct_idx as usize)?;
                    elem.add_child(XmlNode::Text(format!(
                        "{}[{:04X}]",
                        struct_name, variant_idx
                    )));
                }
                Ok(XmlNode::Element(elem))
            }
            DataType::Reference => {
                let offset = self.df.reference_value_offset() + index * 20;
                let _item1: u32 = self.df.read_value_at(offset)?;
                let bytes: [u8; 16] = [
                    self.df.data()[offset as usize + 4],
                    self.df.data()[offset as usize + 5],
                    self.df.data()[offset as usize + 6],
                    self.df.data()[offset as usize + 7],
                    self.df.data()[offset as usize + 8],
                    self.df.data()[offset as usize + 9],
                    self.df.data()[offset as usize + 10],
                    self.df.data()[offset as usize + 11],
                    self.df.data()[offset as usize + 12],
                    self.df.data()[offset as usize + 13],
                    self.df.data()[offset as usize + 14],
                    self.df.data()[offset as usize + 15],
                    self.df.data()[offset as usize + 16],
                    self.df.data()[offset as usize + 17],
                    self.df.data()[offset as usize + 18],
                    self.df.data()[offset as usize + 19],
                ];
                let guid = DataForgeGuid { bytes };
                let mut elem = XmlElement::new("Reference");
                if guid.is_empty() {
                    elem.add_child(XmlNode::Text("null".to_string()));
                } else {
                    elem.add_child(XmlNode::Text(guid.to_string()));
                }
                Ok(XmlNode::Element(elem))
            }
            DataType::Unknown(t) => {
                let mut elem = XmlElement::new("Unknown");
                elem.add_child(XmlNode::Text(format!("type {}", t)));
                Ok(XmlNode::Element(elem))
            }
        }
    }
}
