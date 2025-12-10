//! XML output generation for DataForge records

use byteorder::{LittleEndian, ReadBytesExt};
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

        // Start XML document
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");

        // Build record element
        let content = ctx.build_struct_xml(
            record.struct_index,
            record.variant_index as u32,
            &record_name,
        )?;

        // Add metadata attributes
        let open_tag = format!(
            "<{} __type=\"{}\" __ref=\"{}\" __path=\"{}\">",
            Self::escape_xml(&record_name),
            Self::escape_xml(&struct_name),
            record.hash.to_string(),
            Self::escape_xml(&file_name),
        );

        if content.is_empty() {
            xml.push_str(&open_tag.replace(">", " />"));
        } else {
            xml.push_str(&open_tag);
            xml.push_str(&content);
            xml.push_str(&format!("</{}>", Self::escape_xml(&record_name)));
        }

        if format_xml {
            Ok(Self::format_xml_string(&xml))
        } else {
            Ok(xml)
        }
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

    /// Format an XML string with proper indentation for human readability
    /// Implements VSCode-style formatting:
    /// - 2 space indentation
    /// - Short text content stays inline with tags (e.g., `<Name>Value</Name>`)
    /// - Only nested elements get newlines and indentation
    fn format_xml_string(xml: &str) -> String {
        use quick_xml::events::Event;
        use quick_xml::Reader;

        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut result = String::with_capacity(xml.len() * 2);
        let mut indent_level: usize = 0;
        let mut pending_start_tag: Option<String> = None;
        let mut pending_text: Option<String> = None;

        loop {
            match reader.read_event() {
                Ok(Event::Eof) => break,
                Ok(Event::Decl(decl)) => {
                    // XML declaration
                    result.push_str("<?xml");
                    if let Ok(version) = decl.version() {
                        result.push_str(&format!(
                            " version=\"{}\"",
                            String::from_utf8_lossy(&version)
                        ));
                    }
                    if let Some(Ok(encoding)) = decl.encoding() {
                        result.push_str(&format!(
                            " encoding=\"{}\"",
                            String::from_utf8_lossy(&encoding)
                        ));
                    }
                    result.push_str("?>\n");
                }
                Ok(Event::Start(e)) => {
                    // Flush any pending content
                    if let Some(tag) = pending_start_tag.take() {
                        result.push_str(&tag);
                        result.push('\n');
                        indent_level += 1;
                    }
                    pending_text = None;

                    // Write indentation
                    for _ in 0..indent_level {
                        result.push_str("  ");
                    }

                    // Build the start tag
                    let tag_str = Self::format_start_tag(&e);
                    pending_start_tag = Some(tag_str);
                }
                Ok(Event::End(e)) => {
                    let tag_name = String::from_utf8_lossy(e.name().as_ref()).to_string();

                    if let Some(start_tag) = pending_start_tag.take() {
                        if let Some(text) = pending_text.take() {
                            // Inline format: <Tag>text</Tag>
                            result.push_str(&start_tag);
                            result.push_str(&text);
                            result.push_str(&format!("</{}>\n", Self::escape_xml(&tag_name)));
                        } else {
                            // Self-closing style for empty elements
                            let self_closing =
                                start_tag.trim_end_matches('>').to_string() + " />\n";
                            result.push_str(&self_closing);
                        }
                    } else {
                        // Regular closing tag with indentation
                        indent_level = indent_level.saturating_sub(1);
                        for _ in 0..indent_level {
                            result.push_str("  ");
                        }
                        result.push_str(&format!("</{}>\n", Self::escape_xml(&tag_name)));
                    }
                    pending_text = None;
                }
                Ok(Event::Empty(e)) => {
                    // Flush any pending content
                    if let Some(tag) = pending_start_tag.take() {
                        result.push_str(&tag);
                        result.push('\n');
                        indent_level += 1;
                    }
                    pending_text = None;

                    // Write indentation
                    for _ in 0..indent_level {
                        result.push_str("  ");
                    }

                    // Write self-closing tag
                    let tag_str = Self::format_start_tag(&e);
                    let self_closing = tag_str.trim_end_matches('>').to_string() + " />\n";
                    result.push_str(&self_closing);
                }
                Ok(Event::Text(e)) => {
                    let text = String::from_utf8_lossy(&e).to_string();
                    if !text.trim().is_empty() {
                        pending_text = Some(text.trim().to_string());
                    }
                }
                Ok(Event::CData(e)) => {
                    if let Some(tag) = pending_start_tag.take() {
                        result.push_str(&tag);
                        result.push('\n');
                        indent_level += 1;
                    }
                    for _ in 0..indent_level {
                        result.push_str("  ");
                    }
                    result.push_str("<![CDATA[");
                    result.push_str(&String::from_utf8_lossy(&e.into_inner()));
                    result.push_str("]]>\n");
                }
                Ok(Event::Comment(e)) => {
                    if let Some(tag) = pending_start_tag.take() {
                        result.push_str(&tag);
                        result.push('\n');
                        indent_level += 1;
                    }
                    for _ in 0..indent_level {
                        result.push_str("  ");
                    }
                    result.push_str("<!--");
                    result.push_str(&String::from_utf8_lossy(&e.into_inner()));
                    result.push_str("-->\n");
                }
                Ok(Event::PI(e)) => {
                    result.push_str("<?");
                    result.push_str(&String::from_utf8_lossy(&e.into_inner()));
                    result.push_str("?>\n");
                }
                Ok(Event::DocType(e)) => {
                    result.push_str("<!DOCTYPE ");
                    result.push_str(&String::from_utf8_lossy(&e.into_inner()));
                    result.push_str(">\n");
                }
                Ok(_) => {
                    // Ignore other event types (e.g., GeneralRef in some quick-xml versions)
                }
                Err(_) => {
                    // If parsing fails, return original XML
                    return xml.to_string();
                }
            }
        }

        result
    }

    /// Format a start tag with its attributes
    fn format_start_tag(e: &quick_xml::events::BytesStart) -> String {
        let tag_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
        let mut tag_str = format!("<{}", Self::escape_xml(&tag_name));

        for attr in e.attributes().flatten() {
            let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
            let value = String::from_utf8_lossy(&attr.value).to_string();
            tag_str.push_str(&format!(" {}=\"{}\"", key, value));
        }
        tag_str.push('>');
        tag_str
    }

    /// Escape special XML characters
    fn escape_xml(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
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

    fn build_struct_xml(
        &mut self,
        struct_index: u32,
        variant_index: u32,
        _name: &str,
    ) -> Result<String> {
        // Check for recursion
        let key = (struct_index, variant_index);
        if self.struct_stack.contains(&key) || self.struct_stack.len() > MAX_POINTER_DEPTH {
            return Ok(String::new());
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
            None => return Ok(String::new()),
        };

        // Read all properties
        let mut xml = String::new();
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
                    let attr_xml = self.read_attribute_value(&mut cursor, prop, &prop_name)?;
                    xml.push_str(&attr_xml);
                    self.node_count += 1;
                }
                _ => {
                    let array_xml = self.read_array_value(&mut cursor, prop, &prop_name)?;
                    xml.push_str(&array_xml);
                }
            }
        }

        self.struct_stack.remove(&key);
        Ok(xml)
    }

    /// Build XML for an inline struct (data at current cursor position)
    fn build_inline_struct_xml(
        &mut self,
        cursor: &mut Cursor<&[u8]>,
        struct_index: u32,
        _name: &str,
    ) -> Result<String> {
        // Check for recursion
        let key = (struct_index, 0xFFFFFFFF); // Use special variant for inline
        if self.struct_stack.contains(&key) || self.struct_stack.len() > MAX_POINTER_DEPTH {
            return Ok(String::new());
        }
        self.struct_stack.insert(key);

        // Get all properties including inherited ones
        let properties = self.get_all_properties(struct_index)?;

        let mut xml = String::new();

        for prop_idx in properties {
            if self.node_count >= MAX_NODES {
                break;
            }

            let prop = &self.df.property_definitions()[prop_idx];
            let prop_name = self.df.read_blob_at_offset(prop.name_offset as u64)?;

            match prop.conversion_type {
                ConversionType::Attribute => {
                    let attr_xml = self.read_attribute_value(cursor, prop, &prop_name)?;
                    xml.push_str(&attr_xml);
                    self.node_count += 1;
                }
                _ => {
                    let array_xml = self.read_array_value(cursor, prop, &prop_name)?;
                    xml.push_str(&array_xml);
                }
            }
        }

        self.struct_stack.remove(&key);
        Ok(xml)
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

    fn read_attribute_value(
        &mut self,
        cursor: &mut Cursor<&[u8]>,
        prop: &PropertyDefinition,
        name: &str,
    ) -> Result<String> {
        let escaped_name = DataForge::escape_xml(name);

        match prop.data_type {
            DataType::Boolean => {
                let val = cursor.read_u8()? != 0;
                Ok(format!(
                    " {}=\"{}\"",
                    escaped_name,
                    if val { "1" } else { "0" }
                ))
            }
            DataType::Int8 => {
                let val = cursor.read_i8()?;
                Ok(format!(" {}=\"{}\"", escaped_name, val))
            }
            DataType::Int16 => {
                let val = cursor.read_i16::<LittleEndian>()?;
                Ok(format!(" {}=\"{}\"", escaped_name, val))
            }
            DataType::Int32 => {
                let val = cursor.read_i32::<LittleEndian>()?;
                Ok(format!(" {}=\"{}\"", escaped_name, val))
            }
            DataType::Int64 => {
                let val = cursor.read_i64::<LittleEndian>()?;
                Ok(format!(" {}=\"{}\"", escaped_name, val))
            }
            DataType::UInt8 => {
                let val = cursor.read_u8()?;
                Ok(format!(" {}=\"{}\"", escaped_name, val))
            }
            DataType::UInt16 => {
                let val = cursor.read_u16::<LittleEndian>()?;
                Ok(format!(" {}=\"{}\"", escaped_name, val))
            }
            DataType::UInt32 => {
                let val = cursor.read_u32::<LittleEndian>()?;
                Ok(format!(" {}=\"{}\"", escaped_name, val))
            }
            DataType::UInt64 => {
                let val = cursor.read_u64::<LittleEndian>()?;
                Ok(format!(" {}=\"{}\"", escaped_name, val))
            }
            DataType::Single => {
                let val = cursor.read_f32::<LittleEndian>()?;
                Ok(format!(" {}=\"{}\"", escaped_name, val))
            }
            DataType::Double => {
                let val = cursor.read_f64::<LittleEndian>()?;
                Ok(format!(" {}=\"{}\"", escaped_name, val))
            }
            DataType::Guid => {
                let mut bytes = [0u8; 16];
                cursor.read_exact(&mut bytes)?;
                let guid = DataForgeGuid { bytes };
                Ok(format!(" {}=\"{}\"", escaped_name, guid.to_string()))
            }
            DataType::String => {
                let offset = cursor.read_u32::<LittleEndian>()?;
                let val = self.df.read_text_at_offset(offset as u64)?;
                Ok(format!(
                    " {}=\"{}\"",
                    escaped_name,
                    DataForge::escape_xml(&val)
                ))
            }
            DataType::Locale => {
                let offset = cursor.read_u32::<LittleEndian>()?;
                let val = self.df.read_text_at_offset(offset as u64)?;
                Ok(format!(
                    " {}=\"{}\"",
                    escaped_name,
                    DataForge::escape_xml(&val)
                ))
            }
            DataType::Enum => {
                let offset = cursor.read_u32::<LittleEndian>()?;
                let val = self.df.read_text_at_offset(offset as u64)?;
                Ok(format!(
                    " {}=\"{}\"",
                    escaped_name,
                    DataForge::escape_xml(&val)
                ))
            }
            DataType::Reference => {
                let _item1 = cursor.read_u32::<LittleEndian>()?;
                let mut bytes = [0u8; 16];
                cursor.read_exact(&mut bytes)?;
                let guid = DataForgeGuid { bytes };
                if guid.is_empty() {
                    Ok(format!(" {}=\"null\"", escaped_name))
                } else {
                    Ok(format!(" {}=\"{}\"", escaped_name, guid.to_string()))
                }
            }
            DataType::StrongPointer | DataType::WeakPointer => {
                let struct_idx = cursor.read_u32::<LittleEndian>()?;
                let variant_idx = cursor.read_u16::<LittleEndian>()?;
                let _padding = cursor.read_u16::<LittleEndian>()?;

                if struct_idx == 0xFFFFFFFF {
                    Ok(format!(" {}=\"null\"", escaped_name))
                } else {
                    let struct_name = self.df.get_struct_name(struct_idx as usize)?;
                    Ok(format!(
                        " {}=\"{}[{:04X}]\"",
                        escaped_name, struct_name, variant_idx
                    ))
                }
            }
            DataType::Class => {
                // Inline class - data is stored at current cursor position
                // We need to read properties of the nested struct directly from cursor
                let content = self.build_inline_struct_xml(cursor, prop.index as u32, name)?;
                if content.is_empty() {
                    Ok(format!("<{} />", escaped_name))
                } else {
                    Ok(format!("<{}{}></{}>", escaped_name, content, escaped_name))
                }
            }
            DataType::Unknown(t) => Ok(format!(" {}=\"Unknown type {}\"", escaped_name, t)),
        }
    }

    fn read_array_value(
        &mut self,
        cursor: &mut Cursor<&[u8]>,
        prop: &PropertyDefinition,
        name: &str,
    ) -> Result<String> {
        let array_count = cursor.read_u32::<LittleEndian>()?;
        let first_index = cursor.read_u32::<LittleEndian>()?;

        if array_count == 0 {
            return Ok(String::new());
        }

        let escaped_name = DataForge::escape_xml(name);
        let mut xml = format!("<{}>", escaped_name);

        for i in 0..array_count.min(MAX_NODES as u32) {
            if self.node_count >= MAX_NODES {
                break;
            }

            let item_xml = self.read_array_item(prop, first_index, i as u16)?;
            xml.push_str(&item_xml);
            self.node_count += 1;
        }

        xml.push_str(&format!("</{}>", escaped_name));
        Ok(xml)
    }

    fn read_array_item(
        &mut self,
        prop: &PropertyDefinition,
        first_index: u32,
        offset: u16,
    ) -> Result<String> {
        let index = first_index as u64 + offset as u64;

        match prop.data_type {
            DataType::Boolean => {
                let val: bool = self
                    .df
                    .read_value_at(self.df.boolean_value_offset() + index)?;
                Ok(format!(
                    "<Boolean>{}</Boolean>",
                    if val { "1" } else { "0" }
                ))
            }
            DataType::Int8 => {
                let val: i8 = self.df.read_value_at(self.df.int8_value_offset() + index)?;
                Ok(format!("<Int8>{}</Int8>", val))
            }
            DataType::Int16 => {
                let val: i16 = self
                    .df
                    .read_value_at(self.df.int16_value_offset() + index * 2)?;
                Ok(format!("<Int16>{}</Int16>", val))
            }
            DataType::Int32 => {
                let val: i32 = self
                    .df
                    .read_value_at(self.df.int32_value_offset() + index * 4)?;
                Ok(format!("<Int32>{}</Int32>", val))
            }
            DataType::Int64 => {
                let val: i64 = self
                    .df
                    .read_value_at(self.df.int64_value_offset() + index * 8)?;
                Ok(format!("<Int64>{}</Int64>", val))
            }
            DataType::UInt8 => {
                let val: u8 = self
                    .df
                    .read_value_at(self.df.uint8_value_offset() + index)?;
                Ok(format!("<UInt8>{}</UInt8>", val))
            }
            DataType::UInt16 => {
                let val: u16 = self
                    .df
                    .read_value_at(self.df.uint16_value_offset() + index * 2)?;
                Ok(format!("<UInt16>{}</UInt16>", val))
            }
            DataType::UInt32 => {
                let val: u32 = self
                    .df
                    .read_value_at(self.df.uint32_value_offset() + index * 4)?;
                Ok(format!("<UInt32>{}</UInt32>", val))
            }
            DataType::UInt64 => {
                let val: u64 = self
                    .df
                    .read_value_at(self.df.uint64_value_offset() + index * 8)?;
                Ok(format!("<UInt64>{}</UInt64>", val))
            }
            DataType::Single => {
                let val: f32 = self
                    .df
                    .read_value_at(self.df.single_value_offset() + index * 4)?;
                Ok(format!("<Single>{}</Single>", val))
            }
            DataType::Double => {
                let val: f64 = self
                    .df
                    .read_value_at(self.df.double_value_offset() + index * 8)?;
                Ok(format!("<Double>{}</Double>", val))
            }
            DataType::String => {
                let str_offset: u32 = self
                    .df
                    .read_value_at(self.df.string_value_offset() + index * 4)?;
                let val = self.df.read_text_at_offset(str_offset as u64)?;
                Ok(format!("<String>{}</String>", DataForge::escape_xml(&val)))
            }
            DataType::Locale => {
                let str_offset: u32 = self
                    .df
                    .read_value_at(self.df.locale_value_offset() + index * 4)?;
                let val = self.df.read_text_at_offset(str_offset as u64)?;
                Ok(format!("<Locale>{}</Locale>", DataForge::escape_xml(&val)))
            }
            DataType::Enum => {
                let str_offset: u32 = self
                    .df
                    .read_value_at(self.df.enum_value_offset() + index * 4)?;
                let val = self.df.read_text_at_offset(str_offset as u64)?;
                Ok(format!("<Enum>{}</Enum>", DataForge::escape_xml(&val)))
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
                Ok(format!("<Guid>{}</Guid>", guid.to_string()))
            }
            DataType::Class => {
                // Array of structs
                let mapping = &self.df.data_mappings()[prop.index as usize];
                let struct_name = self.df.get_struct_name(mapping.struct_index as usize)?;
                let content = self.build_struct_xml(
                    prop.index as u32,
                    first_index + offset as u32,
                    &struct_name,
                )?;
                if content.is_empty() {
                    Ok(format!("<{} />", DataForge::escape_xml(&struct_name)))
                } else {
                    Ok(format!(
                        "<{}{}></{}>",
                        DataForge::escape_xml(&struct_name),
                        content,
                        DataForge::escape_xml(&struct_name)
                    ))
                }
            }
            DataType::StrongPointer => {
                let offset = self.df.strong_value_offset() + index * 8;
                let struct_idx: u32 = self.df.read_value_at(offset)?;
                let variant_idx: u16 = self.df.read_value_at(offset + 4)?;

                if struct_idx == 0xFFFFFFFF {
                    Ok("<StrongPointer>null</StrongPointer>".to_string())
                } else {
                    let struct_name = self.df.get_struct_name(struct_idx as usize)?;
                    let content =
                        self.build_struct_xml(struct_idx, variant_idx as u32, &struct_name)?;
                    if content.is_empty() {
                        Ok(format!("<{} />", DataForge::escape_xml(&struct_name)))
                    } else {
                        Ok(format!(
                            "<{}{}></{}>",
                            DataForge::escape_xml(&struct_name),
                            content,
                            DataForge::escape_xml(&struct_name)
                        ))
                    }
                }
            }
            DataType::WeakPointer => {
                let offset = self.df.weak_value_offset() + index * 8;
                let struct_idx: u32 = self.df.read_value_at(offset)?;
                let variant_idx: u16 = self.df.read_value_at(offset + 4)?;

                if struct_idx == 0xFFFFFFFF {
                    Ok("<WeakPointer>null</WeakPointer>".to_string())
                } else {
                    let struct_name = self.df.get_struct_name(struct_idx as usize)?;
                    Ok(format!(
                        "<WeakPointer>{}[{:04X}]</WeakPointer>",
                        struct_name, variant_idx
                    ))
                }
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
                if guid.is_empty() {
                    Ok("<Reference>null</Reference>".to_string())
                } else {
                    Ok(format!("<Reference>{}</Reference>", guid.to_string()))
                }
            }
            DataType::Unknown(t) => Ok(format!("<Unknown>type {}</Unknown>", t)),
        }
    }
}
