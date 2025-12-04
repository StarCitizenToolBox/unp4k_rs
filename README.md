# unp4k_rs

A Rust implementation of [unp4k](https://github.com/dolkensp/unp4k) - a tool for extracting and modifying Star Citizen `.p4k` files.

> [!NOTE]
> The p4k editing feature is experimental. Currently, editing can be successful, but the game will not pass verification.

## Features

- 📦 Open and extract Star Citizen `.p4k` archives
- ✏️ Create, modify and patch `.p4k` archives
- 🔐 AES-128-CBC encryption/decryption support
- 🗜️ Support for STORE, DEFLATE, and ZSTD compression
- 📝 CryXML binary format to standard XML conversion
- 🚀 Fast parallel extraction
- 💻 Cross-platform (Windows, macOS, Linux)

## Usage

### Quick Extract (like original unp4k)

```bash
# Extract all files
unp4k Data.p4k

# Extract files matching a pattern
unp4k Data.p4k "*.xml"
unp4k Data.p4k "Data/Libs/*"
```

### List Files

```bash
# List all files
unp4k list Data.p4k

# List files matching a pattern
unp4k list Data.p4k "*.dcb"
```

### Extract Files

```bash
# Extract to current directory
unp4k extract Data.p4k

# Extract with pattern
unp4k extract Data.p4k "*.xml" -o ./output

# Extract and convert CryXML to standard XML
unp4k extract Data.p4k "*.xml" --convert-xml
```

### Show Archive Info

```bash
unp4k info Data.p4k
```

### Create a P4K Archive

```bash
# Create a new P4K from a directory
unp4k pack output.p4k ./my_files

# With custom compression
unp4k pack output.p4k ./my_files -c zstd
unp4k pack output.p4k ./my_files -c deflate
unp4k pack output.p4k ./my_files -c store

# Without encryption
unp4k pack output.p4k ./my_files -e false

# With base path prefix
unp4k pack output.p4k ./my_files -b Data/MyMod
```

### Patch an Existing P4K

```bash
# Patch a P4K with files from a directory
# Files in patch directory will replace matching files in the P4K
unp4k patch Data.p4k ./patches

# Save to a new file
unp4k patch Data.p4k ./patches -o Data_patched.p4k
```

### Add a Single File

```bash
# Add a file to the archive
unp4k add Data.p4k myfile.xml

# Add with custom archive path
unp4k add Data.p4k myfile.xml -a Data/Config/myfile.xml
```

### Delete Files

```bash
# Delete files matching patterns
unp4k delete Data.p4k "*.tmp" "*.bak"

# Save to a new file
unp4k delete Data.p4k "*.tmp" -o Data_clean.p4k
```

## Library Usage

Example:

```rust
use unp4k::{P4kFile, CryXmlReader};

fn main() -> anyhow::Result<()> {
    // Open the archive
    let mut p4k = P4kFile::open("Data.p4k")?;
    
    // List entries
    for entry in p4k.entries() {
        println!("{}: {} bytes", entry.name, entry.uncompressed_size);
    }
    
    // Extract a file
    let data = p4k.extract("Data/Libs/Config/defaultProfile.xml")?;
    
    // Convert CryXML to standard XML
    if CryXmlReader::is_cryxml(&data) {
        let xml = CryXmlReader::parse(&data)?;
        println!("{}", xml);
    }
    
    Ok(())
}
```

### Creating and Modifying Archives

```rust
use unp4k::{P4kWriter, P4kWriteEntry, P4kWriteOptions, P4kModifier, CompressionMethod};

fn create_archive() -> anyhow::Result<()> {
    // Create a new P4K
    let mut writer = P4kWriter::create("my_archive.p4k")?;
    
    // Add entries
    let entry = P4kWriteEntry::new("Data/test.xml", b"<root/>".to_vec());
    writer.add_entry(entry)?;
    
    // Or add from file
    writer.add_file("local_file.txt", "Data/remote_file.txt")?;
    
    writer.finish()?;
    Ok(())
}

fn modify_archive() -> anyhow::Result<()> {
    // Open existing P4K for modification
    let mut modifier = P4kModifier::open("Data.p4k")?;
    
    // Add/replace a file
    modifier.add(P4kWriteEntry::new("Data/new_file.xml", b"<data/>".to_vec()));
    
    // Delete a file
    modifier.delete("Data/old_file.xml");
    
    // Save to new file
    modifier.save("Data_modified.p4k")?;
    Ok(())
}
```
```

## File Format

The `.p4k` files are encrypted ZIP archives with custom features:

- **Encryption**: AES-128-CBC with a known public key (same as CryEngine)
- **Compression Methods**:
  - `STORE` (0) - No compression
  - `DEFLATE` (8) - Standard ZIP compression
  - `ZSTD` (100) - Zstandard compression (custom extension)
- **CryXML**: Binary XML format used for many game configuration files

## Credits

- Original [unp4k](https://github.com/dolkensp/unp4k) by dolkensp
- Star Citizen by Cloud Imperium Games

## License

GNU AFFERO GENERAL PUBLIC LICENSE Version 3