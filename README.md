# unp4k_rs

A Rust implementation of [unp4k](https://github.com/dolkensp/unp4k) - a tool for extracting and modifying Star Citizen `.p4k` files.

> [!NOTE]
> The functionality to modify/create P4K is experimental; it is only used for testing local tools and cannot be verified by the game.

## Installation

### From Git (Recommended)

```bash
cargo install --git https://github.com/StarCitizenToolBox/unp4k_rs.git
```

### From Source

```bash
git clone https://github.com/StarCitizenToolBox/unp4k_rs.git
cd unp4k_rs
cargo install --path .
```

### Verify Installation

```bash
unp4k --help
```

## Features

- 📦 Open and extract Star Citizen `.p4k` archives
- ✏️ Create, modify and patch `.p4k` archives
- 🔐 AES-128-CBC encryption/decryption support
- 🗜️ Support for STORE, DEFLATE, and ZSTD compression
- 📝 CryXML binary format to standard XML conversion
- 📊 DataForge/DCB binary format to XML conversion
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

# With base path prefix
unp4k patch Data.p4k ./patches -b Data/Localization
```

### Add a Single File

```bash
# Add a file to the archive
unp4k add Data.p4k myfile.xml

# Add with custom archive path
unp4k add Data.p4k myfile.xml -a Data/Config/myfile.xml
```

### Replace a Single File

```bash
# Replace a file in the archive (keeps original compression settings)
unp4k replace Data.p4k myfile.xml Data/Config/myfile.xml
```

### Delete Files

```bash
# Delete files matching patterns
unp4k delete Data.p4k "*.tmp" "*.bak"
```

### Convert DataForge/DCB to XML

```bash
# Show DCB file info
unp4k dcb Game.dcb --info

# Convert to separate XML files (like upstream unp4k)
unp4k dcb Game.dcb

# Convert to a single merged XML file
unp4k dcb Game.dcb --merge

# Specify output directory
unp4k dcb Game.dcb -o ./output
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

GNU GENERAL PUBLIC LICENSE Version 3