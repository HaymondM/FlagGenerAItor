# FlagGenerAItor

A command-line and web-based tool that leverages generative AI to help users solve Capture The Flag (CTF) cybersecurity challenges.

## Quick Start

```bash
# Build the project
cargo build --release

# Analyze a challenge file
./target/release/ctf-assistant analyze --file challenge.jpg --description "Find the hidden flag"

# Start web interface
./target/release/ctf-assistant web --port 3000
```

## Project Structure

This is a Rust workspace with two main crates:

### `ctf-assistant` (Binary Crate)
The main application providing both CLI and web interfaces.

- **CLI Interface**: Command-line tool for analyzing files and challenges
- **Web Interface**: Web dashboard for file upload and analysis

### `ctf-core` (Library Crate)
Core functionality library with modular architecture:

- **`core`**: Fundamental data structures, error types, and storage interfaces
- **`analysis`**: File analysis, decoding pipeline, steganography, and web analysis
- **`plugins`**: Extensible plugin system for specialized analysis
- **`interfaces`**: AI integration and analysis orchestration

## Features

### CLI Interface
- **Multiple Output Formats**: Text (colorized), JSON, and compact formats
- **Progress Indicators**: Visual feedback for long-running operations
- **Verbose Mode**: Detailed logging and processing information
- **File Validation**: Automatic file type detection and size limits (100MB)
- **Flexible Analysis**: Configurable recursion depth and AI hint generation
- **Challenge History**: Track and review past analyses with filtering
- **Command Aliases**: Short commands (a, w, h) for faster workflow

### Analysis Capabilities
- **File Type Detection**: Magic byte analysis for accurate file identification
- **Decoder Pipeline**: Automatic application of Base64, ROT13, XOR, and other transformations
- **Steganography Analysis**: Hidden data detection in images and other media
- **Plugin System**: Extensible architecture for specialized analysis tools
- **AI Integration**: Educational hints and guidance without revealing solutions

## Getting Started

### Prerequisites
- Rust 1.70+ with Cargo
- External tools for steganography analysis (will be documented in future tasks)

### Building
```bash
cargo build --release
```

### Running CLI

The CLI provides comprehensive analysis capabilities with multiple output formats:

```bash
# Basic file analysis
cargo run --bin ctf-assistant -- analyze --file challenge.jpg --description "Hidden message in image"

# Analysis with verbose output and JSON format
cargo run --bin ctf-assistant -- analyze --file data.txt --description "Encoded text" --verbose --format json

# Skip AI hints and set custom recursion depth
cargo run --bin ctf-assistant -- analyze --file mystery.bin --no-hints --max-depth 3

# Compact output for scripting
cargo run --bin ctf-assistant -- analyze --file encoded.txt --format compact

# View challenge history
cargo run --bin ctf-assistant -- history --limit 10 --filter image

# Get help for any command
cargo run --bin ctf-assistant -- --help
cargo run --bin ctf-assistant -- analyze --help
```

### Running Web Interface
```bash
# Start web server on default port (3000)
cargo run --bin ctf-assistant -- web

# Start on custom port and host
cargo run --bin ctf-assistant -- web --port 8080 --host 0.0.0.0
```

## Development

This project follows a spec-driven development approach. See `.kiro/specs/ctf-ai-assistant/` for:
- Requirements document
- Design document  
- Implementation tasks

## Dependencies

### Core Dependencies
- **tokio**: Async runtime
- **serde**: Serialization framework
- **uuid**: Unique identifier generation
- **chrono**: Date/time handling
- **anyhow**: Error handling
- **clap**: CLI argument parsing
- **axum**: Web framework

### Analysis Dependencies
- **infer**: File type detection
- **exif**: Image metadata extraction
- **base64**: Base64 encoding/decoding
- **flate2**: Compression handling
- **goblin**: Binary analysis

### CLI Dependencies
- **colored**: Terminal color output
- **indicatif**: Progress bars and spinners
- **atty**: Terminal detection for color support

### Testing Dependencies
- **proptest**: Property-based testing
- **tempfile**: Temporary file handling
- **mockall**: Mock object generation

## License

TBD