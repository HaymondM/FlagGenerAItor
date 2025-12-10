# CTF AI Assistant

A command-line and web-based tool that leverages generative AI to help users solve Capture The Flag (CTF) cybersecurity challenges.

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

## Getting Started

### Prerequisites
- Rust 1.70+ with Cargo
- External tools for steganography analysis (will be documented in future tasks)

### Building
```bash
cargo build --release
```

### Running CLI
```bash
cargo run --bin ctf-assistant -- analyze --file example.txt --description "Sample challenge"
```

### Running Web Interface
```bash
cargo run --bin ctf-assistant -- web --port 3000
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

### Testing Dependencies
- **proptest**: Property-based testing
- **tempfile**: Temporary file handling
- **mockall**: Mock object generation

## License

TBD