//! File analysis and type detection

use crate::core::models::{FileType, FileMetadata};
use crate::Result;
use chrono::Utc;
use std::io::Cursor;

pub struct FileAnalyzer;

impl FileAnalyzer {
    pub fn new() -> Self {
        Self
    }
    
    /// Detect file type using magic bytes
    pub fn detect_file_type(&self, data: &[u8]) -> FileType {
        if data.is_empty() {
            return FileType::Unknown;
        }

        // Use infer crate for magic byte detection
        if let Some(kind) = infer::get(data) {
            match kind.mime_type() {
                // Image types
                mime if mime.starts_with("image/") => FileType::Image,
                
                // PDF documents
                "application/pdf" => FileType::Pdf,
                
                // Archive types
                "application/zip" | "application/x-rar-compressed" | 
                "application/x-tar" | "application/gzip" => FileType::Zip,
                
                // Binary executables
                "application/x-executable" | "application/x-mach-binary" |
                "application/x-msdownload" => FileType::Binary,
                
                // Network captures
                mime if mime.contains("pcap") => FileType::Pcap,
                
                _ => {
                    // Check for text-based formats by examining content
                    self.detect_text_based_type(data)
                }
            }
        } else {
            // Fallback to content-based detection for text files
            self.detect_text_based_type(data)
        }
    }
    
    /// Detect text-based file types by examining content
    fn detect_text_based_type(&self, data: &[u8]) -> FileType {
        // First check for binary executable signatures before trying text analysis
        if self.is_binary_executable(data) {
            return FileType::Binary;
        }
        
        // Try to convert to UTF-8 string for text analysis
        if let Ok(content) = std::str::from_utf8(data) {
            let content_lower = content.to_lowercase();
            
            // Check for HTML
            if content_lower.contains("<!doctype html") || 
               content_lower.contains("<html") ||
               (content_lower.contains("<head>") && content_lower.contains("<body>")) {
                return FileType::Html;
            }
            
            // Check for JavaScript
            if content_lower.contains("function") && 
               (content_lower.contains("var ") || content_lower.contains("let ") || 
                content_lower.contains("const ") || content_lower.contains("=>")) {
                return FileType::Javascript;
            }
            
            // Check for network capture text formats
            if content_lower.contains("wireshark") || 
               content_lower.contains("tcpdump") ||
               content_lower.contains("packet capture") {
                return FileType::Pcap;
            }
            
            // Default to text if it's valid UTF-8
            FileType::Text
        } else {
            // If it's not valid UTF-8 and not a recognized binary, it's unknown
            FileType::Unknown
        }
    }
    
    /// Check if data contains binary executable signatures
    fn is_binary_executable(&self, data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }
        
        // Check for common executable signatures
        match &data[0..4] {
            // ELF magic number
            [0x7f, b'E', b'L', b'F'] => true,
            // PE magic number (MZ)
            [b'M', b'Z', _, _] => true,
            // Mach-O magic numbers
            [0xfe, 0xed, 0xfa, 0xce] | [0xce, 0xfa, 0xed, 0xfe] |
            [0xfe, 0xed, 0xfa, 0xcf] | [0xcf, 0xfa, 0xed, 0xfe] => true,
            _ => false,
        }
    }
    
    /// Extract metadata from file
    pub fn extract_metadata(&self, data: &[u8], file_type: &FileType) -> Result<FileMetadata> {
        let mut metadata = FileMetadata::new();
        metadata.created_at = Some(Utc::now());
        
        // Set MIME type based on file type
        metadata.mime_type = Some(file_type.to_mime_type().to_string());
        
        // Add basic file information
        metadata.add_field("file_size".to_string(), data.len().to_string());
        metadata.add_field("file_type".to_string(), file_type.to_string());
        
        // Extract type-specific metadata
        match file_type {
            FileType::Image => {
                self.extract_image_metadata(data, &mut metadata)?;
            }
            FileType::Binary => {
                self.extract_binary_metadata(data, &mut metadata)?;
            }
            FileType::Text | FileType::Html | FileType::Javascript => {
                self.extract_text_metadata(data, &mut metadata)?;
            }
            FileType::Zip => {
                self.extract_archive_metadata(data, &mut metadata)?;
            }
            _ => {
                // For other types, just add basic entropy information
                let entropy = self.calculate_entropy(data);
                metadata.add_field("entropy".to_string(), format!("{:.2}", entropy));
            }
        }
        
        Ok(metadata)
    }
    
    /// Extract metadata from image files
    fn extract_image_metadata(&self, data: &[u8], metadata: &mut FileMetadata) -> Result<()> {
        // Calculate entropy for steganography analysis
        let entropy = self.calculate_entropy(data);
        metadata.add_field("entropy".to_string(), format!("{:.2}", entropy));
        
        // Try to extract EXIF data using kamadak-exif crate
        let exif_reader = exif::Reader::new();
        {
            let mut cursor = Cursor::new(data);
            if let Ok(exif) = exif_reader.read_from_container(&mut cursor) {
                let mut exif_count = 0;
                for field in exif.fields() {
                    let tag_name = format!("exif_{}", field.tag);
                    let value = field.display_value().with_unit(&exif).to_string();
                    metadata.add_field(tag_name, value);
                    exif_count += 1;
                    
                    // Limit EXIF fields to prevent excessive metadata
                    if exif_count >= 20 {
                        break;
                    }
                }
                
                if exif_count > 0 {
                    metadata.add_field("exif_fields_count".to_string(), exif_count.to_string());
                }
            }
        }
        
        // Add image-specific analysis hints
        if entropy > 7.5 {
            metadata.add_field("steganography_hint".to_string(), 
                "High entropy detected - possible hidden data".to_string());
        }
        
        Ok(())
    }
    
    /// Extract metadata from binary files
    fn extract_binary_metadata(&self, data: &[u8], metadata: &mut FileMetadata) -> Result<()> {
        // Use goblin crate for binary analysis
        match goblin::Object::parse(data) {
            Ok(obj) => {
                match obj {
                    goblin::Object::Elf(elf) => {
                        metadata.add_field("binary_type".to_string(), "ELF".to_string());
                        metadata.add_field("architecture".to_string(), 
                            format!("{:?}", elf.header.e_machine));
                        metadata.add_field("entry_point".to_string(), 
                            format!("0x{:x}", elf.header.e_entry));
                        metadata.add_field("sections_count".to_string(), 
                            elf.section_headers.len().to_string());
                    }
                    goblin::Object::PE(pe) => {
                        metadata.add_field("binary_type".to_string(), "PE".to_string());
                        metadata.add_field("machine_type".to_string(), 
                            format!("0x{:x}", pe.header.coff_header.machine));
                        metadata.add_field("sections_count".to_string(), 
                            pe.sections.len().to_string());
                        if let Some(entry) = pe.header.optional_header {
                            metadata.add_field("entry_point".to_string(), 
                                format!("0x{:x}", entry.standard_fields.address_of_entry_point));
                        }
                    }
                    goblin::Object::Mach(mach) => {
                        match mach {
                            goblin::mach::Mach::Binary(macho) => {
                                metadata.add_field("binary_type".to_string(), "Mach-O".to_string());
                                metadata.add_field("cpu_type".to_string(), 
                                    format!("0x{:x}", macho.header.cputype));
                                metadata.add_field("file_type".to_string(), 
                                    format!("0x{:x}", macho.header.filetype));
                            }
                            goblin::mach::Mach::Fat(_) => {
                                metadata.add_field("binary_type".to_string(), "Fat Mach-O".to_string());
                            }
                        }
                    }
                    _ => {
                        metadata.add_field("binary_type".to_string(), "Unknown".to_string());
                    }
                }
            }
            Err(_) => {
                // Not a recognized binary format, add basic analysis
                metadata.add_field("binary_type".to_string(), "Unknown".to_string());
                
                // Look for strings in the binary
                let strings = self.extract_strings(data, 4);
                if !strings.is_empty() {
                    metadata.add_field("strings_count".to_string(), strings.len().to_string());
                    // Add first few strings as samples
                    for (i, string) in strings.iter().take(5).enumerate() {
                        metadata.add_field(format!("string_{}", i), string.clone());
                    }
                }
            }
        }
        
        // Calculate entropy
        let entropy = self.calculate_entropy(data);
        metadata.add_field("entropy".to_string(), format!("{:.2}", entropy));
        
        Ok(())
    }
    
    /// Extract metadata from text files
    fn extract_text_metadata(&self, data: &[u8], metadata: &mut FileMetadata) -> Result<()> {
        if let Ok(content) = std::str::from_utf8(data) {
            let lines: Vec<&str> = content.lines().collect();
            metadata.add_field("line_count".to_string(), lines.len().to_string());
            
            let char_count = content.chars().count();
            metadata.add_field("character_count".to_string(), char_count.to_string());
            
            let word_count = content.split_whitespace().count();
            metadata.add_field("word_count".to_string(), word_count.to_string());
            
            // Check for common patterns that might indicate encoding
            if content.contains("base64") || content.contains("Base64") {
                metadata.add_field("encoding_hint".to_string(), "Contains base64 references".to_string());
            }
            
            if content.contains("-----BEGIN") && content.contains("-----END") {
                metadata.add_field("encoding_hint".to_string(), "Contains PEM-like structure".to_string());
            }
            
            // Calculate entropy for encoded content detection
            let entropy = self.calculate_entropy(data);
            metadata.add_field("entropy".to_string(), format!("{:.2}", entropy));
            
            if entropy > 6.0 {
                metadata.add_field("encoding_hint".to_string(), 
                    "High entropy - possibly encoded content".to_string());
            }
        }
        
        Ok(())
    }
    
    /// Extract metadata from archive files
    fn extract_archive_metadata(&self, data: &[u8], metadata: &mut FileMetadata) -> Result<()> {
        // Basic archive analysis
        metadata.add_field("archive_type".to_string(), "Archive".to_string());
        
        // Calculate compression ratio estimate
        let entropy = self.calculate_entropy(data);
        metadata.add_field("entropy".to_string(), format!("{:.2}", entropy));
        
        if entropy < 6.0 {
            metadata.add_field("compression_hint".to_string(), 
                "Low entropy - good compression or structured data".to_string());
        }
        
        Ok(())
    }
    
    /// Calculate Shannon entropy of data
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        
        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }
        
        let len = data.len() as f64;
        let mut entropy = 0.0;
        
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        
        entropy
    }
    
    /// Extract printable strings from binary data
    fn extract_strings(&self, data: &[u8], min_length: usize) -> Vec<String> {
        let mut strings = Vec::new();
        let mut current_string = Vec::new();
        
        for &byte in data {
            if byte.is_ascii_graphic() || byte == b' ' {
                current_string.push(byte);
            } else {
                if current_string.len() >= min_length {
                    if let Ok(s) = String::from_utf8(current_string.clone()) {
                        strings.push(s);
                    }
                }
                current_string.clear();
            }
        }
        
        // Check final string
        if current_string.len() >= min_length {
            if let Ok(s) = String::from_utf8(current_string) {
                strings.push(s);
            }
        }
        
        // Limit number of strings to prevent excessive metadata
        strings.truncate(100);
        strings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_file_type_text() {
        let analyzer = FileAnalyzer::new();
        let text_data = b"Hello, world! This is a text file.";
        assert_eq!(analyzer.detect_file_type(text_data), FileType::Text);
    }

    #[test]
    fn test_detect_file_type_html() {
        let analyzer = FileAnalyzer::new();
        let html_data = b"<!DOCTYPE html><html><head><title>Test</title></head><body>Hello</body></html>";
        assert_eq!(analyzer.detect_file_type(html_data), FileType::Html);
    }

    #[test]
    fn test_detect_file_type_javascript() {
        let analyzer = FileAnalyzer::new();
        let js_data = b"function test() { var x = 5; console.log('Hello'); }";
        assert_eq!(analyzer.detect_file_type(js_data), FileType::Javascript);
    }

    #[test]
    fn test_detect_file_type_binary() {
        let analyzer = FileAnalyzer::new();
        let elf_data = b"\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let detected_type = analyzer.detect_file_type(elf_data);
        
        // The binary detection should work through our is_binary_executable check
        // since the infer crate might not recognize this minimal ELF header
        assert_eq!(detected_type, FileType::Binary);
    }

    #[test]
    fn test_detect_file_type_empty() {
        let analyzer = FileAnalyzer::new();
        let empty_data = b"";
        assert_eq!(analyzer.detect_file_type(empty_data), FileType::Unknown);
    }

    #[test]
    fn test_extract_metadata() {
        let analyzer = FileAnalyzer::new();
        let text_data = b"Hello, world!";
        let file_type = FileType::Text;
        
        let metadata = analyzer.extract_metadata(text_data, &file_type).unwrap();
        assert!(metadata.mime_type.is_some());
        assert_eq!(metadata.get_field("file_size").unwrap(), "13");
        assert_eq!(metadata.get_field("file_type").unwrap(), "Text");
    }

    #[test]
    fn test_calculate_entropy() {
        let analyzer = FileAnalyzer::new();
        
        // Test with uniform data (low entropy)
        let uniform_data = vec![0u8; 100];
        let entropy = analyzer.calculate_entropy(&uniform_data);
        assert!(entropy < 1.0);
        
        // Test with random-like data (high entropy)
        let random_data: Vec<u8> = (0..=255).collect();
        let entropy = analyzer.calculate_entropy(&random_data);
        assert!(entropy > 7.0);
    }

    #[test]
    fn test_extract_strings() {
        let analyzer = FileAnalyzer::new();
        let data = b"Hello\x00World\x00Test\x01String";
        let strings = analyzer.extract_strings(data, 4);
        
        assert!(strings.contains(&"Hello".to_string()));
        assert!(strings.contains(&"World".to_string()));
        assert!(strings.contains(&"Test".to_string()));
        assert!(strings.contains(&"String".to_string()));
    }
}