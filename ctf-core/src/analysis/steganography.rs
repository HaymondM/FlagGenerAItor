//! Steganography analysis tools

use crate::core::models::{Finding, FindingCategory, FileMetadata};
use crate::core::errors::CtfError;
use crate::Result;
use exif::{Reader, Tag};
use std::collections::HashMap;
use std::io::Cursor;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{debug, warn};

/// Maximum timeout for external tool execution (30 seconds)
const EXTERNAL_TOOL_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum output size from external tools (1MB)
const MAX_OUTPUT_SIZE: usize = 1024 * 1024;

pub struct SteganographyAnalyzer;

impl SteganographyAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Extract EXIF metadata from image data
    pub fn extract_image_metadata(&self, data: &[u8]) -> Result<FileMetadata> {
        let mut metadata = FileMetadata::new();
        
        // Try to extract EXIF data
        match self.extract_exif_data(data) {
            Ok(exif_data) => {
                for (key, value) in exif_data {
                    metadata.add_field(key, value);
                }
                debug!("Successfully extracted EXIF metadata");
            }
            Err(e) => {
                debug!("Failed to extract EXIF data: {}", e);
                // Not an error - many images don't have EXIF data
            }
        }

        // Add basic image information
        metadata.add_field("image_size_bytes".to_string(), data.len().to_string());
        
        // Try to detect image format from magic bytes
        if let Some(format) = self.detect_image_format(data) {
            metadata.add_field("image_format".to_string(), format);
        }

        Ok(metadata)
    }

    /// Extract EXIF data from image bytes
    fn extract_exif_data(&self, data: &[u8]) -> Result<HashMap<String, String>> {
        let mut exif_data = HashMap::new();
        let cursor = Cursor::new(data);
        
        let exif_reader = Reader::new();
        let exif = exif_reader.read_from_container(&mut cursor.clone())
            .map_err(|e| CtfError::AnalysisError { 
                message: format!("Failed to read EXIF data: {}", e) 
            })?;

        // Extract common EXIF fields
        for field in exif.fields() {
            let tag_name = match field.tag {
                Tag::Make => "camera_make",
                Tag::Model => "camera_model",
                Tag::DateTime => "date_time",
                Tag::DateTimeOriginal => "date_time_original",
                Tag::DateTimeDigitized => "date_time_digitized",
                Tag::Software => "software",
                Tag::Artist => "artist",
                Tag::Copyright => "copyright",
                Tag::ImageDescription => "image_description",
                Tag::Orientation => "orientation",
                Tag::XResolution => "x_resolution",
                Tag::YResolution => "y_resolution",
                Tag::ResolutionUnit => "resolution_unit",
                Tag::WhitePoint => "white_point",
                Tag::PrimaryChromaticities => "primary_chromaticities",
                Tag::YCbCrCoefficients => "ycbcr_coefficients",
                Tag::ReferenceBlackWhite => "reference_black_white",
                Tag::ColorSpace => "color_space",
                Tag::PixelXDimension => "pixel_x_dimension",
                Tag::PixelYDimension => "pixel_y_dimension",
                Tag::ExifVersion => "exif_version",
                Tag::ComponentsConfiguration => "components_configuration",
                Tag::FlashpixVersion => "flashpix_version",
                Tag::UserComment => "user_comment",
                Tag::RelatedSoundFile => "related_sound_file",
                Tag::ImageUniqueID => "image_unique_id",
                Tag::GPSLatitudeRef => "gps_latitude_ref",
                Tag::GPSLatitude => "gps_latitude",
                Tag::GPSLongitudeRef => "gps_longitude_ref",
                Tag::GPSLongitude => "gps_longitude",
                Tag::GPSAltitudeRef => "gps_altitude_ref",
                Tag::GPSAltitude => "gps_altitude",
                Tag::GPSTimeStamp => "gps_timestamp",
                Tag::GPSDateStamp => "gps_datestamp",
                _ => continue, // Skip unknown tags
            };

            let value = field.display_value().with_unit(&exif).to_string();
            if !value.trim().is_empty() && value != "undefined" {
                exif_data.insert(tag_name.to_string(), value);
            }
        }

        Ok(exif_data)
    }

    /// Detect image format from magic bytes
    fn detect_image_format(&self, data: &[u8]) -> Option<String> {
        if data.len() < 8 {
            return None;
        }

        // Check for common image format magic bytes
        if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
            Some("JPEG".to_string())
        } else if data.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
            Some("PNG".to_string())
        } else if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
            Some("GIF".to_string())
        } else if data.starts_with(b"RIFF") && data.len() > 12 && &data[8..12] == b"WEBP" {
            Some("WebP".to_string())
        } else if data.starts_with(&[0x42, 0x4D]) {
            Some("BMP".to_string())
        } else if data.starts_with(&[0x49, 0x49, 0x2A, 0x00]) || data.starts_with(&[0x4D, 0x4D, 0x00, 0x2A]) {
            Some("TIFF".to_string())
        } else {
            None
        }
    }

    /// Run steganography detection tools on image data
    pub async fn detect_steganography(&self, data: &[u8]) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let start_time = Instant::now();

        // Create temporary file for external tools
        let temp_file = tempfile::NamedTempFile::new()
            .map_err(|e| CtfError::AnalysisError { 
                message: format!("Failed to create temporary file: {}", e) 
            })?;
        
        std::fs::write(temp_file.path(), data)
            .map_err(|e| CtfError::AnalysisError { 
                message: format!("Failed to write temporary file: {}", e) 
            })?;

        // Run zsteg if available
        if let Ok(zsteg_findings) = self.run_zsteg(temp_file.path().to_str().unwrap()).await {
            findings.extend(zsteg_findings);
        }

        // Run strings extraction
        if let Ok(strings_findings) = self.extract_strings(data).await {
            findings.extend(strings_findings);
        }

        debug!("Steganography detection completed in {:?}", start_time.elapsed());
        Ok(findings)
    }

    /// Run zsteg tool for steganography detection
    async fn run_zsteg(&self, file_path: &str) -> Result<Vec<Finding>> {
        debug!("Running zsteg on file: {}", file_path);
        
        let output_result = timeout(
            EXTERNAL_TOOL_TIMEOUT,
            tokio::task::spawn_blocking({
                let file_path = file_path.to_string();
                move || {
                    Command::new("zsteg")
                        .arg(&file_path)
                        .arg("-a") // All methods
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .output()
                }
            })
        ).await;

        let output = match output_result {
            Ok(Ok(Ok(output))) => output,
            Ok(Ok(Err(e))) => {
                warn!("Failed to execute zsteg: {}", e);
                return Ok(vec![]);
            }
            Ok(Err(e)) => {
                warn!("Failed to spawn zsteg task: {}", e);
                return Ok(vec![]);
            }
            Err(_) => {
                warn!("zsteg execution timed out");
                return Ok(vec![]);
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            debug!("zsteg failed with error: {}", stderr);
            return Ok(vec![]);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.trim().is_empty() {
            return Ok(vec![]);
        }

        // Parse zsteg output for findings
        let mut findings = Vec::new();
        for line in stdout.lines() {
            if line.trim().is_empty() || line.starts_with("b") && line.contains("..") {
                continue;
            }

            // Look for meaningful data patterns
            if self.is_meaningful_zsteg_output(line) {
                let finding = Finding::new(
                    FindingCategory::Steganography,
                    format!("Potential hidden data detected: {}", line.trim()),
                    0.7, // Medium-high confidence for zsteg findings
                    vec![format!("zsteg output: {}", line.trim())],
                    vec![
                        "Examine the detected data more closely".to_string(),
                        "Try extracting the data using the specific method indicated".to_string(),
                    ],
                )?;
                findings.push(finding);
            }
        }

        if findings.is_empty() {
            // Create a negative finding to indicate clean scan
            let finding = Finding::new(
                FindingCategory::Steganography,
                "No hidden data detected by zsteg analysis".to_string(),
                0.8, // High confidence in negative result
                vec!["zsteg scan completed without findings".to_string()],
                vec!["Consider other steganography techniques or tools".to_string()],
            )?;
            findings.push(finding);
        }

        Ok(findings)
    }

    /// Check if zsteg output line indicates meaningful data
    fn is_meaningful_zsteg_output(&self, line: &str) -> bool {
        let line_lower = line.to_lowercase();
        
        // Skip binary noise patterns
        if line.contains("..") && line.len() > 50 {
            return false;
        }

        // Look for text patterns
        if line_lower.contains("text") || 
           line_lower.contains("ascii") ||
           line_lower.contains("utf") ||
           line.chars().filter(|c| c.is_ascii_alphanumeric() || c.is_ascii_punctuation()).count() > line.len() / 2 {
            return true;
        }

        // Look for file signatures
        if line_lower.contains("png") ||
           line_lower.contains("jpg") ||
           line_lower.contains("gif") ||
           line_lower.contains("pdf") ||
           line_lower.contains("zip") {
            return true;
        }

        // Look for common flag patterns
        if line.contains("flag") || 
           line.contains("ctf") ||
           line.contains("{") && line.contains("}") {
            return true;
        }

        false
    }

    /// Extract strings from binary data
    async fn extract_strings(&self, data: &[u8]) -> Result<Vec<Finding>> {
        debug!("Extracting strings from binary data");
        
        let strings = self.find_ascii_strings(data, 4); // Minimum length of 4
        let total_strings = strings.len();
        
        if strings.is_empty() {
            let finding = Finding::new(
                FindingCategory::Steganography,
                "No meaningful strings found in image data".to_string(),
                0.6,
                vec!["String extraction completed".to_string()],
                vec!["Image may not contain hidden text data".to_string()],
            )?;
            return Ok(vec![finding]);
        }

        let mut findings = Vec::new();
        let mut interesting_strings = Vec::new();

        // Filter for potentially interesting strings
        for string in strings {
            if self.is_interesting_string(&string) {
                interesting_strings.push(string);
            }
        }

        if !interesting_strings.is_empty() {
            let finding = Finding::new(
                FindingCategory::Steganography,
                format!("Found {} potentially interesting strings in image", interesting_strings.len()),
                0.6,
                interesting_strings.iter().take(10).map(|s| format!("String: {}", s)).collect(),
                vec![
                    "Examine the strings for hidden messages or clues".to_string(),
                    "Look for patterns, URLs, or encoded data".to_string(),
                ],
            )?;
            findings.push(finding);
        } else {
            let finding = Finding::new(
                FindingCategory::Steganography,
                "Strings found but none appear particularly interesting".to_string(),
                0.3,
                vec![format!("Total strings found: {}", total_strings)],
                vec!["Manual review of strings may still be worthwhile".to_string()],
            )?;
            findings.push(finding);
        }

        Ok(findings)
    }

    /// Find ASCII strings in binary data
    fn find_ascii_strings(&self, data: &[u8], min_length: usize) -> Vec<String> {
        let mut strings = Vec::new();
        let mut current_string = Vec::new();

        for &byte in data {
            if byte.is_ascii_graphic() || byte == b' ' || byte == b'\t' {
                current_string.push(byte);
            } else {
                if current_string.len() >= min_length {
                    if let Ok(string) = String::from_utf8(current_string.clone()) {
                        strings.push(string);
                    }
                }
                current_string.clear();
            }
        }

        // Don't forget the last string if the data ends with printable characters
        if current_string.len() >= min_length {
            if let Ok(string) = String::from_utf8(current_string) {
                strings.push(string);
            }
        }

        strings
    }

    /// Check if a string is potentially interesting for CTF analysis
    fn is_interesting_string(&self, string: &str) -> bool {
        let string_lower = string.to_lowercase();
        
        // Look for common CTF patterns
        if string_lower.contains("flag") ||
           string_lower.contains("ctf") ||
           string_lower.contains("password") ||
           string_lower.contains("key") ||
           string_lower.contains("secret") {
            return true;
        }

        // Look for URLs or file paths
        if string.contains("http") ||
           string.contains("ftp") ||
           string.contains("://") ||
           string.contains("/") && string.len() > 10 {
            return true;
        }

        // Look for encoded data patterns
        if string.len() > 20 && (
            string.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=') || // Base64-like
            string.chars().all(|c| c.is_ascii_hexdigit()) || // Hex
            string.chars().all(|c| c.is_ascii_digit() || c == '.' || c == '-') // Numbers/coordinates
        ) {
            return true;
        }

        // Look for flag-like patterns
        if (string.contains('{') && string.contains('}')) ||
           string.starts_with("flag") ||
           string.len() > 15 && string.chars().filter(|c| c.is_ascii_uppercase()).count() > string.len() / 2 {
            return true;
        }

        false
    }

    /// Create comprehensive steganography analysis report
    pub fn create_analysis_report(&self, findings: Vec<Finding>, metadata: FileMetadata) -> Result<Vec<Finding>> {
        let mut report_findings = findings;
        
        // Add metadata summary finding
        let metadata_summary = self.create_metadata_summary(&metadata)?;
        report_findings.insert(0, metadata_summary);

        // Deduplicate similar findings
        self.deduplicate_findings(&mut report_findings);

        Ok(report_findings)
    }

    /// Create a summary finding for image metadata
    fn create_metadata_summary(&self, metadata: &FileMetadata) -> Result<Finding> {
        let mut evidence = Vec::new();
        let mut confidence = 0.5;

        // Check for interesting metadata fields
        for (key, value) in &metadata.additional {
            if key.contains("gps") || key.contains("location") {
                evidence.push(format!("GPS/Location data: {} = {}", key, value));
                confidence = 0.8; // GPS data is often interesting
            } else if key.contains("software") || key.contains("camera") {
                evidence.push(format!("Device info: {} = {}", key, value));
            } else if key.contains("date") || key.contains("time") {
                evidence.push(format!("Timestamp: {} = {}", key, value));
            } else if !value.is_empty() {
                evidence.push(format!("{}: {}", key, value));
            }
        }

        if evidence.is_empty() {
            evidence.push("No significant metadata found".to_string());
            confidence = 0.3;
        }

        Ok(Finding::new(
            FindingCategory::Steganography,
            "Image metadata analysis completed".to_string(),
            confidence,
            evidence,
            vec![
                "Review metadata for clues about image origin or processing".to_string(),
                "GPS coordinates or timestamps might be relevant to the challenge".to_string(),
            ],
        )?)
    }

    /// Remove duplicate or very similar findings
    fn deduplicate_findings(&self, findings: &mut Vec<Finding>) {
        let mut i = 0;
        while i < findings.len() {
            let mut j = i + 1;
            while j < findings.len() {
                if self.are_similar_findings(&findings[i], &findings[j]) {
                    // Keep the higher confidence finding
                    if findings[j].confidence > findings[i].confidence {
                        findings.swap(i, j);
                    }
                    findings.remove(j);
                } else {
                    j += 1;
                }
            }
            i += 1;
        }
    }

    /// Check if two findings are similar enough to be considered duplicates
    fn are_similar_findings(&self, finding1: &Finding, finding2: &Finding) -> bool {
        // Same category and similar descriptions
        finding1.category == finding2.category &&
        (finding1.description.contains(&finding2.description) ||
         finding2.description.contains(&finding1.description) ||
         self.similarity_score(&finding1.description, &finding2.description) > 0.8)
    }

    /// Calculate similarity score between two strings (simple implementation)
    fn similarity_score(&self, s1: &str, s2: &str) -> f32 {
        let s1_words: std::collections::HashSet<&str> = s1.split_whitespace().collect();
        let s2_words: std::collections::HashSet<&str> = s2.split_whitespace().collect();
        
        let intersection = s1_words.intersection(&s2_words).count();
        let union = s1_words.union(&s2_words).count();
        
        if union == 0 {
            0.0
        } else {
            intersection as f32 / union as f32
        }
    }

    /// Analyze image for hidden data (main entry point)
    pub async fn analyze_image(&self, data: &[u8]) -> Result<Vec<Finding>> {
        debug!("Starting steganography analysis for image data ({} bytes)", data.len());
        
        // Extract metadata
        let metadata = self.extract_image_metadata(data)?;
        
        // Run steganography detection
        let stego_findings = self.detect_steganography(data).await?;
        
        // Create comprehensive report
        let final_findings = self.create_analysis_report(stego_findings, metadata)?;
        
        debug!("Steganography analysis completed with {} findings", final_findings.len());
        Ok(final_findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::models::{FindingCategory, FileMetadata};

    #[tokio::test]
    async fn test_extract_image_metadata_empty() {
        let analyzer = SteganographyAnalyzer::new();
        let empty_data = vec![];
        
        let result = analyzer.extract_image_metadata(&empty_data);
        assert!(result.is_ok());
        
        let metadata = result.unwrap();
        assert_eq!(metadata.additional.get("image_size_bytes"), Some(&"0".to_string()));
    }

    #[tokio::test]
    async fn test_detect_image_format_jpeg() {
        let analyzer = SteganographyAnalyzer::new();
        let jpeg_header = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46];
        
        let format = analyzer.detect_image_format(&jpeg_header);
        assert_eq!(format, Some("JPEG".to_string()));
    }

    #[tokio::test]
    async fn test_detect_image_format_png() {
        let analyzer = SteganographyAnalyzer::new();
        let png_header = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        
        let format = analyzer.detect_image_format(&png_header);
        assert_eq!(format, Some("PNG".to_string()));
    }

    #[tokio::test]
    async fn test_find_ascii_strings() {
        let analyzer = SteganographyAnalyzer::new();
        let data = b"Hello\x00World\x00Test\x00";
        
        let strings = analyzer.find_ascii_strings(data, 4);
        assert!(strings.contains(&"Hello".to_string()));
        assert!(strings.contains(&"World".to_string()));
        assert!(strings.contains(&"Test".to_string()));
    }

    #[tokio::test]
    async fn test_is_interesting_string_flag() {
        let analyzer = SteganographyAnalyzer::new();
        
        assert!(analyzer.is_interesting_string("flag{test}"));
        assert!(analyzer.is_interesting_string("CTF_FLAG"));
        assert!(analyzer.is_interesting_string("password123"));
        assert!(analyzer.is_interesting_string("http://example.com"));
        assert!(!analyzer.is_interesting_string("hello"));
    }

    #[tokio::test]
    async fn test_extract_strings_empty() {
        let analyzer = SteganographyAnalyzer::new();
        let empty_data = vec![];
        
        let result = analyzer.extract_strings(&empty_data).await;
        assert!(result.is_ok());
        
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, FindingCategory::Steganography);
        assert!(findings[0].description.contains("No meaningful strings"));
    }

    #[tokio::test]
    async fn test_create_metadata_summary() {
        let analyzer = SteganographyAnalyzer::new();
        let mut metadata = FileMetadata::new();
        metadata.add_field("gps_latitude".to_string(), "40.7128".to_string());
        metadata.add_field("camera_make".to_string(), "Canon".to_string());
        
        let result = analyzer.create_metadata_summary(&metadata);
        assert!(result.is_ok());
        
        let finding = result.unwrap();
        assert_eq!(finding.category, FindingCategory::Steganography);
        assert!(finding.confidence > 0.5);
        assert!(finding.evidence.iter().any(|e| e.contains("GPS")));
    }

    #[tokio::test]
    async fn test_analyze_image_basic() {
        let analyzer = SteganographyAnalyzer::new();
        let test_data = b"Test image data with some text";
        
        let result = analyzer.analyze_image(test_data).await;
        assert!(result.is_ok());
        
        let findings = result.unwrap();
        assert!(!findings.is_empty());
        
        // Should have at least metadata summary
        assert!(findings.iter().any(|f| f.description.contains("metadata analysis")));
    }
}