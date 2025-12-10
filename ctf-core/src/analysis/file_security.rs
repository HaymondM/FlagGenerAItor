//! File security and validation utilities

use crate::core::models::MAX_FILE_SIZE;
use crate::Result;
use anyhow::anyhow;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// File security validator
pub struct FileSecurityValidator;

impl FileSecurityValidator {
    pub fn new() -> Self {
        Self
    }
    
    /// Validate file size against maximum limit
    pub fn validate_file_size(&self, data: &[u8]) -> Result<()> {
        let size = data.len() as u64;
        if size > MAX_FILE_SIZE {
            return Err(anyhow!(
                "File size {} bytes exceeds maximum allowed size of {} bytes", 
                size, 
                MAX_FILE_SIZE
            ).into());
        }
        Ok(())
    }
    
    /// Validate and sanitize file name to prevent path traversal
    pub fn sanitize_filename(&self, filename: &str) -> Result<String> {
        if filename.is_empty() {
            return Err(anyhow!("Filename cannot be empty").into());
        }
        
        // Remove any path components and dangerous characters
        let sanitized = filename
            .replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_")
            .replace("..", "_")
            .trim()
            .to_string();
        
        if sanitized.is_empty() {
            return Err(anyhow!("Filename contains only invalid characters").into());
        }
        
        // Prevent reserved names on Windows
        let lower = sanitized.to_lowercase();
        let reserved_names = [
            "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5",
            "com6", "com7", "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4",
            "lpt5", "lpt6", "lpt7", "lpt8", "lpt9"
        ];
        
        if reserved_names.contains(&lower.as_str()) {
            return Ok(format!("_{}", sanitized));
        }
        
        // Limit filename length
        if sanitized.len() > 255 {
            Ok(sanitized[..255].to_string())
        } else {
            Ok(sanitized)
        }
    }
    
    /// Generate secure storage path with unique identifier
    pub fn generate_secure_path(&self, base_dir: &Path, original_name: &str) -> Result<PathBuf> {
        let sanitized_name = self.sanitize_filename(original_name)?;
        let file_id = Uuid::new_v4();
        
        // Extract extension safely
        let extension = Path::new(&sanitized_name)
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("");
        
        // Create filename with UUID to ensure uniqueness
        let secure_filename = if extension.is_empty() {
            file_id.to_string()
        } else {
            format!("{}.{}", file_id, extension)
        };
        
        let secure_path = base_dir.join(secure_filename);
        
        // Ensure the path is within the base directory (prevent path traversal)
        if !secure_path.starts_with(base_dir) {
            return Err(anyhow!("Generated path is outside base directory").into());
        }
        
        Ok(secure_path)
    }
    
    /// Validate that a path is safe and within allowed boundaries
    pub fn validate_path(&self, path: &Path, allowed_base: &Path) -> Result<()> {
        // Canonicalize the base path (which should exist)
        let canonical_base = allowed_base.canonicalize()
            .map_err(|_| anyhow!("Invalid base path: {}", allowed_base.display()))?;
        
        // For the target path, we need to handle the case where it doesn't exist yet
        let canonical_path = if path.exists() {
            // If the path exists, canonicalize it
            path.canonicalize()
                .map_err(|_| anyhow!("Invalid path: {}", path.display()))?
        } else {
            // If the path doesn't exist, canonicalize its parent and join the filename
            let parent = path.parent()
                .ok_or_else(|| anyhow!("Path has no parent: {}", path.display()))?;
            
            let filename = path.file_name()
                .ok_or_else(|| anyhow!("Path has no filename: {}", path.display()))?;
            
            // Canonicalize the parent directory (create it if it doesn't exist)
            std::fs::create_dir_all(parent)?;
            let canonical_parent = parent.canonicalize()
                .map_err(|_| anyhow!("Invalid parent path: {}", parent.display()))?;
            
            canonical_parent.join(filename)
        };
        
        // Check if the path is within the allowed base directory
        if !canonical_path.starts_with(&canonical_base) {
            return Err(anyhow!(
                "Path {} is outside allowed directory {}", 
                canonical_path.display(), 
                canonical_base.display()
            ).into());
        }
        
        Ok(())
    }
    
    /// Create a secure temporary directory for file processing
    pub fn create_secure_temp_dir(&self) -> Result<std::path::PathBuf> {
        use std::env;
        use std::fs;
        
        let temp_base = env::temp_dir();
        let temp_name = format!("ctf_analysis_{}", uuid::Uuid::new_v4());
        let temp_path = temp_base.join(temp_name);
        
        fs::create_dir_all(&temp_path)?;
        Ok(temp_path)
    }
    
    /// Validate file content for basic security checks
    pub fn validate_file_content(&self, data: &[u8], filename: &str) -> Result<()> {
        // Check for empty files
        if data.is_empty() {
            return Err(anyhow!("File is empty").into());
        }
        
        // Check for extremely large files that might cause memory issues
        if data.len() > MAX_FILE_SIZE as usize {
            return Err(anyhow!("File too large for processing").into());
        }
        
        // Basic malware signature detection (very basic patterns)
        self.check_basic_malware_signatures(data, filename)?;
        
        Ok(())
    }
    
    /// Basic malware signature detection
    fn check_basic_malware_signatures(&self, data: &[u8], filename: &str) -> Result<()> {
        // Check for suspicious file extensions with executable content
        let lower_filename = filename.to_lowercase();
        let suspicious_extensions = [".exe", ".scr", ".bat", ".cmd", ".com", ".pif"];
        
        let has_suspicious_extension = suspicious_extensions.iter()
            .any(|ext| lower_filename.ends_with(ext));
        
        if has_suspicious_extension {
            // Check for PE header in files with suspicious extensions
            if data.len() >= 2 && &data[0..2] == b"MZ" {
                // This is likely a Windows executable
                // In a real implementation, you might want to allow this for reverse engineering challenges
                // For now, we'll just log it as a warning but allow it
                tracing::warn!("Uploaded file {} appears to be a Windows executable", filename);
            }
        }
        
        // Check for script injection patterns in text files
        if let Ok(content) = std::str::from_utf8(data) {
            let content_lower = content.to_lowercase();
            
            // Look for potentially dangerous script patterns
            let dangerous_patterns = [
                "<script", "javascript:", "vbscript:", "data:text/html",
                "eval(", "document.write", "innerHTML", "outerhtml"
            ];
            
            for pattern in &dangerous_patterns {
                if content_lower.contains(pattern) {
                    tracing::warn!("File {} contains potentially dangerous pattern: {}", filename, pattern);
                    // Don't block these as they might be legitimate CTF challenges
                    break;
                }
            }
        }
        
        Ok(())
    }
    
    /// Clean up temporary files securely
    pub fn secure_cleanup(&self, paths: &[PathBuf]) -> Result<()> {
        for path in paths {
            if path.exists() {
                std::fs::remove_file(path)
                    .map_err(|e| anyhow!("Failed to remove file {}: {}", path.display(), e))?;
            }
        }
        Ok(())
    }
    
    /// Check if file type is allowed for upload
    pub fn is_file_type_allowed(&self, data: &[u8]) -> bool {
        // For CTF challenges, we want to be permissive but still block obviously dangerous files
        
        // Allow empty files (they might be part of challenges)
        if data.is_empty() {
            return true;
        }
        
        // Block files that are clearly malicious executables with no educational value
        // This is a very basic check - in practice, you might want more sophisticated detection
        
        // For now, allow all file types since CTF challenges can involve any type of file
        // The security is handled through sandboxing and process isolation
        true
    }
}

impl Default for FileSecurityValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    
    #[test]
    fn test_validate_file_size() {
        let validator = FileSecurityValidator::new();
        
        // Test valid size
        let small_data = vec![0u8; 1000];
        assert!(validator.validate_file_size(&small_data).is_ok());
        
        // Test oversized file
        let large_data = vec![0u8; (MAX_FILE_SIZE + 1) as usize];
        assert!(validator.validate_file_size(&large_data).is_err());
    }
    
    #[test]
    fn test_sanitize_filename() {
        let validator = FileSecurityValidator::new();
        
        // Test normal filename
        assert_eq!(validator.sanitize_filename("test.txt").unwrap(), "test.txt");
        
        // Test filename with dangerous characters
        assert_eq!(validator.sanitize_filename("../../../etc/passwd").unwrap(), "______etc_passwd");
        
        // Test Windows reserved name
        assert_eq!(validator.sanitize_filename("CON").unwrap(), "_CON");
        
        // Test empty filename
        assert!(validator.sanitize_filename("").is_err());
    }
    
    #[test]
    fn test_generate_secure_path() {
        let validator = FileSecurityValidator::new();
        let temp_base = env::temp_dir();
        let base_path = temp_base.join("test_ctf_secure_path");
        std::fs::create_dir_all(&base_path).unwrap();
        
        let secure_path = validator.generate_secure_path(&base_path, "test.txt").unwrap();
        
        // Should be within base directory
        assert!(secure_path.starts_with(&base_path));
        
        // Should have .txt extension
        assert_eq!(secure_path.extension().unwrap(), "txt");
        
        // Cleanup
        let _ = std::fs::remove_dir_all(&base_path);
    }
    
    #[test]
    fn test_validate_path() {
        let validator = FileSecurityValidator::new();
        let temp_base = env::temp_dir();
        let base_path = temp_base.join("test_ctf_validate_path");
        std::fs::create_dir_all(&base_path).unwrap();
        
        // Create a file within the base directory
        let safe_file = base_path.join("safe.txt");
        std::fs::write(&safe_file, "test").unwrap();
        
        // Should pass validation
        assert!(validator.validate_path(&safe_file, &base_path).is_ok());
        
        // Cleanup
        let _ = std::fs::remove_dir_all(&base_path);
    }
    
    #[test]
    fn test_validate_file_content() {
        let validator = FileSecurityValidator::new();
        
        // Test valid content
        let valid_data = b"Hello, world!";
        assert!(validator.validate_file_content(valid_data, "test.txt").is_ok());
        
        // Test empty file
        let empty_data = b"";
        assert!(validator.validate_file_content(empty_data, "empty.txt").is_err());
    }
    
    #[test]
    fn test_is_file_type_allowed() {
        let validator = FileSecurityValidator::new();
        
        // Test text file
        let text_data = b"Hello, world!";
        assert!(validator.is_file_type_allowed(text_data));
        
        // Test binary data
        let binary_data = b"\x7fELF\x01\x01\x01\x00";
        assert!(validator.is_file_type_allowed(binary_data));
        
        // Test empty file
        let empty_data = b"";
        assert!(validator.is_file_type_allowed(empty_data));
    }
}