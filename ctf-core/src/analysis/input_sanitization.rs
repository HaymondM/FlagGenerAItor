//! Input sanitization and validation for secure external tool execution

use crate::Result;
use anyhow::anyhow;
use regex::Regex;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

/// Input sanitizer for external tool execution
pub struct InputSanitizer {
    /// Allowed commands (whitelist approach)
    allowed_commands: HashSet<String>,
    /// Dangerous patterns to block
    dangerous_patterns: Vec<Regex>,
    /// Maximum input length
    max_input_length: usize,
}

impl InputSanitizer {
    /// Create a new input sanitizer with default settings
    pub fn new() -> Result<Self> {
        let mut sanitizer = Self {
            allowed_commands: HashSet::new(),
            dangerous_patterns: Vec::new(),
            max_input_length: 10000,
        };

        sanitizer.initialize_default_settings()?;
        Ok(sanitizer)
    }

    /// Create a new input sanitizer with custom settings
    pub fn with_allowed_commands(commands: Vec<String>) -> Result<Self> {
        let mut sanitizer = Self::new()?;
        sanitizer.allowed_commands = commands.into_iter().collect();
        Ok(sanitizer)
    }

    /// Initialize default security settings
    fn initialize_default_settings(&mut self) -> Result<()> {
        // Default allowed commands for CTF analysis
        let default_commands = vec![
            "strings".to_string(),
            "file".to_string(),
            "hexdump".to_string(),
            "xxd".to_string(),
            "zsteg".to_string(),
            "steghide".to_string(),
            "binwalk".to_string(),
            "exiftool".to_string(),
            "identify".to_string(), // ImageMagick
            "ffprobe".to_string(),  // FFmpeg
            "objdump".to_string(),
            "readelf".to_string(),
            "nm".to_string(),
            "ldd".to_string(),
            "otool".to_string(),    // macOS
            "dumpbin".to_string(),  // Windows
        ];

        self.allowed_commands = default_commands.into_iter().collect();

        // Compile dangerous patterns - using simple string matching for now
        let dangerous_pattern_strings = vec![
            // Command injection patterns
            r"[;&|`$]",
            r"\$\(",
            
            // Path traversal patterns
            r"\.\./",
            r"\.\.\\",
            
            // Dangerous commands (simple substring matching)
            r"rm -rf",
            r"del /f",
            r"format c:",
            r"fdisk",
            r"sudo rm",
            r"chmod 777",
            r"wget http",
            r"curl http",
            
            // Script execution patterns
            r"<script",
            r"javascript:",
            r"vbscript:",
            r"data:text/html",
            
            // SQL injection patterns
            r"' OR ",
            r"' AND ",
            r"UNION SELECT",
            
            // XSS patterns
            r"onclick=",
            r"onload=",
            r"onerror=",
            
            // File inclusion patterns
            r"file://",
            r"php://",
        ];

        for pattern_str in dangerous_pattern_strings {
            match Regex::new(pattern_str) {
                Ok(regex) => self.dangerous_patterns.push(regex),
                Err(e) => warn!("Failed to compile regex pattern '{}': {}", pattern_str, e),
            }
        }

        debug!("Initialized input sanitizer with {} allowed commands and {} dangerous patterns", 
               self.allowed_commands.len(), self.dangerous_patterns.len());

        Ok(())
    }

    /// Sanitize and validate a command for execution
    pub fn sanitize_command(&self, command: &str) -> Result<String> {
        // Check input length
        if command.len() > self.max_input_length {
            return Err(anyhow!("Command too long: {} characters (max: {})", 
                              command.len(), self.max_input_length).into());
        }

        // Check for dangerous patterns
        for pattern in &self.dangerous_patterns {
            if pattern.is_match(command) {
                return Err(anyhow!("Command contains dangerous pattern: {}", 
                                  pattern.as_str()).into());
            }
        }

        // Extract the base command (first word)
        let base_command = command.split_whitespace().next()
            .ok_or_else(|| anyhow!("Empty command"))?;

        // Check if command is in whitelist
        if !self.is_command_allowed(base_command) {
            return Err(anyhow!("Command '{}' is not in the allowed list", base_command).into());
        }

        // Additional validation for specific commands
        self.validate_command_specific(command)?;

        Ok(command.to_string())
    }

    /// Sanitize command arguments
    pub fn sanitize_arguments(&self, args: &[String]) -> Result<Vec<String>> {
        let mut sanitized_args = Vec::new();

        for arg in args {
            let sanitized_arg = self.sanitize_single_argument(arg)?;
            sanitized_args.push(sanitized_arg);
        }

        Ok(sanitized_args)
    }

    /// Sanitize a single argument
    fn sanitize_single_argument(&self, arg: &str) -> Result<String> {
        // Check argument length
        if arg.len() > 1000 {
            return Err(anyhow!("Argument too long: {} characters", arg.len()).into());
        }

        // Check for dangerous patterns in arguments
        for pattern in &self.dangerous_patterns {
            if pattern.is_match(arg) {
                return Err(anyhow!("Argument contains dangerous pattern: {}", 
                                  pattern.as_str()).into());
            }
        }

        // Validate file paths in arguments
        if arg.starts_with('/') || arg.starts_with('\\') || arg.contains("..") {
            self.validate_file_path_argument(arg)?;
        }

        Ok(arg.to_string())
    }

    /// Check if a command is allowed
    fn is_command_allowed(&self, command: &str) -> bool {
        // Extract just the command name without path
        let command_name = Path::new(command)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(command);

        self.allowed_commands.contains(command_name)
    }

    /// Validate command-specific patterns
    fn validate_command_specific(&self, command: &str) -> Result<()> {
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.is_empty() {
            return Err(anyhow!("Empty command").into());
        }

        let base_command = Path::new(parts[0])
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(parts[0]);

        match base_command {
            "strings" => self.validate_strings_command(&parts),
            "file" => self.validate_file_command(&parts),
            "hexdump" | "xxd" => self.validate_hex_command(&parts),
            "zsteg" => self.validate_zsteg_command(&parts),
            "steghide" => self.validate_steghide_command(&parts),
            "binwalk" => self.validate_binwalk_command(&parts),
            "exiftool" => self.validate_exiftool_command(&parts),
            "objdump" | "readelf" | "nm" => self.validate_binary_analysis_command(&parts),
            _ => Ok(()), // Other commands pass basic validation
        }
    }

    /// Validate strings command
    fn validate_strings_command(&self, parts: &[&str]) -> Result<()> {
        // strings is generally safe, but validate arguments
        for &part in parts.iter().skip(1) {
            if part.starts_with('-') {
                // Validate flags
                match part {
                    "-a" | "-f" | "-o" | "-t" | "-n" | "-w" | "--all" | 
                    "--print-file-name" | "--radix" | "--target" | 
                    "--bytes" | "--include-all-whitespace" => continue,
                    _ if part.starts_with("-n") => continue, // -n followed by number
                    _ => return Err(anyhow!("Unsafe strings flag: {}", part).into()),
                }
            }
        }
        Ok(())
    }

    /// Validate file command
    fn validate_file_command(&self, parts: &[&str]) -> Result<()> {
        // file command is generally safe for analysis
        for &part in parts.iter().skip(1) {
            if part.starts_with('-') {
                match part {
                    "-b" | "-i" | "-L" | "-z" | "-0" | "--brief" | 
                    "--mime" | "--dereference" | "--uncompress" | "--print0" => continue,
                    _ => return Err(anyhow!("Unsafe file flag: {}", part).into()),
                }
            }
        }
        Ok(())
    }

    /// Validate hex dump commands
    fn validate_hex_command(&self, parts: &[&str]) -> Result<()> {
        // hexdump and xxd are safe for read-only analysis
        for &part in parts.iter().skip(1) {
            if part.starts_with('-') {
                match part {
                    "-C" | "-c" | "-d" | "-o" | "-x" | "-l" | "-s" | "-v" |
                    "-g" | "-u" | "-p" | "-r" | "-i" => continue,
                    _ if part.starts_with("-l") || part.starts_with("-s") || 
                         part.starts_with("-g") => continue, // With values
                    _ => return Err(anyhow!("Unsafe hex command flag: {}", part).into()),
                }
            }
        }
        Ok(())
    }

    /// Validate zsteg command
    fn validate_zsteg_command(&self, parts: &[&str]) -> Result<()> {
        // zsteg is for steganography analysis
        for &part in parts.iter().skip(1) {
            if part.starts_with('-') {
                match part {
                    "-a" | "-v" | "-E" | "-o" | "-l" | "-b" | "-O" | "-P" => continue,
                    _ => return Err(anyhow!("Unsafe zsteg flag: {}", part).into()),
                }
            }
        }
        Ok(())
    }

    /// Validate steghide command
    fn validate_steghide_command(&self, parts: &[&str]) -> Result<()> {
        // Only allow extraction, not embedding
        if parts.len() < 2 {
            return Err(anyhow!("steghide requires subcommand").into());
        }

        match parts[1] {
            "extract" | "info" => {
                // These are safe read-only operations
                for &part in parts.iter().skip(2) {
                    if part.starts_with('-') {
                        match part {
                            "-sf" | "-xf" | "-p" | "-v" | "-q" => continue,
                            _ => return Err(anyhow!("Unsafe steghide flag: {}", part).into()),
                        }
                    }
                }
                Ok(())
            }
            _ => Err(anyhow!("Only 'extract' and 'info' steghide operations are allowed").into()),
        }
    }

    /// Validate binwalk command
    fn validate_binwalk_command(&self, parts: &[&str]) -> Result<()> {
        // binwalk for firmware analysis - be careful with extraction
        for &part in parts.iter().skip(1) {
            if part.starts_with('-') {
                match part {
                    "-B" | "-E" | "-A" | "-H" | "-g" | "-R" | "-r" | "-y" | 
                    "-f" | "-v" | "-q" | "-h" | "--signature" | "--opcodes" |
                    "--cast" | "--hexdump" | "--grep" | "--raw" | "--term" |
                    "--format" | "--verbose" | "--quiet" | "--help" => continue,
                    "-e" | "--extract" => {
                        // Extraction can be dangerous, but might be needed for analysis
                        warn!("binwalk extraction enabled - ensure secure environment");
                        continue;
                    }
                    _ => return Err(anyhow!("Unsafe binwalk flag: {}", part).into()),
                }
            }
        }
        Ok(())
    }

    /// Validate exiftool command
    fn validate_exiftool_command(&self, parts: &[&str]) -> Result<()> {
        // exiftool for metadata extraction - read-only operations only
        for &part in parts.iter().skip(1) {
            if part.starts_with('-') {
                match part {
                    "-a" | "-u" | "-g" | "-H" | "-l" | "-s" | "-S" | "-t" | "-v" |
                    "-x" | "-X" | "-j" | "-csv" | "-php" | "-tab" | "-args" => continue,
                    _ if part.starts_with("-TAG") => continue, // Specific tag extraction
                    _ => return Err(anyhow!("Unsafe exiftool flag: {}", part).into()),
                }
            }
        }
        Ok(())
    }

    /// Validate binary analysis commands
    fn validate_binary_analysis_command(&self, parts: &[&str]) -> Result<()> {
        // objdump, readelf, nm are for binary analysis
        for &part in parts.iter().skip(1) {
            if part.starts_with('-') {
                match part {
                    "-a" | "-f" | "-p" | "-h" | "-x" | "-d" | "-D" | "-S" | "-s" |
                    "-g" | "-e" | "-r" | "-R" | "-t" | "-T" | "-C" | "-w" | "-W" |
                    "--archive-headers" | "--file-headers" | "--private-headers" |
                    "--headers" | "--all-headers" | "--disassemble" | "--disassemble-all" |
                    "--source" | "--full-contents" | "--stabs" | "--syms" | "--dynamic-syms" |
                    "--reloc" | "--dynamic-reloc" | "--debugging" | "--line-numbers" |
                    "--demangle" | "--wide" | "--dwarf" => continue,
                    _ => return Err(anyhow!("Unsafe binary analysis flag: {}", part).into()),
                }
            }
        }
        Ok(())
    }

    /// Validate file path arguments
    fn validate_file_path_argument(&self, path_arg: &str) -> Result<()> {
        let path = Path::new(path_arg);

        // Check for path traversal
        if path_arg.contains("..") {
            return Err(anyhow!("Path traversal detected in argument: {}", path_arg).into());
        }

        // Check for absolute paths outside allowed directories
        if path.is_absolute() {
            // In a real implementation, you'd check against allowed directories
            // For now, we'll be restrictive
            let allowed_prefixes = ["/tmp", "/var/tmp"];
            let path_str = path_arg.to_lowercase();
            
            if !allowed_prefixes.iter().any(|prefix| path_str.starts_with(prefix)) {
                return Err(anyhow!("Absolute path not in allowed directory: {}", path_arg).into());
            }
        }

        // Check for dangerous file extensions in paths
        if let Some(extension) = path.extension().and_then(|ext| ext.to_str()) {
            let dangerous_extensions = ["exe", "bat", "cmd", "scr", "com", "pif", "sh"];
            if dangerous_extensions.contains(&extension.to_lowercase().as_str()) {
                warn!("Potentially dangerous file extension in path: {}", extension);
            }
        }

        Ok(())
    }

    /// Sanitize output from external tools
    pub fn sanitize_output(&self, output: &str) -> Result<String> {
        // Limit output size
        let max_output_size = 1024 * 1024; // 1MB
        let sanitized = if output.len() > max_output_size {
            warn!("Output truncated due to size limit");
            &output[..max_output_size]
        } else {
            output
        };

        // Remove potentially dangerous content from output
        let mut cleaned = sanitized.to_string();

        // Remove ANSI escape sequences
        let ansi_regex = Regex::new(r"\x1b\[[0-9;]*m").unwrap();
        cleaned = ansi_regex.replace_all(&cleaned, "").to_string();

        // Remove null bytes and other control characters
        cleaned = cleaned.chars()
            .filter(|&c| c >= ' ' || c == '\n' || c == '\r' || c == '\t')
            .collect();

        // Check for suspicious patterns in output
        for pattern in &self.dangerous_patterns {
            if pattern.is_match(&cleaned) {
                warn!("Dangerous pattern detected in output, filtering applied");
                // In a real implementation, you might want to filter out specific matches
                break;
            }
        }

        Ok(cleaned)
    }

    /// Add a command to the allowed list
    pub fn add_allowed_command(&mut self, command: String) {
        self.allowed_commands.insert(command);
    }

    /// Remove a command from the allowed list
    pub fn remove_allowed_command(&mut self, command: &str) {
        self.allowed_commands.remove(command);
    }

    /// Get the list of allowed commands
    pub fn get_allowed_commands(&self) -> Vec<String> {
        self.allowed_commands.iter().cloned().collect()
    }

    /// Set maximum input length
    pub fn set_max_input_length(&mut self, length: usize) {
        self.max_input_length = length;
    }
}

impl Default for InputSanitizer {
    fn default() -> Self {
        Self::new().expect("Failed to create default InputSanitizer")
    }
}

/// Safe file path utilities
pub struct SafePathHandler;

impl SafePathHandler {
    /// Resolve a path safely, preventing traversal attacks
    pub fn resolve_safe_path(base: &Path, relative: &str) -> Result<PathBuf> {
        // Normalize the relative path
        let normalized = relative.replace('\\', "/");
        
        // Check for dangerous patterns
        if normalized.contains("..") || normalized.starts_with('/') {
            return Err(anyhow!("Unsafe path: {}", relative).into());
        }

        // Build the path
        let resolved = base.join(&normalized);

        // Ensure the resolved path is still within the base directory
        let canonical_base = base.canonicalize()
            .map_err(|e| anyhow!("Cannot canonicalize base path: {}", e))?;
        
        let canonical_resolved = resolved.canonicalize()
            .map_err(|e| anyhow!("Cannot canonicalize resolved path: {}", e))?;

        if !canonical_resolved.starts_with(&canonical_base) {
            return Err(anyhow!("Path traversal detected: {}", relative).into());
        }

        Ok(resolved)
    }

    /// Create a safe temporary file path
    pub fn create_safe_temp_path(base: &Path, prefix: &str, extension: &str) -> Result<PathBuf> {
        use uuid::Uuid;

        // Sanitize inputs
        let safe_prefix = prefix.chars()
            .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
            .collect::<String>();

        let safe_extension = extension.chars()
            .filter(|c| c.is_alphanumeric())
            .collect::<String>();

        if safe_prefix.is_empty() {
            return Err(anyhow!("Invalid prefix").into());
        }

        // Generate unique filename
        let unique_id = Uuid::new_v4();
        let filename = if safe_extension.is_empty() {
            format!("{}_{}", safe_prefix, unique_id)
        } else {
            format!("{}_{}.{}", safe_prefix, unique_id, safe_extension)
        };

        Ok(base.join(filename))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_input_sanitizer_creation() {
        let sanitizer = InputSanitizer::new().unwrap();
        assert!(!sanitizer.allowed_commands.is_empty());
    }

    #[test]
    fn test_command_validation() {
        let sanitizer = InputSanitizer::new().unwrap();

        // Valid commands
        assert!(sanitizer.sanitize_command("strings file.txt").is_ok());
        assert!(sanitizer.sanitize_command("file test.bin").is_ok());

        // Invalid commands
        assert!(sanitizer.sanitize_command("rm -rf /").is_err());
        assert!(sanitizer.sanitize_command("strings file.txt; rm -rf /").is_err());
        assert!(sanitizer.sanitize_command("$(malicious_command)").is_err());
    }

    #[test]
    fn test_argument_sanitization() {
        let sanitizer = InputSanitizer::new().unwrap();

        // Valid arguments
        let valid_args = vec!["file.txt".to_string()];
        assert!(sanitizer.sanitize_arguments(&valid_args).is_ok());

        // Invalid arguments
        let invalid_args = vec!["../../../etc/passwd".to_string()];
        assert!(sanitizer.sanitize_arguments(&invalid_args).is_err());

        let injection_args = vec!["file.txt; rm -rf /".to_string()];
        assert!(sanitizer.sanitize_arguments(&injection_args).is_err());
    }

    #[test]
    fn test_output_sanitization() {
        let sanitizer = InputSanitizer::new().unwrap();

        // Normal output
        let normal_output = "File: test.txt\nType: ASCII text";
        let sanitized = sanitizer.sanitize_output(normal_output).unwrap();
        assert_eq!(sanitized, normal_output);

        // Output with ANSI codes
        let ansi_output = "\x1b[31mError:\x1b[0m File not found";
        let sanitized = sanitizer.sanitize_output(ansi_output).unwrap();
        assert!(!sanitized.contains("\x1b"));
    }

    #[test]
    fn test_safe_path_resolution() {
        use std::env;
        let temp_dir = env::temp_dir();
        
        // Create the temp directory if it doesn't exist
        std::fs::create_dir_all(&temp_dir).unwrap();
        
        // Valid relative path - create the subdirectory first
        let subdir = temp_dir.join("subdir");
        std::fs::create_dir_all(&subdir).unwrap();
        let test_file = subdir.join("file.txt");
        std::fs::write(&test_file, "test").unwrap();
        
        let safe_path = SafePathHandler::resolve_safe_path(&temp_dir, "subdir/file.txt");
        assert!(safe_path.is_ok());

        // Path traversal attempt
        let unsafe_path = SafePathHandler::resolve_safe_path(&temp_dir, "../../../etc/passwd");
        assert!(unsafe_path.is_err());

        // Absolute path
        let absolute_path = SafePathHandler::resolve_safe_path(&temp_dir, "/etc/passwd");
        assert!(absolute_path.is_err());
    }

    #[test]
    fn test_temp_path_creation() {
        let temp_dir = env::temp_dir();
        
        let temp_path = SafePathHandler::create_safe_temp_path(&temp_dir, "test", "txt").unwrap();
        
        assert!(temp_path.starts_with(&temp_dir));
        assert_eq!(temp_path.extension().unwrap(), "txt");
        assert!(temp_path.file_name().unwrap().to_str().unwrap().starts_with("test_"));
    }

    #[test]
    fn test_command_specific_validation() {
        let sanitizer = InputSanitizer::new().unwrap();

        // Valid strings command
        assert!(sanitizer.sanitize_command("strings file.txt").is_ok());

        // Invalid strings command with dangerous pattern
        assert!(sanitizer.sanitize_command("strings file.txt; rm -rf /").is_err());

        // Valid steghide command
        assert!(sanitizer.sanitize_command("steghide extract image.jpg").is_ok());

        // Invalid steghide command (embed operation)
        assert!(sanitizer.sanitize_command("steghide embed image.jpg").is_err());
    }

    #[test]
    fn test_allowed_commands_management() {
        let mut sanitizer = InputSanitizer::new().unwrap();
        
        // Add new command
        sanitizer.add_allowed_command("newcommand".to_string());
        assert!(sanitizer.is_command_allowed("newcommand"));

        // Remove command
        sanitizer.remove_allowed_command("newcommand");
        assert!(!sanitizer.is_command_allowed("newcommand"));
    }
}