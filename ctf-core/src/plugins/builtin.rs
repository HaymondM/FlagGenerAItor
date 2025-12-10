//! Built-in analysis plugins

use super::{AnalysisPlugin, AnalysisContext, PluginResult};
use crate::core::models::{FileType, Finding, FindingCategory};
use crate::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::time::Instant;
use tracing::debug;

/// Cryptography analysis plugin with frequency analysis
pub struct CryptographyPlugin;

impl CryptographyPlugin {
    pub fn new() -> Self {
        Self
    }
    
    /// Perform frequency analysis on text data
    fn frequency_analysis(&self, data: &[u8]) -> HashMap<u8, usize> {
        let mut frequencies = HashMap::new();
        for &byte in data {
            *frequencies.entry(byte).or_insert(0) += 1;
        }
        frequencies
    }
    
    /// Calculate entropy of data
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        
        let frequencies = self.frequency_analysis(data);
        let length = data.len() as f64;
        
        let mut entropy = 0.0;
        for &count in frequencies.values() {
            let probability = count as f64 / length;
            if probability > 0.0 {
                entropy -= probability * probability.log2();
            }
        }
        
        entropy
    }
    
    /// Detect potential cipher patterns
    fn detect_cipher_patterns(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Check for high entropy (potential encryption/encoding)
        let entropy = self.calculate_entropy(data);
        if entropy > 7.0 {
            findings.push(Finding::new(
                FindingCategory::Cryptography,
                "High entropy detected - possible encrypted or encoded data".to_string(),
                0.8,
                vec![format!("Entropy: {:.2}", entropy)],
                vec![
                    "Try common decoding methods (Base64, hex, etc.)".to_string(),
                    "Consider XOR or substitution ciphers".to_string(),
                ],
            ).unwrap());
        }
        
        // Check for repeating patterns (potential key reuse)
        if let Some(pattern_finding) = self.detect_repeating_patterns(data) {
            findings.push(pattern_finding);
        }
        
        // Check for common cipher indicators
        if let Some(indicator_finding) = self.detect_cipher_indicators(data) {
            findings.push(indicator_finding);
        }
        
        findings
    }
    
    /// Detect repeating patterns that might indicate key reuse
    fn detect_repeating_patterns(&self, data: &[u8]) -> Option<Finding> {
        if data.len() < 16 {
            return None;
        }
        
        // Look for repeating 4-byte patterns
        let mut pattern_counts = HashMap::new();
        for window in data.windows(4) {
            *pattern_counts.entry(window).or_insert(0) += 1;
        }
        
        let max_repeats = pattern_counts.values().max().unwrap_or(&0);
        if *max_repeats > 3 {
            Some(Finding::new(
                FindingCategory::Cryptography,
                "Repeating patterns detected - possible key reuse or weak cipher".to_string(),
                0.7,
                vec![format!("Maximum pattern repetitions: {}", max_repeats)],
                vec![
                    "Analyze pattern spacing for key length".to_string(),
                    "Try Vigenère cipher analysis".to_string(),
                ],
            ).unwrap())
        } else {
            None
        }
    }
    
    /// Detect common cipher indicators
    fn detect_cipher_indicators(&self, data: &[u8]) -> Option<Finding> {
        let text = String::from_utf8_lossy(data);
        
        // Check for common cipher formats
        if text.chars().all(|c| c.is_ascii_uppercase() || c.is_whitespace()) {
            Some(Finding::new(
                FindingCategory::Cryptography,
                "All uppercase text detected - possible classical cipher".to_string(),
                0.6,
                vec!["Text contains only uppercase letters and spaces".to_string()],
                vec![
                    "Try Caesar cipher with different shifts".to_string(),
                    "Consider Atbash or other substitution ciphers".to_string(),
                ],
            ).unwrap())
        } else {
            None
        }
    }
}

#[async_trait]
impl AnalysisPlugin for CryptographyPlugin {
    fn name(&self) -> &str {
        "cryptography"
    }
    
    fn supported_types(&self) -> Vec<FileType> {
        vec![FileType::Text, FileType::Binary, FileType::Unknown]
    }
    
    async fn analyze(&self, file_data: &[u8], context: &AnalysisContext) -> Result<PluginResult> {
        let start_time = Instant::now();
        
        debug!("Running cryptography analysis on {} bytes", file_data.len());
        
        let findings = self.detect_cipher_patterns(file_data);
        let confidence = if findings.is_empty() { 0.1 } else { 0.8 };
        
        let execution_time = start_time.elapsed();
        
        Ok(PluginResult::new(findings, confidence, execution_time))
    }
    
    fn priority(&self) -> u8 {
        70
    }
    
    fn version(&self) -> &str {
        "1.0.0"
    }
    
    fn description(&self) -> &str {
        "Cryptographic analysis including frequency analysis and cipher detection"
    }
}

/// Reverse engineering plugin with strings and symbols analysis
pub struct ReverseEngineeringPlugin;

impl ReverseEngineeringPlugin {
    pub fn new() -> Self {
        Self
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
        
        // Don't forget the last string
        if current_string.len() >= min_length {
            if let Ok(s) = String::from_utf8(current_string) {
                strings.push(s);
            }
        }
        
        strings
    }
    
    /// Analyze binary for interesting strings and patterns
    fn analyze_binary_content(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Extract strings
        let strings = self.extract_strings(data, 4);
        
        if !strings.is_empty() {
            let interesting_strings: Vec<&String> = strings.iter()
                .filter(|s| self.is_interesting_string(s))
                .collect();
            
            if !interesting_strings.is_empty() {
                let evidence: Vec<String> = interesting_strings.iter()
                    .take(10) // Limit to first 10 interesting strings
                    .map(|s| format!("\"{}\"", s))
                    .collect();
                
                findings.push(Finding::new(
                    FindingCategory::ReverseEngineering,
                    format!("Found {} interesting strings in binary", interesting_strings.len()),
                    0.7,
                    evidence,
                    vec![
                        "Examine strings for clues about functionality".to_string(),
                        "Look for hardcoded credentials or keys".to_string(),
                        "Check for file paths or URLs".to_string(),
                    ],
                ).unwrap());
            }
        }
        
        // Check for common binary patterns
        if let Some(pattern_finding) = self.detect_binary_patterns(data) {
            findings.push(pattern_finding);
        }
        
        findings
    }
    
    /// Check if a string is potentially interesting for reverse engineering
    fn is_interesting_string(&self, s: &str) -> bool {
        let s_lower = s.to_lowercase();
        
        // Check for common interesting patterns
        s_lower.contains("flag") ||
        s_lower.contains("key") ||
        s_lower.contains("password") ||
        s_lower.contains("secret") ||
        s_lower.contains("admin") ||
        s_lower.contains("root") ||
        s_lower.contains("http") ||
        s_lower.contains("ftp") ||
        s_lower.contains(".txt") ||
        s_lower.contains(".exe") ||
        s_lower.contains(".dll") ||
        s_lower.contains("ctf") ||
        s.len() > 20 // Long strings might be interesting
    }
    
    /// Detect common binary patterns
    fn detect_binary_patterns(&self, data: &[u8]) -> Option<Finding> {
        // Check for ELF header
        if data.len() >= 4 && &data[0..4] == b"\x7fELF" {
            return Some(Finding::new(
                FindingCategory::ReverseEngineering,
                "ELF executable detected".to_string(),
                0.9,
                vec!["File starts with ELF magic bytes".to_string()],
                vec![
                    "Use disassembler tools like objdump or Ghidra".to_string(),
                    "Check for symbols and section headers".to_string(),
                ],
            ).unwrap());
        }
        
        // Check for PE header
        if data.len() >= 2 && &data[0..2] == b"MZ" {
            return Some(Finding::new(
                FindingCategory::ReverseEngineering,
                "PE executable detected".to_string(),
                0.9,
                vec!["File starts with MZ magic bytes".to_string()],
                vec![
                    "Use PE analysis tools".to_string(),
                    "Check imports and exports".to_string(),
                ],
            ).unwrap());
        }
        
        None
    }
}

#[async_trait]
impl AnalysisPlugin for ReverseEngineeringPlugin {
    fn name(&self) -> &str {
        "reverse-engineering"
    }
    
    fn supported_types(&self) -> Vec<FileType> {
        vec![FileType::Binary, FileType::Unknown]
    }
    
    async fn analyze(&self, file_data: &[u8], context: &AnalysisContext) -> Result<PluginResult> {
        let start_time = Instant::now();
        
        debug!("Running reverse engineering analysis on {} bytes", file_data.len());
        
        let findings = self.analyze_binary_content(file_data);
        let confidence = if findings.is_empty() { 0.2 } else { 0.8 };
        
        let execution_time = start_time.elapsed();
        
        Ok(PluginResult::new(findings, confidence, execution_time))
    }
    
    fn priority(&self) -> u8 {
        60
    }
    
    fn version(&self) -> &str {
        "1.0.0"
    }
    
    fn description(&self) -> &str {
        "Reverse engineering analysis including strings extraction and binary pattern detection"
    }
}

/// Web analysis plugin for HTTP parsing and vulnerability detection
pub struct WebAnalysisPlugin;

impl WebAnalysisPlugin {
    pub fn new() -> Self {
        Self
    }
    
    /// Parse HTTP request data
    fn parse_http_request(&self, data: &str) -> Option<HttpRequest> {
        let lines: Vec<&str> = data.lines().collect();
        if lines.is_empty() {
            return None;
        }
        
        // Parse request line
        let request_parts: Vec<&str> = lines[0].split_whitespace().collect();
        if request_parts.len() < 3 {
            return None;
        }
        
        let method = request_parts[0].to_string();
        let path = request_parts[1].to_string();
        let version = request_parts[2].to_string();
        
        // Parse headers
        let mut headers = HashMap::new();
        let mut body_start = lines.len();
        
        for (i, line) in lines.iter().enumerate().skip(1) {
            if line.is_empty() {
                body_start = i + 1;
                break;
            }
            
            if let Some(colon_pos) = line.find(':') {
                let key = line[..colon_pos].trim().to_string();
                let value = line[colon_pos + 1..].trim().to_string();
                headers.insert(key, value);
            }
        }
        
        // Extract body
        let body = if body_start < lines.len() {
            lines[body_start..].join("\n")
        } else {
            String::new()
        };
        
        Some(HttpRequest {
            method,
            path,
            version,
            headers,
            body,
        })
    }
    
    /// Analyze HTTP request for vulnerabilities
    fn analyze_http_vulnerabilities(&self, request: &HttpRequest) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Check for SQL injection patterns
        if let Some(sqli_finding) = self.detect_sql_injection(&request.path, &request.body) {
            findings.push(sqli_finding);
        }
        
        // Check for XSS patterns
        if let Some(xss_finding) = self.detect_xss_patterns(&request.path, &request.body) {
            findings.push(xss_finding);
        }
        
        // Check for SSTI patterns
        if let Some(ssti_finding) = self.detect_ssti_patterns(&request.path, &request.body) {
            findings.push(ssti_finding);
        }
        
        // Check for interesting parameters
        if let Some(param_finding) = self.analyze_parameters(&request.path, &request.body) {
            findings.push(param_finding);
        }
        
        findings
    }
    
    /// Detect potential SQL injection patterns
    fn detect_sql_injection(&self, path: &str, body: &str) -> Option<Finding> {
        let combined = format!("{} {}", path, body).to_lowercase();
        
        let sqli_patterns = [
            "union select", "or 1=1", "' or '1'='1", "admin'--", 
            "' union", "order by", "group by", "having", "drop table"
        ];
        
        for pattern in &sqli_patterns {
            if combined.contains(pattern) {
                return Some(Finding::new(
                    FindingCategory::WebVulnerability,
                    "Potential SQL injection pattern detected".to_string(),
                    0.8,
                    vec![format!("Found pattern: {}", pattern)],
                    vec![
                        "Test with SQL injection payloads".to_string(),
                        "Check for error-based SQL injection".to_string(),
                        "Try time-based blind SQL injection".to_string(),
                    ],
                ).unwrap());
            }
        }
        
        None
    }
    
    /// Detect potential XSS patterns
    fn detect_xss_patterns(&self, path: &str, body: &str) -> Option<Finding> {
        let combined = format!("{} {}", path, body).to_lowercase();
        
        let xss_patterns = [
            "<script", "javascript:", "onerror=", "onload=", 
            "alert(", "document.cookie", "eval("
        ];
        
        for pattern in &xss_patterns {
            if combined.contains(pattern) {
                return Some(Finding::new(
                    FindingCategory::WebVulnerability,
                    "Potential XSS pattern detected".to_string(),
                    0.7,
                    vec![format!("Found pattern: {}", pattern)],
                    vec![
                        "Test with XSS payloads".to_string(),
                        "Check for reflected XSS".to_string(),
                        "Try stored XSS if applicable".to_string(),
                    ],
                ).unwrap());
            }
        }
        
        None
    }
    
    /// Detect potential SSTI patterns
    fn detect_ssti_patterns(&self, path: &str, body: &str) -> Option<Finding> {
        let combined = format!("{} {}", path, body);
        
        let ssti_patterns = [
            "{{", "}}", "${", "<%", "%>", "#{", "[[", "]]"
        ];
        
        for pattern in &ssti_patterns {
            if combined.contains(pattern) {
                return Some(Finding::new(
                    FindingCategory::WebVulnerability,
                    "Potential Server-Side Template Injection pattern detected".to_string(),
                    0.6,
                    vec![format!("Found template syntax: {}", pattern)],
                    vec![
                        "Test with SSTI payloads for different template engines".to_string(),
                        "Try mathematical expressions in templates".to_string(),
                        "Check for code execution capabilities".to_string(),
                    ],
                ).unwrap());
            }
        }
        
        None
    }
    
    /// Analyze parameters for fuzzing opportunities
    fn analyze_parameters(&self, path: &str, body: &str) -> Option<Finding> {
        let mut parameters = Vec::new();
        
        // Extract URL parameters
        if let Some(query_start) = path.find('?') {
            let query = &path[query_start + 1..];
            for param in query.split('&') {
                if let Some(eq_pos) = param.find('=') {
                    parameters.push(param[..eq_pos].to_string());
                }
            }
        }
        
        // Extract POST parameters (simple form data)
        if body.contains('=') && body.contains('&') {
            for param in body.split('&') {
                if let Some(eq_pos) = param.find('=') {
                    parameters.push(param[..eq_pos].to_string());
                }
            }
        }
        
        if !parameters.is_empty() {
            Some(Finding::new(
                FindingCategory::WebVulnerability,
                format!("Found {} parameters suitable for fuzzing", parameters.len()),
                0.5,
                parameters.iter().take(10).map(|p| format!("Parameter: {}", p)).collect(),
                vec![
                    "Fuzz parameters with various payloads".to_string(),
                    "Test for injection vulnerabilities".to_string(),
                    "Check parameter pollution".to_string(),
                ],
            ).unwrap())
        } else {
            None
        }
    }
}

#[async_trait]
impl AnalysisPlugin for WebAnalysisPlugin {
    fn name(&self) -> &str {
        "web-analysis"
    }
    
    fn supported_types(&self) -> Vec<FileType> {
        vec![FileType::Text, FileType::Html, FileType::Javascript]
    }
    
    async fn analyze(&self, file_data: &[u8], context: &AnalysisContext) -> Result<PluginResult> {
        let start_time = Instant::now();
        
        debug!("Running web analysis on {} bytes", file_data.len());
        
        let data_str = String::from_utf8_lossy(file_data);
        let mut findings = Vec::new();
        
        // Try to parse as HTTP request
        if let Some(request) = self.parse_http_request(&data_str) {
            findings.extend(self.analyze_http_vulnerabilities(&request));
        } else {
            // Analyze as general web content
            let dummy_request = HttpRequest {
                method: "GET".to_string(),
                path: data_str.to_string(),
                version: "HTTP/1.1".to_string(),
                headers: HashMap::new(),
                body: String::new(),
            };
            findings.extend(self.analyze_http_vulnerabilities(&dummy_request));
        }
        
        let confidence = if findings.is_empty() { 0.1 } else { 0.7 };
        let execution_time = start_time.elapsed();
        
        Ok(PluginResult::new(findings, confidence, execution_time))
    }
    
    fn priority(&self) -> u8 {
        80
    }
    
    fn version(&self) -> &str {
        "1.0.0"
    }
    
    fn description(&self) -> &str {
        "Web application analysis including HTTP parsing and vulnerability detection"
    }
}

/// Simple HTTP request representation
#[derive(Debug, Clone)]
struct HttpRequest {
    method: String,
    path: String,
    version: String,
    headers: HashMap<String, String>,
    body: String,
}