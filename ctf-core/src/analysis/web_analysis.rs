//! Web application analysis tools

use crate::core::models::{Finding, FindingCategory};
use crate::Result;
use anyhow::{anyhow, Context};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub version: String,
    pub headers: HashMap<String, String>,
    pub parameters: HashMap<String, String>,
    pub cookies: HashMap<String, String>,
    pub body: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status_code: u16,
    pub status_text: String,
    pub version: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurpLogEntry {
    pub request: HttpRequest,
    pub response: Option<HttpResponse>,
    pub timestamp: Option<String>,
}

pub struct WebAnalyzer {
    sql_injection_patterns: Vec<Regex>,
    xss_patterns: Vec<Regex>,
    ssti_patterns: Vec<Regex>,
    csrf_patterns: Vec<Regex>,
}

impl WebAnalyzer {
    pub fn new() -> Result<Self> {
        let sql_injection_patterns = vec![
            Regex::new(r"(?i)(union\s+select|or\s+1\s*=\s*1|and\s+1\s*=\s*1)")?,
            Regex::new(r"(?i)('|;|--)")?,
            Regex::new(r"(?i)(drop\s+table|insert\s+into|delete\s+from|update\s+set)")?,
            Regex::new(r"(?i)(information_schema|sys\.tables|mysql\.user)")?,
        ];

        let xss_patterns = vec![
            Regex::new(r"(?i)(<script|</script>|javascript:|on\w+\s*=)")?,
            Regex::new(r"(?i)(alert\s*\(|confirm\s*\(|prompt\s*\()")?,
            Regex::new(r"(?i)(<img[^>]*src\s*=|<iframe[^>]*src\s*=)")?,
            Regex::new(r"(?i)(eval\s*\(|document\.cookie|window\.location)")?,
        ];

        let ssti_patterns = vec![
            Regex::new(r"\{\{.*\}\}")?,
            Regex::new(r"\{%.*%\}")?,
            Regex::new(r"\$\{.*\}")?,
            Regex::new(r"<%.*%>")?,
        ];

        let csrf_patterns = vec![
            Regex::new(r"(?i)(csrf|xsrf)")?,
            Regex::new(r"(?i)(_token|authenticity_token)")?,
        ];

        Ok(WebAnalyzer {
            sql_injection_patterns,
            xss_patterns,
            ssti_patterns,
            csrf_patterns,
        })
    }

    /// Parse Burp Suite log format
    pub fn parse_burp_log(&self, log_data: &str) -> Result<Vec<BurpLogEntry>> {
        let mut entries = Vec::new();
        
        // Split by request/response pairs (simplified parsing)
        let sections: Vec<&str> = log_data.split("======================================================").collect();
        
        for section in sections {
            if section.trim().is_empty() {
                continue;
            }
            
            if let Ok(entry) = self.parse_burp_section(section) {
                entries.push(entry);
            }
        }
        
        Ok(entries)
    }

    /// Parse a single Burp log section
    fn parse_burp_section(&self, section: &str) -> Result<BurpLogEntry> {
        let lines: Vec<&str> = section.lines().collect();
        let mut request_lines = Vec::new();
        let mut response_lines = Vec::new();
        let mut in_response = false;
        
        for line in lines {
            if line.starts_with("HTTP/") && !in_response {
                in_response = true;
                response_lines.push(line);
            } else if in_response {
                response_lines.push(line);
            } else {
                request_lines.push(line);
            }
        }
        
        let request = self.parse_http_request(&request_lines.join("\n"))?;
        let response = if !response_lines.is_empty() {
            Some(self.parse_http_response(&response_lines.join("\n"))?)
        } else {
            None
        };
        
        Ok(BurpLogEntry {
            request,
            response,
            timestamp: None,
        })
    }

    /// Parse raw HTTP request
    pub fn parse_http_request(&self, request_data: &str) -> Result<HttpRequest> {
        let lines: Vec<&str> = request_data.lines().collect();
        if lines.is_empty() {
            return Err(anyhow!("Empty HTTP request").into());
        }

        // Parse request line
        let request_line_parts: Vec<&str> = lines[0].split_whitespace().collect();
        if request_line_parts.len() < 3 {
            return Err(anyhow!("Invalid HTTP request line").into());
        }

        let method = request_line_parts[0].to_string();
        let url_path = request_line_parts[1].to_string();
        let version = request_line_parts[2].to_string();

        // Parse headers
        let mut headers = HashMap::new();
        let mut body_start = lines.len();
        
        for (i, line) in lines.iter().enumerate().skip(1) {
            if line.trim().is_empty() {
                body_start = i + 1;
                break;
            }
            
            if let Some(colon_pos) = line.find(':') {
                let key = line[..colon_pos].trim().to_lowercase();
                let value = line[colon_pos + 1..].trim().to_string();
                headers.insert(key, value);
            }
        }

        // Extract host for full URL
        let host = headers.get("host").unwrap_or(&"localhost".to_string()).clone();
        let full_url = if url_path.starts_with("http") {
            url_path.clone()
        } else {
            format!("http://{}{}", host, url_path)
        };

        // Parse URL parameters
        let parameters = self.extract_url_parameters(&full_url)?;

        // Parse cookies
        let cookies = self.extract_cookies(&headers);

        // Parse body
        let body = if body_start < lines.len() {
            Some(lines[body_start..].join("\n"))
        } else {
            None
        };

        Ok(HttpRequest {
            method,
            url: full_url,
            version,
            headers,
            parameters,
            cookies,
            body,
        })
    }

    /// Parse HTTP response
    pub fn parse_http_response(&self, response_data: &str) -> Result<HttpResponse> {
        let lines: Vec<&str> = response_data.lines().collect();
        if lines.is_empty() {
            return Err(anyhow!("Empty HTTP response").into());
        }

        // Parse status line
        let status_line_parts: Vec<&str> = lines[0].split_whitespace().collect();
        if status_line_parts.len() < 3 {
            return Err(anyhow!("Invalid HTTP response line").into());
        }

        let version = status_line_parts[0].to_string();
        let status_code: u16 = status_line_parts[1].parse()
            .context("Invalid status code")?;
        let status_text = status_line_parts[2..].join(" ");

        // Parse headers
        let mut headers = HashMap::new();
        let mut body_start = lines.len();
        
        for (i, line) in lines.iter().enumerate().skip(1) {
            if line.trim().is_empty() {
                body_start = i + 1;
                break;
            }
            
            if let Some(colon_pos) = line.find(':') {
                let key = line[..colon_pos].trim().to_lowercase();
                let value = line[colon_pos + 1..].trim().to_string();
                headers.insert(key, value);
            }
        }

        // Parse body
        let body = if body_start < lines.len() {
            Some(lines[body_start..].join("\n"))
        } else {
            None
        };

        Ok(HttpResponse {
            status_code,
            status_text,
            version,
            headers,
            body,
        })
    }

    /// Extract URL parameters from URL
    fn extract_url_parameters(&self, url_str: &str) -> Result<HashMap<String, String>> {
        let mut parameters = HashMap::new();
        
        if let Ok(url) = Url::parse(url_str) {
            for (key, value) in url.query_pairs() {
                parameters.insert(key.to_string(), value.to_string());
            }
        }
        
        Ok(parameters)
    }

    /// Extract cookies from headers
    fn extract_cookies(&self, headers: &HashMap<String, String>) -> HashMap<String, String> {
        let mut cookies = HashMap::new();
        
        if let Some(cookie_header) = headers.get("cookie") {
            for cookie_pair in cookie_header.split(';') {
                if let Some(eq_pos) = cookie_pair.find('=') {
                    let key = cookie_pair[..eq_pos].trim().to_string();
                    let value = cookie_pair[eq_pos + 1..].trim().to_string();
                    cookies.insert(key, value);
                }
            }
        }
        
        cookies
    }

    /// Analyze web content for vulnerabilities
    pub async fn analyze_web_content(&self, data: &[u8]) -> Result<Vec<Finding>> {
        let content = String::from_utf8_lossy(data);
        self.analyze_http_request(&content).await
    }

    /// Analyze HTTP requests for vulnerabilities
    pub async fn analyze_http_request(&self, request_data: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Try to parse as raw HTTP request first
        if let Ok(request) = self.parse_http_request(request_data) {
            findings.extend(self.detect_vulnerabilities(&request)?);
            findings.extend(self.identify_fuzzing_parameters(&request)?);
        } else if let Ok(burp_entries) = self.parse_burp_log(request_data) {
            // Try to parse as Burp log
            for entry in burp_entries {
                findings.extend(self.detect_vulnerabilities(&entry.request)?);
                findings.extend(self.identify_fuzzing_parameters(&entry.request)?);
            }
        } else {
            return Err(anyhow!("Unable to parse HTTP request data").into());
        }
        
        Ok(findings)
    }

    /// Detect vulnerabilities in HTTP request
    fn detect_vulnerabilities(&self, request: &HttpRequest) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check all parameters and body for vulnerabilities
        let mut all_values = Vec::new();
        all_values.extend(request.parameters.values());
        all_values.extend(request.cookies.values());
        if let Some(body) = &request.body {
            all_values.push(body);
        }
        
        for value in all_values {
            findings.extend(self.check_sql_injection(value)?);
            findings.extend(self.check_xss(value)?);
            findings.extend(self.check_ssti(value)?);
        }
        
        findings.extend(self.check_csrf_protection(request)?);
        
        Ok(findings)
    }

    /// Check for SQL injection patterns
    fn check_sql_injection(&self, value: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        for pattern in &self.sql_injection_patterns {
            if pattern.is_match(value) {
                let finding = Finding::new(
                    FindingCategory::WebVulnerability,
                    "Potential SQL injection vulnerability detected".to_string(),
                    0.7,
                    vec![format!("Suspicious pattern found in: {}", value)],
                    vec![
                        "Test with SQL injection payloads".to_string(),
                        "Check for error-based SQL injection".to_string(),
                        "Try union-based injection techniques".to_string(),
                    ],
                )?;
                findings.push(finding);
                break; // Only report once per value
            }
        }
        
        Ok(findings)
    }

    /// Check for XSS patterns
    fn check_xss(&self, value: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        for pattern in &self.xss_patterns {
            if pattern.is_match(value) {
                let finding = Finding::new(
                    FindingCategory::WebVulnerability,
                    "Potential Cross-Site Scripting (XSS) vulnerability detected".to_string(),
                    0.6,
                    vec![format!("XSS pattern found in: {}", value)],
                    vec![
                        "Test with XSS payloads".to_string(),
                        "Check for reflected XSS".to_string(),
                        "Try DOM-based XSS techniques".to_string(),
                    ],
                )?;
                findings.push(finding);
                break; // Only report once per value
            }
        }
        
        Ok(findings)
    }

    /// Check for Server-Side Template Injection patterns
    fn check_ssti(&self, value: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        for pattern in &self.ssti_patterns {
            if pattern.is_match(value) {
                let finding = Finding::new(
                    FindingCategory::WebVulnerability,
                    "Potential Server-Side Template Injection (SSTI) vulnerability detected".to_string(),
                    0.8,
                    vec![format!("Template injection pattern found in: {}", value)],
                    vec![
                        "Test with SSTI payloads".to_string(),
                        "Check template engine type".to_string(),
                        "Try code execution payloads".to_string(),
                    ],
                )?;
                findings.push(finding);
                break; // Only report once per value
            }
        }
        
        Ok(findings)
    }

    /// Check for CSRF protection
    fn check_csrf_protection(&self, request: &HttpRequest) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Only check POST, PUT, DELETE requests
        if !matches!(request.method.to_uppercase().as_str(), "POST" | "PUT" | "DELETE" | "PATCH") {
            return Ok(findings);
        }
        
        let has_csrf_token = request.parameters.keys().any(|k| {
            self.csrf_patterns.iter().any(|p| p.is_match(k))
        }) || request.body.as_ref().map_or(false, |body| {
            self.csrf_patterns.iter().any(|p| p.is_match(body))
        });
        
        if !has_csrf_token {
            let finding = Finding::new(
                FindingCategory::WebVulnerability,
                "Potential CSRF vulnerability - no CSRF token detected".to_string(),
                0.5,
                vec![format!("No CSRF protection found in {} request", request.method)],
                vec![
                    "Test for CSRF vulnerability".to_string(),
                    "Check if request can be replayed".to_string(),
                    "Verify if referrer checking is implemented".to_string(),
                ],
            )?;
            findings.push(finding);
        }
        
        Ok(findings)
    }

    /// Identify parameters suitable for fuzzing
    fn identify_fuzzing_parameters(&self, request: &HttpRequest) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        if !request.parameters.is_empty() {
            let param_names: Vec<String> = request.parameters.keys().cloned().collect();
            let finding = Finding::new(
                FindingCategory::WebVulnerability,
                "Parameters identified for fuzzing".to_string(),
                0.4,
                vec![format!("Found parameters: {}", param_names.join(", "))],
                vec![
                    "Fuzz parameters with various payloads".to_string(),
                    "Test for injection vulnerabilities".to_string(),
                    "Check parameter validation".to_string(),
                    "Try boundary value testing".to_string(),
                ],
            )?;
            findings.push(finding);
        }
        
        Ok(findings)
    }
}

impl Default for WebAnalyzer {
    fn default() -> Self {
        Self::new().expect("Failed to create WebAnalyzer")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_parse_http_request() {
        let analyzer = WebAnalyzer::new().unwrap();
        let request_data = "GET /test?param=value HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc123\r\n\r\n";
        
        let request = analyzer.parse_http_request(request_data).unwrap();
        
        assert_eq!(request.method, "GET");
        assert_eq!(request.url, "http://example.com/test?param=value");
        assert_eq!(request.version, "HTTP/1.1");
        assert_eq!(request.parameters.get("param"), Some(&"value".to_string()));
        assert_eq!(request.cookies.get("session"), Some(&"abc123".to_string()));
    }

    #[tokio::test]
    async fn test_sql_injection_detection() {
        let analyzer = WebAnalyzer::new().unwrap();
        let request_data = "POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nusername=admin' OR 1=1--&password=test";
        
        let findings = analyzer.analyze_http_request(request_data).await.unwrap();
        
        let sql_findings: Vec<_> = findings.iter()
            .filter(|f| f.description.contains("SQL injection"))
            .collect();
        
        assert!(!sql_findings.is_empty());
        assert!(sql_findings[0].confidence > 0.5);
    }

    #[tokio::test]
    async fn test_xss_detection() {
        let analyzer = WebAnalyzer::new().unwrap();
        let request_data = "GET /search?q=<script>alert('xss')</script> HTTP/1.1\r\nHost: example.com\r\n\r\n";
        
        let findings = analyzer.analyze_http_request(request_data).await.unwrap();
        
        let xss_findings: Vec<_> = findings.iter()
            .filter(|f| f.description.contains("XSS"))
            .collect();
        
        assert!(!xss_findings.is_empty());
        assert!(xss_findings[0].confidence > 0.5);
    }

    #[tokio::test]
    async fn test_csrf_detection() {
        let analyzer = WebAnalyzer::new().unwrap();
        let request_data = "POST /transfer HTTP/1.1\r\nHost: example.com\r\n\r\namount=1000&to=attacker";
        
        let findings = analyzer.analyze_http_request(request_data).await.unwrap();
        
        let csrf_findings: Vec<_> = findings.iter()
            .filter(|f| f.description.contains("CSRF"))
            .collect();
        
        assert!(!csrf_findings.is_empty());
        assert!(csrf_findings[0].confidence > 0.0);
    }

    #[tokio::test]
    async fn test_parameter_fuzzing_identification() {
        let analyzer = WebAnalyzer::new().unwrap();
        let request_data = "GET /api/user?id=123&name=test HTTP/1.1\r\nHost: example.com\r\n\r\n";
        
        let findings = analyzer.analyze_http_request(request_data).await.unwrap();
        
        let fuzzing_findings: Vec<_> = findings.iter()
            .filter(|f| f.description.contains("fuzzing"))
            .collect();
        
        assert!(!fuzzing_findings.is_empty());
        assert!(fuzzing_findings[0].evidence[0].contains("Found parameters: id, name"));
    }
}