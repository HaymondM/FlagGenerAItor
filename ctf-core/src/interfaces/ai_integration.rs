//! AI integration for hint generation

use crate::core::models::{HintRequest, HintResponse, FindingCategory, AnalysisContext, Finding};
use crate::Result;
use anyhow::{anyhow, Context};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, error, warn};

/// OpenAI API configuration
#[derive(Debug, Clone)]
pub struct OpenAIConfig {
    pub api_key: String,
    pub model: String,
    pub base_url: String,
    pub max_tokens: u32,
    pub temperature: f32,
    pub timeout: Duration,
}

impl Default for OpenAIConfig {
    fn default() -> Self {
        Self {
            api_key: std::env::var("OPENAI_API_KEY").unwrap_or_default(),
            model: "gpt-3.5-turbo".to_string(),
            base_url: "https://api.openai.com/v1".to_string(),
            max_tokens: 1000,
            temperature: 0.7,
            timeout: Duration::from_secs(30),
        }
    }
}

/// OpenAI API request structure
#[derive(Debug, Serialize)]
struct OpenAIRequest {
    model: String,
    messages: Vec<OpenAIMessage>,
    max_tokens: u32,
    temperature: f32,
}

/// OpenAI API message structure
#[derive(Debug, Serialize)]
struct OpenAIMessage {
    role: String,
    content: String,
}

/// OpenAI API response structure
#[derive(Debug, Deserialize)]
struct OpenAIResponse {
    choices: Vec<OpenAIChoice>,
}

#[derive(Debug, Deserialize)]
struct OpenAIChoice {
    message: OpenAIResponseMessage,
}

#[derive(Debug, Deserialize)]
struct OpenAIResponseMessage {
    content: String,
}

/// Hint generator with OpenAI integration
pub struct HintGenerator {
    client: Client,
    config: OpenAIConfig,
}

impl HintGenerator {
    /// Create a new hint generator with default configuration
    pub fn new() -> Self {
        Self::with_config(OpenAIConfig::default())
    }

    /// Create a new hint generator with custom configuration
    pub fn with_config(config: OpenAIConfig) -> Self {
        let client = Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("Failed to create HTTP client");

        Self { client, config }
    }

    /// Generate educational hints for a challenge
    pub async fn generate_hints(&self, request: &HintRequest) -> Result<HintResponse> {
        debug!("Generating hints for challenge {}", request.challenge_id);

        // Validate request
        request.validate()?;

        // Check if API key is available
        if self.config.api_key.is_empty() {
            warn!("OpenAI API key not configured, returning fallback response");
            return self.generate_fallback_hints(request);
        }

        // Build the prompt
        let prompt = self.build_prompt(request)?;
        debug!("Built prompt with {} characters", prompt.len());

        // Make API request
        match self.call_openai_api(&prompt).await {
            Ok(response) => {
                debug!("Received response from OpenAI API");
                self.parse_ai_response(&response, request)
            }
            Err(e) => {
                error!("OpenAI API call failed: {}", e);
                warn!("Falling back to rule-based hints");
                self.generate_fallback_hints(request)
            }
        }
    }

    /// Build the prompt for the AI model
    fn build_prompt(&self, request: &HintRequest) -> Result<String> {
        let mut prompt = String::new();

        // System prompt for educational boundaries
        prompt.push_str("You are an educational CTF (Capture The Flag) assistant. Your role is to provide helpful hints and guidance without giving away complete solutions or flags. ");
        prompt.push_str("Focus on teaching concepts, suggesting approaches, and explaining reasoning. ");
        prompt.push_str("Never provide exact flags, complete exploit code, or step-by-step solutions.\n\n");

        // Add analysis context
        prompt.push_str("## Analysis Context\n");
        self.add_context_to_prompt(&mut prompt, &request.analysis_context)?;

        // Add conversation history if available
        if !request.conversation_history.is_empty() {
            prompt.push_str("\n## Previous Conversation\n");
            for exchange in &request.conversation_history {
                prompt.push_str(&format!("User: {}\n", exchange.request));
                prompt.push_str(&format!("Assistant: {}\n\n", exchange.response.hints.join(" ")));
            }
        }

        // Add current user query
        prompt.push_str(&format!("\n## Current Question\n{}\n\n", request.user_query));

        // Add response format instructions
        prompt.push_str("## Response Format\n");
        prompt.push_str("Provide your response in the following format:\n");
        prompt.push_str("HINTS: [List 2-3 educational hints]\n");
        prompt.push_str("REASONING: [Explain your thought process]\n");
        prompt.push_str("NEXT_STEPS: [Suggest 1-2 next actions to try]\n");
        prompt.push_str("RESOURCES: [Recommend learning materials if relevant]\n");

        Ok(prompt)
    }

    /// Add analysis context to the prompt
    fn add_context_to_prompt(&self, prompt: &mut String, context: &AnalysisContext) -> Result<()> {
        // File types
        if !context.file_types.is_empty() {
            prompt.push_str("File types analyzed: ");
            let types: Vec<String> = context.file_types.iter().map(|t| t.to_string()).collect();
            prompt.push_str(&types.join(", "));
            prompt.push('\n');
        }

        // Transformations attempted
        if !context.transformations_attempted.is_empty() {
            prompt.push_str("Transformations attempted: ");
            let transformations: Vec<String> = context.transformations_attempted.iter()
                .map(|t| t.description().to_string()).collect();
            prompt.push_str(&transformations.join(", "));
            prompt.push('\n');
        }

        // Findings
        if !context.findings.is_empty() {
            prompt.push_str("Key findings:\n");
            for finding in &context.findings {
                prompt.push_str(&format!("- {} ({}): {}\n", 
                    finding.category, 
                    if finding.is_high_confidence() { "High confidence" } else { "Low confidence" },
                    finding.description
                ));
            }
        }

        // Additional metadata
        if !context.metadata.is_empty() {
            prompt.push_str("Additional context:\n");
            for (key, value) in &context.metadata {
                prompt.push_str(&format!("- {}: {}\n", key, value));
            }
        }

        Ok(())
    }

    /// Make API call to OpenAI
    async fn call_openai_api(&self, prompt: &str) -> Result<String> {
        let request = OpenAIRequest {
            model: self.config.model.clone(),
            messages: vec![
                OpenAIMessage {
                    role: "user".to_string(),
                    content: prompt.to_string(),
                }
            ],
            max_tokens: self.config.max_tokens,
            temperature: self.config.temperature,
        };

        let response = self.client
            .post(&format!("{}/chat/completions", self.config.base_url))
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .context("Failed to send request to OpenAI API")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow!("OpenAI API error {}: {}", status, error_text).into());
        }

        let api_response: OpenAIResponse = response.json().await
            .context("Failed to parse OpenAI API response")?;

        if api_response.choices.is_empty() {
            return Err(anyhow!("OpenAI API returned no choices").into());
        }

        Ok(api_response.choices[0].message.content.clone())
    }

    /// Parse AI response into structured format
    fn parse_ai_response(&self, response: &str, _request: &HintRequest) -> Result<HintResponse> {
        let mut hints = Vec::new();
        let mut reasoning = String::new();
        let mut next_steps = Vec::new();
        let mut resources = Vec::new();

        let lines: Vec<&str> = response.lines().collect();
        let mut current_section = "";

        for line in lines {
            let line = line.trim();
            
            if line.starts_with("HINTS:") {
                current_section = "hints";
                let content = line.strip_prefix("HINTS:").unwrap_or("").trim();
                if !content.is_empty() {
                    hints.push(content.to_string());
                }
            } else if line.starts_with("REASONING:") {
                current_section = "reasoning";
                reasoning = line.strip_prefix("REASONING:").unwrap_or("").trim().to_string();
            } else if line.starts_with("NEXT_STEPS:") {
                current_section = "next_steps";
                let content = line.strip_prefix("NEXT_STEPS:").unwrap_or("").trim();
                if !content.is_empty() {
                    next_steps.push(content.to_string());
                }
            } else if line.starts_with("RESOURCES:") {
                current_section = "resources";
                let content = line.strip_prefix("RESOURCES:").unwrap_or("").trim();
                if !content.is_empty() {
                    resources.push(content.to_string());
                }
            } else if !line.is_empty() && line.starts_with('-') {
                // Handle bullet points
                let content = line.strip_prefix('-').unwrap_or(line).trim();
                if !content.is_empty() {
                    match current_section {
                        "hints" => hints.push(content.to_string()),
                        "next_steps" => next_steps.push(content.to_string()),
                        "resources" => resources.push(content.to_string()),
                        _ => {}
                    }
                }
            } else if !line.is_empty() && current_section == "reasoning" {
                // Continue reasoning section
                if !reasoning.is_empty() {
                    reasoning.push(' ');
                }
                reasoning.push_str(line);
            }
        }

        // Apply content filtering
        hints = self.filter_content(hints)?;
        reasoning = self.filter_reasoning(&reasoning)?;

        // Ensure we have at least some content
        if hints.is_empty() {
            hints.push("Consider analyzing the file structure and looking for patterns in the data.".to_string());
        }

        if reasoning.is_empty() {
            reasoning = "Based on the analysis results, there are several approaches worth exploring.".to_string();
        }

        Ok(HintResponse::new(hints, reasoning, next_steps, resources)?)
    }

    /// Filter content to prevent solution leakage
    fn filter_content(&self, hints: Vec<String>) -> Result<Vec<String>> {
        let forbidden_patterns = [
            "flag{", "ctf{", "FLAG{", "CTF{",
            "password is", "the answer is", "solution:",
            "exploit:", "payload:", "inject:",
        ];

        let filtered: Vec<String> = hints.into_iter()
            .filter(|hint| {
                let hint_lower = hint.to_lowercase();
                !forbidden_patterns.iter().any(|pattern| hint_lower.contains(pattern))
            })
            .map(|hint| {
                // Replace potentially revealing terms
                hint.replace("flag", "target")
                    .replace("FLAG", "TARGET")
                    .replace("password", "credential")
                    .replace("exploit", "technique")
            })
            .collect();

        Ok(filtered)
    }

    /// Filter reasoning to maintain educational boundaries
    fn filter_reasoning(&self, reasoning: &str) -> Result<String> {
        let forbidden_patterns = [
            "flag{", "ctf{", "FLAG{", "CTF{",
            "the exact", "complete solution", "step-by-step",
        ];

        let reasoning_lower = reasoning.to_lowercase();
        if forbidden_patterns.iter().any(|pattern| reasoning_lower.contains(pattern)) {
            return Ok("The analysis suggests several potential approaches worth investigating further.".to_string());
        }

        Ok(reasoning.replace("flag", "target")
            .replace("FLAG", "TARGET")
            .replace("password", "credential")
            .replace("exploit", "technique"))
    }

    /// Generate fallback hints when AI is unavailable
    fn generate_fallback_hints(&self, request: &HintRequest) -> Result<HintResponse> {
        let context = &request.analysis_context;
        let mut hints = Vec::new();
        let mut next_steps = Vec::new();
        let mut resources = Vec::new();

        // Generate vulnerability-specific hints for web vulnerabilities
        let web_findings: Vec<Finding> = context.findings.iter()
            .filter(|f| f.category == FindingCategory::WebVulnerability)
            .cloned()
            .collect();

        if !web_findings.is_empty() {
            let vuln_hints = self.generate_vulnerability_hints(&web_findings)?;
            hints.extend(vuln_hints);

            // Add vulnerability-specific resources
            for finding in &web_findings {
                let vuln_type = self.identify_vulnerability_type(finding)?;
                let vuln_resources = self.generate_learning_resources(&vuln_type);
                resources.extend(vuln_resources);

                // Add payload suggestions as next steps
                let payload_suggestions = self.generate_payload_suggestions(&vuln_type)?;
                next_steps.extend(payload_suggestions);
            }
        }

        // Generate hints based on other finding categories
        for finding in &context.findings {
            match finding.category {
                FindingCategory::Steganography => {
                    hints.push("Look for hidden data within the file structure or metadata.".to_string());
                    next_steps.push("Try different steganography tools and examine file headers.".to_string());
                    resources.push("Learn about steganography techniques and detection methods.".to_string());
                }
                FindingCategory::Cryptography => {
                    hints.push("Analyze the patterns in the data for cryptographic signatures.".to_string());
                    next_steps.push("Consider frequency analysis and common cipher types.".to_string());
                    resources.push("Study classical and modern cryptography methods.".to_string());
                }
                FindingCategory::ReverseEngineering => {
                    hints.push("Look at the binary structure and identify key functions or strings.".to_string());
                    next_steps.push("Use disassemblers and debuggers to understand the program flow.".to_string());
                    resources.push("Study assembly language and reverse engineering techniques.".to_string());
                }
                FindingCategory::Forensics => {
                    hints.push("Examine file timestamps, metadata, and recovery techniques.".to_string());
                    next_steps.push("Use forensic tools to analyze file system artifacts.".to_string());
                    resources.push("Learn about digital forensics methodologies.".to_string());
                }
                FindingCategory::WebVulnerability => {
                    // Already handled above with vulnerability-specific logic
                    continue;
                }
                _ => {
                    hints.push("Examine the file contents and structure for unusual patterns.".to_string());
                    next_steps.push("Try different analysis tools and approaches.".to_string());
                }
            }
        }

        // Generate hints based on transformations
        if !context.transformations_attempted.is_empty() {
            hints.push("Some transformations were attempted - look for patterns in the results.".to_string());
            next_steps.push("Try combining different decoding methods or look for nested encodings.".to_string());
        }

        // Default hints if nothing specific found
        if hints.is_empty() {
            hints.push("Start by understanding the file type and structure.".to_string());
            hints.push("Look for patterns, unusual data, or hidden information.".to_string());
            next_steps.push("Use appropriate analysis tools for the file type.".to_string());
            next_steps.push("Document your findings and try different approaches.".to_string());
        }

        // Remove duplicates
        hints.sort();
        hints.dedup();
        next_steps.sort();
        next_steps.dedup();
        resources.sort();
        resources.dedup();

        let reasoning = format!(
            "Based on the analysis of {} file type(s) and {} finding(s), including {} web vulnerability finding(s), several specialized approaches are worth exploring.",
            context.file_types.len(),
            context.findings.len(),
            web_findings.len()
        );

        Ok(HintResponse::new(hints, reasoning, next_steps, resources)?)
    }

    /// Generate vulnerability-specific hints based on findings
    pub fn generate_vulnerability_hints(&self, findings: &[Finding]) -> Result<Vec<String>> {
        let mut hints = Vec::new();
        let mut vulnerability_types = HashMap::new();

        // Group findings by category and analyze patterns
        for finding in findings {
            if finding.category == FindingCategory::WebVulnerability {
                let vuln_type = self.identify_vulnerability_type(finding)?;
                vulnerability_types.entry(vuln_type).or_insert_with(Vec::new).push(finding);
            }
        }

        // Generate specific hints for each vulnerability type
        for (vuln_type, related_findings) in vulnerability_types {
            let specific_hints = self.generate_hints_for_vulnerability(&vuln_type, &related_findings)?;
            hints.extend(specific_hints);
        }

        // Add general web security hints if no specific vulnerabilities found
        if hints.is_empty() && findings.iter().any(|f| f.category == FindingCategory::WebVulnerability) {
            hints.extend(self.generate_general_web_hints()?);
        }

        Ok(hints)
    }

    /// Identify specific vulnerability type from finding
    fn identify_vulnerability_type(&self, finding: &Finding) -> Result<VulnerabilityType> {
        let description_lower = finding.description.to_lowercase();
        let evidence_text = finding.evidence.join(" ").to_lowercase();
        let combined_text = format!("{} {}", description_lower, evidence_text);

        if combined_text.contains("sql") || combined_text.contains("injection") || combined_text.contains("union") {
            Ok(VulnerabilityType::SqlInjection)
        } else if combined_text.contains("xss") || combined_text.contains("script") || combined_text.contains("javascript") {
            Ok(VulnerabilityType::CrossSiteScripting)
        } else if combined_text.contains("ssti") || combined_text.contains("template") || combined_text.contains("jinja") {
            Ok(VulnerabilityType::ServerSideTemplateInjection)
        } else if combined_text.contains("csrf") || combined_text.contains("token") || combined_text.contains("referer") {
            Ok(VulnerabilityType::CrossSiteRequestForgery)
        } else if combined_text.contains("lfi") || combined_text.contains("file") || combined_text.contains("path") {
            Ok(VulnerabilityType::LocalFileInclusion)
        } else if combined_text.contains("rce") || combined_text.contains("command") || combined_text.contains("exec") {
            Ok(VulnerabilityType::RemoteCodeExecution)
        } else if combined_text.contains("auth") || combined_text.contains("login") || combined_text.contains("session") {
            Ok(VulnerabilityType::AuthenticationBypass)
        } else {
            Ok(VulnerabilityType::General)
        }
    }

    /// Generate hints for specific vulnerability types
    fn generate_hints_for_vulnerability(&self, vuln_type: &VulnerabilityType, findings: &[&Finding]) -> Result<Vec<String>> {
        let mut hints = Vec::new();

        match vuln_type {
            VulnerabilityType::SqlInjection => {
                hints.push("Look for input parameters that interact with database queries.".to_string());
                hints.push("Try testing with single quotes, UNION statements, and boolean-based payloads.".to_string());
                hints.push("Consider time-based blind injection techniques if direct output isn't visible.".to_string());
                
                // Add specific hints based on evidence
                for finding in findings {
                    if finding.evidence.iter().any(|e| e.contains("error")) {
                        hints.push("Database errors in responses can reveal valuable information about the schema.".to_string());
                    }
                    if finding.evidence.iter().any(|e| e.contains("parameter")) {
                        hints.push("Focus on the identified parameters - they may be vulnerable injection points.".to_string());
                    }
                }
            }
            
            VulnerabilityType::CrossSiteScripting => {
                hints.push("Test input fields and URL parameters for script injection.".to_string());
                hints.push("Try different XSS payloads: reflected, stored, and DOM-based.".to_string());
                hints.push("Look for ways to bypass input filtering and encoding.".to_string());
                
                for finding in findings {
                    if finding.evidence.iter().any(|e| e.contains("reflect")) {
                        hints.push("Reflected XSS occurs when user input is immediately returned in the response.".to_string());
                    }
                    if finding.evidence.iter().any(|e| e.contains("stored")) {
                        hints.push("Stored XSS persists the payload in the application for other users to trigger.".to_string());
                    }
                }
            }
            
            VulnerabilityType::ServerSideTemplateInjection => {
                hints.push("Identify the template engine being used (Jinja2, Twig, etc.).".to_string());
                hints.push("Test template syntax injection in user-controllable input.".to_string());
                hints.push("Look for ways to access system functions through template expressions.".to_string());
                
                for finding in findings {
                    if finding.evidence.iter().any(|e| e.contains("jinja")) {
                        hints.push("Jinja2 templates use {{ }} for expressions - try injecting template syntax.".to_string());
                    }
                    if finding.evidence.iter().any(|e| e.contains("twig")) {
                        hints.push("Twig templates have specific syntax - research Twig SSTI payloads.".to_string());
                    }
                }
            }
            
            VulnerabilityType::CrossSiteRequestForgery => {
                hints.push("Check if the application uses CSRF tokens for state-changing requests.".to_string());
                hints.push("Look for requests that can be triggered from external sites.".to_string());
                hints.push("Test if the Referer header is properly validated.".to_string());
            }
            
            VulnerabilityType::LocalFileInclusion => {
                hints.push("Test file path parameters with directory traversal sequences (../).".to_string());
                hints.push("Try accessing system files like /etc/passwd or /proc/self/environ.".to_string());
                hints.push("Look for ways to include remote files or uploaded content.".to_string());
            }
            
            VulnerabilityType::RemoteCodeExecution => {
                hints.push("Identify input that gets passed to system commands or eval functions.".to_string());
                hints.push("Test command injection with separators like ; | & and $().".to_string());
                hints.push("Look for ways to upload and execute files on the server.".to_string());
            }
            
            VulnerabilityType::AuthenticationBypass => {
                hints.push("Test for weak session management and predictable tokens.".to_string());
                hints.push("Look for ways to escalate privileges or access other user accounts.".to_string());
                hints.push("Check if authentication can be bypassed through parameter manipulation.".to_string());
            }
            
            VulnerabilityType::General => {
                hints.push("Analyze the application's attack surface and input validation.".to_string());
                hints.push("Look for unusual behavior in responses to malformed input.".to_string());
            }
        }

        Ok(hints)
    }

    /// Generate general web security hints
    fn generate_general_web_hints(&self) -> Result<Vec<String>> {
        Ok(vec![
            "Start by mapping the application's functionality and input points.".to_string(),
            "Test all user-controllable input for injection vulnerabilities.".to_string(),
            "Look for information disclosure in error messages and responses.".to_string(),
            "Check for authentication and authorization flaws.".to_string(),
            "Examine client-side code for sensitive information or logic flaws.".to_string(),
        ])
    }

    /// Generate learning resources for vulnerability types
    pub fn generate_learning_resources(&self, vuln_type: &VulnerabilityType) -> Vec<String> {
        match vuln_type {
            VulnerabilityType::SqlInjection => vec![
                "OWASP SQL Injection Prevention Cheat Sheet".to_string(),
                "SQLMap documentation for automated testing".to_string(),
                "PortSwigger Web Security Academy - SQL Injection".to_string(),
            ],
            VulnerabilityType::CrossSiteScripting => vec![
                "OWASP XSS Prevention Cheat Sheet".to_string(),
                "PortSwigger Web Security Academy - Cross-site scripting".to_string(),
                "XSS Filter Evasion Cheat Sheet".to_string(),
            ],
            VulnerabilityType::ServerSideTemplateInjection => vec![
                "PortSwigger Web Security Academy - Server-side template injection".to_string(),
                "Template injection methodology and payloads".to_string(),
                "Jinja2 and Twig template engine documentation".to_string(),
            ],
            VulnerabilityType::CrossSiteRequestForgery => vec![
                "OWASP CSRF Prevention Cheat Sheet".to_string(),
                "Understanding SameSite cookie attribute".to_string(),
                "CSRF token implementation best practices".to_string(),
            ],
            VulnerabilityType::LocalFileInclusion => vec![
                "File inclusion vulnerability testing guide".to_string(),
                "Directory traversal attack techniques".to_string(),
                "Log poisoning and LFI to RCE techniques".to_string(),
            ],
            VulnerabilityType::RemoteCodeExecution => vec![
                "Command injection prevention techniques".to_string(),
                "Secure coding practices for system calls".to_string(),
                "Input validation and sanitization methods".to_string(),
            ],
            VulnerabilityType::AuthenticationBypass => vec![
                "OWASP Authentication Cheat Sheet".to_string(),
                "Session management security best practices".to_string(),
                "Multi-factor authentication implementation".to_string(),
            ],
            VulnerabilityType::General => vec![
                "OWASP Top 10 Web Application Security Risks".to_string(),
                "Web application penetration testing methodology".to_string(),
                "Secure development lifecycle practices".to_string(),
            ],
        }
    }

    /// Generate payload suggestions with appropriate boundaries
    pub fn generate_payload_suggestions(&self, vuln_type: &VulnerabilityType) -> Result<Vec<String>> {
        let suggestions = match vuln_type {
            VulnerabilityType::SqlInjection => vec![
                "Try basic injection: ' OR '1'='1".to_string(),
                "Test for error-based injection with invalid syntax".to_string(),
                "Use UNION SELECT to extract data from other tables".to_string(),
                "Consider time-based payloads: ' AND SLEEP(5)--".to_string(),
            ],
            VulnerabilityType::CrossSiteScripting => vec![
                "Basic payload: <script>alert('XSS')</script>".to_string(),
                "Event handler: <img src=x onerror=alert('XSS')>".to_string(),
                "Try different contexts: URL, form fields, headers".to_string(),
                "Test filter bypasses with encoding and obfuscation".to_string(),
            ],
            VulnerabilityType::ServerSideTemplateInjection => vec![
                "Test template expressions: {{7*7}} or ${7*7}".to_string(),
                "Try accessing config: {{config}} or {{self}}".to_string(),
                "Look for object methods: {{''.__class__}}".to_string(),
                "Research engine-specific payloads for your target".to_string(),
            ],
            VulnerabilityType::LocalFileInclusion => vec![
                "Directory traversal: ../../../../etc/passwd".to_string(),
                "Null byte injection: ../../../etc/passwd%00".to_string(),
                "Try different encodings: ..%2F..%2F..%2Fetc%2Fpasswd".to_string(),
                "Test with wrapper protocols: php://filter/".to_string(),
            ],
            _ => vec![
                "Start with simple test cases to confirm the vulnerability".to_string(),
                "Gradually increase payload complexity".to_string(),
                "Document successful payloads for further exploitation".to_string(),
            ],
        };

        // Filter payloads to ensure they're educational, not complete exploits
        let filtered: Vec<String> = suggestions.into_iter()
            .map(|s| self.sanitize_payload_suggestion(s))
            .collect();

        Ok(filtered)
    }

    /// Sanitize payload suggestions to maintain educational boundaries
    fn sanitize_payload_suggestion(&self, suggestion: String) -> String {
        // Remove or modify overly specific exploits
        suggestion
            .replace("rm -rf", "[destructive command]")
            .replace("/bin/sh", "[shell command]")
            .replace("cat /etc/passwd", "cat [system file]")
            .replace("wget", "[download command]")
            .replace("curl", "[http request]")
    }
}

/// Enumeration of vulnerability types for specialized hint generation
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VulnerabilityType {
    SqlInjection,
    CrossSiteScripting,
    ServerSideTemplateInjection,
    CrossSiteRequestForgery,
    LocalFileInclusion,
    RemoteCodeExecution,
    AuthenticationBypass,
    General,
}

impl Default for HintGenerator {
    fn default() -> Self {
        Self::new()
    }
}