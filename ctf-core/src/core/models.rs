//! Core data models for the CTF Assistant

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;
use anyhow::{Result, anyhow};
use std::fmt;

/// Maximum file size allowed (100MB)
pub const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;

/// Maximum recursion depth for transformations
pub const MAX_TRANSFORMATION_DEPTH: u8 = 5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub id: Uuid,
    pub name: String,
    pub files: Vec<ChallengeFile>,
    pub context: String,
    pub created_at: DateTime<Utc>,
    pub analysis_results: Vec<AnalysisResult>,
}

impl Challenge {
    /// Create a new challenge with validation
    pub fn new(name: String, context: String) -> Result<Self> {
        if name.trim().is_empty() {
            return Err(anyhow!("Challenge name cannot be empty"));
        }
        
        Ok(Challenge {
            id: Uuid::new_v4(),
            name: name.trim().to_string(),
            files: Vec::new(),
            context,
            created_at: Utc::now(),
            analysis_results: Vec::new(),
        })
    }

    /// Add a file to the challenge
    pub fn add_file(&mut self, file: ChallengeFile) {
        self.files.push(file);
    }

    /// Add an analysis result
    pub fn add_analysis_result(&mut self, result: AnalysisResult) {
        self.analysis_results.push(result);
    }

    /// Validate the challenge structure
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(anyhow!("Challenge name cannot be empty"));
        }

        for file in &self.files {
            file.validate()?;
        }

        for result in &self.analysis_results {
            result.validate()?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeFile {
    pub id: Uuid,
    pub original_name: String,
    pub file_type: FileType,
    pub size: u64,
    pub hash: String,
    pub storage_path: PathBuf,
    pub metadata: FileMetadata,
}

impl ChallengeFile {
    /// Create a new challenge file with validation
    pub fn new(
        original_name: String,
        file_type: FileType,
        size: u64,
        hash: String,
        storage_path: PathBuf,
        metadata: FileMetadata,
    ) -> Result<Self> {
        if original_name.trim().is_empty() {
            return Err(anyhow!("File name cannot be empty"));
        }

        if size > MAX_FILE_SIZE {
            return Err(anyhow!("File size {} exceeds maximum allowed size of {} bytes", size, MAX_FILE_SIZE));
        }

        if hash.is_empty() {
            return Err(anyhow!("File hash cannot be empty"));
        }

        Ok(ChallengeFile {
            id: Uuid::new_v4(),
            original_name: original_name.trim().to_string(),
            file_type,
            size,
            hash,
            storage_path,
            metadata,
        })
    }

    /// Validate the challenge file
    pub fn validate(&self) -> Result<()> {
        if self.original_name.trim().is_empty() {
            return Err(anyhow!("File name cannot be empty"));
        }

        if self.size > MAX_FILE_SIZE {
            return Err(anyhow!("File size {} exceeds maximum allowed size", self.size));
        }

        if self.hash.is_empty() {
            return Err(anyhow!("File hash cannot be empty"));
        }

        Ok(())
    }

    /// Check if file is an image type
    pub fn is_image(&self) -> bool {
        matches!(self.file_type, FileType::Image)
    }

    /// Check if file is a binary type
    pub fn is_binary(&self) -> bool {
        matches!(self.file_type, FileType::Binary)
    }

    /// Check if file is a web-related type
    pub fn is_web_related(&self) -> bool {
        matches!(self.file_type, FileType::Javascript | FileType::Html)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FileType {
    Image,
    Binary,
    Pcap,
    Pdf,
    Zip,
    Javascript,
    Html,
    Text,
    Unknown,
}

impl FileType {
    /// Convert from MIME type string
    pub fn from_mime_type(mime_type: &str) -> Self {
        match mime_type {
            mime if mime.starts_with("image/") => FileType::Image,
            "application/octet-stream" => FileType::Binary,
            "application/vnd.tcpdump.pcap" => FileType::Pcap,
            "application/pdf" => FileType::Pdf,
            "application/zip" => FileType::Zip,
            "text/javascript" | "application/javascript" => FileType::Javascript,
            "text/html" => FileType::Html,
            mime if mime.starts_with("text/") => FileType::Text,
            _ => FileType::Unknown,
        }
    }

    /// Convert to MIME type string
    pub fn to_mime_type(&self) -> &'static str {
        match self {
            FileType::Image => "image/*",
            FileType::Binary => "application/octet-stream",
            FileType::Pcap => "application/vnd.tcpdump.pcap",
            FileType::Pdf => "application/pdf",
            FileType::Zip => "application/zip",
            FileType::Javascript => "text/javascript",
            FileType::Html => "text/html",
            FileType::Text => "text/plain",
            FileType::Unknown => "application/octet-stream",
        }
    }

    /// Check if file type supports steganography analysis
    pub fn supports_steganography(&self) -> bool {
        matches!(self, FileType::Image)
    }

    /// Check if file type supports web vulnerability analysis
    pub fn supports_web_analysis(&self) -> bool {
        matches!(self, FileType::Javascript | FileType::Html | FileType::Text)
    }
}

impl fmt::Display for FileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileType::Image => write!(f, "Image"),
            FileType::Binary => write!(f, "Binary"),
            FileType::Pcap => write!(f, "Network Capture"),
            FileType::Pdf => write!(f, "PDF Document"),
            FileType::Zip => write!(f, "Archive"),
            FileType::Javascript => write!(f, "JavaScript"),
            FileType::Html => write!(f, "HTML"),
            FileType::Text => write!(f, "Text"),
            FileType::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub mime_type: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub modified_at: Option<DateTime<Utc>>,
    pub additional: HashMap<String, String>,
}

impl FileMetadata {
    /// Create new file metadata
    pub fn new() -> Self {
        FileMetadata {
            mime_type: None,
            created_at: None,
            modified_at: None,
            additional: HashMap::new(),
        }
    }

    /// Add additional metadata field
    pub fn add_field(&mut self, key: String, value: String) {
        self.additional.insert(key, value);
    }

    /// Get additional metadata field
    pub fn get_field(&self, key: &str) -> Option<&String> {
        self.additional.get(key)
    }
}

impl Default for FileMetadata {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub analyzer: String,
    pub file_id: Uuid,
    pub transformations: Vec<TransformationResult>,
    pub findings: Vec<Finding>,
    pub confidence: f32,
    pub execution_time: Duration,
}

impl AnalysisResult {
    /// Create a new analysis result with validation
    pub fn new(
        analyzer: String,
        file_id: Uuid,
        transformations: Vec<TransformationResult>,
        findings: Vec<Finding>,
        execution_time: Duration,
    ) -> Result<Self> {
        if analyzer.trim().is_empty() {
            return Err(anyhow!("Analyzer name cannot be empty"));
        }

        let confidence = Self::calculate_confidence(&transformations, &findings);

        Ok(AnalysisResult {
            analyzer: analyzer.trim().to_string(),
            file_id,
            transformations,
            findings,
            confidence,
            execution_time,
        })
    }

    /// Calculate overall confidence based on transformations and findings
    fn calculate_confidence(transformations: &[TransformationResult], findings: &[Finding]) -> f32 {
        if transformations.is_empty() && findings.is_empty() {
            return 0.0;
        }

        let transformation_confidence = if transformations.is_empty() {
            0.0
        } else {
            let meaningful_count = transformations.iter().filter(|t| t.meaningful).count() as f32;
            meaningful_count / transformations.len() as f32
        };

        let findings_confidence = if findings.is_empty() {
            0.0
        } else {
            findings.iter().map(|f| f.confidence).sum::<f32>() / findings.len() as f32
        };

        (transformation_confidence + findings_confidence) / 2.0
    }

    /// Validate the analysis result
    pub fn validate(&self) -> Result<()> {
        if self.analyzer.trim().is_empty() {
            return Err(anyhow!("Analyzer name cannot be empty"));
        }

        if !(0.0..=1.0).contains(&self.confidence) {
            return Err(anyhow!("Confidence must be between 0.0 and 1.0"));
        }

        for transformation in &self.transformations {
            transformation.validate()?;
        }

        for finding in &self.findings {
            finding.validate()?;
        }

        Ok(())
    }

    /// Check if analysis found meaningful results
    pub fn has_meaningful_results(&self) -> bool {
        self.transformations.iter().any(|t| t.meaningful) || !self.findings.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformationResult {
    pub transformation: TransformationType,
    pub input_preview: String,
    pub output_preview: String,
    pub success: bool,
    pub meaningful: bool,
    pub chain_depth: u8,
}

impl TransformationResult {
    /// Create a new transformation result with validation
    pub fn new(
        transformation: TransformationType,
        input_preview: String,
        output_preview: String,
        success: bool,
        meaningful: bool,
        chain_depth: u8,
    ) -> Result<Self> {
        if chain_depth > MAX_TRANSFORMATION_DEPTH {
            return Err(anyhow!("Chain depth {} exceeds maximum allowed depth of {}", chain_depth, MAX_TRANSFORMATION_DEPTH));
        }

        Ok(TransformationResult {
            transformation,
            input_preview: Self::truncate_preview(input_preview),
            output_preview: Self::truncate_preview(output_preview),
            success,
            meaningful,
            chain_depth,
        })
    }

    /// Truncate preview to reasonable length
    fn truncate_preview(preview: String) -> String {
        const MAX_PREVIEW_LENGTH: usize = 200;
        if preview.len() > MAX_PREVIEW_LENGTH {
            format!("{}...", &preview[..MAX_PREVIEW_LENGTH])
        } else {
            preview
        }
    }

    /// Validate the transformation result
    pub fn validate(&self) -> Result<()> {
        if self.chain_depth > MAX_TRANSFORMATION_DEPTH {
            return Err(anyhow!("Chain depth exceeds maximum allowed depth"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransformationType {
    Base64Decode,
    Base32Decode,
    Base58Decode,
    HexToAscii,
    BinaryToText,
    Rot13,
    Rot47,
    Caesar { shift: u8 },
    XorBruteForce { key: u8 },
    GzipDecompress,
    ZlibDecompress,
}

impl TransformationType {
    /// Get human-readable description of the transformation
    pub fn description(&self) -> &'static str {
        match self {
            TransformationType::Base64Decode => "Base64 decoding",
            TransformationType::Base32Decode => "Base32 decoding",
            TransformationType::Base58Decode => "Base58 decoding",
            TransformationType::HexToAscii => "Hexadecimal to ASCII conversion",
            TransformationType::BinaryToText => "Binary to text conversion",
            TransformationType::Rot13 => "ROT13 cipher",
            TransformationType::Rot47 => "ROT47 cipher",
            TransformationType::Caesar { .. } => "Caesar cipher",
            TransformationType::XorBruteForce { .. } => "XOR brute force",
            TransformationType::GzipDecompress => "Gzip decompression",
            TransformationType::ZlibDecompress => "Zlib decompression",
        }
    }

    /// Check if transformation is a cipher operation
    pub fn is_cipher(&self) -> bool {
        matches!(self, 
            TransformationType::Rot13 | 
            TransformationType::Rot47 | 
            TransformationType::Caesar { .. } | 
            TransformationType::XorBruteForce { .. }
        )
    }

    /// Check if transformation is an encoding operation
    pub fn is_encoding(&self) -> bool {
        matches!(self,
            TransformationType::Base64Decode |
            TransformationType::Base32Decode |
            TransformationType::Base58Decode |
            TransformationType::HexToAscii |
            TransformationType::BinaryToText
        )
    }

    /// Check if transformation is a compression operation
    pub fn is_compression(&self) -> bool {
        matches!(self,
            TransformationType::GzipDecompress |
            TransformationType::ZlibDecompress
        )
    }
}

impl fmt::Display for TransformationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransformationType::Caesar { shift } => write!(f, "Caesar cipher (shift: {})", shift),
            TransformationType::XorBruteForce { key } => write!(f, "XOR brute force (key: 0x{:02x})", key),
            _ => write!(f, "{}", self.description()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub category: FindingCategory,
    pub description: String,
    pub confidence: f32,
    pub evidence: Vec<String>,
    pub suggested_actions: Vec<String>,
}

impl Finding {
    /// Create a new finding with validation
    pub fn new(
        category: FindingCategory,
        description: String,
        confidence: f32,
        evidence: Vec<String>,
        suggested_actions: Vec<String>,
    ) -> Result<Self> {
        if description.trim().is_empty() {
            return Err(anyhow!("Finding description cannot be empty"));
        }

        if !(0.0..=1.0).contains(&confidence) {
            return Err(anyhow!("Confidence must be between 0.0 and 1.0"));
        }

        Ok(Finding {
            category,
            description: description.trim().to_string(),
            confidence,
            evidence,
            suggested_actions,
        })
    }

    /// Validate the finding
    pub fn validate(&self) -> Result<()> {
        if self.description.trim().is_empty() {
            return Err(anyhow!("Finding description cannot be empty"));
        }

        if !(0.0..=1.0).contains(&self.confidence) {
            return Err(anyhow!("Confidence must be between 0.0 and 1.0"));
        }

        Ok(())
    }

    /// Check if finding is high confidence (>= 0.7)
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.7
    }

    /// Add evidence to the finding
    pub fn add_evidence(&mut self, evidence: String) {
        if !evidence.trim().is_empty() {
            self.evidence.push(evidence.trim().to_string());
        }
    }

    /// Add suggested action to the finding
    pub fn add_suggested_action(&mut self, action: String) {
        if !action.trim().is_empty() {
            self.suggested_actions.push(action.trim().to_string());
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FindingCategory {
    Steganography,
    Cryptography,
    WebVulnerability,
    ReverseEngineering,
    Forensics,
    General,
}

impl FindingCategory {
    /// Get human-readable description of the category
    pub fn description(&self) -> &'static str {
        match self {
            FindingCategory::Steganography => "Hidden data in files",
            FindingCategory::Cryptography => "Cryptographic analysis",
            FindingCategory::WebVulnerability => "Web application security",
            FindingCategory::ReverseEngineering => "Binary analysis",
            FindingCategory::Forensics => "Digital forensics",
            FindingCategory::General => "General analysis",
        }
    }
}

impl fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FindingCategory::Steganography => write!(f, "Steganography"),
            FindingCategory::Cryptography => write!(f, "Cryptography"),
            FindingCategory::WebVulnerability => write!(f, "Web Vulnerability"),
            FindingCategory::ReverseEngineering => write!(f, "Reverse Engineering"),
            FindingCategory::Forensics => write!(f, "Forensics"),
            FindingCategory::General => write!(f, "General"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HintRequest {
    pub challenge_id: Uuid,
    pub user_query: String,
    pub analysis_context: AnalysisContext,
    pub conversation_history: Vec<HintExchange>,
}

impl HintRequest {
    /// Create a new hint request with validation
    pub fn new(
        challenge_id: Uuid,
        user_query: String,
        analysis_context: AnalysisContext,
        conversation_history: Vec<HintExchange>,
    ) -> Result<Self> {
        if user_query.trim().is_empty() {
            return Err(anyhow!("User query cannot be empty"));
        }

        Ok(HintRequest {
            challenge_id,
            user_query: user_query.trim().to_string(),
            analysis_context,
            conversation_history,
        })
    }

    /// Validate the hint request
    pub fn validate(&self) -> Result<()> {
        if self.user_query.trim().is_empty() {
            return Err(anyhow!("User query cannot be empty"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HintResponse {
    pub hints: Vec<String>,
    pub reasoning: String,
    pub suggested_next_steps: Vec<String>,
    pub learning_resources: Vec<String>,
}

impl HintResponse {
    /// Create a new hint response with validation
    pub fn new(
        hints: Vec<String>,
        reasoning: String,
        suggested_next_steps: Vec<String>,
        learning_resources: Vec<String>,
    ) -> Result<Self> {
        if hints.is_empty() {
            return Err(anyhow!("Hints cannot be empty"));
        }

        if reasoning.trim().is_empty() {
            return Err(anyhow!("Reasoning cannot be empty"));
        }

        let filtered_hints: Vec<String> = hints.into_iter()
            .filter(|h| !h.trim().is_empty())
            .map(|h| h.trim().to_string())
            .collect();

        if filtered_hints.is_empty() {
            return Err(anyhow!("At least one non-empty hint is required"));
        }

        Ok(HintResponse {
            hints: filtered_hints,
            reasoning: reasoning.trim().to_string(),
            suggested_next_steps: suggested_next_steps.into_iter()
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().to_string())
                .collect(),
            learning_resources: learning_resources.into_iter()
                .filter(|r| !r.trim().is_empty())
                .map(|r| r.trim().to_string())
                .collect(),
        })
    }

    /// Validate the hint response
    pub fn validate(&self) -> Result<()> {
        if self.hints.is_empty() {
            return Err(anyhow!("Hints cannot be empty"));
        }

        if self.reasoning.trim().is_empty() {
            return Err(anyhow!("Reasoning cannot be empty"));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HintExchange {
    pub request: String,
    pub response: HintResponse,
    pub timestamp: DateTime<Utc>,
}

impl HintExchange {
    /// Create a new hint exchange
    pub fn new(request: String, response: HintResponse) -> Self {
        HintExchange {
            request: request.trim().to_string(),
            response,
            timestamp: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisContext {
    pub file_types: Vec<FileType>,
    pub transformations_attempted: Vec<TransformationType>,
    pub findings: Vec<Finding>,
    pub metadata: HashMap<String, String>,
}

impl AnalysisContext {
    /// Create a new analysis context
    pub fn new() -> Self {
        AnalysisContext {
            file_types: Vec::new(),
            transformations_attempted: Vec::new(),
            findings: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Add a file type to the context
    pub fn add_file_type(&mut self, file_type: FileType) {
        if !self.file_types.contains(&file_type) {
            self.file_types.push(file_type);
        }
    }

    /// Add a transformation to the context
    pub fn add_transformation(&mut self, transformation: TransformationType) {
        if !self.transformations_attempted.contains(&transformation) {
            self.transformations_attempted.push(transformation);
        }
    }

    /// Add a finding to the context
    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    /// Add metadata to the context
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    /// Check if context has any meaningful findings
    pub fn has_findings(&self) -> bool {
        !self.findings.is_empty()
    }

    /// Get high confidence findings
    pub fn high_confidence_findings(&self) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.is_high_confidence()).collect()
    }
}

impl Default for AnalysisContext {
    fn default() -> Self {
        Self::new()
    }
}