//! Core data models for the CTF Assistant

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub id: Uuid,
    pub name: String,
    pub files: Vec<ChallengeFile>,
    pub context: String,
    pub created_at: DateTime<Utc>,
    pub analysis_results: Vec<AnalysisResult>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub mime_type: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub modified_at: Option<DateTime<Utc>>,
    pub additional: HashMap<String, String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformationResult {
    pub transformation: TransformationType,
    pub input_preview: String,
    pub output_preview: String,
    pub success: bool,
    pub meaningful: bool,
    pub chain_depth: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub category: FindingCategory,
    pub description: String,
    pub confidence: f32,
    pub evidence: Vec<String>,
    pub suggested_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindingCategory {
    Steganography,
    Cryptography,
    WebVulnerability,
    ReverseEngineering,
    Forensics,
    General,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HintRequest {
    pub challenge_id: Uuid,
    pub user_query: String,
    pub analysis_context: AnalysisContext,
    pub conversation_history: Vec<HintExchange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HintResponse {
    pub hints: Vec<String>,
    pub reasoning: String,
    pub suggested_next_steps: Vec<String>,
    pub learning_resources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HintExchange {
    pub request: String,
    pub response: HintResponse,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisContext {
    pub file_types: Vec<FileType>,
    pub transformations_attempted: Vec<TransformationType>,
    pub findings: Vec<Finding>,
    pub metadata: HashMap<String, String>,
}