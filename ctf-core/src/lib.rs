//! CTF Core Library
//! 
//! This library provides the core functionality for the CTF AI Assistant,
//! including file analysis, decoding pipelines, plugin management, and AI integration.

pub mod core;
pub mod analysis;
pub mod plugins;
pub mod interfaces;

// Re-export commonly used types
pub use core::{
    models::{Challenge, ChallengeFile, AnalysisResult, Finding},
    errors::CtfError,
};

pub use analysis::{
    file_analyzer::FileAnalyzer,
    decoder_pipeline::DecoderPipeline,
};

pub use plugins::PluginManager;

/// Result type used throughout the CTF Assistant
pub type Result<T> = std::result::Result<T, CtfError>;