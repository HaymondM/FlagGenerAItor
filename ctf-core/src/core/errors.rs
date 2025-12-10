//! Error types for the CTF Assistant

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CtfError {
    #[error("File operation failed: {0}")]
    FileError(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("Analysis error: {message}")]
    AnalysisError { message: String },
    
    #[error("Plugin error: {plugin_name} - {message}")]
    PluginError { plugin_name: String, message: String },
    
    #[error("AI integration error: {0}")]
    AiError(String),
    
    #[error("Security violation: {0}")]
    SecurityError(String),
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
}