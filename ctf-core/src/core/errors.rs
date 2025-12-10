//! Error types for the CTF Assistant

use thiserror::Error;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// Contextual information about an error occurrence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorContext {
    /// The operation that was being performed when the error occurred
    pub operation: String,
    /// The file type being processed (if applicable)
    pub file_type: Option<String>,
    /// The file path or identifier (if applicable)
    pub file_path: Option<String>,
    /// Additional diagnostic information
    pub diagnostics: HashMap<String, String>,
    /// Timestamp when the error occurred
    pub timestamp: DateTime<Utc>,
    /// Stack trace or call chain information
    pub call_chain: Vec<String>,
}

impl ErrorContext {
    pub fn new(operation: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            file_type: None,
            file_path: None,
            diagnostics: HashMap::new(),
            timestamp: Utc::now(),
            call_chain: Vec::new(),
        }
    }

    pub fn with_file_type(mut self, file_type: impl Into<String>) -> Self {
        self.file_type = Some(file_type.into());
        self
    }

    pub fn with_file_path(mut self, file_path: impl Into<String>) -> Self {
        self.file_path = Some(file_path.into());
        self
    }

    pub fn with_diagnostic(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.diagnostics.insert(key.into(), value.into());
        self
    }

    pub fn with_call_chain(mut self, chain: Vec<String>) -> Self {
        self.call_chain = chain;
        self
    }

    pub fn add_to_call_chain(&mut self, function: impl Into<String>) {
        self.call_chain.push(function.into());
    }
}

/// User-friendly error information for display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserFriendlyError {
    /// Simple, non-technical error message
    pub message: String,
    /// Suggested actions the user can take
    pub suggestions: Vec<String>,
    /// Whether this error is recoverable
    pub recoverable: bool,
    /// Error category for grouping similar errors
    pub category: ErrorCategory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorCategory {
    FileAccess,
    FileFormat,
    Analysis,
    Network,
    Configuration,
    Security,
    Plugin,
    System,
}

#[derive(Error, Debug)]
pub enum CtfError {
    #[error("File operation failed: {0}")]
    FileError(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("Regex error: {0}")]
    RegexError(#[from] regex::Error),
    
    #[error("General error: {0}")]
    GeneralError(#[from] anyhow::Error),
    
    #[error("Analysis error: {message}")]
    AnalysisError { 
        message: String,
        context: Option<ErrorContext>,
    },
    
    #[error("Plugin error: {plugin_name} - {message}")]
    PluginError { 
        plugin_name: String, 
        message: String,
        context: Option<ErrorContext>,
    },
    
    #[error("AI integration error: {0}")]
    AiError(String),
    
    #[error("Security violation: {0}")]
    SecurityError(String),
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("File processing error: {message}")]
    FileProcessingError {
        message: String,
        context: ErrorContext,
    },

    #[error("External tool error: {tool} failed with: {message}")]
    ExternalToolError {
        tool: String,
        message: String,
        context: Option<ErrorContext>,
    },

    #[error("Timeout error: {operation} timed out after {duration_ms}ms")]
    TimeoutError {
        operation: String,
        duration_ms: u64,
        context: Option<ErrorContext>,
    },

    #[error("Resource limit exceeded: {resource} limit of {limit} exceeded")]
    ResourceLimitError {
        resource: String,
        limit: String,
        context: Option<ErrorContext>,
    },
}

impl CtfError {
    /// Create a new analysis error with context
    pub fn analysis_error(message: impl Into<String>, context: ErrorContext) -> Self {
        Self::AnalysisError {
            message: message.into(),
            context: Some(context),
        }
    }

    /// Create a new plugin error with context
    pub fn plugin_error(plugin_name: impl Into<String>, message: impl Into<String>, context: ErrorContext) -> Self {
        Self::PluginError {
            plugin_name: plugin_name.into(),
            message: message.into(),
            context: Some(context),
        }
    }

    /// Create a new file processing error with context
    pub fn file_processing_error(message: impl Into<String>, context: ErrorContext) -> Self {
        Self::FileProcessingError {
            message: message.into(),
            context,
        }
    }

    /// Create a new external tool error with context
    pub fn external_tool_error(tool: impl Into<String>, message: impl Into<String>, context: Option<ErrorContext>) -> Self {
        Self::ExternalToolError {
            tool: tool.into(),
            message: message.into(),
            context,
        }
    }

    /// Create a new timeout error with context
    pub fn timeout_error(operation: impl Into<String>, duration_ms: u64, context: Option<ErrorContext>) -> Self {
        Self::TimeoutError {
            operation: operation.into(),
            duration_ms,
            context,
        }
    }

    /// Create a new resource limit error with context
    pub fn resource_limit_error(resource: impl Into<String>, limit: impl Into<String>, context: Option<ErrorContext>) -> Self {
        Self::ResourceLimitError {
            resource: resource.into(),
            limit: limit.into(),
            context,
        }
    }

    /// Get the error context if available
    pub fn context(&self) -> Option<&ErrorContext> {
        match self {
            Self::AnalysisError { context, .. } => context.as_ref(),
            Self::PluginError { context, .. } => context.as_ref(),
            Self::FileProcessingError { context, .. } => Some(context),
            Self::ExternalToolError { context, .. } => context.as_ref(),
            Self::TimeoutError { context, .. } => context.as_ref(),
            Self::ResourceLimitError { context, .. } => context.as_ref(),
            _ => None,
        }
    }

    /// Convert to user-friendly error information
    pub fn to_user_friendly(&self) -> UserFriendlyError {
        match self {
            Self::FileError(io_err) => {
                let (message, suggestions) = match io_err.kind() {
                    std::io::ErrorKind::NotFound => (
                        "The specified file could not be found".to_string(),
                        vec![
                            "Check that the file path is correct".to_string(),
                            "Ensure the file exists and is accessible".to_string(),
                        ]
                    ),
                    std::io::ErrorKind::PermissionDenied => (
                        "Permission denied accessing the file".to_string(),
                        vec![
                            "Check file permissions".to_string(),
                            "Try running with appropriate privileges".to_string(),
                        ]
                    ),
                    std::io::ErrorKind::InvalidData => (
                        "The file contains invalid or corrupted data".to_string(),
                        vec![
                            "Verify the file is not corrupted".to_string(),
                            "Try with a different file".to_string(),
                        ]
                    ),
                    _ => (
                        "An error occurred while accessing the file".to_string(),
                        vec!["Check the file and try again".to_string()]
                    ),
                };
                UserFriendlyError {
                    message,
                    suggestions,
                    recoverable: true,
                    category: ErrorCategory::FileAccess,
                }
            },
            Self::FileProcessingError { message, context } => {
                let mut suggestions = vec!["Check that the file format is supported".to_string()];
                if let Some(file_type) = &context.file_type {
                    suggestions.push(format!("Verify the file is a valid {} file", file_type));
                }
                suggestions.push("Try with a different file".to_string());

                UserFriendlyError {
                    message: format!("Failed to process file: {}", message),
                    suggestions,
                    recoverable: true,
                    category: ErrorCategory::FileFormat,
                }
            },
            Self::AnalysisError { message, .. } => {
                UserFriendlyError {
                    message: format!("Analysis failed: {}", message),
                    suggestions: vec![
                        "Try with a different analysis approach".to_string(),
                        "Check if the file format is supported".to_string(),
                        "Enable verbose mode for more details".to_string(),
                    ],
                    recoverable: true,
                    category: ErrorCategory::Analysis,
                }
            },
            Self::PluginError { plugin_name, message, .. } => {
                UserFriendlyError {
                    message: format!("Plugin '{}' failed: {}", plugin_name, message),
                    suggestions: vec![
                        "Try disabling the plugin and running again".to_string(),
                        "Check plugin configuration".to_string(),
                        "Update or reinstall the plugin".to_string(),
                    ],
                    recoverable: true,
                    category: ErrorCategory::Plugin,
                }
            },
            Self::ExternalToolError { tool, message, .. } => {
                UserFriendlyError {
                    message: format!("External tool '{}' failed: {}", tool, message),
                    suggestions: vec![
                        format!("Ensure '{}' is installed and accessible", tool),
                        "Check system PATH environment variable".to_string(),
                        "Try running the analysis without external tools".to_string(),
                    ],
                    recoverable: true,
                    category: ErrorCategory::System,
                }
            },
            Self::TimeoutError { operation, duration_ms, .. } => {
                UserFriendlyError {
                    message: format!("Operation '{}' timed out after {}ms", operation, duration_ms),
                    suggestions: vec![
                        "Try with a smaller file".to_string(),
                        "Increase timeout limits in configuration".to_string(),
                        "Check system resources and performance".to_string(),
                    ],
                    recoverable: true,
                    category: ErrorCategory::System,
                }
            },
            Self::ResourceLimitError { resource, limit, .. } => {
                UserFriendlyError {
                    message: format!("Resource limit exceeded: {} limit of {}", resource, limit),
                    suggestions: vec![
                        "Try with a smaller file".to_string(),
                        "Increase resource limits in configuration".to_string(),
                        "Free up system resources".to_string(),
                    ],
                    recoverable: true,
                    category: ErrorCategory::System,
                }
            },
            Self::SecurityError(msg) => {
                UserFriendlyError {
                    message: format!("Security check failed: {}", msg),
                    suggestions: vec![
                        "Ensure the file is from a trusted source".to_string(),
                        "Scan the file for malware".to_string(),
                        "Use a different file".to_string(),
                    ],
                    recoverable: false,
                    category: ErrorCategory::Security,
                }
            },
            Self::AiError(msg) => {
                UserFriendlyError {
                    message: format!("AI service error: {}", msg),
                    suggestions: vec![
                        "Check internet connection".to_string(),
                        "Verify API credentials".to_string(),
                        "Try again later".to_string(),
                        "Use the tool without AI hints".to_string(),
                    ],
                    recoverable: true,
                    category: ErrorCategory::Network,
                }
            },
            Self::ConfigError(msg) => {
                UserFriendlyError {
                    message: format!("Configuration error: {}", msg),
                    suggestions: vec![
                        "Check configuration file syntax".to_string(),
                        "Reset to default configuration".to_string(),
                        "Refer to documentation for valid settings".to_string(),
                    ],
                    recoverable: true,
                    category: ErrorCategory::Configuration,
                }
            },
            _ => {
                UserFriendlyError {
                    message: "An unexpected error occurred".to_string(),
                    suggestions: vec![
                        "Try the operation again".to_string(),
                        "Enable verbose mode for more details".to_string(),
                        "Report this issue if it persists".to_string(),
                    ],
                    recoverable: true,
                    category: ErrorCategory::System,
                }
            },
        }
    }

    /// Log the error with full context and diagnostic information
    pub fn log_with_context(&self) {
        use tracing::{error, warn};

        if let Some(context) = self.context() {
            error!(
                operation = %context.operation,
                file_type = ?context.file_type,
                file_path = ?context.file_path,
                timestamp = %context.timestamp,
                call_chain = ?context.call_chain,
                diagnostics = ?context.diagnostics,
                error = %self,
                "Contextual error occurred"
            );
        } else {
            warn!(error = %self, "Error occurred without context");
        }
    }
}