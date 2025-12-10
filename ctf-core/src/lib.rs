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
    errors::{CtfError, ErrorContext, UserFriendlyError, ErrorCategory},
    error_handler::{ErrorHandler, ErrorHandlerConfig, handle_error, handle_and_format_error, init_error_handler},
    verbose_logger::{VerboseLogger, VerboseConfig, ProcessingSummary, init_verbose_logger, get_verbose_logger},
};

pub use analysis::{
    file_analyzer::FileAnalyzer,
    file_security::FileSecurityValidator,
    decoder_pipeline::DecoderPipeline,
    steganography::SteganographyAnalyzer,
    process_isolation::{ProcessIsolation, IsolationConfig, IsolationConfigBuilder, IsolationResult},
    input_sanitization::{InputSanitizer, SafePathHandler},
    file_cleanup::{FileCleanupManager, RetentionPolicy, FileType as CleanupFileType, CleanupReport, CleanupStatistics},
};

pub use plugins::PluginManager;

/// Result type used throughout the CTF Assistant
pub type Result<T> = std::result::Result<T, CtfError>;