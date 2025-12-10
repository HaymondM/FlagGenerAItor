//! Centralized error handling and logging system

use crate::core::errors::{CtfError, ErrorContext, UserFriendlyError, ErrorCategory};
use tracing::{error, warn, debug};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// Global error statistics and tracking
#[derive(Debug, Default)]
pub struct ErrorStatistics {
    total_errors: AtomicU64,
    errors_by_category: Arc<std::sync::Mutex<HashMap<String, u64>>>,
    recent_errors: Arc<std::sync::Mutex<Vec<ErrorRecord>>>,
}

/// Record of an error occurrence for tracking and analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorRecord {
    pub error_type: String,
    pub category: ErrorCategory,
    pub message: String,
    pub context: Option<ErrorContext>,
    pub timestamp: DateTime<Utc>,
    pub resolved: bool,
}

/// Configuration for error handling behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorHandlerConfig {
    /// Maximum number of recent errors to keep in memory
    pub max_recent_errors: usize,
    /// Whether to log full stack traces
    pub log_stack_traces: bool,
    /// Whether to collect diagnostic information
    pub collect_diagnostics: bool,
    /// Minimum log level for errors
    pub min_log_level: String,
}

impl Default for ErrorHandlerConfig {
    fn default() -> Self {
        Self {
            max_recent_errors: 100,
            log_stack_traces: true,
            collect_diagnostics: true,
            min_log_level: "error".to_string(),
        }
    }
}

/// Centralized error handler for the CTF Assistant
pub struct ErrorHandler {
    config: ErrorHandlerConfig,
    statistics: ErrorStatistics,
}

impl ErrorHandler {
    pub fn new(config: ErrorHandlerConfig) -> Self {
        Self {
            config,
            statistics: ErrorStatistics::default(),
        }
    }

    /// Handle an error with full logging and tracking
    pub fn handle_error(&self, error: &CtfError) -> UserFriendlyError {
        // Increment error counters
        self.statistics.total_errors.fetch_add(1, Ordering::Relaxed);
        
        let user_friendly = error.to_user_friendly();
        
        // Update category statistics
        if let Ok(mut categories) = self.statistics.errors_by_category.lock() {
            let category_name = format!("{:?}", user_friendly.category);
            *categories.entry(category_name).or_insert(0) += 1;
        }

        // Create error record
        let record = ErrorRecord {
            error_type: self.get_error_type_name(error),
            category: user_friendly.category.clone(),
            message: error.to_string(),
            context: error.context().cloned(),
            timestamp: Utc::now(),
            resolved: false,
        };

        // Add to recent errors (with size limit)
        if let Ok(mut recent) = self.statistics.recent_errors.lock() {
            recent.push(record.clone());
            if recent.len() > self.config.max_recent_errors {
                recent.remove(0);
            }
        }

        // Log the error with appropriate level and detail
        self.log_error(error, &record);

        user_friendly
    }

    /// Handle an error and format it for display
    pub fn handle_and_format_error(&self, error: &CtfError, verbose: bool) -> String {
        let user_friendly = self.handle_error(error);
        self.format_error_for_display(&user_friendly, error.context(), verbose)
    }

    /// Format error for user display
    pub fn format_error_for_display(&self, user_friendly: &UserFriendlyError, context: Option<&ErrorContext>, verbose: bool) -> String {
        let mut output = String::new();
        
        // Main error message
        output.push_str(&format!("❌ {}\n", user_friendly.message));
        
        // Add context information if verbose
        if verbose {
            if let Some(ctx) = context {
                output.push_str(&format!("\n📍 Context:\n"));
                output.push_str(&format!("   Operation: {}\n", ctx.operation));
                
                if let Some(file_type) = &ctx.file_type {
                    output.push_str(&format!("   File Type: {}\n", file_type));
                }
                
                if let Some(file_path) = &ctx.file_path {
                    output.push_str(&format!("   File Path: {}\n", file_path));
                }
                
                output.push_str(&format!("   Timestamp: {}\n", ctx.timestamp.format("%Y-%m-%d %H:%M:%S UTC")));
                
                if !ctx.call_chain.is_empty() {
                    output.push_str(&format!("   Call Chain: {}\n", ctx.call_chain.join(" → ")));
                }
                
                if !ctx.diagnostics.is_empty() {
                    output.push_str("   Diagnostics:\n");
                    for (key, value) in &ctx.diagnostics {
                        output.push_str(&format!("     {}: {}\n", key, value));
                    }
                }
            }
        }
        
        // Add suggestions
        if !user_friendly.suggestions.is_empty() {
            output.push_str("\n💡 Suggestions:\n");
            for (i, suggestion) in user_friendly.suggestions.iter().enumerate() {
                output.push_str(&format!("   {}. {}\n", i + 1, suggestion));
            }
        }
        
        // Add recovery information
        if user_friendly.recoverable {
            output.push_str("\n🔄 This error is recoverable. You can try the suggested actions above.\n");
        } else {
            output.push_str("\n⚠️  This error requires immediate attention and may not be recoverable.\n");
        }
        
        output
    }

    /// Get error statistics
    pub fn get_statistics(&self) -> HashMap<String, u64> {
        let mut stats = HashMap::new();
        stats.insert("total_errors".to_string(), self.statistics.total_errors.load(Ordering::Relaxed));
        
        if let Ok(categories) = self.statistics.errors_by_category.lock() {
            for (category, count) in categories.iter() {
                stats.insert(format!("category_{}", category.to_lowercase()), *count);
            }
        }
        
        stats
    }

    /// Get recent error records
    pub fn get_recent_errors(&self, limit: Option<usize>) -> Vec<ErrorRecord> {
        if let Ok(recent) = self.statistics.recent_errors.lock() {
            let limit = limit.unwrap_or(recent.len());
            recent.iter().rev().take(limit).cloned().collect()
        } else {
            Vec::new()
        }
    }

    /// Clear error statistics and history
    pub fn clear_statistics(&self) {
        self.statistics.total_errors.store(0, Ordering::Relaxed);
        
        if let Ok(mut categories) = self.statistics.errors_by_category.lock() {
            categories.clear();
        }
        
        if let Ok(mut recent) = self.statistics.recent_errors.lock() {
            recent.clear();
        }
    }

    /// Create error context for a specific operation
    pub fn create_context(&self, operation: impl Into<String>) -> ErrorContext {
        let mut context = ErrorContext::new(operation);
        
        if self.config.collect_diagnostics {
            // Add system diagnostics
            context = context
                .with_diagnostic("system_time", Utc::now().to_rfc3339())
                .with_diagnostic("thread_id", format!("{:?}", std::thread::current().id()));
            
            // Add memory usage if available
            #[cfg(target_os = "linux")]
            {
                if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                    for line in status.lines() {
                        if line.starts_with("VmRSS:") {
                            context = context.with_diagnostic("memory_usage", line.trim().to_string());
                            break;
                        }
                    }
                }
            }
        }
        
        context
    }

    /// Log error with appropriate detail level
    fn log_error(&self, error: &CtfError, record: &ErrorRecord) {
        match record.category {
            ErrorCategory::Security => {
                error!(
                    error_type = %record.error_type,
                    category = ?record.category,
                    message = %record.message,
                    timestamp = %record.timestamp,
                    context = ?record.context,
                    "SECURITY ERROR: {}", error
                );
            },
            ErrorCategory::System => {
                error!(
                    error_type = %record.error_type,
                    category = ?record.category,
                    message = %record.message,
                    "System error: {}", error
                );
            },
            ErrorCategory::Plugin => {
                warn!(
                    error_type = %record.error_type,
                    category = ?record.category,
                    message = %record.message,
                    "Plugin error: {}", error
                );
            },
            _ => {
                error!(
                    error_type = %record.error_type,
                    category = ?record.category,
                    message = %record.message,
                    "Error occurred: {}", error
                );
            }
        }

        // Log context details if available and configured
        if self.config.log_stack_traces {
            if let Some(context) = &record.context {
                debug!(
                    operation = %context.operation,
                    file_type = ?context.file_type,
                    file_path = ?context.file_path,
                    call_chain = ?context.call_chain,
                    diagnostics = ?context.diagnostics,
                    "Error context details"
                );
            }
        }
    }

    /// Get the type name of an error for categorization
    fn get_error_type_name(&self, error: &CtfError) -> String {
        match error {
            CtfError::FileError(_) => "FileError".to_string(),
            CtfError::SerializationError(_) => "SerializationError".to_string(),
            CtfError::RegexError(_) => "RegexError".to_string(),
            CtfError::GeneralError(_) => "GeneralError".to_string(),
            CtfError::AnalysisError { .. } => "AnalysisError".to_string(),
            CtfError::PluginError { .. } => "PluginError".to_string(),
            CtfError::AiError(_) => "AiError".to_string(),
            CtfError::SecurityError(_) => "SecurityError".to_string(),
            CtfError::InvalidInput(_) => "InvalidInput".to_string(),
            CtfError::ConfigError(_) => "ConfigError".to_string(),
            CtfError::FileProcessingError { .. } => "FileProcessingError".to_string(),
            CtfError::ExternalToolError { .. } => "ExternalToolError".to_string(),
            CtfError::TimeoutError { .. } => "TimeoutError".to_string(),
            CtfError::ResourceLimitError { .. } => "ResourceLimitError".to_string(),
        }
    }
}

/// Global error handler instance
static mut GLOBAL_ERROR_HANDLER: Option<ErrorHandler> = None;
static INIT: std::sync::Once = std::sync::Once::new();

/// Initialize the global error handler
pub fn init_error_handler(config: ErrorHandlerConfig) {
    INIT.call_once(|| {
        unsafe {
            GLOBAL_ERROR_HANDLER = Some(ErrorHandler::new(config));
        }
    });
}

/// Get the global error handler instance
pub fn get_error_handler() -> Option<&'static ErrorHandler> {
    unsafe { GLOBAL_ERROR_HANDLER.as_ref() }
}

/// Handle an error using the global error handler
pub fn handle_error(error: &CtfError) -> UserFriendlyError {
    if let Some(handler) = get_error_handler() {
        handler.handle_error(error)
    } else {
        // Fallback if no global handler is initialized
        warn!("No global error handler initialized, using fallback");
        error.to_user_friendly()
    }
}

/// Handle and format an error using the global error handler
pub fn handle_and_format_error(error: &CtfError, verbose: bool) -> String {
    if let Some(handler) = get_error_handler() {
        handler.handle_and_format_error(error, verbose)
    } else {
        // Fallback formatting
        let user_friendly = error.to_user_friendly();
        format!("❌ {}\n💡 Suggestions: {}", 
            user_friendly.message, 
            user_friendly.suggestions.join(", ")
        )
    }
}