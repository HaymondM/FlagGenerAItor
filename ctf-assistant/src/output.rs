//! Output formatting utilities for CLI interface

use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use serde_json::Value;
use std::time::Duration;
use ctf_core::{UserFriendlyError, ErrorContext, ErrorCategory};

/// Output formatter for different display formats
pub struct OutputFormatter {
    format: OutputFormat,
    use_colors: bool,
}

#[derive(Clone, Debug)]
pub enum OutputFormat {
    Text,
    Json,
    Compact,
}

impl OutputFormatter {
    pub fn new(format: OutputFormat) -> Self {
        let use_colors = atty::is(atty::Stream::Stdout);
        Self { format, use_colors }
    }

    /// Create a progress bar for long operations
    pub fn create_progress_bar(&self, message: &str) -> ProgressBar {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
                .template("{spinner:.green} {msg}")
                .unwrap(),
        );
        pb.set_message(message.to_string());
        pb.enable_steady_tick(Duration::from_millis(100));
        pb
    }

    /// Format analysis results header
    pub fn format_analysis_header(&self, file: &str, description: Option<&str>) -> String {
        match self.format {
            OutputFormat::Text => {
                let mut output = String::new();
                
                if self.use_colors {
                    output.push_str(&format!("\n{}\n", "🔍 CTF Assistant Analysis Report".bright_cyan().bold()));
                    output.push_str(&format!("{}\n", "═".repeat(40).bright_blue()));
                    output.push_str(&format!("{} {}\n", "📁 File:".bright_yellow(), file.white().bold()));
                } else {
                    output.push_str("\n🔍 CTF Assistant Analysis Report\n");
                    output.push_str("═══════════════════════════════════════\n");
                    output.push_str(&format!("📁 File: {}\n", file));
                }
                
                if let Some(desc) = description {
                    if self.use_colors {
                        output.push_str(&format!("{} {}\n", "📝 Description:".bright_yellow(), desc.white()));
                    } else {
                        output.push_str(&format!("📝 Description: {}\n", desc));
                    }
                }
                
                output
            }
            OutputFormat::Json | OutputFormat::Compact => String::new(),
        }
    }

    /// Format file metadata information
    pub fn format_file_info(&self, size: u64, max_depth: u8, hints_enabled: bool) -> String {
        match self.format {
            OutputFormat::Text => {
                let mut output = String::new();
                
                if self.use_colors {
                    output.push_str(&format!("{} {} bytes\n", "📊 Size:".bright_yellow(), size.to_string().bright_white()));
                    output.push_str(&format!("{} {}\n", "⚙️  Max Depth:".bright_yellow(), max_depth.to_string().bright_white()));
                    output.push_str(&format!("{} {}\n", "🤖 AI Hints:".bright_yellow(), 
                        if hints_enabled { "Enabled".bright_green() } else { "Disabled".bright_red() }));
                } else {
                    output.push_str(&format!("📊 Size: {} bytes\n", size));
                    output.push_str(&format!("⚙️  Max Depth: {}\n", max_depth));
                    output.push_str(&format!("🤖 AI Hints: {}\n", if hints_enabled { "Enabled" } else { "Disabled" }));
                }
                
                output
            }
            OutputFormat::Json | OutputFormat::Compact => String::new(),
        }
    }

    /// Format analysis results section
    pub fn format_analysis_section(&self, title: &str, items: &[String]) -> String {
        match self.format {
            OutputFormat::Text => {
                let mut output = String::new();
                
                if self.use_colors {
                    output.push_str(&format!("\n{}\n", title.bright_cyan().bold()));
                    output.push_str(&format!("{}\n", "─".repeat(title.len()).bright_blue()));
                } else {
                    output.push_str(&format!("\n{}\n", title));
                    output.push_str(&format!("{}\n", "─".repeat(title.len())));
                }
                
                for (i, item) in items.iter().enumerate() {
                    if self.use_colors {
                        output.push_str(&format!("  {} {}\n", format!("{}.", i + 1).bright_blue(), item.white()));
                    } else {
                        output.push_str(&format!("  {}. {}\n", i + 1, item));
                    }
                }
                
                output
            }
            OutputFormat::Json | OutputFormat::Compact => String::new(),
        }
    }

    /// Format findings with confidence levels
    pub fn format_findings(&self, findings: &[(String, f32)]) -> String {
        match self.format {
            OutputFormat::Text => {
                let mut output = String::new();
                
                if self.use_colors {
                    output.push_str(&format!("\n{}\n", "🔍 Key Findings".bright_cyan().bold()));
                    output.push_str(&format!("{}\n", "─".repeat(15).bright_blue()));
                } else {
                    output.push_str("\n🔍 Key Findings\n");
                    output.push_str("───────────────\n");
                }
                
                for (finding, confidence) in findings {
                    let confidence_color = if *confidence > 0.8 {
                        "bright_green"
                    } else if *confidence > 0.5 {
                        "bright_yellow"
                    } else {
                        "bright_red"
                    };
                    
                    if self.use_colors {
                        let confidence_str = format!("{:.0}%", confidence * 100.0);
                        let colored_confidence = match confidence_color {
                            "bright_green" => confidence_str.bright_green(),
                            "bright_yellow" => confidence_str.bright_yellow(),
                            _ => confidence_str.bright_red(),
                        };
                        output.push_str(&format!("  • {} {}\n", finding.white(), 
                            format!("({})", colored_confidence).dimmed()));
                    } else {
                        output.push_str(&format!("  • {} ({:.0}%)\n", finding, confidence * 100.0));
                    }
                }
                
                output
            }
            OutputFormat::Json | OutputFormat::Compact => String::new(),
        }
    }

    /// Format success message
    pub fn format_success(&self, message: &str) -> String {
        match self.format {
            OutputFormat::Text => {
                if self.use_colors {
                    format!("{} {}\n", "✅".bright_green(), message.bright_green())
                } else {
                    format!("✅ {}\n", message)
                }
            }
            OutputFormat::Json | OutputFormat::Compact => String::new(),
        }
    }

    /// Format warning message
    pub fn format_warning(&self, message: &str) -> String {
        match self.format {
            OutputFormat::Text => {
                if self.use_colors {
                    format!("{} {}\n", "⚠️".bright_yellow(), message.bright_yellow())
                } else {
                    format!("⚠️  {}\n", message)
                }
            }
            OutputFormat::Json | OutputFormat::Compact => String::new(),
        }
    }

    /// Format error message
    pub fn format_error(&self, message: &str) -> String {
        match self.format {
            OutputFormat::Text => {
                if self.use_colors {
                    format!("{} {}\n", "❌".bright_red(), message.bright_red().bold())
                } else {
                    format!("❌ {}\n", message)
                }
            }
            OutputFormat::Json | OutputFormat::Compact => String::new(),
        }
    }

    /// Format JSON output
    pub fn format_json(&self, data: &Value) -> String {
        match self.format {
            OutputFormat::Json => {
                serde_json::to_string_pretty(data).unwrap_or_else(|_| "{}".to_string())
            }
            _ => String::new(),
        }
    }

    /// Format compact output
    pub fn format_compact(&self, key_values: &[(&str, &str)]) -> String {
        match self.format {
            OutputFormat::Compact => {
                key_values
                    .iter()
                    .map(|(k, v)| format!("{}={}", k.to_uppercase(), v))
                    .collect::<Vec<_>>()
                    .join(" ")
            }
            _ => String::new(),
        }
    }

    /// Format history entry
    pub fn format_history_entry(&self, timestamp: &str, file: &str, status: &str) -> String {
        match self.format {
            OutputFormat::Text => {
                if self.use_colors {
                    format!("  {} {} {}\n", 
                        timestamp.bright_blue(),
                        file.white().bold(),
                        match status {
                            "completed" => status.bright_green(),
                            "failed" => status.bright_red(),
                            _ => status.bright_yellow(),
                        }
                    )
                } else {
                    format!("  {} {} {}\n", timestamp, file, status)
                }
            }
            OutputFormat::Json | OutputFormat::Compact => String::new(),
        }
    }

    /// Format a user-friendly error with context
    pub fn format_user_friendly_error(&self, error: &UserFriendlyError, context: Option<&ErrorContext>, verbose: bool) -> String {
        match self.format {
            OutputFormat::Text => {
                let mut output = String::new();
                
                // Error icon and message with color coding
                let (icon, message_color) = match error.category {
                    ErrorCategory::Security => ("🔒", "bright_red"),
                    ErrorCategory::FileAccess => ("📁", "bright_red"),
                    ErrorCategory::FileFormat => ("📄", "bright_yellow"),
                    ErrorCategory::Network => ("🌐", "bright_yellow"),
                    ErrorCategory::Plugin => ("🔌", "bright_yellow"),
                    ErrorCategory::System => ("⚙️", "bright_red"),
                    _ => ("❌", "bright_red"),
                };
                
                if self.use_colors {
                    let colored_message = match message_color {
                        "bright_red" => error.message.bright_red().bold(),
                        "bright_yellow" => error.message.bright_yellow().bold(),
                        _ => error.message.white().bold(),
                    };
                    output.push_str(&format!("{} {}\n", icon, colored_message));
                } else {
                    output.push_str(&format!("{} {}\n", icon, error.message));
                }
                
                // Add context information if verbose
                if verbose {
                    if let Some(ctx) = context {
                        if self.use_colors {
                            output.push_str(&format!("\n{}\n", "📍 Context:".bright_cyan()));
                            output.push_str(&format!("   {}: {}\n", "Operation".bright_blue(), ctx.operation.white()));
                        } else {
                            output.push_str("\n📍 Context:\n");
                            output.push_str(&format!("   Operation: {}\n", ctx.operation));
                        }
                        
                        if let Some(file_type) = &ctx.file_type {
                            if self.use_colors {
                                output.push_str(&format!("   {}: {}\n", "File Type".bright_blue(), file_type.white()));
                            } else {
                                output.push_str(&format!("   File Type: {}\n", file_type));
                            }
                        }
                        
                        if let Some(file_path) = &ctx.file_path {
                            if self.use_colors {
                                output.push_str(&format!("   {}: {}\n", "File Path".bright_blue(), file_path.white()));
                            } else {
                                output.push_str(&format!("   File Path: {}\n", file_path));
                            }
                        }
                        
                        if self.use_colors {
                            output.push_str(&format!("   {}: {}\n", "Timestamp".bright_blue(), 
                                ctx.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string().white()));
                        } else {
                            output.push_str(&format!("   Timestamp: {}\n", ctx.timestamp.format("%Y-%m-%d %H:%M:%S UTC")));
                        }
                        
                        if !ctx.call_chain.is_empty() {
                            if self.use_colors {
                                output.push_str(&format!("   {}: {}\n", "Call Chain".bright_blue(), 
                                    ctx.call_chain.join(" → ").white()));
                            } else {
                                output.push_str(&format!("   Call Chain: {}\n", ctx.call_chain.join(" → ")));
                            }
                        }
                        
                        if !ctx.diagnostics.is_empty() {
                            if self.use_colors {
                                output.push_str(&format!("   {}:\n", "Diagnostics".bright_blue()));
                            } else {
                                output.push_str("   Diagnostics:\n");
                            }
                            for (key, value) in &ctx.diagnostics {
                                if self.use_colors {
                                    output.push_str(&format!("     {}: {}\n", key.bright_blue(), value.white()));
                                } else {
                                    output.push_str(&format!("     {}: {}\n", key, value));
                                }
                            }
                        }
                    }
                }
                
                // Add suggestions
                if !error.suggestions.is_empty() {
                    if self.use_colors {
                        output.push_str(&format!("\n{}\n", "💡 Suggestions:".bright_cyan()));
                    } else {
                        output.push_str("\n💡 Suggestions:\n");
                    }
                    for (i, suggestion) in error.suggestions.iter().enumerate() {
                        if self.use_colors {
                            output.push_str(&format!("   {}. {}\n", format!("{}", i + 1).bright_blue(), suggestion.white()));
                        } else {
                            output.push_str(&format!("   {}. {}\n", i + 1, suggestion));
                        }
                    }
                }
                
                // Add recovery information
                if error.recoverable {
                    if self.use_colors {
                        output.push_str(&format!("\n{} {}\n", "🔄".bright_green(), 
                            "This error is recoverable. You can try the suggested actions above.".bright_green()));
                    } else {
                        output.push_str("\n🔄 This error is recoverable. You can try the suggested actions above.\n");
                    }
                } else {
                    if self.use_colors {
                        output.push_str(&format!("\n{} {}\n", "⚠️".bright_red(), 
                            "This error requires immediate attention and may not be recoverable.".bright_red().bold()));
                    } else {
                        output.push_str("\n⚠️  This error requires immediate attention and may not be recoverable.\n");
                    }
                }
                
                output
            }
            OutputFormat::Json => {
                let json_error = serde_json::json!({
                    "error": {
                        "message": error.message,
                        "category": format!("{:?}", error.category),
                        "recoverable": error.recoverable,
                        "suggestions": error.suggestions,
                        "context": context.map(|ctx| serde_json::json!({
                            "operation": ctx.operation,
                            "file_type": ctx.file_type,
                            "file_path": ctx.file_path,
                            "timestamp": ctx.timestamp,
                            "call_chain": ctx.call_chain,
                            "diagnostics": ctx.diagnostics
                        }))
                    }
                });
                serde_json::to_string_pretty(&json_error).unwrap_or_else(|_| "{}".to_string())
            }
            OutputFormat::Compact => {
                let mut parts = vec![
                    format!("ERROR={}", error.message.replace(' ', "_")),
                    format!("CATEGORY={:?}", error.category),
                    format!("RECOVERABLE={}", error.recoverable),
                ];
                
                if let Some(ctx) = context {
                    parts.push(format!("OPERATION={}", ctx.operation.replace(' ', "_")));
                    if let Some(file_type) = &ctx.file_type {
                        parts.push(format!("FILE_TYPE={}", file_type));
                    }
                }
                
                parts.join(" ")
            }
        }
    }
}

impl From<crate::OutputFormat> for OutputFormat {
    fn from(format: crate::OutputFormat) -> Self {
        match format {
            crate::OutputFormat::Text => OutputFormat::Text,
            crate::OutputFormat::Json => OutputFormat::Json,
            crate::OutputFormat::Compact => OutputFormat::Compact,
        }
    }
}