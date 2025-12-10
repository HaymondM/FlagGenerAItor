//! Output formatting utilities for CLI interface

use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use serde_json::Value;
use std::time::Duration;

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