//! Verbose output and detailed logging system

use tracing::{debug, info, warn};
use std::collections::HashMap;
use std::time::Duration;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// Configuration for verbose output behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerboseConfig {
    /// Whether to show timing information for operations
    pub show_timing: bool,
    /// Whether to show intermediate processing results
    pub show_intermediate_results: bool,
    /// Whether to show detailed step-by-step progress
    pub show_detailed_steps: bool,
    /// Whether to show diagnostic information
    pub show_diagnostics: bool,
    /// Whether to show memory usage information
    pub show_memory_usage: bool,
    /// Maximum length for intermediate result previews
    pub max_preview_length: usize,
}

impl Default for VerboseConfig {
    fn default() -> Self {
        Self {
            show_timing: true,
            show_intermediate_results: true,
            show_detailed_steps: true,
            show_diagnostics: true,
            show_memory_usage: false,
            max_preview_length: 200,
        }
    }
}

/// Information about a processing step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingStep {
    pub name: String,
    pub description: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration: Option<Duration>,
    pub status: StepStatus,
    pub intermediate_results: Vec<IntermediateResult>,
    pub diagnostics: HashMap<String, String>,
    pub sub_steps: Vec<ProcessingStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StepStatus {
    NotStarted,
    InProgress,
    Completed,
    Failed(String),
    Skipped(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntermediateResult {
    pub name: String,
    pub description: String,
    pub data_type: String,
    pub preview: String,
    pub full_size: usize,
    pub confidence: Option<f32>,
    pub metadata: HashMap<String, String>,
}

/// Verbose logger for detailed operation tracking
pub struct VerboseLogger {
    config: VerboseConfig,
    current_steps: Vec<ProcessingStep>,
    step_stack: Vec<usize>, // Stack of indices for nested steps
    enabled: bool,
}

impl VerboseLogger {
    pub fn new(config: VerboseConfig, enabled: bool) -> Self {
        Self {
            config,
            current_steps: Vec::new(),
            step_stack: Vec::new(),
            enabled,
        }
    }

    /// Start a new processing step
    pub fn start_step(&mut self, name: impl Into<String>, description: impl Into<String>) -> usize {
        if !self.enabled {
            return 0;
        }

        let step = ProcessingStep {
            name: name.into(),
            description: description.into(),
            started_at: Utc::now(),
            completed_at: None,
            duration: None,
            status: StepStatus::InProgress,
            intermediate_results: Vec::new(),
            diagnostics: HashMap::new(),
            sub_steps: Vec::new(),
        };

        if self.config.show_detailed_steps {
            let indent = "  ".repeat(self.step_stack.len());
            info!("{}🔄 Starting: {}", indent, step.description);
        }

        // Always add as top-level step for simplicity
        self.current_steps.push(step);
        let step_index = self.current_steps.len() - 1;
        self.step_stack.push(step_index);
        
        step_index
    }

    /// Complete the current processing step
    pub fn complete_step(&mut self, success: bool, message: Option<String>) {
        if !self.enabled || self.step_stack.is_empty() {
            return;
        }

        let step_index = self.step_stack.pop().unwrap();
        let now = Utc::now();
        
        // Update step status first
        {
            let step = self.get_current_step_mut(step_index);
            step.completed_at = Some(now);
            step.duration = Some(now.signed_duration_since(step.started_at).to_std().unwrap_or(Duration::ZERO));
            
            step.status = if success {
                StepStatus::Completed
            } else {
                StepStatus::Failed(message.unwrap_or_else(|| "Unknown error".to_string()))
            };
        }

        // Log the completion (collect info first to avoid borrowing issues)
        if self.config.show_detailed_steps {
            let indent = "  ".repeat(self.step_stack.len());
            let show_timing = self.config.show_timing;
            
            let step = self.get_current_step_mut(step_index);
            let duration_str = if show_timing {
                format!(" ({}ms)", step.duration.unwrap().as_millis())
            } else {
                String::new()
            };

            match &step.status {
                StepStatus::Completed => {
                    info!("{}✅ Completed: {}{}", indent, step.description, duration_str);
                }
                StepStatus::Failed(err) => {
                    warn!("{}❌ Failed: {} - {}{}", indent, step.description, err, duration_str);
                }
                _ => {}
            }
        }
    }

    /// Skip the current processing step
    pub fn skip_step(&mut self, reason: impl Into<String>) {
        if !self.enabled || self.step_stack.is_empty() {
            return;
        }

        let step_index = self.step_stack.pop().unwrap();
        let now = Utc::now();
        let reason_str = reason.into();
        
        // Update step status first
        {
            let step = self.get_current_step_mut(step_index);
            step.completed_at = Some(now);
            step.duration = Some(now.signed_duration_since(step.started_at).to_std().unwrap_or(Duration::ZERO));
            step.status = StepStatus::Skipped(reason_str.clone());
        }

        // Log the skip (collect info first to avoid borrowing issues)
        if self.config.show_detailed_steps {
            let indent = "  ".repeat(self.step_stack.len());
            let step = self.get_current_step_mut(step_index);
            info!("{}⏭️  Skipped: {} - {}", indent, step.description, reason_str);
        }
    }

    /// Add an intermediate result to the current step
    pub fn add_intermediate_result(&mut self, name: impl Into<String>, description: impl Into<String>, data: &[u8], data_type: impl Into<String>, confidence: Option<f32>) {
        if !self.enabled || self.step_stack.is_empty() {
            return;
        }

        let preview = if data.len() <= self.config.max_preview_length {
            String::from_utf8_lossy(data).to_string()
        } else {
            let preview_data = &data[..self.config.max_preview_length.min(data.len())];
            format!("{}... (truncated, {} total bytes)", String::from_utf8_lossy(preview_data), data.len())
        };

        let result = IntermediateResult {
            name: name.into(),
            description: description.into(),
            data_type: data_type.into(),
            preview,
            full_size: data.len(),
            confidence,
            metadata: HashMap::new(),
        };

        let step_index = *self.step_stack.last().unwrap();
        let step = self.get_current_step_mut(step_index);
        step.intermediate_results.push(result.clone());

        if self.config.show_intermediate_results {
            let indent = "  ".repeat(self.step_stack.len() + 1);
            let confidence_str = if let Some(conf) = confidence {
                format!(" (confidence: {:.1}%)", conf * 100.0)
            } else {
                String::new()
            };
            
            info!("{}📊 {}: {} bytes{}", indent, result.description, result.full_size, confidence_str);
            
            if result.preview.len() <= 100 {
                debug!("{}   Preview: {}", indent, result.preview);
            } else {
                debug!("{}   Preview: {}...", indent, &result.preview[..100]);
            }
        }
    }

    /// Add diagnostic information to the current step
    pub fn add_diagnostic(&mut self, key: impl Into<String>, value: impl Into<String>) {
        if !self.enabled || self.step_stack.is_empty() {
            return;
        }

        let step_index = *self.step_stack.last().unwrap();
        let step = self.get_current_step_mut(step_index);
        let key_str = key.into();
        let value_str = value.into();
        
        step.diagnostics.insert(key_str.clone(), value_str.clone());

        if self.config.show_diagnostics {
            let indent = "  ".repeat(self.step_stack.len() + 1);
            debug!("{}🔍 {}: {}", indent, key_str, value_str);
        }
    }

    /// Log memory usage information
    pub fn log_memory_usage(&self, operation: &str) {
        if !self.enabled || !self.config.show_memory_usage {
            return;
        }

        #[cfg(target_os = "linux")]
        {
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                for line in status.lines() {
                    if line.starts_with("VmRSS:") {
                        let indent = "  ".repeat(self.step_stack.len() + 1);
                        debug!("{}💾 Memory usage during {}: {}", indent, operation, line.trim());
                        break;
                    }
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let indent = "  ".repeat(self.step_stack.len() + 1);
            debug!("{}💾 Memory usage tracking not available on this platform", indent);
        }
    }

    /// Get a summary of all processing steps
    pub fn get_summary(&self) -> ProcessingSummary {
        let total_steps = self.count_all_steps(&self.current_steps);
        let completed_steps = self.count_steps_by_status(&self.current_steps, &StepStatus::Completed);
        let failed_steps = self.count_failed_steps(&self.current_steps);
        let total_duration = self.calculate_total_duration(&self.current_steps);

        ProcessingSummary {
            total_steps,
            completed_steps,
            failed_steps,
            skipped_steps: self.count_skipped_steps(&self.current_steps),
            total_duration,
            steps: self.current_steps.clone(),
        }
    }

    /// Format the processing summary for display
    pub fn format_summary(&self, summary: &ProcessingSummary) -> String {
        let mut output = String::new();
        
        output.push_str("📋 Processing Summary\n");
        output.push_str("═══════════════════\n");
        output.push_str(&format!("Total Steps: {}\n", summary.total_steps));
        output.push_str(&format!("Completed: {}\n", summary.completed_steps));
        output.push_str(&format!("Failed: {}\n", summary.failed_steps));
        output.push_str(&format!("Skipped: {}\n", summary.skipped_steps));
        
        if self.config.show_timing {
            output.push_str(&format!("Total Duration: {}ms\n", summary.total_duration.as_millis()));
        }
        
        output.push('\n');
        
        // Show detailed step breakdown
        for (i, step) in summary.steps.iter().enumerate() {
            output.push_str(&self.format_step(step, 0, i + 1));
        }
        
        output
    }

    /// Clear all processing steps and reset state
    pub fn clear(&mut self) {
        self.current_steps.clear();
        self.step_stack.clear();
    }

    // Helper methods
    fn get_current_step_mut(&mut self, index: usize) -> &mut ProcessingStep {
        &mut self.current_steps[index]
    }

    fn count_all_steps(&self, steps: &[ProcessingStep]) -> usize {
        steps.iter().map(|step| 1 + self.count_all_steps(&step.sub_steps)).sum()
    }

    fn count_steps_by_status(&self, steps: &[ProcessingStep], target_status: &StepStatus) -> usize {
        steps.iter().map(|step| {
            let current_match = match (&step.status, target_status) {
                (StepStatus::Completed, StepStatus::Completed) => 1,
                _ => 0,
            };
            current_match + self.count_steps_by_status(&step.sub_steps, target_status)
        }).sum()
    }

    fn count_failed_steps(&self, steps: &[ProcessingStep]) -> usize {
        steps.iter().map(|step| {
            let current_failed = match &step.status {
                StepStatus::Failed(_) => 1,
                _ => 0,
            };
            current_failed + self.count_failed_steps(&step.sub_steps)
        }).sum()
    }

    fn count_skipped_steps(&self, steps: &[ProcessingStep]) -> usize {
        steps.iter().map(|step| {
            let current_skipped = match &step.status {
                StepStatus::Skipped(_) => 1,
                _ => 0,
            };
            current_skipped + self.count_skipped_steps(&step.sub_steps)
        }).sum()
    }

    fn calculate_total_duration(&self, steps: &[ProcessingStep]) -> Duration {
        steps.iter().map(|step| {
            let step_duration = step.duration.unwrap_or(Duration::ZERO);
            let sub_duration = self.calculate_total_duration(&step.sub_steps);
            step_duration + sub_duration
        }).sum()
    }

    fn format_step(&self, step: &ProcessingStep, indent_level: usize, number: usize) -> String {
        let mut output = String::new();
        let indent = "  ".repeat(indent_level);
        
        let status_icon = match &step.status {
            StepStatus::Completed => "✅",
            StepStatus::Failed(_) => "❌",
            StepStatus::Skipped(_) => "⏭️",
            StepStatus::InProgress => "🔄",
            StepStatus::NotStarted => "⏸️",
        };
        
        let duration_str = if self.config.show_timing && step.duration.is_some() {
            format!(" ({}ms)", step.duration.unwrap().as_millis())
        } else {
            String::new()
        };
        
        output.push_str(&format!("{}{}. {} {}{}\n", indent, number, status_icon, step.description, duration_str));
        
        // Show failure reason
        if let StepStatus::Failed(reason) = &step.status {
            output.push_str(&format!("{}   Error: {}\n", indent, reason));
        }
        
        // Show skip reason
        if let StepStatus::Skipped(reason) = &step.status {
            output.push_str(&format!("{}   Reason: {}\n", indent, reason));
        }
        
        // Show intermediate results
        if self.config.show_intermediate_results && !step.intermediate_results.is_empty() {
            output.push_str(&format!("{}   Results:\n", indent));
            for result in &step.intermediate_results {
                let confidence_str = if let Some(conf) = result.confidence {
                    format!(" ({:.1}%)", conf * 100.0)
                } else {
                    String::new()
                };
                output.push_str(&format!("{}     • {}: {} bytes{}\n", indent, result.description, result.full_size, confidence_str));
            }
        }
        
        // Show diagnostics
        if self.config.show_diagnostics && !step.diagnostics.is_empty() {
            output.push_str(&format!("{}   Diagnostics:\n", indent));
            for (key, value) in &step.diagnostics {
                output.push_str(&format!("{}     {}: {}\n", indent, key, value));
            }
        }
        
        // Show sub-steps
        for (i, sub_step) in step.sub_steps.iter().enumerate() {
            output.push_str(&self.format_step(sub_step, indent_level + 1, i + 1));
        }
        
        output
    }
}

/// Summary of all processing steps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingSummary {
    pub total_steps: usize,
    pub completed_steps: usize,
    pub failed_steps: usize,
    pub skipped_steps: usize,
    pub total_duration: Duration,
    pub steps: Vec<ProcessingStep>,
}

/// Global verbose logger instance
static mut GLOBAL_VERBOSE_LOGGER: Option<VerboseLogger> = None;
static VERBOSE_INIT: std::sync::Once = std::sync::Once::new();

/// Initialize the global verbose logger
pub fn init_verbose_logger(config: VerboseConfig, enabled: bool) {
    VERBOSE_INIT.call_once(|| {
        unsafe {
            GLOBAL_VERBOSE_LOGGER = Some(VerboseLogger::new(config, enabled));
        }
    });
}

/// Get the global verbose logger instance
pub fn get_verbose_logger() -> Option<&'static mut VerboseLogger> {
    unsafe { GLOBAL_VERBOSE_LOGGER.as_mut() }
}

/// Convenience macros for verbose logging
#[macro_export]
macro_rules! verbose_step {
    ($name:expr, $desc:expr) => {
        if let Some(logger) = $crate::core::verbose_logger::get_verbose_logger() {
            logger.start_step($name, $desc)
        } else {
            0
        }
    };
}

#[macro_export]
macro_rules! verbose_complete {
    ($success:expr) => {
        if let Some(logger) = $crate::core::verbose_logger::get_verbose_logger() {
            logger.complete_step($success, None)
        }
    };
    ($success:expr, $msg:expr) => {
        if let Some(logger) = $crate::core::verbose_logger::get_verbose_logger() {
            logger.complete_step($success, Some($msg.to_string()))
        }
    };
}

#[macro_export]
macro_rules! verbose_result {
    ($name:expr, $desc:expr, $data:expr, $type:expr) => {
        if let Some(logger) = $crate::core::verbose_logger::get_verbose_logger() {
            logger.add_intermediate_result($name, $desc, $data, $type, None)
        }
    };
    ($name:expr, $desc:expr, $data:expr, $type:expr, $confidence:expr) => {
        if let Some(logger) = $crate::core::verbose_logger::get_verbose_logger() {
            logger.add_intermediate_result($name, $desc, $data, $type, Some($confidence))
        }
    };
}

#[macro_export]
macro_rules! verbose_diagnostic {
    ($key:expr, $value:expr) => {
        if let Some(logger) = $crate::core::verbose_logger::get_verbose_logger() {
            logger.add_diagnostic($key, $value)
        }
    };
}