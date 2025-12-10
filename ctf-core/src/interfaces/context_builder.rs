//! Context builder for AI prompt generation

use crate::core::models::{
    AnalysisContext, AnalysisResult, Challenge, Finding, HintExchange, 
    TransformationType, FindingCategory
};
use crate::Result;
use std::collections::HashMap;
use tracing::{debug, warn};

/// Configuration for context building
#[derive(Debug, Clone)]
pub struct ContextBuilderConfig {
    /// Maximum number of characters in the final prompt
    pub max_prompt_size: usize,
    /// Maximum number of conversation history entries to include
    pub max_history_entries: usize,
    /// Maximum number of findings to include per category
    pub max_findings_per_category: usize,
    /// Whether to include detailed transformation results
    pub include_transformation_details: bool,
    /// Whether to prioritize high-confidence findings
    pub prioritize_high_confidence: bool,
}

impl Default for ContextBuilderConfig {
    fn default() -> Self {
        Self {
            max_prompt_size: 8000, // Conservative limit for most models
            max_history_entries: 5,
            max_findings_per_category: 3,
            include_transformation_details: true,
            prioritize_high_confidence: true,
        }
    }
}

/// Context builder for aggregating analysis results into AI prompts
pub struct ContextBuilder {
    config: ContextBuilderConfig,
}

impl ContextBuilder {
    /// Create a new context builder with default configuration
    pub fn new() -> Self {
        Self::with_config(ContextBuilderConfig::default())
    }

    /// Create a new context builder with custom configuration
    pub fn with_config(config: ContextBuilderConfig) -> Self {
        Self { config }
    }

    /// Build analysis context from challenge data
    pub fn build_context(&self, challenge: &Challenge) -> Result<AnalysisContext> {
        debug!("Building analysis context for challenge {}", challenge.id);

        let mut context = AnalysisContext::new();

        // Add file types
        for file in &challenge.files {
            context.add_file_type(file.file_type.clone());
        }

        // Process analysis results
        for result in &challenge.analysis_results {
            self.process_analysis_result(&mut context, result)?;
        }

        // Add challenge metadata
        context.add_metadata("challenge_name".to_string(), challenge.name.clone());
        context.add_metadata("file_count".to_string(), challenge.files.len().to_string());
        context.add_metadata("analysis_count".to_string(), challenge.analysis_results.len().to_string());

        // Add file size information
        let total_size: u64 = challenge.files.iter().map(|f| f.size).sum();
        context.add_metadata("total_file_size".to_string(), format!("{} bytes", total_size));

        debug!("Built context with {} file types, {} transformations, {} findings", 
            context.file_types.len(), 
            context.transformations_attempted.len(), 
            context.findings.len()
        );

        Ok(context)
    }

    /// Process a single analysis result into the context
    fn process_analysis_result(&self, context: &mut AnalysisContext, result: &AnalysisResult) -> Result<()> {
        // Add transformations
        for transformation in &result.transformations {
            context.add_transformation(transformation.transformation.clone());
        }

        // Add findings with prioritization
        let mut findings_by_category: HashMap<FindingCategory, Vec<&Finding>> = HashMap::new();
        
        for finding in &result.findings {
            findings_by_category
                .entry(finding.category.clone())
                .or_default()
                .push(finding);
        }

        // Sort and limit findings per category
        for (_category, mut findings) in findings_by_category {
            // Sort by confidence if prioritization is enabled
            if self.config.prioritize_high_confidence {
                findings.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
            }

            // Take up to max_findings_per_category
            let limit = self.config.max_findings_per_category.min(findings.len());
            for finding in findings.into_iter().take(limit) {
                context.add_finding(finding.clone());
            }
        }

        // Add analyzer metadata
        context.add_metadata(
            format!("{}_confidence", result.analyzer),
            format!("{:.2}", result.confidence)
        );
        context.add_metadata(
            format!("{}_execution_time", result.analyzer),
            format!("{:.2}s", result.execution_time.as_secs_f64())
        );

        Ok(())
    }

    /// Optimize context for prompt size constraints
    pub fn optimize_context(&self, mut context: AnalysisContext) -> Result<AnalysisContext> {
        debug!("Optimizing context for size constraints");

        // Estimate current size
        let estimated_size = self.estimate_context_size(&context);
        
        if estimated_size <= self.config.max_prompt_size {
            debug!("Context size {} is within limits", estimated_size);
            return Ok(context);
        }

        warn!("Context size {} exceeds limit {}, optimizing", estimated_size, self.config.max_prompt_size);

        // Reduce findings if necessary
        if context.findings.len() > 10 {
            // Keep only high-confidence findings
            context.findings.retain(|f| f.is_high_confidence());
            
            // If still too many, keep only the highest confidence ones
            if context.findings.len() > 10 {
                context.findings.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
                context.findings.truncate(10);
            }
        }

        // Reduce metadata if necessary
        if context.metadata.len() > 20 {
            // Keep only essential metadata
            let essential_keys = ["challenge_name", "file_count", "analysis_count", "total_file_size"];
            context.metadata.retain(|k, _| essential_keys.contains(&k.as_str()));
        }

        // Remove duplicate transformations
        context.transformations_attempted.sort();
        context.transformations_attempted.dedup();

        // Remove duplicate file types
        context.file_types.sort_by(|a, b| format!("{:?}", a).cmp(&format!("{:?}", b)));
        context.file_types.dedup();

        let final_size = self.estimate_context_size(&context);
        debug!("Optimized context size: {} -> {}", estimated_size, final_size);

        Ok(context)
    }

    /// Estimate the size of a context when converted to text
    fn estimate_context_size(&self, context: &AnalysisContext) -> usize {
        let mut size = 0;

        // File types
        size += context.file_types.len() * 20; // Average file type name length

        // Transformations
        size += context.transformations_attempted.len() * 30; // Average transformation description length

        // Findings
        for finding in &context.findings {
            size += finding.description.len();
            size += finding.evidence.iter().map(|e| e.len()).sum::<usize>();
            size += finding.suggested_actions.iter().map(|a| a.len()).sum::<usize>();
            size += 50; // Overhead for formatting
        }

        // Metadata
        for (key, value) in &context.metadata {
            size += key.len() + value.len() + 10; // Overhead for formatting
        }

        size
    }

    /// Manage conversation history for optimal context
    pub fn manage_conversation_history(&self, mut history: Vec<HintExchange>) -> Result<Vec<HintExchange>> {
        debug!("Managing conversation history with {} entries", history.len());

        if history.len() <= self.config.max_history_entries {
            return Ok(history);
        }

        // Sort by timestamp (most recent first)
        history.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Take the most recent entries
        history.truncate(self.config.max_history_entries);

        // Reverse to maintain chronological order
        history.reverse();

        debug!("Reduced conversation history to {} entries", history.len());
        Ok(history)
    }

    /// Build a summary of analysis results for context
    pub fn build_analysis_summary(&self, results: &[AnalysisResult]) -> Result<String> {
        if results.is_empty() {
            return Ok("No analysis results available.".to_string());
        }

        let mut summary = String::new();

        // Overall statistics
        let total_findings: usize = results.iter().map(|r| r.findings.len()).sum();
        let avg_confidence: f32 = results.iter().map(|r| r.confidence).sum::<f32>() / results.len() as f32;
        let total_transformations: usize = results.iter().map(|r| r.transformations.len()).sum();

        summary.push_str(&format!(
            "Analysis Summary: {} analyzer(s) found {} finding(s) across {} transformation(s) with average confidence {:.2}\n\n",
            results.len(), total_findings, total_transformations, avg_confidence
        ));

        // Findings by category
        let mut findings_by_category: HashMap<FindingCategory, Vec<&Finding>> = HashMap::new();
        for result in results {
            for finding in &result.findings {
                findings_by_category
                    .entry(finding.category.clone())
                    .or_default()
                    .push(finding);
            }
        }

        if !findings_by_category.is_empty() {
            summary.push_str("Key Findings by Category:\n");
            for (category, findings) in findings_by_category {
                let high_confidence_count = findings.iter().filter(|f| f.is_high_confidence()).count();
                summary.push_str(&format!(
                    "- {}: {} finding(s) ({} high confidence)\n",
                    category, findings.len(), high_confidence_count
                ));
            }
            summary.push('\n');
        }

        // Transformation summary
        let mut transformation_counts: HashMap<TransformationType, usize> = HashMap::new();
        for result in results {
            for transformation in &result.transformations {
                *transformation_counts.entry(transformation.transformation.clone()).or_insert(0) += 1;
            }
        }

        if !transformation_counts.is_empty() {
            summary.push_str("Transformations Attempted:\n");
            let mut sorted_transformations: Vec<_> = transformation_counts.into_iter().collect();
            sorted_transformations.sort_by(|a, b| b.1.cmp(&a.1)); // Sort by count descending
            
            for (transformation, count) in sorted_transformations.into_iter().take(10) {
                summary.push_str(&format!("- {}: {} time(s)\n", transformation.description(), count));
            }
        }

        Ok(summary)
    }

    /// Calculate token estimate for prompt optimization
    pub fn estimate_tokens(&self, text: &str) -> usize {
        // Rough estimation: 1 token ≈ 4 characters for English text
        // This is a conservative estimate for prompt planning
        (text.len() as f64 / 4.0).ceil() as usize
    }

    /// Optimize prompt for token limits
    pub fn optimize_for_tokens(&self, prompt: &str, max_tokens: usize) -> Result<String> {
        let estimated_tokens = self.estimate_tokens(prompt);
        
        if estimated_tokens <= max_tokens {
            return Ok(prompt.to_string());
        }

        warn!("Prompt estimated at {} tokens exceeds limit of {}, truncating", estimated_tokens, max_tokens);

        // Calculate target character count
        let target_chars = max_tokens * 4;
        
        if prompt.len() <= target_chars {
            return Ok(prompt.to_string());
        }

        // Truncate while trying to preserve structure
        let lines: Vec<&str> = prompt.lines().collect();
        let mut result = String::new();
        let mut current_length = 0;

        for line in lines {
            if current_length + line.len() + 1 > target_chars {
                break;
            }
            result.push_str(line);
            result.push('\n');
            current_length += line.len() + 1;
        }

        // Add truncation notice
        if result.len() < prompt.len() {
            result.push_str("\n[Context truncated due to length limits]");
        }

        Ok(result)
    }
}

impl Default for ContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::models::*;

    use std::time::Duration;
    use uuid::Uuid;

    fn create_test_challenge() -> Challenge {
        let mut challenge = Challenge::new("Test Challenge".to_string(), "Test context".to_string()).unwrap();
        
        let file = ChallengeFile::new(
            "test.txt".to_string(),
            FileType::Text,
            1024,
            "hash123".to_string(),
            "path/to/file".into(),
            FileMetadata::new(),
        ).unwrap();
        
        challenge.add_file(file);
        challenge
    }

    fn create_test_analysis_result() -> AnalysisResult {
        let transformation = TransformationResult::new(
            TransformationType::Base64Decode,
            "input".to_string(),
            "output".to_string(),
            true,
            true,
            1,
        ).unwrap();

        let finding = Finding::new(
            FindingCategory::Cryptography,
            "Test finding".to_string(),
            0.8,
            vec!["evidence".to_string()],
            vec!["action".to_string()],
        ).unwrap();

        AnalysisResult::new(
            "test_analyzer".to_string(),
            Uuid::new_v4(),
            vec![transformation],
            vec![finding],
            Duration::from_secs(1),
        ).unwrap()
    }

    #[test]
    fn test_build_context() {
        let builder = ContextBuilder::new();
        let mut challenge = create_test_challenge();
        let result = create_test_analysis_result();
        challenge.add_analysis_result(result);

        let context = builder.build_context(&challenge).unwrap();

        assert!(!context.file_types.is_empty());
        assert!(!context.transformations_attempted.is_empty());
        assert!(!context.findings.is_empty());
        assert!(!context.metadata.is_empty());
    }

    #[test]
    fn test_optimize_context() {
        let config = ContextBuilderConfig {
            max_prompt_size: 100, // Very small limit to force optimization
            ..Default::default()
        };
        let builder = ContextBuilder::with_config(config);
        
        let mut context = AnalysisContext::new();
        
        // Add many findings to trigger optimization
        for i in 0..20 {
            let finding = Finding::new(
                FindingCategory::General,
                format!("Finding {}", i),
                0.5,
                vec![],
                vec![],
            ).unwrap();
            context.add_finding(finding);
        }

        let optimized = builder.optimize_context(context).unwrap();
        assert!(optimized.findings.len() <= 10);
    }

    #[test]
    fn test_manage_conversation_history() {
        let builder = ContextBuilder::new();
        let mut history = Vec::new();

        // Create more history entries than the limit
        for i in 0..10 {
            let response = HintResponse::new(
                vec![format!("Hint {}", i)],
                "Reasoning".to_string(),
                vec![],
                vec![],
            ).unwrap();
            
            let exchange = HintExchange::new(format!("Request {}", i), response);
            history.push(exchange);
        }

        let managed = builder.manage_conversation_history(history).unwrap();
        assert!(managed.len() <= builder.config.max_history_entries);
    }

    #[test]
    fn test_build_analysis_summary() {
        let builder = ContextBuilder::new();
        let results = vec![create_test_analysis_result()];

        let summary = builder.build_analysis_summary(&results).unwrap();
        assert!(summary.contains("Analysis Summary"));
        assert!(summary.contains("finding(s)"));
    }

    #[test]
    fn test_estimate_tokens() {
        let builder = ContextBuilder::new();
        let text = "This is a test string for token estimation.";
        let tokens = builder.estimate_tokens(text);
        assert!(tokens > 0);
        assert!(tokens <= text.len()); // Should be less than character count
    }

    #[test]
    fn test_optimize_for_tokens() {
        let builder = ContextBuilder::new();
        let long_text = "A".repeat(1000);
        
        let optimized = builder.optimize_for_tokens(&long_text, 50).unwrap();
        assert!(optimized.len() < long_text.len());
        assert!(builder.estimate_tokens(&optimized) <= 50);
    }
}