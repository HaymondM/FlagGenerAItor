//! Analysis orchestrator for coordinating all components

use crate::analysis::decoder_pipeline::DecoderPipeline;
use crate::analysis::file_analyzer::FileAnalyzer;
use crate::analysis::steganography::SteganographyAnalyzer;
use crate::analysis::web_analysis::WebAnalyzer;
use crate::core::models::{Challenge, AnalysisResult, ChallengeFile, FileType, Finding, FindingCategory, TransformationResult};
use crate::interfaces::ai_integration::HintGenerator;
use crate::interfaces::context_builder::ContextBuilder;
use crate::plugins::{PluginManager, AnalysisContext};
use crate::Result;
use anyhow::{anyhow, Context as AnyhowContext};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Progress tracking for analysis operations
#[derive(Debug, Clone)]
pub struct AnalysisProgress {
    pub total_files: usize,
    pub completed_files: usize,
    pub current_operation: String,
    pub estimated_remaining: Option<Duration>,
}

impl AnalysisProgress {
    pub fn new(total_files: usize) -> Self {
        Self {
            total_files,
            completed_files: 0,
            current_operation: "Starting analysis".to_string(),
            estimated_remaining: None,
        }
    }

    pub fn update(&mut self, completed_files: usize, operation: String) {
        self.completed_files = completed_files;
        self.current_operation = operation;
        
        // Simple estimation based on completed work
        if completed_files > 0 && self.total_files > completed_files {
            let avg_time_per_file = Duration::from_secs(5); // Rough estimate
            let remaining_files = self.total_files - completed_files;
            self.estimated_remaining = Some(avg_time_per_file * remaining_files as u32);
        }
    }

    pub fn progress_percentage(&self) -> f32 {
        if self.total_files == 0 {
            return 100.0;
        }
        (self.completed_files as f32 / self.total_files as f32) * 100.0
    }
}

/// Configuration for analysis orchestration
#[derive(Debug, Clone)]
pub struct OrchestrationConfig {
    /// Maximum time to spend on analysis per file
    pub max_analysis_time_per_file: Duration,
    /// Whether to run plugins in parallel
    pub parallel_plugin_execution: bool,
    /// Maximum recursion depth for decoder pipeline
    pub max_decoder_depth: u8,
    /// Whether to generate AI hints automatically
    pub auto_generate_hints: bool,
    /// Minimum confidence threshold for including results
    pub min_confidence_threshold: f32,
}

impl Default for OrchestrationConfig {
    fn default() -> Self {
        Self {
            max_analysis_time_per_file: Duration::from_secs(60),
            parallel_plugin_execution: true,
            max_decoder_depth: 5,
            auto_generate_hints: true,
            min_confidence_threshold: 0.1,
        }
    }
}

/// Analysis orchestrator for coordinating all components
pub struct AnalysisOrchestrator {
    file_analyzer: FileAnalyzer,
    decoder_pipeline: DecoderPipeline,
    steganography_analyzer: SteganographyAnalyzer,
    web_analyzer: WebAnalyzer,
    plugin_manager: Arc<PluginManager>,
    hint_generator: HintGenerator,
    context_builder: ContextBuilder,
    config: OrchestrationConfig,
}

impl AnalysisOrchestrator {
    /// Create a new analysis orchestrator with default configuration
    pub fn new() -> Self {
        Self::with_config(OrchestrationConfig::default())
    }

    /// Create a new analysis orchestrator with custom configuration
    pub fn with_config(config: OrchestrationConfig) -> Self {
        Self {
            file_analyzer: FileAnalyzer::new(),
            decoder_pipeline: DecoderPipeline::new(),
            steganography_analyzer: SteganographyAnalyzer::new(),
            web_analyzer: WebAnalyzer::new().expect("Failed to create WebAnalyzer"),
            plugin_manager: Arc::new(PluginManager::new()),
            hint_generator: HintGenerator::new(),
            context_builder: ContextBuilder::new(),
            config,
        }
    }

    /// Create orchestrator with plugin manager
    pub async fn with_plugins(plugin_manager: PluginManager, config: OrchestrationConfig) -> Self {
        Self {
            file_analyzer: FileAnalyzer::new(),
            decoder_pipeline: DecoderPipeline::new(),
            steganography_analyzer: SteganographyAnalyzer::new(),
            web_analyzer: WebAnalyzer::new().expect("Failed to create WebAnalyzer"),
            plugin_manager: Arc::new(plugin_manager),
            hint_generator: HintGenerator::new(),
            context_builder: ContextBuilder::new(),
            config,
        }
    }
    
    /// Orchestrate complete analysis of a challenge
    pub async fn analyze_challenge(&self, challenge: &Challenge) -> Result<Vec<AnalysisResult>> {
        let start_time = Instant::now();
        info!("Starting analysis orchestration for challenge: {} with {} files", 
              challenge.name, challenge.files.len());

        let mut progress = AnalysisProgress::new(challenge.files.len());
        let mut all_results = Vec::new();

        // Process each file in the challenge
        for (index, file) in challenge.files.iter().enumerate() {
            progress.update(index, format!("Analyzing file: {}", file.original_name));
            info!("Processing file {}/{}: {} ({})", 
                  index + 1, challenge.files.len(), file.original_name, file.file_type);

            match self.analyze_single_file(file).await {
                Ok(mut file_results) => {
                    info!("File analysis completed with {} results", file_results.len());
                    all_results.append(&mut file_results);
                }
                Err(e) => {
                    error!("Failed to analyze file {}: {}", file.original_name, e);
                    
                    // Create an error result to track the failure
                    if let Ok(error_result) = AnalysisResult::new(
                        "orchestrator".to_string(),
                        file.id,
                        vec![],
                        vec![Finding::new(
                            FindingCategory::General,
                            format!("Analysis failed: {}", e),
                            0.0,
                            vec![],
                            vec!["Check file integrity and try manual analysis".to_string()],
                        )?],
                        Duration::from_millis(100),
                    ) {
                        all_results.push(error_result);
                    }
                }
            }
        }

        progress.update(challenge.files.len(), "Analysis complete".to_string());
        
        let total_time = start_time.elapsed();
        info!("Challenge analysis completed in {:?} with {} total results", 
              total_time, all_results.len());

        // Filter results by confidence threshold
        let filtered_results: Vec<AnalysisResult> = all_results.into_iter()
            .filter(|result| result.confidence >= self.config.min_confidence_threshold)
            .collect();

        info!("Filtered to {} results above confidence threshold {:.2}", 
              filtered_results.len(), self.config.min_confidence_threshold);

        Ok(filtered_results)
    }

    /// Analyze a single file with all available analyzers
    async fn analyze_single_file(&self, file: &ChallengeFile) -> Result<Vec<AnalysisResult>> {
        let file_start_time = Instant::now();
        debug!("Starting analysis of file: {} ({})", file.original_name, file.file_type);

        // Load file data
        let file_data = self.load_file_data(file).await
            .with_context(|| format!("Failed to load file data for {}", file.original_name))?;

        let mut results = Vec::new();

        // 1. File type-specific analysis
        match file.file_type {
            FileType::Image => {
                debug!("Running image-specific analysis");
                if let Ok(stego_results) = self.run_steganography_analysis(file, &file_data).await {
                    results.extend(stego_results);
                }
            }
            FileType::Javascript | FileType::Html | FileType::Text => {
                debug!("Running web-specific analysis");
                if let Ok(web_results) = self.run_web_analysis(file, &file_data).await {
                    results.extend(web_results);
                }
            }
            _ => {
                debug!("Running general analysis for file type: {:?}", file.file_type);
            }
        }

        // 2. Decoder pipeline analysis (for all file types)
        debug!("Running decoder pipeline analysis");
        if let Ok(decoder_results) = self.run_decoder_analysis(file, &file_data).await {
            results.extend(decoder_results);
        }

        // 3. Plugin-based analysis
        debug!("Running plugin analysis");
        if let Ok(plugin_results) = self.run_plugin_analysis(file, &file_data).await {
            results.extend(plugin_results);
        }

        let file_analysis_time = file_start_time.elapsed();
        debug!("File analysis completed in {:?} with {} results", 
               file_analysis_time, results.len());

        // Check if we exceeded the time limit
        if file_analysis_time > self.config.max_analysis_time_per_file {
            warn!("File analysis exceeded time limit: {:?} > {:?}", 
                  file_analysis_time, self.config.max_analysis_time_per_file);
        }

        Ok(results)
    }

    /// Load file data from storage
    async fn load_file_data(&self, file: &ChallengeFile) -> Result<Vec<u8>> {
        Ok(fs::read(&file.storage_path).await
            .with_context(|| format!("Failed to read file from {}", file.storage_path.display()))?)
    }

    /// Run steganography analysis for image files
    async fn run_steganography_analysis(&self, file: &ChallengeFile, data: &[u8]) -> Result<Vec<AnalysisResult>> {
        let start_time = Instant::now();
        
        match self.steganography_analyzer.analyze_image(data, &file.original_name).await {
            Ok(findings) => {
                let execution_time = start_time.elapsed();
                let _confidence = if findings.is_empty() { 0.1 } else { 0.8 };
                
                let result = AnalysisResult::new(
                    "steganography".to_string(),
                    file.id,
                    vec![], // Steganography doesn't produce transformations
                    findings,
                    execution_time,
                )?;
                
                Ok(vec![result])
            }
            Err(e) => {
                warn!("Steganography analysis failed for {}: {}", file.original_name, e);
                Ok(vec![])
            }
        }
    }

    /// Run web analysis for web-related files
    async fn run_web_analysis(&self, file: &ChallengeFile, data: &[u8]) -> Result<Vec<AnalysisResult>> {
        let start_time = Instant::now();
        
        match self.web_analyzer.analyze_web_content(data).await {
            Ok(findings) => {
                let execution_time = start_time.elapsed();
                let _confidence = if findings.is_empty() { 0.1 } else { 0.7 };
                
                let result = AnalysisResult::new(
                    "web-analysis".to_string(),
                    file.id,
                    vec![], // Web analysis doesn't produce transformations
                    findings,
                    execution_time,
                )?;
                
                Ok(vec![result])
            }
            Err(e) => {
                warn!("Web analysis failed for {}: {}", file.original_name, e);
                Ok(vec![])
            }
        }
    }

    /// Run decoder pipeline analysis
    async fn run_decoder_analysis(&self, file: &ChallengeFile, data: &[u8]) -> Result<Vec<AnalysisResult>> {
        let start_time = Instant::now();
        
        match self.decoder_pipeline.process_recursive(data, self.config.max_decoder_depth).await {
            Ok(transformations) => {
                let execution_time = start_time.elapsed();
                
                // Group transformations by meaningfulness and create findings
                let meaningful_transformations: Vec<&TransformationResult> = transformations.iter()
                    .filter(|t| t.meaningful)
                    .collect();

                let mut findings = Vec::new();
                
                if !meaningful_transformations.is_empty() {
                    let evidence: Vec<String> = meaningful_transformations.iter()
                        .take(5) // Limit evidence to prevent overwhelming output
                        .map(|t| format!("{}: {}", t.transformation.description(), t.output_preview))
                        .collect();

                    findings.push(Finding::new(
                        FindingCategory::Cryptography,
                        format!("Found {} meaningful transformations", meaningful_transformations.len()),
                        0.8,
                        evidence,
                        vec![
                            "Examine the decoded content for flags or clues".to_string(),
                            "Try combining multiple transformations".to_string(),
                        ],
                    )?);
                }

                let _confidence = if meaningful_transformations.is_empty() { 0.2 } else { 0.8 };
                
                let result = AnalysisResult::new(
                    "decoder-pipeline".to_string(),
                    file.id,
                    transformations,
                    findings,
                    execution_time,
                )?;
                
                Ok(vec![result])
            }
            Err(e) => {
                warn!("Decoder pipeline analysis failed for {}: {}", file.original_name, e);
                Ok(vec![])
            }
        }
    }

    /// Run plugin-based analysis
    async fn run_plugin_analysis(&self, file: &ChallengeFile, data: &[u8]) -> Result<Vec<AnalysisResult>> {
        let context = AnalysisContext::new(
            file.file_type.clone(),
            file.original_name.clone(),
            file.id,
            file.size,
        );

        match self.plugin_manager.execute_plugins(data, &context).await {
            Ok(results) => Ok(results),
            Err(e) => {
                warn!("Plugin analysis failed for {}: {}", file.original_name, e);
                Ok(vec![])
            }
        }
    }

    /// Aggregate and deduplicate analysis results
    pub fn aggregate_results(&self, results: Vec<AnalysisResult>) -> Result<Vec<AnalysisResult>> {
        debug!("Aggregating {} analysis results", results.len());

        // Group results by file_id for better organization
        let mut results_by_file: HashMap<Uuid, Vec<AnalysisResult>> = HashMap::new();
        
        for result in results {
            results_by_file.entry(result.file_id).or_default().push(result);
        }

        let mut aggregated_results = Vec::new();

        for (_file_id, file_results) in results_by_file {
            // Merge similar findings to reduce noise
            let merged_results = self.merge_similar_findings(file_results)?;
            aggregated_results.extend(merged_results);
        }

        debug!("Aggregated to {} results", aggregated_results.len());
        Ok(aggregated_results)
    }

    /// Merge similar findings to reduce noise
    fn merge_similar_findings(&self, results: Vec<AnalysisResult>) -> Result<Vec<AnalysisResult>> {
        // For now, just return the results as-is
        // In the future, we could implement sophisticated merging logic
        Ok(results)
    }

    /// Generate status report for analysis progress
    pub fn generate_status_report(&self, progress: &AnalysisProgress) -> String {
        format!(
            "Analysis Progress: {:.1}% ({}/{} files)\nCurrent: {}\nEstimated remaining: {}",
            progress.progress_percentage(),
            progress.completed_files,
            progress.total_files,
            progress.current_operation,
            progress.estimated_remaining
                .map(|d| format!("{:.1}s", d.as_secs_f64()))
                .unwrap_or_else(|| "Unknown".to_string())
        )
    }

    /// Get orchestrator configuration
    pub fn get_config(&self) -> &OrchestrationConfig {
        &self.config
    }

    /// Update orchestrator configuration
    pub fn update_config(&mut self, config: OrchestrationConfig) {
        self.config = config;
    }

    /// Get plugin manager reference
    pub fn get_plugin_manager(&self) -> &PluginManager {
        &self.plugin_manager
    }

    /// Validate challenge before analysis
    pub fn validate_challenge(&self, challenge: &Challenge) -> Result<()> {
        challenge.validate()?;

        if challenge.files.is_empty() {
            return Err(anyhow!("Challenge has no files to analyze").into());
        }

        // Check file accessibility
        for file in &challenge.files {
            if !file.storage_path.exists() {
                return Err(anyhow!("File not found: {}", file.storage_path.display()).into());
            }
        }

        Ok(())
    }

    /// Estimate analysis time for a challenge
    pub fn estimate_analysis_time(&self, challenge: &Challenge) -> Duration {
        // Simple estimation based on file count and types
        let base_time_per_file = Duration::from_secs(10);
        let image_bonus = Duration::from_secs(5); // Images take longer due to steganography
        
        let mut total_time = Duration::ZERO;
        
        for file in &challenge.files {
            total_time += base_time_per_file;
            
            if file.file_type == FileType::Image {
                total_time += image_bonus;
            }
        }

        // Add overhead for orchestration
        total_time += Duration::from_secs(5);
        
        total_time
    }
}

impl Default for AnalysisOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}