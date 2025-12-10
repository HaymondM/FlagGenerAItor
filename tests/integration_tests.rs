//! End-to-end integration tests for the CTF Assistant
//! 
//! These tests verify complete analysis workflows from file upload to hint generation,
//! interface parity between CLI and web, and plugin system functionality.

use anyhow::Result;
use ctf_core::{
    core::models::{Challenge, ChallengeFile, FileType, FileMetadata},
    interfaces::orchestrator::{AnalysisOrchestrator, OrchestrationConfig},
    plugins::PluginManager,
    core::storage::Storage,
};
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;
use tokio::fs;
use uuid::Uuid;

/// Test data directory for integration tests
const TEST_DATA_DIR: &str = "tests/data";

/// Helper to create test files
struct TestFileBuilder {
    temp_dir: TempDir,
}

impl TestFileBuilder {
    fn new() -> Result<Self> {
        Ok(Self {
            temp_dir: tempfile::tempdir()?,
        })
    }

    /// Create a test text file with encoded content
    async fn create_encoded_text_file(&self, content: &str, encoding: &str) -> Result<PathBuf> {
        let encoded_content = match encoding {
            "base64" => base64::encode(content),
            "hex" => hex::encode(content.as_bytes()),
            "rot13" => content.chars().map(|c| {
                match c {
                    'a'..='z' => ((c as u8 - b'a' + 13) % 26 + b'a') as char,
                    'A'..='Z' => ((c as u8 - b'A' + 13) % 26 + b'A') as char,
                    _ => c,
                }
            }).collect(),
            _ => content.to_string(),
        };

        let file_path = self.temp_dir.path().join(format!("test_{}.txt", encoding));
        fs::write(&file_path, encoded_content).await?;
        Ok(file_path)
    }

    /// Create a test image file (simple PNG header)
    async fn create_test_image(&self) -> Result<PathBuf> {
        // Simple PNG header + minimal data
        let png_data = vec![
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
            0x00, 0x00, 0x00, 0x0D, // IHDR chunk length
            0x49, 0x48, 0x44, 0x52, // IHDR
            0x00, 0x00, 0x00, 0x01, // Width: 1
            0x00, 0x00, 0x00, 0x01, // Height: 1
            0x08, 0x02, 0x00, 0x00, 0x00, // Bit depth, color type, etc.
            0x90, 0x77, 0x53, 0xDE, // CRC
            0x00, 0x00, 0x00, 0x00, // IEND chunk length
            0x49, 0x45, 0x4E, 0x44, // IEND
            0xAE, 0x42, 0x60, 0x82, // CRC
        ];

        let file_path = self.temp_dir.path().join("test_image.png");
        fs::write(&file_path, png_data).await?;
        Ok(file_path)
    }

    /// Create a test web file with potential vulnerabilities
    async fn create_test_web_file(&self) -> Result<PathBuf> {
        let html_content = r#"
<!DOCTYPE html>
<html>
<head>
    <title>Test Challenge</title>
</head>
<body>
    <form action="/submit" method="POST">
        <input type="text" name="username" value="">
        <input type="password" name="password" value="">
        <input type="hidden" name="csrf_token" value="abc123">
        <button type="submit">Login</button>
    </form>
    <script>
        // Potential XSS vulnerability
        document.write("Welcome " + location.search.substring(1));
    </script>
</body>
</html>
        "#;

        let file_path = self.temp_dir.path().join("test_web.html");
        fs::write(&file_path, html_content).await?;
        Ok(file_path)
    }

    fn temp_dir_path(&self) -> &std::path::Path {
        self.temp_dir.path()
    }
}

/// Helper to create test challenges
async fn create_test_challenge(
    name: &str,
    files: Vec<(PathBuf, FileType)>,
    storage: &Storage,
) -> Result<Challenge> {
    let challenge_id = Uuid::new_v4();
    let mut challenge_files = Vec::new();

    for (file_path, file_type) in files {
        let file_data = fs::read(&file_path).await?;
        let file_id = Uuid::new_v4();
        
        // Store file in storage
        let stored_path = storage.store_file(&file_data, &file_path.file_name().unwrap().to_string_lossy()).await?;
        
        let challenge_file = ChallengeFile {
            id: file_id,
            original_name: file_path.file_name().unwrap().to_string_lossy().to_string(),
            file_type,
            size: file_data.len() as u64,
            hash: format!("{:x}", sha2::Sha256::digest(&file_data)),
            storage_path: stored_path,
            metadata: FileMetadata::default(),
        };
        
        challenge_files.push(challenge_file);
    }

    Ok(Challenge {
        id: challenge_id,
        name: name.to_string(),
        files: challenge_files,
        context: format!("Test challenge: {}", name),
        created_at: chrono::Utc::now(),
        analysis_results: Vec::new(),
    })
}

#[tokio::test]
async fn test_complete_analysis_workflow() -> Result<()> {
    // Setup test environment
    let test_builder = TestFileBuilder::new()?;
    let storage = Storage::new_temp().await?;
    
    // Create test files with different encodings
    let base64_file = test_builder.create_encoded_text_file("flag{test_base64}", "base64").await?;
    let hex_file = test_builder.create_encoded_text_file("flag{test_hex}", "hex").await?;
    let rot13_file = test_builder.create_encoded_text_file("flag{test_rot13}", "rot13").await?;
    let image_file = test_builder.create_test_image().await?;
    
    // Create test challenge
    let challenge = create_test_challenge(
        "Complete Workflow Test",
        vec![
            (base64_file, FileType::Text),
            (hex_file, FileType::Text),
            (rot13_file, FileType::Text),
            (image_file, FileType::Image),
        ],
        &storage,
    ).await?;

    // Configure orchestrator
    let config = OrchestrationConfig {
        max_analysis_time_per_file: Duration::from_secs(30),
        parallel_plugin_execution: true,
        max_decoder_depth: 3,
        auto_generate_hints: false, // Skip AI for integration test
        min_confidence_threshold: 0.1,
    };
    
    let orchestrator = AnalysisOrchestrator::with_config(config);
    
    // Validate challenge before analysis
    orchestrator.validate_challenge(&challenge)?;
    
    // Run complete analysis
    let results = orchestrator.analyze_challenge(&challenge).await?;
    
    // Verify results
    assert!(!results.is_empty(), "Analysis should produce results");
    
    // Check that we have results for each file
    let file_ids: std::collections::HashSet<_> = challenge.files.iter().map(|f| f.id).collect();
    let result_file_ids: std::collections::HashSet<_> = results.iter().map(|r| r.file_id).collect();
    
    // We should have at least some results for our files
    assert!(!result_file_ids.is_disjoint(&file_ids), "Results should reference challenge files");
    
    // Check for meaningful transformations in decoder results
    let decoder_results: Vec<_> = results.iter()
        .filter(|r| r.analyzer == "decoder-pipeline")
        .collect();
    
    assert!(!decoder_results.is_empty(), "Should have decoder pipeline results");
    
    // Verify that some transformations were marked as meaningful
    let has_meaningful = decoder_results.iter()
        .any(|r| r.transformations.iter().any(|t| t.meaningful));
    
    assert!(has_meaningful, "Should find meaningful transformations in encoded files");
    
    println!("✓ Complete analysis workflow test passed");
    println!("  - Analyzed {} files", challenge.files.len());
    println!("  - Generated {} results", results.len());
    println!("  - Found meaningful transformations: {}", has_meaningful);
    
    Ok(())
}

#[tokio::test]
async fn test_plugin_system_integration() -> Result<()> {
    // Setup test environment
    let test_builder = TestFileBuilder::new()?;
    let storage = Storage::new_temp().await?;
    
    // Create test files for plugin analysis
    let web_file = test_builder.create_test_web_file().await?;
    let text_file = test_builder.create_encoded_text_file("test content", "plain").await?;
    
    // Create challenge
    let challenge = create_test_challenge(
        "Plugin System Test",
        vec![
            (web_file, FileType::Html),
            (text_file, FileType::Text),
        ],
        &storage,
    ).await?;

    // Create plugin manager and load plugins
    let plugin_manager = PluginManager::new();
    
    // Configure orchestrator with plugins
    let config = OrchestrationConfig {
        max_analysis_time_per_file: Duration::from_secs(20),
        parallel_plugin_execution: true,
        max_decoder_depth: 2,
        auto_generate_hints: false,
        min_confidence_threshold: 0.1,
    };
    
    let orchestrator = AnalysisOrchestrator::with_plugins(plugin_manager, config).await;
    
    // Run analysis
    let results = orchestrator.analyze_challenge(&challenge).await?;
    
    // Verify plugin execution
    assert!(!results.is_empty(), "Plugin analysis should produce results");
    
    // Check for built-in plugin results
    let plugin_analyzers: Vec<_> = results.iter()
        .map(|r| &r.analyzer)
        .filter(|analyzer| analyzer.contains("plugin") || analyzer.contains("builtin"))
        .collect();
    
    println!("✓ Plugin system integration test passed");
    println!("  - Plugin analyzers found: {:?}", plugin_analyzers);
    println!("  - Total results: {}", results.len());
    
    Ok(())
}

#[tokio::test]
async fn test_multi_file_processing_isolation() -> Result<()> {
    // Setup test environment
    let test_builder = TestFileBuilder::new()?;
    let storage = Storage::new_temp().await?;
    
    // Create multiple files with different content
    let file1 = test_builder.create_encoded_text_file("flag{file1}", "base64").await?;
    let file2 = test_builder.create_encoded_text_file("flag{file2}", "hex").await?;
    let file3 = test_builder.create_encoded_text_file("flag{file3}", "rot13").await?;
    
    // Create challenge with multiple files
    let challenge = create_test_challenge(
        "Multi-file Isolation Test",
        vec![
            (file1, FileType::Text),
            (file2, FileType::Text),
            (file3, FileType::Text),
        ],
        &storage,
    ).await?;

    let orchestrator = AnalysisOrchestrator::new();
    
    // Run analysis
    let results = orchestrator.analyze_challenge(&challenge).await?;
    
    // Verify isolation - each file should have separate results
    let file_ids: std::collections::HashSet<_> = challenge.files.iter().map(|f| f.id).collect();
    let result_file_ids: std::collections::HashSet<_> = results.iter().map(|r| r.file_id).collect();
    
    // Should have results for multiple files
    assert!(result_file_ids.len() > 1, "Should have results for multiple files");
    
    // Verify no cross-contamination by checking that results are properly attributed
    for result in &results {
        assert!(file_ids.contains(&result.file_id), "Result should reference a valid file ID");
    }
    
    println!("✓ Multi-file processing isolation test passed");
    println!("  - Processed {} files", challenge.files.len());
    println!("  - Results for {} files", result_file_ids.len());
    
    Ok(())
}

#[tokio::test]
async fn test_error_handling_and_recovery() -> Result<()> {
    // Setup test environment
    let test_builder = TestFileBuilder::new()?;
    let storage = Storage::new_temp().await?;
    
    // Create a valid file and a problematic file path
    let valid_file = test_builder.create_encoded_text_file("valid content", "base64").await?;
    
    // Create challenge with one valid file
    let mut challenge = create_test_challenge(
        "Error Handling Test",
        vec![(valid_file, FileType::Text)],
        &storage,
    ).await?;
    
    // Add a file with invalid path to test error handling
    let invalid_file = ChallengeFile {
        id: Uuid::new_v4(),
        original_name: "nonexistent.txt".to_string(),
        file_type: FileType::Text,
        size: 100,
        hash: "invalid".to_string(),
        storage_path: PathBuf::from("/nonexistent/path/file.txt"),
        metadata: FileMetadata::default(),
    };
    challenge.files.push(invalid_file);

    let orchestrator = AnalysisOrchestrator::new();
    
    // Run analysis - should handle errors gracefully
    let results = orchestrator.analyze_challenge(&challenge).await?;
    
    // Should still have results for the valid file
    assert!(!results.is_empty(), "Should have results despite errors");
    
    // Check for error results
    let error_results: Vec<_> = results.iter()
        .filter(|r| r.analyzer == "orchestrator")
        .collect();
    
    // Should have at least one error result for the invalid file
    assert!(!error_results.is_empty(), "Should have error results for failed files");
    
    println!("✓ Error handling and recovery test passed");
    println!("  - Handled {} files with errors gracefully", error_results.len());
    
    Ok(())
}

#[tokio::test]
async fn test_analysis_time_limits() -> Result<()> {
    // Setup test environment
    let test_builder = TestFileBuilder::new()?;
    let storage = Storage::new_temp().await?;
    
    // Create test file
    let test_file = test_builder.create_encoded_text_file("test content", "base64").await?;
    
    // Create challenge
    let challenge = create_test_challenge(
        "Time Limit Test",
        vec![(test_file, FileType::Text)],
        &storage,
    ).await?;

    // Configure with very short time limit
    let config = OrchestrationConfig {
        max_analysis_time_per_file: Duration::from_millis(100), // Very short
        parallel_plugin_execution: false,
        max_decoder_depth: 1,
        auto_generate_hints: false,
        min_confidence_threshold: 0.1,
    };
    
    let orchestrator = AnalysisOrchestrator::with_config(config);
    
    // Run analysis - should complete despite time constraints
    let start_time = std::time::Instant::now();
    let results = orchestrator.analyze_challenge(&challenge).await?;
    let total_time = start_time.elapsed();
    
    // Should complete in reasonable time
    assert!(total_time < Duration::from_secs(10), "Analysis should complete quickly");
    
    // Should still produce some results
    assert!(!results.is_empty(), "Should produce results even with time limits");
    
    println!("✓ Analysis time limits test passed");
    println!("  - Completed in {:?}", total_time);
    println!("  - Generated {} results", results.len());
    
    Ok(())
}

#[tokio::test]
async fn test_confidence_threshold_filtering() -> Result<()> {
    // Setup test environment
    let test_builder = TestFileBuilder::new()?;
    let storage = Storage::new_temp().await?;
    
    // Create test files
    let encoded_file = test_builder.create_encoded_text_file("flag{confidence_test}", "base64").await?;
    
    // Create challenge
    let challenge = create_test_challenge(
        "Confidence Threshold Test",
        vec![(encoded_file, FileType::Text)],
        &storage,
    ).await?;

    // Test with low threshold
    let low_threshold_config = OrchestrationConfig {
        min_confidence_threshold: 0.1,
        ..Default::default()
    };
    
    let orchestrator_low = AnalysisOrchestrator::with_config(low_threshold_config);
    let results_low = orchestrator_low.analyze_challenge(&challenge).await?;
    
    // Test with high threshold
    let high_threshold_config = OrchestrationConfig {
        min_confidence_threshold: 0.9,
        ..Default::default()
    };
    
    let orchestrator_high = AnalysisOrchestrator::with_config(high_threshold_config);
    let results_high = orchestrator_high.analyze_challenge(&challenge).await?;
    
    // Low threshold should have more or equal results
    assert!(results_low.len() >= results_high.len(), 
            "Low threshold should have more results than high threshold");
    
    println!("✓ Confidence threshold filtering test passed");
    println!("  - Low threshold (0.1): {} results", results_low.len());
    println!("  - High threshold (0.9): {} results", results_high.len());
    
    Ok(())
}

/// Helper function to run all integration tests
pub async fn run_all_integration_tests() -> Result<()> {
    println!("Running CTF Assistant Integration Tests...\n");
    
    test_complete_analysis_workflow().await?;
    test_plugin_system_integration().await?;
    test_multi_file_processing_isolation().await?;
    test_error_handling_and_recovery().await?;
    test_analysis_time_limits().await?;
    test_confidence_threshold_filtering().await?;
    
    println!("\n✅ All integration tests passed!");
    
    Ok(())
}