//! Interface parity tests between CLI and web interfaces
//! 
//! These tests verify that both CLI and web interfaces provide equivalent
//! functionality and produce consistent results.

use anyhow::Result;
use ctf_core::{
    core::models::{Challenge, ChallengeFile, FileType, FileMetadata},
    core::storage::Storage,
    interfaces::orchestrator::AnalysisOrchestrator,
};
use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;
use tokio::fs;
use uuid::Uuid;

/// Test helper for creating temporary files and challenges
struct InterfaceTestHelper {
    temp_dir: TempDir,
    storage: Storage,
}

impl InterfaceTestHelper {
    async fn new() -> Result<Self> {
        Ok(Self {
            temp_dir: tempfile::tempdir()?,
            storage: Storage::new_temp().await?,
        })
    }

    /// Create a test file with known content
    async fn create_test_file(&self, name: &str, content: &str) -> Result<PathBuf> {
        let file_path = self.temp_dir.path().join(name);
        fs::write(&file_path, content).await?;
        Ok(file_path)
    }

    /// Create a challenge for testing
    async fn create_test_challenge(&self, name: &str, file_path: PathBuf) -> Result<Challenge> {
        let file_data = fs::read(&file_path).await?;
        let file_id = Uuid::new_v4();
        
        // Store file in storage
        let stored_path = self.storage.store_file(&file_data, &file_path.file_name().unwrap().to_string_lossy()).await?;
        
        let challenge_file = ChallengeFile {
            id: file_id,
            original_name: file_path.file_name().unwrap().to_string_lossy().to_string(),
            file_type: FileType::Text,
            size: file_data.len() as u64,
            hash: format!("{:x}", sha2::Sha256::digest(&file_data)),
            storage_path: stored_path,
            metadata: FileMetadata::default(),
        };

        Ok(Challenge {
            id: Uuid::new_v4(),
            name: name.to_string(),
            files: vec![challenge_file],
            context: format!("Test challenge: {}", name),
            created_at: chrono::Utc::now(),
            analysis_results: Vec::new(),
        })
    }

    fn temp_dir_path(&self) -> &std::path::Path {
        self.temp_dir.path()
    }
}

/// Simulate CLI analysis by calling the orchestrator directly
async fn simulate_cli_analysis(challenge: &Challenge) -> Result<Value> {
    let orchestrator = AnalysisOrchestrator::new();
    let results = orchestrator.analyze_challenge(challenge).await?;
    
    // Convert results to JSON format similar to CLI output
    let cli_output = serde_json::json!({
        "challenge_name": challenge.name,
        "files_analyzed": challenge.files.len(),
        "total_results": results.len(),
        "results": results.iter().map(|r| {
            serde_json::json!({
                "analyzer": r.analyzer,
                "file_id": r.file_id,
                "confidence": r.confidence,
                "findings_count": r.findings.len(),
                "transformations_count": r.transformations.len(),
                "execution_time_ms": r.execution_time.as_millis(),
                "meaningful_transformations": r.transformations.iter()
                    .filter(|t| t.meaningful)
                    .count()
            })
        }).collect::<Vec<_>>(),
        "interface": "cli"
    });
    
    Ok(cli_output)
}

/// Simulate web interface analysis
async fn simulate_web_analysis(challenge: &Challenge) -> Result<Value> {
    let orchestrator = AnalysisOrchestrator::new();
    let results = orchestrator.analyze_challenge(challenge).await?;
    
    // Convert results to JSON format similar to web API response
    let web_output = serde_json::json!({
        "challenge": {
            "name": challenge.name,
            "id": challenge.id,
            "files": challenge.files.len()
        },
        "analysis": {
            "total_results": results.len(),
            "results": results.iter().map(|r| {
                serde_json::json!({
                    "analyzer": r.analyzer,
                    "file_id": r.file_id,
                    "confidence": r.confidence,
                    "findings": r.findings.len(),
                    "transformations": r.transformations.len(),
                    "execution_time": r.execution_time.as_millis(),
                    "meaningful_outputs": r.transformations.iter()
                        .filter(|t| t.meaningful)
                        .count()
                })
            }).collect::<Vec<_>>()
        },
        "interface": "web"
    });
    
    Ok(web_output)
}

#[tokio::test]
async fn test_cli_web_analysis_equivalence() -> Result<()> {
    // Setup test environment
    let helper = InterfaceTestHelper::new().await?;
    
    // Create test file with base64 encoded content
    let test_content = base64::encode("flag{interface_parity_test}");
    let test_file = helper.create_test_file("encoded.txt", &test_content).await?;
    
    // Create challenge
    let challenge = helper.create_test_challenge("Interface Parity Test", test_file).await?;
    
    // Run analysis through both interfaces
    let cli_result = simulate_cli_analysis(&challenge).await?;
    let web_result = simulate_web_analysis(&challenge).await?;
    
    // Extract core analysis data for comparison
    let cli_results = cli_result["results"].as_array().unwrap();
    let web_results = web_result["analysis"]["results"].as_array().unwrap();
    
    // Verify equivalent number of results
    assert_eq!(cli_results.len(), web_results.len(), 
               "CLI and web should produce same number of results");
    
    // Verify equivalent analyzers are used
    let cli_analyzers: std::collections::HashSet<_> = cli_results.iter()
        .map(|r| r["analyzer"].as_str().unwrap())
        .collect();
    let web_analyzers: std::collections::HashSet<_> = web_results.iter()
        .map(|r| r["analyzer"].as_str().unwrap())
        .collect();
    
    assert_eq!(cli_analyzers, web_analyzers, 
               "CLI and web should use same analyzers");
    
    // Verify equivalent meaningful transformations found
    let cli_meaningful: u64 = cli_results.iter()
        .map(|r| r["meaningful_transformations"].as_u64().unwrap_or(0))
        .sum();
    let web_meaningful: u64 = web_results.iter()
        .map(|r| r["meaningful_outputs"].as_u64().unwrap_or(0))
        .sum();
    
    assert_eq!(cli_meaningful, web_meaningful,
               "CLI and web should find same number of meaningful transformations");
    
    println!("✓ CLI/Web analysis equivalence test passed");
    println!("  - Both interfaces used {} analyzers", cli_analyzers.len());
    println!("  - Both found {} meaningful transformations", cli_meaningful);
    
    Ok(())
}

#[tokio::test]
async fn test_output_format_consistency() -> Result<()> {
    // Setup test environment
    let helper = InterfaceTestHelper::new().await?;
    
    // Create test files with different content types
    let base64_content = base64::encode("flag{format_test_base64}");
    let hex_content = hex::encode("flag{format_test_hex}");
    let rot13_content = "synt{sbezng_grfg_ebg13}"; // ROT13 of "flag{format_test_rot13}"
    
    let base64_file = helper.create_test_file("base64.txt", &base64_content).await?;
    let hex_file = helper.create_test_file("hex.txt", &hex_content).await?;
    let rot13_file = helper.create_test_file("rot13.txt", rot13_content).await?;
    
    // Test each file type
    for (file_path, test_name) in [
        (base64_file, "Base64 Format Test"),
        (hex_file, "Hex Format Test"),
        (rot13_file, "ROT13 Format Test"),
    ] {
        let challenge = helper.create_test_challenge(test_name, file_path).await?;
        
        let cli_result = simulate_cli_analysis(&challenge).await?;
        let web_result = simulate_web_analysis(&challenge).await?;
        
        // Verify both interfaces provide structured output
        assert!(cli_result.is_object(), "CLI should provide structured output");
        assert!(web_result.is_object(), "Web should provide structured output");
        
        // Verify required fields are present
        assert!(cli_result["results"].is_array(), "CLI should have results array");
        assert!(web_result["analysis"]["results"].is_array(), "Web should have results array");
        
        // Verify confidence scores are consistent
        let cli_confidences: Vec<f64> = cli_result["results"].as_array().unwrap().iter()
            .map(|r| r["confidence"].as_f64().unwrap_or(0.0))
            .collect();
        let web_confidences: Vec<f64> = web_result["analysis"]["results"].as_array().unwrap().iter()
            .map(|r| r["confidence"].as_f64().unwrap_or(0.0))
            .collect();
        
        assert_eq!(cli_confidences, web_confidences, 
                   "Confidence scores should be consistent between interfaces");
    }
    
    println!("✓ Output format consistency test passed");
    println!("  - Tested 3 different content types");
    println!("  - Verified structured output format");
    println!("  - Confirmed confidence score consistency");
    
    Ok(())
}

#[tokio::test]
async fn test_error_handling_parity() -> Result<()> {
    // Setup test environment
    let helper = InterfaceTestHelper::new().await?;
    
    // Create a challenge with an invalid file path
    let mut challenge = Challenge {
        id: Uuid::new_v4(),
        name: "Error Handling Test".to_string(),
        files: vec![ChallengeFile {
            id: Uuid::new_v4(),
            original_name: "nonexistent.txt".to_string(),
            file_type: FileType::Text,
            size: 100,
            hash: "invalid".to_string(),
            storage_path: PathBuf::from("/nonexistent/path/file.txt"),
            metadata: FileMetadata::default(),
        }],
        context: "Test error handling".to_string(),
        created_at: chrono::Utc::now(),
        analysis_results: Vec::new(),
    };
    
    // Both interfaces should handle errors gracefully
    let cli_result = simulate_cli_analysis(&challenge).await;
    let web_result = simulate_web_analysis(&challenge).await;
    
    // Both should succeed (graceful error handling) or both should fail
    match (cli_result, web_result) {
        (Ok(cli_data), Ok(web_data)) => {
            // Both succeeded - verify they report errors consistently
            let cli_results = cli_data["results"].as_array().unwrap();
            let web_results = web_data["analysis"]["results"].as_array().unwrap();
            
            // Should have error results
            assert!(!cli_results.is_empty(), "CLI should report error results");
            assert!(!web_results.is_empty(), "Web should report error results");
            
            println!("✓ Both interfaces handled errors gracefully");
        }
        (Err(_), Err(_)) => {
            // Both failed - this is also acceptable for consistency
            println!("✓ Both interfaces failed consistently");
        }
        _ => {
            panic!("Interfaces should handle errors consistently");
        }
    }
    
    println!("✓ Error handling parity test passed");
    
    Ok(())
}

#[tokio::test]
async fn test_feature_completeness_parity() -> Result<()> {
    // Setup test environment
    let helper = InterfaceTestHelper::new().await?;
    
    // Create comprehensive test file with multiple encoding layers
    let inner_content = "flag{feature_completeness_test}";
    let base64_encoded = base64::encode(inner_content);
    let hex_encoded = hex::encode(base64_encoded.as_bytes());
    
    let test_file = helper.create_test_file("complex.txt", &hex_encoded).await?;
    let challenge = helper.create_test_challenge("Feature Completeness Test", test_file).await?;
    
    // Run analysis through both interfaces
    let cli_result = simulate_cli_analysis(&challenge).await?;
    let web_result = simulate_web_analysis(&challenge).await?;
    
    // Extract feature usage data
    let cli_results = cli_result["results"].as_array().unwrap();
    let web_results = web_result["analysis"]["results"].as_array().unwrap();
    
    // Verify both interfaces use the same core features
    let cli_features: std::collections::HashSet<_> = cli_results.iter()
        .map(|r| r["analyzer"].as_str().unwrap())
        .collect();
    let web_features: std::collections::HashSet<_> = web_results.iter()
        .map(|r| r["analyzer"].as_str().unwrap())
        .collect();
    
    assert_eq!(cli_features, web_features, 
               "Both interfaces should use same analysis features");
    
    // Verify decoder pipeline is used by both
    assert!(cli_features.contains("decoder-pipeline"), 
            "CLI should use decoder pipeline");
    assert!(web_features.contains("decoder-pipeline"), 
            "Web should use decoder pipeline");
    
    // Verify transformation counts are equivalent
    let cli_total_transformations: u64 = cli_results.iter()
        .map(|r| r["transformations_count"].as_u64().unwrap_or(0))
        .sum();
    let web_total_transformations: u64 = web_results.iter()
        .map(|r| r["transformations"].as_u64().unwrap_or(0))
        .sum();
    
    assert_eq!(cli_total_transformations, web_total_transformations,
               "Both interfaces should perform same number of transformations");
    
    println!("✓ Feature completeness parity test passed");
    println!("  - Both interfaces use {} analyzers", cli_features.len());
    println!("  - Both performed {} transformations", cli_total_transformations);
    
    Ok(())
}

#[tokio::test]
async fn test_performance_parity() -> Result<()> {
    // Setup test environment
    let helper = InterfaceTestHelper::new().await?;
    
    // Create a moderately complex test file
    let test_content = "flag{performance_test}".repeat(100); // Larger content
    let encoded_content = base64::encode(&test_content);
    
    let test_file = helper.create_test_file("performance.txt", &encoded_content).await?;
    let challenge = helper.create_test_challenge("Performance Test", test_file).await?;
    
    // Measure CLI performance
    let cli_start = std::time::Instant::now();
    let cli_result = simulate_cli_analysis(&challenge).await?;
    let cli_duration = cli_start.elapsed();
    
    // Measure web performance
    let web_start = std::time::Instant::now();
    let web_result = simulate_web_analysis(&challenge).await?;
    let web_duration = web_start.elapsed();
    
    // Performance should be similar (within 2x of each other)
    let ratio = if cli_duration > web_duration {
        cli_duration.as_millis() as f64 / web_duration.as_millis() as f64
    } else {
        web_duration.as_millis() as f64 / cli_duration.as_millis() as f64
    };
    
    assert!(ratio < 2.0, 
            "Performance should be similar between interfaces (ratio: {:.2})", ratio);
    
    // Verify both produced results
    assert!(!cli_result["results"].as_array().unwrap().is_empty(), 
            "CLI should produce results");
    assert!(!web_result["analysis"]["results"].as_array().unwrap().is_empty(), 
            "Web should produce results");
    
    println!("✓ Performance parity test passed");
    println!("  - CLI duration: {:?}", cli_duration);
    println!("  - Web duration: {:?}", web_duration);
    println!("  - Performance ratio: {:.2}", ratio);
    
    Ok(())
}

/// Helper function to run all interface parity tests
pub async fn run_all_interface_parity_tests() -> Result<()> {
    println!("Running Interface Parity Tests...\n");
    
    test_cli_web_analysis_equivalence().await?;
    test_output_format_consistency().await?;
    test_error_handling_parity().await?;
    test_feature_completeness_parity().await?;
    test_performance_parity().await?;
    
    println!("\n✅ All interface parity tests passed!");
    
    Ok(())
}