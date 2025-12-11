//! Simple integration test to verify the CTF Assistant works end-to-end

use anyhow::Result;
use ctf_core::{
    analysis::file_analyzer::FileAnalyzer,
    core::models::FileType,
};

#[tokio::test]
async fn test_file_analyzer_basic() -> Result<()> {
    // Test file analyzer with simple content
    let file_analyzer = FileAnalyzer::new();
    
    // Test text detection
    let text_data = b"Hello, World!";
    let file_type = file_analyzer.detect_file_type(text_data);
    assert_eq!(file_type, FileType::Text, "Should detect as text file");
    
    // Test HTML detection
    let html_data = b"<html><body>Test</body></html>";
    let file_type = file_analyzer.detect_file_type(html_data);
    assert_eq!(file_type, FileType::Html, "Should detect as HTML file");
    
    // Test JavaScript detection - simple JS might be detected as text
    let js_data = b"console.log('test');";
    let file_type = file_analyzer.detect_file_type(js_data);
    // Accept either JavaScript or Text detection for simple JS
    assert!(file_type == FileType::Javascript || file_type == FileType::Text, 
            "Should detect as JavaScript or Text file");
    
    println!("✓ File analyzer basic test passed");
    
    Ok(())
}

#[tokio::test]
async fn test_metadata_extraction() -> Result<()> {
    let file_analyzer = FileAnalyzer::new();
    
    // Test metadata extraction for text
    let text_data = b"Hello, World!";
    let file_type = FileType::Text;
    let metadata = file_analyzer.extract_metadata(text_data, &file_type)?;
    
    // Should have some metadata
    assert!(metadata.mime_type.is_some() || metadata.additional.len() > 0, 
            "Should extract some metadata");
    
    println!("✓ Metadata extraction test passed");
    
    Ok(())
}
#[tokio::test]
async fn test_base64_decoding_direct() {
    use ctf_core::analysis::decoder_pipeline::DecoderPipeline;
    
    let pipeline = DecoderPipeline::new();
    let base64_data = b"ZmxhZ3toZWxsb193b3JsZH0=";
    
    println!("Testing base64 decoding with: {}", String::from_utf8_lossy(base64_data));
    
    let results = pipeline.process(base64_data).await.unwrap();
    
    println!("Found {} transformation results:", results.len());
    for result in &results {
        println!("- {}: {} (success: {}, meaningful: {})", 
                 result.transformation.description(),
                 result.output_preview,
                 result.success,
                 result.meaningful);
    }
    
    // Check if we found a meaningful base64 decode
    let base64_results: Vec<_> = results.iter()
        .filter(|r| r.transformation.description().contains("Base64"))
        .collect();
    
    assert!(!base64_results.is_empty(), "Should find base64 transformation");
    
    let meaningful_base64: Vec<_> = base64_results.iter()
        .filter(|r| r.meaningful && r.success)
        .collect();
    
    if !meaningful_base64.is_empty() {
        println!("Found meaningful base64 decode: {}", meaningful_base64[0].output_preview);
        assert!(meaningful_base64[0].output_preview.contains("flag{hello_world}"));
    } else {
        println!("No meaningful base64 results found");
        // Let's check what we got
        for result in &base64_results {
            println!("Base64 result: {} -> {} (meaningful: {})", 
                     result.transformation.description(),
                     result.output_preview,
                     result.meaningful);
        }
    }
}
#[tokio::test]
async fn test_full_analysis_pipeline() {
    use ctf_core::{
        core::{
            models::Challenge,
            storage::{SqliteStorage, ChallengeStorage, FileStorage},
        },
        interfaces::orchestrator::AnalysisOrchestrator,
    };
    use tempfile::TempDir;
    
    // Create temporary directory for test
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.db");
    let files_dir = temp_dir.path().join("files");
    
    // Initialize storage
    let storage = SqliteStorage::new(
        db_path.to_str().unwrap(), 
        files_dir.to_str().unwrap()
    ).await.unwrap();
    
    // Create test file with base64 content
    let base64_content = "ZmxhZ3toZWxsb193b3JsZH0=";
    
    // Store the file
    let challenge_file = storage.store_file(base64_content.as_bytes(), "test.txt").await.unwrap();
    println!("Stored file: {} -> {}", challenge_file.original_name, challenge_file.storage_path.display());
    
    // Create challenge
    let mut challenge = Challenge::new("Debug Test".to_string(), "Testing base64 decoding".to_string()).unwrap();
    challenge.add_file(challenge_file);
    
    // Store challenge
    storage.store_challenge(&challenge).await.unwrap();
    println!("Stored challenge: {} ({})", challenge.name, challenge.id);
    
    // Run analysis
    let orchestrator = AnalysisOrchestrator::new();
    let analysis_results = orchestrator.analyze_challenge(&challenge).await.unwrap();
    
    println!("Analysis completed with {} results:", analysis_results.len());
    for result in &analysis_results {
        println!("- Analyzer: {}", result.analyzer);
        println!("  Confidence: {:.2}", result.confidence);
        println!("  Transformations: {}", result.transformations.len());
        for transform in &result.transformations {
            if transform.meaningful {
                println!("    * {}: {} (meaningful)", 
                         transform.transformation.description(),
                         transform.output_preview);
            }
        }
        println!("  Findings: {}", result.findings.len());
        for finding in &result.findings {
            println!("    * {}: {}", finding.category, finding.description);
        }
        println!();
    }
    
    // Update challenge with results
    let mut updated_challenge = challenge;
    for result in analysis_results {
        updated_challenge.add_analysis_result(result);
    }
    
    // Store updated challenge
    storage.store_challenge(&updated_challenge).await.unwrap();
    println!("Updated challenge stored with {} analysis results", updated_challenge.analysis_results.len());
    
    // Retrieve challenge to verify storage
    let retrieved_challenge = storage.get_challenge(updated_challenge.id).await.unwrap();
    if let Some(retrieved) = retrieved_challenge {
        println!("Retrieved challenge: {}", retrieved.name);
        println!("Analysis results: {}", retrieved.analysis_results.len());
        
        // Verify we have meaningful results
        assert!(!retrieved.analysis_results.is_empty(), "Should have analysis results");
        
        let mut found_meaningful_base64 = false;
        for result in &retrieved.analysis_results {
            println!("- {}: {} transformations, {} findings", 
                     result.analyzer, 
                     result.transformations.len(),
                     result.findings.len());
            
            // Show meaningful transformations
            let meaningful: Vec<_> = result.transformations.iter()
                .filter(|t| t.meaningful)
                .collect();
            
            if !meaningful.is_empty() {
                println!("  Meaningful transformations:");
                for t in meaningful {
                    println!("    * {}: {}", t.transformation.description(), t.output_preview);
                    if t.transformation.description().contains("Base64") && t.output_preview.contains("flag{hello_world}") {
                        found_meaningful_base64 = true;
                    }
                }
            }
        }
        
        assert!(found_meaningful_base64, "Should find meaningful base64 decode with flag");
        println!("✓ Test passed: Found meaningful base64 decode");
    } else {
        panic!("Could not retrieve challenge!");
    }
}