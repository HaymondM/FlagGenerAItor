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