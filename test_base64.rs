use ctf_core::analysis::decoder_pipeline::DecoderPipeline;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pipeline = DecoderPipeline::new();
    let base64_data = b"ZmxhZ3toZWxsb193b3JsZH0=";
    
    println!("Testing base64 decoding with: {}", String::from_utf8_lossy(base64_data));
    
    let results = pipeline.process(base64_data).await?;
    
    println!("Found {} transformation results:", results.len());
    for result in &results {
        println!("- {}: {} (success: {}, meaningful: {})", 
                 result.transformation.description(),
                 result.output_preview,
                 result.success,
                 result.meaningful);
    }
    
    // Also test recursive processing
    let recursive_results = pipeline.process_recursive(base64_data, 3).await?;
    println!("\nRecursive processing found {} results:", recursive_results.len());
    for result in &recursive_results {
        println!("- {}: {} (success: {}, meaningful: {})", 
                 result.transformation.description(),
                 result.output_preview,
                 result.success,
                 result.meaningful);
    }
    
    Ok(())
}