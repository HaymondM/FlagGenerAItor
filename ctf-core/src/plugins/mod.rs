//! Plugin system for extensible analysis capabilities

use crate::core::models::{FileType, AnalysisResult};
use crate::Result;
use async_trait::async_trait;

#[async_trait]
pub trait AnalysisPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn supported_types(&self) -> Vec<FileType>;
    async fn analyze(&self, file_data: &[u8], context: &AnalysisContext) -> Result<PluginResult>;
    fn priority(&self) -> u8;
}

pub struct AnalysisContext {
    pub file_type: FileType,
    pub file_name: String,
}

pub struct PluginResult {
    pub findings: Vec<crate::core::models::Finding>,
    pub confidence: f32,
}

pub struct PluginManager {
    plugins: Vec<Box<dyn AnalysisPlugin>>,
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }
    
    /// Discover and load plugins from directory
    pub async fn load_plugins(&mut self, _plugin_dir: &str) -> Result<()> {
        // TODO: Implement plugin discovery in future tasks
        Ok(())
    }
    
    /// Execute plugins for given file type
    pub async fn execute_plugins(&self, file_data: &[u8], file_type: FileType) -> Result<Vec<AnalysisResult>> {
        // TODO: Implement plugin execution in future tasks
        Ok(vec![])
    }
}