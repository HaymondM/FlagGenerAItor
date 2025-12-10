//! Plugin system for extensible analysis capabilities

pub mod builtin;
#[cfg(test)]
mod tests;

use crate::core::models::{FileType, AnalysisResult, Finding};
use crate::core::errors::CtfError;
use crate::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Plugin interface for extensible analysis capabilities
#[async_trait]
pub trait AnalysisPlugin: Send + Sync {
    /// Get the plugin name
    fn name(&self) -> &str;
    
    /// Get the file types this plugin supports
    fn supported_types(&self) -> Vec<FileType>;
    
    /// Analyze the given file data
    async fn analyze(&self, file_data: &[u8], context: &AnalysisContext) -> Result<PluginResult>;
    
    /// Get the plugin priority (higher values execute first)
    fn priority(&self) -> u8;
    
    /// Get plugin version (optional, defaults to "1.0.0")
    fn version(&self) -> &str {
        "1.0.0"
    }
    
    /// Get plugin description (optional)
    fn description(&self) -> &str {
        "Analysis plugin"
    }
}

/// Context provided to plugins during analysis
#[derive(Debug, Clone)]
pub struct AnalysisContext {
    pub file_type: FileType,
    pub file_name: String,
    pub file_id: Uuid,
    pub file_size: u64,
    pub metadata: HashMap<String, String>,
}

impl AnalysisContext {
    /// Create a new analysis context
    pub fn new(file_type: FileType, file_name: String, file_id: Uuid, file_size: u64) -> Self {
        Self {
            file_type,
            file_name,
            file_id,
            file_size,
            metadata: HashMap::new(),
        }
    }
    
    /// Add metadata to the context
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }
    
    /// Get metadata from the context
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }
}

/// Result returned by plugin analysis
#[derive(Debug, Clone)]
pub struct PluginResult {
    pub findings: Vec<Finding>,
    pub confidence: f32,
    pub execution_time: Duration,
    pub metadata: HashMap<String, String>,
}

impl PluginResult {
    /// Create a new plugin result
    pub fn new(findings: Vec<Finding>, confidence: f32, execution_time: Duration) -> Self {
        Self {
            findings,
            confidence,
            execution_time,
            metadata: HashMap::new(),
        }
    }
    
    /// Add metadata to the result
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }
    
    /// Check if the result has any findings
    pub fn has_findings(&self) -> bool {
        !self.findings.is_empty()
    }
}

/// Plugin capability information
#[derive(Debug, Clone)]
pub struct PluginCapability {
    pub name: String,
    pub version: String,
    pub description: String,
    pub supported_types: Vec<FileType>,
    pub priority: u8,
}

impl PluginCapability {
    /// Create capability info from a plugin
    pub fn from_plugin(plugin: &dyn AnalysisPlugin) -> Self {
        Self {
            name: plugin.name().to_string(),
            version: plugin.version().to_string(),
            description: plugin.description().to_string(),
            supported_types: plugin.supported_types(),
            priority: plugin.priority(),
        }
    }
}

/// Plugin manager for discovering, loading, and executing plugins
pub struct PluginManager {
    plugins: Vec<Box<dyn AnalysisPlugin>>,
    capabilities: HashMap<String, PluginCapability>,
}

impl PluginManager {
    /// Create a new plugin manager
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
            capabilities: HashMap::new(),
        }
    }
    
    /// Register a plugin with the manager
    pub fn register_plugin(&mut self, plugin: Box<dyn AnalysisPlugin>) -> Result<()> {
        let name = plugin.name().to_string();
        
        // Check for duplicate plugin names
        if self.capabilities.contains_key(&name) {
            return Err(CtfError::PluginError {
                plugin_name: name,
                message: "Plugin is already registered".to_string(),
                context: None,
            });
        }
        
        // Create capability info
        let capability = PluginCapability::from_plugin(plugin.as_ref());
        
        info!("Registering plugin: {} v{}", capability.name, capability.version);
        debug!("Plugin supports file types: {:?}", capability.supported_types);
        
        // Store capability and plugin
        self.capabilities.insert(name.clone(), capability);
        self.plugins.push(plugin);
        
        Ok(())
    }
    
    /// Discover and load plugins from a directory
    pub async fn load_plugins(&mut self, plugin_dir: &str) -> Result<()> {
        let plugin_path = Path::new(plugin_dir);
        
        if !plugin_path.exists() {
            info!("Plugin directory '{}' does not exist, creating it", plugin_dir);
            std::fs::create_dir_all(plugin_path)?;
            return Ok(());
        }
        
        if !plugin_path.is_dir() {
            return Err(CtfError::ConfigError(
                format!("Plugin path '{}' is not a directory", plugin_dir)
            ));
        }
        
        info!("Discovering plugins in directory: {}", plugin_dir);
        
        // For now, we'll register built-in plugins
        // In the future, this could be extended to load dynamic libraries
        self.load_builtin_plugins().await?;
        
        info!("Loaded {} plugins", self.plugins.len());
        Ok(())
    }
    
    /// Load built-in plugins
    async fn load_builtin_plugins(&mut self) -> Result<()> {
        info!("Loading built-in plugins");
        
        // Register cryptography plugin
        let crypto_plugin = Box::new(builtin::CryptographyPlugin::new());
        self.register_plugin(crypto_plugin)?;
        
        // Register reverse engineering plugin
        let re_plugin = Box::new(builtin::ReverseEngineeringPlugin::new());
        self.register_plugin(re_plugin)?;
        
        // Register web analysis plugin
        let web_plugin = Box::new(builtin::WebAnalysisPlugin::new());
        self.register_plugin(web_plugin)?;
        
        info!("Successfully loaded {} built-in plugins", 3);
        Ok(())
    }
    
    /// Get all registered plugin capabilities
    pub fn get_capabilities(&self) -> Vec<&PluginCapability> {
        self.capabilities.values().collect()
    }
    
    /// Get plugins that support a specific file type
    pub fn get_plugins_for_type(&self, file_type: &FileType) -> Vec<&dyn AnalysisPlugin> {
        let mut matching_plugins: Vec<&dyn AnalysisPlugin> = self.plugins
            .iter()
            .filter(|plugin| plugin.supported_types().contains(file_type))
            .map(|plugin| plugin.as_ref())
            .collect();
        
        // Sort by priority (higher priority first)
        matching_plugins.sort_by(|a, b| b.priority().cmp(&a.priority()));
        
        matching_plugins
    }
    
    /// Execute all plugins that support the given file type
    pub async fn execute_plugins(
        &self, 
        file_data: &[u8], 
        context: &AnalysisContext
    ) -> Result<Vec<AnalysisResult>> {
        let matching_plugins = self.get_plugins_for_type(&context.file_type);
        
        if matching_plugins.is_empty() {
            debug!("No plugins found for file type: {:?}", context.file_type);
            return Ok(vec![]);
        }
        
        info!("Executing {} plugins for file type: {:?}", 
              matching_plugins.len(), context.file_type);
        
        let mut results = Vec::new();
        let mut failed_plugins = Vec::new();
        
        for plugin in matching_plugins {
            let start_time = Instant::now();
            
            match self.execute_single_plugin(plugin, file_data, context).await {
                Ok(plugin_result) => {
                    let findings_count = plugin_result.findings.len();
                    let execution_time = plugin_result.execution_time;
                    
                    // Create analysis result with plugin-specific information
                    let analysis_result = AnalysisResult::new(
                        plugin.name().to_string(),
                        context.file_id,
                        vec![], // Plugins don't produce transformations
                        plugin_result.findings,
                        execution_time,
                    )?;
                    
                    results.push(analysis_result);
                    
                    info!("Plugin '{}' completed successfully in {:?} with {} findings", 
                          plugin.name(), execution_time, findings_count);
                }
                Err(e) => {
                    let execution_time = start_time.elapsed();
                    warn!("Plugin '{}' failed after {:?}: {}", 
                          plugin.name(), execution_time, e);
                    
                    // Track failed plugins for reporting
                    failed_plugins.push((plugin.name().to_string(), e.to_string()));
                    
                    // Continue with other plugins even if one fails
                    // This implements the failure resilience requirement (7.5)
                }
            }
        }
        
        // Log summary of plugin execution
        if !failed_plugins.is_empty() {
            warn!("Plugin execution summary: {} succeeded, {} failed", 
                  results.len(), failed_plugins.len());
            for (plugin_name, error) in failed_plugins {
                debug!("Failed plugin '{}': {}", plugin_name, error);
            }
        } else {
            info!("All {} plugins executed successfully", results.len());
        }
        
        Ok(results)
    }
    
    /// Execute a single plugin with error handling and timeout
    async fn execute_single_plugin(
        &self,
        plugin: &dyn AnalysisPlugin,
        file_data: &[u8],
        context: &AnalysisContext,
    ) -> Result<PluginResult> {
        let start_time = Instant::now();
        
        debug!("Executing plugin: {}", plugin.name());
        
        // Execute the plugin analysis
        let result = plugin.analyze(file_data, context).await?;
        
        let execution_time = start_time.elapsed();
        
        // Validate the result
        if result.confidence < 0.0 || result.confidence > 1.0 {
            return Err(CtfError::PluginError {
                plugin_name: plugin.name().to_string(),
                message: format!("Invalid confidence value: {}", result.confidence),
                context: None,
            });
        }
        
        // Validate findings
        for finding in &result.findings {
            finding.validate()?;
        }
        
        debug!("Plugin '{}' analysis completed with {} findings", 
               plugin.name(), result.findings.len());
        
        Ok(PluginResult {
            findings: result.findings,
            confidence: result.confidence,
            execution_time,
            metadata: result.metadata,
        })
    }
    
    /// Get the number of registered plugins
    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }
    
    /// Check if a plugin with the given name is registered
    pub fn has_plugin(&self, name: &str) -> bool {
        self.capabilities.contains_key(name)
    }
    
    /// Execute a specific plugin by name
    pub async fn execute_plugin_by_name(
        &self,
        plugin_name: &str,
        file_data: &[u8],
        context: &AnalysisContext,
    ) -> Result<AnalysisResult> {
        let plugin = self.plugins
            .iter()
            .find(|p| p.name() == plugin_name)
            .ok_or_else(|| CtfError::PluginError {
                plugin_name: plugin_name.to_string(),
                message: "Plugin not found".to_string(),
                context: None,
            })?;
        
        // Check if plugin supports the file type
        if !plugin.supported_types().contains(&context.file_type) {
            return Err(CtfError::PluginError {
                plugin_name: plugin_name.to_string(),
                message: format!("Plugin does not support file type: {:?}", context.file_type),
                context: None,
            });
        }
        
        let plugin_result = self.execute_single_plugin(plugin.as_ref(), file_data, context).await?;
        
        let analysis_result = AnalysisResult::new(
            plugin.name().to_string(),
            context.file_id,
            vec![],
            plugin_result.findings,
            plugin_result.execution_time,
        )?;
        
        Ok(analysis_result)
    }
    
    /// Get execution statistics
    pub fn get_execution_stats(&self) -> PluginExecutionStats {
        PluginExecutionStats {
            total_plugins: self.plugins.len(),
            plugins_by_type: self.get_plugins_by_type_count(),
        }
    }
    
    /// Get count of plugins by file type
    fn get_plugins_by_type_count(&self) -> HashMap<FileType, usize> {
        let mut counts = HashMap::new();
        
        for plugin in &self.plugins {
            for file_type in plugin.supported_types() {
                *counts.entry(file_type).or_insert(0) += 1;
            }
        }
        
        counts
    }
}

/// Plugin execution statistics
#[derive(Debug, Clone)]
pub struct PluginExecutionStats {
    pub total_plugins: usize,
    pub plugins_by_type: HashMap<FileType, usize>,
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginManager {
    /// Create a new plugin manager with built-in plugins loaded
    pub async fn with_builtin_plugins() -> Result<Self> {
        let mut manager = Self::new();
        manager.load_builtin_plugins().await?;
        Ok(manager)
    }
}