//! Storage utilities and database interfaces

use crate::core::models::*;
use crate::Result;
use uuid::Uuid;

/// Trait for challenge storage operations
pub trait ChallengeStorage {
    async fn store_challenge(&self, challenge: &Challenge) -> Result<()>;
    async fn get_challenge(&self, id: Uuid) -> Result<Option<Challenge>>;
    async fn list_challenges(&self) -> Result<Vec<Challenge>>;
    async fn delete_challenge(&self, id: Uuid) -> Result<()>;
}

/// Trait for file storage operations
pub trait FileStorage {
    async fn store_file(&self, file_data: &[u8], original_name: &str) -> Result<ChallengeFile>;
    async fn get_file(&self, id: Uuid) -> Result<Option<Vec<u8>>>;
    async fn delete_file(&self, id: Uuid) -> Result<()>;
}

/// Placeholder implementation - will be implemented in future tasks
pub struct SqliteStorage;

impl SqliteStorage {
    pub fn new() -> Self {
        Self
    }
}