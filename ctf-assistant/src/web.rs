use anyhow::Result;
use axum::{
    extract::{Multipart, Path, Query, State},
    http::StatusCode,
    response::{Html, Json},
    routing::{get, post},
    Router,
};
use ctf_core::{
    core::{
        models::{Challenge, AnalysisContext, HintRequest, HintResponse},
        storage::{SqliteStorage, ChallengeStorage, FileStorage},
    },
    interfaces::{
        orchestrator::AnalysisOrchestrator,
        ai_integration::HintGenerator,
    },
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::fs;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    services::ServeDir,
    trace::TraceLayer,
};
use tracing::{info, error, warn};
use uuid::Uuid;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<SqliteStorage>,
    pub orchestrator: Arc<AnalysisOrchestrator>,
    pub hint_generator: Arc<HintGenerator>,
}

/// File upload response
#[derive(Serialize)]
pub struct UploadResponse {
    pub success: bool,
    pub challenge_id: Option<Uuid>,
    pub message: String,
}

/// Analysis request
#[derive(Deserialize)]
pub struct AnalysisRequest {
    pub challenge_id: Uuid,
    pub user_query: Option<String>,
}

/// Analysis response
#[derive(Serialize)]
pub struct AnalysisResponse {
    pub success: bool,
    pub challenge: Option<Challenge>,
    pub hints: Option<HintResponse>,
    pub message: String,
}

/// History query parameters
#[derive(Deserialize)]
pub struct HistoryQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// History response
#[derive(Serialize)]
pub struct HistoryResponse {
    pub challenges: Vec<Challenge>,
    pub total: usize,
}

pub async fn start_server(host: String, port: u16) -> Result<()> {
    info!("Starting web server on {}:{}", host, port);
    
    // Initialize storage
    let storage = Arc::new(
        SqliteStorage::new("./data/ctf_assistant.db", "./data/files").await?
    );
    
    // Initialize components
    let orchestrator = Arc::new(AnalysisOrchestrator::new());
    let hint_generator = Arc::new(HintGenerator::new());
    
    let app_state = AppState {
        storage,
        orchestrator,
        hint_generator,
    };
    
    // Create static files directory if it doesn't exist
    fs::create_dir_all("./static").await?;
    
    let app = Router::new()
        // Dashboard routes
        .route("/", get(dashboard))
        .route("/dashboard", get(dashboard))
        .route("/results", get(results_page))
        
        // API routes
        .route("/api/upload", post(upload_file))
        .route("/api/analyze/:challenge_id", post(analyze_challenge))
        .route("/api/challenges", get(list_challenges))
        .route("/api/challenges/:challenge_id", get(get_challenge))
        .route("/api/challenges/:challenge_id", axum::routing::delete(delete_challenge))
        .route("/api/hint", post(generate_hint))
        
        // Static file serving
        .nest_service("/static", ServeDir::new("./static"))
        
        // Add middleware
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CorsLayer::permissive())
        )
        .with_state(app_state);
    
    let bind_addr = format!("{}:{}", host, port);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    info!("Web server listening on http://{}", bind_addr);
    
    axum::serve(listener, app).await?;
    
    Ok(())
}

/// Dashboard HTML page
async fn dashboard() -> Result<Html<String>, StatusCode> {
    match fs::read_to_string("./static/dashboard.html").await {
        Ok(content) => Ok(Html(content)),
        Err(_) => {
            // Fallback HTML if file doesn't exist
            Ok(Html(r#"
<!DOCTYPE html>
<html>
<head>
    <title>CTF Assistant</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; }
        h1 { color: #333; text-align: center; }
        .error { color: #e53e3e; text-align: center; padding: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚩 CTF AI Assistant</h1>
        <div class="error">
            Dashboard is loading... Please ensure the static files are properly deployed.
        </div>
    </div>
</body>
</html>
            "#.to_string()))
        }
    }
}

/// Results page HTML
async fn results_page() -> Result<Html<String>, StatusCode> {
    match fs::read_to_string("./static/results.html").await {
        Ok(content) => Ok(Html(content)),
        Err(_) => {
            // Fallback HTML if file doesn't exist
            Ok(Html(r#"
<!DOCTYPE html>
<html>
<head>
    <title>Challenge Results - CTF Assistant</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; }
        h1 { color: #333; text-align: center; }
        .error { color: #e53e3e; text-align: center; padding: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚩 Challenge Results</h1>
        <div class="error">
            Results page is loading... Please ensure the static files are properly deployed.
        </div>
        <a href="/">← Back to Dashboard</a>
    </div>
</body>
</html>
            "#.to_string()))
        }
    }
}

/// Handle file upload
async fn upload_file(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<UploadResponse>, StatusCode> {
    let mut challenge_name = String::new();
    let mut challenge_context = String::new();
    let mut uploaded_files = Vec::new();
    
    // Process multipart form data
    while let Some(field) = multipart.next_field().await.map_err(|_| StatusCode::BAD_REQUEST)? {
        let name = field.name().unwrap_or("").to_string();
        
        match name.as_str() {
            "challenge_name" => {
                challenge_name = field.text().await.map_err(|_| StatusCode::BAD_REQUEST)?;
            }
            "challenge_context" => {
                challenge_context = field.text().await.map_err(|_| StatusCode::BAD_REQUEST)?;
            }
            "files" => {
                let filename = field.file_name().unwrap_or("unknown").to_string();
                let data = field.bytes().await.map_err(|_| StatusCode::BAD_REQUEST)?;
                
                // Store file using storage layer
                match state.storage.store_file(&data, &filename).await {
                    Ok(challenge_file) => {
                        uploaded_files.push(challenge_file);
                        info!("Uploaded file: {} ({} bytes)", filename, data.len());
                    }
                    Err(e) => {
                        error!("Failed to store file {}: {}", filename, e);
                        return Ok(Json(UploadResponse {
                            success: false,
                            challenge_id: None,
                            message: format!("Failed to store file {}: {}", filename, e),
                        }));
                    }
                }
            }
            _ => {
                warn!("Unknown form field: {}", name);
            }
        }
    }
    
    // Validate required fields
    if challenge_name.trim().is_empty() {
        return Ok(Json(UploadResponse {
            success: false,
            challenge_id: None,
            message: "Challenge name is required".to_string(),
        }));
    }
    
    if uploaded_files.is_empty() {
        return Ok(Json(UploadResponse {
            success: false,
            challenge_id: None,
            message: "At least one file is required".to_string(),
        }));
    }
    
    // Create challenge
    let mut challenge = Challenge::new(challenge_name, challenge_context)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Add files to challenge
    for file in uploaded_files {
        challenge.add_file(file);
    }
    
    // Store challenge
    match state.storage.store_challenge(&challenge).await {
        Ok(_) => {
            info!("Created challenge: {} ({})", challenge.name, challenge.id);
            Ok(Json(UploadResponse {
                success: true,
                challenge_id: Some(challenge.id),
                message: "Challenge created successfully".to_string(),
            }))
        }
        Err(e) => {
            error!("Failed to store challenge: {}", e);
            Ok(Json(UploadResponse {
                success: false,
                challenge_id: None,
                message: format!("Failed to store challenge: {}", e),
            }))
        }
    }
}

/// Analyze a challenge
async fn analyze_challenge(
    State(state): State<AppState>,
    Path(challenge_id): Path<Uuid>,
) -> Result<Json<AnalysisResponse>, StatusCode> {
    // Get challenge from storage
    let challenge = match state.storage.get_challenge(challenge_id).await {
        Ok(Some(challenge)) => challenge,
        Ok(None) => {
            return Ok(Json(AnalysisResponse {
                success: false,
                challenge: None,
                hints: None,
                message: "Challenge not found".to_string(),
            }));
        }
        Err(e) => {
            error!("Failed to get challenge {}: {}", challenge_id, e);
            return Ok(Json(AnalysisResponse {
                success: false,
                challenge: None,
                hints: None,
                message: format!("Failed to get challenge: {}", e),
            }));
        }
    };
    
    // Run analysis using orchestrator
    match state.orchestrator.analyze_challenge(&challenge).await {
        Ok(analysis_results) => {
            // Update challenge with analysis results
            let mut updated_challenge = challenge;
            for result in analysis_results {
                updated_challenge.add_analysis_result(result);
            }
            
            // Store updated challenge
            if let Err(e) = state.storage.store_challenge(&updated_challenge).await {
                error!("Failed to store analysis results: {}", e);
            }
            
            info!("Analyzed challenge: {} ({})", updated_challenge.name, updated_challenge.id);
            Ok(Json(AnalysisResponse {
                success: true,
                challenge: Some(updated_challenge),
                hints: None,
                message: "Analysis completed successfully".to_string(),
            }))
        }
        Err(e) => {
            error!("Failed to analyze challenge {}: {}", challenge_id, e);
            Ok(Json(AnalysisResponse {
                success: false,
                challenge: Some(challenge),
                hints: None,
                message: format!("Analysis failed: {}", e),
            }))
        }
    }
}

/// Generate hints for a challenge
async fn generate_hint(
    State(state): State<AppState>,
    Json(request): Json<AnalysisRequest>,
) -> Result<Json<AnalysisResponse>, StatusCode> {
    // Get challenge from storage
    let challenge = match state.storage.get_challenge(request.challenge_id).await {
        Ok(Some(challenge)) => challenge,
        Ok(None) => {
            return Ok(Json(AnalysisResponse {
                success: false,
                challenge: None,
                hints: None,
                message: "Challenge not found".to_string(),
            }));
        }
        Err(e) => {
            error!("Failed to get challenge {}: {}", request.challenge_id, e);
            return Ok(Json(AnalysisResponse {
                success: false,
                challenge: None,
                hints: None,
                message: format!("Failed to get challenge: {}", e),
            }));
        }
    };
    
    // Build analysis context from challenge results
    let mut context = AnalysisContext::new();
    for file in &challenge.files {
        context.add_file_type(file.file_type.clone());
    }
    
    for result in &challenge.analysis_results {
        for transformation in &result.transformations {
            context.add_transformation(transformation.transformation.clone());
        }
        for finding in &result.findings {
            context.add_finding(finding.clone());
        }
    }
    
    // Get conversation history
    let conversation_history = match state.storage.get_hint_history(request.challenge_id).await {
        Ok(history) => history,
        Err(e) => {
            warn!("Failed to get hint history: {}", e);
            Vec::new()
        }
    };
    
    // Create hint request
    let user_query = request.user_query.unwrap_or_else(|| "Please provide hints for this challenge".to_string());
    let hint_request = match HintRequest::new(
        request.challenge_id,
        user_query,
        context,
        conversation_history,
    ) {
        Ok(req) => req,
        Err(e) => {
            error!("Failed to create hint request: {}", e);
            return Ok(Json(AnalysisResponse {
                success: false,
                challenge: Some(challenge),
                hints: None,
                message: format!("Failed to create hint request: {}", e),
            }));
        }
    };
    
    // Generate hints
    match state.hint_generator.generate_hints(&hint_request).await {
        Ok(hints) => {
            // Store hint exchange in history
            let exchange = ctf_core::core::models::HintExchange::new(
                hint_request.user_query.clone(),
                hints.clone(),
            );
            
            if let Err(e) = state.storage.store_hint_exchange(request.challenge_id, &exchange).await {
                warn!("Failed to store hint exchange: {}", e);
            }
            
            info!("Generated hints for challenge: {}", request.challenge_id);
            Ok(Json(AnalysisResponse {
                success: true,
                challenge: Some(challenge),
                hints: Some(hints),
                message: "Hints generated successfully".to_string(),
            }))
        }
        Err(e) => {
            error!("Failed to generate hints: {}", e);
            Ok(Json(AnalysisResponse {
                success: false,
                challenge: Some(challenge),
                hints: None,
                message: format!("Failed to generate hints: {}", e),
            }))
        }
    }
}

/// List challenges with pagination
async fn list_challenges(
    State(state): State<AppState>,
    Query(params): Query<HistoryQuery>,
) -> Result<Json<HistoryResponse>, StatusCode> {
    match state.storage.list_challenges_filtered(params.limit, params.offset).await {
        Ok(challenges) => {
            let total = challenges.len();
            Ok(Json(HistoryResponse {
                challenges,
                total,
            }))
        }
        Err(e) => {
            error!("Failed to list challenges: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Get a specific challenge
async fn get_challenge(
    State(state): State<AppState>,
    Path(challenge_id): Path<Uuid>,
) -> Result<Json<Challenge>, StatusCode> {
    match state.storage.get_challenge(challenge_id).await {
        Ok(Some(challenge)) => Ok(Json(challenge)),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            error!("Failed to get challenge {}: {}", challenge_id, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Delete a challenge
async fn delete_challenge(
    State(state): State<AppState>,
    Path(challenge_id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    match state.storage.delete_challenge(challenge_id).await {
        Ok(_) => {
            info!("Deleted challenge: {}", challenge_id);
            Ok(StatusCode::NO_CONTENT)
        }
        Err(e) => {
            error!("Failed to delete challenge {}: {}", challenge_id, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}