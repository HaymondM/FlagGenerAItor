use anyhow::Result;
use axum::{
    response::Html,
    routing::get,
    Router,
};
use tracing::info;

pub async fn start_server(port: u16) -> Result<()> {
    info!("Starting web server on port {}", port);
    
    let app = Router::new()
        .route("/", get(dashboard));
    
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    info!("Web server listening on http://0.0.0.0:{}", port);
    
    axum::serve(listener, app).await?;
    
    Ok(())
}

async fn dashboard() -> Html<&'static str> {
    Html(r#"
    <!DOCTYPE html>
    <html>
    <head>
        <title>CTF Assistant</title>
    </head>
    <body>
        <h1>CTF AI Assistant</h1>
        <p>Web interface will be implemented in future tasks</p>
    </body>
    </html>
    "#)
}