use anyhow::Result;
use axum::{
    response::Html,
    routing::get,
    Router,
};
use tracing::info;

pub async fn start_server(host: String, port: u16) -> Result<()> {
    info!("Starting web server on {}:{}", host, port);
    
    let app = Router::new()
        .route("/", get(dashboard));
    
    let bind_addr = format!("{}:{}", host, port);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    info!("Web server listening on http://{}", bind_addr);
    
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