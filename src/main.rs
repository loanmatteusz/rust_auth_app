use actix_web::{ web, get, App, HttpResponse, HttpServer, Responder };
use dotenv::dotenv;
use sqlx::{Pool, Postgres};

mod database {
    pub mod postgres_connection;
}
mod service;

#[derive(Clone)]
pub struct AppState {
    pg_client: Pool<Postgres>,
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body("Hello World!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let _pool = database::postgres_connection::start_connection().await;

    println!("Server is running on port: 8080!");
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState {
                pg_client: _pool.clone(),
            }))
            .service(index)
            .configure(service::user::services::user_routes)
    }).bind(("127.0.0.1", 8080))?.run().await
}
