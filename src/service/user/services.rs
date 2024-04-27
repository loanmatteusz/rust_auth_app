use actix_web::{web, get, post, put, delete, HttpResponse, Responder};
use bcrypt::{DEFAULT_COST, hash, verify};
use jsonwebtoken::{decode, DecodingKey, EncodingKey, Header, Validation};
use serde_json::json;
use chrono::Utc;

use crate::service::user::models::{CreateUser, UpdateUser, User, LoginUser, JwtClaims, ValidateRoute};
use crate::AppState;


#[get("/users")]
async fn get_users(data: web::Data<AppState>) -> impl Responder {
    let result = sqlx::query!("SELECT * FROM users")
        .fetch_all(&data.pg_client)
        .await;

    match result {
        Ok(users) => HttpResponse::Ok().json(
            users
                .iter()
                .map(|user| User {
                    id: user.id,
                    name: user.name.clone(),
                    email: user.email.clone(),
                    password: user.password.clone(),
                })
                .collect::<Vec<User>>(),
        ),
        Err(_) => HttpResponse::InternalServerError().body("Error trying to get users from database."),
    }
}


#[post("/users")]
async fn create_user(data: web::Data<AppState>, user: web::Json<CreateUser>) -> impl Responder {
    let hashed = hash(&user.password, DEFAULT_COST).expect("Failed to hash password");

    if !(user.name != "") {
        return HttpResponse::BadRequest().json(serde_json::json!({ "message": "Name is required" }));
    }
    if !(user.email != "") {
        return HttpResponse::BadRequest().json(serde_json::json!({ "message": "Email is required" }));
    }
    if !(user.password != "") {
        return HttpResponse::BadRequest().json(serde_json::json!({ "message": "Password is required" }));
    }
    if !(hashed != user.password) {
        return HttpResponse::InternalServerError().body("Error hashing password!");
    }

    let result = sqlx::query!(
        "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *",
        user.name,
        user.email,
        hashed,
    ).fetch_one(&data.pg_client).await;

    match result {
        Ok(query_result) => {
            let user = User {
                id: query_result.id,
                name: query_result.name,
                email: query_result.email,
                password: query_result.password,
            };
            HttpResponse::Created().json(serde_json::json!({
                "message": "User Created",
                "data": user,
            }))
        }
        Err(err) => {
            if err.to_string().contains("users_email_key") {
                return HttpResponse::Conflict().json(serde_json::json!({
                    "message": "Email already exists"
                }));
            }
            println!("Error: {err}");
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": format!("Error, {}", err),
            }))
        }
    }
}


#[put("/users/{id}")]
async fn update_user(data: web::Data<AppState>, user: web::Json<UpdateUser>, id: web::Path<i32>) -> impl Responder {
    let result = sqlx::query!(
        "UPDATE users SET name = $1, email = $2, password = $3 WHERE id = $4",
        user.name,
        user.email,
        user.password,
        id.into_inner()
    ).execute(&data.pg_client).await;

    match result {
        Ok(_) => HttpResponse::Ok().body("User Updated"),
        Err(e) => {
            println!("Error: {}", e);
            HttpResponse::InternalServerError().body("Error")
        }
    }
}


#[delete("/users/{id}")]
async fn delete_user(data: web::Data<AppState>, id: web::Path<i32>) -> impl Responder {
    let result = sqlx::query!("DELETE FROM users WHERE id = $1", id.into_inner())
        .execute(&data.pg_client)
        .await;

    match result {
        Ok(_) => HttpResponse::Ok().body("User Deleted"),
        Err(e) => {
            println!("Error: {}", e);
            HttpResponse::InternalServerError().body("Error")
        }
    }
}


#[post("/login")]
async fn login(data: web::Data<AppState>, body: web::Json<LoginUser>) -> impl Responder {
    if body.email.is_empty() {
        return HttpResponse::NotFound().json(json!({
            "message": "Email not found",
        }));
    }
    if body.password.is_empty() {
        return HttpResponse::NotFound().json(json!({
            "message": "Password not found",
        }));
    }

    let user = sqlx::query!("SELECT * FROM users WHERE email = $1", body.email)
        .fetch_one(&data.pg_client).await;

    match user {
        Ok(user) => {
            let password_is_valid = verify(body.password.clone(), &user.password)
                .expect("Invalid credentials");
            if !password_is_valid {
                return HttpResponse::NotFound().json(json!({ "message": "Invalid credentials" }));
            }

            let claims = JwtClaims {
                sub: user.id,
                name: user.name,
                email: user.email,
                exp: (Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
            };

            let token = jsonwebtoken::encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(data.jwt.as_bytes()),
            ).expect("Something went wrong");
            // .unwrap(); // Não é uma boa prática usar unwrap, melhor tratar os errors

            HttpResponse::Ok().json(json!({ "data": token }))
        },
        Err(_) => HttpResponse::NotFound().json(json!({ "message": "Invalid credentials" })),
    }
}


#[post("/validate")]
async fn verify_token(data: web::Data<AppState>, body: web::Json<ValidateRoute>) -> impl Responder {
    let token = decode::<JwtClaims>(
        &body.token,
        &DecodingKey::from_secret(data.jwt.as_bytes()),
        &Validation::default(),
    );

    match token {
        Ok(token_created) => {
            HttpResponse::Ok().json(json!({
                "message": "token is valid",
                "is_valid": true,
                "data": token_created.claims,
            }))
        },
        Err(_) => {
            HttpResponse::BadRequest().json(json!({
                "message": "token is valid",
                "is_valid": false,
                "data": {},
            }))
        },
    }
}


pub fn user_routes(cfg: &mut web::ServiceConfig) {
    cfg
        .service(get_users)
        .service(create_user)
        .service(update_user)
        .service(delete_user)
        .service(login)
        .service(verify_token);
}
