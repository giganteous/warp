#![deny(warnings)]

#[macro_use]
extern crate diesel;

use std::env;
use warp::Filter;


/// Provides a RESTful web server managing some Todos.
///
/// API will be:
///
/// - `GET /todos`: return a JSON list of Todos.
/// - `POST /todos`: create a new Todo.
/// - `PUT /todos/:id`: update a specific Todo.
/// - `DELETE /todos/:id`: delete a specific Todo.
#[tokio::main]
async fn main() {
    if env::var_os("RUST_LOG").is_none() {
        // Set `RUST_LOG=todos=debug` to see debug logs,
        // this only shows access logs.
        env::set_var("RUST_LOG", "todos=info");
    }
    pretty_env_logger::init();

    let pool = db::pg_pool();

    let api = filters::todos(pool);

    // View access logs by setting `RUST_LOG=todos`.
    let routes = api.with(warp::log("todos"));
    // Start up the server...
    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}

mod filters {
    use super::handlers;
    use super::models::{ListOptions, NewTodo, Todo};
    use super::db::{Pool, Conn, PoolError};
    use warp::Filter;

    /// The 4 TODOs filters combined.
    pub fn todos(
        pool: Pool,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        todos_list(pool.clone())
            .or(todos_create(pool.clone()))
            .or(todos_update(pool.clone()))
            .or(todos_delete(pool))
    }

    /// GET /todos?offset=3&limit=5
    pub fn todos_list(
        pool: Pool,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path!("todos")
            .and(warp::get())
            .and(warp::query::<ListOptions>())
            .and(with_conn_from_pool(pool))
            .and_then(handlers::list_todos)
    }

    /// POST /todos with JSON body
    pub fn todos_create(
        pool: Pool,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path!("todos")
            .and(warp::post())
            .and(json_body_new())
            .and(with_conn_from_pool(pool))
            .and_then(handlers::create_todo)
    }

    /// PUT /todos/:id with JSON body
    pub fn todos_update(
        pool: Pool,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path!("todos" / i64)
            .and(warp::put())
            .and(json_body())
            .and(with_conn_from_pool(pool))
            .and_then(handlers::update_todo)
    }

    /// DELETE /todos/:id
    pub fn todos_delete(
        pool: Pool,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        // We'll make one of our endpoints admin-only to show how authentication filters are used
        let admin_only = warp::header::exact("authorization", "Bearer admin");

        warp::path!("todos" / i64)
            // It is important to put the auth check _after_ the path filters.
            // If we put the auth check before, the request `PUT /todos/invalid-string`
            // would try this filter and reject because the authorization header doesn't match,
            // rather because the param is wrong for that other path.
            .and(admin_only)
            .and(warp::delete())
            .and(with_conn_from_pool(pool))
            .and_then(handlers::delete_todo)
    }

    fn with_conn_from_pool(pool: Pool) -> impl Filter<Extract = (Conn,), Error = warp::reject::Rejection> + Clone {
        warp::any().map(move || pool.clone()).and_then(|pool: Pool| async move {
            match pool.get() {
                Ok(conn) => Ok(conn),
                Err(_) => Err(warp::reject::custom(PoolError)),
            }
        })
    }

    fn json_body() -> impl Filter<Extract = (Todo,), Error = warp::Rejection> + Clone {
        // When accepting a body, we want a JSON body
        // (and to reject huge payloads)...
        warp::body::content_length_limit(1024 * 16).and(warp::body::json())
    }

    fn json_body_new() -> impl Filter<Extract = (NewTodo,), Error = warp::Rejection> + Clone {
        // do not accept the 'id' key
        warp::body::content_length_limit(1024 * 16).and(warp::body::json())
    }
}

/// These are our API handlers, the ends of each filter chain.
/// Notice how thanks to using `Filter::and`, we can define a function
/// with the exact arguments we'd expect from each filter in the chain.
/// No tuples are needed, it's auto flattened for the functions.
mod handlers {
    use super::models::{Todo, NewTodo, ListOptions};
    use super::db::Conn;
    use super::schema::todos;
    use std::convert::Infallible;
    use diesel::prelude::*;
    use warp::http::StatusCode;

    pub async fn list_todos(opts: ListOptions, conn: Conn) -> Result<impl warp::Reply, Infallible> {
        // Just return a JSON array of todos, applying the limit and offset.
        let result = todos::table
            .offset(opts.offset.unwrap_or(0))
            .limit(opts.limit.unwrap_or(std::i64::MAX))
            .load::<Todo>(&conn).expect("the select to succeed");
        Ok(warp::reply::json(&result))
    }

    pub async fn create_todo(create: NewTodo, conn: Conn) -> Result<impl warp::Reply, Infallible> {
        log::debug!("create_todo: {:?}", create);

        match diesel::insert_into(todos::table)
            .values(create)
            .execute(&conn) {
                // return `201 Created`.
                Ok(_) => Ok(StatusCode::CREATED),
                Err(e) => {
                    log::warn!("    -> error: {}", e);
                    Ok(StatusCode::INTERNAL_SERVER_ERROR)
                },
        }
    }

    pub async fn update_todo(id: i64, update: Todo, conn: Conn) -> Result<impl warp::Reply, Infallible> {
        log::debug!("update_todo: id={}, todo={:?}", id, update);

        if update.id != id {
            log::info!("one should not update the primary key");
            return Ok(StatusCode::BAD_REQUEST)
        }

        match diesel::update(todos::table).set(&update).execute(&conn) {
            Ok(u) if u > 0 => Ok(StatusCode::OK),
            Ok(_) => {
                log::debug!("    -> todo id not found!");
                Ok(StatusCode::NOT_FOUND)
            },
            Err(e) => {
                log::warn!("    -> error: {}", e);
                Ok(StatusCode::INTERNAL_SERVER_ERROR)
            },
        }
    }

    pub async fn delete_todo(id: i64, conn: Conn) -> Result<impl warp::Reply, Infallible> {
        log::debug!("delete_todo: id={}", id);

        match diesel::delete(todos::table.filter(todos::id.eq(id))).execute(&conn) {
            // respond with a `204 No Content`, which means successful,
            // yet no body expected...
            Ok(d) if d > 0 => Ok(StatusCode::NO_CONTENT),
            Ok(_) => {
                log::debug!("    -> todo id not found!");
                Ok(StatusCode::NOT_FOUND)
            },
            Err(e) => {
                log::warn!("    -> error: {}", e);
                Ok(StatusCode::INTERNAL_SERVER_ERROR)
            },
        }
    }
}

mod schema {
    table! {
        todos (id) {
            id -> Int8,
            text -> Varchar,
            completed -> Bool,
        }
    }
}

mod db {
    use diesel::r2d2; //::{self,ConnectionManager,Pool};
    use warp::reject::Reject;

    /// the pool with database connections
    pub type Pool = r2d2::Pool<r2d2::ConnectionManager<diesel::PgConnection>>;

    /// a single database connection handed by the pool
    pub type Conn = r2d2::PooledConnection<r2d2::ConnectionManager<diesel::PgConnection>>;

    pub fn pg_pool() -> Pool {
        let manager = r2d2::ConnectionManager::<diesel::PgConnection>::new("postgres://ubuntu:1234@localhost/petrol");
        r2d2::Pool::builder()
            .max_size(2)
            .min_idle(Some(0))
            .build(manager).expect("Postgres connection could not be established")
    }

    #[derive(Debug)]
    pub(crate) struct PoolError;
    impl Reject for PoolError {}
}

mod models {
    use super::schema::todos;
    use serde_derive::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize, Clone, Queryable, Identifiable, AsChangeset)]
    pub struct Todo {
        pub id: i64,
        pub text: String,
        pub completed: bool,
    }

    #[derive(Debug, Deserialize, Insertable)]
    #[table_name = "todos"]
    pub struct NewTodo {
        pub text: String,
        pub completed: bool,
    }

    // The query parameters for list_todos.
    #[derive(Debug, Deserialize)]
    pub struct ListOptions {
        pub offset: Option<i64>,
        pub limit: Option<i64>,
    }
}

