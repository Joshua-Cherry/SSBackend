//! All API routes. Mounted under `/api` in main.rs, so `/health` here is
//! `/api/health` in the browser.
//!
//! | Method | Path                              | Who                    |
//! |--------|-----------------------------------|------------------------|
//! | GET    | /api/health                       | public                 |
//! | POST   | /api/auth/login                   | public                 |
//! | POST   | /api/auth/logout                  | any logged-in user     |
//! | GET    | /api/auth/me                      | any logged-in user     |
//! | POST   | /api/auth/password                | any logged-in user     |
//! | GET    | /api/incidents                    | any (scope by role)    |
//! | POST   | /api/incidents                    | any logged-in user     |
//! | GET    | /api/incidents/{id}               | owner, reviewer, admin |
//! | PATCH  | /api/incidents/{id}/status        | reviewer               |
//! | POST   | /api/incidents/{id}/comments      | reviewer, admin        |
//! | GET    | /api/admin/users                  | admin                  |
//! | POST   | /api/admin/users                  | admin                  |
//! | PATCH  | /api/admin/users/{id}             | admin (not on self)    |
//! | GET    | /api/admin/audit                  | admin                  |
//! | GET    | /api/admin/audit/verify           | admin                  |

mod account;
mod admin;
mod incidents;

use axum::{routing::get, Router};

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        // Public, unauthenticated status check (data class "Public").
        .route("/health", get(|| async { "ok" }))
        .merge(account::router())
        .merge(incidents::router())
        .merge(admin::router())
}
