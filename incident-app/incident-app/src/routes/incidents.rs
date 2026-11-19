//! Incidents and comments (FR-6 to FR-10).
//!
//! Who sees what:
//! - user:     only incidents they submitted
//! - reviewer: every incident that is not closed (FR-7), plus their own
//! - admin:    every incident, any status (FR-10)
//!
//! An incident outside the caller's scope is reported as "not found" rather
//! than "forbidden", so its existence is not revealed.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, patch, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    audit,
    auth::{AuthUser, Role},
    error::{AppError, AppJson},
    validate, AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/incidents", get(list).post(create))
        .route("/incidents/{id}", get(detail))
        .route("/incidents/{id}/status", patch(update_status))
        .route("/incidents/{id}/comments", post(add_comment))
}

/// List view: no description (data class "Sensitive"), only title and status
/// (class "Internal"). The description is returned only by the detail endpoint.
#[derive(Serialize, sqlx::FromRow)]
struct IncidentSummary {
    id: i64,
    title: String,
    status: String,
    version: i32,
    created_by: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Serialize, sqlx::FromRow)]
struct IncidentDetail {
    id: i64,
    title: String,
    description: String,
    status: String,
    /// Send this back when changing the status (optimistic locking, NFR-5).
    version: i32,
    created_by_id: i64,
    created_by: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Serialize, sqlx::FromRow)]
struct CommentView {
    id: i64,
    author: String,
    body: String,
    created_at: DateTime<Utc>,
}

#[derive(Deserialize)]
struct ListParams {
    /// Optional filter: open, under_review or closed.
    status: Option<String>,
}

/// GET /api/incidents?status=open
async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<IncidentSummary>>, AppError> {
    let status = params.status.as_deref().map(validate::status).transpose()?;
    // Scope by role (FR-7, FR-10).
    let only_owner = (user.role == Role::User).then_some(user.id);
    let hide_closed = user.role == Role::Reviewer;

    let rows: Vec<IncidentSummary> = sqlx::query_as(
        "SELECT i.id, i.title, i.status, i.version, u.username AS created_by,
                i.created_at, i.updated_at
           FROM incidents i
           JOIN users u ON u.id = i.created_by
          WHERE ($1::bigint IS NULL OR i.created_by = $1)
            AND (NOT $2 OR i.status <> 'closed' OR i.created_by = $4)
            AND ($3::text IS NULL OR i.status = $3)
          ORDER BY i.created_at DESC
          LIMIT 500",
    )
    .bind(only_owner)
    .bind(hide_closed)
    .bind(status)
    .bind(user.id)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(rows))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewIncident {
    title: String,
    description: String,
}

/// POST /api/incidents  `{ "title": "...", "description": "..." }`  (FR-6)
async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    AppJson(req): AppJson<NewIncident>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let title = validate::single_line(&req.title, "Title", 200)?;
    let description = validate::text(&req.description, "Description", 10_000)?;

    let mut tx = state.db.begin().await?;
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO incidents (title, description, created_by)
         VALUES ($1, $2, $3)
         RETURNING id",
    )
    .bind(&title)
    .bind(&description)
    .bind(user.id)
    .fetch_one(&mut *tx)
    .await?;
    audit::record(
        &mut tx,
        Some(user.id),
        audit::INCIDENT_CREATED,
        "incident",
        Some(id),
    )
    .await?;
    tx.commit().await?;

    Ok((StatusCode::CREATED, Json(json!({ "id": id }))))
}

/// GET /api/incidents/{id} - the incident with its description and comments.
async fn detail(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    let incident: IncidentDetail = sqlx::query_as(
        "SELECT i.id, i.title, i.description, i.status, i.version,
                i.created_by AS created_by_id, u.username AS created_by,
                i.created_at, i.updated_at
           FROM incidents i
           JOIN users u ON u.id = i.created_by
          WHERE i.id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)?;

    if !can_view(&user, incident.created_by_id, &incident.status) {
        tracing::warn!(
            user_id = user.id,
            incident_id = id,
            "blocked access to incident outside scope"
        );
        return Err(AppError::NotFound);
    }

    let comments: Vec<CommentView> = sqlx::query_as(
        "SELECT c.id, u.username AS author, c.body, c.created_at
           FROM comments c
           JOIN users u ON u.id = c.author_id
          WHERE c.incident_id = $1
          ORDER BY c.created_at",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(json!({ "incident": incident, "comments": comments })))
}

fn can_view(user: &AuthUser, created_by: i64, status: &str) -> bool {
    match user.role {
        Role::Admin => true,
        Role::Reviewer => status != "closed" || created_by == user.id,
        Role::User => created_by == user.id,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusChange {
    status: String,
    /// The `version` the reviewer saw; rejected if someone changed it since.
    version: i32,
}

/// PATCH /api/incidents/{id}/status  `{ "status": "under_review", "version": 1 }`  (FR-8)
async fn update_status(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
    AppJson(req): AppJson<StatusChange>,
) -> Result<Json<Value>, AppError> {
    user.require(&[Role::Reviewer])?;
    let status = validate::status(&req.status)?;

    let mut tx = state.db.begin().await?;
    // Optimistic locking (NFR-5): only succeeds if nobody changed it meanwhile.
    let updated: Option<(i32,)> = sqlx::query_as(
        "UPDATE incidents
            SET status = $1, version = version + 1, updated_at = now()
          WHERE id = $2 AND version = $3
          RETURNING version",
    )
    .bind(status)
    .bind(id)
    .bind(req.version)
    .fetch_optional(&mut *tx)
    .await?;

    let Some((new_version,)) = updated else {
        let exists: Option<(i64,)> = sqlx::query_as("SELECT id FROM incidents WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
        return Err(match exists {
            Some(_) => AppError::Conflict(
                "This incident was changed by someone else. Refresh and try again.".to_string(),
            ),
            None => AppError::NotFound,
        });
    };

    audit::record(
        &mut tx,
        Some(user.id),
        audit::STATUS_CHANGED,
        "incident",
        Some(id),
    )
    .await?;
    tx.commit().await?;

    Ok(Json(
        json!({ "id": id, "status": status, "version": new_version }),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewComment {
    body: String,
}

/// POST /api/incidents/{id}/comments  `{ "body": "..." }`  (FR-9)
async fn add_comment(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
    AppJson(req): AppJson<NewComment>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    user.require(&[Role::Reviewer, Role::Admin])?;
    let body = validate::text(&req.body, "Comment", 5_000)?;

    let mut tx = state.db.begin().await?;
    let exists: Option<(i64,)> = sqlx::query_as("SELECT id FROM incidents WHERE id = $1")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
    if exists.is_none() {
        return Err(AppError::NotFound);
    }

    let (comment_id,): (i64,) = sqlx::query_as(
        "INSERT INTO comments (incident_id, author_id, body)
         VALUES ($1, $2, $3)
         RETURNING id",
    )
    .bind(id)
    .bind(user.id)
    .bind(&body)
    .fetch_one(&mut *tx)
    .await?;
    audit::record(
        &mut tx,
        Some(user.id),
        audit::COMMENT_CREATED,
        "comment",
        Some(comment_id),
    )
    .await?;
    tx.commit().await?;

    Ok((StatusCode::CREATED, Json(json!({ "id": comment_id }))))
}
