//! Server-side input validation (SR-7).
//!
//! Every value from a request is checked here before it reaches the database.
//! The database repeats the key rules as CHECK constraints, so invalid data is
//! rejected even if a check here were missed. All SQL uses bind parameters
//! (SR-8), so these checks are about data quality, not injection.
//!
//! Output encoding is the frontend's job: it must insert user text with
//! `textContent`, never `innerHTML`.

use crate::{auth::Role, error::AppError};

fn bad(message: impl Into<String>) -> AppError {
    AppError::BadRequest(message.into())
}

/// 3-50 characters: letters, digits, '.', '_' or '-' (matches the DB constraint).
pub fn username(value: &str) -> Result<(), AppError> {
    let length_ok = (3..=50).contains(&value.chars().count());
    let chars_ok = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if length_ok && chars_ok {
        Ok(())
    } else {
        Err(bad(
            "Username must be 3-50 characters: letters, digits, '.', '_' or '-'.",
        ))
    }
}

/// OWASP ASVS: at least 12 characters, at least 64 allowed, no composition rules.
pub fn password(value: &str) -> Result<(), AppError> {
    let length = value.chars().count();
    if !(12..=128).contains(&length) {
        return Err(bad("Password must be 12-128 characters."));
    }
    Ok(())
}

/// Multi-line free text: trimmed, required, length-limited, and free of
/// control characters other than newline and tab.
pub fn text(value: &str, field: &str, max_chars: usize) -> Result<String, AppError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(bad(format!("{field} is required.")));
    }
    if value.chars().count() > max_chars {
        return Err(bad(format!(
            "{field} must be at most {max_chars} characters."
        )));
    }
    if value
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err(bad(format!(
            "{field} contains characters that are not allowed."
        )));
    }
    Ok(value.to_string())
}

/// Like `text`, but a single line (no line breaks or tabs).
pub fn single_line(value: &str, field: &str, max_chars: usize) -> Result<String, AppError> {
    let value = text(value, field, max_chars)?;
    if value.contains(['\n', '\r', '\t']) {
        return Err(bad(format!("{field} must be a single line.")));
    }
    Ok(value)
}

/// The three incident statuses (FR-8).
pub fn status(value: &str) -> Result<&'static str, AppError> {
    match value {
        "open" => Ok("open"),
        "under_review" => Ok("under_review"),
        "closed" => Ok("closed"),
        _ => Err(bad("Status must be open, under_review or closed.")),
    }
}

/// The three roles (FR-2).
pub fn role(value: &str) -> Result<Role, AppError> {
    Role::parse(value).ok_or_else(|| bad("Role must be user, reviewer or admin."))
}
