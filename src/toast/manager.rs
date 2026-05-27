use crate::error::{AppError, Result};
use serde::Deserialize;
use serde_json::Value;

/// A toast notification to display.
#[derive(Debug, Deserialize)]
pub struct ToastNotification {
    pub title: Option<String>,
    pub body: Option<String>,
    /// Deduplication tag (replaces existing toast with same tag).
    pub tag: Option<String>,
    /// Optional absolute path to an image (e.g. `C:\path\to\img.png`).
    pub image_path: Option<String>,
    /// Optional action buttons.
    #[serde(default)]
    pub actions: Vec<ToastAction>,
}

/// A button/action on a toast notification.
#[derive(Debug, Deserialize)]
pub struct ToastAction {
    pub text: String,
    /// Arguments passed back when clicked (daemon forwards to .NET).
    pub arguments: String,
}

/// Toast Manager — wrapper around Windows Toast Notifications.
///
/// On non-Windows platforms, this is a no-op stub.
pub struct ToastManager {
    app_id: String,
}

impl ToastManager {
    /// Create a new ToastManager with the given AppUserModelId.
    ///
    /// The `app_id` must match the .NET application's AppUserModelId
    /// for proper Action Center grouping.
    pub fn new(app_id: impl Into<String>) -> Self {
        Self {
            app_id: app_id.into(),
        }
    }

    /// Show a toast notification.
    #[cfg(windows)]
    pub fn show(&self, notification: &ToastNotification) -> Result<()> {
        use windows::core::HSTRING;
        use windows::Data::Xml::Dom::XmlDocument;
        use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};

        let xml_str = build_toast_xml(notification);

        let doc = XmlDocument::new()
            .map_err(|e| AppError::Toast(format!("Failed to create XmlDocument: {e}")))?;
        doc.LoadXml(&HSTRING::from(&xml_str))
            .map_err(|e| AppError::Toast(format!("Failed to load toast XML: {e}")))?;

        let toast = ToastNotification::CreateToastNotification(&doc)
            .map_err(|e| AppError::Toast(format!("Failed to create ToastNotification: {e}")))?;

        if let Some(tag) = &notification.tag {
            toast
                .SetTag(&HSTRING::from(tag))
                .map_err(|e| AppError::Toast(format!("Failed to set toast tag: {e}")))?;
        }

        let notifier =
            ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(&self.app_id))
                .map_err(|e| AppError::Toast(format!("Failed to create ToastNotifier: {e}")))?;
        notifier
            .Show(&toast)
            .map_err(|e| AppError::Toast(format!("Failed to show toast: {e}")))?;

        tracing::info!(
            "Toast shown: title={:?}, body={:?}, tag={:?}, image={:?}",
            notification.title,
            notification.body,
            notification.tag,
            notification.image_path,
        );
        Ok(())
    }

    #[cfg(not(windows))]
    pub fn show(&self, _notification: &ToastNotification) -> Result<()> {
        tracing::warn!("Toast not available on non-Windows");
        Ok(())
    }

    /// Clear a toast by tag.
    #[cfg(windows)]
    pub fn clear_by_tag(&self, tag: &str) -> Result<()> {
        use windows::core::HSTRING;
        use windows::UI::Notifications::ToastNotificationManager;

        let history = ToastNotificationManager::History()
            .map_err(|e| AppError::Toast(format!("Failed to get history: {e}")))?;
        history
            .RemoveGroupWithId(&HSTRING::from(&self.app_id), &HSTRING::from(tag))
            .map_err(|e| AppError::Toast(format!("Failed to clear toast '{tag}': {e}")))?;

        tracing::debug!("Toast cleared: tag={tag}");
        Ok(())
    }

    #[cfg(not(windows))]
    pub fn clear_by_tag(&self, _tag: &str) -> Result<()> {
        Ok(())
    }

    /// Clear all toasts from this app.
    #[cfg(windows)]
    pub fn clear_all(&self) -> Result<()> {
        use windows::core::HSTRING;
        use windows::UI::Notifications::ToastNotificationManager;

        let history = ToastNotificationManager::History()
            .map_err(|e| AppError::Toast(format!("Failed to get history: {e}")))?;
        history
            .ClearWithId(&HSTRING::from(&self.app_id))
            .map_err(|e| AppError::Toast(format!("Failed to clear all toasts: {e}")))?;

        tracing::debug!("All toasts cleared for app_id={}", self.app_id);
        Ok(())
    }

    #[cfg(not(windows))]
    pub fn clear_all(&self) -> Result<()> {
        Ok(())
    }
}

/// Parse toast notification params from an RPC request.
pub fn parse_toast_params(params: &Value) -> Result<ToastNotification> {
    serde_json::from_value(params.clone()).map_err(|e| AppError::InvalidRpcParams(e.to_string()))
}

// ============================================================
// XML builder
// ============================================================

/// Build the toast XML string for the Windows Toast API.
///
/// Uses the `ToastGeneric` template (recommended for Windows 10+),
/// supporting title, body, image, and action buttons.
fn build_toast_xml(notification: &ToastNotification) -> String {
    let mut xml = String::from(r#"<?xml version="1.0" encoding="utf-8"?><toast>"#);

    // ── Visual ──
    xml.push_str("<visual><binding template='ToastGeneric'>");

    if let Some(title) = &notification.title {
        xml.push_str(&format!("<text>{}</text>", escape_xml(title)));
    }
    if let Some(body) = &notification.body {
        xml.push_str(&format!("<text>{}</text>", escape_xml(body)));
    }
    if let Some(path) = &notification.image_path {
        // Image must use absolute file:// URI
        let uri = if path.starts_with("file://") {
            path.clone()
        } else {
            format!("file:///{}", path.replace('\\', "/"))
        };
        xml.push_str(&format!(
            "<image placement='appLogoOverride' src='{}'/>",
            escape_xml(&uri)
        ));
    }

    xml.push_str("</binding></visual>");

    // ── Actions ──
    if !notification.actions.is_empty() {
        xml.push_str("<actions>");
        for action in &notification.actions {
            xml.push_str(&format!(
                "<action content='{}' arguments='{}'/>",
                escape_xml(&action.text),
                escape_xml(&action.arguments),
            ));
        }
        xml.push_str("</actions>");
    }

    xml.push_str("</toast>");
    xml
}

/// Escape special XML characters.
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
