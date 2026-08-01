//! Inter-template state sharing for cross-template variable exchange.
//!
//! This module enables templates to export extracted variables for use by
//! subsequently-executed templates, creating a shared state across the
//! scanning session.
//!
//! # Design
//!
//! - Templates declare `exports` to publish variables to a global namespace
//! - Templates reference exported variables via `{{template_id.var_name}}` syntax
//! - The `InterTemplateState` tracks all exported values per target
//! - Variable resolution follows a hierarchical lookup: local → imported → global

use rustc_hash::FxHashMap;
use secir::Template;
use std::collections::HashMap;

/// Tracks exported variables from templates for cross-template sharing.
///
/// Each target gets its own namespace to prevent cross-contamination between
/// different scan targets. Within a target namespace, variables are stored
/// with their fully-qualified name: `<template_id>.<variable_name>`.
#[derive(Debug, Default, Clone)]
pub struct InterTemplateState {
    /// Per-target exported variable storage.
    /// Key: (`target_url`, `template_id.var_name`) → exported value
    exports: FxHashMap<(String, String), String>,

    /// Cache of which templates have exported which variables (to avoid re-export)
    export_cache: FxHashMap<(String, String), Vec<String>>,
}

impl InterTemplateState {
    /// Create a new empty inter-template state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Export a variable from a template for use by other templates.
    ///
    /// The variable is stored with the fully-qualified name: `<template_id>.<var_name>`
    pub fn export_variable(
        &mut self,
        target: &str,
        template_id: &str,
        var_name: &str,
        value: String,
    ) {
        let qualified_name = format!("{template_id}.{var_name}");
        self.exports
            .insert((target.to_string(), qualified_name), value);

        // Track that this template exported this variable
        self.export_cache
            .entry((target.to_string(), template_id.to_string()))
            .or_default()
            .push(var_name.to_string());
    }

    /// Export all declared exports from a template based on its export declarations.
    ///
    /// This should be called after a template successfully matches and extractors
    /// have populated the local variables.
    pub fn export_template_variables(
        &mut self,
        target: &str,
        template: &Template,
        extracted_vars: &HashMap<String, String>,
    ) {
        for export in &template.exports {
            let var_name = &export.name;

            // Only export if the variable was actually extracted
            if let Some(value) = extracted_vars.get(var_name) {
                self.export_variable(target, &template.id, var_name, value.clone());
            }
        }
    }

    /// Import a variable from another template.
    ///
    /// Looks up a fully-qualified variable name: `<source_template_id>.<var_name>`
    pub fn import_variable(
        &self,
        target: &str,
        source_template_id: &str,
        var_name: &str,
    ) -> Option<&str> {
        let qualified_name = format!("{source_template_id}.{var_name}");
        self.exports
            .get(&(target.to_string(), qualified_name))
            .map(std::string::String::as_str)
    }

    /// Get a variable using the fully-qualified name format.
    ///
    /// The name should be in the format: `template_id.variable_name`
    pub fn get_qualified(&self, target: &str, qualified_name: &str) -> Option<&str> {
        self.exports
            .get(&(target.to_string(), qualified_name.to_string()))
            .map(std::string::String::as_str)
    }

    /// Check if a template has already exported variables for this target.
    #[must_use]
    pub fn has_exports(&self, target: &str, template_id: &str) -> bool {
        self.export_cache
            .contains_key(&(target.to_string(), template_id.to_string()))
    }

    /// Get all exported variables for a specific template on a target.
    #[must_use]
    pub fn get_template_exports(&self, target: &str, template_id: &str) -> Option<&Vec<String>> {
        self.export_cache
            .get(&(target.to_string(), template_id.to_string()))
    }

    /// Clear all exports for a specific target.
    pub fn clear_target(&mut self, target: &str) {
        let keys_to_remove: Vec<_> = self
            .exports
            .keys()
            .filter(|(t, _)| t == target)
            .cloned()
            .collect();
        for key in keys_to_remove {
            self.exports.remove(&key);
        }

        let cache_keys_to_remove: Vec<_> = self
            .export_cache
            .keys()
            .filter(|(t, _)| t == target)
            .cloned()
            .collect();
        for key in cache_keys_to_remove {
            self.export_cache.remove(&key);
        }
    }

    /// Clear all state.
    pub fn clear(&mut self) {
        self.exports.clear();
        self.export_cache.clear();
    }

    /// Returns the number of exported variables across all targets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.exports.len()
    }

    /// Returns true if no variables have been exported.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.exports.is_empty()
    }
}

/// Resolves variable references that may include inter-template imports.
///
/// Supports two forms of variable references:
/// - Simple: `{{var_name}}` - resolved from local scope
/// - Qualified: `{{template_id.var_name}}` - resolved from inter-template state
#[must_use]
pub fn resolve_variable_reference(
    state: &InterTemplateState,
    target: &str,
    local_vars: &HashMap<String, String>,
    var_ref: &str,
) -> Option<String> {
    // Check if this is a qualified reference (template_id.var_name)
    if let Some(dot_pos) = var_ref.find('.') {
        let (template_id, var_name) = var_ref.split_at(dot_pos);
        let var_name = &var_name[1..]; // Skip the dot

        // First check local scope (local overrides imported)
        if let Some(value) = local_vars.get(var_ref) {
            return Some(value.clone());
        }

        // Then check inter-template state
        if let Some(value) = state.import_variable(target, template_id, var_name) {
            return Some(value.to_string());
        }
    }

    // Simple variable reference - check local scope only
    local_vars.get(var_ref).cloned()
}

/// Substitutes variables in a string, supporting both local and inter-template references.
///
/// Variable syntax: `{{var_name}}` or `{{template_id.var_name}}`
#[must_use]
pub fn substitute_variables_with_imports(
    state: &InterTemplateState,
    target: &str,
    local_vars: &HashMap<String, String>,
    input: &str,
) -> String {
    let mut result = input.to_string();

    // Find all {{variable}} patterns (bounded to avoid cyclic {{x}} → {{x}} loops).
    let mut start = 0;
    let mut substitutions = 0usize;
    const MAX_SUBSTITUTIONS: usize = 64;
    while substitutions < MAX_SUBSTITUTIONS {
        let Some(var_start) = result[start..].find("{{") else {
            break;
        };
        let var_start = start + var_start;
        if let Some(var_end_rel) = result[var_start..].find("}}") {
            let var_end = var_start + var_end_rel + 2;
            let var_name = &result[var_start + 2..var_end - 2];
            let placeholder = &result[var_start..var_end];

            // Try to resolve the variable
            if let Some(value) = resolve_variable_reference(state, target, local_vars, var_name) {
                if value == placeholder {
                    start = var_end;
                } else {
                    result.replace_range(var_start..var_end, &value);
                    substitutions += 1;
                }
            } else {
                // Variable not found - leave as-is and continue
                start = var_end;
            }
        } else {
            break;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use secir::TemplateExport;

    #[test]
    fn export_and_import_variable() {
        let mut state = InterTemplateState::new();

        // Template "auth" exports a session token
        state.export_variable(
            "https://example.com",
            "auth",
            "session_token",
            "abc123".to_string(),
        );

        // Template "scan" imports it
        let value = state.import_variable("https://example.com", "auth", "session_token");
        assert_eq!(value, Some("abc123"));

        // Different target should not see the export
        let value = state.import_variable("https://other.com", "auth", "session_token");
        assert_eq!(value, None);
    }

    #[test]
    fn qualified_name_lookup() {
        let mut state = InterTemplateState::new();
        state.export_variable(
            "https://example.com",
            "login",
            "token",
            "xyz789".to_string(),
        );

        let value = state.get_qualified("https://example.com", "login.token");
        assert_eq!(value, Some("xyz789"));
    }

    #[test]
    fn local_vars_override_imports() {
        let state = InterTemplateState::new();
        let mut local_vars = HashMap::new();
        local_vars.insert("auth.token".to_string(), "local_override".to_string());

        // Even though there's no export in state, local var should be found
        let result =
            resolve_variable_reference(&state, "https://example.com", &local_vars, "auth.token");
        assert_eq!(result, Some("local_override".to_string()));
    }

    #[test]
    fn substitute_with_imports() {
        let mut state = InterTemplateState::new();
        state.export_variable(
            "https://example.com",
            "auth",
            "token",
            "bearer123".to_string(),
        );

        let local_vars = HashMap::new();
        let result = substitute_variables_with_imports(
            &state,
            "https://example.com",
            &local_vars,
            "Authorization: Bearer {{auth.token}}",
        );

        assert_eq!(result, "Authorization: Bearer bearer123");
    }

    #[test]
    fn substitute_mixed_local_and_imported() {
        let mut state = InterTemplateState::new();
        state.export_variable("https://example.com", "auth", "token", "tok".to_string());

        let mut local_vars = HashMap::new();
        local_vars.insert("endpoint".to_string(), "/api/users".to_string());

        let result = substitute_variables_with_imports(
            &state,
            "https://example.com",
            &local_vars,
            "GET {{endpoint}} with {{auth.token}}",
        );

        assert_eq!(result, "GET /api/users with tok");
    }

    #[test]
    fn unknown_variables_preserved() {
        let state = InterTemplateState::new();
        let local_vars = HashMap::new();

        let result = substitute_variables_with_imports(
            &state,
            "https://example.com",
            &local_vars,
            "Unknown: {{missing.var}}",
        );

        assert_eq!(result, "Unknown: {{missing.var}}");
    }

    #[test]
    fn clear_target_removes_exports() {
        let mut state = InterTemplateState::new();
        state.export_variable("https://a.com", "t1", "v1", "a".to_string());
        state.export_variable("https://b.com", "t1", "v1", "b".to_string());

        state.clear_target("https://a.com");

        assert!(state.import_variable("https://a.com", "t1", "v1").is_none());
        assert_eq!(
            state.import_variable("https://b.com", "t1", "v1"),
            Some("b")
        );
    }

    #[test]
    fn export_template_variables_from_declarations() {
        let mut state = InterTemplateState::new();

        let template = Template {
            depends_on: vec![],
            id: "login".to_string(),
            ir_version: 1,
            exports: vec![TemplateExport {
                name: "session".to_string(),
                alias: None,
            }],
            requests: vec![secir::RequestDef::default()],
            info: secir::template::TemplateInfo {
                name: "Login".to_string(),
                author: vec!["test".to_string()],
                severity: secir::Severity::Info,
                description: None,
                reference: vec![],
                tags: vec![],
                metadata: secir::template::TemplateMeta::default(),
            },
            extends: None,
            imports: vec![],
            protocol: secir::Protocol::Http,
            self_contained: false,
            variables: std::collections::HashMap::new(),
            cli_variables: std::collections::HashMap::new(),
            source_path: None,
            flow: None,
            workflows: vec![],
            extensions: std::collections::HashMap::new(),
            parallel_groups: vec![],
        };

        let mut extracted = HashMap::new();
        extracted.insert("session".to_string(), "sess123".to_string());
        extracted.insert("other".to_string(), "ignored".to_string());

        state.export_template_variables("https://example.com", &template, &extracted);

        // Exported variables should be available
        assert_eq!(
            state.import_variable("https://example.com", "login", "session"),
            Some("sess123")
        );

        // Non-exported variables should not be in state
        assert!(
            state
                .import_variable("https://example.com", "login", "other")
                .is_none()
        );
    }

    #[test]
    fn has_exports_tracks_exported_templates() {
        let mut state = InterTemplateState::new();

        assert!(!state.has_exports("https://example.com", "auth"));

        state.export_variable("https://example.com", "auth", "token", "val".to_string());

        assert!(state.has_exports("https://example.com", "auth"));
    }

    #[test]
    fn is_empty_and_len() {
        let mut state = InterTemplateState::new();

        assert!(state.is_empty());
        assert_eq!(state.len(), 0);

        state.export_variable("https://example.com", "t1", "v1", "a".to_string());

        assert!(!state.is_empty());
        assert_eq!(state.len(), 1);
    }

    #[test]
    fn verify_inter_template_no_infinite_loop_on_cycle() {
        use std::sync::mpsc;
        use std::time::Duration;

        let state = InterTemplateState::new();
        let mut local_vars = std::collections::HashMap::new();
        local_vars.insert("x".to_string(), "{{x}}".to_string());

        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = substitute_variables_with_imports(
                &state,
                "https://example.com",
                &local_vars,
                "{{x}}",
            );
            let _ = tx.send(result);
        });

        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(result) => assert_eq!(result, "{{x}}"),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!(
                    "Infinite loop detected in substitute_variables_with_imports on cyclic reference"
                );
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("Thread panicked during substitution");
            }
        }
    }
}
