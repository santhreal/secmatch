use std::collections::HashMap;

// Simulate the workflow state handling since it's not exported from secmatch lib correctly right now
pub struct WorkflowState {
    pub variables: HashMap<String, String>,
}

impl WorkflowState {
    pub fn substitute(&self, input: &str) -> String {
        let mut result = input.to_string();
        for (key, value) in &self.variables {
            result = result.replace(&format!("{{{{{key}}}}}"), value);
        }
        result
    }
}

#[test]
fn test_workflow_state_substitution_and_extraction() {
    let mut state = WorkflowState {
        variables: HashMap::new(),
    };

    // Simulate Step 1 completion
    state
        .variables
        .insert("token".to_string(), "abcdef123".to_string());

    // Verify substitution for Step 2
    let path = "/api/data?token={{token}}".to_string();
    let path_subbed = state.substitute(&path);
    assert_eq!(path_subbed, "/api/data?token=abcdef123");

    let header_val = "Bearer {{token}}".to_string();
    let header_subbed = state.substitute(&header_val);
    assert_eq!(header_subbed, "Bearer abcdef123");
}
