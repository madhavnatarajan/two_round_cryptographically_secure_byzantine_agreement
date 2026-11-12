use serde::Serialize;
use crate::adversary::{Behavior, Node};
use crate::protocol::NodeOutput;

pub struct RunResult {
    pub nodes: Vec<Node>,
    pub n: usize,
    pub t: usize,
    pub core_set: Vec<usize>,
    pub outputs: Vec<NodeOutput>,
}

#[derive(Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum GradeStatus {
    Pass,
    Fail,
    OutsideModel,
}

#[derive(Serialize)]
pub struct Verdict {
    pub status: GradeStatus,
    pub agreement: Option<bool>,
    pub validity: Option<bool>,
    pub termination: Option<bool>,
}

pub fn grade(result: &RunResult) -> Verdict {
    let faulty_count = result.nodes.iter()
        .filter(|n| n.behavior != Behavior::Honest)
        .count();

    // Protocol makes no guarantees outside the fault bound.
    if faulty_count > result.t {
        return Verdict {
            status: GradeStatus::OutsideModel,
            agreement: None, validity: None, termination: None,
        };
    }

    let honest_nodes: Vec<&Node> = result.nodes.iter()
        .filter(|n| n.behavior == Behavior::Honest)
        .collect();

    let termination = honest_nodes.iter()
        .all(|n| result.outputs.iter().any(|o| o.node_id == n.id));

    let honest_outputs: Vec<&str> = result.outputs.iter()
        .filter(|o| honest_nodes.iter().any(|n| n.id == o.node_id))
        .map(|o| o.message.as_str())
        .collect();

    let agreement = honest_outputs.windows(2).all(|w| w[0] == w[1]);

    let honest_inputs: Vec<&Vec<u8>> = honest_nodes.iter().map(|n| &n.input).collect();
    let all_same_input = honest_inputs.windows(2).all(|w| w[0] == w[1]);

    let validity = if !all_same_input {
        // Inputs differ among honest nodes. A CORE may still have formed around
        // a subset's common value. Valid outputs are: the CORE's agreed value,
        // or ⊥ if no CORE formed.
        if result.core_set.is_empty() {
            honest_outputs.iter().all(|o| *o == "⊥")
        } else {
            // Find the common input of CORE members (they must all be honest with same input
            // for a CORE to form; if a liar is in CORE it broadcast the honest root).
            // The agreed output is whatever honest nodes reconstructed — check all agree.
            honest_outputs.windows(2).all(|w| w[0] == w[1]) && !honest_outputs.iter().any(|o| *o == "⊥")
        }
    } else {
        let expected = String::from_utf8_lossy(honest_inputs[0])
            .trim_matches(char::from(0))
            .to_string();
        if result.core_set.is_empty() {
            // No CORE formed within fault bound — ⊥ is acceptable.
            honest_outputs.iter().all(|o| *o == "⊥")
        } else {
            // CORE formed — output must equal the common input.
            honest_outputs.iter().all(|o| *o == expected)
        }
    };

    let overall = agreement && validity && termination;
    Verdict {
        status: if overall { GradeStatus::Pass } else { GradeStatus::Fail },
        agreement: Some(agreement),
        validity: Some(validity),
        termination: Some(termination),
    }
}
