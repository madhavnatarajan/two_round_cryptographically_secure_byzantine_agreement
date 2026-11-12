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
    /// Protocol-specific: ⊥ iff no CORE formed. Separate from BA validity.
    pub protocol_conformance: Option<bool>,
}

pub fn grade(result: &RunResult) -> Verdict {
    let faulty_count = result.nodes.iter()
        .filter(|n| n.behavior != Behavior::Honest)
        .count();

    if faulty_count > result.t {
        return Verdict {
            status: GradeStatus::OutsideModel,
            agreement: None, validity: None, termination: None,
            protocol_conformance: None,
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

    // BA validity: if all honest inputs are equal, output must equal that value.
    // When honest inputs differ, BA validity is vacuous.
    let honest_inputs: Vec<&Vec<u8>> = honest_nodes.iter().map(|n| &n.input).collect();
    let all_same_input = honest_inputs.windows(2).all(|w| w[0] == w[1]);
    let validity = if all_same_input {
        let expected = String::from_utf8_lossy(honest_inputs[0])
            .trim_matches(char::from(0))
            .to_string();
        honest_outputs.iter().all(|o| *o == expected)
    } else {
        true
    };

    // Protocol conformance: ⊥ output iff no CORE formed.
    let all_bot = honest_outputs.iter().all(|o| *o == "⊥");
    let none_bot = honest_outputs.iter().all(|o| *o != "⊥");
    let protocol_conformance = if result.core_set.is_empty() { all_bot } else { none_bot };

    let overall = agreement && validity && termination;
    Verdict {
        status: if overall { GradeStatus::Pass } else { GradeStatus::Fail },
        agreement: Some(agreement),
        validity: Some(validity),
        termination: Some(termination),
        protocol_conformance: Some(protocol_conformance),
    }
}
