use serde::Serialize;
use crate::adversary::{Behavior, Node};
use crate::protocol::NodeOutput;

pub struct RunResult {
    pub nodes: Vec<Node>,
    pub core_set: Vec<usize>,
    pub outputs: Vec<NodeOutput>,
}

#[derive(Serialize)]
pub struct Verdict {
    pub agreement: bool,
    pub validity: bool,
    pub termination: bool,
    pub overall: bool,
}

pub fn grade(result: &RunResult) -> Verdict {
    let honest_nodes: Vec<&Node> = result.nodes.iter()
        .filter(|n| n.behavior == Behavior::Honest)
        .collect();

    // Termination: every honest node produced an output.
    let termination = honest_nodes.iter().all(|n| {
        result.outputs.iter().any(|o| o.node_id == n.id)
    });

    // Agreement: all honest node outputs are the same value.
    let honest_outputs: Vec<&str> = result.outputs.iter()
        .filter(|o| honest_nodes.iter().any(|n| n.id == o.node_id))
        .map(|o| o.message.as_str())
        .collect();

    let agreement = honest_outputs.windows(2).all(|w| w[0] == w[1]);

    // Validity: if all honest nodes had the same input, the output must equal it
    // (or ⊥ if no CORE formed). If inputs differ, any output is valid.
    let honest_inputs: Vec<&Vec<u8>> = honest_nodes.iter().map(|n| &n.input).collect();
    let all_same_input = honest_inputs.windows(2).all(|w| w[0] == w[1]);

    let validity = if !all_same_input {
        true
    } else {
        let expected = String::from_utf8_lossy(honest_inputs[0])
            .trim_matches(char::from(0))
            .to_string();
        // Output must be either the common input or ⊥
        honest_outputs.iter().all(|o| *o == expected || *o == "⊥")
    };

    let overall = agreement && validity && termination;
    Verdict { agreement, validity, termination, overall }
}
