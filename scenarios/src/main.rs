use harness::adversary::{Behavior, Node};
use harness::grader::{grade, GradeStatus, RunResult};
use harness::protocol::Simulation;
use serde::Serialize;
use std::fs;

#[derive(Serialize)]
struct NodeOutputRecord {
    node_id: usize,
    message: String,
    liar_caught: bool,
}

#[derive(Serialize)]
struct Verdict {
    status: String,
    agreement: Option<bool>,
    validity: Option<bool>,
    termination: Option<bool>,
}

#[derive(Serialize)]
struct ScenarioResult {
    scenario: &'static str,
    n: usize,
    t: usize,
    node_behaviors: Vec<String>,
    node_inputs: Vec<String>,
    core_set: Vec<usize>,
    node_outputs: Vec<NodeOutputRecord>,
    verdict: Verdict,
}

fn run_scenario(
    scenario: &'static str,
    n: usize,
    t: usize,
    inputs: Vec<&str>,
    behaviors: Vec<Behavior>,
) -> ScenarioResult {
    let nodes: Vec<Node> = behaviors.iter().enumerate().map(|(i, b)| Node {
        id: i,
        input: inputs[i].as_bytes().to_vec(),
        behavior: b.clone(),
    }).collect();

    let sim = Simulation { nodes: nodes.clone(), n, t };
    let (core_set, whiteboard, all_msgs) = sim.run_round_1();
    let outputs = sim.run_round_2(core_set.clone(), &whiteboard, &all_msgs);

    let result = RunResult { nodes, n, t, core_set: core_set.clone(), outputs };
    let verdict = grade(&result);

    let status_str = match verdict.status {
        GradeStatus::Pass => "pass",
        GradeStatus::Fail => "fail",
        GradeStatus::OutsideModel => "outside_model",
    };
    println!("[{}] {}", scenario, status_str);

    let node_outputs = result.outputs.iter().map(|o| NodeOutputRecord {
        node_id: o.node_id,
        message: o.message.clone(),
        liar_caught: o.liar_caught,
    }).collect();

    ScenarioResult {
        scenario, n, t,
        node_behaviors: behaviors.iter().map(|b| format!("{:?}", b)).collect(),
        node_inputs: inputs.iter().map(|s| s.to_string()).collect(),
        core_set,
        node_outputs,
        verdict: Verdict {
            status: status_str.to_string(),
            agreement: verdict.agreement,
            validity: verdict.validity,
            termination: verdict.termination,
        },
    }
}

fn main() {
    let mut results = Vec::new();

    // 1. Happy path — all honest, same input
    results.push(run_scenario("all_honest_same_input", 7, 3,
        vec!["hello", "hello", "hello", "hello", "hello", "hello", "hello"],
        vec![Behavior::Honest; 7],
    ));

    // 2. All honest, different inputs — no CORE, output ⊥
    results.push(run_scenario("all_honest_different_inputs", 7, 3,
        vec!["aaa", "bbb", "ccc", "ddd", "eee", "fff", "ggg"],
        vec![Behavior::Honest; 7],
    ));

    // 3. Majority same input, minority different
    results.push(run_scenario("majority_same_minority_different", 7, 3,
        vec!["hello", "hello", "hello", "hello", "hello", "other", "other"],
        vec![Behavior::Honest; 7],
    ));

    // 4. Exactly t mutes, rest honest same input
    results.push(run_scenario("exactly_t_mutes", 7, 3,
        vec!["hello", "hello", "hello", "hello", "hello", "hello", "hello"],
        vec![Behavior::Honest, Behavior::Honest, Behavior::Honest, Behavior::Honest,
             Behavior::Mute, Behavior::Mute, Behavior::Mute],
    ));

    // 5. More than t mutes — CORE cannot form
    results.push(run_scenario("more_than_t_mutes", 7, 3,
        vec!["hello", "hello", "hello", "hello", "hello", "hello", "hello"],
        vec![Behavior::Honest, Behavior::Honest, Behavior::Honest,
             Behavior::Mute, Behavior::Mute, Behavior::Mute, Behavior::Mute],
    ));

    // 6. Exactly t liars, rest honest — liars caught in Round 2
    results.push(run_scenario("exactly_t_liars", 7, 3,
        vec!["hello", "hello", "hello", "hello", "hello", "hello", "hello"],
        vec![Behavior::Honest, Behavior::Honest, Behavior::Honest, Behavior::Honest,
             Behavior::Liar, Behavior::Liar, Behavior::Liar],
    ));

    // 7. Liars inside CORE — their shards rejected via Merkle proof
    results.push(run_scenario("liars_inside_core", 7, 3,
        vec!["hello", "hello", "hello", "hello", "hello", "hello", "hello"],
        vec![Behavior::Liar, Behavior::Honest, Behavior::Honest, Behavior::Honest,
             Behavior::Honest, Behavior::Honest, Behavior::Honest],
    ));

    // 8. Minimum valid config n=2t+1
    results.push(run_scenario("minimum_valid_config", 5, 2,
        vec!["hello", "hello", "hello", "hello", "hello"],
        vec![Behavior::Honest; 5],
    ));

    // 9. Minimum valid config with exactly t faults
    results.push(run_scenario("minimum_config_with_t_faults", 5, 2,
        vec!["hello", "hello", "hello", "hello", "hello"],
        vec![Behavior::Honest, Behavior::Honest, Behavior::Honest,
             Behavior::Liar, Behavior::Liar],
    ));

    // 10. Mixed faults — some mute, some liar
    results.push(run_scenario("mixed_mute_and_liar", 7, 3,
        vec!["hello", "hello", "hello", "hello", "hello", "hello", "hello"],
        vec![Behavior::Honest, Behavior::Honest, Behavior::Honest, Behavior::Honest,
             Behavior::Mute, Behavior::Liar, Behavior::Liar],
    ));

    let json = serde_json::to_string_pretty(&results).unwrap();
    fs::write("scenarios/results.json", &json).unwrap();
    println!("\n✅ Results written to scenarios/results.json");
}
