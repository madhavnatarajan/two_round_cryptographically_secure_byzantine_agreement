use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use reed_solomon_erasure::galois_8::ReedSolomon;
use rs_merkle::{algorithms::Sha256, Hasher, MerkleTree};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tower_http::cors::{Any, CorsLayer};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Behavior {
    Honest,
    Mute,
    Liar,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2PMessage {
    pub sender_id: usize,
    pub component_index: usize,
    pub component: Vec<u8>,
    pub proof: Vec<[u8; 32]>, // Merkle witness
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Node {
    pub id: usize,
    pub input: Vec<u8>,
    pub behavior: Behavior,
}

impl Node {
    pub fn execute_round_1(&self, n: usize, t: usize) -> (Option<[u8; 32]>, Vec<P2PMessage>) {
        if self.behavior == Behavior::Mute {
            return (None, vec![]);
        }

        // --- ROBUSTNESS FIX ---
        // Ensure the input is long enough and padded to be divisible by `t+1`.
        let mut input_data = self.input.clone();
        let data_shards_count = t + 1;
        if input_data.len() < data_shards_count {
            input_data.resize(data_shards_count, 0);
        }
        let remainder = input_data.len() % data_shards_count;
        if remainder != 0 {
            input_data.extend(vec![0; data_shards_count - remainder]);
        }
        let block_size = input_data.len() / data_shards_count;
        let mut shards: Vec<Vec<u8>> = input_data.chunks(block_size).map(|c| c.to_vec()).collect();
        
        for _ in 0..(n - (t + 1)) {
            shards.push(vec![0u8; block_size]);
        }

        let rs = ReedSolomon::new(t + 1, n - (t + 1)).unwrap();
        rs.encode(&mut shards).unwrap();

        let mut leaves = Vec::new();
        for (j, shard) in shards.iter().enumerate() {
            let mut leaf_data = vec![j as u8];
            leaf_data.extend(shard);
            leaves.push(Sha256::hash(&leaf_data));
        }

        let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        let root = merkle_tree.root();

        let mut messages = Vec::new();
        for j in 0..n {
            let mut sent_shard = shards[j].clone();
            
            if self.behavior == Behavior::Liar && !sent_shard.is_empty() {
                sent_shard[0] = sent_shard[0].wrapping_add(1); 
            }

            let proof = merkle_tree.proof(&[j]);
            messages.push(P2PMessage {
                sender_id: self.id,
                component_index: j,
                component: sent_shard,
                proof: proof.proof_hashes().to_vec(),
            });
        }
        (root, messages)
    }
}

pub struct Simulation {
    pub nodes: Vec<Node>,
    pub n: usize,
    pub t: usize,
}

impl Simulation {
    pub fn run_round_1(&self) -> (Vec<usize>, Vec<Option<[u8; 32]>>, Vec<P2PMessage>) {
        println!("--- Starting Round 1 ---");
        let mut oracle_whiteboard = vec![None; self.n];
        let mut all_p2p_messages = Vec::new();

        for node in &self.nodes {
            let (root, p2p_msgs) = node.execute_round_1(self.n, self.t);
            oracle_whiteboard[node.id] = root;
            all_p2p_messages.extend(p2p_msgs);
        }

        let core_set = self.identify_core(&oracle_whiteboard);
        
        println!("Oracle Whiteboard (Agreed Roots):");
        for (i, root) in oracle_whiteboard.iter().enumerate() {
            match root {
                Some(r) => println!("  P{}: 0x{}...", i, &hex::encode(r)[0..8]),
                None => println!("  P{}: MUTE (No Root)", i),
            }
        }
        println!("\nCalculated CORE set: {:?}", core_set);
        
        (core_set, oracle_whiteboard, all_p2p_messages)
    }

    fn identify_core(&self, whiteboard: &[Option<[u8; 32]>]) -> Vec<usize> {
        let threshold = self.n - self.t;
        let mut core_set = Vec::new();
        
        for target_root in whiteboard.iter() {
            if let Some(t_root) = target_root {
                let count = whiteboard.iter().filter(|r| r.as_ref() == Some(t_root)).count();
                if count >= threshold {
                    core_set = whiteboard.iter()
                        .enumerate()
                        .filter(|(_, r)| r.as_ref() == Some(t_root))
                        .map(|(idx, _)| idx)
                        .collect();
                    break;
                }
            }
        }
        core_set
    }

    pub fn run_round_2(
        &self,
        core_set: Vec<usize>,
        oracle_whiteboard: &[Option<[u8; 32]>],
        all_p2p_messages: &[P2PMessage],
    ) -> (bool, String) {
        println!("\n--- Starting Round 2 (Verification & Reconstruction) ---");

        // Let's demonstrate reconstruction from the perspective of a non-CORE node.
        // We'll pick the first honest node that is NOT in the CORE set.
        let target_node_id = self.nodes.iter()
            .find(|n| n.behavior == Behavior::Honest && !core_set.contains(&n.id))
            .map(|n| n.id)
            .unwrap_or(0); // Default to 0 if all honest nodes are in CORE

        if core_set.is_empty() {
            println!("❌ No CORE set formed — nodes have differing inputs. Outputting ⊥.");
            return (false, "⊥".to_string());
        }

        let agreed_root = oracle_whiteboard[core_set[0]].unwrap();
        let mut collected_shards: Vec<Option<Vec<u8>>> = vec![None; self.n];
        let mut verified_count = 0;
        let mut liar_caught = false;

        for msg in all_p2p_messages {
            // A node only trusts data that originated from a CORE member.
            if !core_set.contains(&msg.sender_id) { continue; }

            // For the demo, the target node will try to collect the first t+1 components (0..=t).
            // It only needs to hear from one CORE member for each component index.
            // We check if we already have a shard for this component index.
            if msg.component_index > self.t || collected_shards[msg.component_index].is_some() {
                continue;
            }
            
            let mut leaf_data = vec![msg.component_index as u8];
            leaf_data.extend(&msg.component);
            let leaf_hash = Sha256::hash(&leaf_data);

            let proof = rs_merkle::MerkleProof::<Sha256>::new(msg.proof.clone());

            let is_valid = proof.verify(
                agreed_root,
                &[msg.component_index],
                &[leaf_hash],
                self.n
            );
            
            if is_valid {
                // The node collects the j-th component from a CORE member.
                println!("✅ Node {} verified component C{} from P{}", target_node_id, msg.component_index, msg.sender_id);
                collected_shards[msg.component_index] = Some(msg.component.clone());
                verified_count += 1;
            } else {
                println!(
                    "🚨 CAUGHT THE LIAR! Node {} rejected corrupted data from P{}.", 
                    target_node_id, msg.sender_id
                );
                liar_caught = true;
            }
        }
        let target_node = target_node_id; // for print statements
        println!("Node {} collected {} verified components.", target_node, verified_count);

        if verified_count >= self.t + 1 {
            let rs = ReedSolomon::new(self.t + 1, self.n - (self.t + 1)).unwrap();
            rs.reconstruct(&mut collected_shards).unwrap();
            
            let mut recovered_data = Vec::new();
            // The original message is in the first `t+1` shards.
            // We need to collect all of them to form the full message.
            let data_shards = &collected_shards[0..=self.t];
            recovered_data.extend(
                data_shards.iter().flatten().flatten()
            );
            
            let recovered_string = String::from_utf8_lossy(&recovered_data)
                .trim_matches(char::from(0))
                .to_string();
                
            println!("✅ Node {} successfully reconstructed: {}", target_node, recovered_string);
            (liar_caught, recovered_string)
        } else {
            println!("❌ Node {} failed to collect enough components (t+1 required).", target_node);
            (liar_caught, "Failed to reconstruct.".to_string())
        }
    }
}

#[derive(Clone, Default, Serialize)]
struct AppState {
    n: usize,
    t: usize,
    nodes: Vec<Node>,
    whiteboard: Vec<Option<[u8; 32]>>,
    #[serde(skip_serializing)]
    all_p2p_messages: Vec<P2PMessage>,
    core_set: Vec<usize>,
    liar_caught: bool,
    recovered_message: String,
    round1_complete: bool,
    round2_complete: bool,
}

type SharedState = Arc<Mutex<AppState>>;

#[tokio::main]
async fn main() {
    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);

    let initial_state = AppState::default();
    let shared_state = Arc::new(Mutex::new(initial_state));

    let app = Router::new()
        .route("/status", get(get_status))
        .route("/start", post(start_simulation))
        .route("/round1", post(run_sim_round_1))
        .route("/round2", post(run_sim_round_2))
        .with_state(shared_state)
        .layer(cors);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("🚀 Server listening on http://127.0.0.1:3000");
    println!("➡️ Open index.html in your browser to start the demo.");
    axum::serve(listener, app).await.unwrap();
}

async fn get_status(State(state): State<SharedState>) -> Json<AppState> {
    let state_guard = state.lock().unwrap();
    Json(state_guard.clone())
}

#[derive(Deserialize)]
struct StartPayload {
    n: usize,
    t: usize,
    #[serde(rename = "inputStrings")]
    input_strings: Vec<String>,
    #[serde(rename = "nodeBehaviors")]
    node_behaviors: Vec<Behavior>,
}

async fn start_simulation(
    State(state): State<SharedState>,
    Json(payload): Json<StartPayload>,
) -> StatusCode {
    println!("\n--- RESETTING SIMULATION ---");
    
    // Validate the core security condition of the protocol
    if payload.n <= 2 * payload.t {
        println!("❌ Invalid configuration: n must be > 2t. Received n={}, t={}", payload.n, payload.t);
        return StatusCode::BAD_REQUEST;
    }
    
    // The Reed-Solomon library has a hard limit of 256 total shards.
    if payload.n > 256 {
        println!("❌ Invalid configuration: n must be <= 256. Received n={}", payload.n);
        return StatusCode::BAD_REQUEST;
    }

    println!("Received config: n={}, t={}, inputs={:?}", payload.n, payload.t, payload.input_strings);

    let mut nodes = Vec::new();
    for (i, behavior) in payload.node_behaviors.iter().enumerate() {
        println!("  - Node P{} behavior: {:?}", i, behavior);
        let input = payload.input_strings.get(i).cloned().unwrap_or_default();
        nodes.push(Node { id: i, input: input.into_bytes(), behavior: behavior.clone() });
    }

    let mut state_guard = state.lock().unwrap();
    *state_guard = AppState { n: payload.n, t: payload.t, nodes, ..Default::default() };

    StatusCode::OK
}

#[derive(Serialize)]
struct Round1Response {
    whiteboard: Vec<Option<String>>,
    core_set: Vec<usize>,
    node_behaviors: Vec<Behavior>,
    round1_complete: bool,
}

async fn run_sim_round_1(State(state): State<SharedState>) -> (StatusCode, Json<Round1Response>) {
    let mut state_guard = state.lock().unwrap();
    if state_guard.round1_complete {
        // Avoid re-running if already done
        return (StatusCode::BAD_REQUEST, Json(Round1Response { whiteboard: vec![], core_set: vec![], node_behaviors: vec![], round1_complete: true }));
    }

    let sim = Simulation { nodes: state_guard.nodes.clone(), n: state_guard.n, t: state_guard.t };
    let (core_set, whiteboard, all_msgs) = sim.run_round_1();

    state_guard.core_set = core_set.clone();
    state_guard.whiteboard = whiteboard.clone();
    state_guard.all_p2p_messages = all_msgs;
    state_guard.round1_complete = true;

    let whiteboard_strings: Vec<Option<String>> = whiteboard.iter().map(|root| {
        root.map(|r| format!("0x{}", &hex::encode(r)[0..8]))
    }).collect();

    let response = Round1Response {
        whiteboard: whiteboard_strings,
        core_set,
        node_behaviors: state_guard.nodes.iter().map(|n| n.behavior.clone()).collect(),
        round1_complete: true,
    };

    (StatusCode::OK, Json(response))
}

async fn run_sim_round_2(State(state): State<SharedState>) -> (StatusCode, Json<AppState>) {
    let mut state_guard = state.lock().unwrap();
    if !state_guard.round1_complete || state_guard.round2_complete {
        return (StatusCode::BAD_REQUEST, Json(state_guard.clone()));
    }

    let sim = Simulation { nodes: state_guard.nodes.clone(), n: state_guard.n, t: state_guard.t };
    let (liar_caught, recovered_message) = sim.run_round_2(
        state_guard.core_set.clone(), &state_guard.whiteboard, &state_guard.all_p2p_messages
    );

    state_guard.liar_caught = liar_caught;
    state_guard.recovered_message = recovered_message;
    state_guard.round2_complete = true;

    (StatusCode::OK, Json(state_guard.clone()))
}
