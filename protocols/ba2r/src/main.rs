use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use harness::adversary::{Behavior, Node};
use harness::protocol::Simulation;
use harness::adversary::P2PMessage;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tower_http::cors::{Any, CorsLayer};

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
    recovered_message: String, // consensus output shown in UI (first honest node's output)
    round1_complete: bool,
    round2_complete: bool,
}

type SharedState = Arc<Mutex<AppState>>;

#[tokio::main]
async fn main() {
    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);
    let shared_state = Arc::new(Mutex::new(AppState::default()));

    let app = Router::new()
        .route("/status", get(get_status))
        .route("/start", post(start_simulation))
        .route("/round1", post(run_sim_round_1))
        .route("/round2", post(run_sim_round_2))
        .with_state(shared_state)
        .layer(cors);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    println!("🚀 Server listening on http://127.0.0.1:3000");
    println!("➡️  Open index.html in your browser to start the demo.");
    axum::serve(listener, app).await.unwrap();
}

async fn get_status(State(state): State<SharedState>) -> Json<AppState> {
    Json(state.lock().unwrap().clone())
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

    if payload.n <= 2 * payload.t {
        println!("❌ Invalid configuration: n must be > 2t. Received n={}, t={}", payload.n, payload.t);
        return StatusCode::BAD_REQUEST;
    }
    if payload.n > 256 {
        println!("❌ Invalid configuration: n must be <= 256. Received n={}", payload.n);
        return StatusCode::BAD_REQUEST;
    }

    println!("Received config: n={}, t={}, inputs={:?}", payload.n, payload.t, payload.input_strings);

    let nodes = payload.node_behaviors.iter().enumerate().map(|(i, behavior)| {
        println!("  - Node P{} behavior: {:?}", i, behavior);
        let input = payload.input_strings.get(i).cloned().unwrap_or_default();
        Node { id: i, input: input.into_bytes(), behavior: behavior.clone() }
    }).collect();

    *state.lock().unwrap() = AppState { n: payload.n, t: payload.t, nodes, ..Default::default() };
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
    let mut s = state.lock().unwrap();
    if s.round1_complete {
        return (StatusCode::BAD_REQUEST, Json(Round1Response {
            whiteboard: vec![], core_set: vec![], node_behaviors: vec![], round1_complete: true,
        }));
    }

    let sim = Simulation { nodes: s.nodes.clone(), n: s.n, t: s.t };
    let (core_set, whiteboard, all_msgs) = sim.run_round_1();

    let whiteboard_strings = whiteboard.iter().map(|root| {
        root.map(|r| format!("0x{}", &hex::encode(r)[0..8]))
    }).collect();

    let node_behaviors = s.nodes.iter().map(|n| n.behavior.clone()).collect();
    s.core_set = core_set.clone();
    s.whiteboard = whiteboard;
    s.all_p2p_messages = all_msgs;
    s.round1_complete = true;

    (StatusCode::OK, Json(Round1Response { whiteboard: whiteboard_strings, core_set, node_behaviors, round1_complete: true }))
}

async fn run_sim_round_2(State(state): State<SharedState>) -> (StatusCode, Json<AppState>) {
    let mut s = state.lock().unwrap();
    if !s.round1_complete || s.round2_complete {
        return (StatusCode::BAD_REQUEST, Json(s.clone()));
    }

    let sim = Simulation { nodes: s.nodes.clone(), n: s.n, t: s.t };
    let outputs = sim.run_round_2(
        s.core_set.clone(), &s.whiteboard, &s.all_p2p_messages,
    );

    // For the UI, show the first honest node's output as the consensus value.
    let first = outputs.first();
    s.liar_caught = outputs.iter().any(|o| o.liar_caught);
    s.recovered_message = first.map(|o| o.message.clone()).unwrap_or("⊥".to_string());
    s.round2_complete = true;

    (StatusCode::OK, Json(s.clone()))
}
