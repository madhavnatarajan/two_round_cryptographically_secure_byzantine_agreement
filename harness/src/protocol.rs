use rs_merkle::{algorithms::Sha256, Hasher};
use reed_solomon_erasure::galois_8::ReedSolomon;
use crate::adversary::{Behavior, Node, P2PMessage, VerifiedShard};

pub struct Simulation {
    pub nodes: Vec<Node>,
    pub n: usize,
    pub t: usize,
}

/// Output produced by one node in Round 2.
pub struct NodeOutput {
    pub node_id: usize,
    pub message: String,   // reconstructed value or "⊥"
    pub liar_caught: bool,
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

    pub fn identify_core(&self, whiteboard: &[Option<[u8; 32]>]) -> Vec<usize> {
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
    ) -> Vec<NodeOutput> {
        println!("\n--- Starting Round 2 (Verification & Reconstruction) ---");

        if core_set.is_empty() {
            println!("❌ No CORE set formed — outputting ⊥ for all honest nodes.");
            return self.nodes.iter()
                .filter(|n| n.behavior == Behavior::Honest)
                .map(|n| NodeOutput { node_id: n.id, message: "⊥".to_string(), liar_caught: false })
                .collect();
        }

        let agreed_root = oracle_whiteboard[core_set[0]].unwrap();

        // --- Modified Local Computation ---
        // Every honest node j picks its verified shard j from Round 1 messages
        // (sent by any CORE member), then broadcasts it in Round 2.
        let mut round2_broadcasts: Vec<VerifiedShard> = Vec::new();
        let mut liar_flags: Vec<bool> = vec![false; self.n];

        for node in self.nodes.iter().filter(|n| n.behavior == Behavior::Honest) {
            let j = node.id;
            // Find the first valid shard j sent by a CORE member to node j.
            for msg in all_p2p_messages {
                if msg.receiver_id != j { continue; }
                if msg.component_index != j { continue; }
                if !core_set.contains(&msg.sender_id) { continue; }

                let mut leaf_data = vec![j as u8];
                leaf_data.extend(&msg.component);
                let leaf_hash = Sha256::hash(&leaf_data);
                let proof = rs_merkle::MerkleProof::<Sha256>::new(msg.proof.clone());

                if proof.verify(agreed_root, &[j], &[leaf_hash], self.n) {
                    round2_broadcasts.push(VerifiedShard {
                        node_id: j,
                        component_index: j,
                        component: msg.component.clone(),
                        proof: msg.proof.clone(),
                    });
                    break;
                } else {
                    liar_flags[msg.sender_id] = true;
                }
            }
        }

        // --- Modified Round 2: Reconstruction ---
        // Every honest node reconstructs from the t+1 verified shards broadcast above.
        let mut all_outputs = Vec::new();

        for node in self.nodes.iter().filter(|n| n.behavior == Behavior::Honest) {
            let mut collected_shards: Vec<Option<Vec<u8>>> = vec![None; self.n];
            let mut verified_count = 0;

            for vs in &round2_broadcasts {
                if collected_shards[vs.component_index].is_some() { continue; }

                let mut leaf_data = vec![vs.component_index as u8];
                leaf_data.extend(&vs.component);
                let leaf_hash = Sha256::hash(&leaf_data);
                let proof = rs_merkle::MerkleProof::<Sha256>::new(vs.proof.clone());

                if proof.verify(agreed_root, &[vs.component_index], &[leaf_hash], self.n) {
                    collected_shards[vs.component_index] = Some(vs.component.clone());
                    verified_count += 1;
                }
            }

            let message = if verified_count >= self.t + 1 {
                let rs = ReedSolomon::new(self.t + 1, self.n - (self.t + 1)).unwrap();
                rs.reconstruct(&mut collected_shards).unwrap();
                let recovered: Vec<u8> = collected_shards[0..=self.t]
                    .iter().flatten().flatten().cloned().collect();
                String::from_utf8_lossy(&recovered).trim_matches(char::from(0)).to_string()
            } else {
                "⊥".to_string()
            };

            all_outputs.push(NodeOutput {
                node_id: node.id,
                message,
                liar_caught: liar_flags.iter().any(|&f| f),
            });
        }

        all_outputs
    }
}
