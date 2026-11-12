use rs_merkle::{algorithms::Sha256, Hasher, MerkleTree};
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Behavior {
    Honest,
    Mute,
    Liar,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifiedShard {
    pub node_id: usize,
    pub component_index: usize,
    pub component: Vec<u8>,
    pub proof: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2PMessage {
    pub sender_id: usize,
    pub receiver_id: usize,
    pub component_index: usize,
    pub component: Vec<u8>,
    pub proof: Vec<[u8; 32]>,
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
                receiver_id: j,
                component_index: j,
                component: sent_shard,
                proof: proof.proof_hashes().to_vec(),
            });
        }
        (root, messages)
    }
}
