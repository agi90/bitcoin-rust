use std::collections::HashMap;
use super::messages::TxMessage;

pub struct TxStore {
    // TODO: move this to an ibrid disk-memory store
    store: HashMap<[u8; 32], TxMessage>,
}

impl TxStore {
    pub fn has(&self, hash: &[u8]) -> bool {
        self.store.get(hash).is_some()
    }

    pub fn get(&self, hash: &[u8]) -> Option<&TxMessage> {
        self.store.get(hash)
    }

    pub fn insert(&mut self, hash: [u8; 32], message: TxMessage) {
        self.store.insert(hash, message);
    }

    pub fn new() -> TxStore {
        TxStore {
            store: HashMap::new(),
        }
    }
}
