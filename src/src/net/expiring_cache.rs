use std::collections::HashMap;
use time;
use time::SteadyTime;

use std::hash::Hash;
use std::mem;

pub struct ExpiringCache<V> {
    store: HashMap<V, time::SteadyTime>,
    timeout: time::Duration,
    checking_interval: time::Duration,
    last_checked: time::SteadyTime,
}

impl<V: Eq + Hash + Clone> ExpiringCache<V> {
    pub fn new(timeout: time::Duration, checking_interval: time::Duration) -> ExpiringCache<V> {
        ExpiringCache {
            store: HashMap::new(),
            timeout: timeout,
            checking_interval: checking_interval,
            last_checked: SteadyTime::now(),
        }
    }

    fn check_expiration(&mut self) {
        let now = SteadyTime::now();

        if self.last_checked + self.checking_interval > now {
            return;
        }

        println!("CHECKING! len = {:?}", self.store.len());
        let mut store = mem::replace(&mut self.store, HashMap::new());

        store = store.into_iter()
            .filter(|el| el.1 > now)
            .collect();

        mem::replace(&mut self.store, store);

        println!("END CHECKING! len = {:?}", self.store.len());
        self.last_checked = SteadyTime::now();
    }

    pub fn insert(&mut self, key: V) {
        self.check_expiration();
        self.store.insert(key, SteadyTime::now() + self.timeout);
    }

    pub fn has(&mut self, key: &V) -> bool {
        self.check_expiration();
        self.store.get(key).is_some()
    }

    pub fn remove(&mut self, key: &V) {
        self.check_expiration();
        self.store.remove(key);
    }

    pub fn len(&self) -> usize { self.store.len() }
}

