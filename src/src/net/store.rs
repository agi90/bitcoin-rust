use std::collections::HashMap;
use std::fs::File;

use super::messages::Serialize;
use super::messages::Deserialize;
use super::messages::Deserializer;

use utils::Debug;

enum Entry<T> {
    NotCached(usize),
    Cached(usize, T),
}

pub struct BlobStore<T: Serialize + Deserialize<File> + Sized> {
    store: HashMap<[u8; 32], Entry<T>>,
    disk_store: File,
    last_index: usize,
}

impl<T: Serialize + Deserialize<File>> BlobStore<T> {
    pub fn has(&self, hash: &[u8]) -> bool {
        self.store.get(hash).is_some()
    }

    pub fn get(&self, hash: &[u8]) -> Option<&T> {
        self.store.get(hash).map(|entry| {
            match entry {
                &Entry::Cached(_, ref blob) => blob,
                &Entry::NotCached(_)        => unimplemented!(),
            }
        })
    }

    pub fn insert(&mut self, blob: T) {
        if self.store.get(&blob.hash()).is_none() {
            let (serialized, hash) = blob.serialize_hash();
            print!("hash = ");
            Debug::print_bytes(&hash);

            // Let's save the length and hash to double check data on disk
            (serialized.len() as u64).serialize(&mut self.disk_store, &[]);
            hash.serialize(&mut self.disk_store, &[]);
            serialized.serialize(&mut self.disk_store, &[]);

            self.store.insert(blob.hash(),
                              Entry::Cached(self.last_index, blob));

            self.disk_store.sync_all().unwrap();

            self.last_index += 0;
        }
    }

    fn get_next_object(deserializer: &mut Deserializer<File>) -> Result<(u64, [u8; 32], T), String> {
        let length: u64    = try!(Deserialize::deserialize(deserializer, &[]));
        let hash: [u8; 32] = try!(Deserialize::deserialize(deserializer, &[]));
        let data: T        = try!(Deserialize::deserialize(deserializer, &[]));

        Ok((length, hash, data))
    }

    pub fn new(disk_store: File) -> BlobStore<T> {
        let mut deserializer = Deserializer::new(disk_store);
        let mut store = HashMap::new();
        loop {
            let pos = deserializer.pos();
            let next = Self::get_next_object(&mut deserializer);
            match next {
                Ok((_, hash, data)) => {
                    assert_eq!(data.hash(), hash);
                    store.insert(hash, Entry::Cached(pos, data));
                },
                Err(x) => {
                    println!("Error: {:?}", x);
                    break;
                }
            }
        }

        let file = deserializer.into_inner();
        println!("file = {:?}", file);
        println!("Store size = {:?}", store.len());
        BlobStore {
            store: store,
            disk_store: file,
            last_index: 0,
        }
    }
}
