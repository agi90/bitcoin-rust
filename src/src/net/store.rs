use std::collections::HashMap;
use std::fs::File;

use super::messages::NetworkType;
use super::messages::BlockMessage;
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

pub struct BlockStore {
    store: BlobStore<BlockMessage>,
    height_store_rev: HashMap<[u8; 32], usize>,
    height_store: Vec<[u8; 32]>,
    highest_block: [u8; 32],
}

impl BlockStore {
    pub fn has(&self, hash: &[u8; 32]) -> bool { self.store.has(hash) }

    pub fn height(&self) -> usize { self.height_store_rev[&self.highest_block] }

    pub fn insert(&mut self, block: BlockMessage) {
        let hash = block.hash();
        self.store.insert(block);

        self.highest_block =
            Self::insert_chain(&hash, &self.store, &mut self.height_store_rev,
                               &mut self.height_store, self.highest_block);
    }

    fn reload_chain(&mut self) {
        for (ref hash, _) in self.store.store.iter() {
            self.highest_block =
                Self::insert_chain(hash, &self.store, &mut self.height_store_rev,
                                   &mut self.height_store, self.highest_block);
        }
    }

    pub fn block_locators(&self) -> Vec<[u8; 32]> {
        let height = self.height();
        let mut index = 0;
        let mut locator = vec![];

        println!("height {}", height);
        while height > index {
            locator.push(self.height_store[height - index]);
            println!("locator {}", height - index);
            if index < 10 {
                index += 1;
            } else {
                index *= 2;
            }
        }

        println!("locator {}", 0);
        locator.push(self.height_store[0]);
        locator
    }

    // TODO: this function is static because of the borrow checker, we need to run this function
    // both when receiving a new block from the network and when reading blocks from disk.
    // Unfortunately we cannot borrow self as mutable (for height_store_rev) and as immutable (for
    // store) so this function cannot be non-static until rust supports partial borrows. Maybe
    // double check if there are other possibilities.
    fn insert_chain(hash: &[u8; 32],
                    store: &BlobStore<BlockMessage>,
                    height_store_rev: &mut HashMap<[u8; 32], usize>,
                    height_store: &mut Vec<[u8; 32]>,
                    highest_block: [u8; 32]) -> [u8; 32] {
        let height = height_store_rev[&highest_block];
        let mut new_height = 0;
        let mut chain = vec![];
        let mut prev_hash = hash;
        let mut valid_chain = true;
        let mut new_highest_block = highest_block;

        loop {
            if let Some(prev_height) = height_store_rev.get(prev_hash) {
                new_height = *prev_height;
                break;
            }

            let el = store.get(prev_hash);

            match el {
                None => {
                    println!("Error: invalid chain!");
                    valid_chain = false;
                    break;
                },
                Some(x) => {
                    chain.push(prev_hash);
                    prev_hash = x.prev_block();
                }
            }
        }

        // Only update the best chain if the resulting chain is going to be
        // longer.
        if valid_chain && chain.len() + new_height > height {
            for el in chain.iter().rev() {
                new_height += 1;
                new_highest_block = **el;

                print!("New height: {:?}. ", new_height);
                Debug::print_bytes(&new_highest_block);

                height_store_rev.insert(new_highest_block, new_height);
                if new_height >= height_store.len() {
                    height_store.push(new_highest_block);
                } else {
                    height_store[new_height] = new_highest_block;
                }
            }
        }

        if new_height > height {
            new_highest_block
        } else {
            highest_block
        }
    }

    pub fn new(disk_store: File, network_type: NetworkType) -> BlockStore {
        let genesis = match network_type {
            NetworkType::TestNet3 =>
                [0x06, 0x12, 0x8E, 0x87, 0xBE, 0x8B, 0x1B, 0x4D,
                 0xEA, 0x47, 0xA7, 0x24, 0x7D, 0x55, 0x28, 0xD2,
                 0x70, 0x2C, 0x96, 0x82, 0x6C, 0x7A, 0x64, 0x84,
                 0x97, 0xE7, 0x73, 0xB8, 0x00, 0x00, 0x00, 0x00],
            NetworkType::Main =>
                [0x48, 0x60, 0xEB, 0x18, 0xBF, 0x1B, 0x16, 0x20,
                 0xE3, 0x7E, 0x94, 0x90, 0xFC, 0x8A, 0x42, 0x75,
                 0x14, 0x41, 0x6F, 0xD7, 0x51, 0x59, 0xAB, 0x86,
                 0x68, 0x8E, 0x9A, 0x83, 0x00, 0x00, 0x00, 0x00],
            NetworkType::TestNet =>  unimplemented!(),
            NetworkType::NameCoin => unimplemented!(),
            NetworkType::Unknown =>  unreachable!(),
        };

        let mut store = BlockStore {
            store: BlobStore::new(disk_store),
            height_store_rev: HashMap::new(),
            height_store: vec![genesis],
            highest_block: genesis,
        };

        store.height_store_rev.insert(genesis, 0);
        store.reload_chain();

        store
    }
}
