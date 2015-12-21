use std::collections::HashMap;
use std::fs::File;
use std::io::Write;

use super::messages::{BlockMetadata, NetworkType, BlockMessage, Serialize,
                      Deserialize, BitcoinHash};

use std::io::{Seek, SeekFrom};

pub struct BlockBlobStore {
    store: HashMap<BitcoinHash, (BlockMetadata, usize)>,
    disk_store: File,
    last_index: usize,
}

impl BlockBlobStore {
    pub fn has(&self, hash: &BitcoinHash) -> bool {
        self.store.get(hash).is_some()
    }

    pub fn get(&self, hash: &BitcoinHash) -> Option<&BlockMetadata> {
        self.store.get(hash).map(|data| &data.0)
    }

    pub fn get_block(&mut self, hash: &BitcoinHash) -> Option<BlockMessage> {
        self.store.get(hash).map(|data| data.1)
            .map(|pos| {
                self.disk_store.seek(SeekFrom::Start(pos as u64)).unwrap();

                let length: u64        = Deserialize::deserialize(&mut self.disk_store).unwrap();
                let hash: BitcoinHash  = Deserialize::deserialize(&mut self.disk_store).unwrap();
                let block: BlockMessage= Deserialize::deserialize(&mut self.disk_store).unwrap();

                let (serialized, real_hash) = block.serialize_hash();

                assert_eq!(serialized.len() as u64, length);
                assert_eq!(hash, real_hash);

                block
            })
    }

    pub fn insert(&mut self, block: BlockMessage, hash: &BitcoinHash, data: &[u8]) {
        if self.store.get(hash).is_none() {
            // Let's save the length and hash to double check data on disk
            (data.len() as u64).serialize(&mut self.disk_store);
            self.disk_store.write_all(hash.inner()).unwrap();
            self.disk_store.write_all(data).unwrap();

            self.store.insert(hash.clone(), (block.into_metadata(), self.last_index));

            self.disk_store.sync_all().unwrap();
            self.last_index += 0;
        }
    }

    fn get_next_object(file: &mut File) ->
        Result<(u64, BitcoinHash, BlockMetadata), String> {
        let pos = file.seek(SeekFrom::Current(0)).unwrap();
        let length: u64 = try!(Deserialize::deserialize(file));
        let hash: BitcoinHash = try!(Deserialize::deserialize(file));
        let data: BlockMetadata = try!(Deserialize::deserialize(file));

        match file.seek(SeekFrom::Current((length - 80) as i64)) {
            Ok(_) => {},
            Err(_) => {
                // Let's truncate the file, the client probably crashed mid-writing
                println!("Truncating to {}", pos);
                file.set_len(pos).unwrap();
            }
        }

        Ok((length, hash, data))
    }

    pub fn new(disk_store_: File) -> BlockBlobStore {
        let mut disk_store = disk_store_;

        let mut store = HashMap::new();
        loop {
            let pos = disk_store.seek(SeekFrom::Current(0)).unwrap();
            let next = Self::get_next_object(&mut disk_store);
            match next {
                Ok((_, hash, block_header)) => {
                    store.insert(hash, (block_header, pos as usize));
                },
                Err(_) => {
                    break;
                }
            }
        }

        let last_index = disk_store.seek(SeekFrom::Current(0)).unwrap();
        BlockBlobStore {
            store: store,
            disk_store: disk_store,
            last_index: last_index as usize,
        }
    }
}

pub struct BlockStore {
    store: BlockBlobStore,
    height_store_rev: HashMap<BitcoinHash, usize>,
    height_store: Vec<BitcoinHash>,
    highest_block: BitcoinHash,
}

impl BlockStore {
    pub fn has(&self, hash: &BitcoinHash) -> bool { self.store.has(hash) }

    pub fn get_metadata(&self, hash: &BitcoinHash) -> Option<&BlockMetadata> {
        self.store.get(hash)
    }

    pub fn get_height(&self, hash: &BitcoinHash) -> Option<usize> {
        self.height_store_rev.get(hash).cloned()
    }

    pub fn height(&self) -> usize { self.height_store_rev[&self.highest_block] }

    pub fn insert(&mut self, block: BlockMessage, hash: &BitcoinHash, data: &[u8]) {
        self.store.insert(block, hash, data);

        self.highest_block =
            Self::insert_chain(hash, &self.store, &mut self.height_store_rev,
                               &mut self.height_store, self.highest_block);
    }

    fn reload_chain(&mut self) {
        for (ref hash, _) in self.store.store.iter() {
            self.highest_block =
                Self::insert_chain(hash, &self.store, &mut self.height_store_rev,
                                   &mut self.height_store, self.highest_block);
        }
    }

    pub fn block_locators(&self) -> Vec<BitcoinHash> {
        let height = self.height();
        let mut index = 0;
        let mut locator = vec![];

        while height > index {
            locator.push(self.height_store[height - index]);
            if index < 10 {
                index += 1;
            } else {
                index *= 2;
            }
        }

        locator.push(self.height_store[0]);
        locator
    }

    // TODO: this function is static because of the borrow checker, we need to run this function
    // both when receiving a new block from the network and when reading blocks from disk.
    // Unfortunately we cannot borrow self as mutable (for height_store_rev) and as immutable (for
    // store) so this function cannot be non-static until rust supports partial borrows. Maybe
    // double check if there are other possibilities.
    fn insert_chain(hash: &BitcoinHash,
                    store: &BlockBlobStore,
                    height_store_rev: &mut HashMap<BitcoinHash, usize>,
                    height_store: &mut Vec<BitcoinHash>,
                    highest_block: BitcoinHash) -> BitcoinHash {
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
                    valid_chain = false;
                    break;
                },
                Some(x) => {
                    chain.push(prev_hash);
                    prev_hash = &x.prev_block;
                }
            }
        }

        // Only update the best chain if the resulting chain is going to be
        // longer.
        if valid_chain && chain.len() + new_height > height {
            for el in chain.iter().rev() {
                new_height += 1;
                new_highest_block = **el;

                println!("New height: {:?}. {:?}", new_height, new_highest_block);

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
        let genesis = BitcoinHash::new(match network_type {
            NetworkType::TestNet3 =>
                [0x43, 0x49, 0x7F, 0xD7, 0xF8, 0x26, 0x95, 0x71,
                 0x08, 0xF4, 0xA3, 0x0F, 0xD9, 0xCE, 0xC3, 0xAE,
                 0xBA, 0x79, 0x97, 0x20, 0x84, 0xE9, 0x0E, 0xAD,
                 0x01, 0xEA, 0x33, 0x09, 0x00, 0x00, 0x00, 0x00],
            NetworkType::Main =>
                [0x6F, 0xE2, 0x8C, 0x0A, 0xB6, 0xF1, 0xB3, 0x72,
                 0xC1, 0xA6, 0xA2, 0x46, 0xAE, 0x63, 0xF7, 0x4F,
                 0x93, 0x1E, 0x83, 0x65, 0xE1, 0x5A, 0x08, 0x9C,
                 0x68, 0xD6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00],
            NetworkType::TestNet =>  unimplemented!(),
            NetworkType::NameCoin => unimplemented!(),
            NetworkType::Unknown =>  unreachable!(),
        });

        let mut store = BlockStore {
            store: BlockBlobStore::new(disk_store),
            height_store_rev: HashMap::new(),
            height_store: vec![genesis],
            highest_block: genesis,
        };

        store.height_store_rev.insert(genesis, 0);
        store.reload_chain();

        store
    }
}
