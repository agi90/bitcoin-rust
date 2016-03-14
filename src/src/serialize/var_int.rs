use super::{VarInt, Serialize, Serializer, Deserialize, Deserializer};

impl VarInt {
    pub fn new(data: u64) -> VarInt {
        VarInt {
            data: data,
        }
    }

    pub fn as_u64(&self) -> u64 {
        self.data
    }
}

impl Serialize for VarInt {
    fn serialize(&self, serializer: &mut Serializer) {
        let data = serializer.to_bytes(self.data);

        match self.data {
            0x00000...0x0000000fc => {
                serializer.push(data[0])
            },
            0x000fd...0x00000ffff => {
                serializer.push(0xfd);
                serializer.push_bytes(&data[0..2]);
            },
            0x10000...0x0ffffffff => {
                serializer.push(0xfe);
                serializer.push_bytes(&data[0..4]);
            },
            _ => {
                serializer.push(0xff);
                serializer.push_bytes(&data[0..8]);
            },
        };
    }
}

impl Deserialize for VarInt {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, String> {
        let mut data = [0; 1];
        try!(deserializer.read_ex(&mut data));

        if data[0] < 0xfd {
            return Ok(VarInt::new(data[0] as u64));
        }

        let bytes = match data[0] {
            0xfd => 2,
            0xfe => 4,
            0xff => 8,
            _    => 0,
        };

        Ok(VarInt::new(try!(deserializer.to_u_fixed(bytes))))
    }
}

