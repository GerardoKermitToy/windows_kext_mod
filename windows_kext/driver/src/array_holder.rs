use alloc::vec::Vec;

pub struct ArrayHolder(Option<Vec<u8>>);

impl ArrayHolder {
    pub const fn default() -> Self {
        Self(None)
    }

    pub fn save(&mut self, data: &[u8]) {
        self.0 = Some(data.to_vec());
    }

    pub fn load(&mut self) -> Option<Vec<u8>> {
        self.0.take()
    }
}
