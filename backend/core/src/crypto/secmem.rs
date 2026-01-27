pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn into_inner(mut self) -> Vec<u8> {
        let mut out = Vec::new();
        std::mem::swap(&mut out, &mut self.data);
        out
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        for byte in &mut self.data {
            *byte = 0;
        }
    }
}
