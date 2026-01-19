// Secure memory management
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

pub struct SecureMemory {
    data: Vec<u8>,
}

impl SecureMemory {
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0u8; size],
        }
    }
    
    pub fn from_data(data: Vec<u8>) -> Self {
        Self { data }
    }
    
    pub fn zero(&mut self) {
        for byte in &mut self.data {
            *byte = 0;
        }
    }
    
    pub fn len(&self) -> usize {
        self.data.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Drop for SecureMemory {
    fn drop(&mut self) {
        // Overwrite with random data multiple times
        use ring::rand::SystemRandom;
        let mut rng = SystemRandom::new();
        
        for _ in 0..3 {
            for byte in &mut self.data {
                *byte = rng.next_u32() as u8;
            }
        }
        
        // Final zero
        self.zero();
    }
}

impl Deref for SecureMemory {
    type Target = [u8];
    
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for SecureMemory {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

pub struct SecureString {
    inner: SecureMemory,
}

impl SecureString {
    pub fn new(s: &str) -> Self {
        Self {
            inner: SecureMemory::from_data(s.as_bytes().to_vec()),
        }
    }
    
    pub fn from_secure_memory(mem: SecureMemory) -> Self {
        Self { inner: mem }
    }
    
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.inner).unwrap()
    }
    
    pub fn into_secure_memory(self) -> SecureMemory {
        self.inner
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        // Ensure secure erasure
        self.inner.zero();
    }
}

impl std::fmt::Display for SecureString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::fmt::Debug for SecureString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureString({} bytes)", self.inner.len())
    }
}