use std::io;

pub use sha2;

use sha2::Sha256;

pub struct Salt {
    pub salt: Vec<u8>,
}

impl Salt {
    pub fn from_slice(s: &[u8]) -> Self {
        let mut salt: Vec<u8> = Vec::with_capacity(s.len());
        salt.extend_from_slice(s);
        Self { salt }
    }
}

pub struct Info {
    pub info: Vec<u8>,
}

impl Info {
    pub fn from_slice(s: &[u8]) -> Self {
        let mut info: Vec<u8> = Vec::with_capacity(s.len());
        info.extend_from_slice(s);
        Self { info }
    }
}

pub struct Ikm {
    secret: Vec<u8>,
}

impl Ikm {
    pub fn from_secret(secret: Vec<u8>) -> Self {
        Self { secret }
    }

    pub fn from_slice(secret: &[u8]) -> Self {
        let mut s: Vec<u8> = Vec::with_capacity(secret.len());
        s.extend_from_slice(secret);
        Self { secret: s }
    }
}

impl Ikm {
    pub fn derive_key(&self, salt: &Salt, info: &Info, key: &mut [u8]) -> Result<(), io::Error> {
        let hk = hkdf::Hkdf::<Sha256>::new(Some(&salt.salt), &self.secret);
        hk.expand(&info.info, key)
            .map_err(|_| "unable to derive key")
            .map_err(io::Error::other)?;
        Ok(())
    }
}

pub struct Pepper {
    secret: Vec<u8>,
}

impl Pepper {
    pub fn from_secret(secret: [u8; 32]) -> Self {
        let mut s: Vec<u8> = Vec::with_capacity(32);
        s.extend_from_slice(&secret);
        Self { secret: s }
    }

    pub fn from_slice(secret: &[u8]) -> Self {
        let mut s: Vec<u8> = Vec::with_capacity(secret.len());
        s.extend_from_slice(secret);
        Self { secret: s }
    }
}

impl Pepper {
    pub fn into_ikm(self, original: &Ikm) -> Ikm {
        let mut secret: Vec<u8> = self.secret;
        secret.extend_from_slice(&original.secret);
        Ikm { secret }
    }
}
