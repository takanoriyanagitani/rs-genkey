use std::io;

use io::Read;

use std::fs::File;

use rs_genkey::sha2;

use sha2::Digest;
use sha2::Sha256;

use rs_genkey::Ikm;
use rs_genkey::Info;
use rs_genkey::Pepper;
use rs_genkey::Salt;

fn env_val_by_key(key: &'static str) -> Result<String, io::Error> {
    std::env::var(key)
        .map_err(|e| format!("env var {key} missing: {e}"))
        .map_err(io::Error::other)
}

fn env2ikm_location() -> Result<String, io::Error> {
    env_val_by_key("ENV_IN_SECRET_IKM_LOCATION")
}

fn env2pepper_location() -> Result<String, io::Error> {
    env_val_by_key("ENV_IN_SECRET_PEPPER_LOCATION")
}

fn env2salt_location() -> Result<String, io::Error> {
    env_val_by_key("ENV_IN_PUBLIC_SALT_LOCATION")
}

fn env2info_location() -> Result<String, io::Error> {
    env_val_by_key("ENV_IN_PUBLIC_INFO_LOCATION")
}

fn limit2filename2bytes(limit: u64) -> impl Fn(String) -> Result<Vec<u8>, io::Error> {
    move |filename: String| {
        let f: File = File::open(filename)?;
        let mut taken = f.take(limit);
        let mut buf: Vec<u8> = vec![];
        taken.read_to_end(&mut buf)?;
        Ok(buf)
    }
}

fn env2ikm() -> Result<Ikm, io::Error> {
    let loc: String = env2ikm_location()?;
    let raw: Vec<u8> = limit2filename2bytes(32)(loc)?;
    Ok(Ikm::from_slice(&raw))
}

fn env2pepper() -> Result<Pepper, io::Error> {
    let loc: String = env2pepper_location()?;
    let raw: Vec<u8> = limit2filename2bytes(32)(loc)?;
    Ok(Pepper::from_slice(&raw))
}

fn env2salt() -> Result<Salt, io::Error> {
    let loc: String = env2salt_location()?;
    let raw: Vec<u8> = limit2filename2bytes(32)(loc)?;
    Ok(Salt { salt: raw })
}

fn env2info() -> Result<Info, io::Error> {
    let loc: String = env2info_location()?;
    let raw: Vec<u8> = limit2filename2bytes(32)(loc)?;
    Ok(Info { info: raw })
}

fn sub() -> Result<(), io::Error> {
    let s: Salt = env2salt()?;
    let i: Info = env2info()?;
    let k: Ikm = env2ikm()?;
    let p: Pepper = env2pepper()?;
    let k: Ikm = p.into_ikm(&k);

    let mut key: [u8; 32] = [0; 32];
    k.derive_key(&s, &i, &mut key)?;

    let hash = Sha256::digest(key);

    println!("digest of the derived key: {:x}", hash);

    Ok(())
}

fn main() {
    sub().unwrap()
}
