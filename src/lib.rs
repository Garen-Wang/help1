#[allow(dead_code)]
pub mod sm2;
pub mod sm4;
pub mod aes;
pub mod rsa;

use std::{fs, io::Write, path::PathBuf, time::Instant};

fn create_msg_to_file(sizename: &str, filename: &str, size: usize) -> std::io::Result<()> {
    let filename = ["msg", sizename, filename].iter().collect::<PathBuf>();
    if filename.exists() {
        // println!("{:?} has existed", filename.as_os_str());
        // log::info!("{:?} has existed", filename.as_os_str());
        return Ok(());
    }
    let now = Instant::now();
    let mut file = fs::File::create(filename)?;

    // 1. fixed values
    // let mut buf = vec![0x42u8; size];

    // 2. random values
    let mut buf: Vec<u8> = (0..size).map(|_| rand::random::<u8>() ).collect();

    file.write_all(&mut buf)?;
    let elapsed = now.elapsed();
    // println!("generate {} file cost {:.2?}", sizename, elapsed);
    log::info!("generate {} file cost {:.2?}", sizename, elapsed);
    Ok(())
}

pub fn create_msg_for_size(sizename: &str, size: usize) -> std::io::Result<()> {
    let dir = ["msg", sizename].iter().collect::<PathBuf>();
    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }
    for i in 0..10 {
        let filename = format!("{}.txt", i);
        create_msg_to_file(sizename, &filename, size)?;
    }
    Ok(())
}

pub fn read_msg_from_file(sizename: &str, filename: &str) -> std::io::Result<Vec<u8>> {
    let path = ["msg", sizename, filename].iter().collect::<PathBuf>();
    fs::read(path)
}

pub fn write_cipher_to_file(cipher_type: &str, sizename: &str, filename: &str, cipher_text: &[u8]) -> std::io::Result<()> {
    let dir = [cipher_type, sizename].iter().collect::<PathBuf>();
    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }
    let path = [cipher_type, sizename, filename].iter().collect::<PathBuf>();
    let mut file = fs::File::create(path)?;
    file.write_all(cipher_text)?;
    Ok(())
}

