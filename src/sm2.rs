use std::{fs, io::Write, time::{Duration, Instant}};

use smcrypto::sm2;

use crate::write_cipher_to_file;

pub fn sm2_generate_key_pair() -> std::io::Result<()> {
    let (private_key, public_key) = sm2::gen_keypair();
    let mut private_key_file = fs::File::create("sm2/private.pem")?;
    let mut public_key_file = fs::File::create("sm2/public.pem")?;
    private_key_file.write_all(private_key.as_bytes())?;
    public_key_file.write_all(public_key.as_bytes())?;
    Ok(())
}

fn read_key_pair() -> std::io::Result<(String, String)> {
    let private_key = fs::read_to_string("sm2/private.pem")?;
    let public_key = fs::read_to_string("sm2/public.pem")?;
    Ok((private_key, public_key))
}

pub fn sm2_encrypt(plain_text: &[u8], sizename: &str, filename: &str) -> Duration {
    let (private_key, public_key) = read_key_pair().unwrap();
    let sm2 = sm2::CryptSM2::new(&private_key, &public_key, 1);

    let now = Instant::now();
    let cipher_text = sm2.encrypt(&plain_text);
    let elapsed = now.elapsed();
    log::info!("sm2 {} {} encrypt elapsed: {:.2?}", sizename, filename, elapsed);

    write_cipher_to_file("sm2", sizename, filename, cipher_text.as_bytes()).unwrap();
    elapsed
    // println!("{}", cipher_text);

    // let plain_text = sm2.decrypt(cipher_text);
}

#[cfg(test)]
mod tests {
    use rand::RngCore;

    #[test]
    fn sm2_sign_example() {
        let plain_text = b"hello world!";
        let mut private_key = [0; 32];
        rand::thread_rng().fill_bytes(&mut private_key);
        let key_pair = efficient_sm2::KeyPair::new(&private_key).unwrap();

        let sig = key_pair.sign(plain_text).unwrap();

        sig.verify(&key_pair.public_key(), plain_text).unwrap();
    }

    #[test]
    fn sm2_encrypt_example() {
        use smcrypto::sm2;
        let (private_key, public_key) = sm2::gen_keypair();
        let sm2 = sm2::CryptSM2::new(&private_key, &public_key, 1);

        let std_plain_text = *b"hello hello hello hello sb";

        let cipher_text = sm2.encrypt(&std_plain_text);

        println!("{}", cipher_text);

        let plain_text = sm2.decrypt(cipher_text);
        assert_eq!(plain_text, std_plain_text);
    }
}