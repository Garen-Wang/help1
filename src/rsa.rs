use std::time::{Instant, Duration};

use rsa::PublicKey;

use crate::write_cipher_to_file;


pub fn rsa_encrypt(plain_text: &[u8], sizename: &str, filename: &str) -> Duration {
    let mut rng = rand::rngs::OsRng;
    let bit_size = 1024; // max length: 100
    let private_key = rsa::RsaPrivateKey::new(&mut rng, bit_size).unwrap();
    let public_key = rsa::RsaPublicKey::from(&private_key);

    let pt_len = plain_text.len();
    let mut cipher_text: Vec<u8> = vec![];

    let now = Instant::now();
    for i in (0..pt_len).step_by(100) {
        let upper_bound = (i+100).min(pt_len);
        let ref plain = plain_text[i..upper_bound];

        let mut cipher = public_key.encrypt(&mut rng, rsa::PaddingScheme::new_pkcs1v15_encrypt(), plain).unwrap();
        cipher_text.append(&mut cipher);
    }
    // let cipher_text = public_key.encrypt(&mut rng, rsa::PaddingScheme::new_pkcs1v15_encrypt(), &plain_text[..]).unwrap();

    let elapsed = now.elapsed();
    // println!("rsa {} {} encrypt elapsed: {:.2?}", sizename, filename, elapsed);
    log::info!("rsa {} {} encrypt elapsed: {:.2?}", sizename, filename, elapsed);

    write_cipher_to_file("rsa", sizename, filename, &cipher_text).unwrap();
    elapsed

    // let path = ["rsa", filename].iter().collect::<PathBuf>();
    // let mut cipher_file = fs::File::create(path).unwrap();
    // cipher_file.write_all(&cipher_text).unwrap();

    // println!("{:?}", cipher_text);
}

#[cfg(test)]
mod tests {
    use rsa::PublicKey;

    #[test]
    fn rsa_example() {
        let mut rng = rand::rngs::OsRng;
        // let bit_size = 2048;
        let bit_size = 1024;
        let private_key = rsa::RsaPrivateKey::new(&mut rng, bit_size).unwrap();
        let public_key = rsa::RsaPublicKey::from(&private_key);

        let plain_text = b"hello world! hello world!";
        let cipher_text = public_key.encrypt(&mut rng, rsa::PaddingScheme::new_pkcs1v15_encrypt(), &plain_text[..]).unwrap();
        println!("{:?}", cipher_text);

        // let decrypted = private_key.decrypt(rsa::PaddingScheme::new_pkcs1v15_encrypt(), &cipher_text).unwrap();
        // println!("{:?}", decrypted);
    }

}