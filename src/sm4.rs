use std::time::{Duration, Instant};
use hex_literal::hex;
use sm4::Sm4;
use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

use crate::write_cipher_to_file;

pub fn sm4_encrypt(plain_text: &[u8], sizename: &str, filename: &str) -> Duration {
    type Sm4CbcEncryptor = cbc::Encryptor<Sm4>;
    
    let key = hex!("0123456789abcdeffedcba9876543210"); // 16 bytes
    let iv = hex!("fedcba98765432100123456789abcdef");

    let pt_len = plain_text.len();
    let padding_len = (1 + pt_len / 16) * 16;
    let mut buf = vec![0u8; padding_len];

    buf[..pt_len].copy_from_slice(&plain_text);

    let now = Instant::now();

    let cipher_text = Sm4CbcEncryptor::new(
        &key.into(),
        &iv.into(),
    ).encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len).unwrap();

    let elapsed = now.elapsed();
    log::info!("sm4 {} {} encrypt elapsed: {:.2?}", sizename, filename, elapsed);

    write_cipher_to_file("sm4", sizename, filename, cipher_text).unwrap();
    elapsed
}

#[cfg(test)]

mod tests {
    use aes::cipher::{KeyInit, BlockEncrypt, BlockDecrypt};
    use hex_literal::hex;
    use sm4::Sm4;
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

    #[test]
    fn sm4_single_block_example() {
        // let key = hex!("deadbeef");
        let key = hex!("0123456789abcdeffedcba9876543210"); // 16 bytes
        let plain_text = hex!("0123456789abcdeffedcba9876543210"); // 16 bytes
        let cipher_text = hex!("681EDF34D206965E86B3E94F536E4246"); // 16 bytes
        let cipher = Sm4::new(&key.into());
        let mut block = plain_text.clone().into();
        cipher.encrypt_block(&mut block);
        // println!("{:?}", block.as_slice());
        assert_eq!(cipher_text, block.as_slice());

        cipher.decrypt_block(&mut block);
        assert_eq!(plain_text, block.as_slice());
    }

    #[test]
    fn sm4_multi_block_example() {
        type Sm4CbcEncryptor = cbc::Encryptor<Sm4>;
        type Sm4CbcDecryptor = cbc::Decryptor<Sm4>;
        
        let std_plain_text = *b"hello world! this is my plaintext."; // 34 bytes
        let std_cipher_text = hex!("a60ac531bf16f1a66b344f01e06a65441b25efd134ae164cfb289dad5770b4f9a9ceeeb83faa20b5cbc8ec765782c0bf");
        
        let mut buf = [0u8; 48];
        let pt_len = std_plain_text.len();

        let key = hex!("0123456789abcdeffedcba9876543210"); // 16 bytes
        let iv = hex!("fedcba98765432100123456789abcdef");

        buf[..pt_len].copy_from_slice(&std_plain_text);

        let cipher_text = Sm4CbcEncryptor::new(
            &key.into(),
            &iv.into(),
        ).encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len).unwrap();

        // println!("{}", hex::encode(&cipher_text));
        assert_eq!(cipher_text, &std_cipher_text);

        let plain_text = Sm4CbcDecryptor::new(
            &key.into(),
            &iv.into(),
        ).decrypt_padded_mut::<Pkcs7>(&mut buf).unwrap();

        assert_eq!(plain_text, &std_plain_text);

        let mut buf = [0u8; 48];
        let cipher_text = Sm4CbcEncryptor::new(&key.into(), &iv.into())
            .encrypt_padded_b2b_mut::<Pkcs7>(&plain_text, &mut buf).unwrap();
        assert_eq!(cipher_text, &std_cipher_text);

        let mut buf = [0u8; 48];
        let plain_text = Sm4CbcDecryptor::new(&key.into(), &iv.into())
            .decrypt_padded_b2b_mut::<Pkcs7>(&cipher_text, &mut buf).unwrap();

        assert_eq!(plain_text, &std_plain_text);
    }
}