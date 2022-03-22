use std::time::{Duration, Instant};

use aes::Aes128;
use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

use crate::write_cipher_to_file;

pub fn aes_encrypt(plain_text: &[u8], sizename: &str, filename: &str) -> Duration {
    type Aes128CbcEncryptor = cbc::Encryptor<Aes128>;
    let key = [0x42u8; 16];
    let iv = [0x42u8; 16];
    
    let pt_len = plain_text.len();
    let padding_len = (1 + pt_len / 16) * 16;
    let mut buf = vec![0u8; padding_len];

    // buf[..pt_len].copy_from_slice(&plain_text);
    let ref mut slice = buf[..pt_len];
    slice.copy_from_slice(&plain_text);

    let now = Instant::now();
    
    let cipher_text = Aes128CbcEncryptor::new(&key.into(), &iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len).unwrap();

    let elapsed = now.elapsed();
    log::info!("aes128cbc {} {} encrypt elapsed: {:.2?}", sizename, filename, elapsed);
    write_cipher_to_file("aes", sizename, filename, cipher_text).unwrap();
    elapsed
    
    // println!("cipher text: {}", hex::encode(cipher_text));

    // let mut buf = [0u8; 48];
    // let cipher_text = Aes128CbcEncryptor::new(&key.into(), &iv.into())
    //     .encrypt_padded_b2b_mut::<Pkcs7>(&plain_text, &mut buf).unwrap();
    // assert_eq!(cipher_text, &std_cipher_text);

}

// pub fn aes_decrypt(cipher_text: &mut [u8]) {
//     type Aes128CbcDecryptor = cbc::Decryptor<Aes128>;
//     let key = [0x42u8; 16];
//     let iv = [0x24u8; 16];

//     let plain_text = Aes128CbcDecryptor::new(&key.into(), &iv.into())
//         .decrypt_padded_mut::<Pkcs7>(cipher_text).unwrap();
//     println!("plain text: {}", hex::encode(plain_text));

//     // let mut buf = [0u8; 48];
//     // let plain_text = Aes128CbcDecryptor::new(&key.into(), &iv.into())
//     //     .decrypt_padded_b2b_mut::<Pkcs7>(&cipher_text, &mut buf).unwrap();

//     // assert_eq!(plain_text, &plain_text);
// }

#[cfg(test)]
mod tests {
    use aes::{cipher::{KeyInit, BlockEncrypt, BlockDecrypt, generic_array::GenericArray}, Aes128};
    use hex_literal::hex;
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
    #[test]
    fn aes128_single_block_example() {
        let key = GenericArray::from([0u8; 16]);
        let mut block = GenericArray::from([42u8; 16]);

        // Initialize cipher
        let cipher = Aes128::new(&key);

        let block_copy = block.clone();

        // Encrypt block in-place
        cipher.encrypt_block(&mut block);

        // And decrypt it back
        cipher.decrypt_block(&mut block);
        assert_eq!(block, block_copy);

        // implementation supports parallel block processing
        // number of blocks processed in parallel depends in general
        // on hardware capabilities
        let mut blocks = [block; 100];
        cipher.encrypt_blocks(&mut blocks);

        for block in blocks.iter_mut() {
            cipher.decrypt_block(block);
            assert_eq!(block, &block_copy);
        }

        cipher.decrypt_blocks(&mut blocks);

        for block in blocks.iter_mut() {
            cipher.encrypt_block(block);
            assert_eq!(block, &block_copy);
        }
    }

    #[test]
    fn aes128_multi_block_example() {
        type Aes128CbcEncryptor = cbc::Encryptor<Aes128>;
        type Aes128CbcDecryptor = cbc::Decryptor<Aes128>;

        let std_cipher_text = hex!(
            "c7fe247ef97b21f07cbdd26cb5d346bf"
            "d27867cb00d9486723e159978fb9a5f9"
            "14cfb228a710de4171e396e7b6cf859e"
        );

        let key = [0x42u8; 16];
        let iv = [0x24u8; 16];
        let std_plain_text = *b"hello world! this is my plaintext.";
        
        let mut buf = [0u8; 48];
        let pt_len = std_plain_text.len();

        buf[..pt_len].copy_from_slice(&std_plain_text);
        
        let cipher_text = Aes128CbcEncryptor::new(&key.into(), &iv.into())
            .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len).unwrap();
        
        // assert_eq!(cipher_text, &buf);
        assert_eq!(cipher_text, &std_cipher_text);

        // println!("{:?}", cipher_text);
        // println!("{:?}", buf);

        let plain_text = Aes128CbcDecryptor::new(&key.into(), &iv.into())
            .decrypt_padded_mut::<Pkcs7>(&mut buf).unwrap();
        assert_eq!(plain_text, &std_plain_text);

        let mut buf = [0u8; 48];
        let cipher_text = Aes128CbcEncryptor::new(&key.into(), &iv.into())
            .encrypt_padded_b2b_mut::<Pkcs7>(&plain_text, &mut buf).unwrap();
        assert_eq!(cipher_text, &std_cipher_text);

        let mut buf = [0u8; 48];
        let plain_text = Aes128CbcDecryptor::new(&key.into(), &iv.into())
            .decrypt_padded_b2b_mut::<Pkcs7>(&cipher_text, &mut buf).unwrap();

        assert_eq!(plain_text, &std_plain_text);
    }


}