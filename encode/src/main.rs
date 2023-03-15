use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand_core::{OsRng, RngCore};
use hex;
use std::fs::File;
use std::io::Read;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

const KEY: &[u8; 16] = b"abcdedghijklmnop"; // 模拟密钥，请勿在实际程序中使用
const XOR_KEY: &[u8] = b"mysecretkey"; // XOR 密钥


/// 生成随机 iv
fn generate_iv() -> [u8; 16] {
    let mut rng = OsRng;
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);

    bytes
}

fn xor_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    for (i, byte) in data.iter().enumerate() {
        result.push(byte ^ key[i % key.len()]);
    }
    result
}

fn xor_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    xor_encrypt(data, key)
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(data: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(data)
}

/// 加密
pub fn encrypt(plain: &[u8]) -> (Vec<u8>, [u8; 16]) {
    let iv = generate_iv();

    let mut buf = vec![0u8; plain.len() + 16]; // 将 buf 数组长度修改为 plain.len() + 16
    let ct = Aes128CbcEnc::new(KEY.into(), &iv.into())
        .encrypt_padded_b2b_mut::<Pkcs7>(plain, &mut buf)
        .unwrap();

    (ct.to_vec(), iv)
}

/// 解密
pub fn decrypt(cipher: &[u8], iv: [u8; 16]) -> Vec<u8> {
    let mut buf = vec![0u8; cipher.len() + 16]; // 将 buf 数组长度修改为 cipher.len() + 16
    let pt = Aes128CbcDec::new(KEY.into(), &iv.into())
        .decrypt_padded_b2b_mut::<Pkcs7>(cipher, &mut buf)
        .unwrap();

    pt.to_vec()
}

fn main() {
    let separator = "*".repeat(40);
    // 读取本地 bin 文件
    let mut file = File::open("bin").expect("Unable to open bin");
    let mut data = Vec::new();
    file.read_to_end(&mut data).expect("Unable to read bin");
    println!("明文：{:?}", &data);
    let (ct, iv) = encrypt(&data);
    let xorencode = xor_encrypt(&ct, XOR_KEY);
    println!("xorencode:{:?}", &xorencode);
    let hexencode = hex_encode(&xorencode);
    println!("hexencode:{:?}", &hexencode);
    let hexdecode = hex_decode(&hexencode).unwrap();
    println!("hexdecode:{:?}", &hexdecode);
    let xordencode = xor_decrypt(&hexdecode, XOR_KEY);
    println!("xordencode:{:?}", &xordencode);
    let pt = decrypt(&xordencode, iv);
    println!("解密结果：{:?}", pt);

    assert_eq!(&data, &pt); // 修改此处，去掉 to_vec()
}
