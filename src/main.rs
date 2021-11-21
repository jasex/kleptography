use ecies::{PublicKey, SecretKey};
use hex::decode;
use sha3::digest::DynDigest;
use sha3::{Digest, Keccak256};
use std::env;
use std::io::BufRead;

fn main() {
    use sign::kleptographic::*;

    let args: Vec<String> = env::args().collect();
    let param = Param::new();
    if args[1] == "--mulsign".to_string() {
        if let Ok(hash1) = hex::decode(&args[2]) {
            if let Ok(hash2) = hex::decode(&args[3]) {
                let user_private = BigInt::from_hex(
                    "5dcb5c0a110e3918914f16f07a5d28d3e56e241a337f7fd316ba52d515fa91de",
                )
                .unwrap();
                let attacker_private = BigInt::from_hex(
                    "6c86c120ac099e545eca4d6afdb1fec11c7becd262cdbcf4c8db0591f40049fd",
                )
                .unwrap();

                let user_key = KeyPair::new(Scalar::from_bigint(&user_private));
                let attacker_key = KeyPair::new(Scalar::from_bigint(&attacker_private));
                let [sign1, sign2] = mal_sign_hash(
                    hash1,
                    hash2,
                    param.clone(),
                    user_key.clone(),
                    attacker_key.clone(),
                )
                .unwrap();
                println!("{}", sign1.v);
                println!("0x{}", sign1.r.to_bigint().to_hex());
                println!("0x{}", sign1.s.to_bigint().to_hex());

                println!("{}", sign2.v);
                println!("0x{}", sign2.r.to_bigint().to_hex());
                println!("0x{}", sign2.s.to_bigint().to_hex());
            }
        } else {
            println!("Error hex format");
        }
    } else if args[1] == "--encrypt".to_string() {
        let message = args[2].clone();
        let private = "5dcb5c0a110e3918914f16f07a5d28d3e56e241a337f7fd316ba52d515fa91de";
        let cipher = encrypt(message.clone(), private.to_string());
        println!("{}", hex::encode(message.clone().as_bytes()));
        println!("{}", hex::encode(cipher));
    } else if args[1] == "--decrypt".to_string() {
        let cipher = args[2].clone();
        let private = "5dcb5c0a110e3918914f16f07a5d28d3e56e241a337f7fd316ba52d515fa91de";
        let plain = decrypt(hex::decode(cipher.clone()).unwrap(), private.to_string());
        println!("{}", String::from_utf8_lossy(&plain));
    }
}
