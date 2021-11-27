use ecies::{PublicKey, SecretKey};
use hex::decode;
use sha3::digest::DynDigest;
use sha3::{Digest, Keccak256};
use std::env;
use std::io::{BufRead, Read};

fn main() {
    use sign::kleptographic::*;
    use std::fs::File;

    let args: Vec<String> = env::args().collect();
    let mut f = File::open("./param.json").unwrap();
    let mut buf = String::new();
    f.read_to_string(&mut buf);
    // let param = Param::new();
    // let temp = serde_json::to_string(&param).unwrap();
    // println!("{}", buf);
    let param: Param = serde_json::from_str(&buf).unwrap();
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
        println!("{}", hex::encode(cipher));
    } else if args[1] == "--decrypt".to_string() {
        let cipher = args[2].clone();
        let private = args[3].clone();
        // let private = "5dcb5c0a110e3918914f16f07a5d28d3e56e241a337f7fd316ba52d515fa91de";
        let plain = decrypt(hex::decode(cipher.clone()).unwrap(), private.clone());
        println!("{}", String::from_utf8_lossy(&plain));
    } else if args[1] == "--recover".to_string() {
        if let Ok(hash1) = hex::decode(&args[2]) {
            if let Ok(hash2) = hex::decode(&args[3]) {
                let attacker_private = BigInt::from_hex(
                    "6c86c120ac099e545eca4d6afdb1fec11c7becd262cdbcf4c8db0591f40049fd",
                )
                .unwrap();
                let attacker_key = KeyPair::new(Scalar::from_bigint(&attacker_private));
                let mut sign1 = Signature::new();
                let mut sign2 = Signature::new();
                let v1: u16 = args[4].parse().unwrap();
                let v2: u16 = args[7].parse().unwrap();
                sign1.v = BigInt::from(v1);
                sign1.r = Scalar::from_bigint(&BigInt::from_hex(&args[5]).unwrap());
                sign1.s = Scalar::from_bigint(&BigInt::from_hex(&args[6]).unwrap());
                sign2.v = BigInt::from(v2);
                sign2.r = Scalar::from_bigint(&BigInt::from_hex(&args[8]).unwrap());
                sign2.s = Scalar::from_bigint(&BigInt::from_hex(&args[9]).unwrap());
                let user_private = BigInt::from_hex(
                    "5dcb5c0a110e3918914f16f07a5d28d3e56e241a337f7fd316ba52d515fa91de",
                )
                .unwrap();
                let user_key = KeyPair::new(Scalar::from_bigint(&user_private));
                let extract = extract_users_private_key_hash(
                    hash1,
                    hash2,
                    param.clone(),
                    sign1.clone(),
                    sign2.clone(),
                    attacker_key.clone(),
                    user_key.public.clone(),
                )
                .unwrap();
                println!("{:?}", extract);
            }
        }
    }
}
