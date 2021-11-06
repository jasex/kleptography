use sha3::digest::DynDigest;
use sha3::{Digest, Keccak256};

fn main() {
    use sign::kleptographic::*;

    // messages to be signed
    let message1 = String::from("Hello motherfucker!");
    let message2 = String::from("You too motherfucker!");
    let param = Param::new();
    // user and attacker's keypair
    let user_keypair = KeyPair::new(Scalar::random());
    let attacker_keypair = KeyPair::new(Scalar::random());

    let mut hasher = Keccak256::new();
    Digest::update(&mut hasher, message1.as_bytes());
    let hash1 = hasher.finalize();

    let mut hasher = Keccak256::new();
    Digest::update(&mut hasher, message2.as_bytes());
    let hash2 = hasher.finalize();
    let [sign1, sign2] = mal_sign_hash(
        hash1.clone().to_vec(),
        hash2.clone().to_vec(),
        param.clone(),
        user_keypair.clone(),
        attacker_keypair.clone(),
    )
    .unwrap();
    let out1 = verify_hash(
        hash1.clone().to_vec(),
        sign1.clone(),
        user_keypair.public.clone(),
    );
    let out2 = verify_hash(
        hash2.clone().to_vec(),
        sign2.clone(),
        user_keypair.public.clone(),
    );
    println!("{:?}", out1);
    println!("{:?}", out2);
    let recover = extract_users_private_key_hash(
        hash1.clone().to_vec(),
        hash2.clone().to_vec(),
        param.clone(),
        sign1.clone(),
        sign2.clone(),
        attacker_keypair.clone(),
        user_keypair.public.clone(),
    )
    .unwrap();
    println!("{:?}", recover.to_bigint());
    println!("{:?}", user_keypair.private.to_bigint());
}
