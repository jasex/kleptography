fn main() {
    use sign::kleptographic::*;

    // messages to be signed
    let message1 = String::from("Hello motherfucker!");
    let message2 = String::from("You too motherfucker!");
    let param = Param::new();
    // user and attacker's keypair
    let user_keypair = KeyPair::new(Scalar::random());
    let attacker_keypair = KeyPair::new(Scalar::random());
    // mal_sign is bad signature algorithm
    let [sign1, sign2] = mal_sign(
        message1.clone(),
        message2.clone(),
        param.clone(),
        user_keypair.clone(),
        attacker_keypair.clone(),
    )
    .unwrap();

    // user extract_users_private_key() function to recover user's private key
    let recover = extract_users_private_key(
        message1.clone(),
        message2.clone(),
        param.clone(),
        sign1.clone(),
        sign2.clone(),
        attacker_keypair.private.clone(),
        attacker_keypair.public.clone(),
        user_keypair.public.clone(),
    )
    .unwrap();

    // should be the same
    println!("{:?}", recover.to_bigint());
    println!("{:?}", user_keypair.private.to_bigint());
}
