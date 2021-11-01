pub mod kleptographic {
    pub use curv::arithmetic::Converter;
    pub use curv::elliptic::curves::{Point, Scalar, Secp256k1};
    pub use curv::BigInt;
    pub use openssl::hash::{Hasher, MessageDigest};
    pub use rand::thread_rng;
    use rand::Rng;

    #[derive(Clone, Debug)]
    pub struct Param {
        a: Scalar<Secp256k1>,
        b: Scalar<Secp256k1>,
        h: Scalar<Secp256k1>,
        e: Scalar<Secp256k1>,
    }

    #[derive(Clone, Debug)]
    pub struct Signature {
        pub r: Scalar<Secp256k1>,
        pub s: Scalar<Secp256k1>,
    }

    #[derive(Clone, Debug)]
    pub struct KeyPair {
        pub private: Scalar<Secp256k1>,
        pub public: Point<Secp256k1>,
    }

    impl KeyPair {
        pub fn new(private: Scalar<Secp256k1>) -> Self {
            KeyPair {
                private: private.clone(),
                public: private * Point::generator(),
            }
        }
    }

    impl Param {
        pub fn new() -> Self {
            Param {
                a: Scalar::random(),
                b: Scalar::random(),
                h: Scalar::random(),
                e: Scalar::random(),
            }
        }
    }

    pub fn sign(message: String, keypair: KeyPair, k: Scalar<Secp256k1>) -> Option<Signature> {
        let mut hasher = Hasher::new(MessageDigest::sha256()).expect("Init hasher error");
        hasher.update(message.as_bytes()).expect("Hash error");
        let m: Scalar<Secp256k1> = Scalar::from_bytes(hasher.finish().unwrap().as_ref()).unwrap();
        let signature_point = k.clone() * Point::generator();
        let r: Scalar<Secp256k1> = Scalar::from_bigint(&signature_point.x_coord().unwrap());
        let s: Scalar<Secp256k1> =
            k.clone().invert().unwrap() * (m.clone() + r.clone() * keypair.private.clone());
        Some(Signature { r, s })
    }
    pub fn mal_sign(
        message1: String,
        message2: String,
        param: Param,
        user_key_pair: KeyPair,
        attacker_key_pair: KeyPair,
    ) -> Option<[Signature; 2]> {
        let mut hasher = Hasher::new(MessageDigest::sha256()).unwrap();

        let k1: Scalar<Secp256k1> = Scalar::random();
        let sign1 = sign(message1.clone(), user_key_pair.clone(), k1.clone()).unwrap();

        let mut rng = thread_rng();
        let u: Scalar<Secp256k1> = Scalar::from(rng.gen::<u16>() % 2);
        let j: Scalar<Secp256k1> = Scalar::from(rng.gen::<u16>() % 2);
        let z = k1.clone() * param.a.clone() * Point::generator()
            + param.b.clone() * k1.clone() * attacker_key_pair.public.clone()
            + j.clone() * param.h.clone() * Point::generator()
            + u.clone() * param.e.clone() * attacker_key_pair.public.clone();
        let zx = z.x_coord().unwrap();
        hasher.update(&zx.to_bytes()).expect("Hash error");
        let k2: Scalar<Secp256k1> = Scalar::from_bytes(hasher.finish().unwrap().as_ref()).unwrap();
        let sign2 = sign(message2.clone(), user_key_pair.clone(), k2.clone()).unwrap();

        return Some([sign1, sign2]);
    }

    pub fn verify(message: String, sign: Signature, public: Point<Secp256k1>) -> Result<(), ()> {
        let mut hasher = Hasher::new(MessageDigest::sha256()).unwrap();
        hasher.update(message.as_bytes()).unwrap();
        let m1: Scalar<Secp256k1> = Scalar::from_bytes(hasher.finish().unwrap().as_ref()).unwrap();
        let w = sign.s.invert().unwrap();
        let u1 = m1.clone() * w.clone();
        let u2 = sign.r.clone() * w.clone();
        let verify_point = u1.clone() * Point::generator() + u2.clone() * public.clone();
        if sign.r.to_bigint() == verify_point.x_coord().unwrap() {
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn extract_users_private_key(
        message1: String,
        message2: String,
        param: Param,
        sign1: Signature,
        sign2: Signature,
        attackers_private: Scalar<Secp256k1>,
        attackers_public: Point<Secp256k1>,
        user_public: Point<Secp256k1>,
    ) -> Option<Scalar<Secp256k1>> {
        let mut hasher = Hasher::new(MessageDigest::sha256()).expect("Unable to initial hasher");
        // calculate the hash of message1
        hasher.update(message1.as_bytes()).expect("Hash error");
        let m1: Scalar<Secp256k1> = Scalar::from_bytes(hasher.finish().unwrap().as_ref()).unwrap();
        // calculate the hash of message2
        hasher.update(message2.as_bytes()).expect("Hash error");
        let m2: Scalar<Secp256k1> = Scalar::from_bytes(hasher.finish().unwrap().as_ref()).unwrap();

        let w = sign1.s.invert().unwrap();
        let u1 = m1.clone() * w.clone();
        let u2 = sign1.r.clone() * w.clone();

        let verify_point = u1.clone() * Point::generator() + u2.clone() * user_public.clone();
        let z1 = verify_point.clone() * param.a.clone()
            + (verify_point.clone() * param.b.clone() * attackers_private.clone());

        for u in 0..=1 {
            for j in 0..=1 {
                let z2 = z1.clone()
                    + Scalar::from(j) * param.h.clone() * Point::generator()
                    + Scalar::from(u) * param.e.clone() * attackers_public.clone();
                let zx: Scalar<Secp256k1> = Scalar::from_bigint(&z2.x_coord().unwrap());
                hasher
                    .update(&zx.to_bigint().to_bytes())
                    .expect("Hash error");
                let hash: Scalar<Secp256k1> =
                    Scalar::from_bytes(hasher.finish().unwrap().as_ref()).unwrap();

                let k_candidate = hash.clone();
                let verify_point_candidate = k_candidate.clone() * Point::generator();
                let r_candidate = verify_point_candidate.x_coord().unwrap();
                if r_candidate == sign2.r.to_bigint() {
                    return Some(
                        (sign2.s.clone() * k_candidate.clone() - m2) * (sign2.r.invert().unwrap()),
                    );
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::kleptographic::*;

    #[test]
    fn test_extract_users_private_key() {
        let message1 = String::from("first message");
        let message2 = String::from("second message");
        let param = Param::new();
        let user_keypair = KeyPair::new(Scalar::random());
        let attacker_keypair = KeyPair::new(Scalar::random());
        let signs = mal_sign(
            message1.clone(),
            message2.clone(),
            param.clone(),
            user_keypair.clone(),
            attacker_keypair.clone(),
        )
        .unwrap();
        let temp = extract_users_private_key(
            message1.clone(),
            message2.clone(),
            param.clone(),
            signs[0].clone(),
            signs[1].clone(),
            attacker_keypair.private.clone(),
            attacker_keypair.public.clone(),
            user_keypair.public.clone(),
        )
        .unwrap();
        assert_eq!(temp.to_bigint(), user_keypair.private.to_bigint());
    }

    #[test]
    fn sign_and_verify() {
        let message1 = String::from("i'm first message");
        let keypair = KeyPair::new(Scalar::random());
        let sig = sign(message1.clone(), keypair.clone(), Scalar::random()).unwrap();
        assert_eq!(
            verify(message1.clone(), sig.clone(), keypair.public.clone()),
            Ok(())
        );
    }
}
