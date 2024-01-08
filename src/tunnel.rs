use std::{
    collections::HashMap,
    sync::{Mutex, RwLock},
};

use x25519::{PublicKey, StaticSecret};

use crate::{
    cipher::{Decryptor, Encryptor},
    handshake::{Initiator, Responder},
};

pub struct Tunnel {
    self_secret: StaticSecret,
    peer_public: PublicKey,
    preshared_key: [u8; 0x20],
    initiator_map: Mutex<HashMap<[u8; 0x04], Initiator>>,
    encryptor: Mutex<Encryptor>,
    decryptor_map: RwLock<HashMap<[u8; 0x04], Decryptor>>,
}
