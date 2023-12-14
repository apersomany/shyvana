use x25519::{PublicKey, StaticSecret};

pub struct Config {
    pub(crate) self_secret: StaticSecret,
    pub(crate) self_public: PublicKey,
    pub(crate) peer_public: PublicKey,
}

impl Config {
    pub fn new(self_secret: [u8; 32], peer_public: [u8; 32]) -> Self {
        Config {
            self_secret: StaticSecret::from(self_secret),
            self_public: PublicKey::from(&StaticSecret::from(self_secret)),
            peer_public: PublicKey::from(peer_public),
        }
    }
}
