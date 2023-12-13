use x25519::StaticSecret;

pub struct Config {
    pub(crate) self_secret: [u8; 32],
    pub(crate) self_public: [u8; 32],
    pub(crate) peer_public: [u8; 32],
}

impl Config {
    pub fn new(self_secret: [u8; 32], peer_public: [u8; 32]) -> Self {
        Config {
            self_secret: self_secret,
            self_public: StaticSecret::from(self_secret).to_bytes(),
            peer_public: peer_public,
        }
    }
}
