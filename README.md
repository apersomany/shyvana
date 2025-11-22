# Shyvana

Shyvana is a Rust implementation of the WireGuard® protocol. It aims to provide a lightweight and secure VPN tunnel implementation.

**Note:** This project is currently a work in progress and is not yet ready for production use.

## Project Structure

- `src/handshake.rs`: Implements the Noise protocol handshake (Initiator and Responder).
- `src/packet.rs`: Defines the wire format for WireGuard packets.
- `src/crypto.rs`: Wrappers for cryptographic primitives (Blake2s, ChaCha20Poly1305, HMAC, etc.).
- `src/cipher.rs`: Handles packet encryption and decryption.
- `src/tunnel.rs`: Core tunnel state management.
- `src/async_tunnel.rs`: Async wrapper for the tunnel (planned).

## Status

The project currently contains the basic data structures and cryptographic primitives required for the WireGuard protocol. The handshake logic is partially implemented, but the core packet processing loop and transport data encryption are incomplete.

## TODO

- [ ] **Cipher Implementation**: Implement `Encryptor::encrypt` in `src/cipher.rs`.
- [ ] **Tunnel Logic**: Implement the `Tunnel` struct in `src/tunnel.rs` to handle packet processing, session management, and timers.
- [ ] **Async Support**: Implement `AsyncTunnel` in `src/async_tunnel.rs`.
- [ ] **Cookie Reply**: Add the `CookieReply` packet definition to `src/packet.rs` (Message Type 3) and implement handling logic in `src/handshake.rs`.
- [ ] **Tests**: Add unit and integration tests to verify protocol correctness.