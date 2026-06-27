# Bitcoin Digital Signature Demo
### BitDevs Uyo — Socratic Seminar #12

A hands on Rust demo that walks through how Bitcoin authorizes transactions using **ECDSA digital signatures**  from keypair generation to tamper detection.

Built for the Chapter 8 session of *Mastering Bitcoin (3rd Edition)*.

---

## What This Demo Covers

Bitcoin never "sends" coins directly. Instead, it uses **cryptographic proof** — a digital signature — to prove that the rightful owner authorized a transaction. This demo implements that flow step by step:

```
Keypair Generation → Message Hashing → Signing → Verification → Tamper Test
```

---

## The Signature Pipeline

### 1. Keypair Generation
```
private key (x)  →  public key (P)
```
A random private key is generated using `OsRng` (OS-level randomness). The public key is derived from it using elliptic curve multiplication on **secp256k1** — the same curve Bitcoin uses.

> The private key signs. The public key verifies. You never reveal the private key.

---

### 2. Fhash(m) — Double SHA-256
```
SHA256(SHA256(message)) → 32-byte digest (z)
```
Bitcoin doesn't sign the raw message. It hashes it twice with SHA-256 first. This produces a fixed 32-byte value regardless of message length, and makes the signature scheme resistant to length-extension attacks.

---

### 3. Fsig(z, x) — ECDSA Signature
```
sign(z, private_key) → signature (r, s)
```
The signature is a pair `(r, s)` serialized in **DER format** — exactly how Bitcoin encodes signatures on-chain in legacy transactions.

> `r` is derived from a random nonce point on the curve. `s` is computed using the private key and the hash.

---

### 4. Verification
```
verify(z, signature, public_key) → VALID or INVALID
```
The verifier recomputes `R'` from the signature and checks whether `R'.x == r`. No private key is needed — only the public key, the message hash, and the signature.

---

### 5. Tamper Test
```
verify(different_hash, same_signature, public_key) → INVALID
```
Changing even one character in the message produces a completely different hash. The original signature will **always** fail verification against a tampered message — this is the core security guarantee.

---

## Running the Demo

**Prerequisites:** Rust installed → [rustup.rs](https://rustup.rs)

```bash
git clone https://github.com/BitDevsUyo/digital-signature-demo-socratic-seminar-12.git
cd digital-signature-demo-socratic-seminar-12
cargo run
```

**Expected output:**
```
KEYPAIR
private key : <hex>
public key  : <hex>

MESSAGE
Message (m): Send 0.5 BTC to Alice

Fhash(m) DOUBLE SHA-256
SHA256(SHA256(m)): <32-byte hex>

Fsig(Fhash(m), x) — ECDSA SIGNATURE
Signature (DER): <DER-encoded hex>

VERIFICATION
Result: VALID — R'.x == r, signature checks out

TAMPER TEST
Tampered message: Send 5.0 BTC to Eve
Result: INVALID — hash changed, signature rejected
```

---

## Dependencies

| Crate | Purpose | Docs |
|---|---|---|
| `secp256k1` | Keypair generation, ECDSA sign/verify on secp256k1 | [docs.rs](https://docs.rs/secp256k1/latest/secp256k1/) |
| `sha2` | SHA-256 hashing (double-hash for Fhash) | [docs.rs](https://docs.rs/sha2/latest/sha2/) |
| `hex` | Encode byte arrays as readable hex strings | [docs.rs](https://docs.rs/hex/latest/hex/) |

---

## Further Reading

| Resource | Link |
|---|---|
| Mastering Bitcoin 3rd Ed. — Chapter 8 | [github.com/bitcoinbook](https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch08_signatures.adoc) |
| BIP-340 (Schnorr for Bitcoin) | [github.com/bitcoin/bips](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) |
| rust-secp256k1 source & examples | [github.com/rust-bitcoin/rust-secp256k1](https://github.com/rust-bitcoin/rust-secp256k1) |


*BitDevs Uyo · Socratic Seminar #12 · June 2026*
