use secp256k1::{Secp256k1, Message};
use sha2::{Sha256, Digest};
// For printing byte arrays as readable hex strings
use hex;

fn main() {
    let secp = Secp256k1::new();

    // Generate a private key (x)
    // secret_key  = x  
    // public_key  (a point on the curve, safe to share)
    let (secret_key, public_key) = secp.generate_keypair(&mut secp256k1::rand::rngs::OsRng);

    // Print the private key as a 64-char hex string (32 bytes)
    println!("KEYPAIR ");
    println!("Private key (x):{}", secret_key.display_secret());

    // Print the compressed public key (33 bytes: 02/03 prefix + 32-byte x-coord)
    println!("Public key(P):{}", hex::encode(public_key.serialize()));

    
    // Define the message (m)
    // In Bitcoin this would be a serialized transaction
    let message_text = "Send 0.5 BTC to Alice";
    println!("\nMESSAGE");
    println!("Message (m): {}", message_text);

    // Fhash(m) — double SHA-256 hash of the message 
    // Bitcoin always hashes twice: SHA256(SHA256(m))
    // This produces a 32-byte digest called z
    // First SHA-256 pass
    let first_hash = Sha256::digest(message_text.as_bytes());
    // Second SHA-256 pass — feed output of first hash in
    let second_hash = Sha256::digest(&first_hash);
    // Convert the 32-byte hash to a hex string for display
    let hash_hex = hex::encode(&second_hash);
    println!("\nFhash(m) DOUBLE SHA-256 ");
    println!("SHA256(SHA256(m)):{}", hash_hex);

    //  Wrap the hash into a secp256k1 Message type 
    // secp256k1::Message expects exactly 32 bytes — our double-SHA256 is perfect
    // This is z in the formula: sig = Fsig(z, x)
    let msg = Message::from_slice(&second_hash).expect("32 bytes");



    // The signature is the pair (r, s)
    let signature = secp.sign_ecdsa(&msg, &secret_key);
    // DER-encode the signature (how Bitcoin serializes signatures on-chain)
    let sig_bytes = signature.serialize_der();
    println!("\n Fsig(Fhash(m), x) — ECDSA SIGNATURE");
    println!("Signature (DER):{}", hex::encode(&sig_bytes));



    // Verification — anyone with the public key can verify 
    println!("\nVERIFICATION");
    match secp.verify_ecdsa(&msg, &signature, &public_key) {
        Ok(_)  => println!("Result: VALID — R'.x == r, signature checks out"),
        Err(e) => println!("Result: INVALID — {}", e),
    }

    // Tamper test  change the message and try to verify 
    // A completely different hash means R'.x will NOT equal r → verification fails
    let tampered_text = "Send 5.0 BTC to Eve"; 
    let t1 = Sha256::digest(tampered_text.as_bytes());
    let t2 = Sha256::digest(&t1);
    let tampered_msg = Message::from_slice(&t2).expect("32 bytes");

    println!("\n TAMPER TEST ");
    println!("Tampered message : {}", tampered_text);
    match secp.verify_ecdsa(&tampered_msg, &signature, &public_key) {
        Ok(_)  => println!("Result: VALID (this should never happen)"),
        Err(_) => println!("Result: INVALID — hash changed, signature rejected"),
    }
}

