use secp256k1::{PublicKey, Secp256k1, SecretKey};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use ripemd::{Ripemd160};
use bs58;

#[derive(Debug)]
pub struct WalletAddress {
    private_key: String,
    public_key: String,
    address: String,
}

impl WalletAddress {
    pub fn new() -> Self {
        // Create a cryptographic context
        let secp = Secp256k1::new();
        
        // Generate a random private key
        let mut random_number_gen = OsRng::default();
        let secret_key = SecretKey::new(&mut random_number_gen);
        
        // Generate a public key
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        
        // Convert keys to hex strings
        let private_key = hex::encode(secret_key.secret_bytes());
        let public_key_hex = hex::encode(public_key.serialize().to_vec());
        
        // Generate address (Bitcoin-style)
        let address = Self::generate_bitcoin_address(&public_key.serialize());
        
        WalletAddress {
            private_key,
            public_key: public_key_hex,
            address,
        }
    }
    
    fn generate_bitcoin_address(public_key: &[u8]) -> String {
        // Step 1: SHA256 of public key
        let mut sha256_hasher = Sha256::new();
        sha256_hasher.update(public_key);
        let sha256_result = sha256_hasher.finalize();
        
        // Step 2: RIPEMD160 of SHA256 result
        let mut ripemd_hasher = Ripemd160::new();
        ripemd_hasher.update(sha256_result);
        let ripemd_result = ripemd_hasher.finalize();
        
        // Step 3: Add version byte (0x00 for mainnet)
        let mut address_bytes = vec![0x00];
        address_bytes.extend_from_slice(&ripemd_result);
        
        // Step 4: Double SHA256 for checksum
        let mut checksum_hasher = Sha256::new();
        checksum_hasher.update(&address_bytes);
        let temp_hash = checksum_hasher.finalize();
        
        let mut checksum_hasher2 = Sha256::new();
        checksum_hasher2.update(temp_hash);
        let checksum = &checksum_hasher2.finalize()[..4];
        
        // Step 5: Combine version + hash + checksum
        address_bytes.extend_from_slice(checksum);
        
        // Step 6: Base58 encode
        bs58::encode(address_bytes).into_string()
    }

    // fn generate_ethereum_address() -> String {}
    
    pub fn display(&self) {
        println!("Private Key: {}", self.private_key);
        println!("Public Key: {}", self.public_key);
        println!("Address: {}", self.address);
    }
}

fn main() {
    let wallet = WalletAddress::new();
    wallet.display();
}