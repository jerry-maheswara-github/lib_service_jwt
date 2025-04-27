//! # Scalable JWT Management with Rust
//! 
//! **lib_service_jwt** is a lightweight, ergonomic, and extensible library built on top of [`jsonwebtoken`](https://docs.rs/jsonwebtoken) that simplifies working with JSON Web Tokens (JWT) in Rust applications. Designed for production-grade authentication systems, it abstracts the complexity of key handling and token generation, while giving you full control when you need it.
//! 
//! ---
//! 
//! ## ✨ Features
//! 
//! - ✅ Simple API for generating and decoding JWTs
//! - 🔐 Supports both access and refresh tokens
//! - 🔁 Built-in expiration handling
//! - 🧩 Easily extensible with custom claims
//! - 🧪 Includes ready-to-use test helpers for local development
//! - 📦 Built on top of the trusted [`jsonwebtoken`](https://docs.rs/jsonwebtoken) crate
//! 
//! ---
//! 
//! ## 📦 Installation
//! 
//! Add the following to your `Cargo.toml`:
//! 
//! ```toml
//! [dependencies]
//! lib_service_jwt = "0.1.0"
//! ```
//! 
//! ---
//! 
//! ## 🚀 Quick Start
//! 
//! ```bash
//! use lib_service_jwt::{JwtAlgorithm, JwtKeys};
//! 
//! let algo = JwtAlgorithm::RS256 {
//!     access_private: include_bytes!("../keys/access-private.pem").to_vec(),
//!     access_public: include_bytes!("../keys/access-public.pem").to_vec(),
//!     refresh_private: include_bytes!("../keys/refresh-private.pem").to_vec(),
//!     refresh_public: include_bytes!("../keys/refresh-public.pem").to_vec(),
//! };
//! 
//! let kid = "some-key-id";
//! let user_id = "user123";
//! let expires_in = 60 * 60 * 24 * 30;
//! let mut extra = HashMap::new();
//! let roles = vec!["admin", "user"]; 
//! extra.insert("roles".to_string(), json!(roles)); 
//!
//! let audiences: Option<Vec<String>> = Some(vec!["myApp1".to_string(), "myApp2".to_string()]);
//! extra.insert("aud".to_string(), json!(audiences));  
//! 
//! let token = keys.generate_access_token(kid, user_id, expires_in, Some(extra.clone())).unwrap();
//! 
//! let audiences_dec: Option<Vec<String>>  = Some(vec!["myApp1".to_string(), "myApp2".to_string()]);
//! let decoded_token = keys.decode_token(&token, "access", audiences_dec).unwrap();
//! 
//! println!("User ID: {}", decoded_token.claims.sub);
//! ```
//! 
//! ---
//! 
//! ## 🛠️ Modules
//! 
//! - **`jwt`** – Core logic for generating, decoding, and verifying JWTs.
//! - **`model`** – Contains the `Claims` structure.
//! 
//! ---
//! 
//! ## 🔐 Security
//! 
//! - Built-in support for RSA (RS256) key pairs
//! - Automatically checks expiration (`exp`) during decoding
//! - Allows additional custom claims for roles, permissions, or any metadata
//! 
//! ---
//! 
//! ## 🔑 Generating RSA Private and Public Keys
//! 
//! To generate **RSA private** and **public keys** for use with **lib_service_jwt**, follow these steps:
//! 
//! ### 1. Install OpenSSL (if not already installed)
//! You can install OpenSSL using the appropriate package manager for your system:
//! 
//! - **macOS**: `brew install openssl`
//! - **Ubuntu**: `sudo apt-get install openssl`
//! - **Windows**: Download the installer from [here](https://slproweb.com/products/Win32OpenSSL.html).
//! 
//! ### 2. Generate the RSA Private Keys
//! 
//! For **access** tokens, run the following command to generate the private key:
//! 
//! ```bash
//! openssl genpkey -algorithm RSA -out access-private.pem -pkeyopt rsa_keygen_bits:2048
//! ```
//! 
//! For **refresh** tokens, run this command:
//! 
//! ```bash
//! openssl genpkey -algorithm RSA -out refresh-private.pem -pkeyopt rsa_keygen_bits:2048
//! ```
//! 
//! These commands will generate **RSA private keys** encrypted with AES256 and save them to `access-private.pem` and `refresh-private.pem`.
//! 
//! ### 3. Generate the RSA Public Keys
//! 
//! Once you have the private keys, you can extract the corresponding public keys with the following commands:
//! 
//! For **access** tokens:
//! 
//! ```bash
//! openssl rsa -pubout -in access-private.pem -out access-public.pem
//! ```
//! 
//! For **refresh** tokens:
//! 
//! ```bash
//! openssl rsa -pubout -in refresh-private.pem -out refresh-public.pem
//! ```
//! 
//! These commands will generate the corresponding public keys and save them to `access-public.pem` and `refresh-public.pem`.
//! 
//! ### 4. Use the Keys in Your Project
//! 
//! Once you have `access-private.pem`, `access-public.pem`, `refresh-private.pem`, and `refresh-public.pem`, you can include these keys in your project by embedding them directly in your code or loading them from disk.
//! 
//! ---
//! # 🧩 **JWK (JSON Web Key)** 
//! 
//! A **JSON Web Key** (JWK) is a JSON data structure that represents a cryptographic key. 
//! It is used in JSON Web Signature (JWS) or JSON Web Encryption (JWE) to help verify or sign JSON Web Tokens (JWTs). 
//! JWKs are often used to securely share public keys.
//! 
//! You can distribute your `jwks.json` file in a standard format by placing it under the `.well-known/` directory in your web server. This follows the convention used by many services and helps ensure your JWKs are accessible for verification by others.
//! 
//! For example, the JWK set can be accessible at:
//! 
//! ```bash
//! https://yourdomain.com/.well-known/jwks.json
//! ```
//! 
//! This makes it easier for clients or services to automatically fetch and use your public keys for validating JWTs.
//! 
//! To create a **JWK** (JSON Web Key), you need to extract two key components from the RSA public key: **modulus** (`n`) and **exponent** (`e`).
//! 
//! ### 1. Extract Modulus (n) and Exponent (e) from the Public Key
//! 
//! This command will extract the **modulus** and **public exponent** 
//! (which is usually `65537` in many RSA implementations) and display it in the terminal.
//! > **Note:**
//! > The string has been truncated for readability.
//! > The full value is much longer.
//! 
//! ```bash
//! $ openssl pkey -in access-public.pem -pubin -noout -text
//! 
//! Public-Key: (2048 bit)
//! Modulus:
//!     00:b5:f2:5a:2e:bc:d7:20:b5:20:d5:4d:cd:d4:a5:
//!     7c:c8:9a:fd:d8:61:e7:e4:eb:58:65:1e:ea:5a:4d:
//!     4c:73:87:32:e0:91:a3:92:56:2e:a7:bc:1e:32:30:
//!     43:f5:fd:db:05:5a:08:b2:25:15:5f:ac:4d ...
//!     ... 76:e9
//! Exponent: 65537 (0x10001)
//! ```
//! 
//! ### 2. Convert Modulus and Exponent to Base64url Encoding
//! 
//! JWK requires **base64url encoding** for both the modulus (`n`) and the public exponent (`e`). You can convert them using the `base64` command in bash. Here’s how:
//! 
//! #### Encode Modulus (n) to Base64url:
//! 
//! ```bash
//! echo "00:b5:f2:5a:2e:bc:d7:20:b5:20:d5:4d:cd:d4:a5:
//!       7c:c8:9a:fd:d8:61:e7:e4:eb:58:65:1e:ea:5a:4d:
//!       4c:73:87:32:e0:91:a3:92:56:2e:a7:bc:1e:32:30:
//!       43:f5:fd:db:05:5a:08:b2:25:15:5f:ac:4d ...
//!       ... 76:e9" | tr -d ": \n" | xxd -p -r | base64 | tr +/ -_ | tr -d "=\n"
//! ```
//! Result:
//! ```bash
//! 3drYbtHpiwwif5JoaYTCeQbsLRSY2i4 ... PW1MhYjnLeAo1Ap4tfV26Q
//! ```
//! 
//! 
//! #### Encode Exponent (e) to Base64url:
//! 
//! ```bash
//! $ echo 010001 | xxd -p -r | base64
//! ```
//! Result:
//! ```bash
//! AQAB
//! ```
//! 
//! ### 3. Create the JWK in JSON Format
//! 
//! Now you can create the **JWK (JSON Web Key)** in JSON format with the encoded modulus and exponent. Here’s how to do it using bash:
//! 
//! ```bash
//! $ nano jwks.json
//! 
//! {
//!   "keys": [
//!     {
//!       "kty": "RSA",
//!       "kid": "your-key-id", 
//!       "use": "sig",
//!       "n": "3drYbtHpiwwif5JoaYTCeQbsLRSY2i4 ... PW1MhYjnLeAo1Ap4tfV26Q",
//!       "e": "AQAB"
//!     }
//!   ]
//! }
//! 
//! ```
//! 
//! ### Explanation:
//! - **`kty`**: The key type, here we use RSA.
//! - **`kid`**: Key ID, you can set it to a unique ID for your key.
//! - **`use`**: Indicates the use of this key, here it is used for signing (`sig`).
//! - **`n`** and **`e`**: The modulus and public exponent, encoded in **base64url** format.
//! 
//! ---
//! 
//! ## 📄 License
//!
//! Licensed under the <a href="https://www.apache.org/licenses/LICENSE-2.0.txt" target="_blank">Apache License 2.0</a>.
//! 
//! ---
//! 
//! ## 👨‍💻 Author
//! 
//! Created and maintained by [Jerry Maheswara](https://github.com/jerry-maheswara-github).  
//! Feel free to reach out for suggestions, issues, or improvements!
//! 
//! ---
//! 
//! ## ❤️ Built with Love in Rust
//! 
//! This project is built with ❤️ using **Rust** — a systems programming language that is safe, fast, and concurrent. Rust is the perfect choice for building reliable and efficient applications.
//! 
//! ---
//! 
//! ## 👋 Contributing
//! 
//! Pull requests, issues, and feedback are welcome!  
//! If you find this crate useful, give it a ⭐ and share it with others in the Rust community.
//! 
//! 

pub mod model;
pub mod jwt;
