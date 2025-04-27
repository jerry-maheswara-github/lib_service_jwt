# lib-service-jwt — Simple & Extensible JWT Management in Rust

**lib-service-jwt** is a lightweight, ergonomic, and extensible library built on top of [`jsonwebtoken`](https://docs.rs/jsonwebtoken) that simplifies working with JSON Web Tokens (JWT) in Rust applications. Designed for production-grade authentication systems, it abstracts the complexity of key handling and token generation, while giving you full control when you need it.

---

## ✨ Features

- ✅ Simple API for generating and decoding JWTs
- 🔐 Supports both access and refresh tokens
- 🔁 Built-in expiration handling
- 🧩 Easily extensible with custom claims
- 🧪 Includes ready-to-use test helpers for local development
- 📦 Built on top of the trusted [`jsonwebtoken`](https://docs.rs/jsonwebtoken) crate

---

## 📦 Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
lib-service-jwt = "0.1.0" # Replace with the actual version
```

---

## 🚀 Quick Start

```
use lib_service_jwt::{JwtAlgorithm, JwtKeys};

let algo = JwtAlgorithm::RS256 {
    access_private: include_bytes!("../keys/access-private.pem").to_vec(),
    access_public: include_bytes!("../keys/access-public.pem").to_vec(),
    refresh_private: include_bytes!("../keys/refresh-private.pem").to_vec(),
    refresh_public: include_bytes!("../keys/refresh-public.pem").to_vec(),
};

let keys = JwtKeys::from_algorithm(algo).unwrap();

let token = keys.generate_access_token("key-id", "user123", 3600, None).unwrap();
let claims = keys.decode_token(&token, "access").unwrap();

println!("User ID: {}", claims.claims.sub);
```

---

## 🛠️ Modules

- **`jwt`** – Core logic for generating, decoding, and verifying JWTs.
- **`model`** – Contains the `Claims` structure and other supporting types.

---

## 🔐 Security

- Built-in support for RSA (RS256) key pairs
- Automatically checks expiration (`exp`) during decoding
- Allows additional custom claims for roles, permissions, or any metadata

---

## 📝 Generating RSA Private and Public Keys

To generate RSA private and public keys for use with **lib-service-jwt**, you can use OpenSSL. Below are the steps for generating the keys:

### 1. Install OpenSSL (if you haven't already)
You can install OpenSSL using your package manager:

- **macOS**: `brew install openssl`
- **Ubuntu**: `sudo apt-get install openssl`
- **Windows**: Download the installer from [here](https://slproweb.com/products/Win32OpenSSL.html).

### 2. Generate the RSA Private Keys

For **access** tokens, run the following command to generate the private key:

```bash
openssl genpkey -algorithm RSA -out access-private.pem -pkeyopt rsa_keygen_bits:2048
```

For **refresh** tokens, run this command:

```bash
openssl genpkey -algorithm RSA -out refresh-private.pem -pkeyopt rsa_keygen_bits:2048
```

These commands will generate RSA private keys encrypted with AES256 and save them to `access-private.pem` and `refresh-private.pem` respectively. You can remove the `-aes256` flag if you don't want encryption.

### 3. Generate the RSA Public Keys

Once you have the private keys, you can extract the corresponding public keys using these commands:

For **access** tokens:

```bash
openssl rsa -pubout -in access-private.pem -out access-public.pem
```

For **refresh** tokens:

```bash
openssl rsa -pubout -in refresh-private.pem -out refresh-public.pem
```

These commands will generate the corresponding public keys and save them to `access-public.pem` and `refresh-public.pem`.

### 4. Use the Keys in Your Project

Once you have the `access-private.pem`, `access-public.pem`, `refresh-private.pem`, and `refresh-public.pem` keys, you can include them in your project by embedding them in your code or loading them from disk.

---



## 📄 License

Licensed under the [Apache License 2.0](LICENSE).

---

## 👨‍💻 Author

Created and maintained by [Jerry Maheswara](https://github.com/jerry-maheswara-github).  
Feel free to reach out for suggestions, issues, or improvements!

---

## ❤️ Built with Love in Rust

This project is built with ❤️ using **Rust** — a systems programming language that is safe, fast, and concurrent. Rust is the perfect choice for building reliable and efficient applications.

---

## 👋 Contributing

Pull requests, issues, and feedback are welcome!  
If you find this crate useful, give it a ⭐ and share it with others in the Rust community.
