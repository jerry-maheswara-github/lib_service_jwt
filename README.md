# Scalable JWT Management with Rust

**lib_service_jwt** is a lightweight, ergonomic, and extensible library built on top of [`jsonwebtoken`](https://docs.rs/jsonwebtoken) that simplifies working with JSON Web Tokens (JWT) in Rust applications. Designed for production-grade authentication systems, it abstracts the complexity of key handling and token generation, while giving you full control when you need it.

---

## ✨ Features

- ✅ Simple API for generating and decoding JWTs
- 🔐 Supports both access and refresh tokens
- 🔁 Built-in expiration handling
- 🧩 Easily extensible with custom claims
- 🧪 Includes ready-to-use test helpers for local development
- 📦 Built on top of the trusted [`jsonwebtoken`](https://docs.rs/jsonwebtoken) crate
- 🛠️ Supports multiple JWT algorithms:
  - **RS256**: RSA signing algorithm with public/private key pairs for secure JWT generation and verification.
  - **ES256**: ECDSA using the P-256 curve for signing JWTs with improved performance and security in certain environments.

---

## 🚀 Quick Start

### 🔐 Using RS256 (RSA)

```code
 use lib_service_jwt::jwt::{JwtAlgorithm, JwtKeys};
 use std::collections::HashMap;
 use serde_json::json;

 let algo = JwtAlgorithm::RS256 {
    access_private: include_bytes!("../examples/rsa/access-private.pem").to_vec(),
    access_public: include_bytes!("../examples/rsa/access-public.pem").to_vec(),
    refresh_private: include_bytes!("../examples/rsa/refresh-private.pem").to_vec(),
    refresh_public: include_bytes!("../examples/rsa/refresh-public.pem").to_vec(),
 };

 let keys = JwtKeys::from_algorithm(algo).expect("Failed to create JwtKeys");

 let kid = "rsa-key-id";
 let user_id = "user123";
 let expires_in = 60 * 60 * 24 * 30;
 let mut extra = HashMap::new();
 let roles = vec!["admin", "user"];
 extra.insert("roles".to_string(), json!(roles));

 let audiences = Some(vec!["myApp1".to_string(), "myApp2".to_string()]);
 extra.insert("aud".to_string(), json!(audiences.clone()));

 let token = keys.generate_access_token(kid, user_id, expires_in, Some(extra.clone())).unwrap();
 let decoded_token = keys.decode_token(&token, "access", audiences).unwrap();

 println!("User ID: {}", decoded_token.claims.sub);
```

---

### 🧬 Using ES256 (ECDSA with P-256)

```code
 use lib_service_jwt::jwt::{JwtAlgorithm, JwtKeys};
 use std::collections::HashMap;
 use serde_json::json;

 let algo = JwtAlgorithm::ES256 {
    access_private: include_bytes!("../examples/ec/ec-access-private.pem").to_vec(),
    access_public: include_bytes!("../examples/ec/ec-access-public.pem").to_vec(),
    refresh_private: include_bytes!("../examples/ec/ec-refresh-private.pem").to_vec(),
    refresh_public: include_bytes!("../examples/ec/ec-refresh-public.pem").to_vec(),
 };

 let keys = JwtKeys::from_algorithm(algo).expect("Failed to create JwtKeys");

 let kid = "ec-key-id";
 let user_id = "user123";
 let expires_in = 60 * 60 * 24 * 30;
 let mut extra = HashMap::new();
 let roles = vec!["admin", "user"];
 extra.insert("roles".to_string(), json!(roles));

 let audiences = Some(vec!["myApp1".to_string(), "myApp2".to_string()]);
 extra.insert("aud".to_string(), json!(audiences.clone()));

 let token = keys.generate_access_token(kid, user_id, expires_in, Some(extra.clone())).unwrap();
 let decoded_token = keys.decode_token(&token, "access", audiences).unwrap();

 println!("User ID: {}", decoded_token.claims.sub);
```

---

## 🛠️ Modules

- **`jwt`** – Core logic for generating, decoding, and verifying JWTs.
- **`model`** – Contains the `Claims` structure.

---

## 🔐 Security

- Built-in support for RSA (RS256) key pairs
- Automatically checks expiration (`exp`) during decoding
- Allows additional custom claims for roles, permissions, or any metadata

---

## 🔑 Generating RSA Private and Public Keys

To generate **RSA private** and **public keys** for use with **lib_service_jwt**, follow these steps:

### 1. Install OpenSSL (if not already installed)
You can install OpenSSL using the appropriate package manager for your system:

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

These commands will generate **RSA private keys** encrypted with AES256 and save them to `access-private.pem` and `refresh-private.pem`.

### 3. Generate the RSA Public Keys

Once you have the private keys, you can extract the corresponding public keys with the following commands:

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

Once you have `access-private.pem`, `access-public.pem`, `refresh-private.pem`, and `refresh-public.pem`, you can include these keys in your project by embedding them directly in your code or loading them from disk.

---

# 🧩 **JWK (JSON Web Key) for RS256**

A **JSON Web Key** (JWK) is a JSON data structure that represents a cryptographic key.
It is used in JSON Web Signature (JWS) or JSON Web Encryption (JWE) to help verify or sign JSON Web Tokens (JWTs).
JWKs are often used to securely share public keys.

You can distribute your `jwks.json` file in a standard format by placing it under the `.well-known/` directory in your web server. This follows the convention used by many services and helps ensure your JWKs are accessible for verification by others.

For example, the JWK set can be accessible at:

```bash
https://yourdomain.com/.well-known/jwks.json
```

This makes it easier for clients or services to automatically fetch and use your public keys for validating JWTs.

To create a **JWK** (JSON Web Key), you need to extract two key components from the RSA public key: **modulus** (`n`) and **exponent** (`e`).

### 1. Extract Modulus (n) and Exponent (e) from the Public Key

This command will extract the **modulus** and **public exponent**
(which is usually `65537` in many RSA implementations) and display it in the terminal.
> **Note:**
> The string has been truncated for readability.
> The full value is much longer.

```bash
$ openssl pkey -in access-public.pem -pubin -noout -text

Public-Key: (2048 bit)
Modulus:
    00:b5:f2:5a:2e:bc:d7:20:b5:20:d5:4d:cd:d4:a5:
    7c:c8:9a:fd:d8:61:e7:e4:eb:58:65:1e:ea:5a:4d:
    4c:73:87:32:e0:91:a3:92:56:2e:a7:bc:1e:32:30:
    43:f5:fd:db:05:5a:08:b2:25:15:5f:ac:4d ...
    ... 76:e9
Exponent: 65537 (0x10001)
```

### 2. Convert Modulus and Exponent to Base64url Encoding

JWK requires **base64url encoding** for both the modulus (`n`) and the public exponent (`e`). You can convert them using the `base64` command in bash. Here’s how:

#### Encode Modulus (n) to Base64url:

```bash
echo "00:b5:f2:5a:2e:bc:d7:20:b5:20:d5:4d:cd:d4:a5:
      7c:c8:9a:fd:d8:61:e7:e4:eb:58:65:1e:ea:5a:4d:
      4c:73:87:32:e0:91:a3:92:56:2e:a7:bc:1e:32:30:
      43:f5:fd:db:05:5a:08:b2:25:15:5f:ac:4d ...
      ... 76:e9" | tr -d ": \n" | xxd -p -r | base64 | tr +/ -_ | tr -d "=\n"
```
Result:
```bash
3drYbtHpiwwif5JoaYTCeQbsLRSY2i4 ... PW1MhYjnLeAo1Ap4tfV26Q
```


#### Encode Exponent (e) to Base64url:

```bash
$ echo 010001 | xxd -p -r | base64
```
Result:
```bash
AQAB
```

### 3. Create the JWK in JSON Format

Now you can create the **JWK (JSON Web Key)** in JSON format with the encoded modulus and exponent. Here’s how to do it using text-editor like nano:

```bash
$ nano jwks.json

{
  "keys": [
    {
      "kty": "RSA",
      "kid": "some-key-id", 
      "use": "sig",
      "n": "3drYbtHpiwwif5JoaYTCeQbsLRSY2i4 ... PW1MhYjnLeAo1Ap4tfV26Q",
      "e": "AQAB"
    }
  ]
}

```

### Explanation:
- **`kty`**: The key type, here we use RSA.
- **`kid`**: Key ID, you can set it to a unique ID for your key.
- **`use`**: Indicates the use of this key, here it is used for signing (`sig`).
- **`n`** and **`e`**: The modulus and public exponent, encoded in **base64url** format.

---

## 🔑 Generating EC256 (ES256) Private and Public Keys

To generate **EC256 (P-256)** private and public keys for use with **lib_service_jwt**, follow these steps:

### 1. Install OpenSSL (if not already installed)

Same as above:

- **macOS**: `brew install openssl`
- **Ubuntu**: `sudo apt-get install openssl`
- **Windows**: Download from [here](https://slproweb.com/products/Win32OpenSSL.html).

### 2. Generate the EC256 Private Keys

For **access** tokens:

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec-access-private.pem
```

For **refresh** tokens:

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec-refresh-private.pem
```

This generates EC private keys using the **P-256 curve**, and saves them to `ec-access-private.pem` and `ec-refresh-private.pem`.

### 3. Generate the EC256 Public Keys

For **access** tokens:

```bash
openssl ec -in ec-access-private.pem -pubout -out ec-access-public.pem
```

For **refresh** tokens:

```bash
openssl ec -in ec-refresh-private.pem -pubout -out ec-refresh-public.pem
```

This generates the public keys as `ec-access-public.pem` and `ec-refresh-public.pem`.

### 4. Use the EC256 Keys in Your Project

In your Rust project, load the keys like this:

```rust
use lib_service_jwt::errors::JwtServiceError;
use lib_service_jwt::jwt::{JwtAlgorithm, JwtKeys};

fn main() -> Result<(), JwtServiceError> {
    let keys = JwtKeys::from_algorithm(JwtAlgorithm::ES256 {
        access_private: include_bytes!("../examples/ec/ec-access-private.pem").to_vec(),
        access_public: include_bytes!("../examples/ec/ec-access-public.pem").to_vec(),
        refresh_private: include_bytes!("../examples/ec/ec-refresh-private.pem").to_vec(),
        refresh_public: include_bytes!("../examples/ec/ec-refresh-public.pem").to_vec(),
    })?;
    Ok(())
}
```

Use these with the `ES256` algorithm in the `jsonwebtoken` crate.

---

# 🧩 **JWK (JSON Web Key) for EC256**

A **JSON Web Key** (JWK) is a JSON data structure that represents a cryptographic key.
For the **ES256** algorithm (Elliptic Curve using P-256), the public key is represented by its
**x** and **y** coordinates on the elliptic curve.

You can distribute your `jwks.json` file by hosting it at a public endpoint,
typically under the `.well-known/` directory on your server:

```bash
https://yourdomain.com/.well-known/jwks.json
```

This allows clients or services to automatically fetch your public key and verify JWTs signed with ES256.

### 1. Extract the Public Key Coordinates (x, y)

First, ensure you have your EC public key (`ec-access-public.pem`) generated with OpenSSL.

Then use the following command to inspect the key:

```bash
openssl ec -in ec-access-public.pem -pubin -text -noout
```

You will see something like:

```bash
read EC key
Public-Key: (256 bit)
pub:
    04:d0:de:ba:ff:be:...:3e:7c:9a
ASN1 OID: prime256v1
NIST CURVE: P-256
```

The `pub` value is an uncompressed point: it starts with `04`, followed by the 32-byte `x` and 32-byte `y` coordinates.

### 2. Extract x and y Coordinates

You can extract the `x` and `y` values from the public key in hex form and then base64url-encode them:

```bash
# Extract public key to DER format (binary)
openssl ec -in ec-access-public.pem -pubin -outform DER -out ec-access-public.der

# Convert to raw uncompressed coordinates (skip first byte 0x04)
dd if=ec-access-public.der bs=1 skip=27 count=64 of=ec-xy.raw

# Split into x and y
dd if=ec-xy.raw bs=1 count=32 of=ec-x.raw
dd if=ec-xy.raw bs=1 skip=32 count=32 of=ec-y.raw

# Convert to base64url
base64 -w0 ec-x.raw | tr +/ -_ | tr -d '=' > ec-x.b64
base64 -w0 ec-y.raw | tr +/ -_ | tr -d '=' > ec-y.b64
```

### 3. Create the JWK JSON

Now create your `jwks.json` file with the values from `ec-x.b64` and `ec-y.b64`:

```bash
$ nano jwks.json

{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "base64url-encoded-x-coordinate",
      "y": "base64url-encoded-y-coordinate",
      "use": "sig",
      "alg": "ES256",
      "kid": "your-ec-key-id"
    }
  ]
}
```

### Explanation:
- **`kty`**: Key type — for EC keys this is `"EC"`.
- **`crv`**: Curve — `"P-256"` for ES256.
- **`x`** and **`y`**: X and Y coordinates of the public key in **base64url** format (no padding).
- **`use`**: `"sig"` indicates this key is used for signing.
- **`alg`**: `"ES256"` specifies the JWT algorithm.
- **`kid`**: Key ID — used to match the JWT header with the key.

---
✅ You now have a valid `jwks.json` file ready to serve and use with ES256 JWTs.

---

## 📄 License

Licensed under the <a href="https://www.apache.org/licenses/LICENSE-2.0.txt" target="_blank">Apache License 2.0</a>.

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


---

## 📦 Changelog

### v0.1.2
- **Added ES256 (EC256) support**: You can now sign and verify JWTs using the `ES256` algorithm (Elliptic Curve with P-256).
- **Extended `JwtAlgorithm` enum**: Introduced a new `ES256` variant with corresponding fields for access and refresh keys.
- **Implemented `Ec256KeyPair` backend**: Includes logic for encoding and decoding JWTs using EC private/public key pairs.
- **Documented how to generate EC keys**: Included full OpenSSL-based walkthrough for generating and formatting EC256 keys.
- **JWKS support for EC keys**: Explained how to expose EC public keys via `jwks.json` with correct `x`, `y`, and `crv` fields.
- **Minor improvements**: Code cleanup, improved internal naming consistency, and enhanced documentation.

### v0.1.1
- **Added `JwtServiceError`**: A structured error enum mirroring variants from `jsonwebtoken::errors`, allowing more transparent and fine-grained error handling.
- **Implemented `From<jsonwebtoken::errors::Error>`**: Enables seamless conversion from raw JWT errors into the custom `JwtServiceError` enum.
- **Added `thiserror` dependency**: Used for ergonomic and readable custom error definitions via the `#[derive(Error)]` macro.
- **Minor improvements**: Code cleanup, improved internal naming consistency, and enhanced documentation.

---
