# lib-service-jwt

🚀 Lightweight authentication service logic in Rust using [JWT (JSON Web Tokens)](https://jwt.io) for access and refresh tokens.

`lib-service-jwt` is designed to be embedded in your authentication services or user management APIs. It gives you clean, testable token logic with built-in support for custom claims.

---

## ✨ Features

- 🔐 **Access & Refresh Token Support**  
  Generate separate tokens with individual expiration and secrets.

- 🧩 **Custom Claims**  
  Add any additional fields (e.g. `role`, `user_id`) to your tokens using `HashMap<String, Value>`.

- ⏳ **Expiration Handling**  
  Uses `chrono` for precise time-based token lifetimes.

- 🧪 **Fully Testable & Minimal**  
  No framework dependencies, easy to plug into any stack (Actix, Axum, Rocket, etc.)

---

## 📦 Installation

Add to your `Cargo.toml`:

```toml
lib-service-jwt = { path = "../lib-service-jwt" } # or version from crates.io when published
