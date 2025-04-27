//! This crate provides functionality related to the usage of **JSON Web Tokens (JWT)**.
//!
//! It is built on top of the [`jsonwebtoken`] crate to provide a more structured and extensible
//! way to generate, decode, and manage JWTs for authentication and authorization purposes.
//!
//! The crate is divided into several modules:
//!
//! - `model`: Defines the data structures used in the application, including JWT tokens and related claims.
//! - `jwt`: Provides functions for creating, verifying, and managing JSON Web Tokens.
//!
//! [`jsonwebtoken`]: https://docs.rs/jsonwebtoken

pub mod model;
pub mod jwt;
