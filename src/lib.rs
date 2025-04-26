//! # Dokumentasi Crate: JWT dan JWKS
//!
//! Crate ini menyediakan fungsionalitas terkait dengan penggunaan **JSON Web Tokens (JWT)** 
//! dan **JSON Web Key Sets (JWKS)** dalam aplikasi. Crate ini dibagi menjadi beberapa modul:
//!
//! - `model`: Mendefinisikan struktur data yang digunakan dalam aplikasi, termasuk token JWT dan klaim terkait.
//! - `jwt`: Menyediakan fungsi untuk membuat, memverifikasi, dan mengelola JSON Web Tokens.
//! - `jwks`: Menyediakan fungsionalitas untuk menangani dan mengelola JSON Web Key Sets.

 

pub mod model;
pub mod jwt;
pub mod jwks;
