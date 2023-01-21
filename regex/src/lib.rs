//! # crate for regex engine
//!
//! ## usage
//!
//! ```
//! use regex;
//! let expr = "a(bc)+|c(def)*"; // regex expression
//! let line = "cdefdefdef"; // target
//! regex::do_matching(expr, line, true); // matching with DFS
//! regex::print(expr); // show expression and AST
//! ```
mod engine;
mod helper;

pub use engine::{do_matching, print};
