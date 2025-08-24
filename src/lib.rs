#![no_std]

mod block;
mod db;

pub use db::Db as TimmyDb;

#[cfg(test)]
extern crate std;
