#![no_std]

mod block;
mod db;

pub use db::Db as TimmyDb;
pub use db::DbWriter as TimmyDbWriter;

#[cfg(test)]
extern crate std;
