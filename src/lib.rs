#![no_std]

mod block;
mod db;

#[cfg(any(feature = "std", test))]
pub use block::StdTimestamp;
pub use block::Timestamp;
pub use db::Db as TimmyDb;
pub use db::DbWriter as TimmyDbWriter;

#[cfg(test)]
extern crate std;
