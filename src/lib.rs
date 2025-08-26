#![no_std]

mod block;
mod db;

#[cfg(any(feature = "std", test))]
pub use block::StdTimestamp;
pub use block::Timestamp;
pub use db::Db as MeterDb;
pub use db::DbWriter as MeterDbWriter;

#[cfg(test)]
extern crate std;
