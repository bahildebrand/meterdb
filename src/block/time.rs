use chrono::{DateTime, Utc};

pub trait Timestamp {
    fn now(&self) -> Result<DateTime<Utc>, &'static str>;
}

#[cfg(any(feature = "std", test))]
pub struct StdTimestamp;

#[cfg(any(feature = "std", test))]
impl Timestamp for StdTimestamp {
    fn now(&self) -> Result<DateTime<Utc>, &'static str> {
        Ok(Utc::now())
    }
}
