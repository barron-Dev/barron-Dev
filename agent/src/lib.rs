pub mod events;

#[cfg(windows)]
pub mod etw;

pub use events::{EventKind, EndpointEvent};
