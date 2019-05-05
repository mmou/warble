#![feature(inner_deref)]
//!  AEAD traits and implementation using Strobe.
mod traits;
mod warble;
mod window;

pub use crate::traits::{AeadReceiver, AeadSender, NonceError};
pub use crate::warble::{Warblee, Warbler};
pub use crate::window::Window;
