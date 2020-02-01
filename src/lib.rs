#![no_std]
#![feature(inner_deref)]
///  AEAD traits and implementation using Strobe.
mod traits;
mod warble;
mod window;

#[cfg(any(test, feature = "rand"))]
extern crate rand;

pub use crate::traits::{AeadReceiver, AeadSender, NonceError, DOMAIN_SEP, MAC_LEN, MSG_LEN};
pub use crate::warble::{Warblee, Warbler};
pub use crate::window::Window;
