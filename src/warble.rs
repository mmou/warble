/// Warbler and Warblee implement AeadSender and AeadReceiver respectively. They support
/// authenticated encrypted communication sessions over an unreliable transport.
///
/// Within a session, each pair of send and receive operations forks the transcript in order to
/// allow for out-of-order encryption and authentication of each message. A unique nonce per
/// message ensures uniqueness of the transcript per message.
extern crate rand_core;
extern crate strobe_rs;
use crate::traits::{AeadReceiver, AeadSender, NonceError};
use crate::window::Window;
use rand_core::{CryptoRng, RngCore};
use strobe_rs::{AuthError, Strobe};

static DOMAIN_SEP: &str = "https://github.com/mmou/warble";

/// Warbler maintains sender's transcript for a given session
pub struct Warbler {
    transcript: Strobe,
    counter: u32,
}

/// Warblee maintains the receiver's transcript for a given session.
pub struct Warblee {
    transcript: Strobe,
    window: Window,
}

impl Warbler {
    /// creates a new session, populates session_id with an encrypted, newly generated session id.
    pub fn new<T>(mut transcript: Strobe, rng: &mut T, session_id: Option<&mut [u8]>) -> Self
    where
        T: RngCore + CryptoRng,
    {
        transcript.ad(DOMAIN_SEP.as_bytes(), false);
        transcript.ad(&1u8.to_be_bytes(), false); // protocol version 0x01

        // random session id, ensures unique nonces between sessions
        if let Some(session_id) = session_id {
            let mut new_session_id = rng.next_u64().to_be_bytes();
            session_id.copy_from_slice(&mut new_session_id);
            transcript.send_enc(session_id, false);
        }

        Warbler {
            transcript,
            counter: 0u32,
        }
    }
}

impl Warblee {
    /// creates a new session with a given encrypted session id.
    pub fn new(mut transcript: Strobe, encrypted_session_id: Option<&mut [u8]>) -> Self {
        transcript.ad(DOMAIN_SEP.as_bytes(), false);
        transcript.ad(&1u8.to_be_bytes(), false); // protocol version 0x01
        if let Some(encrypted_session_id) = encrypted_session_id {
            transcript.recv_enc(encrypted_session_id, false);
        }
        Warblee {
            transcript,
            window: Window::new(),
        }
    }
}

impl AeadSender for Warbler {
    fn send(
        &mut self,
        data: Option<&mut [u8]>,
        ad: Option<&[u8]>,
        mac: &mut [u8],
        nonce: &mut [u8],
    ) -> Result<(), NonceError> {
        // fork the transcript
        let transcript = &mut self.transcript.clone();

        // sender is responsible for not reusing nonces
        if self.counter == u32::max_value() - 1 {
            return Err(NonceError);
        } else {
            self.counter += 1;
        }
        let new_nonce = &self.counter.to_be_bytes();
        transcript.meta_ad(new_nonce, false);
        nonce.copy_from_slice(new_nonce);

        if let Some(ad) = ad {
            transcript.ad(ad, false);
        }

        // encrypt then mac
        if let Some(data) = data {
            transcript.send_enc(data, false);
        }
        transcript.send_mac(mac, false);

        Ok(())
    }
}

impl AeadReceiver for Warblee {
    fn receive(
        &mut self,
        data: Option<&mut [u8]>,
        ad: Option<&[u8]>,
        mac: &mut [u8],
        nonce: Option<&mut [u8]>,
    ) -> Result<(), AuthError> {
        // fork the transcript
        let transcript = &mut self.transcript.clone();

        if let Some(nonce) = nonce {
            let mut new_nonce = 0u32.to_be_bytes();
            new_nonce.copy_from_slice(nonce);
            if self.window.check_counter(u32::from_be_bytes(new_nonce)) {
                transcript.meta_ad(&new_nonce, false);
            } else {
                return Err(AuthError);
            }
        }

        if let Some(ad) = ad {
            transcript.ad(ad, false);
        }
        if let Some(data) = data {
            transcript.recv_enc(data, false);
        }

        transcript.recv_mac(mac, false)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate rand;

    use crate::traits::*;
    use crate::warble::*;
    use rand::rngs::OsRng;
    use strobe_rs::{SecParam, Strobe};

    const MSG_LEN: usize = 24; // bytes

    fn setup_warble() -> (Warbler, Warblee) {
        let mut ta = Strobe::new(b"warbletest", SecParam::B128);
        let mut tb = Strobe::new(b"warbletest", SecParam::B128);

        ta.key(b"secretkey", false);
        tb.key(b"secretkey", false);

        let session_id = &mut [0u8; 8];
        let sender = Warbler::new(ta, &mut OsRng, Some(session_id));
        let receiver = Warblee::new(tb, Some(session_id));
        (sender, receiver)
    }

    #[test]
    fn simple() {
        let (mut sender, mut receiver) = setup_warble();
        let txt = b"hello world";
        let mut message = [0u8; MSG_LEN];
        for (m, t) in message.iter_mut().zip(txt.iter()) {
            *m = *t
        }
        let mut pre = [0u8; MSG_LEN];
        pre.copy_from_slice(&message);

        let ad = Some("additional stuff".as_bytes());
        let mut mac = [0u8; MAC_LEN];
        let nonce = &mut 0u32.to_be_bytes();

        assert!(sender.send(Some(&mut message), ad, &mut mac, nonce).is_ok());
        let mut ciphertext = [0u8; MSG_LEN];
        ciphertext.copy_from_slice(&message);

        assert!(receiver
            .receive(Some(&mut ciphertext), ad, &mut mac, Some(nonce))
            .is_ok());
        let mut round_trip = [0u8; MSG_LEN];
        round_trip.copy_from_slice(&ciphertext);

        assert_eq!(round_trip, pre);
        assert_eq!(sender.counter, 1);
    }

    #[test]
    fn in_order_messages() {
        let (mut sender, mut receiver) = setup_warble();
        for _i in 0..20 {
            let txt = b"hello world";
            let mut message = [0u8; MSG_LEN];
            for (m, t) in message.iter_mut().zip(txt.iter()) {
                *m = *t
            }
            let mut pre = [0u8; MSG_LEN];
            pre.copy_from_slice(&message);

            let ad = Some("additional stuff".as_bytes());
            let mut mac = [0u8; MAC_LEN];
            let nonce = &mut 0u32.to_be_bytes();

            assert!(sender.send(Some(&mut message), ad, &mut mac, nonce).is_ok());
            let mut ciphertext = [0u8; MSG_LEN];
            ciphertext.copy_from_slice(&message);

            assert!(receiver
                .receive(Some(&mut ciphertext), ad, &mut mac, Some(nonce))
                .is_ok());
            let mut round_trip = [0u8; MSG_LEN];
            round_trip.copy_from_slice(&ciphertext);

            assert_eq!(round_trip, pre);
        }
        assert_eq!(sender.counter, 20);
    }

    #[test]
    fn unordered_messages() {
        let (mut sender, mut receiver) = setup_warble();
        let txt = b"hello world";
        let mut message1 = [0u8; MSG_LEN];
        let mut message2 = [0u8; MSG_LEN];
        for (m, t) in message1.iter_mut().zip(txt.iter()) {
            *m = *t
        }
        for (m, t) in message2.iter_mut().zip(txt.iter()) {
            *m = *t
        }
        let mut pre = [0u8; MSG_LEN];
        pre.copy_from_slice(&message1);

        let ad = Some("additional stuff".as_bytes());
        let mut mac1 = [0u8; MAC_LEN];
        let mut mac2 = [0u8; MAC_LEN];
        let nonce1 = &mut 0u32.to_be_bytes();
        let nonce2 = &mut 0u32.to_be_bytes();

        assert!(sender
            .send(Some(&mut message1), ad, &mut mac1, nonce1)
            .is_ok());
        let mut ciphertext1 = [0u8; MSG_LEN];
        ciphertext1.copy_from_slice(&message1);

        assert!(sender
            .send(Some(&mut message2), ad, &mut mac2, nonce2)
            .is_ok());
        let mut ciphertext2 = [0u8; MSG_LEN];
        ciphertext2.copy_from_slice(&message2);

        assert!(receiver
            .receive(Some(&mut ciphertext2), ad, &mut mac2, Some(nonce2))
            .is_ok());
        let mut round_trip2 = [0u8; MSG_LEN];
        round_trip2.copy_from_slice(&ciphertext2);
        assert_eq!(round_trip2, pre);

        assert!(receiver
            .receive(Some(&mut ciphertext1), ad, &mut mac1, Some(nonce1))
            .is_ok());
        let mut round_trip1 = [0u8; MSG_LEN];
        round_trip1.copy_from_slice(&ciphertext1);
        assert_eq!(round_trip1, pre);

        assert_eq!(sender.counter, 2);
    }

    #[test]
    fn no_message() {
        let (mut sender, mut receiver) = setup_warble();

        let txt = b"hello world";
        let mut message2 = [0u8; MSG_LEN];
        for (m, t) in message2.iter_mut().zip(txt.iter()) {
            *m = *t
        }
        let mut pre = [0u8; MSG_LEN];
        pre.copy_from_slice(&message2);

        let ad = Some("additional stuff".as_bytes());
        let mut mac1 = [0u8; MAC_LEN];
        let mut mac2 = [0u8; MAC_LEN];
        let nonce1 = &mut 0u32.to_be_bytes();
        let nonce2 = &mut 0u32.to_be_bytes();

        // send no message
        assert!(sender.send(None, ad, &mut mac1, nonce1).is_ok());
        assert!(receiver.receive(None, ad, &mut mac1, Some(nonce1)).is_ok());

        // then, send a message, and assert that you get the expected message
        assert!(sender
            .send(Some(&mut message2), ad, &mut mac2, nonce2)
            .is_ok());
        let mut ciphertext2 = [0u8; MSG_LEN];
        ciphertext2.copy_from_slice(&message2);

        assert!(receiver
            .receive(Some(&mut ciphertext2), ad, &mut mac2, Some(nonce2))
            .is_ok());
        let mut round_trip2 = [0u8; MSG_LEN];
        round_trip2.copy_from_slice(&ciphertext2);
        assert_eq!(round_trip2, pre);
    }

    #[test]
    fn no_additional_data() {
        let (mut sender, mut receiver) = setup_warble();
        let txt = b"hello world";
        let mut message = [0u8; MSG_LEN];
        for (m, t) in message.iter_mut().zip(txt.iter()) {
            *m = *t
        }
        let mut pre = [0u8; MSG_LEN];
        pre.copy_from_slice(&message);

        let ad = None;
        let mut mac = [0u8; MAC_LEN];
        let nonce = &mut 0u32.to_be_bytes();

        assert!(sender.send(Some(&mut message), ad, &mut mac, nonce).is_ok());
        let mut ciphertext = [0u8; MSG_LEN];
        ciphertext.copy_from_slice(&message);

        assert!(receiver
            .receive(Some(&mut ciphertext), ad, &mut mac, Some(nonce))
            .is_ok());
        let mut round_trip = [0u8; MSG_LEN];
        round_trip.copy_from_slice(&ciphertext);
        assert_eq!(round_trip, pre);
    }

    #[test]
    #[should_panic]
    fn bad_transcript() {
        let (mut sender, mut receiver) = setup_warble();
        sender.transcript.ad(b"mess up the transcript!!", false);

        let txt = b"hello world";
        let mut message = [0u8; MSG_LEN];
        for (m, t) in message.iter_mut().zip(txt.iter()) {
            *m = *t
        }
        let mut pre = [0u8; MSG_LEN];
        pre.copy_from_slice(&message);

        let ad = None;
        let mut mac = [0u8; MAC_LEN];
        let nonce = &mut 0u32.to_be_bytes();

        assert!(sender.send(None, ad, &mut mac, nonce).is_ok());
        let mut ciphertext = [0u8; MSG_LEN];
        ciphertext.copy_from_slice(&message);

        assert!(receiver.receive(None, ad, &mut mac, Some(nonce)).is_ok());
        let mut round_trip = [0u8; MSG_LEN];
        round_trip.copy_from_slice(&ciphertext);
        assert_eq!(round_trip, pre);
    }

    #[test]
    #[should_panic]
    fn bad_counter() {
        let (mut sender, _) = setup_warble();
        let message = None;
        let ad = None;
        let mut mac = [0u8; MAC_LEN];
        let nonce = &mut 0u32.to_be_bytes();
        sender.counter = u32::max_value() - 1;
        assert!(sender.send(message, ad, &mut mac, nonce).is_ok());
    }
}
