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
const NONCE_LEN: usize = 64 / 8; // bytes
const MAC_LEN: usize = 16; // bytes
const MIN_LEN: usize = NONCE_LEN + MAC_LEN;

/// Warbler maintains sender's transcript for a given session
pub struct Warbler {
    transcript: Strobe,
    counter: u64,
}

/// Warblee maintains the receiver's transcript for a given session.
pub struct Warblee {
    transcript: Strobe,
    window: Window,
}

impl Warbler {
    /// creates a new session, generates and encrypts a random session id.
    pub fn new<T>(mut transcript: Strobe, rng: &mut T) -> (Self, Vec<u8>)
    where
        T: RngCore + CryptoRng,
    {
        transcript.ad(DOMAIN_SEP.as_bytes().to_vec(), None, false);
        transcript.ad(vec![1], None, false); // protocol version 0x01

        // random session id, ensures unique nonces between sessions
        let session_id: u64 = rng.next_u64();
        let encrypted_session_id =
            transcript.send_enc(session_id.to_be_bytes().to_vec(), None, false);

        (
            Warbler {
                transcript,
                counter: 0u64,
            },
            encrypted_session_id,
        )
    }
}

impl Warblee {
    /// creates a new session with a given encrypted session id.
    pub fn new(mut transcript: Strobe, encrypted_session_id: &[u8]) -> Self {
        transcript.ad(DOMAIN_SEP.as_bytes().to_vec(), None, false);
        transcript.ad(vec![1], None, false); // protocol version 0x01
        transcript.recv_enc(encrypted_session_id.to_vec(), None, false);

        Warblee {
            transcript,
            window: Window::new(),
        }
    }
}

impl AeadSender for Warbler {
    fn send(&mut self, data: Option<&[u8]>, ad: Option<&[u8]>) -> Result<Vec<u8>, NonceError> {
        // fork the transcript
        let transcript = &mut self.transcript.clone();

        // sender is responsible for not reusing nonces
        if self.counter == u64::max_value() - 1 {
            return Err(NonceError);
        } else {
            self.counter += 1;
        }
        let nonce = self.counter.to_be_bytes().to_vec();
        transcript.ad(nonce.clone(), None, false);

        if let Some(ad) = ad {
            transcript.ad(ad.to_vec(), None, false);
        }

        // encrypt then mac
        let mut ciphertext = nonce;
        if let Some(data) = data {
            ciphertext.append(&mut transcript.send_enc(data.to_vec(), None, false));
        }

        ciphertext.append(&mut transcript.send_mac(MAC_LEN, None, false));

        Ok(ciphertext)
    }
}

impl AeadReceiver for Warblee {
    // expected data format: nonce || optional encrypted message || mac
    // TODO: replace with a struct, as is done in
    // https://github.com/rozbb/disco-rs/blob/master/src/symmetric.rs?
    fn receive(&mut self, data: &[u8], ad: Option<&[u8]>) -> Result<Option<Vec<u8>>, AuthError> {
        // fork the transcript
        let transcript = &mut self.transcript.clone();

        let ciphertext = Ciphertext::parse(data)?;

        let mut nonce: [u8; 8] = [0; 8];
        nonce.copy_from_slice(ciphertext.nonce);
        if self.window.check_counter(usize::from_be_bytes(nonce)) {
            transcript.ad(ciphertext.nonce.to_vec(), None, false);
        } else {
            return Err(AuthError);
        }

        if let Some(ad) = ad {
            transcript.ad(ad.to_vec(), None, false);
        }

        let plaintext;
        if ciphertext.msg.len() == 0 {
            plaintext = None;
        } else {
            plaintext = Some(transcript.recv_enc(ciphertext.msg.to_vec(), None, false));
        }

        transcript.recv_mac(ciphertext.mac.to_vec(), None, false)?;
        Ok(plaintext)
    }
}

struct Ciphertext<'a> {
    nonce: &'a [u8],
    msg: &'a [u8],
    mac: &'a [u8],
}

impl<'a> Ciphertext<'a> {
    fn parse(data: &'a [u8]) -> Result<Ciphertext, AuthError> {
        if data.len() < MIN_LEN {
            return Err(AuthError);
        }

        let data_len = data.len() - MAC_LEN;
        Ok(Ciphertext {
            nonce: &data[..NONCE_LEN],
            msg: &data[NONCE_LEN..data_len],
            mac: &data[data_len..],
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate rand;

    use crate::warble::*;
    use rand::rngs::OsRng;
    use strobe_rs::{SecParam, Strobe};
    use yodel::Yodeler;

    // demonstrate usage with yodel for key agreement using SPEKE
    #[allow(non_snake_case)]
    fn setup_yodel() -> (Warbler, Warblee) {
        let mut rng = OsRng::new().unwrap();

        let s_a = Strobe::new(b"yodeltest".to_vec(), SecParam::B128);
        let s_b = Strobe::new(b"yodeltest".to_vec(), SecParam::B128);

        let (yodeler_a, X) = Yodeler::new(s_a, &mut rng, "testpassword".as_bytes());
        let (yodeler_b, Y) = Yodeler::new(s_b, &mut rng, "testpassword".as_bytes());

        let (mut tx_a, mut rx_a) = yodeler_a.complete(Y);
        let (mut tx_b, mut rx_b) = yodeler_b.complete(X);

        assert_eq!(tx_a.prf(64, None, false), rx_b.prf(64, None, false));
        assert_eq!(tx_b.prf(64, None, false), rx_a.prf(64, None, false));

        let (sender, session_id) = Warbler::new(tx_a, &mut rng);
        let receiver = Warblee::new(rx_b, &session_id);
        (sender, receiver)
    }

    fn setup_warble() -> (Warbler, Warblee) {
        let mut rng = OsRng::new().unwrap();

        let mut ta = Strobe::new(b"yodeltest".to_vec(), SecParam::B128);
        let mut tb = Strobe::new(b"yodeltest".to_vec(), SecParam::B128);

        ta.key(b"secretkey".to_vec(), None, false);
        tb.key(b"secretkey".to_vec(), None, false);

        let (sender, session_id) = Warbler::new(ta, &mut rng);
        let receiver = Warblee::new(tb, &session_id);
        (sender, receiver)
    }

    #[test]
    fn simple() {
        let (mut sender, mut receiver) = setup_warble();
        let message = Some("hello world".as_bytes());
        let ad = Some("additional stuff".as_bytes());
        let ciphertext: Vec<u8> = sender.send(message, ad).unwrap();
        let response = receiver.receive(&ciphertext, ad);
        assert_eq!(message, response.unwrap().deref());
        assert_eq!(sender.counter, 1);
    }

    #[test]
    fn in_order_messages() {
        let (mut sender, mut receiver) = setup_warble();
        for i in 0..20 {
            let message = format!("hello world {}", i);
            let message = Some(message.as_bytes());
            let ad = Some("additional stuff".as_bytes());
            let ciphertext: Vec<u8> = sender.send(message, ad).unwrap();
            let response = receiver.receive(&ciphertext, ad);
            assert_eq!(message, response.unwrap().deref());
        }
        assert_eq!(sender.counter, 20);
    }

    #[test]
    fn unordered_messages() {
        let (mut sender, mut receiver) = setup_warble();
        let message = Some("hello world".as_bytes());
        let ad = Some("additional stuff".as_bytes());

        let ciphertext1: Vec<u8> = sender.send(message, ad).unwrap();
        let ciphertext2: Vec<u8> = sender.send(message, ad).unwrap();

        let response2 = receiver.receive(&ciphertext2, ad);
        assert_eq!(message, response2.unwrap().deref());

        let response1 = receiver.receive(&ciphertext1, ad);
        assert_eq!(message, response1.unwrap().deref());

        assert_eq!(sender.counter, 2);
    }

    #[test]
    fn no_message() {
        let (mut sender, mut receiver) = setup_warble();
        let message = None;
        let ad = Some("additional stuff".as_bytes());
        let ciphertext: Vec<u8> = sender.send(message, ad).unwrap();
        let response = receiver.receive(&ciphertext, ad);
        assert_eq!(message, response.unwrap().deref());
    }

    #[test]
    fn no_additional_data() {
        let (mut sender, mut receiver) = setup_warble();
        let message = Some("hello world".as_bytes());
        let ad = None;
        let ciphertext: Vec<u8> = sender.send(message, ad).unwrap();
        let response = receiver.receive(&ciphertext, ad);
        assert_eq!(message, response.unwrap().deref());
    }

    #[test]
    fn no_data() {
        // i mean i guess
        let (mut sender, mut receiver) = setup_warble();
        let message = None;
        let ad = None;
        let ciphertext: Vec<u8> = sender.send(message, ad).unwrap();
        let response = receiver.receive(&ciphertext, ad);
        assert_eq!(message, response.unwrap().deref());
    }

    #[test]
    #[should_panic]
    fn bad_transcript() {
        let (mut sender, mut receiver) = setup_warble();
        sender
            .transcript
            .ad(b"mess up the transcript!!".to_vec(), None, false);
        let message = None;
        let ad = None;
        let ciphertext: Vec<u8> = sender.send(message, ad).unwrap();
        let response = receiver.receive(&ciphertext, ad);
        assert_eq!(message, response.unwrap().deref());
    }

    #[test]
    #[should_panic]
    fn bad_counter() {
        let (mut sender, _) = setup_warble();
        let message = None;
        let ad = None;
        sender.counter = u64::max_value() - 1;
        sender.send(message, ad).unwrap();
    }

    #[test]
    #[should_panic]
    fn short_ciphertext() {
        let (mut sender, mut receiver) = setup_warble();
        let message = Some("hello world".as_bytes());
        let ad = Some("additional stuff".as_bytes());
        let ciphertext: Vec<u8> = sender.send(message, ad).unwrap();
        let response = receiver.receive(&ciphertext[..MIN_LEN - 1], ad);
        assert_eq!(message, response.unwrap().deref());
    }

    #[test]
    fn yodel() {
        let (mut sender, mut receiver) = setup_yodel();
        let message = Some("hello world".as_bytes());
        let ad = Some("additional stuff".as_bytes());
        let ciphertext: Vec<u8> = sender.send(message, ad).unwrap();
        let response = receiver.receive(&ciphertext, ad);
        assert_eq!(message, response.unwrap().deref());
    }
}
