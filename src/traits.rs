//!  AEAD Sender and Receiver traits, and implementations for Strobe, based on https://strobe.sourceforge.io/examples/aead/.
extern crate strobe_rs;
use strobe_rs::{AuthError, Strobe};

static DOMAIN_SEP: &str = "https://strobe.sourceforge.io/examples/aead";
const MAC_LEN: usize = 16; // bytes

#[derive(Debug)]
pub struct NonceError;

pub trait AeadSender {
    fn send(&mut self, data: Option<&[u8]>, ad: Option<&[u8]>) -> Result<Vec<u8>, NonceError>;
}

pub trait AeadReceiver {
    fn receive(&mut self, data: &[u8], ad: Option<&[u8]>) -> Result<Option<Vec<u8>>, AuthError>;
}

impl AeadSender for Strobe {
    fn send(&mut self, data: Option<&[u8]>, ad: Option<&[u8]>) -> Result<Vec<u8>, NonceError> {
        self.ad(DOMAIN_SEP.as_bytes().to_vec(), None, false);

        if let Some(ad) = ad {
            self.ad(ad.to_vec(), None, false);
        }

        // encrypt then mac
        let mut ciphertext = Vec::new();
        if let Some(data) = data {
            ciphertext.append(&mut self.send_enc(data.to_vec(), None, false));
        }

        ciphertext.append(&mut self.send_mac(MAC_LEN, None, false));

        Ok(ciphertext)
    }
}

impl AeadReceiver for Strobe {
    // expected data format: optional encrypted message || mac
    fn receive(&mut self, data: &[u8], ad: Option<&[u8]>) -> Result<Option<Vec<u8>>, AuthError> {
        self.ad(DOMAIN_SEP.as_bytes().to_vec(), None, false);

        if data.len() < MAC_LEN {
            return Err(AuthError);
        }

        if let Some(ad) = ad {
            self.ad(ad.to_vec(), None, false);
        }

        let plaintext;
        let data_len = data.len() - MAC_LEN;
        if data.len() == MAC_LEN {
            plaintext = None;
        } else {
            plaintext = Some(self.recv_enc(data[..data_len].to_vec(), None, false));
        }

        self.recv_mac(data[data_len..].to_vec(), None, false)?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use crate::traits::*;
    use strobe_rs::{SecParam, Strobe};

    fn setup_strobe() -> (Strobe, Strobe) {
        let mut ta = Strobe::new(b"strobetest".to_vec(), SecParam::B128);
        let mut tb = Strobe::new(b"strobetest".to_vec(), SecParam::B128);

        ta.key(b"secretkey".to_vec(), None, false);
        tb.key(b"secretkey".to_vec(), None, false);

        (ta, tb)
    }

    #[test]
    fn strobe() {
        let (mut sender, mut receiver) = setup_strobe();
        let message = Some("hello world".as_bytes());
        let ad = Some("additional stuff".as_bytes());
        let ciphertext: Vec<u8> = sender.send(message, ad).unwrap();
        let response = receiver.receive(&ciphertext, ad);
        assert_eq!(message, response.unwrap().deref());
    }

    #[test]
    #[should_panic]
    fn strobe_unordered_messages() {
        let (mut sender, mut receiver) = setup_strobe();
        let message = Some("hello world".as_bytes());
        let ad = Some("additional stuff".as_bytes());

        let _ciphertext1: Vec<u8> = sender.send(message, ad).unwrap();
        let ciphertext2: Vec<u8> = sender.send(message, ad).unwrap();

        let response2 = receiver.receive(&ciphertext2, ad);
        // bare strobe doesn't support out of order messages
        assert_eq!(message, response2.unwrap().deref());
    }
}
