///  AEAD Sender and Receiver traits, and implementations for the Strobe struct, based on https://strobe.sourceforge.io/examples/aead/.
extern crate strobe_rs;
use strobe_rs::{AuthError, Strobe};

pub static DOMAIN_SEP: &str = "https://strobe.sourceforge.io/examples/aead";
pub const MAC_LEN: usize = 16; // bytes
pub const MSG_LEN: usize = 24; // bytes

#[derive(Debug)]
pub struct NonceError;

pub trait AeadSender {
    fn send(
        &mut self,
        data: Option<&mut [u8]>,
        ad: Option<&[u8]>,
        mac: &mut [u8],
        nonce: &mut [u8],
    ) -> Result<(), NonceError>;
}

pub trait AeadReceiver {
    fn receive(
        &mut self,
        data: Option<&mut [u8]>,
        ad: Option<&[u8]>,
        mac: &mut [u8],
        nonce: Option<&mut [u8]>,
    ) -> Result<(), AuthError>;
}

impl AeadSender for Strobe {
    fn send(
        &mut self,
        data: Option<&mut [u8]>,
        ad: Option<&[u8]>,
        mac: &mut [u8],
        nonce: &mut [u8],
    ) -> Result<(), NonceError> {
        self.ad(DOMAIN_SEP.as_bytes(), false);

        if let Some(ad) = ad {
            self.ad(ad, false);
        }

        let new_nonce = &0usize.to_be_bytes();
        self.meta_ad(new_nonce, false);
        nonce.copy_from_slice(new_nonce);

        // encrypt then mac
        if let Some(d) = data {
            self.send_enc(d, false);
        }
        self.send_mac(mac, false);
        Ok(())
    }
}

impl AeadReceiver for Strobe {
    fn receive(
        &mut self,
        data: Option<&mut [u8]>,
        ad: Option<&[u8]>,
        mac: &mut [u8],
        nonce: Option<&mut [u8]>,
    ) -> Result<(), AuthError> {
        self.ad(DOMAIN_SEP.as_bytes(), false);

        if let Some(ad) = ad {
            self.ad(ad, false);
        }

        if let Some(nonce) = nonce {
            self.meta_ad(nonce, false);
        }

        if let Some(data) = data {
            self.recv_enc(data, false);
        }
        self.recv_mac(mac, false)
    }
}

#[cfg(test)]
mod tests {
    use crate::traits::*;
    use strobe_rs::{SecParam, Strobe};

    fn setup_strobe() -> (Strobe, Strobe) {
        let mut ta = Strobe::new(b"strobetest", SecParam::B128);
        let mut tb = Strobe::new(b"strobetest", SecParam::B128);

        ta.key(b"secretkey", false);
        tb.key(b"secretkey", false);

        (ta, tb)
    }

    #[test]
    fn strobe() {
        let (mut sender, mut receiver) = setup_strobe();
        let mut message = [0u8; MSG_LEN];
        let txt = b"hello world";
        for (m, t) in message.iter_mut().zip(txt.iter()) {
            *m = *t
        }
        assert_eq!(message.len(), MSG_LEN);
        let mut pre = [0u8; MSG_LEN];
        pre.copy_from_slice(&message);

        let ad = Some("additional stuff".as_bytes());
        let mut mac = [0u8; MAC_LEN];
        let nonce = &mut 0usize.to_be_bytes();
        assert!(sender.send(Some(&mut message), ad, &mut mac, nonce).is_ok());
        let mut ciphertext = [0u8; MSG_LEN];
        ciphertext.copy_from_slice(&message);
        assert_eq!(message.len(), ciphertext.len());

        assert!(receiver
            .receive(Some(&mut ciphertext), ad, &mut mac, Some(nonce))
            .is_ok());
        let mut round_trip = [0u8; MSG_LEN];
        round_trip.copy_from_slice(&ciphertext);

        assert_eq!(round_trip, pre);
    }

    #[test]
    #[should_panic]
    fn strobe_unordered_messages() {
        let (mut sender, mut receiver) = setup_strobe();
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
        let nonce1 = &mut 0usize.to_be_bytes();
        let nonce2 = &mut 0usize.to_be_bytes();

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

        // bare strobe doesn't support out of order messages
        assert_eq!(round_trip2, pre);
    }
}
