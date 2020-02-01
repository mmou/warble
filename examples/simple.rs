extern crate rand;
extern crate warble;

use rand::rngs::OsRng;
use std::str;
use strobe_rs::{SecParam, Strobe};
use warble::{AeadReceiver, AeadSender, Warblee, Warbler, MAC_LEN, MSG_LEN};

fn main() {
    // create and key Strobe transcripts.
    let mut ta = Strobe::new(b"warbletest", SecParam::B128);
    let mut tb = Strobe::new(b"warbletest", SecParam::B128);
    ta.key(b"secretkey", false);
    tb.key(b"secretkey", false);

    // ta is the sender's transcript, tb is the receiver's transcript
    let session_id = &mut [0u8; 8];
    let mut sender = Warbler::new(ta, &mut OsRng, session_id);
    let mut receiver = Warblee::new(tb, session_id);

    let txts: [&[u8]; 2] = [b"hello world", b"second message"];
    for txt in &txts {
        println!("Sending message: {:?}", str::from_utf8(txt).unwrap());
        let mut message = [0u8; MSG_LEN];
        for (m, t) in message.iter_mut().zip(txt.iter()) {
            *m = *t
        }
        let mut pre = [0u8; MSG_LEN];
        pre.copy_from_slice(&message);

        let ad = Some("additional stuff".as_bytes());
        let mut mac = [0u8; MAC_LEN];
        let nonce = &mut 0usize.to_be_bytes();

        assert!(sender.send(Some(&mut message), ad, &mut mac, nonce).is_ok());
        let mut ciphertext = [0u8; MSG_LEN];
        ciphertext.copy_from_slice(&message);

        assert!(receiver
            .receive(Some(&mut ciphertext), ad, &mut mac, Some(nonce))
            .is_ok());
        let mut round_trip = [0u8; MSG_LEN];
        round_trip.copy_from_slice(&ciphertext);
        println!(
            "Received message: {:?}",
            str::from_utf8(&round_trip).unwrap()
        );
    }
}
