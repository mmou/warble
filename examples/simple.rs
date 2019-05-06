extern crate rand;
extern crate warble;

use rand::rngs::OsRng;
use std::str;
use strobe_rs::{SecParam, Strobe};
use warble::{AeadReceiver, AeadSender, Warblee, Warbler};

fn main() {
    // create and key Strobe transcripts.
    let mut rng = OsRng::new().unwrap();
    let mut ta = Strobe::new(b"warbletest".to_vec(), SecParam::B128);
    let mut tb = Strobe::new(b"warbletest".to_vec(), SecParam::B128);
    ta.key(b"secretkey".to_vec(), None, false);
    tb.key(b"secretkey".to_vec(), None, false);

    // ta is the sender's transcript, tb is the receiver's transcript
    let (mut sender, session_id) = Warbler::new(ta, &mut rng);
    let mut receiver = Warblee::new(tb, &session_id);

    let messages: [&str; 2] = ["hello world", "second message"];
    for message in &messages {
        println!("Sending message: {:?}", message);
        let message = Some(message.as_bytes());
        let ad = Some("additional stuff".as_bytes());
        let ciphertext: Vec<u8> = sender.send(message, ad).unwrap();
        if let Ok(Some(response)) = receiver.receive(&ciphertext, ad) {
            println!("Received message: {:?}", str::from_utf8(&response).unwrap());
        } else {
            println!("Something went wrong!");
        }
    }
}
