///  Anti-replay window, as described in https://tools.ietf.org/html/rfc6479
/// TODO: use bitmap or generic-array?
const NUM_BLOCKS: u32 = 20;
const BLOCK_LEN: u32 = 5;
const BITMAP_SIZE: u32 = 1024; // 2^10, bits
const BLOCK_SIZE: u32 = 32; // 2^5, bits
const WINDOW_SIZE: u32 = BITMAP_SIZE - BLOCK_SIZE; // 2^10-2^5, bits
const MAX_COUNTER: u32 = u32::max_value() - WINDOW_SIZE as u32 - 1;

pub struct Window {
    seen: [u32; NUM_BLOCKS as usize],
    counter: u32,
}

impl Window {
    pub fn new() -> Self {
        Window {
            seen: [0u32; NUM_BLOCKS as usize],
            counter: 0u32,
        }
    }

    pub fn check_counter(&mut self, counter: u32) -> bool {
        if self.seen.len() == 0 {
            return true;
        }

        // if received counter out of allowed range, false
        if counter == 0 || counter >= MAX_COUNTER {
            return false;
        }

        // if counter is too old, false
        if counter + WINDOW_SIZE < self.counter {
            return false;
        }

        let bit_loc_mask: u32 = (1 << BLOCK_LEN as u32) - 1;
        let bitmap_mask: u32 = NUM_BLOCKS - 1;
        let block_i: u32 = counter >> BLOCK_LEN;

        // if nonce is not too old and > max seen nonce, update window, true
        if counter > self.counter {
            let current_block_i: u32 = self.counter >> BLOCK_LEN;
            let diff: u32 = u32::min(block_i - current_block_i, NUM_BLOCKS);
            for i in 1..diff {
                self.seen[((current_block_i + i) & bitmap_mask) as usize] = 0;
            }
            self.counter = counter;
        }

        let actual_block_i: u32 = block_i & bitmap_mask;
        let bit_i: u32 = counter & bit_loc_mask;
        let bit_i_mask: u32 = 1 << bit_i;
        // if counter is in window range and was seen before, false
        if self.seen[actual_block_i as usize] & bit_i_mask != 0 {
            return false;
        }

        self.seen[actual_block_i as usize] |= bit_i_mask;
        true
    }
}

#[cfg(test)]
mod tests {
    use crate::window::*;

    #[test]
    fn test_check_counter() {
        let mut w = Window::new();
        assert_eq!(false, w.check_counter(0u32), "msg 0");
        assert_eq!(true, w.check_counter(1u32), "msg 1");
        assert_eq!(false, w.check_counter(1u32), "msg 2");
        assert_eq!(true, w.check_counter(5u32), "msg 3");
        assert_eq!(true, w.check_counter(4u32), "msg 4");
        assert_eq!(true, w.check_counter(BLOCK_LEN + 1), "msg 5");
        assert_eq!(true, w.check_counter(BLOCK_LEN * 2), "msg 6");
        assert_eq!(false, w.check_counter(4u32), "msg 7");
        assert_eq!(true, w.check_counter(BLOCK_LEN * 3), "msg 8");
        assert_eq!(true, w.check_counter(BLOCK_LEN * 2 - 1), "msg 9");
        assert_eq!(true, w.check_counter(BLOCK_LEN * 2 - 2), "msg 10");
        assert_eq!(false, w.check_counter(BLOCK_LEN * 2 - 1), "msg 11");
        assert_eq!(true, w.check_counter(WINDOW_SIZE), "msg 12");
        assert_eq!(true, w.check_counter(WINDOW_SIZE - 1), "msg 13");
        assert_eq!(false, w.check_counter(WINDOW_SIZE - 1), "msg 14");
        assert_eq!(true, w.check_counter(WINDOW_SIZE - 2), "msg 15");
        assert_eq!(true, w.check_counter(2u32), "msg 16");
        assert_eq!(false, w.check_counter(2u32), "msg 17");
        assert_eq!(true, w.check_counter(WINDOW_SIZE + 16), "msg 18");
        assert_eq!(false, w.check_counter(3u32), "msg 19");
        assert_eq!(false, w.check_counter(WINDOW_SIZE + 16), "msg 20");
        assert_eq!(true, w.check_counter(WINDOW_SIZE * 4), "msg 21");
        assert_eq!(
            true,
            w.check_counter(WINDOW_SIZE * 4 - (WINDOW_SIZE - 1)),
            "msg 22"
        );
        assert_eq!(false, w.check_counter(10u32), "msg 23");
        assert_eq!(
            true,
            w.check_counter(WINDOW_SIZE * 4 - WINDOW_SIZE),
            "msg 24"
        );
        assert_eq!(
            false,
            w.check_counter(WINDOW_SIZE * 4 - (WINDOW_SIZE - 1)),
            "msg 25"
        );
        assert_eq!(
            true,
            w.check_counter(WINDOW_SIZE * 4 - (WINDOW_SIZE - 2)),
            "msg 26"
        );
        assert_eq!(
            false,
            w.check_counter(WINDOW_SIZE * 4 - (WINDOW_SIZE - 1)),
            "msg 27"
        );
        assert_eq!(false, w.check_counter(MAX_COUNTER), "msg 28");
        assert_eq!(true, w.check_counter(MAX_COUNTER - 1), "msg 29");
        assert_eq!(false, w.check_counter(MAX_COUNTER), "msg 30");
        assert_eq!(false, w.check_counter(MAX_COUNTER - 1), "msg 31");
        assert_eq!(true, w.check_counter(MAX_COUNTER - 2), "msg 32");
        assert_eq!(false, w.check_counter(MAX_COUNTER + 1), "msg 33");
        assert_eq!(false, w.check_counter(MAX_COUNTER + 2), "msg 34");
        assert_eq!(false, w.check_counter(MAX_COUNTER - 2), "msg 35");
        assert_eq!(true, w.check_counter(MAX_COUNTER - 3), "msg 36");
        assert_eq!(false, w.check_counter(12u32), "msg 37");
    }
}
