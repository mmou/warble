//!  Anti-replay window, as described in https://tools.ietf.org/html/rfc6479

const NUM_BLOCKS: usize = 20;
const BLOCK_LEN: usize = 5;
const BITMAP_SIZE: usize = 1024; // 2^10, bits
const WINDOW_SIZE: usize = BITMAP_SIZE - 32; // 2^10-2^5, bits
const MAX_COUNTER: usize = usize::max_value() - WINDOW_SIZE - 1;

pub struct Window {
    seen: [usize; NUM_BLOCKS],
    counter: usize,
}

impl Window {
    pub fn new() -> Self {
        Window {
            seen: [0usize; NUM_BLOCKS],
            counter: 0usize,
        }
    }

    pub fn check_counter(&mut self, counter: usize) -> bool {
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

        let bit_loc_mask: usize = (1 << BLOCK_LEN as usize) - 1;
        let bitmap_mask: usize = NUM_BLOCKS - 1;

        let bit_i: usize = counter & bit_loc_mask;
        let block_i: usize = counter >> BLOCK_LEN;
        let actual_block_i: usize = block_i & bitmap_mask;

        // if nonce is not too old and > max seen nonce, update window, true
        if counter > self.counter {
            let current_block_i: usize = self.counter >> BLOCK_LEN;
            let diff: usize = usize::min(block_i - current_block_i, NUM_BLOCKS);
            for i in 1..diff {
                self.seen[(current_block_i + i) & bitmap_mask] = 0;
            }
            self.counter = counter;
        }

        // if counter is in window range and was seen before, false
        if self.seen[actual_block_i] & (1 << bit_i as usize) != 0 {
            return false;
        }

        self.seen[actual_block_i] |= 1 << bit_i as usize;
        true
    }
}

#[cfg(test)]
mod tests {
    use crate::window::*;

    #[test]
    fn test_check_counter() {
        let mut w = Window::new();
        assert_eq!(false, w.check_counter(0usize), "msg 0");
        assert_eq!(true, w.check_counter(1usize), "msg 1");
        assert_eq!(false, w.check_counter(1usize), "msg 2");
        assert_eq!(true, w.check_counter(5usize), "msg 3");
        assert_eq!(true, w.check_counter(4usize), "msg 4");
        assert_eq!(true, w.check_counter(BLOCK_LEN + 1), "msg 5");
        assert_eq!(true, w.check_counter(BLOCK_LEN * 2), "msg 6");
        assert_eq!(false, w.check_counter(4usize), "msg 7");
        assert_eq!(true, w.check_counter(BLOCK_LEN * 3), "msg 8");
        assert_eq!(true, w.check_counter(BLOCK_LEN * 2 - 1), "msg 9");
        assert_eq!(true, w.check_counter(BLOCK_LEN * 2 - 2), "msg 10");
        assert_eq!(false, w.check_counter(BLOCK_LEN * 2 - 1), "msg 11");
        assert_eq!(true, w.check_counter(WINDOW_SIZE), "msg 12");
        assert_eq!(true, w.check_counter(WINDOW_SIZE - 1), "msg 13");
        assert_eq!(false, w.check_counter(WINDOW_SIZE - 1), "msg 14");
        assert_eq!(true, w.check_counter(WINDOW_SIZE - 2), "msg 15");
        assert_eq!(true, w.check_counter(2usize), "msg 16");
        assert_eq!(false, w.check_counter(2usize), "msg 17");
        assert_eq!(true, w.check_counter(WINDOW_SIZE + 16), "msg 18");
        assert_eq!(false, w.check_counter(3usize), "msg 19");
        assert_eq!(false, w.check_counter(WINDOW_SIZE + 16), "msg 20");
        assert_eq!(true, w.check_counter(WINDOW_SIZE * 4), "msg 21");
        assert_eq!(
            true,
            w.check_counter(WINDOW_SIZE * 4 - (WINDOW_SIZE - 1)),
            "msg 22"
        );
        assert_eq!(false, w.check_counter(10usize), "msg 23");
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
        assert_eq!(false, w.check_counter(12usize), "msg 37");
    }

}
