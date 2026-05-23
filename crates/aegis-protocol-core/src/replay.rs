//! Small replay-protection window for monotonic sequence numbers.

use crate::{Error, Result};

/// Sliding replay window backed by a fixed-size bitset.
///
/// Bit `0` represents the highest accepted sequence. Older accepted sequences
/// occupy increasing bit positions. The generic parameter controls the window
/// size in 64-bit words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayWindow<const WORDS: usize> {
    highest: u64,
    seen: [u64; WORDS],
    initialized: bool,
}

impl<const WORDS: usize> ReplayWindow<WORDS> {
    /// Creates an empty replay window.
    pub const fn new() -> Self {
        Self {
            highest: 0,
            seen: [0; WORDS],
            initialized: false,
        }
    }

    /// Returns the number of sequence values tracked by this window.
    pub const fn window_bits(&self) -> usize {
        WORDS * 64
    }

    /// Returns the highest accepted sequence if the window is initialized.
    pub const fn highest(&self) -> Option<u64> {
        if self.initialized {
            Some(self.highest)
        } else {
            None
        }
    }

    /// Accepts a sequence number or rejects it as replayed/stale.
    pub fn accept(&mut self, sequence: u64) -> Result<()> {
        let bits = self.window_bits();
        if bits == 0 {
            return Err(Error::ResourceExceeded);
        }

        if !self.initialized {
            self.highest = sequence;
            self.clear();
            self.set_bit(0);
            self.initialized = true;
            return Ok(());
        }

        if sequence > self.highest {
            let shift = sequence - self.highest;
            if shift >= bits as u64 {
                self.clear();
            } else {
                self.shift_left(shift as usize);
            }
            self.highest = sequence;
            self.set_bit(0);
            return Ok(());
        }

        let age = self.highest - sequence;
        if age as usize >= bits {
            return Err(Error::ReplayDetected);
        }
        if self.bit_is_set(age as usize) {
            return Err(Error::ReplayDetected);
        }
        self.set_bit(age as usize);
        Ok(())
    }

    fn clear(&mut self) {
        for word in &mut self.seen {
            *word = 0;
        }
    }

    fn set_bit(&mut self, bit: usize) {
        let word = bit / 64;
        let offset = bit % 64;
        self.seen[word] |= 1u64 << offset;
    }

    fn bit_is_set(&self, bit: usize) -> bool {
        let word = bit / 64;
        let offset = bit % 64;
        (self.seen[word] & (1u64 << offset)) != 0
    }

    fn shift_left(&mut self, bits: usize) {
        if bits == 0 {
            return;
        }

        let word_shift = bits / 64;
        let bit_shift = bits % 64;

        for i in (0..WORDS).rev() {
            let mut value = 0u64;
            if i >= word_shift {
                value = self.seen[i - word_shift] << bit_shift;
                if bit_shift != 0 && i > word_shift {
                    value |= self.seen[i - word_shift - 1] >> (64 - bit_shift);
                }
            }
            self.seen[i] = value;
        }
    }
}

impl<const WORDS: usize> Default for ReplayWindow<WORDS> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicate_sequences() {
        let mut window = ReplayWindow::<2>::new();
        assert!(window.accept(10).is_ok());
        assert_eq!(window.accept(10), Err(Error::ReplayDetected));
        assert!(window.accept(11).is_ok());
        assert!(window.accept(9).is_ok());
        assert_eq!(window.accept(9), Err(Error::ReplayDetected));
    }

    #[test]
    fn rejects_stale_sequences() {
        let mut window = ReplayWindow::<1>::new();
        assert!(window.accept(100).is_ok());
        assert!(window.accept(200).is_ok());
        assert_eq!(window.accept(100), Err(Error::ReplayDetected));
    }
}
