use core::iter::Peekable;

// Copied from stwo/crates/prover/src/core/utils.rs

/// An iterator that takes elements from the underlying [Peekable] while the predicate is true.
/// Used to implement [PeekableExt::peek_take_while].
pub struct PeekTakeWhile<'a, I: Iterator, P: FnMut(&I::Item) -> bool> {
    iter: &'a mut Peekable<I>,
    predicate: P,
}
impl<I: Iterator, P: FnMut(&I::Item) -> bool> Iterator for PeekTakeWhile<'_, I, P> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next_if(&mut self.predicate)
    }
}

pub trait PeekableExt<'a, I: Iterator> {
    /// Returns an iterator that takes elements from the underlying [Peekable] while the predicate
    /// is true.
    /// Unlike [Iterator::take_while], this iterator does not consume the first element that does
    /// not satisfy the predicate.
    fn peek_take_while<P: FnMut(&I::Item) -> bool>(
        &'a mut self,
        predicate: P,
    ) -> PeekTakeWhile<'a, I, P>;
}

impl<'a, I: Iterator> PeekableExt<'a, I> for Peekable<I> {
    fn peek_take_while<P: FnMut(&I::Item) -> bool>(
        &'a mut self,
        predicate: P,
    ) -> PeekTakeWhile<'a, I, P> {
        PeekTakeWhile {
            iter: self,
            predicate,
        }
    }
}

/// Returns the bit reversed index of `i` which is represented by `log_size` bits.
pub const fn bit_reverse_index(i: usize, log_size: u32) -> usize {
    if log_size == 0 {
        return i;
    }
    // Use usize::BITS instead of hardcoded 64/32 for platform independence
    i.reverse_bits() >> (usize::BITS - log_size)
} 