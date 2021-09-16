//! Support for heapless and heap-allocated sequences

use core::{
    fmt::{self, Debug, Formatter},
    ops::{Deref, DerefMut},
    slice::Iter,
};

use crate::Error;

// NOTE: in future, it should be possible to simplify this with GATs

#[cfg(feature = "alloc")]
/// The default generic sequence type
pub type DefaultSeq<const S: usize> = Heap;
#[cfg(not(feature = "alloc"))]
/// The default generic sequence type
pub type DefaultSeq<const S: usize> = Stack<S>;

/// A wrapper type for a generic backing sequence
pub struct Vec<Item, B>
where
    B: Seq<Item>,
{
    inner: B::Vec,
}

impl<Item, B> Vec<Item, B>
where
    B: Seq<Item>,
{
    #[inline]
    /// Create a new, empty sequence
    pub fn new() -> Self {
        Self { inner: B::new() }
    }

    #[inline]
    /// Create a new sequence with a minimum capacity
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            inner: B::with_capacity(cap),
        }
    }

    #[inline]
    /// Push a new value at the end of the sequence, failing if the
    /// maximum length has been exceeded
    pub fn push(&mut self, item: Item) -> Result<(), Error> {
        B::push(&mut self.inner, item)
    }

    #[inline]
    /// Get the current length of the sequence
    pub fn len(&self) -> usize {
        B::len(&self.inner)
    }

    /// Get an iterator over the sequence values
    pub fn iter(&self) -> Iter<'_, Item> {
        B::as_slice(&self.inner).into_iter()
    }

    /// Create a new sequence from an iterator of values
    pub fn from_iter(iter: impl IntoIterator<Item = Item>) -> Result<Self, Error> {
        let iter = iter.into_iter();
        let mut slf = Self::with_capacity(iter.size_hint().0);
        for item in iter {
            slf.push(item)?;
        }
        Ok(slf)
    }
}

impl<Item, B> Clone for Vec<Item, B>
where
    B: Seq<Item>,
    Item: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: B::clone(&self.inner),
        }
    }
}

impl<Item, B> Debug for Vec<Item, B>
where
    B: Seq<Item>,
    Item: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(B::as_slice(&self.inner)).finish()
    }
}

impl<Item, B> Deref for Vec<Item, B>
where
    B: Seq<Item>,
{
    type Target = [Item];

    fn deref(&self) -> &Self::Target {
        B::as_slice(&self.inner)
    }
}

impl<Item, B> DerefMut for Vec<Item, B>
where
    B: Seq<Item>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        B::as_slice_mut(&mut self.inner)
    }
}

impl<Item, B> PartialEq for Vec<Item, B>
where
    B: Seq<Item>,
    Item: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        &*self == &*other
    }
}

impl<Item, B> Eq for Vec<Item, B>
where
    B: Seq<Item>,
    Item: Eq,
{
}

/// A generic trait for a backing sequence type
pub trait Seq<Item>: Debug {
    /// The backing type
    type Vec;

    /// Create a new instance of the backing type
    fn new() -> Self::Vec;

    #[inline]
    /// Create a new instance of the backing type with a minimum capacity
    fn with_capacity(_cap: usize) -> Self::Vec {
        Self::new()
    }

    /// Push a new value onto the sequence
    fn push(vec: &mut Self::Vec, item: Item) -> Result<(), Error>;

    /// Access the contained values as a slice
    fn as_slice(vec: &Self::Vec) -> &[Item];

    /// Access the contained values as a mutable slice
    fn as_slice_mut(vec: &mut Self::Vec) -> &mut [Item];

    /// Get the current length of the sequence
    fn len(vec: &Self::Vec) -> usize;

    /// Clone the backing type
    fn clone(vec: &Self::Vec) -> Self::Vec
    where
        Item: Clone;
}

#[cfg(feature = "alloc")]
#[derive(Debug)]
/// A heap-based (std::vec::Vec) sequence type
pub struct Heap;

#[cfg(feature = "alloc")]
impl<Item> Seq<Item> for Heap {
    type Vec = alloc::vec::Vec<Item>;

    #[inline]
    fn new() -> Self::Vec {
        alloc::vec::Vec::new()
    }

    #[inline]
    fn with_capacity(cap: usize) -> Self::Vec {
        alloc::vec::Vec::with_capacity(cap)
    }

    #[inline]
    fn push(vec: &mut Self::Vec, item: Item) -> Result<(), Error> {
        vec.push(item);
        Ok(())
    }

    #[inline]
    fn as_slice(vec: &Self::Vec) -> &[Item] {
        vec.as_ref()
    }

    #[inline]
    fn as_slice_mut(vec: &mut Self::Vec) -> &mut [Item] {
        &mut vec[..]
    }

    #[inline]
    fn len(vec: &Self::Vec) -> usize {
        vec.len()
    }

    #[inline]
    fn clone(vec: &Self::Vec) -> Self::Vec
    where
        Item: Clone,
    {
        vec.clone()
    }
}

#[derive(Debug)]
/// A stack-based (heapless) sequence type
pub struct Stack<const L: usize>;

impl<Item, const L: usize> Seq<Item> for Stack<L> {
    type Vec = heapless::Vec<Item, L>;

    #[inline]
    fn new() -> Self::Vec {
        heapless::Vec::new()
    }

    fn push(vec: &mut Self::Vec, item: Item) -> Result<(), Error> {
        vec.push(item)
            .map_err(|_| err_msg!(Usage, "Exceeded storage capacity"))
    }

    #[inline]
    fn as_slice(vec: &Self::Vec) -> &[Item] {
        vec.as_ref()
    }

    #[inline]
    fn as_slice_mut(vec: &mut Self::Vec) -> &mut [Item] {
        &mut vec[..]
    }

    #[inline]
    fn len(vec: &Self::Vec) -> usize {
        vec.len()
    }

    #[inline]
    fn clone(vec: &Self::Vec) -> Self::Vec
    where
        Item: Clone,
    {
        vec.clone()
    }
}
