use core::{
    fmt::{self, Debug, Formatter},
    ops::{Deref, DerefMut},
    slice::Iter,
};

use super::error::Error;

// NOTE: should be possible to simplify this with GATs

#[cfg(feature = "alloc")]
pub type DefaultSeq<const S: usize> = Heap;
#[cfg(not(feature = "alloc"))]
pub type DefaultSeq<const S: usize> = Stack<S>;

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
    pub fn new() -> Self {
        Self { inner: B::new() }
    }

    #[inline]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            inner: B::with_capacity(cap),
        }
    }

    #[inline]
    pub fn push(&mut self, item: Item) -> Result<(), Error> {
        B::push(&mut self.inner, item)
    }

    #[inline]
    pub fn len(&self) -> usize {
        B::len(&self.inner)
    }

    pub fn iter(&self) -> Iter<'_, Item> {
        B::as_slice(&self.inner).into_iter()
    }

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

pub trait Seq<Item>: Debug {
    type Vec;

    fn new() -> Self::Vec;

    #[inline]
    fn with_capacity(_cap: usize) -> Self::Vec {
        Self::new()
    }

    fn push(vec: &mut Self::Vec, item: Item) -> Result<(), Error>;

    fn as_slice(vec: &Self::Vec) -> &[Item];

    fn as_slice_mut(vec: &mut Self::Vec) -> &mut [Item];

    fn len(vec: &Self::Vec) -> usize;

    fn clone(vec: &Self::Vec) -> Self::Vec
    where
        Item: Clone;
}

#[cfg(feature = "alloc")]
#[derive(Debug)]
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
