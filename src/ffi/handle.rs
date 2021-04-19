use std::{marker::PhantomData, mem, sync::Arc};

use crate::error::Error;

#[repr(transparent)]
pub struct ArcHandle<T>(usize, PhantomData<T>);

impl<T> ArcHandle<T> {
    pub fn invalid() -> Self {
        Self(0, PhantomData)
    }

    pub fn create(value: T) -> Self {
        let results = Arc::into_raw(Arc::new(value));
        Self(results as usize, PhantomData)
    }

    pub fn load(&self) -> Result<Arc<T>, Error> {
        self.validate()?;
        let slf = unsafe { Arc::from_raw(self.0 as *const T) };
        let copy = slf.clone();
        mem::forget(slf); // Arc::increment_strong_count(..) in 1.51
        Ok(copy)
    }

    pub fn remove(&self) {
        if self.0 != 0 {
            unsafe {
                // Drop the initial reference. There could be others outstanding.
                Arc::from_raw(self.0 as *const T);
            }
        }
    }

    #[inline]
    pub fn validate(&self) -> Result<(), Error> {
        if self.0 == 0 {
            Err(err_msg!("Invalid handle"))
        } else {
            Ok(())
        }
    }
}

impl<T> std::fmt::Display for ArcHandle<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Handle({:p})", self.0 as *const T)
    }
}

/// Derive a new handle type having an atomically increasing sequence number
#[macro_export]
macro_rules! new_sequence_handle (($newtype:ident, $counter:ident) => (
    static $counter: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    #[repr(transparent)]
    pub struct $newtype(pub usize);

    impl $newtype {
        #[allow(dead_code)]
        pub fn invalid() -> $newtype {
            $newtype(0)
        }

        #[allow(dead_code)]
        pub fn next() -> $newtype {
            $newtype($counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1)
        }
    }

    impl std::fmt::Display for $newtype {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}({})", stringify!($newtype), self.0)
        }
    }

    impl std::ops::Deref for $newtype {
        type Target = usize;
        fn deref(&self) -> &usize {
            &self.0
        }
    }

    impl PartialEq<usize> for $newtype {
        fn eq(&self, other: &usize) -> bool {
            self.0 == *other
        }
    }
));

#[cfg(test)]
mod tests {
    new_sequence_handle!(TestHandle, TEST_HANDLE_CTR);

    #[test]
    fn test_handle_seq() {
        assert_eq!(TestHandle::next(), 1);
        assert_eq!(TestHandle::next(), 2);
    }
}
