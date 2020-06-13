use std::collections::{btree_map, BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::Waker;
use std::time::Instant;

use futures_util::task::AtomicWaker;

pub struct AtomicCounter {
    count: AtomicUsize,
}

impl AtomicCounter {
    pub fn new(val: usize) -> Self {
        Self {
            count: AtomicUsize::new(val),
        }
    }

    pub fn increment(&self) -> usize {
        self.count.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn decrement(&self) -> usize {
        self.count.fetch_sub(1, Ordering::SeqCst) - 1
    }

    pub fn value(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    pub fn try_increment(&self, max: usize) -> Result<usize, usize> {
        let mut count = self.count.load(Ordering::SeqCst);
        if count < max {
            count = self.increment();
            if count > max {
                self.decrement();
                Err(count)
            } else {
                Ok(count)
            }
        } else {
            Err(count)
        }
    }
}

impl Default for AtomicCounter {
    fn default() -> Self {
        Self::new(0)
    }
}

pub struct TimedMap<R> {
    id_source: AtomicUsize,
    inner: BTreeMap<(Instant, usize), R>,
}

impl<R> Default for TimedMap<R> {
    fn default() -> Self {
        Self {
            id_source: AtomicUsize::default(),
            inner: BTreeMap::new(),
        }
    }
}

impl<R> std::ops::Deref for TimedMap<R> {
    type Target = BTreeMap<(Instant, usize), R>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<R> std::ops::DerefMut for TimedMap<R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<R> TimedMap<R> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn remove_all(&mut self) -> BTreeMap<(Instant, usize), R> {
        let mut result = BTreeMap::new();
        std::mem::swap(&mut self.inner, &mut result);
        result
    }

    pub fn remove_before(
        &mut self,
        min_time: Instant,
    ) -> (BTreeMap<(Instant, usize), R>, Option<Instant>) {
        let mut removed = self.inner.split_off(&(min_time, 0));
        std::mem::swap(&mut self.inner, &mut removed);
        let next_time = self.inner.keys().next().map(|(inst, id)| *inst);
        (removed, next_time)
    }

    pub fn push_timed(&mut self, res: R, time_start: Option<Instant>) {
        let time_start = time_start.unwrap_or_else(|| Instant::now());
        let id = self.id_source.fetch_add(1, Ordering::SeqCst);
        self.inner.insert((time_start, id), res);
    }

    pub fn drain(&mut self) -> DrainMap<'_, (Instant, usize), R> {
        DrainMap {
            inner: &mut self.inner,
        }
    }
}

impl<R> IntoIterator for TimedMap<R> {
    type Item = ((Instant, usize), R);
    type IntoIter = btree_map::IntoIter<(Instant, usize), R>;
    fn into_iter(self) -> btree_map::IntoIter<(Instant, usize), R> {
        self.inner.into_iter()
    }
}

pub struct DrainMap<'a, K, V> {
    inner: &'a mut BTreeMap<K, V>,
}

impl<'a, K: Ord + Copy, V> Iterator for DrainMap<'a, K, V> {
    type Item = (K, V);
    fn next(&mut self) -> Option<Self::Item> {
        // FIXME not very efficient, better options coming in rust nightly
        if let Some(k) = self.inner.keys().next().copied() {
            self.inner.remove(&k).map(|v| (k, v))
        } else {
            None
        }
    }
}

pub struct TimedDeque<R> {
    inner: VecDeque<(R, Instant)>,
}

impl<R> Default for TimedDeque<R> {
    fn default() -> Self {
        Self {
            inner: VecDeque::new(),
        }
    }
}

impl<R> std::ops::Deref for TimedDeque<R> {
    type Target = VecDeque<(R, Instant)>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<R> std::ops::DerefMut for TimedDeque<R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<R> IntoIterator for TimedDeque<R> {
    type Item = (R, Instant);
    type IntoIter = <VecDeque<(R, Instant)> as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<R> TimedDeque<R> {
    pub fn new() -> Self {
        Self {
            inner: VecDeque::new(),
        }
    }

    pub fn remove_all(&mut self) -> Self {
        let mut result = VecDeque::new();
        std::mem::swap(&mut self.inner, &mut result);
        Self { inner: result }
    }

    pub fn remove_before(&mut self, min_time: Instant) -> (Self, Option<Instant>) {
        for idx in (0..self.inner.len()).rev() {
            if self.inner[idx].1 < min_time {
                return (
                    TimedDeque {
                        inner: self.inner.split_off(idx + 1),
                    },
                    Some(self.inner[idx].1),
                );
            }
        }
        let mut result = Self::new();
        std::mem::swap(self, &mut result);
        (result, None)
    }

    pub fn push_timed(&mut self, res: R, time_start: Option<Instant>) {
        let time_start = time_start.unwrap_or(Instant::now());
        let mut idx = 0;
        let count = self.inner.len();
        while idx < count {
            if self.inner[idx].1 >= time_start {
                break;
            }
            idx += 1;
        }
        self.inner.insert(idx, (res, time_start));
    }
}

pub struct Timer {
    pub busy: AtomicBool,
    pub completed: AtomicBool,
    pub waker: AtomicWaker,
}

impl Timer {
    pub fn new(busy: bool) -> Self {
        Self {
            busy: AtomicBool::new(busy),
            completed: AtomicBool::new(false),
            waker: AtomicWaker::new(),
        }
    }

    pub fn update(&self, waker: Option<&Waker>) -> Option<Waker> {
        let result = self.waker.take();
        if waker.is_some() {
            self.waker.register(waker.unwrap());
        }
        result
    }
}
