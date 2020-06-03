use std::sync::{Arc, Mutex};

pub struct Sentinel<T> {
    state: Arc<T>,
    on_drop: Arc<Mutex<Box<dyn Fn(Arc<T>, usize) + Send + 'static>>>,
}

impl<T> Sentinel<T> {
    pub fn new<F>(state: Arc<T>, on_drop: F) -> Self
    where
        F: Fn(Arc<T>, usize) + Send + 'static,
    {
        Self {
            state,
            on_drop: Arc::new(Mutex::new(Box::new(on_drop))),
        }
    }

    pub fn ref_count(&self) -> usize {
        Arc::strong_count(&self.on_drop)
    }

    pub fn unwrap(self) -> Arc<T> {
        self.state.clone()
    }
}

impl<T> Clone for Sentinel<T> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            on_drop: self.on_drop.clone(),
        }
    }
}

impl<T> std::ops::Deref for Sentinel<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &*self.state
    }
}

impl<T> Drop for Sentinel<T> {
    fn drop(&mut self) {
        let remain = self.ref_count() - 1;
        (&self.on_drop.lock().unwrap())(self.state.clone(), remain);
    }
}
