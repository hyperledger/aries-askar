use std::sync::Arc;

pub struct Sentinel<T> {
    state: Option<Arc<T>>,
    on_drop: Arc<Box<dyn Fn(Arc<T>, usize) + Send + Sync + 'static>>,
}

impl<T> Sentinel<T> {
    pub fn new<F>(state: Arc<T>, on_drop: F) -> Self
    where
        F: Fn(Arc<T>, usize) + Send + Sync + 'static,
    {
        Self {
            state: Some(state),
            on_drop: Arc::new(Box::new(on_drop)),
        }
    }

    pub fn ref_count(&self) -> usize {
        Arc::strong_count(&self.on_drop)
    }

    pub fn cancel(mut self) -> Arc<T> {
        self.state.take().unwrap()
    }

    pub fn try_unwrap(mut self) -> Result<T, Self> {
        let state = self.state.take().unwrap();
        Arc::try_unwrap(state).map_err(|state| {
            self.state.replace(state);
            self
        })
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
        &*self.state.as_ref().unwrap()
    }
}

impl<T> Drop for Sentinel<T> {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            let remain = self.ref_count() - 1;
            (&self.on_drop)(state, remain);
        }
    }
}
