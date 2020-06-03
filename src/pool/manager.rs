use std::time::Duration;

use super::ResourceInfo;

pub trait ResourceManager: Send + 'static {
    type Resource: Send;
    type Error: std::fmt::Debug + Send;

    fn init(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    // fn init_timeout(&self) -> Option<Duration> {
    //     None
    // }

    fn create(&self) -> Result<Self::Resource, Self::Error>;

    // fn create_timeout(&self) -> Option<Duration> {
    //     None
    // }

    // after idle timeout:
    // connections under min_count are re-verified
    // connections beyond min_count are dropped
    fn idle_timeout(&self) -> Option<Duration> {
        None
    }

    // should perform keepalive if needed
    fn verify(&self, res: Self::Resource, _info: ResourceInfo) -> Option<Self::Resource> {
        Some(res)
    }

    fn dispose(&self, _res: Self::Resource, _info: ResourceInfo) {}

    fn max_count(&self) -> Option<usize> {
        None
    }

    fn min_count(&self) -> usize {
        0
    }

    fn max_waiters(&self) -> Option<usize> {
        None
    }
}
