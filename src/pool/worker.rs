use super::manager::ResourceManager;
use super::ResourceInfo;

pub trait PoolWorker<M: ResourceManager> {
    fn create(&mut self, f: Box<dyn FnOnce(Result<M::Resource, M::Error>)>);

    fn verify(
        &mut self,
        res: M::Resource,
        info: ResourceInfo,
        f: Box<dyn FnOnce(Option<M::Resource>) + Send>,
    );

    fn dispose(&mut self, res: M::Resource, info: ResourceInfo);
}

pub struct BlockingWorker<M: ResourceManager> {
    manager: M,
}

impl<M: ResourceManager> BlockingWorker<M> {
    pub fn new(manager: M) -> Self {
        Self { manager }
    }
}

impl<M: ResourceManager> PoolWorker<M> for BlockingWorker<M> {
    fn create(&mut self, f: Box<dyn FnOnce(Result<M::Resource, M::Error>)>) {
        let result = self.manager.create();
        f(result)
    }

    fn verify(
        &mut self,
        res: M::Resource,
        info: ResourceInfo,
        f: Box<dyn FnOnce(Option<M::Resource>) + Send>,
    ) {
        let result = self.manager.verify(res, info);
        f(result)
    }

    fn dispose(&mut self, res: M::Resource, info: ResourceInfo) {
        self.manager.dispose(res, info)
    }
}

// TODO
// add worker with a set number of threads for performing operations
