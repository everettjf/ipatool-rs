//! Scoped progress and cooperative cancellation for synchronous native workflows.

use std::{
    cell::RefCell,
    error::Error,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Stage {
    Preparing,
    Authenticating,
    Metadata,
    Licensing,
    Downloading,
    Processing,
    Verifying,
    Publishing,
    Inspecting,
    Collecting,
    Recovering,
    RecoveringOracle,
    ValidatingModel,
    BuildingModel,
    Decrypting,
}

impl Stage {
    pub fn label(self) -> &'static str {
        match self {
            Self::Preparing => "Preparing resources",
            Self::Authenticating => "Authenticating account",
            Self::Metadata => "Resolving application metadata",
            Self::Licensing => "Acquiring free application license",
            Self::Downloading => "Downloading package",
            Self::Processing => "Processing package",
            Self::Verifying => "Verifying output",
            Self::Publishing => "Publishing output",
            Self::Inspecting => "Checking FairPlay materials",
            Self::Collecting => "Collecting enrollment materials",
            Self::Recovering => "Recovering enrollment model",
            Self::RecoveringOracle => "Deriving recovery data",
            Self::ValidatingModel => "Checking recovery model",
            Self::BuildingModel => "Building enrollment model",
            Self::Decrypting => "Decrypting IPA",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    pub stage: Stage,
    pub completed: u64,
    pub total: Option<u64>,
}

#[derive(Debug)]
pub struct Cancelled;

impl fmt::Display for Cancelled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("operation cancelled")
    }
}

impl Error for Cancelled {}

type Observer = dyn Fn(Progress) + Send + Sync;

#[derive(Clone)]
pub struct Operation {
    cancelled: Arc<AtomicBool>,
    observer: Arc<Observer>,
    transfer_identity: Option<String>,
}

impl Default for Operation {
    fn default() -> Self {
        Self::new(|_| {})
    }
}

impl Operation {
    pub fn new(observer: impl Fn(Progress) + Send + Sync + 'static) -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            observer: Arc::new(observer),
            transfer_identity: None,
        }
    }

    /// Bind retained package bytes to a front end's account and request snapshot.
    pub fn with_transfer_identity(&self, identity: String) -> Self {
        Self {
            transfer_identity: Some(identity),
            ..self.clone()
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub fn check(&self) -> Result<()> {
        if self.is_cancelled() {
            return Err(Cancelled.into());
        }
        Ok(())
    }

    pub fn report(&self, progress: Progress) {
        (self.observer)(progress);
    }

    /// Native helpers inherit this context only on the executing worker thread.
    /// Nested operations restore their caller even during unwinding.
    pub fn run<T>(&self, work: impl FnOnce() -> Result<T>) -> Result<T> {
        self.check()?;
        let _scope = Scope(CURRENT.with(|slot| slot.replace(Some(self.clone()))));
        work()
    }
}

thread_local! {
    static CURRENT: RefCell<Option<Operation>> = const { RefCell::new(None) };
}

struct Scope(Option<Operation>);

impl Drop for Scope {
    fn drop(&mut self) {
        CURRENT.with(|slot| {
            slot.replace(self.0.take());
        });
    }
}

pub fn check() -> Result<()> {
    CURRENT.with(|slot| slot.borrow().as_ref().map_or(Ok(()), Operation::check))
}

pub fn is_active() -> bool {
    CURRENT.with(|slot| slot.borrow().is_some())
}

pub fn current() -> Option<Operation> {
    CURRENT.with(|slot| slot.borrow().clone())
}

/// Copy local material with cancellation boundaries between bounded buffers.
pub(crate) fn copy(
    reader: &mut impl std::io::Read,
    writer: &mut impl std::io::Write,
) -> Result<u64> {
    let mut bytes = 0;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        check()?;
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(bytes);
        }
        check()?;
        writer.write_all(&buffer[..count])?;
        bytes += count as u64;
    }
}

/// Let third-party ZIP copy loops observe the same cancellation boundary.
pub(crate) struct CancellableWriter<W>(pub W);

/// Checkpoint decoders and parsers may perform their own internal read loops.
pub(crate) struct CancellableReader<R>(pub R);

impl<R: std::io::Read> std::io::Read for CancellableReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        check().map_err(into_io_error)?;
        self.0.read(bytes)
    }
}

impl<R: std::io::Seek> std::io::Seek for CancellableReader<R> {
    fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
        self.0.seek(position)
    }
}

impl<W: std::io::Write> std::io::Write for CancellableWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if current().is_some_and(|operation| operation.is_cancelled()) {
            return Err(std::io::Error::other(Cancelled));
        }
        self.0.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl<W: std::io::Seek> std::io::Seek for CancellableWriter<W> {
    fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
        self.0.seek(position)
    }
}

pub(crate) fn is_cancellation(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.is::<Cancelled>()
            || cause
                .downcast_ref::<std::io::Error>()
                .and_then(std::io::Error::get_ref)
                .is_some_and(|inner| inner.is::<Cancelled>())
    })
}

/// Keep cancellation downcastable when crossing Read/Seek interfaces. Boxing
/// an anyhow error directly erases its root error's downcast identity.
pub(crate) fn into_io_error(error: anyhow::Error) -> std::io::Error {
    if is_cancellation(&error) {
        std::io::Error::other(Cancelled)
    } else {
        std::io::Error::other(error)
    }
}

pub(crate) fn transfer_identity() -> Option<String> {
    current().and_then(|operation| operation.transfer_identity)
}

/// Preserve retry policy while allowing an application-scoped wait to end early.
pub fn sleep(duration: std::time::Duration) {
    let Some(operation) = current() else {
        std::thread::sleep(duration);
        return;
    };
    let started = std::time::Instant::now();
    while started.elapsed() < duration && !operation.is_cancelled() {
        std::thread::sleep(
            duration
                .saturating_sub(started.elapsed())
                .min(std::time::Duration::from_millis(100)),
        );
    }
}

/// Drop in-flight network futures promptly when cancellation is requested.
/// The enclosing synchronous operation runs this on its worker-local runtime.
pub async fn wait<T, E>(
    future: impl std::future::Future<Output = std::result::Result<T, E>>,
) -> Result<T>
where
    E: Into<anyhow::Error>,
{
    let current = CURRENT.with(|slot| slot.borrow().clone());
    let Some(operation) = current else {
        return future.await.map_err(Into::into);
    };
    tokio::pin!(future);
    loop {
        operation.check()?;
        tokio::select! {
            result = &mut future => return result.map_err(Into::into),
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {},
        }
    }
}

pub fn progress(stage: Stage, completed: u64, total: Option<u64>) {
    let current = CURRENT.with(|slot| slot.borrow().clone());
    if let Some(operation) = current {
        operation.report(Progress {
            stage,
            completed,
            total,
        });
    }
}

pub fn stage(stage: Stage) -> Result<()> {
    check()?;
    progress(stage, 0, None);
    Ok(())
}

/// Complete a short output-publication transaction without interruption.
/// Cancellation remains observable after leaving this transaction.
pub fn publish<T>(work: impl FnOnce() -> Result<T>) -> Result<T> {
    check()?;
    progress(Stage::Publishing, 0, None);
    let _scope = Scope(CURRENT.with(|slot| slot.replace(None)));
    work()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn third_party_zip_copy_cancellation_remains_cancelled_and_preserves_output() {
        use std::io::Write;
        let operation = Operation::default();
        let mut output = CancellableWriter(std::io::Cursor::new(Vec::<u8>::new()));
        operation
            .run(|| {
                output.write_all(b"retained prefix")?;
                operation.cancel();
                let error = output.write_all(b"must not be written").unwrap_err();
                let wrapped = anyhow::Error::new(zip::result::ZipError::Io(error));
                assert!(is_cancellation(&wrapped));
                assert_eq!(
                    super::super::failure::Failure::from_error(&wrapped).kind,
                    super::super::failure::FailureKind::Cancelled
                );
                Ok(())
            })
            .unwrap();
        assert_eq!(output.0.into_inner(), b"retained prefix");
    }

    #[test]
    fn cancelled_operations_never_start_and_preserve_typed_error() {
        let operation = Operation::default();
        operation.cancel();
        let error = operation
            .run(|| -> Result<()> { panic!("cancelled work started") })
            .unwrap_err();
        assert!(error.downcast_ref::<Cancelled>().is_some());
    }

    #[test]
    fn nested_context_restores_cancellation_and_progress_routes() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&events);
        let outer = Operation::new(move |event| sink.lock().unwrap().push(event));
        let inner = Operation::default();
        outer
            .run(|| {
                stage(Stage::Preparing)?;
                inner.run(|| stage(Stage::Downloading))?;
                outer.cancel();
                assert!(check().unwrap_err().is::<Cancelled>());
                Ok(())
            })
            .unwrap();
        assert!(check().is_ok());
        assert_eq!(events.lock().unwrap().len(), 1);
    }

    #[test]
    fn cancellation_during_publication_does_not_split_the_transaction() {
        let operation = Operation::default();
        operation
            .run(|| {
                publish(|| {
                    operation.cancel();
                    check()?;
                    Ok(())
                })?;
                assert!(check().unwrap_err().is::<Cancelled>());
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn context_is_restored_on_unwind_and_is_not_inherited_by_other_threads() {
        let operation = Operation::default();
        operation
            .run(|| {
                operation.cancel();
                assert!(std::thread::spawn(check).join().unwrap().is_ok());
                Ok(())
            })
            .unwrap();
        let fresh = Operation::default();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fresh.run(|| -> Result<()> { panic!("fixture unwind") })
        }));
        assert!(check().is_ok());
    }
}
