//! Python bindings for [`hypertor`].
//!
//! Exposes a `requests`/`httpx`-shaped client and a FastAPI-shaped onion service
//! framework. See the `hypertor` Python package for the user-facing API.
//!
//! This crate is not published to crates.io and has no Rust API of its own: it
//! exists only to be compiled into a Python extension module by maturin. It uses
//! `hypertor` strictly through its public API, so anything the bindings cannot
//! reach is a gap in the Rust API rather than something to work around here.

mod app;
mod client;
mod response;

use std::sync::OnceLock;

use pyo3::prelude::*;
use tokio::runtime::Runtime;

use client::{ConnectionError, HypertorError, StatusError, TimeoutError, TlsError};

/// The tokio runtime shared by every hypertor object in this interpreter.
///
/// One runtime, not one per client: each `Runtime` owns a thread pool, so
/// creating one per client (as the previous bindings did) multiplied OS threads
/// by the number of clients and prevented them from sharing anything.
pub(crate) fn runtime() -> PyResult<&'static Runtime> {
    static RUNTIME: OnceLock<std::io::Result<Runtime>> = OnceLock::new();

    match RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("hypertor")
            .build()
    }) {
        Ok(rt) => Ok(rt),
        Err(e) => Err(HypertorError::new_err(format!(
            "could not start the hypertor runtime: {e}"
        ))),
    }
}

/// Run a future to completion, releasing the GIL while it runs.
///
/// Without detaching, a Tor request — which can take tens of seconds —
/// would hold the GIL for its entire duration and freeze every other Python
/// thread in the process.
pub(crate) fn block_on<F, T>(py: Python<'_>, future: F) -> PyResult<T>
where
    F: std::future::Future<Output = PyResult<T>> + Send,
    T: Send,
{
    let rt = runtime()?;
    py.detach(|| rt.block_on(future))
}

#[pymodule]
fn _hypertor(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", hypertor::VERSION)?;

    m.add_class::<client::PyClient>()?;
    m.add_class::<client::PyAsyncClient>()?;
    m.add_class::<client::PyIsolationToken>()?;
    m.add_class::<response::PyResponse>()?;
    m.add_class::<app::PyOnionApp>()?;
    m.add_class::<app::PyRequest>()?;

    m.add("HypertorError", m.py().get_type::<HypertorError>())?;
    m.add("ConnectionError", m.py().get_type::<ConnectionError>())?;
    m.add("TimeoutError", m.py().get_type::<TimeoutError>())?;
    m.add("TlsError", m.py().get_type::<TlsError>())?;
    m.add("StatusError", m.py().get_type::<StatusError>())?;

    Ok(())
}
