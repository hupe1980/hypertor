//! Python bindings for hypertor
//!
//! Provides both synchronous and asynchronous Python APIs via PyO3.
//!
//! # Client Example
//!
//! ```python
//! from hypertor import Client
//!
//! client = Client()
//! response = client.get("http://example.onion")
//! print(response.text())
//! ```
//!
//! # Server Example (FastAPI-like)
//!
//! ```python
//! from hypertor import OnionApp
//!
//! app = OnionApp()
//!
//! @app.get("/")
//! def home():
//!     return "Welcome to my onion service!"
//!
//! @app.post("/api/echo")
//! def echo(request):
//!     return {"received": request.json()}
//!
//! app.run()  # 🧅 Service live at: xyz...xyz.onion
//! ```

#[cfg(feature = "python")]
mod app;
#[cfg(feature = "python")]
mod client;
#[cfg(feature = "python")]
mod response;

#[cfg(feature = "python")]
pub use client::{
    HypertorError, TorBootstrapError, TorConnectionError, TorTimeoutError, to_py_err,
};

#[cfg(feature = "python")]
use pyo3::prelude::*;

/// Python module for hypertor
#[cfg(feature = "python")]
#[pymodule]
fn _hypertor(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Add version
    m.add("__version__", crate::VERSION)?;

    // Client classes
    m.add_class::<client::PyClient>()?;
    m.add_class::<client::PyAsyncClient>()?;
    m.add_class::<response::PyResponse>()?;

    // Server classes (FastAPI-like)
    m.add_class::<app::PyOnionApp>()?;
    m.add_class::<app::PyAppConfig>()?;
    m.add_class::<app::PyRequest>()?;
    m.add_class::<app::PyAppResponse>()?;

    // Exceptions
    m.add("HypertorError", m.py().get_type::<client::HypertorError>())?;
    m.add(
        "TorBootstrapError",
        m.py().get_type::<client::TorBootstrapError>(),
    )?;
    m.add(
        "ConnectionError",
        m.py().get_type::<client::TorConnectionError>(),
    )?;
    m.add("TimeoutError", m.py().get_type::<client::TorTimeoutError>())?;

    Ok(())
}
