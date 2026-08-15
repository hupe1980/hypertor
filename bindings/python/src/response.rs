//! Python response bindings.

use std::collections::HashMap;

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use hypertor::Response;

use crate::client::{StatusError, to_py_err};

/// An HTTP response.
#[pyclass(name = "Response")]
pub struct PyResponse {
    inner: Response,
}

impl From<Response> for PyResponse {
    fn from(inner: Response) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl PyResponse {
    /// The HTTP status code.
    #[getter]
    fn status_code(&self) -> u16 {
        self.inner.status().as_u16()
    }

    /// Whether the status is 2xx.
    #[getter]
    fn ok(&self) -> bool {
        self.inner.is_success()
    }

    /// The status code's canonical reason phrase.
    #[getter]
    fn reason(&self) -> &str {
        self.inner.status().canonical_reason().unwrap_or("")
    }

    /// The HTTP version the response arrived over.
    #[getter]
    fn http_version(&self) -> String {
        format!("{:?}", self.inner.version())
    }

    /// The response headers, lowercased.
    #[getter]
    fn headers(&self) -> HashMap<String, String> {
        self.inner
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.as_str().to_lowercase(), v.to_string()))
            })
            .collect()
    }

    /// The raw response body.
    #[getter]
    fn content<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.bytes())
    }

    /// The body decoded as UTF-8 text.
    #[getter]
    fn text(&self) -> PyResult<String> {
        self.inner.text().map_err(to_py_err)
    }

    /// The body parsed as JSON.
    ///
    /// Parsed by Python's own `json` module so the result contains ordinary
    /// dicts and lists rather than a foreign object graph.
    fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let text = self.inner.text().map_err(to_py_err)?;
        py.import("json")?.call_method1("loads", (text,))
    }

    /// Raise if the status is not 2xx.
    fn raise_for_status(slf: PyRef<'_, Self>) -> PyResult<PyRef<'_, Self>> {
        if slf.inner.is_success() {
            Ok(slf)
        } else {
            Err(StatusError::new_err(format!(
                "server returned {} {}",
                slf.inner.status().as_u16(),
                slf.inner.status().canonical_reason().unwrap_or("")
            )))
        }
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    /// `bool(response)` is the status, not the body length.
    ///
    /// Without this, `if response:` would be false for any successful response
    /// with an empty body — a `204`, or a `HEAD` — which is the opposite of
    /// what the reader means.
    fn __bool__(&self) -> bool {
        self.inner.is_success()
    }

    fn __repr__(&self) -> String {
        format!(
            "<hypertor.Response [{}] {} bytes>",
            self.inner.status().as_u16(),
            self.inner.len()
        )
    }
}
