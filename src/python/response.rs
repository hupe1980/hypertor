//! Python response bindings

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::response::Response;

/// HTTP Response for Python
#[pyclass(name = "Response")]
pub struct PyResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl From<Response> for PyResponse {
    fn from(resp: Response) -> Self {
        let headers = resp
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|v| (k.as_str().to_string(), v.to_string()))
            })
            .collect();

        Self {
            status: resp.status_code(),
            headers,
            body: resp.into_bytes().to_vec(),
        }
    }
}

#[pymethods]
impl PyResponse {
    /// Get the HTTP status code
    #[getter]
    fn status_code(&self) -> u16 {
        self.status
    }

    /// Check if the response is successful (2xx)
    #[getter]
    fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Check if the response is a redirect (3xx)
    #[getter]
    fn is_redirect(&self) -> bool {
        (300..400).contains(&self.status)
    }

    /// Get the response headers as a list of tuples
    #[getter]
    fn headers(&self) -> Vec<(String, String)> {
        self.headers.clone()
    }

    /// Get a specific header value
    fn header(&self, name: &str) -> Option<String> {
        let name_lower = name.to_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == name_lower)
            .map(|(_, v)| v.clone())
    }

    /// Get the Content-Type header
    #[getter]
    fn content_type(&self) -> Option<String> {
        self.header("content-type")
    }

    /// Get the response body as text
    fn text(&self) -> PyResult<String> {
        String::from_utf8(self.body.clone())
            .map_err(|e| pyo3::exceptions::PyUnicodeDecodeError::new_err(e.to_string()))
    }

    /// Get the response body as bytes
    fn content<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.body)
    }

    /// Get the length of the response body
    fn __len__(&self) -> usize {
        self.body.len()
    }

    /// String representation
    fn __repr__(&self) -> String {
        format!("<Response [{}]>", self.status)
    }

    /// Get the response body as JSON (parsed by Python's json module)
    fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let text = self.text()?;
        let json_module = py.import("json")?;
        json_module.call_method1("loads", (text,))
    }
}
