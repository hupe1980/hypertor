//! Python client bindings.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::client::TorClient;
use crate::error::Error;
use crate::isolation::{IsolationLevel, IsolationToken};

use super::response::PyResponse;
use super::{block_on, runtime};

#[allow(missing_docs)]
mod exceptions {
    use super::*;
    create_exception!(hypertor, HypertorError, PyException);
    create_exception!(hypertor, ConnectionError, HypertorError);
    create_exception!(hypertor, TimeoutError, HypertorError);
    create_exception!(hypertor, TlsError, HypertorError);
}
pub use exceptions::*;

/// Map a hypertor error onto the matching Python exception.
pub fn to_py_err(err: Error) -> PyErr {
    match &err {
        Error::Bootstrap { .. } | Error::Connect { .. } => {
            ConnectionError::new_err(err.to_string())
        }
        Error::Timeout { .. } => TimeoutError::new_err(err.to_string()),
        Error::TlsHandshake { .. } | Error::Tls { .. } => TlsError::new_err(err.to_string()),
        _ => HypertorError::new_err(err.to_string()),
    }
}

/// Shared request-shaping used by both the sync and async clients.
struct RequestSpec {
    method: http::Method,
    url: String,
    headers: Option<HashMap<String, String>>,
    body: Option<Vec<u8>>,
    json: Option<String>,
    data: Option<HashMap<String, String>>,
    params: Option<HashMap<String, String>>,
    timeout: Option<f64>,
    isolation: Option<IsolationToken>,
}

impl RequestSpec {
    async fn send(self, client: Arc<TorClient>) -> PyResult<PyResponse> {
        let mut builder = client.request(self.method, &self.url).map_err(to_py_err)?;

        if let Some(params) = self.params {
            builder = builder.query(params);
        }

        if let Some(headers) = self.headers {
            for (name, value) in headers {
                builder = builder.header(name, value);
            }
        }

        if let Some(json) = self.json {
            // Pre-serialised by the Python layer, so send it verbatim rather
            // than re-encoding it as a JSON string.
            builder = builder
                .header("content-type", "application/json")
                .body(json.into_bytes());
        } else if let Some(data) = self.data {
            builder = builder.form(data);
        } else if let Some(body) = self.body {
            builder = builder.body(body);
        }

        if let Some(seconds) = self.timeout {
            builder = builder.timeout(Duration::from_secs_f64(seconds));
        }

        if let Some(token) = self.isolation {
            builder = builder.isolation(token);
        }

        let response = builder.send().await.map_err(to_py_err)?;
        Ok(PyResponse::from(response))
    }
}

fn build_client(
    timeout: f64,
    max_idle_per_host: usize,
    isolation: &str,
    user_agent: Option<String>,
    verify: bool,
) -> PyResult<TorClient> {
    let level = match isolation {
        "none" => IsolationLevel::None,
        "per_host" => IsolationLevel::PerHost,
        "per_request" => IsolationLevel::PerRequest,
        other => {
            return Err(HypertorError::new_err(format!(
                "unknown isolation {other:?}; expected 'none', 'per_host' or 'per_request'"
            )));
        }
    };

    let mut builder = TorClient::builder()
        .timeout(Duration::from_secs_f64(timeout))
        .pool_max_idle_per_host(max_idle_per_host)
        .isolation(level)
        .danger_accept_invalid_certs(!verify);

    if let Some(ua) = user_agent {
        builder = builder.user_agent(ua);
    }

    let rt = runtime()?;
    rt.block_on(builder.build()).map_err(to_py_err)
}

/// A synchronous Tor HTTP client.
#[pyclass(name = "Client")]
pub struct PyClient {
    client: Arc<TorClient>,
}

#[pymethods]
impl PyClient {
    #[new]
    #[pyo3(signature = (
        timeout = 30.0,
        max_idle_per_host = 4,
        isolation = "per_host",
        user_agent = None,
        verify = true,
    ))]
    fn new(
        py: Python<'_>,
        timeout: f64,
        max_idle_per_host: usize,
        isolation: &str,
        user_agent: Option<String>,
        verify: bool,
    ) -> PyResult<Self> {
        // Bootstrapping takes tens of seconds on a cold cache; holding the GIL
        // for that would freeze the whole interpreter.
        let client = py.allow_threads(|| {
            build_client(timeout, max_idle_per_host, isolation, user_agent, verify)
        })?;

        Ok(Self {
            client: Arc::new(client),
        })
    }

    #[pyo3(signature = (url, *, params = None, headers = None, timeout = None))]
    fn get(
        &self,
        py: Python<'_>,
        url: &str,
        params: Option<HashMap<String, String>>,
        headers: Option<HashMap<String, String>>,
        timeout: Option<f64>,
    ) -> PyResult<PyResponse> {
        self.send(
            py,
            http::Method::GET,
            url,
            None,
            None,
            None,
            params,
            headers,
            timeout,
        )
    }

    #[pyo3(signature = (url, *, body = None, json = None, data = None, headers = None, timeout = None))]
    fn post(
        &self,
        py: Python<'_>,
        url: &str,
        body: Option<Vec<u8>>,
        json: Option<&Bound<'_, PyAny>>,
        data: Option<HashMap<String, String>>,
        headers: Option<HashMap<String, String>>,
        timeout: Option<f64>,
    ) -> PyResult<PyResponse> {
        let json = serialise_json(json)?;
        self.send(
            py,
            http::Method::POST,
            url,
            body,
            json,
            data,
            None,
            headers,
            timeout,
        )
    }

    #[pyo3(signature = (url, *, body = None, json = None, data = None, headers = None, timeout = None))]
    fn put(
        &self,
        py: Python<'_>,
        url: &str,
        body: Option<Vec<u8>>,
        json: Option<&Bound<'_, PyAny>>,
        data: Option<HashMap<String, String>>,
        headers: Option<HashMap<String, String>>,
        timeout: Option<f64>,
    ) -> PyResult<PyResponse> {
        let json = serialise_json(json)?;
        self.send(
            py,
            http::Method::PUT,
            url,
            body,
            json,
            data,
            None,
            headers,
            timeout,
        )
    }

    #[pyo3(signature = (url, *, headers = None, timeout = None))]
    fn delete(
        &self,
        py: Python<'_>,
        url: &str,
        headers: Option<HashMap<String, String>>,
        timeout: Option<f64>,
    ) -> PyResult<PyResponse> {
        self.send(
            py,
            http::Method::DELETE,
            url,
            None,
            None,
            None,
            None,
            headers,
            timeout,
        )
    }

    /// Resolve a hostname through Tor.
    fn resolve(&self, py: Python<'_>, hostname: &str) -> PyResult<Vec<String>> {
        let client = Arc::clone(&self.client);
        let hostname = hostname.to_string();

        block_on(py, async move {
            let ips = client.resolve(&hostname).await.map_err(to_py_err)?;
            Ok(ips.into_iter().map(|ip| ip.to_string()).collect())
        })
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    #[pyo3(signature = (_exc_type = None, _exc_val = None, _exc_tb = None))]
    fn __exit__(
        &self,
        _exc_type: Option<&Bound<'_, PyAny>>,
        _exc_val: Option<&Bound<'_, PyAny>>,
        _exc_tb: Option<&Bound<'_, PyAny>>,
    ) -> bool {
        false
    }

    fn __repr__(&self) -> String {
        "<hypertor.Client>".to_string()
    }
}

impl PyClient {
    #[allow(clippy::too_many_arguments)]
    fn send(
        &self,
        py: Python<'_>,
        method: http::Method,
        url: &str,
        body: Option<Vec<u8>>,
        json: Option<String>,
        data: Option<HashMap<String, String>>,
        params: Option<HashMap<String, String>>,
        headers: Option<HashMap<String, String>>,
        timeout: Option<f64>,
    ) -> PyResult<PyResponse> {
        let spec = RequestSpec {
            method,
            url: url.to_string(),
            headers,
            body,
            json,
            data,
            params,
            timeout,
            isolation: None,
        };
        let client = Arc::clone(&self.client);
        block_on(py, spec.send(client))
    }
}

/// An asyncio-compatible Tor HTTP client.
#[pyclass(name = "AsyncClient")]
pub struct PyAsyncClient {
    client: Arc<TorClient>,
}

#[pymethods]
impl PyAsyncClient {
    #[new]
    #[pyo3(signature = (
        timeout = 30.0,
        max_idle_per_host = 4,
        isolation = "per_host",
        user_agent = None,
        verify = true,
    ))]
    fn new(
        py: Python<'_>,
        timeout: f64,
        max_idle_per_host: usize,
        isolation: &str,
        user_agent: Option<String>,
        verify: bool,
    ) -> PyResult<Self> {
        let client = py.allow_threads(|| {
            build_client(timeout, max_idle_per_host, isolation, user_agent, verify)
        })?;

        Ok(Self {
            client: Arc::new(client),
        })
    }

    #[pyo3(signature = (url, *, params = None, headers = None, timeout = None))]
    fn get<'py>(
        &self,
        py: Python<'py>,
        url: &str,
        params: Option<HashMap<String, String>>,
        headers: Option<HashMap<String, String>>,
        timeout: Option<f64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.send(
            py,
            http::Method::GET,
            url,
            None,
            None,
            None,
            params,
            headers,
            timeout,
        )
    }

    #[pyo3(signature = (url, *, body = None, json = None, data = None, headers = None, timeout = None))]
    fn post<'py>(
        &self,
        py: Python<'py>,
        url: &str,
        body: Option<Vec<u8>>,
        json: Option<&Bound<'_, PyAny>>,
        data: Option<HashMap<String, String>>,
        headers: Option<HashMap<String, String>>,
        timeout: Option<f64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let json = serialise_json(json)?;
        self.send(
            py,
            http::Method::POST,
            url,
            body,
            json,
            data,
            None,
            headers,
            timeout,
        )
    }

    #[pyo3(signature = (url, *, body = None, json = None, data = None, headers = None, timeout = None))]
    fn put<'py>(
        &self,
        py: Python<'py>,
        url: &str,
        body: Option<Vec<u8>>,
        json: Option<&Bound<'_, PyAny>>,
        data: Option<HashMap<String, String>>,
        headers: Option<HashMap<String, String>>,
        timeout: Option<f64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let json = serialise_json(json)?;
        self.send(
            py,
            http::Method::PUT,
            url,
            body,
            json,
            data,
            None,
            headers,
            timeout,
        )
    }

    #[pyo3(signature = (url, *, headers = None, timeout = None))]
    fn delete<'py>(
        &self,
        py: Python<'py>,
        url: &str,
        headers: Option<HashMap<String, String>>,
        timeout: Option<f64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.send(
            py,
            http::Method::DELETE,
            url,
            None,
            None,
            None,
            None,
            headers,
            timeout,
        )
    }

    fn __aenter__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let client = Arc::clone(&self.client);
        pyo3_async_runtimes::tokio::future_into_py(py, async move { Ok(PyAsyncClient { client }) })
    }

    #[pyo3(signature = (_exc_type = None, _exc_val = None, _exc_tb = None))]
    fn __aexit__<'py>(
        &self,
        py: Python<'py>,
        _exc_type: Option<&Bound<'_, PyAny>>,
        _exc_val: Option<&Bound<'_, PyAny>>,
        _exc_tb: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move { Ok(false) })
    }

    fn __repr__(&self) -> String {
        "<hypertor.AsyncClient>".to_string()
    }
}

impl PyAsyncClient {
    #[allow(clippy::too_many_arguments)]
    fn send<'py>(
        &self,
        py: Python<'py>,
        method: http::Method,
        url: &str,
        body: Option<Vec<u8>>,
        json: Option<String>,
        data: Option<HashMap<String, String>>,
        params: Option<HashMap<String, String>>,
        headers: Option<HashMap<String, String>>,
        timeout: Option<f64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let spec = RequestSpec {
            method,
            url: url.to_string(),
            headers,
            body,
            json,
            data,
            params,
            timeout,
            isolation: None,
        };
        let client = Arc::clone(&self.client);
        pyo3_async_runtimes::tokio::future_into_py(py, spec.send(client))
    }
}

/// Serialise a Python object to a JSON string using the stdlib `json` module.
///
/// Deferring to `json.dumps` means dataclasses, custom encoders and everything
/// else a Python user expects keep working, rather than only the handful of
/// types a Rust-side converter would know about.
fn serialise_json(value: Option<&Bound<'_, PyAny>>) -> PyResult<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };

    let py = value.py();
    let json = py.import("json")?;
    let kwargs = PyDict::new(py);
    kwargs.set_item("separators", (",", ":"))?;

    let dumped: String = json
        .call_method("dumps", (value,), Some(&kwargs))?
        .extract()?;

    Ok(Some(dumped))
}
