//! Python client bindings

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::runtime::Runtime;

use crate::client::TorClient;
use crate::config::Config;
use crate::error::Error;

use super::response::PyResponse;

// Define Python exceptions
// Note: create_exception! macro generates undocumented structs, we suppress the warning here
#[allow(missing_docs)]
mod exceptions {
    use super::*;
    create_exception!(hypertor, HypertorError, PyException);
    create_exception!(hypertor, TorBootstrapError, HypertorError);
    create_exception!(hypertor, TorConnectionError, HypertorError);
    create_exception!(hypertor, TorTimeoutError, HypertorError);
    create_exception!(hypertor, TlsError, HypertorError);
}
pub use exceptions::*;

/// Convert Rust error to Python exception
pub fn to_py_err(err: Error) -> PyErr {
    match &err {
        Error::Bootstrap { .. } => TorBootstrapError::new_err(err.to_string()),
        Error::Connection { .. } | Error::Circuit { .. } => {
            TorConnectionError::new_err(err.to_string())
        }
        Error::Timeout { .. } | Error::PoolExhausted { .. } => {
            TorTimeoutError::new_err(err.to_string())
        }
        Error::TlsHandshake { .. } | Error::TlsConfig { .. } => TlsError::new_err(err.to_string()),
        _ => HypertorError::new_err(err.to_string()),
    }
}

/// Synchronous Tor HTTP client for Python
///
/// Example:
///     >>> client = hypertor.Client()
///     >>> response = client.get("http://example.onion")
///     >>> print(response.text())
#[pyclass(name = "Client")]
pub struct PyClient {
    client: Arc<TorClient>,
    runtime: Arc<Runtime>,
}

#[pymethods]
impl PyClient {
    /// Create a new Tor client
    ///
    /// Args:
    ///     timeout: Request timeout in seconds (default: 30)
    ///     max_connections: Maximum pooled connections (default: 10)
    ///
    /// Raises:
    ///     TorBootstrapError: If Tor connection fails
    #[new]
    #[pyo3(signature = (timeout=30, max_connections=10))]
    fn new(timeout: u64, max_connections: usize) -> PyResult<Self> {
        let runtime = Runtime::new().map_err(|e| HypertorError::new_err(e.to_string()))?;

        let config = Config::builder()
            .timeout(std::time::Duration::from_secs(timeout))
            .max_connections(max_connections)
            .build()
            .map_err(to_py_err)?;

        let client = runtime
            .block_on(TorClient::with_config(config))
            .map_err(to_py_err)?;

        Ok(Self {
            client: Arc::new(client),
            runtime: Arc::new(runtime),
        })
    }

    /// Make a GET request
    ///
    /// Args:
    ///     url: The URL to request
    ///
    /// Returns:
    ///     Response object
    fn get(&self, url: &str) -> PyResult<PyResponse> {
        let client = Arc::clone(&self.client);
        let url = url.to_string();

        self.runtime.block_on(async move {
            let builder = client.get(&url).map_err(to_py_err)?;
            let response = builder.send().await.map_err(to_py_err)?;
            Ok(PyResponse::from(response))
        })
    }

    /// Make a POST request
    ///
    /// Args:
    ///     url: The URL to request
    ///     body: Optional request body (bytes)
    ///     json: Optional JSON body (will be serialized)
    ///     data: Optional form data (dict)
    ///
    /// Returns:
    ///     Response object
    #[pyo3(signature = (url, body=None, json=None, data=None))]
    fn post(
        &self,
        url: &str,
        body: Option<&[u8]>,
        json: Option<&str>,
        data: Option<HashMap<String, String>>,
    ) -> PyResult<PyResponse> {
        let client = Arc::clone(&self.client);
        let url = url.to_string();
        let body = body.map(|b| b.to_vec());
        let json = json.map(|s| s.to_string());

        self.runtime.block_on(async move {
            let mut builder = client.post(&url).map_err(to_py_err)?;

            if let Some(j) = json {
                builder = builder.json(&j);
            } else if let Some(d) = data {
                builder = builder
                    .form(d.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                    .map_err(to_py_err)?;
            } else if let Some(b) = body {
                builder = builder.body(b);
            }

            let response = builder.send().await.map_err(to_py_err)?;
            Ok(PyResponse::from(response))
        })
    }

    /// Make a PUT request
    #[pyo3(signature = (url, body=None, json=None, data=None))]
    fn put(
        &self,
        url: &str,
        body: Option<&[u8]>,
        json: Option<&str>,
        data: Option<HashMap<String, String>>,
    ) -> PyResult<PyResponse> {
        let client = Arc::clone(&self.client);
        let url = url.to_string();
        let body = body.map(|b| b.to_vec());
        let json = json.map(|s| s.to_string());

        self.runtime.block_on(async move {
            let mut builder = client.put(&url).map_err(to_py_err)?;

            if let Some(j) = json {
                builder = builder.json(&j);
            } else if let Some(d) = data {
                builder = builder
                    .form(d.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                    .map_err(to_py_err)?;
            } else if let Some(b) = body {
                builder = builder.body(b);
            }

            let response = builder.send().await.map_err(to_py_err)?;
            Ok(PyResponse::from(response))
        })
    }

    /// Make a DELETE request
    fn delete(&self, url: &str) -> PyResult<PyResponse> {
        let client = Arc::clone(&self.client);
        let url = url.to_string();

        self.runtime.block_on(async move {
            let builder = client.delete(&url).map_err(to_py_err)?;
            let response = builder.send().await.map_err(to_py_err)?;
            Ok(PyResponse::from(response))
        })
    }

    /// Get the number of pooled connections
    fn pool_size(&self) -> usize {
        self.client.pool_size()
    }

    /// Clear the connection pool
    fn clear_pool(&self) {
        self.client.clear_pool();
    }

    /// Context manager entry
    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    /// Context manager exit
    #[pyo3(signature = (_exc_type=None, _exc_val=None, _exc_tb=None))]
    fn __exit__(
        &self,
        _exc_type: Option<&Bound<'_, PyAny>>,
        _exc_val: Option<&Bound<'_, PyAny>>,
        _exc_tb: Option<&Bound<'_, PyAny>>,
    ) -> bool {
        self.clear_pool();
        false
    }
}

/// Asynchronous Tor HTTP client for Python
///
/// Example:
///     >>> async with hypertor.AsyncClient() as client:
///     ...     response = await client.get("http://example.onion")
///     ...     print(await response.text())
#[pyclass(name = "AsyncClient")]
pub struct PyAsyncClient {
    client: Arc<TorClient>,
    #[allow(dead_code)]
    runtime: Arc<Runtime>, // Keep runtime alive for the TorClient
}

#[pymethods]
impl PyAsyncClient {
    /// Create a new async Tor client (synchronous initialization)
    ///
    /// Note: This performs synchronous Tor bootstrapping. For fully async
    /// initialization, use `await AsyncClient.create()`
    #[new]
    #[pyo3(signature = (timeout=30, max_connections=10))]
    fn new(timeout: u64, max_connections: usize) -> PyResult<Self> {
        // Create a runtime for bootstrapping AND keep it alive
        let runtime =
            tokio::runtime::Runtime::new().map_err(|e| HypertorError::new_err(e.to_string()))?;

        let config = Config::builder()
            .timeout(std::time::Duration::from_secs(timeout))
            .max_connections(max_connections)
            .build()
            .map_err(to_py_err)?;

        let client = runtime
            .block_on(TorClient::with_config(config))
            .map_err(to_py_err)?;

        Ok(Self {
            client: Arc::new(client),
            runtime: Arc::new(runtime),
        })
    }

    /// Create a new async Tor client asynchronously
    ///
    /// Note: This method still creates a tokio runtime internally.
    /// Use `AsyncClient()` constructor for simpler usage.
    #[staticmethod]
    #[pyo3(signature = (timeout=30, max_connections=10))]
    fn create<'py>(
        py: Python<'py>,
        timeout: u64,
        max_connections: usize,
    ) -> PyResult<Bound<'py, PyAny>> {
        // For async create, we still need a runtime
        let runtime = Arc::new(
            tokio::runtime::Runtime::new().map_err(|e| HypertorError::new_err(e.to_string()))?,
        );
        let rt = Arc::clone(&runtime);

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let config = Config::builder()
                .timeout(std::time::Duration::from_secs(timeout))
                .max_connections(max_connections)
                .build()
                .map_err(to_py_err)?;

            // Run within our runtime
            let client = rt
                .spawn(async move { TorClient::with_config(config).await })
                .await
                .map_err(|e| HypertorError::new_err(e.to_string()))?
                .map_err(to_py_err)?;

            Ok(PyAsyncClient {
                client: Arc::new(client),
                runtime,
            })
        })
    }

    /// Make an async GET request
    fn get<'py>(&self, py: Python<'py>, url: String) -> PyResult<Bound<'py, PyAny>> {
        let client = Arc::clone(&self.client);
        let runtime = Arc::clone(&self.runtime);

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let result = runtime
                .spawn(async move {
                    let builder = client.get(&url)?;
                    builder.send().await
                })
                .await
                .map_err(|e| HypertorError::new_err(e.to_string()))?;

            Ok(PyResponse::from(result.map_err(to_py_err)?))
        })
    }

    /// Make an async POST request
    #[pyo3(signature = (url, body=None, json=None, data=None))]
    fn post<'py>(
        &self,
        py: Python<'py>,
        url: String,
        body: Option<Vec<u8>>,
        json: Option<String>,
        data: Option<HashMap<String, String>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = Arc::clone(&self.client);
        let runtime = Arc::clone(&self.runtime);

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let result = runtime
                .spawn(async move {
                    let mut builder = client.post(&url)?;

                    if let Some(j) = json {
                        builder = builder.json(&j);
                    } else if let Some(d) = data {
                        builder = builder.form(d.iter().map(|(k, v)| (k.as_str(), v.as_str())))?;
                    } else if let Some(b) = body {
                        builder = builder.body(b);
                    }

                    builder.send().await
                })
                .await
                .map_err(|e| HypertorError::new_err(e.to_string()))?;

            Ok(PyResponse::from(result.map_err(to_py_err)?))
        })
    }

    /// Get the number of pooled connections
    fn pool_size(&self) -> usize {
        self.client.pool_size()
    }

    /// Async context manager entry
    fn __aenter__<'py>(slf: PyRef<'py, Self>, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let client = PyAsyncClient {
            client: Arc::clone(&slf.client),
            runtime: Arc::clone(&slf.runtime),
        };
        pyo3_async_runtimes::tokio::future_into_py(py, async move { Ok(client) })
    }

    /// Async context manager exit
    #[pyo3(signature = (_exc_type=None, _exc_val=None, _exc_tb=None))]
    fn __aexit__<'py>(
        &self,
        py: Python<'py>,
        _exc_type: Option<&Bound<'_, PyAny>>,
        _exc_val: Option<&Bound<'_, PyAny>>,
        _exc_tb: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = Arc::clone(&self.client);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            client.clear_pool();
            Ok(false)
        })
    }
}
