//! Python client bindings.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;

use hypertor::{Error, IsolationLevel, IsolationToken, RedirectPolicy, TorClient};

use crate::response::PyResponse;
use crate::{block_on, runtime};

#[allow(missing_docs)]
mod exceptions {
    use super::*;
    create_exception!(hypertor, HypertorError, PyException);
    create_exception!(hypertor, ConnectionError, HypertorError);
    create_exception!(hypertor, TimeoutError, HypertorError);
    create_exception!(hypertor, TlsError, HypertorError);
    create_exception!(hypertor, StatusError, HypertorError);
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
        Error::Status { .. } => StatusError::new_err(err.to_string()),
        _ => HypertorError::new_err(err.to_string()),
    }
}

// ===========================================================================
// Isolation
// ===========================================================================

/// A handle identifying one circuit-sharing group.
///
/// Requests carrying equal tokens may share a circuit; requests carrying
/// different tokens never do.
/// Extracted from Python as the `isolation=` argument, so it needs the
/// `FromPyObject` derive.
#[pyclass(name = "IsolationToken", from_py_object)]
#[derive(Clone, Copy)]
pub struct PyIsolationToken {
    inner: IsolationToken,
}

#[pymethods]
impl PyIsolationToken {
    #[new]
    fn new() -> Self {
        Self {
            inner: IsolationToken::new(),
        }
    }

    fn __repr__(&self) -> String {
        "<hypertor.IsolationToken>".to_string()
    }
}

// ===========================================================================
// Request shaping
// ===========================================================================

/// Everything the sync and async clients need to build one request.
///
/// Kept as one struct so the two clients cannot drift apart: a parameter added
/// to one but forgotten in the other is the classic binding bug.
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

/// The keyword arguments every request method accepts.
#[derive(Default)]
struct RequestArgs {
    body: Option<Vec<u8>>,
    json: Option<String>,
    data: Option<HashMap<String, String>>,
    params: Option<HashMap<String, String>>,
    headers: Option<HashMap<String, String>>,
    timeout: Option<f64>,
    isolation: Option<PyIsolationToken>,
}

impl RequestArgs {
    fn into_spec(self, method: http::Method, url: &str) -> RequestSpec {
        RequestSpec {
            method,
            url: url.to_string(),
            headers: self.headers,
            body: self.body,
            json: self.json,
            data: self.data,
            params: self.params,
            timeout: self.timeout,
            isolation: self.isolation.map(|t| t.inner),
        }
    }
}

/// Settings shared by both clients.
struct ClientSettings {
    timeout: f64,
    connect_timeout: f64,
    max_idle_per_host: usize,
    max_response_size: usize,
    isolation: String,
    user_agent: Option<String>,
    verify: bool,
    max_redirects: usize,
    max_retries: u32,
}

fn build_client(settings: ClientSettings) -> PyResult<TorClient> {
    let level = match settings.isolation.as_str() {
        "none" => IsolationLevel::None,
        "per_host" => IsolationLevel::PerHost,
        "per_request" => IsolationLevel::PerRequest,
        other => {
            return Err(PyValueError::new_err(format!(
                "unknown isolation {other:?}; expected 'none', 'per_host' or 'per_request'"
            )));
        }
    };

    let mut builder = TorClient::builder()
        .timeout(Duration::from_secs_f64(settings.timeout))
        .connect_timeout(Duration::from_secs_f64(settings.connect_timeout))
        .pool_max_idle_per_host(settings.max_idle_per_host)
        .max_response_size(settings.max_response_size)
        .max_retries(settings.max_retries)
        .redirect(RedirectPolicy::limited(settings.max_redirects))
        .isolation(level)
        .danger_accept_invalid_certs(!settings.verify);

    if let Some(ua) = settings.user_agent {
        builder = builder.user_agent(ua);
    }

    let rt = runtime()?;
    rt.block_on(builder.build()).map_err(to_py_err)
}

/// The entire `#[pymethods]` surface of a client, from one definition.
///
/// The sync and async clients expose the same fourteen methods with the same
/// keyword arguments; writing them out twice is how the two surfaces drift, and
/// a keyword that exists on one but not the other is the classic binding bug.
macro_rules! client_pymethods {
    ($client:ident, $send:ident, $ret:ty, $repr:literal $(, $extra:item)*) => {
        #[pymethods]
        impl $client {
            #[new]
            #[pyo3(signature = (
                timeout = 60.0,
                connect_timeout = 30.0,
                max_idle_per_host = 4,
                max_response_size = 16 * 1024 * 1024,
                isolation = "per_host".to_string(),
                user_agent = None,
                verify = true,
                max_redirects = 10,
                max_retries = 2,
            ))]
            #[allow(clippy::too_many_arguments)]
            fn new(
                py: Python<'_>,
                timeout: f64,
                connect_timeout: f64,
                max_idle_per_host: usize,
                max_response_size: usize,
                isolation: String,
                user_agent: Option<String>,
                verify: bool,
                max_redirects: usize,
                max_retries: u32,
            ) -> PyResult<Self> {
                let settings = ClientSettings {
                    timeout,
                    connect_timeout,
                    max_idle_per_host,
                    max_response_size,
                    isolation,
                    user_agent,
                    verify,
                    max_redirects,
                    max_retries,
                };

                // Bootstrapping takes tens of seconds on a cold cache; holding
                // the GIL for that would freeze the whole interpreter.
                let client = py.detach(|| build_client(settings))?;

                Ok(Self {
                    client: Arc::new(client),
                })
            }

            #[pyo3(signature = (url, *, params = None, headers = None, timeout = None, isolation = None))]
            fn get<'py>(
                &self,
                py: Python<'py>,
                url: &str,
                params: Option<HashMap<String, String>>,
                headers: Option<HashMap<String, String>>,
                timeout: Option<f64>,
                isolation: Option<PyIsolationToken>,
            ) -> PyResult<$ret> {
                self.$send(py, http::Method::GET, url, RequestArgs {
                    params, headers, timeout, isolation, ..Default::default()
                })
            }

            #[pyo3(signature = (url, *, params = None, headers = None, timeout = None, isolation = None))]
            fn head<'py>(
                &self,
                py: Python<'py>,
                url: &str,
                params: Option<HashMap<String, String>>,
                headers: Option<HashMap<String, String>>,
                timeout: Option<f64>,
                isolation: Option<PyIsolationToken>,
            ) -> PyResult<$ret> {
                self.$send(py, http::Method::HEAD, url, RequestArgs {
                    params, headers, timeout, isolation, ..Default::default()
                })
            }

            #[pyo3(signature = (url, *, params = None, headers = None, timeout = None, isolation = None))]
            fn options<'py>(
                &self,
                py: Python<'py>,
                url: &str,
                params: Option<HashMap<String, String>>,
                headers: Option<HashMap<String, String>>,
                timeout: Option<f64>,
                isolation: Option<PyIsolationToken>,
            ) -> PyResult<$ret> {
                self.$send(py, http::Method::OPTIONS, url, RequestArgs {
                    params, headers, timeout, isolation, ..Default::default()
                })
            }

            #[pyo3(signature = (url, *, body = None, json = None, data = None, params = None, headers = None, timeout = None, isolation = None))]
            #[allow(clippy::too_many_arguments)]
            fn post<'py>(
                &self,
                py: Python<'py>,
                url: &str,
                body: Option<Vec<u8>>,
                json: Option<&Bound<'_, PyAny>>,
                data: Option<HashMap<String, String>>,
                params: Option<HashMap<String, String>>,
                headers: Option<HashMap<String, String>>,
                timeout: Option<f64>,
                isolation: Option<PyIsolationToken>,
            ) -> PyResult<$ret> {
                let json = serialise_json(json)?;
                self.$send(py, http::Method::POST, url, RequestArgs {
                    body, json, data, params, headers, timeout, isolation,
                })
            }

            #[pyo3(signature = (url, *, body = None, json = None, data = None, params = None, headers = None, timeout = None, isolation = None))]
            #[allow(clippy::too_many_arguments)]
            fn put<'py>(
                &self,
                py: Python<'py>,
                url: &str,
                body: Option<Vec<u8>>,
                json: Option<&Bound<'_, PyAny>>,
                data: Option<HashMap<String, String>>,
                params: Option<HashMap<String, String>>,
                headers: Option<HashMap<String, String>>,
                timeout: Option<f64>,
                isolation: Option<PyIsolationToken>,
            ) -> PyResult<$ret> {
                let json = serialise_json(json)?;
                self.$send(py, http::Method::PUT, url, RequestArgs {
                    body, json, data, params, headers, timeout, isolation,
                })
            }

            #[pyo3(signature = (url, *, body = None, json = None, data = None, params = None, headers = None, timeout = None, isolation = None))]
            #[allow(clippy::too_many_arguments)]
            fn patch<'py>(
                &self,
                py: Python<'py>,
                url: &str,
                body: Option<Vec<u8>>,
                json: Option<&Bound<'_, PyAny>>,
                data: Option<HashMap<String, String>>,
                params: Option<HashMap<String, String>>,
                headers: Option<HashMap<String, String>>,
                timeout: Option<f64>,
                isolation: Option<PyIsolationToken>,
            ) -> PyResult<$ret> {
                let json = serialise_json(json)?;
                self.$send(py, http::Method::PATCH, url, RequestArgs {
                    body, json, data, params, headers, timeout, isolation,
                })
            }

            #[pyo3(signature = (url, *, body = None, json = None, params = None, headers = None, timeout = None, isolation = None))]
            #[allow(clippy::too_many_arguments)]
            fn delete<'py>(
                &self,
                py: Python<'py>,
                url: &str,
                body: Option<Vec<u8>>,
                json: Option<&Bound<'_, PyAny>>,
                params: Option<HashMap<String, String>>,
                headers: Option<HashMap<String, String>>,
                timeout: Option<f64>,
                isolation: Option<PyIsolationToken>,
            ) -> PyResult<$ret> {
                let json = serialise_json(json)?;
                self.$send(py, http::Method::DELETE, url, RequestArgs {
                    body, json, params, headers, timeout, isolation, ..Default::default()
                })
            }

            /// Send a request with an arbitrary method.
            #[pyo3(signature = (method, url, *, body = None, json = None, data = None, params = None, headers = None, timeout = None, isolation = None))]
            #[allow(clippy::too_many_arguments)]
            fn request<'py>(
                &self,
                py: Python<'py>,
                method: &str,
                url: &str,
                body: Option<Vec<u8>>,
                json: Option<&Bound<'_, PyAny>>,
                data: Option<HashMap<String, String>>,
                params: Option<HashMap<String, String>>,
                headers: Option<HashMap<String, String>>,
                timeout: Option<f64>,
                isolation: Option<PyIsolationToken>,
            ) -> PyResult<$ret> {
                let method = http::Method::from_bytes(method.to_uppercase().as_bytes())
                    .map_err(|_| PyValueError::new_err(format!("{method:?} is not an HTTP method")))?;
                let json = serialise_json(json)?;
                self.$send(py, method, url, RequestArgs {
                    body, json, data, params, headers, timeout, isolation,
                })
            }

            fn __repr__(&self) -> String {
                $repr.to_string()
            }

            $($extra)*
        }
    };
}

// ===========================================================================
// Sync client
// ===========================================================================

/// A synchronous Tor HTTP client.
#[pyclass(name = "Client")]
pub struct PyClient {
    client: Arc<TorClient>,
}

client_pymethods!(
    PyClient,
    send_sync,
    PyResponse,
    "<hypertor.Client>",
    /// Resolve a hostname through Tor, never locally.
    fn resolve(&self, py: Python<'_>, hostname: &str) -> PyResult<Vec<String>> {
        let client = Arc::clone(&self.client);
        let hostname = hostname.to_string();

        block_on(py, async move {
            let ips = client.resolve(&hostname).await.map_err(to_py_err)?;
            Ok(ips.into_iter().map(|ip| ip.to_string()).collect())
        })
    },
    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    },
    #[pyo3(signature = (_exc_type = None, _exc_val = None, _exc_tb = None))]
    fn __exit__(
        &self,
        _exc_type: Option<&Bound<'_, PyAny>>,
        _exc_val: Option<&Bound<'_, PyAny>>,
        _exc_tb: Option<&Bound<'_, PyAny>>,
    ) -> bool {
        false
    }
);

impl PyClient {
    fn send_sync(
        &self,
        py: Python<'_>,
        method: http::Method,
        url: &str,
        args: RequestArgs,
    ) -> PyResult<PyResponse> {
        let spec = args.into_spec(method, url);
        let client = Arc::clone(&self.client);
        block_on(py, spec.send(client))
    }
}

// ===========================================================================
// Async client
// ===========================================================================

/// An asyncio-compatible Tor HTTP client.
#[pyclass(name = "AsyncClient")]
pub struct PyAsyncClient {
    client: Arc<TorClient>,
}

client_pymethods!(
    PyAsyncClient,
    send_async,
    Bound<'py, PyAny>,
    "<hypertor.AsyncClient>",
    /// Resolve a hostname through Tor, never locally.
    fn resolve<'py>(&self, py: Python<'py>, hostname: &str) -> PyResult<Bound<'py, PyAny>> {
        let client = Arc::clone(&self.client);
        let hostname = hostname.to_string();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let ips = client.resolve(&hostname).await.map_err(to_py_err)?;
            Ok(ips
                .into_iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<String>>())
        })
    },
    fn __aenter__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let client = Arc::clone(&self.client);
        pyo3_async_runtimes::tokio::future_into_py(py, async move { Ok(PyAsyncClient { client }) })
    },
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
);

impl PyAsyncClient {
    fn send_async<'py>(
        &self,
        py: Python<'py>,
        method: http::Method,
        url: &str,
        args: RequestArgs,
    ) -> PyResult<Bound<'py, PyAny>> {
        let spec = args.into_spec(method, url);
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
