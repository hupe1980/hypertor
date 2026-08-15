//! Python onion service bindings — a FastAPI-shaped `OnionApp`.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyString};

use crate::onion_service::OnionServiceBuilder;
use crate::serve::{OnionApp, Request as ServeRequest, Response as ServeResponse};

use super::client::{HypertorError, to_py_err};
use super::runtime;

/// A request handed to a Python handler.
#[pyclass(name = "Request")]
#[derive(Clone)]
pub struct PyRequest {
    method: String,
    path: String,
    query: HashMap<String, String>,
    params: HashMap<String, String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

#[pymethods]
impl PyRequest {
    /// The HTTP method.
    #[getter]
    fn method(&self) -> &str {
        &self.method
    }

    /// The request path.
    #[getter]
    fn path(&self) -> &str {
        &self.path
    }

    /// The decoded query parameters.
    #[getter]
    fn query(&self) -> HashMap<String, String> {
        self.query.clone()
    }

    /// Path parameters captured by the route pattern.
    #[getter]
    fn params(&self) -> HashMap<String, String> {
        self.params.clone()
    }

    /// The request headers, lowercased.
    #[getter]
    fn headers(&self) -> HashMap<String, String> {
        self.headers.clone()
    }

    /// The raw request body.
    #[getter]
    fn body<'py>(&self, py: Python<'py>) -> Bound<'py, pyo3::types::PyBytes> {
        pyo3::types::PyBytes::new(py, &self.body)
    }

    /// The body decoded as UTF-8 text.
    fn text(&self) -> PyResult<String> {
        String::from_utf8(self.body.clone())
            .map_err(|e| HypertorError::new_err(format!("body is not valid UTF-8: {e}")))
    }

    /// The body parsed as JSON.
    fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        py.import("json")?.call_method1("loads", (self.text()?,))
    }

    fn __repr__(&self) -> String {
        format!("<hypertor.Request {} {}>", self.method, self.path)
    }
}

impl From<&ServeRequest> for PyRequest {
    fn from(req: &ServeRequest) -> Self {
        Self {
            method: req.method().as_str().to_string(),
            path: req.path().to_string(),
            query: req.queries().clone(),
            params: HashMap::new(),
            headers: req
                .headers()
                .iter()
                .filter_map(|(k, v)| {
                    v.to_str()
                        .ok()
                        .map(|v| (k.as_str().to_lowercase(), v.to_string()))
                })
                .collect(),
            body: req.body().to_vec(),
        }
    }
}

/// One registered Python route.
struct PyRoute {
    method: http::Method,
    pattern: String,
    handler: Py<PyAny>,
}

/// A FastAPI-style onion service application.
#[pyclass(name = "OnionApp")]
pub struct PyOnionApp {
    routes: Arc<Mutex<Vec<PyRoute>>>,
    nickname: String,
    state_dir: Option<String>,
    port: u16,
}

#[pymethods]
impl PyOnionApp {
    #[new]
    #[pyo3(signature = (nickname = "hypertor", *, port = 80, state_dir = None))]
    fn new(nickname: &str, port: u16, state_dir: Option<String>) -> Self {
        Self {
            routes: Arc::new(Mutex::new(Vec::new())),
            nickname: nickname.to_string(),
            state_dir,
            port,
        }
    }

    /// Register a `GET` route. Usable as a decorator.
    fn get(&self, path: &str) -> PyRouteDecorator {
        self.decorator(http::Method::GET, path)
    }

    /// Register a `POST` route. Usable as a decorator.
    fn post(&self, path: &str) -> PyRouteDecorator {
        self.decorator(http::Method::POST, path)
    }

    /// Register a `PUT` route. Usable as a decorator.
    fn put(&self, path: &str) -> PyRouteDecorator {
        self.decorator(http::Method::PUT, path)
    }

    /// Register a `DELETE` route. Usable as a decorator.
    fn delete(&self, path: &str) -> PyRouteDecorator {
        self.decorator(http::Method::DELETE, path)
    }

    /// Launch the service and serve until interrupted.
    ///
    /// Returns the `.onion` address once published, then blocks.
    fn run(&self, py: Python<'_>) -> PyResult<()> {
        let nickname = self.nickname.clone();
        let state_dir = self.state_dir.clone();
        let port = self.port;

        // Clone the handler references while the GIL is held; the serving task
        // must not touch Python state until it re-attaches per request.
        let registered: Vec<(http::Method, String, Py<PyAny>)> = self
            .routes
            .lock()
            .iter()
            .map(|r| (r.method.clone(), r.pattern.clone(), r.handler.clone_ref(py)))
            .collect();

        let rt = runtime()?;

        py.allow_threads(move || {
            rt.block_on(async move {
                let mut builder = OnionServiceBuilder::new()
                    .nickname(&nickname)
                    .map_err(to_py_err)?
                    .port(port);

                if let Some(dir) = state_dir {
                    builder = builder.state_dir(dir);
                }

                let service = builder.launch().await.map_err(to_py_err)?;
                let mut app = OnionApp::new();

                for (method, pattern, handler) in registered {
                    app = app.route(method, &pattern, move |req| {
                        let handler = handler.clone();
                        async move { dispatch_to_python(handler, req).await }
                    });
                }

                let serving = app.serve_on(service).await.map_err(to_py_err)?;
                println!("🧅 serving at {}", serving.onion_address());
                serving.wait().await.map_err(to_py_err)
            })
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "<hypertor.OnionApp {} routes={}>",
            self.nickname,
            self.routes.lock().len()
        )
    }
}

impl PyOnionApp {
    fn decorator(&self, method: http::Method, path: &str) -> PyRouteDecorator {
        PyRouteDecorator {
            routes: Arc::clone(&self.routes),
            method,
            pattern: path.to_string(),
        }
    }
}

/// The object returned by `@app.get("/")`, which captures the handler.
#[pyclass]
pub struct PyRouteDecorator {
    routes: Arc<Mutex<Vec<PyRoute>>>,
    method: http::Method,
    pattern: String,
}

#[pymethods]
impl PyRouteDecorator {
    fn __call__(&self, handler: Py<PyAny>) -> Py<PyAny> {
        self.routes.lock().push(PyRoute {
            method: self.method.clone(),
            pattern: self.pattern.clone(),
            handler: handler.clone(),
        });
        // Return the handler unchanged, so decorating does not hide the
        // function from the module that defined it.
        handler
    }
}

/// Call a Python handler and turn whatever it returns into a response.
///
/// Coroutines are awaited via `asyncio.run`, so `async def` handlers work
/// alongside plain ones.
async fn dispatch_to_python(handler: Py<PyAny>, req: ServeRequest) -> ServeResponse {
    let py_req = PyRequest::from(&req);

    let result = Python::attach(|py| -> PyResult<ServeResponse> {
        let outcome = handler.call1(py, (py_req,))?;
        let bound = outcome.bind(py);

        // Await a coroutine if the handler was `async def`.
        let value = if bound.hasattr("__await__")? {
            py.import("asyncio")?.call_method1("run", (bound,))?
        } else {
            bound.clone()
        };

        to_response(&value)
    });

    match result {
        Ok(response) => response,
        Err(e) => {
            tracing::warn!(error = %e, "Python handler raised");
            ServeResponse::status(http::StatusCode::INTERNAL_SERVER_ERROR)
                .with_body("internal server error")
        }
    }
}

/// Convert a handler's return value into a response.
fn to_response(value: &Bound<'_, PyAny>) -> PyResult<ServeResponse> {
    if let Ok(text) = value.downcast::<PyString>() {
        return Ok(ServeResponse::text(text.to_str()?.to_owned()));
    }

    if value.downcast::<PyDict>().is_ok() || value.is_instance_of::<pyo3::types::PyList>() {
        let py = value.py();
        let dumped: String = py
            .import("json")?
            .call_method1("dumps", (value,))?
            .extract()?;
        return Ok(ServeResponse::json_raw(dumped));
    }

    if let Ok(bytes) = value.downcast::<pyo3::types::PyBytes>() {
        return Ok(ServeResponse::status(http::StatusCode::OK).with_body(bytes.as_bytes().to_vec()));
    }

    // Anything else: render it the way Python would print it.
    Ok(ServeResponse::text(value.str()?.to_str()?.to_owned()))
}
