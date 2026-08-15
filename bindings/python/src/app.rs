//! Python onion service bindings — a FastAPI-shaped `OnionApp`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use http::StatusCode;
use parking_lot::Mutex;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyString, PyTuple};

use hypertor::{OnionApp, OnionServiceBuilder, ServeRequest, ServeResponse};

use crate::client::to_py_err;
use crate::runtime;

/// How often [`PyOnionApp::run`] returns to the interpreter to look for signals.
///
/// CPython runs signal handlers only when a thread holds the GIL and reaches
/// the top of the eval loop. A Rust loop that blocks with the GIL released —
/// which serving must, or it would freeze the interpreter — never gives it that
/// chance, so `Ctrl-C` was simply ignored until the process was killed. Coming
/// back this often costs nothing measurable and makes `app.run()` behave like
/// every other Python server.
const SIGNAL_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// A request handed to a Python handler.
///
/// Only ever passed *to* Python, never extracted from it, so it opts out of the
/// `FromPyObject` derive.
#[pyclass(name = "Request", skip_from_py_object)]
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
        String::from_utf8(self.body.clone()).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("body is not valid UTF-8: {e}"))
        })
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
            // Previously hard-coded to an empty map, which silently made
            // `request.params` useless in every Python handler.
            params: req.params().clone(),
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
///
/// The handler is behind an `Arc` so it can be cloned per request without a
/// GIL token. `Py<T>` itself only clones under pyo3's `py-clone` feature, which
/// exists precisely because a refcount bump needs the GIL — acquiring it just
/// to duplicate a pointer, on every request, would be a needless serialisation
/// point.
struct PyRoute {
    method: http::Method,
    pattern: String,
    handler: Arc<Py<PyAny>>,
}

/// A FastAPI-style onion service application.
#[pyclass(name = "OnionApp")]
pub struct PyOnionApp {
    routes: Arc<Mutex<Vec<PyRoute>>>,
    nickname: String,
    state_dir: Option<String>,
    static_dir: Option<String>,
    ports: Vec<u16>,
    max_body_size: usize,
    max_connections: usize,
    header_timeout: f64,
}

#[pymethods]
impl PyOnionApp {
    #[new]
    #[pyo3(signature = (
        nickname = "hypertor",
        *,
        port = 80,
        ports = None,
        state_dir = None,
        static_dir = None,
        max_body_size = 2 * 1024 * 1024,
        max_connections = 256,
        header_timeout = 30.0,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        nickname: &str,
        port: u16,
        ports: Option<Vec<u16>>,
        state_dir: Option<String>,
        static_dir: Option<String>,
        max_body_size: usize,
        max_connections: usize,
        header_timeout: f64,
    ) -> PyResult<Self> {
        let ports = match ports {
            Some(ports) if ports.is_empty() => {
                return Err(PyValueError::new_err(
                    "ports must not be empty; a service accepting no port would \
                     publish a descriptor and then reject every client",
                ));
            }
            Some(ports) => ports,
            None => vec![port],
        };

        // Validated here rather than in `run()`, matching the Rust builder. The
        // nickname selects the service's key material, and reporting a bad one
        // only after every route has been registered — and after a bootstrap
        // has been attempted — puts the failure a long way from its cause.
        //
        // `ValueError`, not `HypertorError`: this is a bad argument, and the
        // documented rule is that configuration mistakes raise `ValueError`
        // before any network work happens — as `ports` and `isolation` do.
        OnionServiceBuilder::new()
            .nickname(nickname)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

        Ok(Self {
            routes: Arc::new(Mutex::new(Vec::new())),
            nickname: nickname.to_string(),
            state_dir,
            static_dir,
            ports,
            max_body_size,
            max_connections,
            header_timeout,
        })
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

    /// Register a `PATCH` route. Usable as a decorator.
    fn patch(&self, path: &str) -> PyRouteDecorator {
        self.decorator(http::Method::PATCH, path)
    }

    /// Register a `DELETE` route. Usable as a decorator.
    fn delete(&self, path: &str) -> PyRouteDecorator {
        self.decorator(http::Method::DELETE, path)
    }

    /// Register a route for an arbitrary method. Usable as a decorator.
    fn route(&self, method: &str, path: &str) -> PyResult<PyRouteDecorator> {
        let method = http::Method::from_bytes(method.to_uppercase().as_bytes()).map_err(|_| {
            pyo3::exceptions::PyValueError::new_err(format!("{method:?} is not an HTTP method"))
        })?;
        Ok(self.decorator(method, path))
    }

    /// Launch the service and serve until interrupted.
    ///
    /// Prints the `.onion` address once published unless `quiet` is set.
    /// `Ctrl-C` raises `KeyboardInterrupt` and shuts the service down cleanly,
    /// letting in-flight requests finish.
    #[pyo3(signature = (*, quiet = false))]
    fn run(&self, py: Python<'_>, quiet: bool) -> PyResult<()> {
        let nickname = self.nickname.clone();
        let state_dir = self.state_dir.clone();
        let static_dir = self.static_dir.clone();
        let ports = self.ports.clone();
        let max_body_size = self.max_body_size;
        let max_connections = self.max_connections;
        let header_timeout = Duration::from_secs_f64(self.header_timeout.max(0.0));

        // Clone the handler references while the GIL is held; the serving task
        // must not touch Python state until it re-attaches per request.
        let registered: Vec<(http::Method, String, Arc<Py<PyAny>>)> = self
            .routes
            .lock()
            .iter()
            .map(|r| (r.method.clone(), r.pattern.clone(), Arc::clone(&r.handler)))
            .collect();

        let rt = runtime()?;

        let serving = py.detach(move || {
            rt.block_on(async move {
                let mut builder = OnionServiceBuilder::new()
                    .nickname(&nickname)
                    .map_err(to_py_err)?
                    .ports(ports);

                if let Some(dir) = state_dir {
                    builder = builder.state_dir(dir);
                }

                let service = builder.launch().await.map_err(to_py_err)?;

                let mut app = OnionApp::new()
                    .max_body_size(max_body_size)
                    .max_connections(max_connections)
                    .header_timeout(header_timeout);
                if let Some(dir) = static_dir {
                    app = app.static_files(dir);
                }

                for (method, pattern, handler) in registered {
                    app = app.route(method, &pattern, move |req| {
                        let handler = Arc::clone(&handler);
                        async move { dispatch_to_python(handler, req).await }
                    });
                }

                app.serve_on(service).await.map_err(to_py_err)
            })
        })?;

        if !quiet {
            println!("🧅 serving at {}", serving.onion_address());
        }

        // Serving happens on the runtime's own threads; this loop exists only
        // so the interpreter regains the GIL often enough to notice a signal.
        let outcome = loop {
            if serving.is_finished() {
                break Ok(());
            }
            if let Err(interrupt) = py.check_signals() {
                break Err(interrupt);
            }
            py.detach(|| rt.block_on(tokio::time::sleep(SIGNAL_POLL_INTERVAL)));
        };

        // Bounded internally, so a client that never finishes its request
        // cannot turn Ctrl-C into a hang.
        let shutdown = py.detach(|| rt.block_on(serving.shutdown()));

        match outcome {
            Err(interrupt) => Err(interrupt),
            Ok(()) => shutdown.map_err(to_py_err),
        }
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
    fn __call__(&self, py: Python<'_>, handler: Py<PyAny>) -> Py<PyAny> {
        self.routes.lock().push(PyRoute {
            method: self.method.clone(),
            pattern: self.pattern.clone(),
            handler: Arc::new(handler.clone_ref(py)),
        });
        // Return the handler unchanged, so decorating does not hide the
        // function from the module that defined it.
        handler
    }
}

/// Call a Python handler and turn whatever it returns into a response.
///
/// Runs on a blocking thread. A Python handler holds the GIL for its whole
/// duration and may itself block — on a file, a database, or `asyncio.run` for
/// an `async def` handler — and doing that on a tokio worker would stall every
/// other connection the service is serving.
async fn dispatch_to_python(handler: Arc<Py<PyAny>>, req: ServeRequest) -> ServeResponse {
    let py_req = PyRequest::from(&req);

    let result = tokio::task::spawn_blocking(move || {
        Python::attach(|py| -> PyResult<ServeResponse> {
            let outcome = handler.call1(py, (py_req,))?;
            let bound = outcome.bind(py);

            // Await a coroutine if the handler was `async def`.
            let value = if bound.hasattr("__await__")? {
                py.import("asyncio")?.call_method1("run", (bound,))?
            } else {
                bound.clone()
            };

            to_response(&value)
        })
    })
    .await;

    match result {
        Ok(Ok(response)) => response,
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "Python handler raised");
            ServeResponse::new(http::StatusCode::INTERNAL_SERVER_ERROR)
                .with_body("internal server error")
        }
        Err(e) => {
            tracing::error!(error = %e, "Python handler panicked");
            ServeResponse::new(http::StatusCode::INTERNAL_SERVER_ERROR)
                .with_body("internal server error")
        }
    }
}

/// Convert a handler's return value into a response.
///
/// Follows Flask's convention, which is what a Python author already expects:
/// a bare value is a `200`, and a tuple adds a status and then headers. Without
/// it there was no way at all to return a `404` or set `Cache-Control` from a
/// Python handler, which made the framework unusable for anything past a demo.
fn to_response(value: &Bound<'_, PyAny>) -> PyResult<ServeResponse> {
    // Checked first: a tuple is a container for the pieces below, not a body.
    if let Ok(tuple) = value.cast::<PyTuple>() {
        return from_tuple(tuple);
    }

    if let Ok(text) = value.cast::<PyString>() {
        return Ok(ServeResponse::text(text.to_str()?.to_owned()));
    }

    if value.cast::<PyDict>().is_ok() || value.is_instance_of::<pyo3::types::PyList>() {
        let py = value.py();
        let dumped: String = py
            .import("json")?
            .call_method1("dumps", (value,))?
            .extract()?;
        return Ok(ServeResponse::json_raw(dumped));
    }

    if let Ok(bytes) = value.cast::<pyo3::types::PyBytes>() {
        // The content type is not optional. A body served without one is
        // content-sniffed by the browser, which is how bytes a handler treated
        // as opaque become script; and the documented contract for returning
        // `bytes` has always said `application/octet-stream`.
        return Ok(ServeResponse::new(StatusCode::OK)
            .with_content_type("application/octet-stream")
            .with_body(bytes.as_bytes().to_vec()));
    }

    // `None` is what a handler that forgot to return anything produces, and
    // "None" as a response body would be a baffling thing to debug.
    if value.is_none() {
        return Ok(ServeResponse::new(StatusCode::NO_CONTENT));
    }

    // Anything else: render it the way Python would print it.
    Ok(ServeResponse::text(value.str()?.to_str()?.to_owned()))
}

/// `(body,)`, `(body, status)` or `(body, status, headers)`.
fn from_tuple(tuple: &Bound<'_, PyTuple>) -> PyResult<ServeResponse> {
    if !(1..=3).contains(&tuple.len()) {
        return Err(PyValueError::new_err(
            "a handler returning a tuple must return (body,), (body, status) \
             or (body, status, headers)",
        ));
    }

    let mut response = to_response(&tuple.get_item(0)?)?;

    if tuple.len() >= 2 {
        let code: u16 = tuple.get_item(1)?.extract().map_err(|_| {
            PyValueError::new_err("the second element of a handler's tuple must be a status code")
        })?;
        let status = StatusCode::from_u16(code)
            .map_err(|_| PyValueError::new_err(format!("{code} is not an HTTP status code")))?;
        response = response.with_status(status);
    }

    if tuple.len() == 3 {
        let headers: HashMap<String, String> = tuple.get_item(2)?.extract().map_err(|_| {
            PyValueError::new_err(
                "the third element of a handler's tuple must be a dict of headers",
            )
        })?;
        for (name, value) in headers {
            response = response.with_header(name.as_str(), &value);
        }
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Evaluate a Python expression and convert it the way a handler's return
    /// value is converted.
    ///
    /// This needs a real interpreter, which is available because the `python`
    /// feature no longer forces `pyo3/extension-module` — under that feature
    /// CPython's symbols are left for a loading interpreter to supply, and
    /// there is no interpreter to load a test binary.
    fn convert(expression: &str) -> PyResult<ServeResponse> {
        Python::initialize();
        Python::attach(|py| {
            let value = py.eval(&std::ffi::CString::new(expression).unwrap(), None, None)?;
            to_response(&value)
        })
    }

    fn ok(expression: &str) -> ServeResponse {
        convert(expression).expect("converts")
    }

    #[test]
    fn a_bare_string_is_a_200() {
        let response = ok("'hello'");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body().unwrap().as_ref(), b"hello");
    }

    #[test]
    fn a_dict_is_json() {
        let response = ok("{'a': 1}");
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json"
        );
        assert_eq!(response.body().unwrap().as_ref(), br#"{"a": 1}"#);
    }

    #[test]
    fn a_tuple_sets_the_status() {
        // Without this there was no way at all to return a 404 from Python.
        let response = ok("('gone', 410)");
        assert_eq!(response.status(), StatusCode::GONE);
        assert_eq!(response.body().unwrap().as_ref(), b"gone");
    }

    #[test]
    fn a_three_element_tuple_also_sets_headers() {
        let response = ok("({'ok': True}, 201, {'location': '/thing/1'})");
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers().get("location").unwrap(), "/thing/1");
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json",
            "the body's own content type must survive the tuple"
        );
    }

    #[test]
    fn a_one_element_tuple_is_just_its_body() {
        assert_eq!(ok("('body',)").status(), StatusCode::OK);
    }

    #[test]
    fn returning_nothing_is_a_204_rather_than_the_text_none() {
        // A handler that forgets to return is a common slip, and a body reading
        // "None" is a baffling thing to debug.
        let response = ok("None");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(response.body().unwrap().is_empty());
    }

    #[test]
    fn bytes_are_passed_through_unchanged() {
        assert_eq!(ok("b'\\x00\\xff'").body().unwrap().as_ref(), b"\x00\xff");
    }

    #[test]
    fn bytes_carry_the_content_type_they_are_documented_to_carry() {
        // Serving a body with no content type at all leaves a browser to sniff
        // it, which is how bytes a handler treated as opaque become script.
        let response = ok("b'\\x00\\xff'");
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/octet-stream"
        );
    }

    #[test]
    fn a_nonsense_status_is_reported_rather_than_ignored() {
        // `http` accepts anything in 100..=999, so the rejects here are a code
        // below the range, a non-integer, and a tuple of the wrong shape.
        for expression in ["('x', 42)", "('x', 'not a status')", "('a','b','c','d')"] {
            assert!(
                convert(expression).is_err(),
                "must reject {expression}: silently serving a 200 would hide the bug"
            );
        }
    }

    #[test]
    fn a_bad_header_map_is_reported() {
        assert!(convert("('x', 200, ['not', 'a', 'dict'])").is_err());
    }
}
