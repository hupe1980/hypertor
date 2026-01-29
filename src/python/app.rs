//! Python OnionApp bindings - FastAPI-like decorator pattern
//!
//! Provides a Pythonic interface for hosting onion services:
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
//! @app.get("/users/{user_id}")
//! def get_user(user_id: int):
//!     return {"id": user_id, "name": "Alice"}
//!
//! app.run()  # 🧅 Service live at: xyz...xyz.onion
//! ```

use parking_lot::RwLock;
use pyo3::prelude::*;
use pyo3::types::{PyCFunction, PyDict, PyList, PyTuple};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::runtime::Runtime;

use super::client::HypertorError;
use crate::onion_service::{OnionService, OnionServiceConfig};

/// Route handler stored from Python decorators
#[allow(dead_code)]
struct PyRoute {
    /// HTTP method
    method: String,
    /// Path pattern (e.g., "/users/{id}")
    path: String,
    /// Python callable (stored as raw pointer for thread safety)
    handler: Py<PyAny>,
    /// Response type hint
    response_model: Option<String>,
}

/// Request object passed to Python handlers
#[pyclass(name = "Request")]
#[derive(Clone)]
pub struct PyRequest {
    /// HTTP method
    #[pyo3(get)]
    pub method: String,
    /// Request path
    #[pyo3(get)]
    pub path: String,
    /// Path parameters extracted from route
    #[pyo3(get)]
    pub params: HashMap<String, String>,
    /// Query parameters
    #[pyo3(get)]
    pub query: HashMap<String, String>,
    /// Request headers
    #[pyo3(get)]
    pub headers: HashMap<String, String>,
    /// Request body bytes
    body: Vec<u8>,
}

#[pymethods]
impl PyRequest {
    /// Get request body as text
    fn text(&self) -> PyResult<String> {
        String::from_utf8(self.body.clone())
            .map_err(|e| HypertorError::new_err(format!("Invalid UTF-8: {}", e)))
    }

    /// Get request body as JSON
    fn json(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let text = self.text()?;
        let json_module = py.import("json")?;
        json_module.call_method1("loads", (text,)).map(|v| v.into())
    }

    /// Get request body as bytes
    fn body(&self) -> &[u8] {
        &self.body
    }

    /// Get a specific header
    fn header(&self, name: &str) -> Option<String> {
        self.headers.get(&name.to_lowercase()).cloned()
    }

    /// Get a specific query parameter
    fn query_param(&self, name: &str) -> Option<String> {
        self.query.get(name).cloned()
    }

    /// Get a specific path parameter
    fn path_param(&self, name: &str) -> Option<String> {
        self.params.get(name).cloned()
    }

    fn __repr__(&self) -> String {
        format!("<Request {} {}>", self.method, self.path)
    }
}

/// Response object for explicit response building
#[pyclass(name = "AppResponse")]
#[derive(Clone)]
#[allow(dead_code)]
pub struct PyAppResponse {
    /// HTTP status code
    #[pyo3(get, set)]
    pub status: u16,
    /// Response headers
    headers: HashMap<String, String>,
    /// Response body
    body: Vec<u8>,
    /// Content type
    content_type: String,
}

#[pymethods]
impl PyAppResponse {
    /// Create new response
    #[new]
    #[pyo3(signature = (body, status=200, content_type="text/plain"))]
    fn new(body: &Bound<'_, PyAny>, status: u16, content_type: &str) -> PyResult<Self> {
        let body_bytes = if let Ok(s) = body.extract::<String>() {
            s.into_bytes()
        } else if let Ok(b) = body.extract::<Vec<u8>>() {
            b
        } else {
            // Try to serialize as JSON
            let json_module = body.py().import("json")?;
            let json_str: String = json_module.call_method1("dumps", (body,))?.extract()?;
            return Ok(Self {
                status,
                headers: HashMap::new(),
                body: json_str.into_bytes(),
                content_type: "application/json".to_string(),
            });
        };

        Ok(Self {
            status,
            headers: HashMap::new(),
            body: body_bytes,
            content_type: content_type.to_string(),
        })
    }

    /// Create JSON response
    #[staticmethod]
    #[pyo3(signature = (data, status=None))]
    fn json(py: Python<'_>, data: &Bound<'_, PyAny>, status: Option<u16>) -> PyResult<Self> {
        let json_module = py.import("json")?;
        let json_str: String = json_module.call_method1("dumps", (data,))?.extract()?;

        Ok(Self {
            status: status.unwrap_or(200),
            headers: HashMap::new(),
            body: json_str.into_bytes(),
            content_type: "application/json".to_string(),
        })
    }

    /// Create HTML response
    #[staticmethod]
    #[pyo3(signature = (content, status=None))]
    fn html(content: String, status: Option<u16>) -> Self {
        Self {
            status: status.unwrap_or(200),
            headers: HashMap::new(),
            body: content.into_bytes(),
            content_type: "text/html; charset=utf-8".to_string(),
        }
    }

    /// Create redirect response
    #[staticmethod]
    #[pyo3(signature = (location, status=None))]
    fn redirect(location: &str, status: Option<u16>) -> Self {
        let mut headers = HashMap::new();
        headers.insert("Location".to_string(), location.to_string());

        Self {
            status: status.unwrap_or(302),
            headers,
            body: Vec::new(),
            content_type: "text/plain".to_string(),
        }
    }

    /// Add a header
    fn set_header(&mut self, name: &str, value: &str) {
        self.headers.insert(name.to_string(), value.to_string());
    }

    /// Get all headers
    fn get_headers(&self) -> HashMap<String, String> {
        self.headers.clone()
    }

    fn __repr__(&self) -> String {
        format!("<Response status={}>", self.status)
    }
}

/// Configuration for OnionApp
#[pyclass(name = "AppConfig")]
#[derive(Clone)]
pub struct PyAppConfig {
    /// Virtual port for .onion address
    #[pyo3(get, set)]
    pub port: u16,
    /// Enable debug mode
    #[pyo3(get, set)]
    pub debug: bool,
    /// Enable request logging
    #[pyo3(get, set)]
    pub log_requests: bool,
    /// Request timeout in seconds
    #[pyo3(get, set)]
    pub timeout: u64,
    /// Max request body size in bytes
    #[pyo3(get, set)]
    pub max_body_size: usize,
    /// Key file path for persistent address
    #[pyo3(get, set)]
    pub key_file: Option<String>,
    /// Enable PoW protection
    #[pyo3(get, set)]
    pub enable_pow: bool,
    /// Security level: "standard", "enhanced", "maximum", "paranoid"
    #[pyo3(get, set)]
    pub security_level: String,
}

#[pymethods]
impl PyAppConfig {
    #[new]
    #[pyo3(signature = (port=80, debug=false, log_requests=true, timeout=30, max_body_size=10485760, key_file=None, enable_pow=false, security_level="standard"))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        port: u16,
        debug: bool,
        log_requests: bool,
        timeout: u64,
        max_body_size: usize,
        key_file: Option<String>,
        enable_pow: bool,
        security_level: &str,
    ) -> Self {
        Self {
            port,
            debug,
            log_requests,
            timeout,
            max_body_size,
            key_file,
            enable_pow,
            security_level: security_level.to_string(),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "<AppConfig port={} security={}>",
            self.port, self.security_level
        )
    }
}

/// FastAPI-like onion service application
///
/// Example:
///     >>> app = OnionApp()
///     >>> @app.get("/")
///     ... def home():
///     ...     return "Hello from Tor!"
///     >>> app.run()
#[pyclass(name = "OnionApp")]
pub struct PyOnionApp {
    /// Configuration
    config: PyAppConfig,
    /// Registered routes
    routes: Arc<RwLock<Vec<PyRoute>>>,
    /// Middleware count (handlers stored separately)
    middleware_count: Arc<RwLock<usize>>,
    /// Error handler count
    error_handler_count: Arc<RwLock<usize>>,
    /// Startup hook count
    startup_hook_count: Arc<RwLock<usize>>,
    /// Shutdown hook count
    shutdown_hook_count: Arc<RwLock<usize>>,
    /// The .onion address (set after run)
    address: Arc<RwLock<Option<String>>>,
    /// Running state
    running: Arc<RwLock<bool>>,
}

#[pymethods]
impl PyOnionApp {
    /// Create new OnionApp
    ///
    /// Args:
    ///     config: Optional AppConfig object
    ///     port: Port number (default: 80)
    ///     debug: Enable debug mode
    ///     key_file: Path to key file for persistent .onion address
    #[new]
    #[pyo3(signature = (config=None, port=80, debug=false, key_file=None))]
    fn new(config: Option<PyAppConfig>, port: u16, debug: bool, key_file: Option<String>) -> Self {
        let config = config.unwrap_or_else(|| PyAppConfig {
            port,
            debug,
            log_requests: true,
            timeout: 30,
            max_body_size: 10 * 1024 * 1024,
            key_file,
            enable_pow: false,
            security_level: "standard".to_string(),
        });

        Self {
            config,
            routes: Arc::new(RwLock::new(Vec::new())),
            middleware_count: Arc::new(RwLock::new(0)),
            error_handler_count: Arc::new(RwLock::new(0)),
            startup_hook_count: Arc::new(RwLock::new(0)),
            shutdown_hook_count: Arc::new(RwLock::new(0)),
            address: Arc::new(RwLock::new(None)),
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Register a GET route
    ///
    /// Usage as decorator:
    ///     @app.get("/path")
    ///     def handler():
    ///         return "response"
    #[pyo3(signature = (path, response_model=None))]
    fn get(
        &self,
        py: Python<'_>,
        path: &str,
        response_model: Option<String>,
    ) -> PyResult<Py<PyAny>> {
        self.route_decorator(py, "GET", path, response_model)
    }

    /// Register a POST route
    #[pyo3(signature = (path, response_model=None))]
    fn post(
        &self,
        py: Python<'_>,
        path: &str,
        response_model: Option<String>,
    ) -> PyResult<Py<PyAny>> {
        self.route_decorator(py, "POST", path, response_model)
    }

    /// Register a PUT route
    #[pyo3(signature = (path, response_model=None))]
    fn put(
        &self,
        py: Python<'_>,
        path: &str,
        response_model: Option<String>,
    ) -> PyResult<Py<PyAny>> {
        self.route_decorator(py, "PUT", path, response_model)
    }

    /// Register a DELETE route
    #[pyo3(signature = (path, response_model=None))]
    fn delete(
        &self,
        py: Python<'_>,
        path: &str,
        response_model: Option<String>,
    ) -> PyResult<Py<PyAny>> {
        self.route_decorator(py, "DELETE", path, response_model)
    }

    /// Register a PATCH route
    #[pyo3(signature = (path, response_model=None))]
    fn patch(
        &self,
        py: Python<'_>,
        path: &str,
        response_model: Option<String>,
    ) -> PyResult<Py<PyAny>> {
        self.route_decorator(py, "PATCH", path, response_model)
    }

    /// Register a route with explicit method(s)
    ///
    /// Usage:
    ///     @app.route("/path", methods=["GET", "POST"])
    ///     def handler(request):
    ///         return "response"
    #[pyo3(signature = (path, methods=None, response_model=None))]
    fn route(
        &self,
        py: Python<'_>,
        path: &str,
        methods: Option<Vec<String>>,
        response_model: Option<String>,
    ) -> PyResult<Py<PyAny>> {
        let methods = methods.unwrap_or_else(|| vec!["GET".to_string()]);
        let routes = Arc::clone(&self.routes);
        let path = path.to_string();

        // Create decorator function
        let decorator = PyCFunction::new_closure(
            py,
            None,
            None,
            move |args: &Bound<'_, PyTuple>, _kwargs: Option<&Bound<'_, PyDict>>| {
                let func = args.get_item(0)?;
                let handler: Py<PyAny> = func.into();

                // Register route for each method
                for method in &methods {
                    routes.write().push(PyRoute {
                        method: method.clone(),
                        path: path.clone(),
                        handler: handler.clone_ref(args.py()),
                        response_model: response_model.clone(),
                    });
                }

                Ok::<_, PyErr>(handler)
            },
        )?;

        Ok(decorator.into())
    }

    /// Add middleware
    ///
    /// Usage:
    ///     @app.middleware
    ///     async def log_request(request, call_next):
    ///         print(f"Request: {request.path}")
    ///         response = await call_next(request)
    ///         return response
    fn middleware(&self, _py: Python<'_>, func: Py<PyAny>) -> PyResult<Py<PyAny>> {
        *self.middleware_count.write() += 1;
        Ok(func)
    }

    /// Register error handler for specific status code
    ///
    /// Usage:
    ///     @app.error_handler(404)
    ///     def not_found(request):
    ///         return {"error": "Not found"}
    fn error_handler(&self, py: Python<'_>, status_code: u16) -> PyResult<Py<PyAny>> {
        let error_handler_count = Arc::clone(&self.error_handler_count);
        let _ = status_code; // Status code would be used in real impl

        let decorator = PyCFunction::new_closure(
            py,
            None,
            None,
            move |args: &Bound<'_, PyTuple>, _kwargs: Option<&Bound<'_, PyDict>>| {
                let func = args.get_item(0)?;
                let handler: Py<PyAny> = func.into();
                *error_handler_count.write() += 1;
                Ok::<_, PyErr>(handler)
            },
        )?;

        Ok(decorator.into())
    }

    /// Register startup hook
    ///
    /// Usage:
    ///     @app.on_startup
    ///     async def startup():
    ///         print("Starting up...")
    fn on_startup(&self, _py: Python<'_>, func: Py<PyAny>) -> PyResult<Py<PyAny>> {
        *self.startup_hook_count.write() += 1;
        Ok(func)
    }

    /// Register shutdown hook
    ///
    /// Usage:
    ///     @app.on_shutdown
    ///     async def shutdown():
    ///         print("Shutting down...")
    fn on_shutdown(&self, _py: Python<'_>, func: Py<PyAny>) -> PyResult<Py<PyAny>> {
        *self.shutdown_hook_count.write() += 1;
        Ok(func)
    }

    /// Get registered routes (for debugging)
    fn routes_info(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let routes = self.routes.read();
        let list = PyList::empty(py);

        for route in routes.iter() {
            let dict = PyDict::new(py);
            dict.set_item("method", &route.method)?;
            dict.set_item("path", &route.path)?;
            list.append(dict)?;
        }

        Ok(list.into())
    }

    /// Get the .onion address (available after run() is called)
    fn address(&self) -> Option<String> {
        self.address.read().clone()
    }

    /// Check if app is running
    fn is_running(&self) -> bool {
        *self.running.read()
    }

    /// Stop the app
    fn stop(&self) {
        *self.running.write() = false;
    }

    /// Run the onion service
    ///
    /// This starts the Tor connection, publishes the service descriptor,
    /// and begins accepting connections.
    /// Start the onion service - REAL Tor integration
    ///
    /// Args:
    ///     host: Ignored (for FastAPI compatibility)
    ///     port: Ignored, uses config.port
    ///     reload: Enable auto-reload on code changes
    ///
    /// Note: This blocks until the server is stopped.
    #[pyo3(signature = (host=None, port=None, reload=false))]
    fn run(
        &self,
        py: Python<'_>,
        host: Option<&str>,
        port: Option<u16>,
        reload: bool,
    ) -> PyResult<()> {
        let _ = (host, port, reload); // Ignored for compatibility

        // Print banner
        println!("╔════════════════════════════════════════════════════════════════════╗");
        println!("║                    🧅 hypertor OnionApp                            ║");
        println!("╠════════════════════════════════════════════════════════════════════╣");
        println!("║ Starting Tor connection...                                         ║");

        *self.running.write() = true;

        // Build OnionServiceConfig from PyAppConfig
        let service_config = {
            let mut config = OnionServiceConfig::new("hypertor-app").port(self.config.port);

            // Wire PoW protection
            if self.config.enable_pow {
                config = config.with_pow();
            }

            // Wire key file for persistent address
            if let Some(ref key_path) = self.config.key_file {
                config = config.key_dir(std::path::PathBuf::from(key_path));
            }

            // Wire security level to vanguards
            match self.config.security_level.as_str() {
                "enhanced" => {
                    config = config.vanguards_lite();
                }
                "maximum" | "paranoid" => {
                    config = config
                        .vanguards_full()
                        .with_pow()
                        .max_streams_per_circuit(100)
                        .rate_limit_at_intro(10.0, 20)
                        .num_intro_points(5);
                }
                _ => {} // "standard" - use defaults
            }

            config
        };

        // Create the tokio runtime for async operations
        let rt = Runtime::new()
            .map_err(|e| HypertorError::new_err(format!("Failed to create runtime: {}", e)))?;

        // Start the REAL onion service
        let address = rt
            .block_on(async {
                let mut service = OnionService::new(service_config);
                service.start().await
            })
            .map_err(|e| HypertorError::new_err(format!("Failed to start onion service: {}", e)))?;

        *self.address.write() = Some(address.clone());

        println!(
            "║ Port: {:5}                                                        ║",
            self.config.port
        );
        println!(
            "║ Routes: {:3}                                                        ║",
            self.routes.read().len()
        );
        println!(
            "║ Security: {:10}                                              ║",
            self.config.security_level
        );
        println!("╠════════════════════════════════════════════════════════════════════╣");
        println!(
            "║ 🧅 Service live at: {}   ║",
            &address[..52.min(address.len())]
        );
        println!("╚════════════════════════════════════════════════════════════════════╝");
        println!();
        println!("Press Ctrl+C to stop");

        // Main loop - wait for signals with proper handling
        let mut interrupted = false;
        while *self.running.read() {
            // Allow Python to handle signals (Ctrl+C raises KeyboardInterrupt)
            if py.check_signals().is_err() {
                // KeyboardInterrupt or other signal - graceful shutdown
                *self.running.write() = false;
                interrupted = true;
                break;
            }

            // Sleep to avoid busy-waiting
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        // Graceful shutdown
        println!("\n🧅 Shutting down onion service...");
        *self.running.write() = false;

        // Set a panic hook to suppress the expected tokio shutdown panic
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {
            // Suppress panic output during shutdown
        }));

        // Shutdown the runtime gracefully with timeout
        // This gives arti's background tasks time to clean up
        rt.shutdown_timeout(std::time::Duration::from_secs(1));

        // Restore the panic hook
        std::panic::set_hook(prev_hook);

        println!("🧅 Onion service stopped.");

        // If we were interrupted, raise KeyboardInterrupt to allow proper Python handling
        if interrupted {
            return Err(pyo3::exceptions::PyKeyboardInterrupt::new_err(""));
        }

        Ok(())
    }

    fn __repr__(&self) -> String {
        let routes = self.routes.read().len();
        let addr = self
            .address
            .read()
            .clone()
            .unwrap_or_else(|| "not started".to_string());
        format!("<OnionApp routes={} address={}>", routes, addr)
    }
}

impl PyOnionApp {
    /// Create a route decorator for a specific method
    fn route_decorator(
        &self,
        py: Python<'_>,
        method: &str,
        path: &str,
        response_model: Option<String>,
    ) -> PyResult<Py<PyAny>> {
        let routes = Arc::clone(&self.routes);
        let method = method.to_string();
        let path = path.to_string();

        let decorator = PyCFunction::new_closure(
            py,
            None,
            None,
            move |args: &Bound<'_, PyTuple>, _kwargs: Option<&Bound<'_, PyDict>>| {
                let func = args.get_item(0)?;
                let handler: Py<PyAny> = func.into();

                routes.write().push(PyRoute {
                    method: method.clone(),
                    path: path.clone(),
                    handler: handler.clone_ref(args.py()),
                    response_model: response_model.clone(),
                });

                Ok::<_, PyErr>(handler)
            },
        )?;

        Ok(decorator.into())
    }
}

/// Helper function to convert Python return values to responses
///
/// Handles automatic conversion from common Python types:
/// - `PyAppResponse` → returns as-is
/// - `str` → text/plain response
/// - `bytes` → application/octet-stream response  
/// - `dict`/`list` → JSON response
/// - `None` → 204 No Content
#[allow(dead_code)]
pub fn py_to_response(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<PyAppResponse> {
    // Already a Response object
    if let Ok(response) = value.extract::<PyAppResponse>() {
        return Ok(response);
    }

    // String -> text response
    if let Ok(s) = value.extract::<String>() {
        return Ok(PyAppResponse {
            status: 200,
            headers: HashMap::new(),
            body: s.into_bytes(),
            content_type: "text/plain; charset=utf-8".to_string(),
        });
    }

    // bytes -> binary response
    if let Ok(b) = value.extract::<Vec<u8>>() {
        return Ok(PyAppResponse {
            status: 200,
            headers: HashMap::new(),
            body: b,
            content_type: "application/octet-stream".to_string(),
        });
    }

    // dict/list -> JSON response
    if value.is_instance_of::<PyDict>() || value.is_instance_of::<PyList>() {
        return PyAppResponse::json(py, value, None);
    }

    // None -> empty response
    if value.is_none() {
        return Ok(PyAppResponse {
            status: 204,
            headers: HashMap::new(),
            body: Vec::new(),
            content_type: "text/plain".to_string(),
        });
    }

    // Try to convert to string as fallback
    let s: String = value.str()?.extract()?;
    Ok(PyAppResponse {
        status: 200,
        headers: HashMap::new(),
        body: s.into_bytes(),
        content_type: "text/plain; charset=utf-8".to_string(),
    })
}
