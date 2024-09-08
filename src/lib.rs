use anyhow::Result;
use arti_client::{TorClient, TorClientConfig};
use http_body_util::{Empty, Full};
use hyper::body::Bytes;
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::http::uri::Scheme;
use hyper::{Request, Response, Uri};
use hyper_util::rt::TokioIo;
use std::io::Error as IoError;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_native_tls::native_tls::TlsConnector;
use tor_rtcompat::PreferredRuntime;

/// A trait for types that implement both `AsyncRead` and `AsyncWrite`.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite {}

/// Configuration for the `Client`.
pub struct ClientConfig {
    /// TLS configuration for HTTPS connections.
    pub tls_config: TlsConnector,
    /// Tor client configuration for routing through the Tor network.
    pub tor_config: TorClientConfig,
}

/// Builder for creating a `ClientConfig`.
pub struct ClientConfigBuilder {
    tls_config: Option<TlsConnector>,
    tor_config: Option<TorClientConfig>,
}

impl ClientConfigBuilder {
    /// Creates a new `ClientConfigBuilder`.
    pub fn new() -> Self {
        ClientConfigBuilder {
            tls_config: None,
            tor_config: None,
        }
    }

    /// Sets the TLS configuration for the `ClientConfigBuilder`.
    pub fn tls_config(mut self, tls_config: TlsConnector) -> Self {
        self.tls_config = Some(tls_config);
        self
    }

    /// Sets the Tor configuration for the `ClientConfigBuilder`.
    pub fn tor_config(mut self, tor_config: TorClientConfig) -> Self {
        self.tor_config = Some(tor_config);
        self
    }

    /// Builds the `ClientConfig` from the `ClientConfigBuilder`.
    pub fn build(self) -> Result<ClientConfig> {
        Ok(ClientConfig {
            tls_config: self.tls_config.unwrap_or_else(|| {
                TlsConnector::builder()
                    .build()
                    .expect("Failed to create default TlsConnector")
            }),
            tor_config: self.tor_config.unwrap_or_else(|| {
                let mut cfg_builder = TorClientConfig::builder();
                cfg_builder.address_filter().allow_onion_addrs(true);
                cfg_builder
                    .build()
                    .expect("Failed to create default TorClientConfig")
            }),
        })
    }
}

/// A client for making HTTP requests over Tor with optional TLS.
pub struct Client {
    tor_client: TorClient<PreferredRuntime>,
    config: ClientConfig,
}

impl Client {
    /// Creates a new `Client` with the provided `ClientConfig`.
    pub async fn with_config(config: ClientConfig) -> Result<Self> {
        let tor_client = Self::create_tor_client(&config).await?;
        Ok(Client { tor_client, config })
    }

    /// Creates a new `Client` with default configuration.
    pub async fn new() -> Result<Self> {
        let default_config = ClientConfigBuilder::new().build()?;
        Self::with_config(default_config).await
    }

    /// Creates a Tor client using the given configuration.
    async fn create_tor_client(config: &ClientConfig) -> Result<TorClient<PreferredRuntime>> {
        let tor_client = TorClient::create_bootstrapped(config.tor_config.clone()).await?;
        Ok(tor_client)
    }

    /// Sends an HTTP HEAD request to the specified URI.
    pub async fn head<T>(&self, uri: T) -> Result<Response<Incoming>>
    where
        Uri: TryFrom<T>,
        <Uri as TryFrom<T>>::Error: Into<hyper::http::Error>,
    {
        let req = Request::head(uri).body(Empty::<Bytes>::new())?;

        let resp = self.send_request(req).await?;
        Ok(resp)
    }

    /// Sends an HTTP GET request to the specified URI.
    pub async fn get<T>(&self, uri: T) -> Result<Response<Incoming>>
    where
        Uri: TryFrom<T>,
        <Uri as TryFrom<T>>::Error: Into<hyper::http::Error>,
    {
        let req = Request::get(uri).body(Empty::<Bytes>::new())?;

        let resp = self.send_request(req).await?;
        Ok(resp)
    }

    /// Sends an HTTP POST request to the specified URI with the given content type and body.
    pub async fn post<T>(
        &self,
        uri: T,
        content_type: &str,
        body: Bytes,
    ) -> Result<Response<Incoming>>
    where
        Uri: TryFrom<T>,
        <Uri as TryFrom<T>>::Error: Into<hyper::http::Error>,
    {
        let req = Request::post(uri)
            .header(hyper::header::CONTENT_TYPE, content_type)
            .body(Full::<Bytes>::from(body))?;

        let resp = self.send_request(req).await?;
        Ok(resp)
    }

    /// Sends an HTTP request and returns the response.
    async fn send_request<B>(&self, req: Request<B>) -> Result<Response<Incoming>>
    where
        B: hyper::body::Body + Send + 'static, // B must implement Body and be sendable
        B::Data: Send,                         // B::Data must be sendable
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>, // B::Error must be convertible to a boxed error
    {
        let stream = self.create_stream(req.uri()).await?;

        let (mut request_sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;

        // Spawn a task to poll the connection and drive the HTTP state
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("Error: {e:?}");
            }
        });

        let mut final_req_builder = Request::builder().uri(req.uri()).method(req.method());

        for (key, value) in req.headers() {
            final_req_builder = final_req_builder.header(key, value);
        }

        if !req.headers().contains_key(hyper::header::HOST) {
            if let Some(authority) = req.uri().authority() {
                let host_header_value = HeaderValue::from_str(authority.as_str()).unwrap();
                final_req_builder =
                    final_req_builder.header(hyper::header::HOST, host_header_value);
            }
        }

        let final_req = final_req_builder.body(req.into_body())?;

        let resp = request_sender.send_request(final_req).await?;

        Ok(resp)
    }

    /// Creates a stream for the specified URI, optionally wrapping it with TLS.
    async fn create_stream(
        &self,
        url: &Uri,
    ) -> Result<Box<dyn AsyncReadWrite + Unpin + Send>, IoError> {
        let host = url
            .host()
            .ok_or_else(|| IoError::new(std::io::ErrorKind::InvalidInput, "Missing host"))?;
        let https = url.scheme() == Some(&Scheme::HTTPS);

        let port = match url.port_u16() {
            Some(port) => port,
            None if https => 443,
            None => 80,
        };

        // Establish the initial stream connection
        let stream = self
            .tor_client
            .connect((host, port))
            .await
            .map_err(|e| IoError::new(std::io::ErrorKind::Other, e))?;

        if https {
            // Wrap the stream with TLS
            let tls_connector = &self.config.tls_config;
            let cx = tokio_native_tls::TlsConnector::from(tls_connector.clone());
            let wrapped_stream = cx
                .connect(host, stream)
                .await
                .map_err(|e| IoError::new(std::io::ErrorKind::Other, e))?;
            Ok(Box::new(wrapped_stream) as Box<dyn AsyncReadWrite + Unpin + Send>)
        } else {
            // Return the unwrapped stream directly for HTTP
            Ok(Box::new(stream) as Box<dyn AsyncReadWrite + Unpin + Send>)
        }
    }
}
