# hypertor

`hypertor` is a Rust library that provides a client for making HTTP requests over the Tor network. It integrates with the Tor network and supports both HTTP and HTTPS protocols with configurable TLS support. Built on top of `hyper` and `arti_client`, it allows you to send GET, POST, and HEAD requests with custom configurations.

## Features

- **HTTP and HTTPS Support:** Send requests over both HTTP and HTTPS.
- **Tor Integration:** Connect through the Tor network.
- **Configurable TLS:** Customize TLS settings for secure connections.
- **Builder Pattern:** Easily configure clients with `ClientConfigBuilder`.

## Installation

Add `hypertor` to your `Cargo.toml`:

```toml
[dependencies]
hypertor = "0.1"  # Replace with the latest version
```

## Usage
Here's a basic example of how to use hypertor to create a client and make HTTP requests:

### Basic Example
```rust
use hypertor::Client;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Create a new client with default configuration
    let client = Client::new().await?;

    // Make a GET request
    let response = client.get("http://httpbin.org/get").await?;
    println!("GET response: {:?}", response);

    // Make a POST request with JSON body
    let body = hyper::body::Bytes::from(r#"{"key":"value"}"#);
    let response = client.post("http://httpbin.org/post", "application/json", body).await?;
    println!("POST response: {:?}", response);

    // Make a HEAD request
    let response = client.head("http://httpbin.org/get").await?;
    println!("HEAD response: {:?}", response);

    Ok(())
}
```

## Custom Configuration
You can also create a client with a custom configuration:
```rust
use hypertor::{Client, ClientConfig, ClientConfigBuilder};
use tokio_native_tls::native_tls::TlsConnector;
use arti_client::TorClientConfig;

#[tokio::main]
async fn main() -> Result<()> {
    // Create a custom TLS connector
    let tls_config = TlsConnector::builder().build()?;

    // Create a custom Tor client configuration
    let tor_config = TorClientConfig::builder()
        .address_filter()
        .allow_onion_addrs(true)
        .build()?;

    // Build client configuration
    let config = ClientConfigBuilder::new()
        .tls_config(tls_config)
        .tor_config(tor_config)
        .build()?;

    // Create a client with the custom configuration
    let client = Client::with_config(config).await?;

    // Use the client as shown in the basic example

    Ok(())
}
```
## Error Handling
hypertor uses anyhow::Result for error handling, which provides a flexible way to handle and propagate errors. For more details, refer to the anyhow documentation.

## Contributing
Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## License
This project is licensed under the MIT License. See the LICENSE file for details.