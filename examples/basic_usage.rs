use anyhow::Result;
use http_body_util::BodyExt;
use hypertor::Client;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new().await?;

    let mut resp = client
        .get("https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion")
        .await?;
    //let mut resp = client.get("http://example.com").await?;

    println!("status: {}", resp.status());
    println!("headers: {:#?}", resp.headers());

    while let Some(frame) = resp.body_mut().frame().await {
        let bytes = frame?.into_data().unwrap();
        println!("body: {}", std::str::from_utf8(&bytes)?);
    }

    Ok(())
}