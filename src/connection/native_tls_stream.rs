//! TLS connection handling functionality when using the `native-tls` crate for
//! handling TLS.
use std::io::{self};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_native_tls::{native_tls, TlsConnector, TlsStream};

use crate::Error;

use super::{Connection, HttpStream};

pub type SecuredStream = TlsStream<TcpStream>;

pub async fn create_secured_stream(conn: &Connection) -> Result<HttpStream, Error> {
    // native-tls setup
    #[cfg(feature = "tracing")]
    tracing::trace!("Setting up TLS parameters for {}.", conn.request.url.host);
    let dns_name = &conn.request.url.host;
    let sess: TlsConnector = match native_tls::TlsConnector::new() {
        Ok(sess) => sess.into(),
        Err(err) => return Err(Error::IoError(io::Error::new(io::ErrorKind::Other, err))),
    };

    // Connect
    #[cfg(feature = "tracing")]
    tracing::trace!("Establishing TCP connection to {}.", conn.request.url.host);
    let tcp = conn.connect().await?;

    // Send request
    #[cfg(feature = "tracing")]
    tracing::trace!("Establishing TLS session to {}.", conn.request.url.host);
    let mut tls = match sess.connect(dns_name, tcp).await {
        Ok(tls) => tls,
        Err(err) => return Err(Error::IoError(io::Error::new(io::ErrorKind::Other, err))),
    };

    #[cfg(feature = "tracing")]
    tracing::trace!("Writing HTTPS request to {}.", conn.request.url.host);
    // let _ = tls.get_ref().set_write_timeout(conn.timeout()?);
    tls.write_all(&conn.request.as_bytes()).await?;

    Ok(HttpStream::create_secured(tls, conn.timeout_at))
}
