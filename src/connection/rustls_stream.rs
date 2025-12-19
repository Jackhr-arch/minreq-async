//! TLS connection handling functionality when using the `rustls` crate for
//! handling TLS.

#[cfg(feature = "https-rustls-probe")]
use rustls_platform_verifier::BuilderVerifierExt;
use std::convert::TryFrom;
use std::io;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::rustls::{self, pki_types::ServerName, ClientConfig};
use tokio_rustls::{client::TlsStream, TlsConnector};
#[cfg(feature = "https-rustls")]
use webpki_roots::TLS_SERVER_ROOTS;

#[cfg(all(feature = "https-rustls-probe", feature = "https-rustls"))]
compile_error!("currently, there is not way to get them work at same time");

use crate::Error;

use super::{Connection, HttpStream};

pub type SecuredStream = TlsStream<TcpStream>;

static CONFIG: std::sync::LazyLock<Result<Arc<ClientConfig>, rustls::Error>> =
    std::sync::LazyLock::new(|| {
        #[cfg(feature = "https-rustls-probe")]
        let builder = ClientConfig::builder().with_platform_verifier()?;
        #[cfg(feature = "https-rustls")]
        let builder = ClientConfig::builder().with_root_certificates(rustls::RootCertStore {
            roots: TLS_SERVER_ROOTS.to_vec(),
        });
        Ok(Arc::new(builder.with_no_client_auth()))
    });

pub async fn create_secured_stream(conn: &Connection) -> Result<HttpStream, Error> {
    // Rustls setup
    #[cfg(feature = "tracing")]
    tracing::trace!("Setting up TLS parameters for {}.", conn.request.url.host);
    let dns_name: ServerName<'static> = match ServerName::try_from(conn.request.url.host.clone()) {
        Ok(result) => result,
        Err(err) => return Err(Error::IoError(io::Error::new(io::ErrorKind::Other, err))),
    };
    let connecter = TlsConnector::from(CONFIG.clone().map_err(Error::RustlsCreateConnection)?);

    // Connect
    #[cfg(feature = "tracing")]
    tracing::trace!("Establishing TCP connection to {}.", conn.request.url.host);
    let tcp = conn.connect().await?;

    // Send request
    #[cfg(feature = "tracing")]
    tracing::trace!("Establishing TLS session to {}.", conn.request.url.host);
    let mut tls = connecter.connect(dns_name, tcp).await?;
    #[cfg(feature = "tracing")]
    tracing::trace!("Writing HTTPS request to {}.", conn.request.url.host);
    tls.write_all(&conn.request.as_bytes()).await?;
    tls.flush().await?;

    Ok(HttpStream::create_secured(tls, conn.timeout_at))
}
