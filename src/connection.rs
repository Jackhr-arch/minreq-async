use crate::request::ParsedRequest;
use crate::{Error, Method, ResponseLazy};
use std::env;
use std::future::Future;
use std::io;
use std::net::ToSocketAddrs;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpStream;

type UnsecuredStream = TcpStream;

#[cfg(feature = "tokio-rustls")]
mod rustls_stream;
#[cfg(feature = "tokio-rustls")]
type SecuredStream = rustls_stream::SecuredStream;

#[cfg(all(not(feature = "tokio-rustls"), feature = "https-native"))]
mod native_tls_stream;
#[cfg(all(not(feature = "tokio-rustls"), feature = "https-native"))]
type SecuredStream = native_tls_stream::SecuredStream;

#[cfg(all(
    not(feature = "tokio-rustls"),
    not(feature = "https-native"),
    feature = "openssl",
))]
mod openssl_stream;
#[cfg(all(
    not(feature = "tokio-rustls"),
    not(feature = "https-native"),
    feature = "openssl",
))]
type SecuredStream = openssl_stream::SecuredStream;

macro_rules! timeout_at {
    ($future:expr, $deadline:expr) => {
        async {
            if let Some(deadline) = $deadline {
                tokio::time::timeout_at(deadline.into(), $future)
                    .await
                    .map_err(|_| timeout_err().into())
                    .flatten()
            } else {
                $future.await
            }
        }
    };
}

pub(crate) enum HttpStream {
    Unsecured(UnsecuredStream, Option<Instant>),
    #[cfg(any(feature = "tokio-rustls", feature = "https-native", feature = "openssl",))]
    Secured(Box<SecuredStream>, Option<Instant>),
}

impl HttpStream {
    fn create_unsecured(stream: UnsecuredStream, timeout_at: Option<Instant>) -> HttpStream {
        HttpStream::Unsecured(stream, timeout_at)
    }

    #[cfg(any(feature = "tokio-rustls", feature = "https-native", feature = "openssl"))]
    fn create_secured(stream: SecuredStream, timeout_at: Option<Instant>) -> HttpStream {
        HttpStream::Secured(Box::new(stream), timeout_at)
    }
}

fn timeout_err() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "the timeout of the request was reached",
    )
}

impl AsyncRead for HttpStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            HttpStream::Unsecured(ref mut stream, timeout_at) => {
                let fut = timeout_at!(stream.read_buf(buf), *timeout_at);
                std::pin::pin!(fut).poll(cx).map_ok(|_| ())
            }
            #[cfg(any(feature = "tokio-rustls", feature = "https-native", feature = "openssl",))]
            HttpStream::Secured(ref mut stream, timeout_at) => {
                let fut = timeout_at!(stream.read_buf(buf), *timeout_at);
                std::pin::pin!(fut).poll(cx).map_ok(|_| ())
            }
        }
    }
}

/// A connection to the server for sending
/// [`Request`](struct.Request.html)s.
pub struct Connection {
    request: ParsedRequest,
    timeout_at: Option<Instant>,
}

impl Connection {
    /// Creates a new `Connection`. See [Request] and [ParsedRequest]
    /// for specifics about *what* is being sent.
    pub(crate) fn new(request: ParsedRequest) -> Connection {
        let timeout = request
            .config
            .timeout
            .or_else(|| match env::var("MINREQ_TIMEOUT") {
                Ok(t) => t.parse::<u64>().ok(),
                Err(_) => None,
            });
        let timeout_at = timeout.map(|t| Instant::now() + Duration::from_secs(t));
        Connection {
            request,
            timeout_at,
        }
    }

    /// Sends the [`Request`](struct.Request.html), consumes this
    /// connection, and returns a [`Response`](struct.Response.html).
    #[cfg(any(feature = "tokio-rustls", feature = "https-native", feature = "openssl",))]
    pub(crate) async fn send_https(mut self) -> Result<ResponseLazy, Error> {
        let timeout_at = self.timeout_at;
        let fut = async {
            self.request.url.host = ensure_ascii_host(self.request.url.host)?;

            #[cfg(feature = "tokio-rustls")]
            let secured_stream = rustls_stream::create_secured_stream(&self).await?;
            #[cfg(all(not(feature = "tokio-rustls"), feature = "https-native"))]
            let secured_stream = native_tls_stream::create_secured_stream(&self).await?;
            #[cfg(all(
                not(feature = "tokio-rustls"),
                not(feature = "https-native"),
                feature = "openssl",
            ))]
            let secured_stream = openssl_stream::create_secured_stream(&self).await?;

            #[cfg(feature = "tracing")]
            tracing::trace!("Reading HTTPS response from {}.", self.request.url.host);
            let response = ResponseLazy::from_stream(
                secured_stream,
                self.request.config.max_headers_size,
                self.request.config.max_status_line_len,
            )
            .await?;

            handle_redirects(self, response).await
        };
        timeout_at!(fut, timeout_at).await
    }

    /// Sends the [`Request`](struct.Request.html), consumes this
    /// connection, and returns a [`Response`](struct.Response.html).
    pub(crate) async fn send(mut self) -> Result<ResponseLazy, Error> {
        let timeout_at = self.timeout_at;
        let fut = async {
            self.request.url.host = ensure_ascii_host(self.request.url.host)?;
            let bytes = self.request.as_bytes();

            #[cfg(feature = "tracing")]
            tracing::trace!("Establishing TCP connection to {}.", self.request.url.host);
            let mut tcp = self.connect().await?;

            // Send request
            #[cfg(feature = "tracing")]
            tracing::trace!("Writing HTTP request.");
            use tokio::io::AsyncWriteExt;
            tcp.write_all(&bytes).await?;

            // Receive response
            #[cfg(feature = "tracing")]
            tracing::trace!("Reading HTTP response.");
            let stream = HttpStream::create_unsecured(tcp, self.timeout_at);
            let response = ResponseLazy::from_stream(
                stream,
                self.request.config.max_headers_size,
                self.request.config.max_status_line_len,
            )
            .await?;
            handle_redirects(self, response).await
        };
        timeout_at!(fut, timeout_at).await
    }

    async fn connect(&self) -> Result<TcpStream, Error> {
        let tcp_connect = async |host: &str, port: u32| -> Result<TcpStream, Error> {
            let addrs = (host, port as u16)
                .to_socket_addrs()
                .map_err(Error::IoError)?;
            let addrs_count = addrs.len();

            // Try all resolved addresses. Return the first one to which we could connect. If all
            // failed return the last error encountered.
            for (i, addr) in addrs.enumerate() {
                let stream = TcpStream::connect(addr).await;
                if stream.is_ok() || i == addrs_count - 1 {
                    return stream.map_err(Error::from);
                }
            }

            Err(Error::AddressNotFound)
        };

        #[cfg(feature = "proxy")]
        match self.request.config.proxy {
            Some(ref proxy) => {
                // do proxy things
                let mut tcp = tcp_connect(&proxy.server, proxy.port)?;

                write!(tcp, "{}", proxy.connect(&self.request)).unwrap();
                tcp.flush()?;

                let mut proxy_response = Vec::new();

                loop {
                    let mut buf = vec![0; 256];
                    let total = tcp.read(&mut buf)?;
                    proxy_response.append(&mut buf);
                    if total < 256 {
                        break;
                    }
                }

                crate::Proxy::verify_response(&proxy_response)?;

                Ok(tcp)
            }
            None => tcp_connect(&self.request.url.host, self.request.url.port.port()),
        }

        #[cfg(not(feature = "proxy"))]
        tcp_connect(&self.request.url.host, self.request.url.port.port()).await
    }
}

async fn handle_redirects(
    connection: Connection,
    mut response: ResponseLazy,
) -> Result<ResponseLazy, Error> {
    let status_code = response.status_code;
    let url = response.headers.get("location");
    match get_redirect(connection, status_code, url) {
        NextHop::Redirect(connection) => {
            let connection = connection?;
            if connection.request.url.https {
                #[cfg(not(any(
                    feature = "tokio-rustls",
                    feature = "openssl",
                    feature = "https-native"
                )))]
                return Err(Error::HttpsFeatureNotEnabled);
                #[cfg(any(feature = "tokio-rustls", feature = "openssl", feature = "https-native"))]
                return Box::pin(connection.send_https()).await;
            } else {
                Box::pin(connection.send()).await
            }
        }
        NextHop::Destination(connection) => {
            let dst_url = connection.request.url;
            dst_url.write_base_url_to(&mut response.url).unwrap();
            dst_url.write_resource_to(&mut response.url).unwrap();
            Ok(response)
        }
    }
}

enum NextHop {
    Redirect(Result<Connection, Error>),
    Destination(Connection),
}

fn get_redirect(mut connection: Connection, status_code: i32, url: Option<&String>) -> NextHop {
    match status_code {
        301 | 302 | 303 | 307 if connection.request.config.follow_redirects => {
            let url = match url {
                Some(url) => url,
                None => return NextHop::Redirect(Err(Error::RedirectLocationMissing)),
            };

            #[cfg(feature = "tracing")]
            tracing::debug!("Redirecting ({}) to: {}", status_code, url);

            match connection.request.redirect_to(url.as_str()) {
                Ok(()) => {
                    if status_code == 303 {
                        match connection.request.config.method {
                            Method::Post | Method::Put | Method::Delete => {
                                connection.request.config.method = Method::Get;
                            }
                            _ => {}
                        }
                    }

                    NextHop::Redirect(Ok(connection))
                }
                Err(err) => NextHop::Redirect(Err(err)),
            }
        }
        _ => NextHop::Destination(connection),
    }
}

fn ensure_ascii_host(host: String) -> Result<String, Error> {
    if host.is_ascii() {
        Ok(host)
    } else {
        #[cfg(not(feature = "punycode"))]
        {
            Err(Error::PunycodeFeatureNotEnabled)
        }

        #[cfg(feature = "punycode")]
        {
            let mut result = String::with_capacity(host.len() * 2);
            for s in host.split('.') {
                if s.is_ascii() {
                    result += s;
                } else {
                    match punycode::encode(s) {
                        Ok(s) => result = result + "xn--" + &s,
                        Err(_) => return Err(Error::PunycodeConversionFailed),
                    }
                }
                result += ".";
            }
            result.truncate(result.len() - 1); // Remove the trailing dot
            Ok(result)
        }
    }
}
