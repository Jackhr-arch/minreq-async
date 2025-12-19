use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt};

use crate::{connection::HttpStream, Error};
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::str;
use std::task::ready;
use tokio::io::BufReader;

/// An HTTP response.
///
/// Returned by [`Request::send`](struct.Request.html#method.send).
///
/// # Example
///
/// ```no_run
/// # #[tokio::main]
/// # async fn main() -> Result<(), minreq::Error> {
/// let response = minreq::get("http://example.com").send().await?;
/// println!("{}", response.as_str()?);
/// # Ok(()) }
/// ```
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Response {
    /// The status code of the response, eg. 404.
    pub status_code: i32,
    /// The reason phrase of the response, eg. "Not Found".
    pub reason_phrase: String,
    /// The headers of the response. The header field names (the
    /// keys) are all lowercase.
    pub headers: HashMap<String, String>,
    /// The URL of the resource returned in this response. May differ from the
    /// request URL if it was redirected or typo corrections were applied (e.g.
    /// <http://example.com?foo=bar> would be corrected to
    /// <http://example.com/?foo=bar>).
    pub url: String,

    body: Vec<u8>,
}

impl Response {
    pub(crate) async fn create(mut parent: ResponseLazy, is_head: bool) -> Result<Response, Error> {
        let mut body = Vec::new();
        if !is_head && parent.status_code != 204 && parent.status_code != 304 {
            parent.read_to_end(&mut body).await?;
        }

        let ResponseLazy {
            status_code,
            reason_phrase,
            headers,
            url,
            ..
        } = parent;

        Ok(Response {
            status_code,
            reason_phrase,
            headers,
            url,
            body,
        })
    }

    /// Returns the body as an `&str`.
    ///
    /// # Errors
    ///
    /// Returns
    /// [`InvalidUtf8InBody`](enum.Error.html#variant.InvalidUtf8InBody)
    /// if the body is not UTF-8, with a description as to why the
    /// provided slice is not UTF-8.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let url = "http://example.org/";
    /// let response = minreq::get(url).send().await?;
    /// println!("{}", response.as_str()?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn as_str(&self) -> Result<&str, Error> {
        match str::from_utf8(&self.body) {
            Ok(s) => Ok(s),
            Err(err) => Err(Error::InvalidUtf8InBody(err)),
        }
    }

    /// Returns a reference to the contained bytes of the body. If you
    /// want the `Vec<u8>` itself, use
    /// [`into_bytes()`](#method.into_bytes) instead.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let url = "http://example.org/";
    /// let response = minreq::get(url).send().await?;
    /// println!("{:?}", response.as_bytes());
    /// # Ok(())
    /// # }
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        &self.body
    }

    /// Turns the `Response` into the inner `Vec<u8>`, the bytes that
    /// make up the response's body. If you just need a `&[u8]`, use
    /// [`as_bytes()`](#method.as_bytes) instead.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let url = "http://example.org/";
    /// let response = minreq::get(url).send().await?;
    /// println!("{:?}", response.into_bytes());
    /// // This would error, as into_bytes consumes the Response:
    /// // let x = response.status_code;
    /// # Ok(())
    /// # }
    /// ```
    pub fn into_bytes(self) -> Vec<u8> {
        self.body
    }

    /// Converts JSON body to a `struct` using Serde.
    ///
    /// # Errors
    ///
    /// Returns
    /// [`SerdeJsonError`](enum.Error.html#variant.SerdeJsonError) if
    /// Serde runs into a problem, or
    /// [`InvalidUtf8InBody`](enum.Error.html#variant.InvalidUtf8InBody)
    /// if the body is not UTF-8.
    ///
    /// # Example
    /// In case compiler cannot figure out return type you might need to declare it explicitly:
    ///
    /// ```no_run
    /// use serde_json::Value;
    ///
    /// # fn main() -> Result<(), minreq::Error> {
    /// # let url_to_json_resource = "http://example.org/resource.json";
    /// // Value could be any type that implements Deserialize!
    /// let user = minreq::get(url_to_json_resource).send().await?.json::<Value>()?;
    /// println!("User name is '{}'", user["name"]);
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "json-using-serde")]
    pub fn json<'a, T>(&'a self) -> Result<T, Error>
    where
        T: serde::de::Deserialize<'a>,
    {
        let str = match self.as_str() {
            Ok(str) => str,
            Err(_) => return Err(Error::InvalidUtf8InResponse),
        };
        match serde_json::from_str(str) {
            Ok(json) => Ok(json),
            Err(err) => Err(Error::SerdeJsonError(err)),
        }
    }
}

/// An HTTP response, which is loaded lazily.
///
/// In comparison to [`Response`](struct.Response.html), this is
/// returned from
/// [`send_lazy()`](struct.Request.html#method.send_lazy), where as
/// [`Response`](struct.Response.html) is returned from
/// [`send()`](struct.Request.html#method.send).
///
/// In practice, "lazy loading" means that the bytes are only loaded
/// as you iterate through them. The bytes are provided in the form of
/// a `Result<(u8, usize), minreq::Error>`, as the reading operation
/// can fail in various ways. The `u8` is the actual byte that was
/// read, and `usize` is how many bytes we are expecting to read in
/// the future (including this byte). Note, however, that the `usize`
/// can change, particularly when the `Transfer-Encoding` is
/// `chunked`: then it will reflect how many bytes are left of the
/// current chunk. The expected size is capped at 16 KiB to avoid
/// server-side DoS attacks targeted at clients accidentally reserving
/// too much memory.
///
/// # Example
/// ```no_run
/// // This is how the normal Response works behind the scenes, and
/// // how you might use ResponseLazy.
/// # #[tokio::main]
/// # async fn main() -> Result<(), minreq::Error> {
/// use tokio::io::AsyncReadExt;
/// let mut response = minreq::get("http://example.com").send_lazy().await?;
/// let mut vec = Vec::new();
/// response.read_to_end(&mut vec).await?;
/// # Ok(())
/// # }
///
/// ```
pub struct ResponseLazy {
    /// The status code of the response, eg. 404.
    pub status_code: i32,
    /// The reason phrase of the response, eg. "Not Found".
    pub reason_phrase: String,
    /// The headers of the response. The header field names (the
    /// keys) are all lowercase.
    pub headers: HashMap<String, String>,
    /// The URL of the resource returned in this response. May differ from the
    /// request URL if it was redirected or typo corrections were applied (e.g.
    /// <http://example.com?foo=bar> would be corrected to
    /// <http://example.com/?foo=bar>).
    pub url: String,

    stream: HttpStreamBytes,
    state: HttpStreamState,
    max_trailing_headers_size: Option<usize>,
}

type HttpStreamBytes = BufReader<HttpStream>;

impl ResponseLazy {
    pub(crate) async fn from_stream(
        stream: HttpStream,
        max_headers_size: Option<usize>,
        max_status_line_len: Option<usize>,
    ) -> Result<ResponseLazy, Error> {
        let mut stream = BufReader::new(stream);
        let ResponseMetadata {
            status_code,
            reason_phrase,
            headers,
            state,
            max_trailing_headers_size,
        } = read_metadata(&mut stream, max_headers_size, max_status_line_len).await?;

        Ok(ResponseLazy {
            status_code,
            reason_phrase,
            headers,
            url: String::new(),
            stream,
            state,
            max_trailing_headers_size,
        })
    }
}

impl AsyncRead for ResponseLazy {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.state {
            HttpStreamState::EndOnClose => {
                let fut = this.stream.read_buf(buf);
                std::pin::pin!(fut).poll(cx).map_ok(|_| ())
            }
            HttpStreamState::ContentLength(ref mut content_length) => {
                if *content_length == 0 {
                    return std::task::Poll::Ready(Ok(()));
                }
                let to_go = buf.remaining().min(*content_length);
                let fut = this.stream.read_exact(buf.initialize_unfilled_to(to_go));
                let size = ready!(std::pin::pin!(fut).poll(cx))?;
                buf.set_filled(buf.filled().len() + size);
                *content_length -= size;
                std::task::Poll::Ready(Ok(()))
            }
            HttpStreamState::Chunked(
                ref mut expecting_more_chunks,
                ref mut chunk_length,
                ref mut content_length,
            ) => {
                let fut = read_chunked(
                    &mut this.stream,
                    &mut this.headers,
                    expecting_more_chunks,
                    chunk_length,
                    content_length,
                    this.max_trailing_headers_size,
                    buf,
                );
                std::pin::pin!(fut).poll(cx)
            }
        }
    }
}

async fn read_trailers(
    bytes: &mut HttpStreamBytes,
    headers: &mut HashMap<String, String>,
    mut max_headers_size: Option<usize>,
) -> Result<(), Option<std::io::Error>> {
    loop {
        let trailer_line = read_line(bytes, max_headers_size).await?;
        if let Some(ref mut max_headers_size) = max_headers_size {
            *max_headers_size -= trailer_line.len() + 2;
        }
        if let Some((header, value)) = parse_header(trailer_line) {
            headers.insert(header, value);
        } else {
            break;
        }
    }
    Ok(())
}

async fn read_chunked(
    stream: &mut HttpStreamBytes,
    headers: &mut HashMap<String, String>,
    expecting_more_chunks: &mut bool,
    current_chunk_length: &mut usize,
    content_length: &mut usize,
    max_trailing_headers_size: Option<usize>,
    buf: &mut tokio::io::ReadBuf<'_>,
) -> std::io::Result<()> {
    if !*expecting_more_chunks && *current_chunk_length == 0 {
        return Ok(());
    }

    if *current_chunk_length == 0 {
        // Max length of the chunk length line is 1KB: not too long to
        // take up much memory, long enough to tolerate some chunk
        // extensions (which are ignored).

        // Get the size of the next chunk
        let length_line = read_line(stream, Some(1024))
            .await
            .map_err(|e| e.unwrap_or(std::io::Error::other(Error::MalformedChunkLength)))?;

        // Note: the trim() and check for empty lines shouldn't be
        // needed according to the RFC, but we might as well, it's a
        // small change and it fixes a few servers.
        let incoming_length = if length_line.is_empty() {
            0
        } else {
            let length = if let Some(i) = length_line.find(';') {
                length_line[..i].trim()
            } else {
                length_line.trim()
            };
            usize::from_str_radix(length, 16)
                .map_err(|_| std::io::Error::other(Error::MalformedChunkLength))?
        };

        if incoming_length == 0 {
            read_trailers(stream, headers, max_trailing_headers_size)
                .await
                .map_err(|e| e.unwrap_or(std::io::Error::other(Error::HeadersOverflow)))?;

            *expecting_more_chunks = false;
            headers.insert("content-length".to_string(), (*content_length).to_string());
            headers.remove("transfer-encoding");
            return Ok(());
        }
        *current_chunk_length = incoming_length;
        *content_length += incoming_length;
    }

    assert!(*current_chunk_length > 0);

    let to_go = buf.remaining().min(*current_chunk_length);
    let fut = stream.read_exact(buf.initialize_unfilled_to(to_go));
    let size = fut.await?;
    buf.set_filled(buf.filled().len() + size);
    *current_chunk_length -= size;

    // If we're at the end of the chunk...
    if *current_chunk_length == 0 {
        //...read the trailing \r\n of the chunk, and
        // possibly return an error instead.

        // TODO: Maybe this could be written in a way
        // that doesn't discard the last ok byte if
        // the \r\n reading fails?
        read_line(stream, Some(2))
            .await
            .map_err(|e| e.unwrap_or(std::io::Error::other(Error::MalformedChunkLength)))?;
    }
    Ok(())
}

enum HttpStreamState {
    // No Content-Length, and Transfer-Encoding != chunked, so we just
    // read unti lthe server closes the connection (this should be the
    // fallback, if I read the rfc right).
    EndOnClose,
    // Content-Length was specified, read that amount of bytes
    ContentLength(usize),
    // Transfer-Encoding == chunked, so we need to save two pieces of
    // information: are we expecting more chunks, how much is there
    // left of the current chunk, and how much have we read? The last
    // number is needed in order to provide an accurate Content-Length
    // header after loading all the bytes.
    Chunked(bool, usize, usize),
}

// This struct is just used in the Response and ResponseLazy
// constructors, but not in their structs, for api-cleanliness
// reasons. (Eg. response.status_code is much cleaner than
// response.meta.status_code or similar.)
struct ResponseMetadata {
    status_code: i32,
    reason_phrase: String,
    headers: HashMap<String, String>,
    state: HttpStreamState,
    max_trailing_headers_size: Option<usize>,
}

async fn read_metadata(
    stream: &mut HttpStreamBytes,
    mut max_headers_size: Option<usize>,
    max_status_line_len: Option<usize>,
) -> Result<ResponseMetadata, Error> {
    let line = read_line(stream, max_status_line_len)
        .await
        .map_err(|e| e.map(Error::IoError).unwrap_or(Error::StatusLineOverflow))?;
    let (status_code, reason_phrase) = parse_status_line(&line);

    let mut headers = HashMap::new();
    loop {
        let line = read_line(stream, max_headers_size)
            .await
            .map_err(|e| e.map(Error::IoError).unwrap_or(Error::HeadersOverflow))?;
        if line.is_empty() {
            // Body starts here
            break;
        }
        if let Some(ref mut max_headers_size) = max_headers_size {
            *max_headers_size -= line.len() + 2;
        }
        if let Some(header) = parse_header(line) {
            headers.insert(header.0, header.1);
        }
    }

    let mut chunked = false;
    let mut content_length = None;
    for (header, value) in &headers {
        // Handle the Transfer-Encoding header
        if header.to_lowercase().trim() == "transfer-encoding"
            && value.to_lowercase().trim() == "chunked"
        {
            chunked = true;
        }

        // Handle the Content-Length header
        if header.to_lowercase().trim() == "content-length" {
            match str::parse::<usize>(value.trim()) {
                Ok(length) => content_length = Some(length),
                Err(_) => return Err(Error::MalformedContentLength),
            }
        }
    }

    let state = if chunked {
        HttpStreamState::Chunked(true, 0, 0)
    } else if let Some(length) = content_length {
        HttpStreamState::ContentLength(length)
    } else {
        HttpStreamState::EndOnClose
    };

    Ok(ResponseMetadata {
        status_code,
        reason_phrase,
        headers,
        state,
        max_trailing_headers_size: max_headers_size,
    })
}

async fn read_line(
    stream: &mut HttpStreamBytes,
    max_len: Option<usize>,
) -> Result<String, Option<std::io::Error>> {
    let mut buf = String::new();
    let size = stream.read_line(&mut buf).await?;
    if max_len.is_some_and(|max| size > max) {
        return Err(None);
    }
    Ok(buf.trim_end_matches("\r\n").to_string())
}

fn parse_status_line(line: &str) -> (i32, String) {
    // sample status line format
    // HTTP/1.1 200 OK
    let mut status_code = String::with_capacity(3);
    let mut reason_phrase = String::with_capacity(2);

    let mut spaces = 0;

    for c in line.chars() {
        if spaces >= 2 {
            reason_phrase.push(c);
        }

        if c == ' ' {
            spaces += 1;
        } else if spaces == 1 {
            status_code.push(c);
        }
    }

    if let Ok(status_code) = status_code.parse::<i32>() {
        return (status_code, reason_phrase);
    }

    (503, "Server did not provide a status line".to_string())
}

fn parse_header(mut line: String) -> Option<(String, String)> {
    if let Some(location) = line.find(':') {
        // Trim the first character of the header if it is a space,
        // otherwise return everything after the ':'. This should
        // preserve the behavior in versions <=2.0.1 in most cases
        // (namely, ones where it was valid), where the first
        // character after ':' was always cut off.
        let value = if let Some(sp) = line.get(location + 1..location + 2) {
            if sp == " " {
                line[location + 2..].to_string()
            } else {
                line[location + 1..].to_string()
            }
        } else {
            line[location + 1..].to_string()
        };

        line.truncate(location);
        // Headers should be ascii, I'm pretty sure. If not, please open an issue.
        line.make_ascii_lowercase();
        return Some((line, value));
    }
    None
}
