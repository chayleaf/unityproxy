use std::{ffi::c_int, io, net::Ipv4Addr, sync::RwLock};

#[cfg(feature = "dns-resolver")]
use hickory_resolver::TokioAsyncResolver;
use http::{uri::Scheme, Request, Response, Uri};
use http_body_util::{Either, Empty};
use hyper::{body::Incoming, service::service_fn, Method};
use hyper_util::rt::TokioIo;
use tokio::{
    net::{TcpListener, TcpStream},
    runtime::Runtime,
    sync::OnceCell,
};
use tokio_util::task::AbortOnDropHandle;

#[cfg(feature = "dns-resolver")]
static RESOLVER: tokio::sync::OnceCell<TokioAsyncResolver> = OnceCell::const_new();

async fn connect_to_address(
    url: &Uri,
    mandatory_port: bool,
    #[cfg(feature = "dns-resolver")] dns_resolver: &TokioAsyncResolver,
) -> io::Result<TcpStream> {
    let auth = url
        .authority()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "missing authority"))?;
    let port = if let Some(port) = auth.port_u16() {
        port
    } else {
        match (mandatory_port, url.scheme()) {
            (false, Some(x)) if x == &Scheme::HTTP => 80,
            (false, Some(x)) if x == &Scheme::HTTPS => 443,
            _ => return Err(io::Error::new(io::ErrorKind::Other, "missing port")),
        }
    };
    #[cfg(feature = "dns-resolver")]
    {
        let mut addrs = dns_resolver
            .lookup_ip(auth.host())
            .await?
            .into_iter()
            .collect::<Vec<_>>();
        addrs.sort();
        let Some(addr) = addrs.into_iter().next() else {
            return Err(io::Error::new(io::ErrorKind::Other, "unknown address"));
        };
        log::info!("connecting to {addr:?}:{port}");
        TcpStream::connect(std::net::SocketAddr::new(addr, port)).await
    }
    #[cfg(not(feature = "dns-resolver"))]
    {
        TcpStream::connect((auth.host(), port)).await
    }
}

#[cfg(feature = "use-rustls")]
async fn https_connect(
    remote: TcpStream,
    host: &str,
) -> io::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    use tokio_rustls::rustls;
    static CLIENT_CONFIG: OnceCell<std::sync::Arc<rustls::ClientConfig>> = OnceCell::const_new();
    let conn = tokio_rustls::TlsConnector::from(
        CLIENT_CONFIG
            .get_or_init(|| async {
                let mut roots = rustls::RootCertStore::empty();
                for cert in
                    rustls_native_certs::load_native_certs().expect("could not load platform certs")
                {
                    roots.add(cert).unwrap();
                }
                std::sync::Arc::new(
                    rustls::ClientConfig::builder()
                        .with_root_certificates(roots)
                        .with_no_client_auth(),
                )
            })
            .await
            .clone(),
    );
    let host = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
    conn.connect(host, remote).await
}

#[cfg(feature = "use-native-tls")]
async fn https_connect(
    remote: TcpStream,
    host: &str,
) -> Result<tokio_native_tls::TlsStream<tokio::net::TcpStream>, hyper_tls::native_tls::Error> {
    let conn =
        tokio_native_tls::TlsConnector::from(tokio_native_tls::native_tls::TlsConnector::new()?);
    conn.connect(host, remote).await
}

pub async fn handle(local: TcpStream) {
    #[cfg(feature = "dns-resolver")]
    let resolver = RESOLVER
        .get_or_init(|| async { TokioAsyncResolver::tokio_from_system_conf().unwrap() })
        .await;
    let conn = hyper::server::conn::http1::Builder::new()
        .auto_date_header(false)
        .preserve_header_case(true)
        .serve_connection(
            TokioIo::new(local),
            service_fn(|mut req: Request<Incoming>| async {
                if req.method() == Method::CONNECT {
                    // for CONNECT, just transparently proxy everything, nothing fancy
                    // use upgrade to signify a switch from http to a different protocol
                    match connect_to_address(
                        req.uri(),
                        true,
                        #[cfg(feature = "dns-resolver")]
                        resolver,
                    )
                    .await
                    {
                        Ok(mut remote) => {
                            tokio::spawn(async move {
                                let upgrade = match hyper::upgrade::on(&mut req).await {
                                    Ok(upgrade) => upgrade,
                                    Err(err) => {
                                        log::error!("connect upgrade: {err}");
                                        return;
                                    }
                                };
                                let mut upgrade = TokioIo::new(upgrade);
                                if let Err(err) =
                                    tokio::io::copy_bidirectional(&mut upgrade, &mut remote).await
                                {
                                    log::error!("connect copy: {err}");
                                }
                            });
                            Ok(Response::new(Either::Left(Empty::new())))
                        }
                        Err(err) => {
                            log::error!("connect conn: {err}");
                            Err("connect error".to_owned())
                        }
                    }
                } else if req.uri().scheme() == Some(&Scheme::HTTP)
                    || req.uri().scheme() == Some(&Scheme::HTTPS)
                {
                    // for http/https, pass the http request further down the line
                    // but remove all proxy-related headers
                    let keys_to_remove = req
                        .headers_mut()
                        .keys()
                        .filter(|key| {
                            let mut key = key.to_string();
                            key.make_ascii_lowercase();
                            key.starts_with("proxy-")
                        })
                        .cloned()
                        .collect::<Vec<_>>();
                    for key in keys_to_remove {
                        req.headers_mut().remove(key);
                    }
                    // rewrite http to https (safe to comment out)
                    if req.uri().scheme() == Some(&Scheme::HTTP) {
                        let mut parts = req.uri().clone().into_parts();
                        parts.scheme = Some(Scheme::HTTPS);
                        if let Ok(uri) = Uri::from_parts(parts) {
                            *req.uri_mut() = uri;
                        }
                    }
                    let https = req.uri().scheme() == Some(&Scheme::HTTPS);
                    match connect_to_address(
                        req.uri(),
                        false,
                        #[cfg(feature = "dns-resolver")]
                        resolver,
                    )
                    .await
                    {
                        Ok(remote) => {
                            // now just pass the request using the appropriate connectors
                            if https {
                                // unwrap is fine because its definitely there after
                                // connect_to_address succeeding
                                let host = req.uri().host().unwrap();

                                let conn = match https_connect(remote, host).await {
                                    Ok(conn) => conn,
                                    Err(err) => {
                                        log::error!("https: {err}");
                                        return Err("https connect error".to_owned());
                                    }
                                };

                                let (mut send_req, conn) =
                                    hyper::client::conn::http1::Builder::new()
                                        .preserve_header_case(true)
                                        .handshake(TokioIo::new(conn))
                                        .await
                                        .map_err(|err| err.to_string())?;
                                tokio::spawn(conn);
                                send_req
                                    .send_request(req)
                                    .await
                                    .map_err(|err| err.to_string())
                                    .map(|x| x.map(Either::Right))
                            } else {
                                let (mut send_req, conn) =
                                    hyper::client::conn::http1::Builder::new()
                                        .preserve_header_case(true)
                                        .handshake(TokioIo::new(remote))
                                        .await
                                        .map_err(|err| err.to_string())?;
                                tokio::spawn(conn);
                                send_req
                                    .send_request(req)
                                    .await
                                    .map_err(|err| err.to_string())
                                    .map(|x| x.map(Either::Right))
                            }
                        }
                        Err(err) => {
                            log::error!("http conn: {err}");
                            Err("connect error".to_owned())
                        }
                    }
                } else {
                    Err("unknown url scheme".to_owned())
                }
            }),
        )
        .with_upgrades();
    let _ = conn.await;
}

static RUNTIME: OnceCell<Runtime> = OnceCell::const_new();
static PROXY_HANDLE: RwLock<Option<AbortOnDropHandle<()>>> = RwLock::new(None);

#[no_mangle]
pub extern "C" fn install_proxy() -> c_int {
    let Ok(mut proxy_handle) = PROXY_HANDLE.write() else {
        return -1;
    };
    let runtime = if let Some(runtime) = RUNTIME.get() {
        Some(runtime)
    } else {
        if let Ok(rt) = Runtime::new() {
            let _ = RUNTIME.set(rt);
        }
        RUNTIME.get()
    };
    let Some(runtime) = runtime else {
        return -2;
    };
    let Ok((listener, addr)) =
        std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).and_then(|listener| {
            listener.set_nonblocking(true)?;
            let addr = listener.local_addr()?;
            Ok((listener, addr))
        })
    else {
        return -3;
    };
    let addr = format!("{}", addr);
    std::env::set_var("http_proxy", addr);
    *proxy_handle = Some(AbortOnDropHandle::new(runtime.spawn(async move {
        let listener = TcpListener::from_std(listener).unwrap();
        loop {
            let (stream, _addr) = listener.accept().await.unwrap();
            tokio::spawn(handle(stream));
        }
    })));
    0
}

#[no_mangle]
pub extern "C" fn uninstall_proxy() -> c_int {
    std::env::set_var("http_proxy", "");
    std::env::set_var("https_proxy", "");
    if let Ok(mut handle) = PROXY_HANDLE.write() {
        *handle = None;
        0
    } else {
        -1
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn simple() {
        assert_eq!(crate::install_proxy(), 0);
        assert_eq!(crate::uninstall_proxy(), 0);
    }
}
