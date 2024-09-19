#[cfg(feature = "binary")]
#[tokio::main]
async fn main() {
    env_logger::init();
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::new(127, 0, 0, 1), 9111))
        .await
        .unwrap();
    loop {
        let (stream, _addr) = listener.accept().await.unwrap();
        tokio::spawn(unityproxy::handle(stream));
    }
}

#[cfg(not(feature = "binary"))]
fn main() {}
