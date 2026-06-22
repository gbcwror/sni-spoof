use anyhow::{Context, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

use crate::config::AppConfig;
use crate::connection::{CompletionResult, ConnectionId, ConnectionState, CONNECTION_TTL_SECS};
use crate::net::parse_ipv4;
use crate::tls::ClientHelloBuilder;
use crate::ConnectionMap;

pub async fn run_proxy(
    config: &AppConfig,
    interface_ip: &str,
    connections: ConnectionMap,
    cancel: CancellationToken,
) -> Result<()> {
    let listener = TcpListener::bind((config.listen_host.as_str(), config.listen_port))
        .await
        .with_context(|| {
            format!(
                "Failed to bind on {}:{}. Is the port already in use?",
                config.listen_host, config.listen_port
            )
        })?;

    info!(
        "Proxy listening on {}:{}",
        config.listen_host, config.listen_port
    );

    let mut cleanup_interval = tokio::time::interval(Duration::from_secs(CONNECTION_TTL_SECS));

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, addr)) => {
                        debug!("New connection from {}", addr);
                        let config       = config.clone();
                        let interface_ip = interface_ip.to_string();
                        let connections  = connections.clone();
                        let cancel       = cancel.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(
                                stream, &config, &interface_ip, connections, cancel,
                            ).await {
                                debug!("Connection from {} ended: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Accept error: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
            _ = cleanup_interval.tick() => {
                cleanup_stale_connections(&connections);
            }
            _ = cancel.cancelled() => {
                info!("Proxy shutting down");
                break;
            }
        }
    }

    Ok(())
}

async fn handle_connection(
    mut incoming: TcpStream,
    config: &AppConfig,
    interface_ip: &str,
    connections: ConnectionMap,
    cancel: CancellationToken,
) -> Result<()> {
    let src_ip = parse_ipv4(interface_ip)?;
    let dst_ip = parse_ipv4(&config.connect_ip)?;

    let fake_data = ClientHelloBuilder::build_randomized(&config.fake_sni);

    let socket = TcpSocket::new_v4().context("Failed to create outgoing socket")?;
    let bind_addr = format!("{}:0", interface_ip).parse()?;
    socket
        .bind(bind_addr)
        .context("Failed to bind outgoing socket")?;

    let raw_socket = socket2::SockRef::from(&socket);
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(11))
        .with_interval(Duration::from_secs(2));
    if let Err(e) = raw_socket.set_tcp_keepalive(&ka) {
        debug!("TCP keepalive ignored: {}", e);
    }

    let src_port = socket.local_addr()?.port();

    let conn_id = ConnectionId {
        src_ip,
        src_port,
        dst_ip,
        dst_port: config.connect_port,
    };

    let state      = ConnectionState::new(fake_data);
    let completion = state.completion.clone();

    {
        let mut conns = connections.lock().unwrap_or_else(|e| e.into_inner());
        conns.insert(conn_id, state);
    }

    let dst_addr = format!("{}:{}", config.connect_ip, config.connect_port).parse()?;
    let outgoing_result = tokio::time::timeout(
        Duration::from_secs(config.connection_timeout_secs),
        socket.connect(dst_addr),
    )
    .await;

    let mut outgoing = match outgoing_result {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            cleanup_connection(&connections, &conn_id);
            if let Err(e2) = incoming.shutdown().await {
                debug!("Shutdown ignored: {}", e2);
            }
            return Err(e.into());
        }
        Err(_) => {
            cleanup_connection(&connections, &conn_id);
            if let Err(e2) = incoming.shutdown().await {
                debug!("Shutdown ignored: {}", e2);
            }
            anyhow::bail!("Connection to target timed out");
        }
    };

    let inject_result = tokio::time::timeout(
        Duration::from_secs(config.connection_timeout_secs),
        async {
            tokio::select! {
                _ = completion.notified() => {}
                _ = cancel.cancelled()    => {}
            }
        },
    )
    .await;

    let result = {
        let conns = connections.lock().unwrap_or_else(|e| e.into_inner());
        conns.get(&conn_id).and_then(|s| s.result)
    };

    cleanup_connection(&connections, &conn_id);

    match (inject_result, result) {
        (Ok(()), Some(CompletionResult::Success)) => {
            debug!("{} fake injection successful", conn_id);
        }
        _ => {
            if let Err(e) = incoming.shutdown().await {
                debug!("Shutdown ignored: {}", e);
            }
            if let Err(e) = outgoing.shutdown().await {
                debug!("Shutdown ignored: {}", e);
            }
            anyhow::bail!("Injection failed or timed out for {}", conn_id);
        }
    }

    let (up, down) = relay(incoming, outgoing, cancel).await;
    debug!(
        "{} relay finished — {} bytes up, {} bytes down",
        conn_id, up, down
    );

    Ok(())
}

async fn relay(
    incoming: TcpStream,
    outgoing: TcpStream,
    cancel: CancellationToken,
) -> (u64, u64) {
    let (mut in_read,  mut in_write)  = incoming.into_split();
    let (mut out_read, mut out_write) = outgoing.into_split();

    let bytes_up   = Arc::new(AtomicU64::new(0));
    let bytes_down = Arc::new(AtomicU64::new(0));

    // peer_done is cancelled by whichever half finishes first,
    // causing the other half to exit cleanly.
    let peer_done = CancellationToken::new();

    // Each task gets its own clone to listen on and to signal with.
    // Cancelling any clone cancels all of them — so either task
    // finishing will unblock the other.
    let pd_listen_a  = peer_done.clone();
    let pd_signal_a  = peer_done.clone();
    let pd_listen_b  = peer_done.clone();
    let pd_signal_b  = peer_done.clone();

    let cancel_a = cancel.clone();
    let cancel_b = cancel.clone();

    let bu = bytes_up.clone();
    let bd = bytes_down.clone();

    let in_to_out = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                result = in_read.read(&mut buf) => {
                    match result {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            bu.fetch_add(n as u64, Ordering::Relaxed);
                            if out_write.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                _ = cancel_a.cancelled()   => break,
                _ = pd_listen_a.cancelled() => break,
            }
        }
        if let Err(e) = out_write.shutdown().await {
            debug!("Relay shutdown ignored: {}", e);
        }
        // Signal the other half that we are done.
        pd_signal_a.cancel();
    });

    let out_to_in = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                result = out_read.read(&mut buf) => {
                    match result {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            bd.fetch_add(n as u64, Ordering::Relaxed);
                            if in_write.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                _ = cancel_b.cancelled()   => break,
                _ = pd_listen_b.cancelled() => break,
            }
        }
        if let Err(e) = in_write.shutdown().await {
            debug!("Relay shutdown ignored: {}", e);
        }
        // Signal the other half that we are done.
        pd_signal_b.cancel();
    });

    let _ = tokio::join!(in_to_out, out_to_in);

    (
        bytes_up.load(Ordering::Relaxed),
        bytes_down.load(Ordering::Relaxed),
    )
}

fn cleanup_stale_connections(connections: &ConnectionMap) {
    let now = std::time::Instant::now();
    let mut conns = connections.lock().unwrap_or_else(|e| e.into_inner());
    let stale: Vec<ConnectionId> = conns
        .iter()
        .filter(|(_, s)| {
            s.active && now.duration_since(s.created_at).as_secs() > CONNECTION_TTL_SECS
        })
        .map(|(id, _)| *id)
        .collect();
    for id in stale {
        if let Some(mut state) = conns.remove(&id) {
            state.active = false;
            state.result = Some(CompletionResult::Failure);
            state.completion.notify_one();
        }
    }
}

fn cleanup_connection(connections: &ConnectionMap, conn_id: &ConnectionId) {
    let mut conns = connections.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(mut state) = conns.remove(conn_id) {
        state.active = false;
        state.completion.notify_one();
    }
}