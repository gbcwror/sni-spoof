mod config;
mod connection;
mod injector;
mod net;
mod proxy;
mod tls;

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::signal;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use config::AppConfig;
use connection::{ConnectionId, ConnectionState};
use injector::PacketInjector;

pub type ConnectionMap = Arc<Mutex<HashMap<ConnectionId, ConnectionState>>>;

fn get_exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

fn main() -> Result<()> {
    let config_path = get_exe_dir().join("config.json");
    let config = AppConfig::load(&config_path)
        .with_context(|| format!("Failed to load config from {}", config_path.display()))?;

    tracing_subscriber::fmt()
        .with_max_level(config.log_level())
        .with_target(false)
        .init();

    info!("SNI-Spoof v{}", env!("CARGO_PKG_VERSION"));

    let interface_ip = net::get_default_interface_ipv4(&config.connect_ip)
        .context("Failed to detect network interface. Check your network connection.")?;

    info!("Listening on {}:{}", config.listen_host, config.listen_port);
    info!("Target: {}:{}", config.connect_ip, config.connect_port);
    info!("Fake SNI: {}", config.fake_sni);
    info!("Bypass method: {:?}", config.bypass_method);
    info!("Interface: {}", interface_ip);

    let connections: ConnectionMap = Arc::new(Mutex::new(HashMap::new()));
    let cancel_token = CancellationToken::new();

    let injector_connections = connections.clone();
    let injector_config      = config.clone();
    let injector_interface   = interface_ip.clone();
    let injector_cancel      = cancel_token.clone();

    let injector_handle = std::thread::Builder::new()
        .name("packet-injector".into())
        .spawn(move || {
            if let Err(e) = PacketInjector::run(
                &injector_config,
                &injector_interface,
                injector_connections,
                injector_cancel,
            ) {
                error!("Packet injector error: {}", e);
            }
        })
        .context("Failed to spawn injector thread")?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.worker_threads as usize)
        .enable_all()
        .build()
        .context("Failed to build tokio runtime")?;

    runtime.block_on(async {
        let proxy_cancel      = cancel_token.clone();
        let proxy_connections = connections.clone();
        let proxy_config      = config.clone();
        let proxy_interface   = interface_ip.clone();

        let proxy_handle = tokio::spawn(async move {
            if let Err(e) = proxy::run_proxy(
                &proxy_config,
                &proxy_interface,
                proxy_connections,
                proxy_cancel,
            )
            .await
            {
                error!("Proxy error: {}", e);
            }
        });

        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Shutting down...");
            }
            _ = cancel_token.cancelled() => {
                info!("Cancelled, shutting down...");
            }
        }

        cancel_token.cancel();
        proxy_handle.abort();
    });

    drop(runtime);

    // The injector thread may be blocked in a syscall (WinDivert recv /
    // nfqueue recv). Give it a short grace period; if it does not finish
    // in time we log a warning and let the OS clean up on process exit.
    let join_deadline = std::time::Duration::from_secs(2);
    let join_start    = std::time::Instant::now();

    loop {
        if injector_handle.is_finished() {
            match injector_handle.join() {
                Ok(())  => {}
                Err(e) => error!("Injector thread panicked: {:?}", e),
            }
            break;
        }
        if join_start.elapsed() >= join_deadline {
            warn!("Injector thread did not exit within 2 s — process will terminate");
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    info!("Shutdown complete");
    Ok(())
}