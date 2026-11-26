use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

#[derive(Clone, Default)]
pub struct TrafficCounters {
    pub tx_bytes: Arc<AtomicU64>,
    pub rx_bytes: Arc<AtomicU64>,
}

impl TrafficCounters {
    pub fn new() -> Self {
        Self {
            tx_bytes: Arc::new(AtomicU64::new(0)),
            rx_bytes: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn totals(&self) -> (u64, u64) {
        (
            self.rx_bytes.load(Ordering::Relaxed),
            self.tx_bytes.load(Ordering::Relaxed),
        )
    }

    pub fn reset(&self) {
        self.rx_bytes.store(0, Ordering::Relaxed);
        self.tx_bytes.store(0, Ordering::Relaxed);
    }
}

pub struct ProxyMeterHandle {
    shutdown_tx: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl ProxyMeterHandle {
    pub fn stop(mut self) {
        let _ = self.shutdown_tx.send(true);
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }

    pub async fn stop_async(mut self) {
        let _ = self.shutdown_tx.send(true);
        let tasks = std::mem::take(&mut self.tasks);
        for task in tasks {
            let abort_handle = task.abort_handle();
            if tokio::time::timeout(Duration::from_millis(500), task)
                .await
                .is_err()
            {
                abort_handle.abort();
            }
        }
    }
}

impl Drop for ProxyMeterHandle {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}

pub fn format_bind_error(port: u16, label: &str, err: &std::io::Error) -> String {
    match err.kind() {
        std::io::ErrorKind::AddrInUse => format!(
            "{label} порт {port} уже занят другим приложением. Освободите порт или измените его в Настройках → Прокси."
        ),
        std::io::ErrorKind::PermissionDenied => format!(
            "Windows заблокировал доступ к {label} порту {port} (диапазон Hyper-V/WSL2 или политики безопасности). Выберите другой порт в Настройках → Прокси."
        ),
        _ => format!("Не удалось открыть локальный {label} порт {port}: {err}"),
    }
}

async fn bind_loopback(port: u16, label: &str) -> Result<TcpListener, String> {
    TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(|e| format_bind_error(port, label, &e))
}

fn spawn_forward_loop(
    listener: TcpListener,
    target_port: u16,
    counters: TrafficCounters,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                accept_res = listener.accept() => {
                    match accept_res {
                        Ok((inbound, _)) => {
                            let c = counters.clone();
                            let conn_shutdown = shutdown_rx.clone();
                            tokio::spawn(async move {
                                let _ = relay_connection(inbound, target_port, c, conn_shutdown).await;
                            });
                        }
                        Err(_) => {
                            // Keep listener alive across transient socket errors (e.g. WSAECONNRESET / EMFILE)
                            tokio::time::sleep(Duration::from_millis(25)).await;
                        }
                    }
                }
            }
        }
        drop(listener);
    })
}

async fn copy_counted<R, W>(
    mut reader: R,
    mut writer: W,
    counter: &AtomicU64,
) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            let _ = writer.shutdown().await;
            return Ok(());
        }
        writer.write_all(&buf[..n]).await?;
        counter.fetch_add(n as u64, Ordering::Relaxed);
    }
}

async fn relay_connection(
    inbound: TcpStream,
    target_port: u16,
    counters: TrafficCounters,
    mut shutdown_rx: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let outbound = TcpStream::connect(("127.0.0.1", target_port)).await?;
    let _ = inbound.set_nodelay(true);
    let _ = outbound.set_nodelay(true);

    let (in_read, in_write) = inbound.into_split();
    let (out_read, out_write) = outbound.into_split();

    let tx_fut = copy_counted(in_read, out_write, &counters.tx_bytes);
    let rx_fut = copy_counted(out_read, in_write, &counters.rx_bytes);

    tokio::select! {
        _ = async {
            let _ = tokio::join!(tx_fut, rx_fut);
        } => {}
        _ = shutdown_rx.changed() => {}
    }

    Ok(())
}

pub async fn start_proxy_meter(
    http_port: u16,
    socks_port: u16,
    target_http_port: u16,
    target_socks_port: u16,
    counters: TrafficCounters,
) -> Result<ProxyMeterHandle, String> {
    if http_port == socks_port {
        return Err("HTTP и SOCKS5 порты не должны совпадать.".to_string());
    }

    let http_listener = bind_loopback(http_port, "HTTP-прокси").await?;
    let socks_listener = bind_loopback(socks_port, "SOCKS5-прокси").await?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let t1 = spawn_forward_loop(
        http_listener,
        target_http_port,
        counters.clone(),
        shutdown_rx.clone(),
    );
    let t2 = spawn_forward_loop(socks_listener, target_socks_port, counters, shutdown_rx);

    Ok(ProxyMeterHandle {
        shutdown_tx,
        tasks: vec![t1, t2],
    })
}

pub fn pick_ephemeral_loopback_ports() -> Result<(u16, u16), String> {
    let l1 = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| format!("Не удалось выделить локальный порт: {e}"))?;
    let l2 = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| format!("Не удалось выделить локальный порт: {e}"))?;
    let p1 = l1
        .local_addr()
        .map_err(|e| format!("Ошибка чтения локального порта: {e}"))?
        .port();
    let p2 = l2
        .local_addr()
        .map_err(|e| format!("Ошибка чтения локального порта: {e}"))?
        .port();
    Ok((p1, p2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_error_distinguishes_addr_in_use_and_permission_denied() {
        let in_use = std::io::Error::from(std::io::ErrorKind::AddrInUse);
        let msg_use = format_bind_error(10808, "HTTP-прокси", &in_use);
        assert!(msg_use.contains("уже занят"));

        let perm = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let msg_perm = format_bind_error(10808, "HTTP-прокси", &perm);
        assert!(msg_perm.contains("Hyper-V"));
    }

    #[tokio::test]
    async fn stop_async_releases_ports_and_counts_traffic() {
        let target = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let echo_task = tokio::spawn(async move {
            if let Ok((mut s, _)) = target.accept().await {
                let mut buf = [0u8; 64];
                if let Ok(n) = s.read(&mut buf).await {
                    let _ = s.write_all(&buf[..n]).await;
                }
            }
        });

        let (http_port, socks_port) = pick_ephemeral_loopback_ports().unwrap();
        let (dummy_socks, _) = pick_ephemeral_loopback_ports().unwrap();
        let counters = TrafficCounters::new();
        let handle = start_proxy_meter(
            http_port,
            socks_port,
            target_port,
            dummy_socks,
            counters.clone(),
        )
        .await
        .expect("start_proxy_meter must succeed");

        let mut client = TcpStream::connect(("127.0.0.1", http_port)).await.unwrap();
        client.write_all(b"HELLO_METER").await.unwrap();
        let _ = client.shutdown().await;
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        assert_eq!(&resp, b"HELLO_METER");

        let (rx, tx) = counters.totals();
        assert!(rx >= 11 && tx >= 11, "rx={rx}, tx={tx}");

        handle.stop_async().await;
        echo_task.abort();

        // Port must be immediately re-bindable after stop_async returns
        let rebound_http = TcpListener::bind(("127.0.0.1", http_port)).await;
        let rebound_socks = TcpListener::bind(("127.0.0.1", socks_port)).await;
        assert!(rebound_http.is_ok(), "http port should be released");
        assert!(rebound_socks.is_ok(), "socks port should be released");
    }
}
