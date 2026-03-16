//! Network initialization and management.

use tokio::sync::mpsc;

use crate::config::NetworkConfig;
use crate::error::{SandboxError, SandboxViolationEvent};
use crate::proxy::{DomainFilter, HttpProxy, Socks5Proxy};

/// Initialize network proxies.
pub async fn initialize_proxies(
    config: &NetworkConfig,
    violations_tx: mpsc::Sender<SandboxViolationEvent>,
) -> Result<(HttpProxy, Socks5Proxy), SandboxError> {
    // Create domain filter from config
    let filter = DomainFilter::from_config(config);

    // Get MITM socket path if configured
    let mitm_socket_path = config.mitm_proxy.as_ref().map(|m| m.socket_path.clone());

    // Create HTTP proxy
    let mut http_proxy =
        HttpProxy::new(filter.clone(), mitm_socket_path, violations_tx.clone()).await?;
    http_proxy.start()?;

    // Create SOCKS5 proxy
    let mut socks_proxy = Socks5Proxy::new(filter, violations_tx).await?;
    socks_proxy.start()?;

    tracing::debug!(
        "Proxies started - HTTP: {}, SOCKS5: {}",
        http_proxy.port(),
        socks_proxy.port()
    );

    Ok((http_proxy, socks_proxy))
}