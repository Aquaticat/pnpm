//! Discovery of a provider's metadata, and the per-provider cache that
//! keeps one copy alive for [`METADATA_TTL`] while [`REFRESH_INTERVAL`] bounds
//! how often a failed discovery is retried.

use super::{
    CoreJsonWebKeySet, CoreProviderMetadata, Duration, Instant, IssuerUrl, OidcState, Provider,
    Result, rejected, secure_url, unavailable,
};

const METADATA_TTL: Duration = Duration::from_mins(5);
const REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// How fresh a provider's metadata has to be. `Refetched` asks for a new
/// discovery, and takes the cached copy only when one was attempted within
/// [`REFRESH_INTERVAL`], which bounds the retries a rejected token triggers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MetadataFreshness {
    Cached,
    Refetched,
}

/// What discovery fetched for one provider. Workload verification reads only
/// the signing keys; browser login also needs the provider's endpoints, which
/// workload-only issuers, such as GitHub Actions, do not publish.
#[derive(Clone)]
pub(super) struct Discovered {
    pub(super) jwks: CoreJsonWebKeySet,
    pub(super) login: Option<CoreProviderMetadata>,
}

#[derive(Default)]
pub(super) struct MetadataCache {
    pub(super) value: Option<(Instant, Discovered)>,
    pub(super) attempted_at: Option<Instant>,
}

impl OidcState {
    pub(super) async fn metadata(
        &self,
        provider: &Provider,
        freshness: MetadataFreshness,
    ) -> Result<Discovered> {
        let cached = cached_metadata(&*provider.metadata.lock().await, freshness);
        if let Some(metadata) = cached {
            return Ok(metadata);
        }
        let _refresh = provider.refresh.lock().await;
        {
            let mut cache = provider.metadata.lock().await;
            if let Some(metadata) = cached_metadata(&cache, freshness) {
                return Ok(metadata);
            }
            if cache.attempted_at.is_some_and(|at| at.elapsed() < REFRESH_INTERVAL) {
                return Err(unavailable());
            }
            cache.attempted_at = Some(Instant::now());
        }
        let issuer = IssuerUrl::new(provider.config.issuer.clone()).map_err(|_| rejected())?;
        let discovered = if provider.config.login.is_some() {
            let metadata =
                CoreProviderMetadata::discover_async(issuer, self).await.map_err(|_| unavailable())?;
            secure_url(metadata.authorization_endpoint().as_str())?;
            if let Some(endpoint) = metadata.token_endpoint() {
                secure_url(endpoint.as_str())?;
            }
            Discovered { jwks: metadata.jwks().clone(), login: Some(metadata) }
        } else {
            Discovered { jwks: self.workload_keys(&issuer).await?, login: None }
        };
        provider.metadata.lock().await.value = Some((Instant::now(), discovered.clone()));
        Ok(discovered)
    }
}

fn cached_metadata(
    cache: &MetadataCache,
    freshness: MetadataFreshness,
) -> Option<Discovered> {
    let unexpired = cache.value
        .as_ref()
        .filter(|(fetched, _)| fetched.elapsed() < METADATA_TTL);
    match freshness {
        MetadataFreshness::Cached => unexpired,
        MetadataFreshness::Refetched => unexpired.filter(|_| {
            cache.attempted_at.is_some_and(|at| at.elapsed() < REFRESH_INTERVAL)
        }),
    }
    .map(|(_, metadata)| metadata.clone())
}
