use super::{
    CoreJsonWebKeySet, IssuerUrl, OidcState, OidcWorkload, Provider, Result, Value,
    match_workload_binding, rejected, token_payload, unavailable, verify_workload,
};
use openidconnect::{
    JsonWebKeySetUrl,
    http::{Method, Request, StatusCode, header::ACCEPT},
};
use serde::Deserialize;

/// The discovery fields workload verification reads. Full provider metadata
/// also requires `authorization_endpoint`, which issuers that only mint
/// workload ID tokens, such as GitHub Actions, do not publish.
#[derive(Deserialize)]
struct WorkloadDiscovery {
    issuer: IssuerUrl,
    jwks_uri: JsonWebKeySetUrl,
}

impl OidcState {
    /// Verifies workload credentials against configured issuers only. The returned restrictions
    /// must be enforced before treating the mapped username as an authenticated caller.
    pub async fn workload(&self, raw: &str) -> Result<Option<OidcWorkload>> {
        if !self.providers
            .values()
            .any(|provider| !provider.config.workloads.is_empty())
            || raw.split('.').count() != 3
        {
            return Ok(None);
        }
        let payload = token_payload(raw)?;
        let issuer = payload
            .get("iss")
            .and_then(Value::as_str)
            .ok_or_else(rejected)?;
        let mut matched = None;
        for provider in self.providers.values() {
            if provider.config.issuer != issuer || provider.config.workloads.is_empty() {
                continue;
            }
            if !self.verify_workload_token(provider, raw).await? {
                continue;
            }
            match_workload_binding(provider, &payload, &mut matched)?;
        }
        matched.map(Some).ok_or_else(rejected)
    }

    /// Whether the token verifies against the provider's keys, refetching its
    /// metadata once in case the signing keys have rotated.
    pub(super) async fn verify_workload_token(
        &self,
        provider: &Provider,
        raw: &str,
    ) -> Result<bool> {
        let metadata = self.metadata(provider, false).await?;
        if verify_workload(&provider.config, &metadata.jwks, raw).is_ok() {
            return Ok(true);
        }
        let refreshed = self.metadata(provider, true).await?;
        Ok(verify_workload(&provider.config, &refreshed.jwks, raw).is_ok())
    }

    /// Fetches the signing keys of an issuer that has no browser login
    /// configured, reading only the discovery fields workload tokens need.
    pub(super) async fn workload_keys(&self, issuer: &IssuerUrl) -> Result<CoreJsonWebKeySet> {
        let discovery_url = issuer
            .join(".well-known/openid-configuration")
            .map_err(|_| unavailable())?;
        let request = Request::builder()
            .uri(discovery_url.as_str())
            .method(Method::GET)
            .header(ACCEPT, "application/json")
            .body(Vec::new())
            .map_err(|_| unavailable())?;
        let response = self.http_request(request).await?;
        if response.status() != StatusCode::OK {
            return Err(unavailable());
        }
        let discovery: WorkloadDiscovery =
            serde_json::from_slice(response.body()).map_err(|_| unavailable())?;
        if discovery.issuer != *issuer {
            return Err(unavailable());
        }
        CoreJsonWebKeySet::fetch_async(&discovery.jwks_uri, self)
            .await
            .map_err(|_| unavailable())
    }
}
