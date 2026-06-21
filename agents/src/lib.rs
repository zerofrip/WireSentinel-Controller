use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedRegistration {
    pub id: String,
    pub cloud_controller_id: String,
    pub tenant_id: String,
    pub cloud_base_url: String,
    pub registered_at: String,
}

#[derive(Debug, Clone)]
pub struct AgentClient {
    base_url: String,
    http: Client,
    device_id: Option<String>,
    enrollment_token: Option<String>,
    federation_token: Option<String>,
    tenant_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterDeviceRequest {
    pub enrollment_token: String,
    pub name: String,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub agent_version: Option<String>,
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceHeartbeat {
    pub agent_version: Option<String>,
    pub metadata: Option<Value>,
}

impl AgentClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: Client::new(),
            device_id: None,
            enrollment_token: None,
            federation_token: None,
            tenant_id: None,
        }
    }

    pub fn with_enrollment_token(mut self, token: impl Into<String>) -> Self {
        self.enrollment_token = Some(token.into());
        self
    }

    pub fn device_id(&self) -> Option<&str> {
        self.device_id.as_deref()
    }

    pub async fn register(&mut self, name: impl Into<String>) -> Result<Device> {
        let token = self
            .enrollment_token
            .clone()
            .context("enrollment token required")?;

        let req = RegisterDeviceRequest {
            enrollment_token: token,
            name: name.into(),
            hostname: None,
            os: Some(std::env::consts::OS.into()),
            agent_version: Some(env!("CARGO_PKG_VERSION").into()),
            metadata: None,
        };

        let url = format!("{}/api/v1/devices/register", self.base_url);
        let resp = self.http.post(url).json(&req).send().await?;
        resp.error_for_status_ref()?;
        let device: Device = resp.json().await?;
        self.device_id = Some(device.id.clone());
        Ok(device)
    }

    pub async fn heartbeat(&self, metadata: Option<Value>) -> Result<Device> {
        let id = self
            .device_id
            .as_deref()
            .context("device not registered; call register() first")?;

        let url = format!("{}/api/v1/devices/{id}/heartbeat", self.base_url);
        let resp = self
            .http
            .post(url)
            .json(&DeviceHeartbeat {
                agent_version: Some(env!("CARGO_PKG_VERSION").into()),
                metadata,
            })
            .send()
            .await?;
        resp.error_for_status_ref()?;
        Ok(resp.json().await?)
    }

    pub async fn enroll_and_heartbeat(&mut self, name: impl Into<String>) -> Result<Device> {
        let device = self.register(name).await?;
        self.heartbeat(None).await?;
        Ok(device)
    }

    pub async fn fetch_device_policy(&self, device_id: &str) -> Result<serde_json::Value> {
        let url = format!("{}/api/v1/policies/devices/{device_id}", self.base_url);
        let resp = self.http.get(url).send().await?;
        resp.error_for_status_ref()?;
        Ok(resp.json().await?)
    }

    pub async fn push_metrics(&self, device_id: &str, snapshot: &serde_json::Value) -> Result<()> {
        let url = format!("{}/api/v1/agents/{device_id}/metrics", self.base_url);
        let resp = self.http.post(url).json(snapshot).send().await?;
        resp.error_for_status_ref()?;
        Ok(())
    }

    pub async fn push_mixnet_heartbeat(
        &self,
        device_id: &str,
        payload: &serde_json::Value,
    ) -> Result<()> {
        let url = format!(
            "{}/api/v1/agents/{device_id}/mixnet/heartbeat",
            self.base_url
        );
        let resp = self.http.post(url).json(payload).send().await?;
        resp.error_for_status_ref()?;
        Ok(())
    }

    pub async fn push_kernel_heartbeat(
        &self,
        device_id: &str,
        payload: &serde_json::Value,
    ) -> Result<()> {
        let url = format!(
            "{}/api/v1/agents/{device_id}/kernel/heartbeat",
            self.base_url
        );
        let resp = self.http.post(url).json(payload).send().await?;
        resp.error_for_status_ref()?;
        Ok(())
    }

    pub async fn push_anonymity_heartbeat(
        &self,
        device_id: &str,
        payload: &serde_json::Value,
    ) -> Result<()> {
        let url = format!(
            "{}/api/v1/agents/{device_id}/anonymity/heartbeat",
            self.base_url
        );
        let resp = self.http.post(url).json(payload).send().await?;
        resp.error_for_status_ref()?;
        Ok(())
    }

    pub async fn push_ztna_heartbeat(
        &self,
        device_id: &str,
        payload: &serde_json::Value,
    ) -> Result<()> {
        let url = format!(
            "{}/api/v1/agents/{device_id}/ztna/heartbeat",
            self.base_url
        );
        let resp = self.http.post(url).json(payload).send().await?;
        resp.error_for_status_ref()?;
        Ok(())
    }

    pub async fn register_connector(
        &self,
        device_id: &str,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let url = format!(
            "{}/api/v1/agents/{device_id}/ztna/connectors",
            self.base_url
        );
        let resp = self.http.post(url).json(payload).send().await?;
        resp.error_for_status_ref()?;
        Ok(resp.json().await?)
    }

    pub async fn push_sse_telemetry(
        &self,
        device_id: &str,
        payload: &serde_json::Value,
    ) -> Result<()> {
        let url = format!(
            "{}/api/v1/agents/{device_id}/sse/telemetry",
            self.base_url
        );
        let resp = self.http.post(url).json(payload).send().await?;
        resp.error_for_status_ref()?;
        Ok(())
    }

    pub async fn report_dlp_incident(
        &self,
        device_id: &str,
        payload: &serde_json::Value,
    ) -> Result<()> {
        let body = if payload.get("dlp_incidents").is_some() {
            payload.clone()
        } else {
            serde_json::json!({ "dlp_incidents": [payload] })
        };
        self.push_sse_telemetry(device_id, &body).await
    }

    pub async fn push_xdr_telemetry(
        &self,
        device_id: &str,
        payload: &serde_json::Value,
    ) -> Result<()> {
        let url = format!(
            "{}/api/v1/agents/{device_id}/xdr/telemetry",
            self.base_url
        );
        let resp = self.http.post(url).json(payload).send().await?;
        resp.error_for_status_ref()?;
        Ok(())
    }

    pub async fn report_edr_event(
        &self,
        device_id: &str,
        payload: &serde_json::Value,
    ) -> Result<()> {
        let body = if payload.get("edr_events").is_some() {
            payload.clone()
        } else {
            serde_json::json!({ "edr_events": [payload] })
        };
        self.push_xdr_telemetry(device_id, &body).await
    }

    pub async fn execute_response_action(
        &self,
        device_id: &str,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let url = format!(
            "{}/api/v1/agents/{device_id}/xdr/response",
            self.base_url
        );
        let resp = self.http.post(url).json(payload).send().await?;
        resp.error_for_status_ref()?;
        Ok(resp.json().await?)
    }

    pub async fn push_cnapp_telemetry(
        &self,
        device_id: &str,
        payload: &serde_json::Value,
    ) -> Result<()> {
        let url = format!(
            "{}/api/v1/agents/{device_id}/cnapp/telemetry",
            self.base_url
        );
        let resp = self.http.post(url).json(payload).send().await?;
        resp.error_for_status_ref()?;
        Ok(())
    }

    pub async fn push_ai_telemetry(
        &self,
        device_id: &str,
        payload: &serde_json::Value,
    ) -> Result<()> {
        let url = format!(
            "{}/api/v1/agents/{device_id}/ai/telemetry",
            self.base_url
        );
        let resp = self.http.post(url).json(payload).send().await?;
        resp.error_for_status_ref()?;
        Ok(())
    }

    pub async fn execute_copilot_query(
        &self,
        device_id: &str,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let url = format!(
            "{}/api/v1/agents/{device_id}/ai/copilot/query",
            self.base_url
        );
        let resp = self.http.post(url).json(payload).send().await?;
        resp.error_for_status_ref()?;
        Ok(resp.json().await?)
    }

    pub async fn request_investigation(
        &self,
        device_id: &str,
        payload: &serde_json::Value,
    ) -> Result<()> {
        let body = if payload.get("investigations").is_some() {
            payload.clone()
        } else {
            serde_json::json!({ "investigations": [payload] })
        };
        self.push_ai_telemetry(device_id, &body).await
    }

    pub async fn report_posture_finding(
        &self,
        device_id: &str,
        payload: &serde_json::Value,
    ) -> Result<()> {
        let body = if payload.get("posture_findings").is_some() {
            payload.clone()
        } else {
            serde_json::json!({ "posture_findings": [payload] })
        };
        self.push_cnapp_telemetry(device_id, &body).await
    }

    pub async fn ingest_sbom(
        &self,
        device_id: &str,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let body = if payload.get("device_id").is_some() {
            payload.clone()
        } else if payload.get("sbom_documents").is_some() {
            serde_json::json!({
                "device_id": device_id,
                "sbom_documents": payload["sbom_documents"]
            })
        } else {
            serde_json::json!({
                "device_id": device_id,
                "sbom_documents": [payload]
            })
        };
        let url = format!("{}/api/v1/cnapp/scan/ingest", self.base_url);
        let resp = self.http.post(url).json(&body).send().await?;
        resp.error_for_status_ref()?;
        Ok(resp.json().await?)
    }

    pub async fn register_federation(
        &mut self,
        token: impl Into<String>,
        tenant_id: impl Into<String>,
        cloud_url: impl Into<String>,
    ) -> Result<FederatedRegistration> {
        let token = token.into();
        let tenant_id = tenant_id.into();
        let cloud_url = cloud_url.into();
        let url = format!("{}/api/v1/federation/register", self.base_url);
        let resp = self
            .http
            .post(url)
            .json(&serde_json::json!({
                "token": &token,
                "tenant_id": &tenant_id,
                "cloud_base_url": cloud_url,
            }))
            .send()
            .await?;
        resp.error_for_status_ref()?;
        let registration: FederatedRegistration = resp.json().await?;
        self.federation_token = Some(token);
        self.tenant_id = Some(tenant_id);
        Ok(registration)
    }

    pub async fn push_sync_bundle(&self, bundle_json: &serde_json::Value) -> Result<()> {
        let token = self
            .federation_token
            .as_deref()
            .context("federation token required; call register_federation() first")?;
        let url = format!("{}/api/v1/federation/sync", self.base_url);
        let resp = self
            .http
            .post(url)
            .header("X-Federation-Token", token)
            .json(&serde_json::json!({
                "bundle": bundle_json,
                "tenant_id": self.tenant_id,
            }))
            .send()
            .await?;
        resp.error_for_status_ref()?;
        Ok(())
    }

    pub async fn push_cloud_usage(
        &self,
        device_id: &str,
        payload: &serde_json::Value,
    ) -> Result<()> {
        let url = format!("{}/api/v1/cloud/usage?device_id={device_id}", self.base_url);
        let resp = self.http.post(url).json(payload).send().await?;
        resp.error_for_status_ref()?;
        Ok(())
    }

    pub async fn push_cloud_health(&self, payload: &serde_json::Value) -> Result<()> {
        let url = format!("{}/api/v1/cloud/health", self.base_url);
        let resp = self.http.post(url).json(payload).send().await?;
        resp.error_for_status_ref()?;
        Ok(())
    }

    pub async fn push_cloud_logs(
        &self,
        device_id: &str,
        payload: &serde_json::Value,
    ) -> Result<()> {
        let url = format!("{}/api/v1/cloud/logs?device_id={device_id}", self.base_url);
        let resp = self.http.post(url).json(payload).send().await?;
        resp.error_for_status_ref()?;
        Ok(())
    }

    pub async fn pull_sync_bundle(&self) -> Result<Value> {
        let token = self
            .federation_token
            .as_deref()
            .context("federation token required; call register_federation() first")?;
        let mut url = format!("{}/api/v1/federation/sync", self.base_url);
        if let Some(ref tid) = self.tenant_id {
            url = format!("{url}?tenant_id={tid}");
        }
        let resp = self
            .http
            .get(url)
            .header("X-Federation-Token", token)
            .send()
            .await?;
        resp.error_for_status_ref()?;
        Ok(resp.json().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_stores_base_url() {
        let client = AgentClient::new("http://localhost:8080/");
        assert_eq!(client.base_url, "http://localhost:8080");
    }
}
