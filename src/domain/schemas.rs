use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProvisioningInfoMap {
    #[serde(rename = "1")]
    pub certificate_issued: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AttestationPackageInfo {
    pub name: String,
    pub version: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AttestationApplicationId {
    pub packages: Vec<AttestationPackageInfo>,
    pub signatures: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SecurityLevel {
    Software,
    TrustedEnvironment,
    StrongBox,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum VerifiedBootState {
    Verified,
    SelfSigned,
    Unverified,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RootOfTrust {
    pub verified_boot_key: Vec<u8>,
    pub device_locked: bool,
    pub verified_boot_state: VerifiedBootState,
    pub verified_boot_hash: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AuthorizationList {
    pub purpose: Option<Vec<i64>>,
    pub algorithm: Option<i64>,
    pub key_size: Option<i64>,
    pub block_mode: Option<Vec<i64>>,
    pub digest: Option<Vec<i64>>,
    pub padding: Option<Vec<i64>>,
    pub ec_curve: Option<i64>,
    pub ml_dsa_variant: Option<i64>,
    pub rsa_public_exponent: Option<i64>,
    pub rsa_oaep_mgf_digest: Option<Vec<i64>>,
    pub active_date_time: Option<i64>,
    pub origination_expire_date_time: Option<i64>,
    pub usage_expire_date_time: Option<i64>,
    pub usage_count_limit: Option<i64>,
    pub no_auth_required: Option<()>,
    pub user_auth_type: Option<i64>,
    pub auth_timeout: Option<i64>,
    pub allow_while_on_body: Option<()>,
    pub trusted_user_presence_required: Option<()>,
    pub trusted_confirmation_required: Option<()>,
    pub unlocked_device_required: Option<()>,
    pub creation_date_time: Option<i64>,
    pub origin: Option<i64>,
    pub rollback_resistant: Option<()>,
    pub root_of_trust: Option<RootOfTrust>,
    pub os_version: Option<i64>,
    pub os_patch_level: Option<i64>,
    pub attestation_application_id: Option<AttestationApplicationId>,
    pub attestation_id_brand: Option<Vec<u8>>,
    pub attestation_id_device: Option<Vec<u8>>,
    pub attestation_id_product: Option<Vec<u8>>,
    pub attestation_id_serial: Option<Vec<u8>>,
    pub attestation_id_imei: Option<Vec<u8>>,
    pub attestation_id_meid: Option<Vec<u8>>,
    pub attestation_id_manufacturer: Option<Vec<u8>>,
    pub attestation_id_model: Option<Vec<u8>>,
    pub vendor_patch_level: Option<i64>,
    pub boot_patch_level: Option<i64>,
    pub attestation_id_second_imei: Option<Vec<u8>>,
    pub module_hash: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct KeyDescription {
    pub attestation_version: i64,
    pub attestation_security_level: SecurityLevel,
    pub key_mint_version: i64,
    pub key_mint_security_level: SecurityLevel,
    pub attestation_challenge: Vec<u8>,
    pub unique_id: Vec<u8>,
    pub software_enforced: AuthorizationList,
    pub hardware_enforced: AuthorizationList,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
pub struct CRLStatus {
    pub status: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CRL {
    pub entries: HashMap<String, CRLStatus>
}