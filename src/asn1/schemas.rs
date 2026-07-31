use rasn::prelude::*;

#[derive(AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct ProvisioningInfoMap(pub OctetString);

#[derive(AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Hash)]
pub struct AttestationPackageInfo {
    pub name: OctetString,
    pub version: Integer,
}

#[derive(AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Hash)]
pub struct AttestationApplicationId {
    pub packages: SetOf<AttestationPackageInfo>,
    pub signatures: SetOf<OctetString>,
}

#[derive(AsnType, Decode, Encode, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[rasn(enumerated)]
pub enum SecurityLevel {
    Software = 0,
    TrustedEnvironment = 1,
    StrongBox = 2,
}

#[derive(AsnType, Decode, Encode, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[rasn(enumerated)]
pub enum VerifiedBootState {
    Verified = 0,
    SelfSigned = 1,
    Unverified = 2,
    Failed = 3,
}

#[derive(AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Hash)]
pub struct RootOfTrust {
    #[rasn(identifier = "verifiedBootKey")]
    pub verified_boot_key: OctetString,
    #[rasn(identifier = "deviceLocked")]
    pub device_locked: bool,
    #[rasn(identifier = "verifiedBootState")]
    pub verified_boot_state: VerifiedBootState,
    #[rasn(identifier = "verifiedBootHash")]
    pub verified_boot_hash: Option<OctetString>,
}

#[derive(AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthorizationList {
    #[rasn(tag(explicit(context, 1)))]
    pub purpose: Option<SetOf<Integer>>,
    #[rasn(tag(explicit(context, 2)))]
    pub algorithm: Option<Integer>,
    #[rasn(tag(explicit(context, 3)), identifier = "keySize")]
    pub key_size: Option<Integer>,
    #[rasn(tag(explicit(context, 4)), identifier = "blockMode")]
    pub block_mode: Option<SetOf<Integer>>,
    #[rasn(tag(explicit(context, 5)))]
    pub digest: Option<SetOf<Integer>>,
    #[rasn(tag(explicit(context, 6)))]
    pub padding: Option<SetOf<Integer>>,
    #[rasn(tag(explicit(context, 10)), identifier = "ecCurve")]
    pub ec_curve: Option<Integer>,
    #[rasn(tag(explicit(context, 11)), identifier = "mlDsaVariant")]
    pub ml_dsa_variant: Option<Integer>,
    #[rasn(tag(explicit(context, 200)), identifier = "rsaPublicExponent")]
    pub rsa_public_exponent: Option<Integer>,
    #[rasn(tag(explicit(context, 203)), identifier = "rsaOaepMgfDigest")]
    pub rsa_oaep_mgf_digest: Option<SetOf<Integer>>,
    #[rasn(tag(explicit(context, 400)), identifier = "activeDateTime")]
    pub active_date_time: Option<Integer>,
    #[rasn(tag(explicit(context, 401)), identifier = "originationExpireDateTime")]
    pub origination_expire_date_time: Option<Integer>,
    #[rasn(tag(explicit(context, 402)), identifier = "usageExpireDateTime")]
    pub usage_expire_date_time: Option<Integer>,
    #[rasn(tag(explicit(context, 405)), identifier = "usageCountLimit")]
    pub usage_count_limit: Option<Integer>,
    #[rasn(tag(explicit(context, 503)), identifier = "noAuthRequired")]
    pub no_auth_required: Option<()>,
    #[rasn(tag(explicit(context, 504)), identifier = "userAuthType")]
    pub user_auth_type: Option<Integer>,
    #[rasn(tag(explicit(context, 505)), identifier = "authTimeout")]
    pub auth_timeout: Option<Integer>,
    #[rasn(tag(explicit(context, 506)), identifier = "allowWhileOnBody")]
    pub allow_while_on_body: Option<()>,
    #[rasn(
        tag(explicit(context, 507)),
        identifier = "trustedUserPresenceRequired"
    )]
    pub trusted_user_presence_required: Option<()>,
    #[rasn(
        tag(explicit(context, 508)),
        identifier = "trustedConfirmationRequired"
    )]
    pub trusted_confirmation_required: Option<()>,
    #[rasn(tag(explicit(context, 509)), identifier = "unlockedDeviceRequired")]
    pub unlocked_device_required: Option<()>,
    #[rasn(tag(explicit(context, 701)), identifier = "creationDateTime")]
    pub creation_date_time: Option<Integer>,
    #[rasn(tag(explicit(context, 702)))]
    pub origin: Option<Integer>,
    #[rasn(tag(explicit(context, 703)), identifier = "rollbackResistant")]
    pub rollback_resistant: Option<()>,
    #[rasn(tag(explicit(context, 704)), identifier = "rootOfTrust")]
    pub root_of_trust: Option<RootOfTrust>,
    #[rasn(tag(explicit(context, 705)), identifier = "osVersion")]
    pub os_version: Option<Integer>,
    #[rasn(tag(explicit(context, 706)), identifier = "osPatchLevel")]
    pub os_patch_level: Option<Integer>,
    #[rasn(tag(explicit(context, 709)), identifier = "attestationApplicationId")]
    pub attestation_application_id: Option<AttestationApplicationId>,
    #[rasn(tag(explicit(context, 710)), identifier = "attestationIdBrand")]
    pub attestation_id_brand: Option<OctetString>,
    #[rasn(tag(explicit(context, 711)), identifier = "attestationIdDevice")]
    pub attestation_id_device: Option<OctetString>,
    #[rasn(tag(explicit(context, 712)), identifier = "attestationIdProduct")]
    pub attestation_id_product: Option<OctetString>,
    #[rasn(tag(explicit(context, 713)), identifier = "attestationIdSerial")]
    pub attestation_id_serial: Option<OctetString>,
    #[rasn(tag(explicit(context, 714)), identifier = "attestationIdImei")]
    pub attestation_id_imei: Option<OctetString>,
    #[rasn(tag(explicit(context, 715)), identifier = "attestationIdMeid")]
    pub attestation_id_meid: Option<OctetString>,
    #[rasn(tag(explicit(context, 716)), identifier = "attestationIdManufacturer")]
    pub attestation_id_manufacturer: Option<OctetString>,
    #[rasn(tag(explicit(context, 717)), identifier = "attestationIdModel")]
    pub attestation_id_model: Option<OctetString>,
    #[rasn(tag(explicit(context, 718)), identifier = "vendorPatchLevel")]
    pub vendor_patch_level: Option<Integer>,
    #[rasn(tag(explicit(context, 719)), identifier = "bootPatchLevel")]
    pub boot_patch_level: Option<Integer>,
    #[rasn(tag(explicit(context, 723)), identifier = "attestationIdSecondImei")]
    pub attestation_id_second_imei: Option<OctetString>,
    #[rasn(tag(explicit(context, 724)), identifier = "moduleHash")]
    pub module_hash: Option<OctetString>,
}

#[derive(AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyDescription {
    #[rasn(identifier = "attestationVersion")]
    pub attestation_version: Integer,
    #[rasn(identifier = "attestationSecurityLevel")]
    pub attestation_security_level: SecurityLevel,
    #[rasn(identifier = "keyMintVersion")]
    pub key_mint_version: Integer,
    #[rasn(identifier = "keyMintSecurityLevel")]
    pub key_mint_security_level: SecurityLevel,
    #[rasn(identifier = "attestationChallenge")]
    pub attestation_challenge: OctetString,
    #[rasn(identifier = "uniqueId")]
    pub unique_id: OctetString,
    #[rasn(identifier = "softwareEnforced")]
    pub software_enforced: AuthorizationList,
    #[rasn(identifier = "hardwareEnforced")]
    pub hardware_enforced: AuthorizationList,
}
