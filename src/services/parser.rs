use crate::{
    asn1::schemas::{
        AttestationApplicationId as AttestationApplicationIdASN1,
        AttestationPackageInfo as AttestationPackageInfoASN1,
        AuthorizationList as AuthorizationListASN1, KeyDescription as KeyDescriptionASN1,
        ProvisioningInfoMap as ProvisioningInfoMapASN1, RootOfTrust as RootOfTrustASN1,
        SecurityLevel as SecurityLevelASN1, VerifiedBootState as VerifiedBootStateASN1,
    },
    domain::schemas::{
        AttestationApplicationId as AttestationApplicationIdDomain,
        AttestationPackageInfo as AttestationPackageInfoDomain,
        AuthorizationList as AuthorizationListDomain, KeyDescription as KeyDescriptionDomain,
        ProvisioningInfoMap as ProvisioningInfoMapDomain, RootOfTrust as RootOfTrustDomain,
        SecurityLevel as SecurityLevelDomain, VerifiedBootState as VerifiedBootStateDomain,
    },
    error::KeyAttestationError,
};
use num_traits::ToPrimitive;
use rasn::prelude::*;
use serde_cbor;

pub struct ParserASN2Domain;

impl ParserASN2Domain {
    pub fn parse_provisioning_info_map(
        provisioning_info_map: ProvisioningInfoMapASN1,
    ) -> Result<ProvisioningInfoMapDomain, KeyAttestationError> {
        provisioning_info_map.try_into()
    }

    pub fn parse_key_description(
        key_description: KeyDescriptionASN1,
    ) -> Result<KeyDescriptionDomain, KeyAttestationError> {
        key_description.try_into()
    }

    pub fn parse_authorization_list(
        authorization_list: AuthorizationListASN1,
    ) -> Result<AuthorizationListDomain, KeyAttestationError> {
        authorization_list.try_into()
    }

    pub fn parse_attestation_application_id(
        attestation_application_id: AttestationApplicationIdASN1,
    ) -> Result<AttestationApplicationIdDomain, KeyAttestationError> {
        attestation_application_id.try_into()
    }

    pub fn parse_attestation_package_info(
        attestation_package_info: AttestationPackageInfoASN1,
    ) -> Result<AttestationPackageInfoDomain, KeyAttestationError> {
        attestation_package_info.try_into()
    }

    pub fn parse_security_level(
        security_level: SecurityLevelASN1,
    ) -> Result<SecurityLevelDomain, KeyAttestationError> {
        security_level.try_into()
    }

    pub fn parse_verified_boot_state(
        verified_boot_state: VerifiedBootStateASN1,
    ) -> Result<VerifiedBootStateDomain, KeyAttestationError> {
        verified_boot_state.try_into()
    }
}

impl TryFrom<ProvisioningInfoMapASN1> for ProvisioningInfoMapDomain {
    type Error = KeyAttestationError;

    fn try_from(value: ProvisioningInfoMapASN1) -> Result<Self, Self::Error> {
        let bytes = value.0.to_vec();
        serde_cbor::from_slice(&bytes)
            .map_err(|e| KeyAttestationError::ConvertingASN1ToDomainError(e.to_string()))
    }
}

impl TryFrom<KeyDescriptionASN1> for KeyDescriptionDomain {
    type Error = KeyAttestationError;

    fn try_from(asn: KeyDescriptionASN1) -> Result<Self, Self::Error> {
        Ok(Self {
            attestation_version: integer_to_i64(&asn.attestation_version)?,
            attestation_security_level: asn.attestation_security_level.try_into()?,
            key_mint_version: integer_to_i64(&asn.key_mint_version)?,
            key_mint_security_level: asn.key_mint_security_level.try_into()?,
            attestation_challenge: asn.attestation_challenge.to_vec(),
            unique_id: asn.unique_id.to_vec(),
            software_enforced: asn.software_enforced.try_into()?,
            hardware_enforced: asn.hardware_enforced.try_into()?,
        })
    }
}

impl TryFrom<AuthorizationListASN1> for AuthorizationListDomain {
    type Error = KeyAttestationError;

    fn try_from(asn: AuthorizationListASN1) -> Result<Self, Self::Error> {
        Ok(Self {
            purpose: option_setof_integer_to_vec(&asn.purpose)?,
            algorithm: option_integer_to_i64(&asn.algorithm)?,
            key_size: option_integer_to_i64(&asn.key_size)?,
            block_mode: option_setof_integer_to_vec(&asn.block_mode)?,
            digest: option_setof_integer_to_vec(&asn.digest)?,
            padding: option_setof_integer_to_vec(&asn.padding)?,
            ec_curve: option_integer_to_i64(&asn.ec_curve)?,
            ml_dsa_variant: option_integer_to_i64(&asn.ml_dsa_variant)?,
            rsa_public_exponent: option_integer_to_i64(&asn.rsa_public_exponent)?,
            rsa_oaep_mgf_digest: option_setof_integer_to_vec(&asn.rsa_oaep_mgf_digest)?,
            active_date_time: option_integer_to_i64(&asn.active_date_time)?,
            origination_expire_date_time: option_integer_to_i64(&asn.origination_expire_date_time)?,
            usage_expire_date_time: option_integer_to_i64(&asn.usage_expire_date_time)?,
            usage_count_limit: option_integer_to_i64(&asn.usage_count_limit)?,
            no_auth_required: asn.no_auth_required,
            user_auth_type: option_integer_to_i64(&asn.user_auth_type)?,
            auth_timeout: option_integer_to_i64(&asn.auth_timeout)?,
            allow_while_on_body: asn.allow_while_on_body,
            trusted_user_presence_required: asn.trusted_user_presence_required,
            trusted_confirmation_required: asn.trusted_confirmation_required,
            unlocked_device_required: asn.unlocked_device_required,
            creation_date_time: option_integer_to_i64(&asn.creation_date_time)?,
            origin: option_integer_to_i64(&asn.origin)?,
            rollback_resistant: asn.rollback_resistant,
            root_of_trust: asn.root_of_trust.map(TryInto::try_into).transpose()?,
            os_version: option_integer_to_i64(&asn.os_version)?,
            os_patch_level: option_integer_to_i64(&asn.os_patch_level)?,
            attestation_application_id: asn
                .attestation_application_id
                .map(TryInto::try_into)
                .transpose()?,
            attestation_id_brand: asn.attestation_id_brand.map(|s| s.to_vec()),
            attestation_id_device: asn.attestation_id_device.map(|s| s.to_vec()),
            attestation_id_product: asn.attestation_id_product.map(|s| s.to_vec()),
            attestation_id_serial: asn.attestation_id_serial.map(|s| s.to_vec()),
            attestation_id_imei: asn.attestation_id_imei.map(|s| s.to_vec()),
            attestation_id_meid: asn.attestation_id_meid.map(|s| s.to_vec()),
            attestation_id_manufacturer: asn.attestation_id_manufacturer.map(|s| s.to_vec()),
            attestation_id_model: asn.attestation_id_model.map(|s| s.to_vec()),
            vendor_patch_level: option_integer_to_i64(&asn.vendor_patch_level)?,
            boot_patch_level: option_integer_to_i64(&asn.boot_patch_level)?,
            attestation_id_second_imei: asn.attestation_id_second_imei.map(|s| s.to_vec()),
            module_hash: asn.module_hash.map(|s| s.to_vec()),
        })
    }
}

impl TryFrom<AttestationApplicationIdASN1> for AttestationApplicationIdDomain {
    type Error = KeyAttestationError;

    fn try_from(asn: AttestationApplicationIdASN1) -> Result<Self, Self::Error> {
        let packages = asn
            .packages
            .to_vec()
            .into_iter()
            .map(|p| p.clone().try_into())
            .collect::<Result<Vec<_>, _>>()?;

        let signatures = asn
            .signatures
            .to_vec()
            .into_iter()
            .map(|s| s.to_vec())
            .collect();

        Ok(Self {
            packages,
            signatures,
        })
    }
}

impl TryFrom<AttestationPackageInfoASN1> for AttestationPackageInfoDomain {
    type Error = KeyAttestationError;

    fn try_from(asn: AttestationPackageInfoASN1) -> Result<Self, Self::Error> {
        let name = String::from_utf8(asn.name.to_vec())
            .map_err(|e| KeyAttestationError::ConvertingASN1ToDomainError(e.to_string()))?;
        let version = integer_to_i64(&asn.version)?;

        Ok(Self { name, version })
    }
}

impl TryFrom<RootOfTrustASN1> for RootOfTrustDomain {
    type Error = KeyAttestationError;

    fn try_from(asn: RootOfTrustASN1) -> Result<Self, Self::Error> {
        Ok(Self {
            verified_boot_key: asn.verified_boot_key.to_vec(),
            device_locked: asn.device_locked,
            verified_boot_state: asn.verified_boot_state.try_into()?,
            verified_boot_hash: asn.verified_boot_hash.map(|s| s.to_vec()),
        })
    }
}

impl TryFrom<SecurityLevelASN1> for SecurityLevelDomain {
    type Error = KeyAttestationError;

    fn try_from(asn: SecurityLevelASN1) -> Result<Self, Self::Error> {
        match asn {
            SecurityLevelASN1::Software => Ok(SecurityLevelDomain::Software),
            SecurityLevelASN1::TrustedEnvironment => Ok(SecurityLevelDomain::TrustedEnvironment),
            SecurityLevelASN1::StrongBox => Ok(SecurityLevelDomain::StrongBox),
        }
    }
}

impl TryFrom<VerifiedBootStateASN1> for VerifiedBootStateDomain {
    type Error = KeyAttestationError;

    fn try_from(asn: VerifiedBootStateASN1) -> Result<Self, Self::Error> {
        match asn {
            VerifiedBootStateASN1::Verified => Ok(VerifiedBootStateDomain::Verified),
            VerifiedBootStateASN1::SelfSigned => Ok(VerifiedBootStateDomain::SelfSigned),
            VerifiedBootStateASN1::Unverified => Ok(VerifiedBootStateDomain::Unverified),
            VerifiedBootStateASN1::Failed => Ok(VerifiedBootStateDomain::Failed),
        }
    }
}

fn integer_to_i64(integer: &Integer) -> Result<i64, KeyAttestationError> {
    integer.to_i64().ok_or_else(|| {
        KeyAttestationError::ConvertingASN1ToDomainError(
            "Unable to convert Integer to i64!".to_string(),
        )
    })
}

fn option_integer_to_i64(data: &Option<Integer>) -> Result<Option<i64>, KeyAttestationError> {
    data.as_ref().map(integer_to_i64).transpose()
}

fn option_setof_integer_to_vec(
    data: &Option<SetOf<Integer>>,
) -> Result<Option<Vec<i64>>, KeyAttestationError> {
    data.as_ref()
        .map(|set| {
            set.to_vec()
                .into_iter()
                .map(|i| integer_to_i64(i))
                .collect::<Result<Vec<i64>, _>>()
        })
        .transpose()
}

pub struct ParserDN2String;

impl ParserDN2String {
    pub fn parse(dn: &str) -> (Option<&str>, Option<&str>) {
        let mut serial = None;
        let mut title = None;

        for part in dn.split(',') {
            let mut parts = part.splitn(2, '=');
            if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                match key {
                    "SERIALNUMBER" => serial = Some(value),
                    "TITLE" => title = Some(value),
                    _ => {}
                }
            }
        }

        (serial, title)
    }
}