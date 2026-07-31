use crate::error::KeyAttestationError;
use crate::{
    asn1::{
        oids::{
            KEY_DESCRIPTION_OID,
            PROVISIONING_INFO_MAP_OID,
        },
        schemas::{
            KeyDescription as KeyDescriptionASN1,
            ProvisioningInfoMap as ProvisioningInfoMapASN1,
        },
    },
    domain::schemas::{
        KeyDescription as KeyDescriptionDomain,
        ProvisioningInfoMap as ProvisioningInfoMapDomain,
    }
};
use rasn::der;
use std::time::SystemTime;
use crate::services::chain::CertificateChain;
use crate::services::constraints_verifiers::ConstraintsVerifier;

#[derive(Debug, Clone, PartialEq)]
pub struct Attestation<'attest> {
    pub chain: CertificateChain<'attest>,
    pub key_description: KeyDescriptionDomain,
    pub provisioning_info_map: Option<ProvisioningInfoMapDomain>,
}

impl<'attest> Attestation<'attest> {
    pub fn new(
        chain: CertificateChain<'attest>
    ) -> Result<Self, KeyAttestationError> {
        let extensions = chain.target_cert.extensions();        

        let key_description = extensions
            .iter()
            .find(|ext| ext.oid.to_id_string() == KEY_DESCRIPTION_OID)
            .ok_or_else(|| KeyAttestationError::AttestationError("KeyDescription extension not found.".to_string()))
            .and_then(|ext| {
                let asn: KeyDescriptionASN1 = der::decode(ext.value)
                    .map_err(|_| KeyAttestationError::AttestationError("KeyDescription parsing error.".to_string()))?;
                asn.try_into()
            })?;

        let provisioning_info_map = extensions
            .iter()
            .find(|ext| ext.oid.to_id_string() == PROVISIONING_INFO_MAP_OID)
            .map(|ext| {
                let asn: ProvisioningInfoMapASN1 = der::decode(ext.value)
                    .map_err(|e| KeyAttestationError::AttestationError(e.to_string()))?;
                let domain: ProvisioningInfoMapDomain = asn.try_into()?;
                Ok(domain)
            })
            .transpose()?;

        Ok(Self {
            chain,
            key_description,
            provisioning_info_map,
        })
    }

    pub fn verify(&self, challenge: &[u8], constraints_for_verify: Option<Vec<Box<dyn ConstraintsVerifier>>>) -> Result<(), KeyAttestationError> {
        #[cfg(any(feature = "verify", feature = "verify-aws"))]
        self.chain.verify_signatures()?;
        self.chain.verify_issuer()?;
        self.chain.verify_time(SystemTime::now())?;

        if self.key_description.attestation_challenge != challenge {
            return Err(KeyAttestationError::AttestationError("Attestation verify error.".to_string()));
        } 

        if let Some(constraints) = constraints_for_verify {
            for constraint in constraints {
                constraint.verify(self)?;
            }
        }
        Ok(())
    }
}