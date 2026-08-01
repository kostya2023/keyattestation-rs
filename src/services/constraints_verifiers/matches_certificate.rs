use crate::domain::schemas::SecurityLevel;
use crate::error::KeyAttestationError;
use crate::services::attestation::Attestation;
use crate::services::constraints_verifiers::ConstraintsVerifier;
use crate::services::parser::ParserDN2String;

pub struct ConstraintVerifierMatchesCertificate;

impl ConstraintsVerifier for ConstraintVerifierMatchesCertificate {
    fn verify(&self, attestation: &Attestation) -> Result<(), KeyAttestationError> {
        let subject = attestation.chain.target_cert.subject().to_string();
        let (_, security_level) = ParserDN2String::parse(&subject);
        let security_level = security_level.ok_or_else(|| {
            KeyAttestationError::ConstraintsVerifyError("Constraints verify error.".to_string())
        })?;

        let security_level = match security_level {
            "SOFTWARE" => Ok(SecurityLevel::Software),
            "TEE" => Ok(SecurityLevel::TrustedEnvironment),
            "STRONGBOX" => Ok(SecurityLevel::StrongBox),
            _ => Err(KeyAttestationError::ConstraintsVerifyError(
                "Constraints verify error.".to_string(),
            )),
        }?;

        if attestation.key_description.attestation_security_level != security_level
            || attestation.key_description.key_mint_security_level != security_level
        {
            return Err(KeyAttestationError::ConstraintsVerifyError(
                "Constraints verify error.".to_string(),
            ));
        }

        Ok(())
    }
}
