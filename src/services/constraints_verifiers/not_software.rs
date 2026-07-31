use crate::domain::schemas::SecurityLevel;
use crate::error::KeyAttestationError;
use crate::services::attestation::Attestation;
use crate::services::constraints_verifiers::ConstraintsVerifier;

pub struct ConstraintVerifierNotSoftware;

impl ConstraintsVerifier for ConstraintVerifierNotSoftware {
    fn verify(&self, attestation: &Attestation) -> Result<(), KeyAttestationError> {
        if attestation.key_description.attestation_security_level == SecurityLevel::Software || attestation.key_description.key_mint_security_level == SecurityLevel::Software {
            return Err(KeyAttestationError::ConstraintsVerifyError("Constraints verify error.".to_string()));
        }
        Ok(())
    }
}