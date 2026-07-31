use crate::domain::schemas::SecurityLevel;
use crate::error::KeyAttestationError;
use crate::services::attestation::Attestation;
use crate::services::constraints_verifiers::ConstraintsVerifier;

pub struct ConstraintsVerifierStrictForSecurityLevel {
    level: SecurityLevel
}

impl ConstraintsVerifierStrictForSecurityLevel {
    pub fn new(level: SecurityLevel) -> Self {
        Self { level }
    }
}

impl ConstraintsVerifier for ConstraintsVerifierStrictForSecurityLevel {
    fn verify(&self, attestation: &Attestation) -> Result<(), KeyAttestationError> {
        if attestation.key_description.attestation_security_level != self.level || attestation.key_description.key_mint_security_level != self.level {
            return Err(KeyAttestationError::ConstraintsVerifyError("Constraints verify error.".to_string()));
        }
        Ok(())
    }
}