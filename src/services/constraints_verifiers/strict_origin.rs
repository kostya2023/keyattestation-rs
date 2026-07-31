use crate::error::KeyAttestationError;
use crate::services::attestation::Attestation;
use crate::services::constraints_verifiers::ConstraintsVerifier;

pub struct ConstraintsVerifierStrictForOrigin {
    origin: i64
}

impl ConstraintsVerifierStrictForOrigin {
    pub fn new(origin: i64) -> Self {
        Self { origin }
    }
}

impl ConstraintsVerifier for ConstraintsVerifierStrictForOrigin {
    fn verify(&self, attestation: &Attestation) -> Result<(), KeyAttestationError> {
        if let Some(origin) = attestation.key_description.software_enforced.origin {
            if origin != self.origin {
                return Err(KeyAttestationError::ConstraintsVerifyError("Constraints verify error.".to_string()));
            }
        }

        if let Some(origin) = attestation.key_description.hardware_enforced.origin {
            if origin != self.origin {
                return Err(KeyAttestationError::ConstraintsVerifyError("Constraints verify error.".to_string()));
            }
        }

        Ok(())
    }
}