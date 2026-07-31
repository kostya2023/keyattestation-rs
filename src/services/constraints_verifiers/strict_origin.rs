use crate::error::KeyAttestationError;
use crate::services::attestation::Attestation;
use crate::services::constraints_verifiers::ConstraintsVerifier;

pub struct ConstraintVerifierStrictForOrigin {
    origin: i64
}

impl ConstraintVerifierStrictForOrigin {
    pub fn new(origin: i64) -> Self {
        Self { origin }
    }
}

impl ConstraintsVerifier for ConstraintVerifierStrictForOrigin {
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