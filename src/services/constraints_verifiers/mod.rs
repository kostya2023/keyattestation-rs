pub mod matches_certificate;
pub mod not_software;
pub mod strict_for_security_level;
pub mod strict_origin;

use crate::error::KeyAttestationError;
use crate::services::attestation::Attestation;

pub trait ConstraintsVerifier {
    fn verify(&self, attestation: &Attestation) -> Result<(), KeyAttestationError>;
}
