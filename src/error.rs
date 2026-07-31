use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyAttestationError {
    #[error("Converting ASN.1 to domain error: {0}")]
    ConvertingASN1ToDomainError(String),

    #[error("Certificate chain error: {0}")]
    CertificateChainError(String),

    #[error("Attestation error: {0}")]
    AttestationError(String),

    #[error("Constraints verify error: {0}")]
    ConstraintsVerifyError(String),
}
