use crate::error::KeyAttestationError;
use crate::domain::schemas::CRL;
use std::time::SystemTime;
use x509_parser::{
    asn1_rs::FromDer, 
    certificate::X509Certificate
};
use hex::encode;

#[derive(Debug, Clone, PartialEq)]
pub struct CertificateChain<'chain> {
    pub target_cert: X509Certificate<'chain>,
    pub middle_certs: Vec<X509Certificate<'chain>>,
    pub root_cert: X509Certificate<'chain>,
}

impl<'chain> CertificateChain<'chain> {
    pub fn from_ders(
        target_cert: &'chain [u8],
        middle_certs: &[&'chain [u8]],
        root_cert: &'chain [u8],
    ) -> Result<Self, KeyAttestationError> {
        let (_, target_cert_parsed) = X509Certificate::from_der(target_cert).map_err(|_| {
            KeyAttestationError::CertificateChainError("Error parsing cert.".to_string())
        })?;

        let (_, root_cert_parsed) = X509Certificate::from_der(root_cert).map_err(|_| {
            KeyAttestationError::CertificateChainError("Error parsing cert.".to_string())
        })?;

        let middle_certs_parsed: Result<Vec<X509Certificate<'chain>>, KeyAttestationError> =
            middle_certs
                .iter()
                .map(|cert| {
                    X509Certificate::from_der(cert)
                        .map(|(_, parsed_cert)| parsed_cert)
                        .map_err(|_| {
                            KeyAttestationError::CertificateChainError(
                                "Error parsing cert.".to_string(),
                            )
                        })
                })
                .collect();
        let middle_certs_parsed = middle_certs_parsed?;

        Ok(Self {
            target_cert: target_cert_parsed,
            middle_certs: middle_certs_parsed,
            root_cert: root_cert_parsed,
        })
    }

    #[cfg(any(feature = "verify", feature = "verify-aws"))]
    pub fn verify_signatures(&self) -> Result<(), KeyAttestationError> {
        self.root_cert
            .verify_signature(Some(&self.root_cert.subject_pki))
            .map_err(|_| {
                KeyAttestationError::CertificateChainError("Verify chain error.".to_string())
            })?;

        match self.middle_certs.len() {
            0 => {
                self.target_cert
                    .verify_signature(Some(&self.root_cert.subject_pki))
                    .map_err(|_| {
                        KeyAttestationError::CertificateChainError(
                            "Verify chain error.".to_string(),
                        )
                    })?;
            }
            1 => {
                self.target_cert
                    .verify_signature(Some(&self.middle_certs[0].subject_pki))
                    .map_err(|_| {
                        KeyAttestationError::CertificateChainError(
                            "Verify chain error.".to_string(),
                        )
                    })?;

                self.middle_certs[0]
                    .verify_signature(Some(&self.root_cert.subject_pki))
                    .map_err(|_| {
                        KeyAttestationError::CertificateChainError(
                            "Verify chain error.".to_string(),
                        )
                    })?;
            }
            _ => {
                self.target_cert
                    .verify_signature(Some(&self.middle_certs[0].subject_pki))
                    .map_err(|_| {
                        KeyAttestationError::CertificateChainError(
                            "Verify chain error.".to_string(),
                        )
                    })?;

                for window in self.middle_certs.windows(2) {
                    let child = &window[0];
                    let parent = &window[1];

                    child
                        .verify_signature(Some(&parent.subject_pki))
                        .map_err(|_| {
                            KeyAttestationError::CertificateChainError(
                                "Verify chain error.".to_string(),
                            )
                        })?;
                }

                self.middle_certs
                    .last()
                    .unwrap()
                    .verify_signature(Some(&self.root_cert.subject_pki))
                    .map_err(|_| {
                        KeyAttestationError::CertificateChainError(
                            "Verify chain error.".to_string(),
                        )
                    })?;
            }
        }

        Ok(())
    }

    pub fn verify_time(&self, now: SystemTime) -> Result<(), KeyAttestationError> {
        let certs = std::iter::once(&self.target_cert)
            .chain(self.middle_certs.iter())
            .chain(std::iter::once(&self.root_cert));

        for cert in certs {
            let validity = cert.validity();

            let not_before = validity.not_before.to_datetime();
            let not_after = validity.not_after.to_datetime();

            if now < not_before || now > not_after {
                return Err(KeyAttestationError::CertificateChainError(
                    "Verify chain error.".to_string(),
                ));
            }
        }

        Ok(())
    }

    pub fn verify_issuer(&self) -> Result<(), KeyAttestationError> {
        let certs = std::iter::once(&self.target_cert)
            .chain(self.middle_certs.iter())
            .chain(std::iter::once(&self.root_cert))
            .collect::<Vec<_>>();

        for window in certs.windows(2) {
            let child = window[0];
            let parent = window[1];

            let child_issuer = child.issuer();
            let parent_subject = parent.subject();

            if child_issuer != parent_subject {
                return Err(KeyAttestationError::CertificateChainError(
                    "Verify chain error.".to_string(),
                ));
            }
        }

        let root_issuer = self.root_cert.issuer();
        let root_subject = self.root_cert.subject();

        if root_issuer != root_subject {
            return Err(KeyAttestationError::CertificateChainError(
                "Verify chain error.".to_string(),
            ));
        }

        Ok(())
    }

    #[cfg(feature = "verify-crl")]
    fn user_agent() -> String {
        format!(
            "keyattestation-rs/{} (https://github.com/kostya2023/keyattestation-rs)",
            env!("CARGO_PKG_VERSION"),
        )
    }

    #[cfg(feature = "verify-crl")]
    pub fn verify_crl(&self) -> Result<(), KeyAttestationError> {
        use reqwest::blocking::Client;
        use std::time::Duration;

        let url = "https://android.googleapis.com/attestation/status";

        let client = Client::builder()
            .user_agent(Self::user_agent())
            .connect_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|_| KeyAttestationError::CertificateChainError("Verify chain error.".to_string()))?;

        let crl: CRL = client
            .get(url)
            .send()
            .map_err(|_| KeyAttestationError::CertificateChainError("Verify chain error.".to_string()))?
            .json()
            .map_err(|_| KeyAttestationError::CertificateChainError("Verify chain error.".to_string()))?;

        self.verify_crl_with(&crl)?;

        Ok(())
    }

    pub fn verify_crl_with(&self, crl: &CRL) -> Result<(), KeyAttestationError> {
        let full_serials: Vec<String> = self.middle_certs
            .iter()
            .map(|cert| encode(cert.raw_serial()))
            .chain(std::iter::once(encode(self.target_cert.raw_serial())))
            .chain(std::iter::once(encode(self.root_cert.raw_serial())))
            .collect();

        for serial in full_serials {
            if let Some(status) = crl.entries.get(&serial) {
                if status.status == "REVOKED" {
                    return Err(KeyAttestationError::CertificateChainError(
                        "Verify chain error.".to_string()
                    ));
                }
            }
        }

        Ok(())
    }
}
