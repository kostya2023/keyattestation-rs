#[cfg(all(feature = "verify-sign", feature = "verify-sign-aws"))]
compile_error!(
    "Features 'verify' and 'verify-aws' are mutually exclusive and cannot be used at the same time. Choose one."
);

pub mod asn1;
pub mod domain;
pub mod error;
pub mod prelude;
pub mod services;

#[cfg(feature = "tests")]
pub mod tests;