// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Result};
use const_oid::AssociatedOid;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signature::Keypair;
use spki::{
    AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, EncodePublicKey, ObjectIdentifier,
    SignatureBitStringEncoding, SubjectPublicKeyInfoOwned,
};
use std::str::FromStr;
use x509_cert::builder::{Builder, RequestBuilder};
use x509_cert::der::asn1::{BitString, OctetString};
use x509_cert::der::{Encode, FixedTag, Tag};
use x509_cert::ext::pkix::SubjectKeyIdentifier;
use x509_cert::ext::{AsExtension, Extension};
use x509_cert::name::Name;
use zeroize::Zeroizing;

const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// Wrapper to implement x509-cert builder traits for VerifyingKey.
#[derive(Clone, Debug)]
pub struct CPoPVerifyingKey(pub VerifyingKey);

impl EncodePublicKey for CPoPVerifyingKey {
    fn to_public_key_der(&self) -> spki::Result<spki::der::Document> {
        let spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: ED25519_OID,
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(self.0.as_bytes())?,
        };
        let der = spki.to_der().map_err(|_| spki::Error::KeyMalformed)?;
        spki::der::Document::try_from(der.as_slice()).map_err(|_| spki::Error::KeyMalformed)
    }
}

/// Wrapper to implement x509-cert builder traits for SigningKey.
pub struct CPoPSigner(pub SigningKey);

impl Keypair for CPoPSigner {
    type VerifyingKey = CPoPVerifyingKey;
    fn verifying_key(&self) -> Self::VerifyingKey {
        CPoPVerifyingKey(self.0.verifying_key())
    }
}

impl DynSignatureAlgorithmIdentifier for CPoPSigner {
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        Ok(AlgorithmIdentifierOwned {
            oid: ED25519_OID,
            parameters: None,
        })
    }
}

/// Newtype wrapper over Ed25519 signature for `SignatureBitStringEncoding` (orphan rule).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CPoPSignature(pub ed25519_dalek::Signature);

impl signature::SignatureEncoding for CPoPSignature {
    type Repr = [u8; 64];
    fn to_bytes(&self) -> Self::Repr {
        self.0.to_bytes()
    }
}

impl TryFrom<&[u8]> for CPoPSignature {
    type Error = signature::Error;
    fn try_from(bytes: &[u8]) -> std::result::Result<Self, Self::Error> {
        ed25519_dalek::Signature::from_slice(bytes)
            .map(CPoPSignature)
            .map_err(|_| signature::Error::new())
    }
}

impl From<CPoPSignature> for [u8; 64] {
    fn from(sig: CPoPSignature) -> Self {
        sig.0.to_bytes()
    }
}

impl Signer<CPoPSignature> for CPoPSigner {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<CPoPSignature, signature::Error> {
        Ok(CPoPSignature(self.0.sign(msg)))
    }
}

impl SignatureBitStringEncoding for CPoPSignature {
    fn to_bitstring(&self) -> std::result::Result<BitString, x509_cert::der::Error> {
        BitString::from_bytes(&self.0.to_bytes())
    }
}

/// X.509 extension for CPoP capability (OID 1.3.6.1.4.1.54066.1.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CPoPCapability(pub OctetString);

impl AssociatedOid for CPoPCapability {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.54066.1.1");
}

impl Encode for CPoPCapability {
    fn encoded_len(&self) -> x509_cert::der::Result<x509_cert::der::Length> {
        self.0.encoded_len()
    }
    fn encode(&self, encoder: &mut impl x509_cert::der::Writer) -> x509_cert::der::Result<()> {
        self.0.encode(encoder)
    }
}

impl FixedTag for CPoPCapability {
    const TAG: Tag = Tag::OctetString;
}

impl AsExtension for CPoPCapability {
    fn critical(&self, _: &x509_cert::name::RdnSequence, _: &[Extension]) -> bool {
        false
    }
}

/// Request payload for enrolling a new CPoP identity with a verifier.
#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    /// User-chosen identifier.
    pub user_id: String,
    /// COSE-encoded Ed25519 public key bytes.
    pub public_key_cose: Vec<u8>,
    /// TPM quote or Secure Enclave blob; empty for software-only.
    pub hardware_attestation: Vec<u8>,
}

/// Manage CPoP signing identity: key generation, CSR creation, and enrollment.
pub struct IdentityManager {
    signer: CPoPSigner,
}

impl IdentityManager {
    /// Generate a new random Ed25519 signing identity.
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(bytes.as_mut());
        Self {
            signer: CPoPSigner(SigningKey::from_bytes(&bytes)),
        }
    }

    /// Restore an identity from a 32-byte Ed25519 secret key.
    pub fn from_secret_key(bytes: &[u8; 32]) -> Self {
        Self {
            signer: CPoPSigner(SigningKey::from_bytes(bytes)),
        }
    }

    /// Return a reference to the underlying Ed25519 signing key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signer.0
    }

    /// Generate a DER-encoded X.509 CSR with SKI and CPoP capability extensions.
    pub fn generate_csr(&self, subject_dn: &str) -> Result<Vec<u8>> {
        let subject = Name::from_str(subject_dn)
            .map_err(|e| Error::Validation(format!("Invalid Subject DN: {}", e)))?;

        let mut builder = RequestBuilder::new(subject, &self.signer)
            .map_err(|e| Error::Crypto(format!("CSR builder error: {}", e)))?;

        let public_key_bytes = self.signer.0.verifying_key().to_bytes();
        let hash = Sha256::digest(public_key_bytes);
        let ski = SubjectKeyIdentifier(
            OctetString::new(hash.to_vec())
                .map_err(|e| Error::Crypto(format!("Failed to create OctetString: {}", e)))?,
        );
        builder
            .add_extension(&ski)
            .map_err(|e| Error::Crypto(format!("Failed to add SKI extension: {}", e)))?;

        let pop_cap =
            CPoPCapability(OctetString::new(vec![0x01]).map_err(|e| Error::Crypto(e.to_string()))?);
        builder
            .add_extension(&pop_cap)
            .map_err(|e| Error::Crypto(format!("Failed to add CPoP extension: {}", e)))?;

        let csr = builder
            .build::<CPoPSignature>()
            .map_err(|e| Error::Crypto(format!("CSR signing error: {}", e)))?;

        csr.to_der()
            .map_err(|e| Error::Crypto(format!("DER encoding error: {}", e)))
    }

    /// `hardware_attestation`: TPM quote or Secure Enclave blob; empty for software-only.
    pub fn create_enrollment_request(
        &self,
        user_id: &str,
        hardware_attestation: &[u8],
    ) -> Result<EnrollmentRequest> {
        let public_key_cose = self.signer.0.verifying_key().to_bytes().to_vec();

        Ok(EnrollmentRequest {
            user_id: user_id.to_string(),
            public_key_cose,
            hardware_attestation: hardware_attestation.to_vec(),
        })
    }
}
