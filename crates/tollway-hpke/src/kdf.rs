use crate::error::HpkeError;

pub trait KdfAlgorithm {
    fn extract(salt: &[u8], ikm: &[u8], prk_out: &mut [u8]) -> Result<(), HpkeError>;
    fn expand(prk: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), HpkeError>;

    fn labeled_extract(
        salt: &[u8],
        suite_id: &[u8],
        label: &[u8],
        ikm: &[u8],
        prk_out: &mut [u8],
    ) -> Result<(), HpkeError>;

    fn labeled_expand(
        prk: &[u8],
        suite_id: &[u8],
        label: &[u8],
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), HpkeError>;
}

// RFC 9180 maximum length assumptions for pure HPKE
// Suite ID: "KEM" (2) + "KDF" (2) + "AEAD" (2) = 6 bytes.
// Labels: e.g., "secret", "info_hash", "key", "base_nonce" (max ~10 bytes).
// IKM: usually the size of the KEM Shared Secret (32 bytes).
// Info: application-specific context (we cap to 256 for no-std stack safety).
const SUITE_ID_MAX_LEN: usize = 10;
const LABEL_MAX_LEN: usize = 32;
const IKM_MAX_LEN: usize = 128; // Covers typical SS up to 1024-bit output
const INFO_MAX_LEN: usize = 256;

const MAX_LABELED_IKM: usize = 7 + SUITE_ID_MAX_LEN + LABEL_MAX_LEN + IKM_MAX_LEN;
const MAX_LABELED_INFO: usize = 2 + 7 + SUITE_ID_MAX_LEN + LABEL_MAX_LEN + INFO_MAX_LEN;

// A standard HkdfSha256 impl utilizing rustcrypto hkdf.
pub struct HkdfSha256;

impl KdfAlgorithm for HkdfSha256 {
    fn extract(salt: &[u8], ikm: &[u8], prk_out: &mut [u8]) -> Result<(), HpkeError> {
        let (prk, _) = hkdf::Hkdf::<sha2::Sha256>::extract(Some(salt), ikm);
        if prk_out.len() < prk.len() {
            prk_out.copy_from_slice(&prk[..prk_out.len()]);
        } else {
            prk_out[..prk.len()].copy_from_slice(&prk);
        }
        Ok(())
    }

    fn expand(prk: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), HpkeError> {
        let hk = hkdf::Hkdf::<sha2::Sha256>::from_prk(prk).map_err(|_| HpkeError::KdfError)?;
        hk.expand(info, out).map_err(|_| HpkeError::KdfError)
    }

    fn labeled_extract(
        salt: &[u8],
        suite_id: &[u8],
        label: &[u8],
        ikm: &[u8],
        prk_out: &mut [u8],
    ) -> Result<(), HpkeError> {
        let total_len = 7 + suite_id.len() + label.len() + ikm.len();
        if total_len > MAX_LABELED_IKM {
            return Err(HpkeError::BufferTooSmall);
        }

        // RFC 9180 LabeledExtract
        // labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
        let mut labeled_ikm = [0u8; MAX_LABELED_IKM]; // Bound mathematically by documented protocol limits
        let mut offset = 0;

        labeled_ikm[offset..offset + 7].copy_from_slice(b"HPKE-v1");
        offset += 7;

        labeled_ikm[offset..offset + suite_id.len()].copy_from_slice(suite_id);
        offset += suite_id.len();

        labeled_ikm[offset..offset + label.len()].copy_from_slice(label);
        offset += label.len();

        labeled_ikm[offset..offset + ikm.len()].copy_from_slice(ikm);
        offset += ikm.len();

        Self::extract(salt, &labeled_ikm[..offset], prk_out)
    }

    fn labeled_expand(
        prk: &[u8],
        suite_id: &[u8],
        label: &[u8],
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), HpkeError> {
        let total_len = 2 + 7 + suite_id.len() + label.len() + info.len();
        if total_len > MAX_LABELED_INFO {
            return Err(HpkeError::BufferTooSmall);
        }

        // RFC 9180 LabeledExpand
        // labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id, label, info)
        let mut labeled_info = [0u8; MAX_LABELED_INFO]; // Bound mathematically by documented protocol limits
        let mut offset = 0;

        let l = out.len() as u16;
        labeled_info[offset..offset + 2].copy_from_slice(&l.to_be_bytes());
        offset += 2;

        labeled_info[offset..offset + 7].copy_from_slice(b"HPKE-v1");
        offset += 7;

        labeled_info[offset..offset + suite_id.len()].copy_from_slice(suite_id);
        offset += suite_id.len();

        labeled_info[offset..offset + label.len()].copy_from_slice(label);
        offset += label.len();

        labeled_info[offset..offset + info.len()].copy_from_slice(info);
        offset += info.len();

        Self::expand(prk, &labeled_info[..offset], out)
    }
}
