//! Authenticode verification: embedded signature first, then the Windows catalog
//! database (how ntdll.dll and most in-box binaries are signed).
//!
//! Policy is offline: cached URL retrieval only, no live revocation check. A valid
//! result means "chains to a trusted root under that policy", nothing more.

use crate::winutil::{OwnedHandle, from_wide, wide};
use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Security::Cryptography::CertGetNameStringW;
use windows_sys::Win32::Security::Cryptography::Catalog::*;
use windows_sys::Win32::Security::WinTrust::*;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureState {
    /// An embedded or catalog signature verified under offline policy.
    Valid,
    /// Neither an embedded signature nor a catalog entry was found.
    Unsigned,
    /// Signed, but the certificate is not trusted: self-signed, expired, or an
    /// unknown root. No assurance, but no sign of tampering either.
    Untrusted,
    /// The signature is broken (file changed after signing), revoked, explicitly
    /// distrusted, or failed verification for another reason.
    Invalid,
}

impl SignatureState {
    /// Unsigned or untrusted: the file carries no usable assurance.
    pub fn lacks_assurance(self) -> bool {
        matches!(self, SignatureState::Unsigned | SignatureState::Untrusted)
    }
}

/// CERT_E_EXPIRED, CERT_E_UNTRUSTEDROOT, CERT_E_CHAINING, CERT_E_UNTRUSTEDCA.
const UNTRUSTED_CODES: [u32; 4] = [0x800B_0101, 0x800B_0109, 0x800B_010A, 0x800B_0112];

fn state_for(status: i32) -> SignatureState {
    match status as u32 {
        0 => SignatureState::Valid,
        code if UNTRUSTED_CODES.contains(&code) => SignatureState::Untrusted,
        _ => SignatureState::Invalid,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureInfo {
    pub state: SignatureState,
    /// Simple display name of the leaf signer certificate, when one was read.
    pub signer: String,
    pub via_catalog: bool,
    /// WinVerifyTrust HRESULT of the decisive check.
    pub status_code: i32,
}

impl SignatureInfo {
    pub fn summary(&self) -> String {
        let source = if self.via_catalog { "catalog" } else { "embedded" };
        match self.state {
            SignatureState::Valid => format!("Valid ({source}), signer: {}", or_unknown(&self.signer)),
            SignatureState::Unsigned => "Unsigned (no embedded signature or catalog entry)".into(),
            SignatureState::Untrusted => format!(
                "Untrusted {source} signature (0x{:08X}: self-signed, expired or unknown root), signer: {}",
                self.status_code as u32,
                or_unknown(&self.signer)
            ),
            SignatureState::Invalid => format!(
                "Invalid {source} signature (0x{:08X}), signer: {}",
                self.status_code as u32,
                or_unknown(&self.signer)
            ),
        }
    }
}

fn or_unknown(value: &str) -> &str {
    if value.is_empty() { "unknown" } else { value }
}

const TRUST_E_NOSIGNATURE: u32 = 0x800b_0100;
const TRUST_E_SUBJECT_FORM_UNKNOWN: u32 = 0x800b_0003;
const CERT_NAME_SIMPLE_DISPLAY_TYPE: u32 = 4;
/// CRYPT_E_FILE_ERROR, E_ACCESSDENIED, sharing violation, file/path not found:
/// the file could not be read, which says nothing about its signature.
const FILE_ACCESS_ERRORS: [u32; 5] = [0x8009_2003, 0x8007_0005, 0x8007_0020, 0x8007_0002, 0x8007_0003];
const GENERIC_READ: u32 = 0x8000_0000;

#[cfg(test)]
#[test]
fn status_codes_map_to_states() {
    assert_eq!(state_for(0), SignatureState::Valid);
    assert_eq!(state_for(0x800B_0109_u32 as i32), SignatureState::Untrusted);
    assert_eq!(state_for(0x8009_6010_u32 as i32), SignatureState::Invalid, "TRUST_E_BAD_DIGEST: modified after signing");
    assert_eq!(state_for(0x800B_010C_u32 as i32), SignatureState::Invalid, "CERT_E_REVOKED");
    assert!(SignatureState::Untrusted.lacks_assurance() && !SignatureState::Invalid.lacks_assurance());
}

/// One WinVerifyTrust VERIFY/CLOSE pair, reading the leaf signer name in between.
unsafe fn verify_trust(trust: &mut WINTRUST_DATA) -> (i32, String) {
    unsafe {
        trust.cbStruct = size_of::<WINTRUST_DATA>() as u32;
        trust.dwUIChoice = WTD_UI_NONE;
        trust.fdwRevocationChecks = WTD_REVOKE_NONE;
        trust.dwStateAction = WTD_STATEACTION_VERIFY;
        trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let status = WinVerifyTrust(null_mut(), &mut action, trust as *mut _ as *mut c_void);
        let mut signer = String::new();
        if !trust.hWVTStateData.is_null() {
            let provider = WTHelperProvDataFromStateData(trust.hWVTStateData);
            if !provider.is_null() {
                let sgnr = WTHelperGetProvSignerFromChain(provider, 0, 0, 0);
                if !sgnr.is_null() && (*sgnr).csCertChain > 0 && !(*sgnr).pasCertChain.is_null() {
                    let cert = (*(*sgnr).pasCertChain).pCert;
                    if !cert.is_null() {
                        let mut buffer = [0u16; 512];
                        let len = CertGetNameStringW(
                            cert,
                            CERT_NAME_SIMPLE_DISPLAY_TYPE,
                            0,
                            null(),
                            buffer.as_mut_ptr(),
                            buffer.len() as u32,
                        );
                        if len > 1 {
                            signer = from_wide(&buffer[..(len as usize - 1).min(buffer.len())]);
                        }
                    }
                }
            }
        }
        trust.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(null_mut(), &mut action, trust as *mut _ as *mut c_void);
        (status, signer)
    }
}

pub fn signature_info(path: &str) -> Result<SignatureInfo, String> {
    if path.is_empty() || path.contains('\0') {
        return Err("No usable file path for signature verification".into());
    }
    unsafe {
        let filename = wide(path);
        let mut file: WINTRUST_FILE_INFO = zeroed();
        file.cbStruct = size_of::<WINTRUST_FILE_INFO>() as u32;
        file.pcwszFilePath = filename.as_ptr();
        let mut trust: WINTRUST_DATA = zeroed();
        trust.dwUnionChoice = WTD_CHOICE_FILE;
        trust.Anonymous.pFile = &mut file;
        let (status, signer) = verify_trust(&mut trust);
        if FILE_ACCESS_ERRORS.contains(&(status as u32)) {
            return Err(format!("Cannot read the file to verify its signature (0x{:08X})", status as u32));
        }
        let unsigned = matches!(status as u32, TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN);
        if !unsigned {
            return Ok(SignatureInfo {
                state: state_for(status),
                signer,
                via_catalog: false,
                status_code: status,
            });
        }
        let not_found = SignatureInfo {
            state: SignatureState::Unsigned,
            signer: String::new(),
            via_catalog: false,
            status_code: status,
        };
        // Read-only handle; the catalog API hashes the file through it.
        let handle = CreateFileW(
            filename.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            0,
            null_mut(),
        );
        if handle == INVALID_HANDLE_VALUE {
            return Ok(not_found);
        }
        let file_handle = OwnedHandle(handle);
        let mut admin: isize = 0;
        let sha256 = wide("SHA256");
        if CryptCATAdminAcquireContext2(&mut admin, null(), sha256.as_ptr(), null(), 0) == 0 {
            return Ok(not_found);
        }
        let mut hash = [0u8; 64];
        let mut hash_len = hash.len() as u32;
        let mut result = not_found.clone();
        if CryptCATAdminCalcHashFromFileHandle2(admin, file_handle.0, &mut hash_len, hash.as_mut_ptr(), 0) != 0 {
            let mut previous: isize = 0;
            let catalog = CryptCATAdminEnumCatalogFromHash(admin, hash.as_ptr(), hash_len, 0, &mut previous);
            if catalog != 0 {
                let mut info: CATALOG_INFO = zeroed();
                info.cbStruct = size_of::<CATALOG_INFO>() as u32;
                if CryptCATCatalogInfoFromContext(catalog, &mut info, 0) != 0 {
                    let tag: String = hash[..hash_len as usize].iter().map(|b| format!("{b:02X}")).collect();
                    let tag = wide(&tag);
                    let mut member: WINTRUST_CATALOG_INFO = zeroed();
                    member.cbStruct = size_of::<WINTRUST_CATALOG_INFO>() as u32;
                    member.pcwszCatalogFilePath = info.wszCatalogFile.as_ptr();
                    member.pcwszMemberTag = tag.as_ptr();
                    member.pcwszMemberFilePath = filename.as_ptr();
                    member.hMemberFile = file_handle.0;
                    member.pbCalculatedFileHash = hash.as_mut_ptr();
                    member.cbCalculatedFileHash = hash_len;
                    member.hCatAdmin = admin;
                    let mut trust: WINTRUST_DATA = zeroed();
                    trust.dwUnionChoice = WTD_CHOICE_CATALOG;
                    trust.Anonymous.pCatalog = &mut member;
                    let (status, signer) = verify_trust(&mut trust);
                    result = SignatureInfo {
                        state: state_for(status),
                        signer,
                        via_catalog: true,
                        status_code: status,
                    };
                }
                CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
            }
        }
        CryptCATAdminReleaseContext(admin, 0);
        Ok(result)
    }
}

/// Signature results keyed by lower-cased path, reused until the file's size or
/// modification time changes. Shared by every scan so each file is verified once.
#[derive(Default)]
pub struct SignatureCache {
    entries: std::collections::HashMap<String, (u64, Option<std::time::SystemTime>, Option<SignatureInfo>)>,
    /// Lookups answered from the cache since creation.
    pub hits: usize,
}

impl SignatureCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// `None` when the file could not be checked at all.
    pub fn get(&mut self, path: &str) -> Option<SignatureInfo> {
        let meta = std::fs::metadata(path).ok();
        let size = meta.as_ref().map_or(0, |m| m.len());
        let modified = meta.as_ref().and_then(|m| m.modified().ok());
        let key = path.to_lowercase();
        if let Some((s, m, sig)) = self.entries.get(&key)
            && *s == size
            && *m == modified
        {
            self.hits += 1;
            return sig.clone();
        }
        let sig = signature_info(path).ok();
        self.entries.insert(key, (size, modified, sig.clone()));
        sig
    }
}
