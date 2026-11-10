//! Confirmed changes to services and drivers: stop, disable, enable, quarantine.
//!
//! Every change re-reads the item first and refuses if its file changed after the
//! user confirmed. Quarantine checks everything it can before changing anything,
//! then stops, disables and moves the file, in that order.

use crate::inventory::image_path_from_command;
use crate::quarantine;
use crate::signature::{SignatureInfo, SignatureState, signature_info};
use crate::storage::DataDir;
use crate::system::{self, ServiceInfo, ServiceStart};
use std::path::Path;
use windows_sys::Win32::System::Services::SERVICE_WIN32_SHARE_PROCESS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceOp {
    Stop,
    Disable,
    EnableAutomatic,
    EnableManual,
    Quarantine,
}

const BOOT_NO_DISABLE: &str = "Boot drivers cannot be disabled here: Windows may not start without them";
const BOOT_NO_QUARANTINE: &str = "Boot drivers cannot be quarantined: Windows may not start without them";
const SHARED_NO_QUARANTINE: &str = "Services hosted by svchost share a file with other services, so it cannot be quarantined";

fn is_boot(s: &ServiceInfo) -> bool {
    s.start_type == "Boot"
}

fn is_shared_host(s: &ServiceInfo) -> bool {
    s.service_type & SERVICE_WIN32_SHARE_PROCESS != 0
        || image_path_from_command(&s.binary_path).is_some_and(|p| p.to_lowercase().ends_with("\\svchost.exe"))
}

/// Whether the operation would change anything for this item.
pub fn applies(op: ServiceOp, s: &ServiceInfo) -> bool {
    match op {
        ServiceOp::Stop => s.state == "Running",
        ServiceOp::Disable => s.start_type != "Disabled",
        ServiceOp::EnableAutomatic | ServiceOp::EnableManual => s.start_type == "Disabled",
        ServiceOp::Quarantine => true,
    }
}

/// Why the operation is never allowed for this item, judged from its listing.
/// The signature check needs the file, so it runs in [`apply`].
pub fn refusal(op: ServiceOp, s: &ServiceInfo) -> Option<&'static str> {
    match op {
        ServiceOp::Disable if is_boot(s) => Some(BOOT_NO_DISABLE),
        ServiceOp::Quarantine if is_boot(s) => Some(BOOT_NO_QUARANTINE),
        ServiceOp::Quarantine if is_shared_host(s) => Some(SHARED_NO_QUARANTINE),
        _ => None,
    }
}

/// Microsoft's own files. Its attestation service also signs nearly every
/// third-party driver as "Hardware Compatibility Publisher", which says nothing
/// about who wrote the driver, so those remain eligible.
fn is_microsoft_own(signature: &SignatureInfo) -> bool {
    signature.state == SignatureState::Valid
        && signature.signer.starts_with("Microsoft")
        && !signature.signer.contains("Hardware Compatibility")
}

/// Performs the operation; returns the message to show.
pub fn apply(data: &DataDir, target: &ServiceInfo, op: ServiceOp) -> Result<String, String> {
    let kind = if target.is_driver() { "driver" } else { "service" };
    let label = format!("{kind} {}", target.name);
    let current = system::list_services(target.is_driver())?
        .into_iter()
        .find(|s| s.name == target.name)
        .ok_or_else(|| format!("The {label} no longer exists; nothing was done"))?;
    if current.binary_path != target.binary_path {
        return Err(format!("The file of the {label} changed after it was listed; nothing was done"));
    }
    if let Some(reason) = refusal(op, &current) {
        return Err(reason.to_string());
    }
    match op {
        ServiceOp::Stop => {
            system::stop_service(&current.name)?;
            Ok(format!("Stopped the {label}"))
        }
        ServiceOp::Disable => {
            system::set_service_start(&current.name, ServiceStart::Disabled)?;
            Ok(format!("Disabled the {label}; Windows will not start it again"))
        }
        ServiceOp::EnableAutomatic => {
            system::set_service_start(&current.name, ServiceStart::Automatic)?;
            Ok(format!("The {label} now starts automatically"))
        }
        ServiceOp::EnableManual => {
            system::set_service_start(&current.name, ServiceStart::Manual)?;
            Ok(format!("The {label} now starts on demand"))
        }
        ServiceOp::Quarantine => quarantine_item(data, &current, &label),
    }
}

fn quarantine_item(data: &DataDir, s: &ServiceInfo, label: &str) -> Result<String, String> {
    let path = image_path_from_command(&s.binary_path).ok_or("Its file could not be determined; nothing was done")?;
    if !Path::new(&path).is_file() {
        return Err(format!("{path} does not exist; nothing was done"));
    }
    quarantine::own_file_refusal(&path).map_or(Ok(()), Err)?;
    let signature = signature_info(&path).map_err(|e| format!("Its signature could not be checked ({e}); nothing was done"))?;
    if is_microsoft_own(&signature) {
        return Err(format!("{path} is signed by {}; Microsoft's own files are not quarantined", signature.signer));
    }
    system::stop_service(&s.name).map_err(|e| format!("It could not be stopped, so nothing was changed: {e}"))?;
    system::set_service_start(&s.name, ServiceStart::Disabled)
        .map_err(|e| format!("It was stopped, but could not be disabled, so its file was left in place: {e}"))?;
    let entry = quarantine::quarantine_service_file(data, &path, label, &signature.summary())
        .map_err(|e| format!("It was stopped and disabled, but quarantine failed: {e}"))?;
    Ok(format!("Stopped and disabled the {label} and quarantined {path} (entry {})", entry.id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(binary_path: &str, start_type: &str, service_type: u32) -> ServiceInfo {
        ServiceInfo {
            name: "x".into(),
            display_name: "x".into(),
            pid: 0,
            state: "Running".into(),
            start_type: start_type.into(),
            binary_path: binary_path.into(),
            service_type,
        }
    }

    fn signed_by(signer: &str, state: SignatureState) -> SignatureInfo {
        SignatureInfo { state, signer: signer.into(), via_catalog: false, status_code: 0 }
    }

    #[test]
    fn boot_drivers_and_shared_hosts_are_protected() {
        let boot = item(r"\SystemRoot\System32\drivers\disk.sys", "Boot", 1);
        assert_eq!(refusal(ServiceOp::Disable, &boot), Some(BOOT_NO_DISABLE));
        assert_eq!(refusal(ServiceOp::Quarantine, &boot), Some(BOOT_NO_QUARANTINE));
        assert_eq!(refusal(ServiceOp::Stop, &boot), None);

        let host = item(r"C:\WINDOWS\system32\svchost.exe -k netsvcs -p", "Automatic", 0x10);
        assert_eq!(refusal(ServiceOp::Quarantine, &host), Some(SHARED_NO_QUARANTINE));
        assert_eq!(refusal(ServiceOp::Disable, &host), None);

        let shared = item(r"C:\Vendor\host.exe", "Automatic", SERVICE_WIN32_SHARE_PROCESS);
        assert_eq!(refusal(ServiceOp::Quarantine, &shared), Some(SHARED_NO_QUARANTINE));

        let own = item(r"C:\Vendor\app.exe", "Automatic", 0x10);
        assert_eq!(refusal(ServiceOp::Quarantine, &own), None);
    }

    #[test]
    fn only_microsofts_own_signatures_are_protected() {
        assert!(is_microsoft_own(&signed_by("Microsoft Windows", SignatureState::Valid)));
        assert!(is_microsoft_own(&signed_by("Microsoft Corporation", SignatureState::Valid)));
        assert!(!is_microsoft_own(&signed_by("Microsoft Windows Hardware Compatibility Publisher", SignatureState::Valid)));
        assert!(!is_microsoft_own(&signed_by("Microsoft Windows", SignatureState::Invalid)), "a broken signature proves nothing");
        assert!(!is_microsoft_own(&signed_by("Example Vendor", SignatureState::Valid)));
    }

    #[test]
    fn choices_only_offer_what_would_change_something() {
        let running = item(r"C:\a.exe", "Automatic", 0x10);
        assert!(applies(ServiceOp::Stop, &running) && applies(ServiceOp::Disable, &running));
        assert!(!applies(ServiceOp::EnableManual, &running));
        let mut off = item(r"C:\a.exe", "Disabled", 0x10);
        off.state = "Stopped".into();
        assert!(!applies(ServiceOp::Stop, &off) && !applies(ServiceOp::Disable, &off));
        assert!(applies(ServiceOp::EnableAutomatic, &off) && applies(ServiceOp::EnableManual, &off));
    }
}
