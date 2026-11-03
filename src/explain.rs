//! Plain-English help for each kind of finding: what it means and what you can do.

use crate::findings::{Finding, Severity};

pub struct Explanation {
    pub meaning: &'static str,
    pub next_steps: &'static str,
}

const fn e(meaning: &'static str, next_steps: &'static str) -> Explanation {
    Explanation { meaning, next_steps }
}

/// Matches on the finding's module and title. Unknown findings get a general note.
pub fn explain(f: &Finding) -> Explanation {
    let t = f.title.as_str();
    let has = |s: &str| t.contains(s);
    match f.module.as_str() {
        "integrity_monitor" => {
            if has("Possible inline hook") {
                e(
                    "The first bytes of a Windows system function in ntdll.dll were changed in memory. Security tools do this on purpose to watch programs, but so does malware that wants to hide or intercept what programs do.",
                    "Check whether you run antivirus, anti-cheat or monitoring software that could explain it. If the change appeared recently (marked NEW) and nothing explains it, scan the PC with Microsoft Defender Offline and capture a new baseline only once the system is known to be clean.",
                )
            } else if has("Memory differs from") {
                e(
                    "Code inside ntdll.dll in memory no longer matches the file on disk or your baseline, away from any function's entry point. This is less typical of hooks but still means something modified it after Windows loaded it.",
                    "Treat it like a hook: look for software that explains it, rescan, and investigate if it is new and unexplained.",
                )
            } else if has("Function-override thunk") && has("outside ntdll") {
                e(
                    "Windows retargets a few small jump stubs in ntdll at load time, but only to places the signed file declares. This one points somewhere else, which is what a hijack of those stubs would look like.",
                    "This is unusual. Note the target described in the detail and investigate the process and modules that own that memory.",
                )
            } else if has("Function-override thunks retargeted") || has("Executable page appended to the ntdll mapping") {
                e(
                    "Normal Windows behaviour: the loader redirects a few declared stubs to optimised code it places next to ntdll.",
                    "Nothing to do.",
                )
            } else if has("Unexplained executable page") {
                e(
                    "There is executable memory attached to ntdll's own mapping that no declared Windows override uses.",
                    "Unusual. Rescan after a reboot; if it persists, investigate further or ask for help.",
                )
            } else if has("currently writable") {
                e(
                    "A code section of ntdll is writable in memory. Code is normally execute-only; patching tools often make it writable to change it.",
                    "Rescan in a minute. If it stays writable, look for software that hooks or patches programs.",
                )
            } else if has("unreadable") {
                e("Part of ntdll could not be read for comparison, so that part was not checked.", "Usually harmless. Rescan; run as administrator if it repeats.")
            } else if has("unexpected path") {
                e(
                    "ntdll.dll was loaded from somewhere other than the Windows System32 folder, which should never happen on a normal system.",
                    "Investigate immediately: this is a strong sign of tampering.",
                )
            } else if has("fails Authenticode") || has("Signer differs") {
                e(
                    "The ntdll.dll file on disk no longer carries a valid Microsoft signature (or a different signer). Windows files should always be signed by Microsoft.",
                    "Run 'sfc /scannow' from an administrator command prompt and a full antivirus scan.",
                )
            } else if has("differs from the baseline") && has("On-disk") {
                e(
                    "The ntdll.dll file changed since you captured the baseline. If its signature is still valid, a Windows update is the usual reason.",
                    "If you recently installed updates, archive the baseline and capture a new one. If not, investigate.",
                )
            } else if has("does not match its recorded hash") || has("Baseline metadata") || has("outside its directory") {
                e(
                    "The saved baseline itself was changed after it was captured, so it can no longer be trusted.",
                    "Archive it and capture a new baseline on a system you trust is clean.",
                )
            } else if has("different ntdll build") {
                e("Your baseline was taken from an older ntdll (usually before a Windows update), so memory is compared with the file instead.", "Archive the baseline and capture a new one.")
            } else if has("No baseline") {
                e(
                    "Without a baseline, every change to ntdll in memory is reported, including ones security software makes on purpose.",
                    "On a system you trust is clean, use Baseline > Capture baseline. Later scans then report only new changes.",
                )
            } else if has("Known differences") {
                e("These memory changes were already present when you captured the baseline and have not changed since.", "Nothing to do.")
            } else {
                general(f)
            }
        }
        "process_inventory" => {
            if has("does not match its image path") {
                e(
                    "The name Windows lists for the process differs from its actual file name. Malware sometimes disguises itself this way.",
                    "Open the file location and check what the file really is (publisher, signature, VirusTotal lookup).",
                )
            } else if has("unexpected location") {
                e(
                    "A process uses the name of a core Windows program (like svchost.exe) but runs from a different folder. This is a classic malware disguise.",
                    "Treat as suspicious: check the file with VirusTotal and its properties; end and quarantine it if it is not something you recognise.",
                )
            } else if has("signature does not verify") {
                e(
                    "The program is signed, but the signature is broken: the file was changed after signing, or the certificate was revoked.",
                    "Be cautious. Re-download the program from its official site, or quarantine it if you don't recognise it.",
                )
            } else if has("untrusted signature") {
                e(
                    "The program is signed with a certificate Windows does not trust (self-signed or expired). That proves nothing about who made it.",
                    "Fine if you know the program (many small tools and old games are like this). Otherwise check it on VirusTotal.",
                )
            } else if has("Unsigned image") {
                e(
                    "The program has no digital signature, so its publisher cannot be verified. Many legitimate small tools are unsigned; malware usually is too, especially in Temp or Downloads.",
                    "If you know the program, nothing to do. If not, look at where it runs from and check it on VirusTotal.",
                )
            } else if has("Signed image running from a temp") {
                e("A signed program runs from a Temp or Downloads folder. Installers and updaters do this routinely.", "Usually fine. Check the signer in the details.")
            } else if has("Office application") {
                e(
                    "An Office program (Word, Excel, Outlook…) started a command shell or script engine. Malicious documents use exactly this to run code.",
                    "If you did not just run a macro or script on purpose, end the process tree and scan the document that was open.",
                )
            } else if has("Browser") && has("script host") {
                e("A web browser started a script engine (PowerShell, mshta…). Drive-by downloads and fake updates do this.", "If unexpected, end the process tree and run a full scan.")
            } else if has("was started by") {
                e(
                    "A core Windows process has an unexpected parent. On a healthy system these are always started by one specific Windows process.",
                    "Treat as suspicious and investigate the parent process.",
                )
            } else {
                general(f)
            }
        }
        "ntdll_sweep" => match f.severity {
            _ if has("summary") => general(f),
            Severity::Info => e(
                "This program changes its own copy of ntdll and points the changes at its own signed code. Browsers and apps built on Chromium or Electron do this to sandbox themselves.",
                "Nothing to do.",
            ),
            Severity::Low => e(
                "ntdll in this process was hooked by a signed module from Program Files or Windows. Antivirus, anti-cheat, overlays and accessibility tools do this.",
                "Fine if you recognise the module in the detail. If not, look it up.",
            ),
            _ if has("unbacked") => e(
                "ntdll in this process jumps into memory that does not belong to any file. Some programs place small trampolines like this; injected malware does too.",
                "Look at the process: is it one you know and trust? If not, check its file on VirusTotal and consider ending it.",
            ),
            _ if has("not a recognisable jump") || has("Many other") => e(
                "ntdll in this process was modified in a way that is not a simple redirect.",
                "Unusual. Investigate the process, and end it if you don't recognise it.",
            ),
            _ => e(
                "ntdll in this process jumps into a module that is unsigned, untrusted or in a Temp/user folder. That is how injected code usually looks.",
                "Treat as suspicious: check the module named in the detail on VirusTotal; end and quarantine the process if it is not explained.",
            ),
        },
        "driver_audit" => {
            if has("signature enforcement is off") {
                e(
                    "Windows is loading kernel drivers without checking their signatures. Drivers run with full control of the PC, so this removes one of its main protections. Rootkits and some game cheats turn it off.",
                    "Unless you turned it off on purpose (driver development), run 'bcdedit' from an administrator prompt to see why, turn enforcement back on and reboot, then scan with Microsoft Defender Offline.",
                )
            } else if has("Test-signing") {
                e(
                    "Windows accepts drivers signed with test certificates that anyone can make. Developers use this; so do rootkits and some cheat or modding tools.",
                    "If you did not enable it, run 'bcdedit /set testsigning off' from an administrator prompt, reboot, and check which drivers needed it.",
                )
            } else if has("Kernel debugging") {
                e(
                    "Kernel debugging is enabled. It lets a debugger control Windows and relaxes some driver protections.",
                    "If you don't debug Windows, run 'bcdedit /debug off' from an administrator prompt and reboot.",
                )
            } else if has("Memory integrity") {
                e(
                    "Memory integrity (core isolation) is off. It uses virtualization to stop drivers from being tampered with and to block incompatible or vulnerable ones. Many gaming PCs have it off for older drivers or performance.",
                    "Optional: turn it on in Windows Security > Device security > Core isolation. Windows lists any drivers that prevent it.",
                )
            } else if has("blocklist") {
                e(
                    "Microsoft's list of known-vulnerable drivers is not being enforced, so Windows will load drivers that attackers abuse to take over the kernel.",
                    "Turn 'Microsoft Vulnerable Driver Blocklist' back on in Windows Security > Device security > Core isolation.",
                )
            } else if has("Known-abusable") {
                e(
                    "This driver's file name matches one publicly documented as abused by attackers: a legitimate but flawed driver they load to gain kernel access ('bring your own vulnerable driver'). Hardware monitors, RGB and overclocking tools often install such drivers.",
                    "If it belongs to software you use (fan control, RGB, overclocking), update that software or uninstall it when you don't need it. If you don't recognise it, check the file on VirusTotal and investigate how it got there.",
                )
            } else if has("file is missing") {
                e(
                    "A driver is loaded in the kernel but its file is gone and no driver registration points to it. Rootkits clean up after loading this way; some hardware-info tools do too.",
                    "If you just ran a hardware-info or overclocking tool, it may be that. Otherwise investigate, and scan with Microsoft Defender Offline.",
                )
            } else if has("signature does not verify") || has("no trusted signature") {
                e(
                    "A loaded kernel driver has no trusted signature, even though Windows normally refuses those. The file may have been changed after it loaded, or enforcement was bypassed.",
                    "Treat as serious: check the file on VirusTotal and scan with Microsoft Defender Offline.",
                )
            } else if has("user-writable") {
                e("A kernel driver was loaded from a folder ordinary programs can write to. Legitimate drivers almost never live there.", "Check the file on VirusTotal and investigate how it was loaded.")
            } else if has("without a driver registration") {
                e(
                    "A driver is loaded in the kernel but no registered driver points to it. Some hardware, overclocking and anti-cheat tools load drivers this way; so do rootkits.",
                    "Check the file's signer and whether it belongs to a tool you use. If not, look it up on VirusTotal.",
                )
            } else {
                general(f)
            }
        }
        "module_audit" => e(
            "A signed program has loaded a DLL that is unsigned (or badly signed) from a Temp or user folder. This is how 'DLL side-loading' attacks hide inside trusted programs.",
            "Check the DLL named in the detail on VirusTotal. If it is unknown, end the process and quarantine the DLL's program.",
        ),
        "persistence_audit" => {
            if has("references a URL") {
                e("Something set to start automatically downloads or opens a web address. Malware uses this to fetch more code at every start.", "Investigate the command; remove the entry if you don't recognise it.")
            } else if has("script") {
                e(
                    "Something starts a script automatically when you sign in. Legitimate tools do this sometimes; it is also a common way for malware to stay on a PC.",
                    "If you know what the script is for, fine. Otherwise look at its contents before removing it.",
                )
            } else if has("runs through") {
                e("A startup entry launches through rundll32 or regsvr32, which can run code from DLL files.", "Usually a vendor utility; check the DLL named in the command.")
            } else if has("missing file") {
                e(
                    "An entry points at a file that no longer exists. Usually something was uninstalled and left this behind. A RUNNING driver whose file is gone is different: drivers that delete themselves are a known hiding trick (some hardware-info tools do it too).",
                    "Stale entries are harmless. For a running driver, check what loaded it.",
                )
            } else if has("signature does not verify") {
                e("A service or startup file's signature is broken: it may have been changed after signing.", "Re-install the software it belongs to, or investigate if unknown.")
            } else if has("temp/download") {
                e("Something set to run automatically lives in a Temp or Downloads folder, which programs rarely do on purpose.", "Investigate; remove the entry if you don't recognise it.")
            } else if has("outside Windows and Program Files") {
                e(
                    "A running driver loads from an unusual folder, not from Windows or Program Files. Games and tools on other drives sometimes do this.",
                    "Check that the folder belongs to software you use and that the file is signed.",
                )
            } else if has("user-writable") || has("unsigned") {
                e(
                    "Something set to run automatically is unsigned or lives in a folder any program can write to, so it is easy to swap for something else.",
                    "Fine for tools you installed yourself; otherwise check the file on VirusTotal.",
                )
            } else {
                general(f)
            }
        }
        _ => general(f),
    }
}

fn general(f: &Finding) -> Explanation {
    match f.severity {
        Severity::Info => e("Informational: a summary or a normal condition worth knowing about.", "Nothing to do."),
        Severity::Low => e("Minor: common on normal systems, worth a glance.", "Check that it matches software you use."),
        Severity::Medium => e("Worth a look: unusual but often explained by software you installed.", "Check the detail and the file involved."),
        Severity::High | Severity::Critical => e("Serious: strongly associated with tampering or malware.", "Investigate promptly; check the files involved on VirusTotal."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(module: &str, severity: Severity, title: &str) -> Finding {
        Finding::new(module, severity, "pid 1 x.exe", title)
    }

    #[test]
    fn known_findings_get_specific_help() {
        assert!(explain(&f("integrity_monitor", Severity::High, "Possible inline hook at NtOpenProcess: memory differs from baseline")).meaning.contains("Security tools"));
        assert!(explain(&f("process_inventory", Severity::High, "svchost.exe is running from an unexpected location")).meaning.contains("disguise"));
        assert!(explain(&f("ntdll_sweep", Severity::Info, "ntdll functions redirected into app.exe")).meaning.contains("sandbox"));
        assert!(explain(&f("persistence_audit", Severity::Medium, "Startup entry runs a .vbs script")).meaning.contains("script"));
        assert!(explain(&f("module_audit", Severity::High, "Signed process loaded an unsigned DLL")).meaning.contains("side-loading"));
        assert!(explain(&f("driver_audit", Severity::Medium, "Known-abusable driver is loaded: RTCore64.sys")).meaning.contains("bring your own"));
        assert!(explain(&f("driver_audit", Severity::High, "Test-signing mode is on")).next_steps.contains("testsigning off"));
    }

    #[test]
    fn unknown_findings_fall_back_by_severity() {
        assert_eq!(explain(&f("other", Severity::Info, "x")).next_steps, "Nothing to do.");
        assert!(explain(&f("other", Severity::High, "x")).meaning.contains("Serious"));
    }
}
