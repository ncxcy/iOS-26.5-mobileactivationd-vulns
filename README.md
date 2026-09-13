# mobileactivationd iOS 26.5 (23F77) vulnerabilities

**only for iOS 26.5, i don't know if these vulns exist in earlier versions, you need to check by yourself, i hope this is valuable to someone <3 (im publishing all of this beacuse all asked me for proofs of vulns which i found and here are they (SecureROM and mobileactivationd)**

---

## 1. hactivation

funct: dealwith\_activation (0x1002c8adc)

this is the biggest finding for me and in my opinion the cleanest approach. at the very top of dealwith\_activation, before any record loading or cert validation happens, there is this block:

```c
if (use_hactivation(self) != 0) {
    maLog("dealwith_activation", 0,
          "Hactivation is enabled, short circuiting activation state to Activated.");
    data_ark_set(self, 0, "ActivationState", "Activated", 0);
    data_ark_set(self, 0, "BrickState", kCFBooleanFalse, 0);
}
```

this block returns success and if the use\_hactivation check returns nonzero, the daemon writes "Activated" directly to data\_ark and returns. no record, no certs, no nonce is verified (as i can see), the device is considered activated from that point forward

use\_hactivation reads two things: first it checks the key "disable-hactivation-ma=1" from some config source (maybe is a mobile gestalt override or an NVRAM variable) Second it checks a data\_ark key "hactivationEnabled". If hactivation is not disabled and the flag is set, the check passes

the XPC string "allow-hactivation" also exists in the binary, suggesting there is a separate entitlement or capability gate that controls whether a caller can trigger this path

possible approach working (i didn't tested it yet but it looks promising): write "hactivationEnabled" = true into data\_ark before dealwith\_activation runs, or find the config source for "disable-hactivation-ma=1" and ensure it is absent. The data\_ark path is stored at /private/var/mobile/Library/mad/data\_ark.plist. With the iBoot chain already bypassed and kernel running with AMFI disabled (cs\_enforcement\_disable=1 boot arg), writing to that file before mobileactivationd starts is straightforward

Why is possible to me, beacuse code path is unconditional once use\_hactivation returns nonzero and no crypto is involved here.

---

## 2. SkipActivationRandomnessCheck 

funct: verify\_activation\_record (0x1002d3244)

Inside verify\_activation\_record, the randomness check is gated on an options dict parameter:

```c
v48 = [opts objectForKeyedSubscript: "SkipActivationRandomnessCheck"];
if (isNSNumber(v48) && [v48 boolValue]) {
}
```

randomness check is skipped and jumps straight to verify_activation_record_certificates, now the string "SkipActivationRandomnessCheck" is confirmed at 0x10038e13b addr. when this key is present and true in the opts dict passed to verify\_activation\_record, the nonce/randomness comparison is never performed. The code logs "Invalid Randomness (actual, expected)" only when this check is not skipped


the opts dict is assembled by the caller depending on which XPC entry point is used, the caller may have control over which keys end up in opts. The HandleActivationInfoWithSessionRequest and HandleActivationInfoRequest XPC handlers are the relevant entry points

---

## 3. UseEnhancedValidation Controls cert chain depth

funct: verify\_activation\_record\_certificates (referenced at 0x100389797)

string "UseEnhancedValidation" at 0x10038e112 controls whether the full Apple PKI chain is validated or a relaxed path is used

When UseEnhancedValidation is false in the opts dict, the cert check uses SecCertificateCopyKey without chain validation. sooo probably means a self signed cert is accepted as long as it contains the right structure, the function goes through evaluateBAATrustWithCerts and evaluateAccessoryTrustWithCerts, both of which call into CoreTrust (CTEvaluateBAASystemTestRoot or CTEvaluateBAAUserTestRoot how i can remember from notes). these CoreTrust functions accept test roots when the device is in a specific security mode

Combining SkipActivationRandomnessCheck=true and UseEnhancedValidation=false in the opts dict gives a path where
- The randomness check is skipped
- The cert chain uses a relaxed validation path

A synthetic activation record with your device serial and UDID, signed with a self signed cert have chance of passing both checks

---

## 4. store\_activation\_record has no validation lol

funct: store\_activation\_record (0x1002d57f4)

function takes an activation record dict (param a1) and writes it directly to disk at

```
/private/var/mobile/Library/mad/activation_records/activation_record.plist
```

It does these things:
1. creates the directory with 0755 permissions if it does not exist
2. copies the input dict into a mutable dict
3. adds LDActivationVersion = 2 to the dict
4. calls store\_dict to write it out as a plist

theres no validation happens on the record contents no cert check, nonce check and serial/UDID check. Whatever dict you pass in gets written to disk (hopefully)

The next time dealwith\_activation runs, it calls load\_and\_validate\_activation\_record which reads this file, if the record on disk is missing required fields, validation fails and the device deactivates, but if it contains a plausible looking dict that passes the serial/UDID string comparison and the cert check it gets accepted

the XPC entry point that can reach store\_activation\_record is the internal path inside handle\_activate, after all validation has been passed, but if you have filesystem write access (which you do with the iBoot chain bypassed and kernel running as root), you can write activation\_record.plist directly without going through any of the XPC validation at all, it reads the file and calls load\_and\_validate\_activation\_record on it, The minimal dict that passes load\_and\_validate is:

- AccountTokenXML: valid plist data containing a dict with SerialNumber and UniqueDeviceID matching the device (readable from lockdownd even on a locked device i saw it)
- DeviceCertificate: any cert data (the check depends on UseEnhancedValidation)

---

## 5. serial and UDID check uses isEqualToString, not Constant Time comparison

func: verify\_activation\_record (at mem addr 0x1002d3244)

the serial number and UDID checks are:

```c
v68 = [device_serial isEqualToString: record_serial];
[device_udid isEqualToString: record_udid];
```

NSString isEqualToString, which is not constant time. this is a timing oracle in principle though exploiting it over IPC is impractical, more importantly both device\_serial and record\_udid come from Gestalt (copyAnswer for SerialNumber and UniqueDeviceID). both of those are readable from lockdownd on a locked device without any authentication (i tested it and confirmed), so the values needed to pass this check are freely available from the device itself

---

## 6. race window in handle\_activate between state writes

i confirmed the presence of "Activation State: %@" log strings and the data\_ark\_set calls in dealwith\_activation

the ActivationState key is written to data\_ark before store\_activation\_record and before storeUCRT complete, if the process is killed between the first data\_ark\_set (ActivationState = Activated) and the remaining writes, the device ends up in a partially activated state with ActivationState = Activated already committed to disk. On the next boot mobileactivationd reads data\_ark, sees Activated, and skips full re validation

this is a TOCTOU on the daemon, triggering it requires killing mobileactivationd at exactly the right moment during an activation (not possible but there is a zero crypto)

---

## 7. FindMyRemoveActivationLock returns not supported

funct: FindMyRemoveActivationLock (0x1002c34c0)

```c
return createMobileActivationError(
    "FindMyRemoveActivationLock", 404,
    "com.apple.MobileActivation.ErrorDomain", -3, 0,
    "Operation not supported on this platform.");
```

funct unconditionally returns an error, the activation lock removal through FindMy is not implemented in this build, this means the iCloud activation lock cannot be removed through the normal FindMy path from this daemon, tt has to be bypassed at a lower level.

---

## 8. evaluateBAATrust accepting test roots

funct: evaluateBAATrust (at 0x1002c28b8)

```c
if (a3 != 0) {
    CTEvaluateBAASystemTestRoot(leaf_data, leaf_len, key_data, key_len, 0, 0, 0);
} else {
    CTEvaluateBAAUserTestRoot(leaf_data, leaf_len, key_data, key_len, 0, 0, 0);
}
```

the a3 parameter selects between system test root and user test root validation, the test root certs are embedded in the binary (confirmed: the large PEM blocks at addr 0x1003290d8, 0x100329d2c, 0x10032bf6c, 0x10032d660, 0x10032edf0). these test certs have known key material in some cases (the test cert at 0x10032d660 is the img4 test secp384r1 cert, key material was been extracted before in the jailbreak comm from my research these days)

so if the CoreTrust on a CPFM:03 (development fused) device accepts signatures from these test roots, then constructing a cert chain that passes evaluateBAATrust becomes possible without Apple's private keys

---

## my plan and possibilites

**filesystem write when booted with iBoot chain bypassed:**

somehow if you can, before mobileactivationd starts, write a crafted data\_ark.plist containing

```
ActivationState = Activated
BrickState = false
```

Or try writing a crafted activation\_record.plist to /private/var/mobile/Library/mad/activation\_records/ that contains matching serial and UDID, when mobileactivationd starts it reads data\_ark reads Activated, and the device boots to home screen :)

No cert, apple servers or crypto

**hactivation flag in data\_ark:**

write data\_ark.plist with hactivationEnabled = true, mobileactivationd calls use\_hactivation, gets true and it writes Activated

**synthetic activation record via XPC:**

call the mobileactivationd XPC interface with HandleActivationInfoRequest, pass an activation record dict containing the device serial and UDID in it, set SkipActivationRandomnessCheck = true and UseEnhancedValidation = false in the options, use a self signed cert for the AccountTokenCertificate, depending on whether CoreTrust accepts test roots on this device, this either works directly or needs the test root certs from the binary probably

this method requires no filesystem access and works from a sandboxed process that has the right entitlement to call mobileactivationd

**race kill between data\_ark writes:**

trigger an activation (send any activation record to handle\_activate) then kill mobileactivationd between the first ActivationState write and the remaining writes restart the daemon, If ActivationState = Activated survived in data\_ark the device may consider itself activated hopefully

(it's hard)

---

## Key addresses

| Address | Function |
|---|---|
| 0x1002c8adc | dealwith\_activation (hactivation check at top) |
| 0x1002d3244 | verify\_activation\_record (randomness check serial/UDID compare) |
| 0x1002d57f4 | store\_activation\_record (no validation write to disk) |
| 0x1002d20a4 | extract\_account\_token (parses AccountTokenXML from record) |
| 0x1002c28b8 | evaluateBAATrust (test root selection) |
| 0x1002c2a14 | evaluateBAATrustWithCerts (cert chain builder) |
| 0x1002c34c0 | FindMyRemoveActivationLock (always returns not supported) |
| 0x1002c2e14 | evaluateAppleSSLTrust (CTEvaluateAppleSSLWithOptionalTemporalCheck) |
| 0x1002c2f64 | evaluateAccessoryTrust (CTEvaluateBAAAccessory) |

## key strings and their meaning

| String | Role |
|---|---|
| SkipActivationRandomnessCheck | opts dict key, skips nonce/randomness comparison |
| UseEnhancedValidation | opts dict key, controls cert chain depth |
| UseFactoryCertificates | opts dict key, selects factory vs production cert path |
| hactivationEnabled | data\_ark key, triggers hactivation short circuit |
| disable-hactivation-ma=1 | config key that blocks hactivation if present |
| allow-hactivation | entitlement or capability name |
| ActivationState | data\_ark key written to mark device as activated |
| BrickState | data\_ark key, must be false for device to work |
| LDActivationVersion | key added to plist when writing activation\_record.plist, value = 2 |
| activation\_record.plist | file at /private/var/mobile/Library/mad/activation\_records/ |
| data\_ark.plist | file at /private/var/mobile/Library/mad/data\_ark.plist |

and im publishing this as research
