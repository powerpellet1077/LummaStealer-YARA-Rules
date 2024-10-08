# YARA Rule for Detection of NetVineSigned.exe Malware

This repository contains a YARA rule developed by the BGD e-GOV CIRT Cyber Threat Intelligence (CTI) team to detect the presence of the malicious `NetVineSigned.exe` file. This executable is part of a stealer malware campaign linked to the Lumma Stealer malware family, known for stealing sensitive information such as credentials, financial data, and browsing history from infected systems.

## Rule Purpose

The provided YARA rule is designed to detect the NetVineSigned.exe malware by looking for specific strings and patterns within the file, allowing security teams to quickly identify and mitigate this threat. The rule was created based on an internal threat intelligence report detailing the Lumma Stealer campaign.

## Rule Details:

- **Rule Name:** `NetVineSigned`
- **Malware Family:** Lumma Stealer
- **Date:** 2024-10-08
- **Author:** BGD e-GOV CIRT CTI Team
- **Description:** This rule identifies the NetVineSigned.exe malware based on unique strings and behaviors extracted from the malicious executable.
- **Hash of Malware:** `cca0ccec702392583c6e1356a3ff1df0d20d5837c3cd317464185e8780121ab1` (SHA-256)

### Detection Coverage
The YARA rule matches against specific strings in files related to the NetVineSigned.exe malware. It also checks for valid PE headers and file size conditions. This rule is effective for identifying files smaller than 7MB that contain at least 8 of the specified strings associated with the malware.

### Rule Summary:
- **File Size**: Triggers if the file size is less than 7MB.
- **Matching Strings**: The rule matches 8 out of 20 strings found in the malware.
- **File Type**: The rule applies to Windows PE files with a valid MZ header.

## Usage

To use this YARA rule in your environment, download the `netvine_signed.yar` file and scan your system with your YARA tool:

```bash
yara -r netvine_signed.yar /path/to/scan/

```

## About Lumma Stealer
Lumma Stealer is a type of InfoStealer malware that exfiltrates sensitive user information, including credentials, financial data, and cryptocurrency. This rule helps security teams detect its presence early, preventing further compromise of affected systems.



### YARA Rule File: `netvine_signed.yar`

```yaml
/*
   YARA Rule Set
   Author: BGD e-GOV CIRT CTI Team
   Date: 2024-10-08
   Description: Detection of NetVineSigned.exe malware
   Reference: Internal Analysis of Lumma Stealer Campaign
*/

rule NetVineSigned {
   meta:
      description = "Detection rule for NetVineSigned.exe malware"
      author = "BGD e-GOV CIRT CTI Team"
      reference = "Internal Threat Intelligence Report"
      date = "2024-10-08"
      hash1 = "cca0ccec702392583c6e1356a3ff1df0d20d5837c3cd317464185e8780121ab1" // SHA-256 hash of NetVineSigned.exe

   strings:
      $s1 = "rundll32.exe shell32.dll,Control_RunDLL MMSys.cpl" fullword ascii
      $s2 = "#Incompatible version of WINSOCK.DLL" fullword ascii
      $s3 = ";http://crt.sectigo.com/SectigoPublicTimeStampingRootR46.p7c0#" fullword ascii
      $s4 = "https://www.ssuiteoffice.com" fullword ascii
      $s5 = "ssuiteoffice.com" fullword ascii
      $s6 = "http://www.netmastersllc.com" fullword ascii
      $s7 = ";http://crl.sectigo.com/SectigoPublicTimeStampingRootR46.crl0|" fullword ascii
      $s8 = "visit us at ssuiteoffice.com" fullword wide
      $s9 = "TLOGINDIALOG" fullword wide
      $s10 = "NetVine - HeaderFooterForm" fullword ascii
      $s11 = "https://sectigo.com/CPS0" fullword ascii
      $s12 = "AddressList.dat" fullword ascii
      $s13 = "Error setting %s.Count8Listbox (%s) style must be virtual in order to set Count\"Unable to find a Table Of Contents" fullword wide
      $s14 = ":http://secure.globalsign.com/cacert/codesigningrootr45.crt0A" fullword ascii
      $s15 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl05" fullword ascii
      $s16 = "-http://ocsp.globalsign.com/codesigningrootr450F" fullword ascii
      $s17 = "9http://crt.sectigo.com/SectigoPublicTimeStampingCAR36.crt0#" fullword ascii
      $s18 = "9http://crl.sectigo.com/SectigoPublicTimeStampingCAR36.crl0z" fullword ascii
      $s19 = "0http://crl.globalsign.com/codesigningrootr45.crl0U" fullword ascii
      $s20 = "GIF encoded data is corrupt!GIF code size not in range 2 to 9,Wrong number of colors; must be a power of 2\"Unrecognized extensi" wide

   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      8 of them
}
```
### Rule Explanation:

- **Purpose**: Detects the malicious `NetVineSigned.exe` executable, which was used in a recent stealer malware campaign identified by the BGD e-GOV CIRT CTI team. This executable is part of the broader Lumma Stealer campaign.
- **Strings**: The rule looks for specific ASCII and wide (Unicode) strings found within the file. These strings include references to URLs, file paths, system functions, and other indicators typically associated with the malware.
- **Condition**: The rule checks if the file is a Windows PE executable (identified by the "MZ" header), is smaller than 7MB, and contains at least 8 of the specified strings.

This YARA rule provides an effective detection mechanism for identifying malicious files associated with the `NetVineSigned.exe` malware. Security teams can utilize this rule to prevent the spread of stealer malware, particularly the Lumma Stealer variant.
