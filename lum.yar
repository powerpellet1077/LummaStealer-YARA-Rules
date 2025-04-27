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
