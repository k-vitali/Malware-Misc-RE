////////////////////////////////////////////////////////
//////////////////// ZLOADER Loader ////////////////////
////////////////////////////////////////////////////////
////////////////////////////////////////////////////////

import "pe"
rule crime_win32_zloader_load_1 {

meta:
	description = "Detects Zloader loader 1.1.20"
	author = "@VK_Intel"
	reference = "https://twitter.com/malwrhunterteam/status/1240664014121828352"
	date = "2020-03-21"


strings:
	$str1 = "antiemule-loader-bot32.dll"

	$loop = {EE 03 00 00 E9 03 00 00 EE 03 00 00 EF 03 00 00 F0 03 00 00 EE 03 00 00 EE 03 00 00 EA 03 00 00 EC 03 00 00 EB 03 00 00 ED 03 00 00}
	$decoder_op = {55 89 e5 53 57 56 8b ?? ?? 85 f6 74 ?? 8b ?? ?? 6a 00 53 e8 ?? ?? ?? ?? 83 c4 08 a8 01 75 ?? 8b ?? ?? ?? ?? ?? 89 f9 e8 ?? ?? ?? ?? 89 c1 0f ?? ?? 66 ?? ?? 66 ?? ?? 74 ?? bb 01 00 00 00 eb ?? 89 d8 99 f7 f9 0f ?? ?? ?? 8b ?? ?? 66 ?? ?? ?? 66 ?? ?? ?? 8d ?? ?? 74 ?? 8d ?? ?? 66 83 fa 5f 72 ?? 66 83 f8 0d 77 ?? ba 00 26 00 00 0f a3 c2 72 ?? eb ?? 31 f6 eb ?? 89 de eb ?? 8b ?? ?? 89 f0 5e 5f 5b 5d c3}


condition:
( uint16(0) == 0x5a4d and pe.exports("DllRegisterServer") and
( 2 of them )
) or ( all of them )
}

import "pe"

////////////////////////////////////////////////////////
//////////////////// ZLOADER hVNC ////////////////////
////////////////////////////////////////////////////////
////////////////////////////////////////////////////////
import "pe"
rule crime_win32_hvnc_zloader1_hvnc_generic
{
meta:

	description = "Detects Zloader hidden VNC"
	author = "@VK_Intel"
	reference = "https://twitter.com/malwrhunterteam/status/1240664014121828352"
	date = "2020-03-21"

    condition:
        pe.exports("VncStartServer") and pe.exports("VncStopServer")
}
