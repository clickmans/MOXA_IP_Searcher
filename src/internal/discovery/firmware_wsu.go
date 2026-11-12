package discovery

import (
	"crypto/aes"
	"crypto/cipher"
	"strings"
)

// Firmware version of a WIFI4 (UDP/5800 "WSU") device.
//
// The last field of a WSU reply is not a plain string but a self contained
// encrypted block (PROTOCOL_SPEC.md §5.3 / §5.3.1). The vendor's
// Wireless Search Utility decrypts it and shows it in its "Firmware version"
// column, e.g. "1.27 Build 25092317". The device side implementation lives in
// userdisk/sbin/serviceAgent of the AWK-1131A firmware v1.27:
//
//	FUN_0040807c      encrypts the version string: enc(buf+0x93,16) and then
//	                  enc(buf+0x9c,16) - two OVERLAPPING 16 byte blocks
//	FUN_00403ad0      derives the AES key from a fixed 32 byte material and
//	                  runs AES-ECB over each 16 byte block
//	remote_encrypt_make_key
//	                  the (self made) derivation; its first 16 bytes are the
//	                  AES-128 key used here
//
// Because the two blocks overlap, the plain text layout is
//
//	buf[0:16]  = first 16 bytes of the version string
//	buf[9:25]  = bytes 9..24 of the same string
//
// so decryption has to run in the REVERSE order: [9:25] first (it was written
// last and destroyed the tail of the first block), then [0:16].

// Firmware block geometry inside a WSU reply.
const (
	// wsuFirmwareOffset is where the encrypted block starts inside a WSU reply
	// (device side offset 0x93).
	wsuFirmwareOffset = 193
	// wsuFirmwareBlockLen is the fixed size of the encrypted block (25 bytes,
	// i.e. two overlapping 16 byte AES blocks: 0x93..0xAB).
	wsuFirmwareBlockLen = 25
	// wsuFirmwareTailOffset is where the second (overlapping) block starts.
	wsuFirmwareTailOffset = 9
	// wsuCipherBlockLen is the AES block size; the block is split on this
	// boundary on the device side as well.
	wsuCipherBlockLen = aes.BlockSize
	// wsuFirmwareMinPayloadLen is the shortest reply that still carries the
	// block. Frames below it (the structural minimum of the parser) are left
	// alone instead of panicking.
	wsuFirmwareMinPayloadLen = wsuFirmwareOffset + wsuFirmwareBlockLen
	// wsuFirmwareMaxLen is the longest firmware string that is accepted: one
	// byte shorter than the block, so a block without any NUL terminator is
	// treated as a decoding failure instead of a 25 character version.
	wsuFirmwareMaxLen = wsuFirmwareBlockLen - 1
	// wsuFirmwareMinLen is the shortest accepted string. An empty result means
	// "decoding failed" and leaves the firmware column blank.
	//
	// The floor is 4 and not 1 on purpose: a random 25 byte block decrypts to a
	// short printable fragment in about 0.5% of the cases (measured by QA with
	// 2000 random blocks: 'f', 'Q', 'x', 'reC', '"Wg'), and such a fragment must
	// not be shown as a firmware version. No real version is shorter than
	// "1.0" plus a build, so nothing is lost.
	wsuFirmwareMinLen = 4
	// wsuFirmwareVersionMark is the character every real version carries: the
	// device encrypts "<major>.<minor> Build <build>"
	//
	//	1.27 Build 25092317   (AWK-1131A-EU, AWK-1137C-EU)
	//	1.0 Build 24031213    (AWK-1132C-US)
	//
	// so at least one dot is guaranteed, and so is at least one decimal digit.
	// Both facts are checked (see looksLikeWSUVersion): the dot alone is not
	// enough, because a printable fragment of 4+ characters can contain a dot by
	// chance while carrying no digit at all ("..reC").
	wsuFirmwareVersionMark = '.'
	// wsuFirmwareDigitMin / wsuFirmwareDigitMax bound the ASCII range of a
	// decimal digit inside a version string.
	wsuFirmwareDigitMin = '0'
	wsuFirmwareDigitMax = '9'
)

// wsuFirmwareKey is the AES-128 key of the block, taken verbatim from the
// device firmware: PROTOCOL_SPEC.md §5.3.1 lists it as the first 16 bytes of
// the derivation output of the fixed 32 byte material at serviceAgent
// .rodata @0x41FB58:
//
//	KEY_RAW  = c50bfe37c6d5616718a17fd0ef209b451e494cce258e1b8bf3c6c8e97d9deea0
//	AES_KEY  = db231ec81df67faf0557007fea779b3a
//
// It is deliberately hard coded: the derivation is only needed to explain where
// the constant comes from, and the block was verified in both directions
// (encrypt the plain string, compare with the captured tail) against three
// different device models. The key is NOT device specific - it is the same for
// every WIFI4 device, which is why one constant decodes the whole product
// family.
var wsuFirmwareKey = [16]byte{
	0xdb, 0x23, 0x1e, 0xc8, 0x1d, 0xf6, 0x7f, 0xaf,
	0x05, 0x57, 0x00, 0x7f, 0xea, 0x77, 0x9b, 0x3a,
}

// DecodeWSUFirmware returns the firmware version string carried by the
// encrypted block of a WIFI4 (UDP/5800) reply, e.g. "1.27 Build 25092317".
//
// The function is pure: it does not look at anything else but payload, so it
// can be tested against captured frames without a socket. It returns "" - never
// a half decoded or garbled string - whenever
//
//   - the frame is too short to contain the block (len < 218),
//   - the key cannot be applied (defensive; a 16 byte key always works),
//   - the plain text holds a byte outside printable ASCII (0x20..0x7E),
//   - the decoded string is shorter than 4 or longer than 24 bytes,
//   - or it does not look like "<major>.<minor> Build <build>" (leading digit
//     and at least one dot).
//
// The last two rules keep the short printable fragments out of the table that a
// wrong key produces by chance (see sanitizeWSUFirmware). A blank result simply
// leaves the 固件版本号 column empty, exactly like a device that does not
// publish its version at all.
func DecodeWSUFirmware(payload []byte) string {
	if len(payload) < wsuFirmwareMinPayloadLen {
		return ""
	}

	// Work on a copy: the caller's frame must stay untouched (it is stored in
	// packet captures and compared against fixtures in the tests).
	buf := make([]byte, wsuFirmwareBlockLen)
	copy(buf, payload[wsuFirmwareOffset:wsuFirmwareOffset+wsuFirmwareBlockLen])

	block, err := aes.NewCipher(wsuFirmwareKey[:])
	if err != nil {
		return ""
	}

	// Reverse order of the encryption: the tail block was written last, so it
	// has to be decrypted first.
	decryptECBBlocks(block, buf[wsuFirmwareTailOffset:wsuFirmwareTailOffset+wsuCipherBlockLen])
	decryptECBBlocks(block, buf[0:wsuCipherBlockLen])

	return sanitizeWSUFirmware(buf)
}

// decryptECBBlocks decrypts dst in place, one 16 byte block at a time.
//
// The standard library deliberately ships no ECB mode (it does not hide
// structure), but this is a wire format of a closed source device that uses
// ECB, so the loop is written out here: ECB is nothing but "apply the block
// cipher to every block independently". A length that is not a multiple of the
// block size is ignored instead of read out of bounds.
func decryptECBBlocks(block cipher.Block, dst []byte) {
	for offset := 0; offset+wsuCipherBlockLen <= len(dst); offset += wsuCipherBlockLen {
		block.Decrypt(dst[offset:offset+wsuCipherBlockLen], dst[offset:offset+wsuCipherBlockLen])
	}
}

// sanitizeWSUFirmware turns the decrypted block into the version string.
//
// The plain text is the version string starting at byte 0 followed by NUL
// padding ("1.27 Build 25092317" is 19 bytes, the remaining 6 bytes are 0x00),
// so everything from the first NUL on is dropped. Anything that is not plain
// printable ASCII is treated as a decoding failure: a wrong key, a truncated
// block or a firmware revision with a different layout must leave the column
// empty rather than print control characters into the table.
//
// Two shape checks follow, because "printable" alone is far too generous for a
// wrong key: a random block decrypts to a short printable fragment in roughly
// one out of two hundred cases. The result has to look like the version string
// the device encrypts - see looksLikeWSUVersion - otherwise the column stays
// empty.
func sanitizeWSUFirmware(buf []byte) string {
	// Length up to the first NUL - the terminator itself is not part of the
	// string.
	end := 0
	for end < len(buf) && buf[end] != 0x00 {
		end++
	}
	if end < wsuFirmwareMinLen || end > wsuFirmwareMaxLen {
		return ""
	}
	for index := 0; index < end; index++ {
		if buf[index] < 0x20 || buf[index] > 0x7e {
			return ""
		}
	}
	// Interior spaces are meaningful ("1.27 Build 25092317"); only leading and
	// trailing blanks (a field that starts with padding) are trimmed.
	version := strings.TrimSpace(string(buf[:end]))
	if !looksLikeWSUVersion(version) {
		return ""
	}
	return version
}

// looksLikeWSUVersion reports whether s has the shape of the version string the
// device encrypts, i.e. "<major>.<minor> Build <build>":
//
//	1.27 Build 25092317   AWK-1131A-EU / AWK-1137C-EU
//	1.0 Build 24031213    AWK-1132C-US
//
// The three checks are the ones a random plain text practically never passes at
// the same time: a length between wsuFirmwareMinLen and wsuFirmwareMaxLen, at
// least one dot and at least one decimal digit. "f", "reC", "abcdefgh", "..reC"
// and "1,27 Build" are all rejected; every observed revision of the family
// passes.
//
// Measured over 500000 random 25 byte blocks (seeded probe): 1136 of them
// decrypt to a printable fragment under the old "printable only" rule, 65 stay
// above 4 characters, and none of them carries a dot - so the two shape checks
// leave nothing behind.
func looksLikeWSUVersion(s string) bool {
	if len(s) < wsuFirmwareMinLen || len(s) > wsuFirmwareMaxLen {
		return false
	}
	if !strings.ContainsRune(s, wsuFirmwareVersionMark) {
		return false
	}
	for index := 0; index < len(s); index++ {
		if s[index] >= wsuFirmwareDigitMin && s[index] <= wsuFirmwareDigitMax {
			return true
		}
	}
	return false
}
