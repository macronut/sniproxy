package proxy

import (
	"bytes"
	"encoding/binary"
)

func GetHost(b []byte) (offset int, length int) {
	offset = bytes.Index(b, []byte("Host: "))
	if offset == -1 {
		return 0, 0
	}
	offset += 6
	length = bytes.Index(b[offset:], []byte("\r\n"))
	if length == -1 {
		return 0, 0
	}

	return
}

func GetHelloLength(header []byte) int {
	headerLen := len(header)
	offset := 11 + 32
	if offset+1 > headerLen {
		return 0
	}
	if header[0] != 0x16 {
		return 0
	}
	Version := binary.BigEndian.Uint16(header[1:3])
	if (Version & 0xFFF8) != 0x0300 {
		return 0
	}
	Length := binary.BigEndian.Uint16(header[3:5])
	return int(Length)
}

func GetSNI(header []byte) (uint16, int, int, bool) {
	headerLen := len(header)
	ech := false
	offset := 11 + 32
	if offset+1 > headerLen {
		return 0, 0, 0, false
	}
	if header[0] != 0x16 {
		return 0, 0, 0, false
	}
	Version := binary.BigEndian.Uint16(header[1:3])
	if (Version & 0xFFF8) != 0x0300 {
		return 0, 0, 0, false
	}
	Length := binary.BigEndian.Uint16(header[3:5])
	if headerLen <= int(Length)-5 {
		return Version, 0, 0, false
	}
	HandshakeType := header[5]
	if HandshakeType != 1 {
		return Version, 0, 0, false
	}
	HandshakeLength := int(binary.BigEndian.Uint32(header[5:9]) & 0xFFFFFF)
	if HandshakeLength > headerLen-9 {
		return Version, 0, 0, false
	}
	Version = binary.BigEndian.Uint16(header[9:11])
	if (Version & 0xFFF8) != 0x0300 {
		return Version, 0, 0, false
	}
	SessionIDLength := header[offset]
	offset += 1 + int(SessionIDLength)
	if offset+2 > headerLen {
		return Version, 0, 0, false
	}
	CipherSuitersLength := binary.BigEndian.Uint16(header[offset : offset+2])
	offset += 2 + int(CipherSuitersLength)
	if offset >= headerLen {
		return Version, 0, 0, false
	}
	CompressionMethodsLenght := header[offset]
	offset += 1 + int(CompressionMethodsLenght)
	if offset+4 > headerLen {
		return Version, 0, 0, false
	}
	ExtensionsLength := binary.BigEndian.Uint16(header[offset : offset+2])
	offset += 2
	ExtensionsEnd := offset + int(ExtensionsLength)
	if ExtensionsEnd > headerLen {
		return Version, 0, 0, false
	}
	for offset < ExtensionsEnd {
		if offset+4 > headerLen {
			return Version, 0, 0, false
		}
		ExtensionType := binary.BigEndian.Uint16(header[offset : offset+2])
		offset += 2
		ExtensionLength := binary.BigEndian.Uint16(header[offset : offset+2])
		offset += 2
		switch ExtensionType {
		case 0:
			if offset+5 > headerLen {
				return Version, 0, 0, ech
			}
			offset += 3
			ServerNameLength := int(binary.BigEndian.Uint16(header[offset : offset+2]))
			offset += 2
			if offset+ServerNameLength >= headerLen {
				return Version, 0, 0, ech
			}
			return Version, offset, ServerNameLength, ech
		case 43:
			SupportedVersionsLength := int(header[offset])
			for i := 0; i < SupportedVersionsLength/2; i++ {
				VersionOffset := offset + 1 + i*2
				SupportedVersion := binary.BigEndian.Uint16(header[VersionOffset : VersionOffset+2])
				if (SupportedVersion < 0x0FFF) && SupportedVersion > Version {
					Version = SupportedVersion
				}
			}
		case 65037:
			ech = true
		}

		offset += int(ExtensionLength)
	}
	return Version, 0, 0, ech
}

func GetTLSVersionString(version uint16) string {
	switch version {
	case 0x301:
		return "TLS 1.0"
	case 0x302:
		return "TLS 1.1"
	case 0x303:
		return "TLS 1.2"
	case 0x304:
		return "TLS 1.3"
	case 0x305:
		return "TLS 1.4" // Reserved
	default:
		return "unknow"
	}
}

func GetTLSVersionID(version string) uint16 {
	switch version {
	case "1.0":
		return 0x301
	case "1.1":
		return 0x302
	case "1.2":
		return 0x303
	case "1.3":
		return 0x304
	case "1.4":
		return 0x305 // Reserved
	default:
		return 0
	}
}
