package proxy

import (
	"errors"
	"io"
	"log"
	"net"
)

type ServiceConfig struct {
	Name     string `json:"name,omitempty"`
	Version  string `json:"version,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Address  string `json:"address,omitempty"`
}

var HostsMap map[string]ServiceConfig

func GetHeader(conn net.Conn) ([]byte, error) {
	buf := make([]byte, 1460)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return nil, err
	}

	if buf[0] == 0x16 {
		headerLen := GetHelloLength(buf[:n]) + 5
		if headerLen > 65535 {
			return nil, errors.New("tls hello is too big")
		}

		header := make([]byte, headerLen)
		copy(header[:], buf[:n])
		offset := n
		for offset < headerLen {
			if n, err = conn.Read(buf); err != nil {
				return nil, err
			}
			copy(header[offset:], buf[:n])
			offset += n
		}
		return header, err
	}

	return buf[:n], err
}

func SNIProxy(client net.Conn) {
	defer client.Close()

	header, err := GetHeader(client)
	if err != nil {
		log.Println(client.RemoteAddr(), err)
	}

	if len(header) == 0 {
		return
	}

	var host string
	if header[0] != 0x16 {
		offset, length := GetHost(header)
		if length == 0 {
			return
		}
		host = string(header[offset : offset+length])
		if net.ParseIP(host) != nil {
			return
		}
	}

	version, offset, length, _ := GetSNI(header)
	if length == 0 {
		host, _, _ = net.SplitHostPort(client.LocalAddr().String())
	} else {
		host = string(header[offset : offset+length])
	}

	config, ok := HostsMap[host]
	if !ok {
		log.Println(client.RemoteAddr(), host, "not allow")
		return
	}

	if version < GetTLSVersionID(config.Version) {
		log.Println(client.RemoteAddr(), host, GetTLSVersionString(version), "< TLS", config.Version)
		return
	}

	conn, err := net.Dial("tcp", config.Address)
	if err != nil {
		log.Println(client.RemoteAddr(), host, err)
		return
	}

	defer conn.Close()

	if _, err = conn.Write(header); err != nil {
		return
	}

	go func() {
		if _, err := io.Copy(client, conn); err != nil {
			return
		}
	}()

	if _, err := io.Copy(conn, client); err != nil {
		return
	}
}
