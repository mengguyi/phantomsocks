package phantomtcp

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

func ReadAtLeast() {

}

func SocksProxy(client net.Conn) {
	defer client.Close()

	host := ""
	var addr net.TCPAddr
	{
		var b [1500]byte
		n, err := client.Read(b[:])
		if err != nil || n < 3 {
			logPrintln(1, client.RemoteAddr(), err)
			return
		}

		var reply []byte
		if b[0] == 0x05 {
			client.Write([]byte{0x05, 0x00})
			n, err = client.Read(b[:4])
			if err != nil || n != 4 {
				return
			}
			switch b[3] {
			case 0x01: //IPv4
				n, err = client.Read(b[:6])
				if n < 6 {
					return
				}
				addr.IP = net.IP(b[:4])
				addr.Port = int(binary.BigEndian.Uint16(b[4:6]))
				// 0x02: connection not allowed by ruleset
				// client.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
			case 0x03: //Domain
				n, err = client.Read(b[:])
				addrLen := b[0]
				if n < int(addrLen+3) {
					return
				}
				host = string(b[1 : addrLen+1])
				addr.Port = int(binary.BigEndian.Uint16(b[n-2:]))
				// 0x02: connection not allowed by ruleset
				//client.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
			case 0x04: //IPv6
				n, err = client.Read(b[:])
				if n < 18 {
					return
				}
				addr.IP = net.IP(b[:16])
				addr.Port = int(binary.BigEndian.Uint16(b[16:18]))
				// 0x02: connection not allowed by ruleset
				// logPrintln(3, "connection not allowed by ruleset from", client.RemoteAddr())
			default:
				// 0x08: address type not supported
				logPrintln(3, "address type", b[0], "not supported from", client.RemoteAddr())
				client.Write([]byte{5, 9, 0, 1, 0, 0, 0, 0, 0, 0})
				return
			}
			reply = []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		} else if b[0] == 0x04 {
			if n > 8 && b[1] == 1 {
				userEnd := 8 + bytes.IndexByte(b[8:n], 0)
				addr.Port = int(binary.BigEndian.Uint16(b[2:4]))
				if b[4]|b[5]|b[6] == 0 {
					hostEnd := bytes.IndexByte(b[userEnd+1:n], 0)
					if hostEnd > 0 {
						host = string(b[userEnd+1 : userEnd+1+hostEnd])
					} else {
						client.Write([]byte{0, 91, 0, 0, 0, 0, 0, 0})
						return
					}
				} else {
					addr.IP = net.IP(b[4:8])
				}

				reply = []byte{0, 90, b[2], b[3], b[4], b[5], b[6], b[7]}
			} else {
				client.Write([]byte{0, 91, 0, 0, 0, 0, 0, 0})
				return
			}
		} else {
			logPrintln(3, "unknow from", client.RemoteAddr())
			return
		}

		if err == nil {
			_, err = client.Write(reply)
		}

		if err != nil {
			logPrintln(1, err)
			return
		}
	}

	tcp_redirect(client, &addr, host, nil)
}

func validOptionalPort(port string) bool {
	if port == "" {
		return true
	}
	if port[0] != ':' {
		return false
	}
	for _, b := range port[1:] {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

func splitHostPort(hostport string) (host string, port int) {
	var err error
	host = hostport
	port = 0

	colon := strings.LastIndexByte(host, ':')
	if colon != -1 && validOptionalPort(host[colon:]) {
		port, err = strconv.Atoi(host[colon+1:])
		if err != nil {
			port = 0
		}
		host = host[:colon]
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}

	return
}

func GetHeader(conn net.Conn) ([]byte, error) {
	buf := make([]byte, 1460)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return nil, err
	}

	if buf[0] == 0x16 {
		headerLen := GetHelloLength(buf[:n]) + 5
		if headerLen > 2440 {
			return nil, errors.New("tls hello is too big")
		}
		if headerLen > n {
			logPrintln(2, "tls big hello")
			header := make([]byte, headerLen)
			copy(header[:], buf[:n])
			n, err = conn.Read(header[n:])
			if err == nil {
				return header, err
			}
		}
	}

	return buf[:n], err
}

func HTTPProxy(client net.Conn) {
	defer client.Close()

	var b [1500]byte
	n, err := client.Read(b[:])
	if err != nil {
		log.Println(err)
		return
	}

	request := b[:n]
	var method, host string
	var port int

	end := bytes.IndexByte(request, '\n')
	if end < 0 {
		return
	}

	fmt.Sscanf(string(request[:end]), "%s%s", &method, &host)
	host, port = splitHostPort(host)
	if port == 0 {
		port = 80
	}

	if method == "CONNECT" {
		fmt.Fprint(client, "HTTP/1.1 200 Connection established\r\n\r\n")
		n, err = client.Read(b[:])
		if err != nil {
			logPrintln(1, err)
			return
		}
		tcp_redirect(client, &net.TCPAddr{Port: port}, host, b[:n])
		return
	} else {
		if strings.HasPrefix(host, "http://") {
			host = host[7:]
			index := strings.IndexByte(host, '/')
			if index != -1 {
				host = host[:index]
			}
			request = bytes.Replace(b[:n], []byte("http://"+host), nil, 1)
			HttpMove(client, "https", request)
		} else {
			return
		}
	}
}

func SNIProxy(client net.Conn) {
	defer client.Close()

	header, err := GetHeader(client)
	if err != nil {
		logPrintln(1, client.RemoteAddr(), err)
	}

	var host string
	var port int
	if header != nil && header[0] == 0x16 {
		offset, length, _ := GetSNI(header)
		if length == 0 {
			return
		}
		host = string(header[offset : offset+length])
		port = 443
	} else {
		offset, length := GetHost(header)
		if length == 0 {
			return
		}
		host = string(header[offset : offset+length])
		portstart := strings.Index(host, ":")
		if portstart == -1 {
			port = 80
		} else {
			port, err = strconv.Atoi(host[portstart+1:])
			if err != nil {
				return
			}
			host = host[:portstart]
		}
		if net.ParseIP(host) != nil {
			return
		}
	}

	tcp_redirect(client, &net.TCPAddr{Port: port}, host, header)
}

func RedirectProxy(client net.Conn) {
	addr, err := GetOriginalDST(client.(*net.TCPConn))
	if err != nil {
		client.Close()
		logPrintln(1, err)
		return
	}

	if addr.String() == client.LocalAddr().String() {
		client.Close()
		return
	}
	tcp_redirect(client, addr, "", nil)
}

func tcp_redirect(client net.Conn, addr *net.TCPAddr, domain string, header []byte) {
	defer client.Close()

	start_time := time.Now()

	var conn net.Conn
	var err error
	{
		var pface *PhantomInterface = nil
		port := addr.Port

		if domain == "" {
			switch addr.IP[0] {
			case 0x00:
				index := int(binary.BigEndian.Uint32(addr.IP[12:16]))
				if index >= len(Nose) {
					return
				}
				domain, pface = GetDNSLie(index)
				addr.IP = nil
			case VirtualAddrPrefix:
				index := int(binary.BigEndian.Uint16(addr.IP[2:4]))
				if index >= len(Nose) {
					return
				}
				domain, pface = GetDNSLie(index)
				addr.IP = nil
			}
		}

		if pface == nil {
			if domain == "" {
				pface = DefaultProfile.GetInterfaceByIP(addr.IP)
				if pface != nil {
					domain = addr.IP.String()
				}
			} else {
				pface, _ = DefaultProfile.GetInterface(domain)
			}
		}

		if pface != nil && (pface.Protocol != 0 || pface.Hint != 0) {
			if pface.Hint&HINT_NOTCP != 0 {
				time.Sleep(time.Second)
				return
			}

			if header == nil {
				header, err = GetHeader(client)
				if err != nil {
					logPrintln(1, domain, err)
					return
				}
			}

			if addr.IP == nil && header != nil && header[0] == 0x16 {
				offset, length, ech := GetSNI(header)
				if length > 0 {
					sni := string(header[offset : offset+length])
					if domain != sni {
						if ech {
							logPrintln(2, domain, "tls hello with ECH", sni)
						} else {
							pface, _ = DefaultProfile.GetInterface(sni)
							if pface == nil {
								return
							}
							domain = sni
						}
					}

					if pface.Hint&HINT_TLSFRAG != 0 {
						header = TLSFragment(header, offset+length/2)
					}
				}

				logPrintln(1, "Redirect:", client.RemoteAddr(), "->", domain, port, pface.Device, time.Since(start_time))

				conn, _, err = pface.Dial(nil, domain, port, header)
				if err == nil {
					var server_hello [4096]byte
					var helloLen int
					err = conn.SetReadDeadline(time.Now().Add(time.Millisecond * time.Duration(pface.Timeout)))
					if err == nil {
						helloLen, err = conn.Read(server_hello[:])
					}
					if err == nil {
						conn.SetReadDeadline(time.Time{})
						_, err := client.Write(server_hello[:helloLen])
						if err != nil {
							logPrintln(2, domain, err)
							return
						}
					}
				}

				if err != nil && pface.Fallback != nil {
					pface = pface.Fallback
					logPrintln(1, "Redirect:", client.RemoteAddr(), "->", domain, port, pface.Device, time.Since(start_time))
					conn, _, err = pface.Dial(nil, domain, port, header)
				}

				if err != nil {
					logPrintln(2, domain, err)
					return
				}
			} else {
				logPrintln(1, "Redirect:", client.RemoteAddr(), "->", domain, port, pface.Device, time.Since(start_time))
				if pface.Hint&HINT_HTTP3 != 0 {
					HttpMove(client, "h3", header)
					return
				} else if pface.Hint&HINT_HTTPS != 0 {
					HttpMove(client, "https", header)
					return
				} else if pface.Hint&HINT_MOVE != 0 {
					HttpMove(client, pface.Address, header)
					return
				} else if pface.Hint&HINT_STRIP != 0 {
					if pface.Hint&HINT_FRONTING != 0 {
						conn, err = pface.DialStrip(domain, "")
						domain = ""
					} else {
						conn, err = pface.DialStrip(domain, domain)
					}

					if err != nil {
						logPrintln(1, err)
						return
					}
					_, err = conn.Write(header)
					if err != nil {
						logPrintln(1, err)
						return
					}
				} else {
					var info *ConnectionInfo
					conn, info, err = pface.Dial(nil, domain, port, header)
					if err != nil && pface.Fallback != nil {
						pface = pface.Fallback
						logPrintln(1, "Redirect:", client.RemoteAddr(), "->", domain, port, pface.Device, time.Since(start_time))
						conn, _, err = pface.Dial(nil, domain, port, header)
					}

					if err != nil {
						logPrintln(2, domain, err)
						return
					}

					if info != nil {
						pface.Keep(client, conn, info)
						return
					}
				}
			}
		} else if addr.IP != nil {
			logPrintln(1, "Redirect:", client.RemoteAddr(), "->", addr)
			conn, err = net.DialTCP("tcp", nil, addr)
			if err != nil {
				logPrintln(1, domain, err)
				return
			}
			if header != nil {
				conn.Write(header)
			}
		} else {
			logPrintln(1, "Redirect:", client.RemoteAddr(), "->", domain, port)
			conn, err = net.Dial("tcp", domain+":"+strconv.Itoa(port))
			if err != nil {
				logPrintln(1, domain, err)
				return
			}
			if header != nil {
				conn.Write(header)
			}
		}
	}

	if conn == nil {
		return
	}

	defer conn.Close()

	_, _, err = relay(client, conn)
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return // ignore i/o timeout
		}
		logPrintln(1, "relay error:", err)
	}
}

func QUICProxy(address string) {
	client, err := ListenUDP(address)
	if err != nil {
		logPrintln(1, err)
		return
	}
	defer client.Close()

	var UDPLock sync.Mutex
	var UDPMap map[string]net.Conn = make(map[string]net.Conn)
	data := make([]byte, 1500)

	for {
		n, clientAddr, err := client.ReadFromUDP(data)
		if err != nil {
			logPrintln(1, err)
			return
		}

		udpConn, ok := UDPMap[clientAddr.String()]

		if ok {
			udpConn.Write(data[:n])
		} else {
			SNI := GetQUICSNI(data[:n])
			if SNI != "" {
				pface, _ := DefaultProfile.GetInterface(SNI)
				if pface.Hint&HINT_UDP == 0 {
					continue
				}
				_, ips := pface.NSLookup(SNI)
				if ips == nil {
					continue
				}

				logPrintln(1, "[QUIC]", clientAddr.String(), SNI, ips)

				udpConn, err = net.DialUDP("udp", nil, &net.UDPAddr{IP: ips[0], Port: 443})
				if err != nil {
					logPrintln(1, err)
					continue
				}

				if pface.Hint&HINT_ZERO != 0 {
					zero_data := make([]byte, 8+rand.Intn(1024))
					_, err = udpConn.Write(zero_data)
					if err != nil {
						logPrintln(1, err)
						continue
					}
				}

				UDPMap[clientAddr.String()] = udpConn
				_, err = udpConn.Write(data[:n])
				if err != nil {
					logPrintln(1, err)
					continue
				}

				go func(clientAddr net.UDPAddr) {
					data := make([]byte, 1500)
					udpConn.SetReadDeadline(time.Now().Add(time.Minute * 2))
					for {
						n, err := udpConn.Read(data)
						if err != nil {
							UDPLock.Lock()
							delete(UDPMap, clientAddr.String())
							UDPLock.Unlock()
							udpConn.Close()
							return
						}
						udpConn.SetReadDeadline(time.Now().Add(time.Minute * 2))
						client.WriteToUDP(data[:n], &clientAddr)
					}
				}(*clientAddr)
			}
		}
	}
}

func SocksUDPProxy(address string) {
	laddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		logPrintln(1, err)
		return
	}
	local, err := net.ListenUDP("udp", laddr)
	if err != nil {
		logPrintln(1, err)
		return
	}
	defer local.Close()

	var ConnLock sync.Mutex
	var ConnMap map[string]net.Conn = make(map[string]net.Conn)
	data := make([]byte, 1472)
	for {
		n, srcAddr, err := local.ReadFromUDP(data)
		if err != nil {
			logPrintln(1, err)
			continue
		}

		var host string
		var port int
		if n < 8 || data[0] != 4 {
			continue
		}
		switch data[1] {
		case 1:
			port = int(binary.BigEndian.Uint16(data[2:4]))
			ConnLock.Lock()
			dstAddr := net.UDPAddr{IP: data[4:8], Port: port, Zone: ""}
			key := strings.Join([]string{srcAddr.String(), dstAddr.String()}, ",")
			conn, ok := ConnMap[key]
			if ok {
				conn.Write(data[8:n])
				ConnLock.Unlock()
				continue
			}
			ConnLock.Unlock()

			var remoteConn net.Conn = nil
			if data[4] == VirtualAddrPrefix {
				index := int(binary.BigEndian.Uint32(data[6:8]))
				if index >= len(Nose) {
					return
				}
				var pface *PhantomInterface
				host, pface = GetDNSLie(index)
				if pface.Protocol != 0 {
					continue
				}
				if pface.Hint&(HINT_UDP|HINT_HTTP3) == 0 {
					continue
				}
				if pface.Hint&(HINT_HTTP3) != 0 {
					if GetQUICVersion(data[:n]) == 0 {
						continue
					}
				}
				_, ips := pface.NSLookup(host)
				if ips == nil {
					continue
				}

				logPrintln(1, "Socks4U:", srcAddr, "->", host, port)
				raddr := net.UDPAddr{IP: ips[0], Port: port}
				remoteConn, err = net.DialUDP("udp", nil, &raddr)
				if err != nil {
					logPrintln(1, err)
					continue
				}

				if pface.Hint&HINT_ZERO != 0 {
					zero_data := make([]byte, 8+rand.Intn(1024))
					_, err = remoteConn.Write(zero_data)
					if err != nil {
						logPrintln(1, err)
						continue
					}
				}

				_, err = remoteConn.Write(data[8:n])
			} else {
				logPrintln(1, "Socks4U:", srcAddr, "->", dstAddr)
				remoteConn, err = net.DialUDP("udp", nil, &dstAddr)
				if err != nil {
					logPrintln(1, err)
					continue
				}
				_, err = remoteConn.Write(data[8:n])
			}

			if err != nil {
				logPrintln(1, err)
				continue
			}

			go func(srcAddr net.UDPAddr, remoteConn net.Conn, key string) {
				data := make([]byte, 1472)
				remoteConn.SetReadDeadline(time.Now().Add(time.Minute * 2))
				for {
					n, err := remoteConn.Read(data)
					if err != nil {
						ConnLock.Lock()
						delete(ConnMap, key)
						ConnLock.Unlock()
						remoteConn.Close()
						return
					}
					remoteConn.SetReadDeadline(time.Now().Add(time.Minute * 2))
					local.WriteToUDP(data[:n], &srcAddr)
				}
			}(*srcAddr, remoteConn, key)
		default:
			continue
		}
	}
}

func Netcat(client net.Conn) {
	defer client.Close()

	for {
		var b [1460]byte
		n, err := client.Read(b[:])
		if err != nil {
			logPrintln(2, client.RemoteAddr(), err)
			return
		}
		if n == 0 {
			return
		}

		cmd := strings.Fields(string(b[:n]))
		if len(cmd) > 0 {
			log.Println(client.RemoteAddr(), cmd)
			cmdlen := len(cmd)
			switch cmd[0] {
			case "host":
				if cmdlen > 1 {
					domain := cmd[1]
					pface, _ := DefaultProfile.GetInterface(domain)
					_, addrs := pface.NSLookup(domain)
					for _, addr := range addrs {
						client.Write([]byte(addr.String() + "\n"))
					}
				}
			case "load":
				if cmdlen > 1 {
					err := LoadProfile(cmd[1])
					if err != nil {
						logPrintln(1, err)
					}
				}
			case "flush":
				if cmdlen > 1 {
					if cmd[1] == "all" {
						for _, records := range DNSCache {
							if records.IPv4Hint.TTL != 0 {
								records.IPv4Hint = nil
							}
							if records.IPv6Hint.TTL != 0 {
								records.IPv6Hint = nil
							}
						}
					} else {
						records, ok := DNSCache[cmd[1]]
						if ok {
							if records.IPv4Hint.TTL != 0 {
								records.IPv4Hint = nil
							}
							if records.IPv6Hint.TTL != 0 {
								records.IPv6Hint = nil
							}
						}
					}
				}
			}
		}
	}
}

func (pface *PhantomInterface) ProxyHandshake(conn net.Conn, synpacket *ConnectionInfo, host string, port int, header []byte) (net.Conn, error) {
	var err error
	proxy_err := errors.New("invalid proxy")

	hint := pface.Hint & HINT_MODIFY
	var proxy_seq uint32 = 0
	switch pface.Protocol {
	case DIRECT:
	case REDIRECT:
	case NAT64:
	case HTTP:
		{
			header := fmt.Sprintf("CONNECT %s HTTP/1.1\r\n", net.JoinHostPort(host, strconv.Itoa(port)))
			if pface.Authorization != "" {
				header += fmt.Sprintf("Authorization: Basic %s\r\n", pface.Authorization)
			}
			header += "\r\n"
			request := []byte(header)
			fakepayload := make([]byte, len(request))
			var n int = 0
			if synpacket != nil {
				if hint&HINT_SSEG != 0 {
					n, err = conn.Write(request[:4])
					if err != nil {
						return conn, err
					}
				} else if hint&HINT_MODE2 != 0 {
					n, err = conn.Write(request[:10])
					if err != nil {
						return conn, err
					}
				}

				proxy_seq += uint32(n)
				err = ModifyAndSendPacket(synpacket, fakepayload, hint, pface.TTL, 2)
				if err != nil {
					return conn, err
				}

				if hint&HINT_SSEG != 0 {
					n, err = conn.Write(request[4:])
				} else if hint&HINT_MODE2 != 0 {
					n, err = conn.Write(request[10:])
				} else {
					n, err = conn.Write(request)
				}
				if err != nil {
					return conn, err
				}
				proxy_seq += uint32(n)
			} else {
				n, err = conn.Write(request)
				if err != nil || n == 0 {
					return conn, err
				}
			}
			var response [128]byte
			n, err = conn.Read(response[:])
			if err != nil || !strings.HasPrefix(string(response[:n]), "HTTP/1.1 200 ") {
				return conn, errors.New("failed to connect to proxy")
			}
		}
	case HTTPS:
		{
			var b [264]byte
			if synpacket != nil {
				err := ModifyAndSendPacket(synpacket, b[:], hint, pface.TTL, 2)
				if err != nil {
					return conn, err
				}
			}
			conf := &tls.Config{
				InsecureSkipVerify: true,
			}
			conn = tls.Client(conn, conf)
			header := fmt.Sprintf("CONNECT %s HTTP/1.1\r\n", net.JoinHostPort(host, strconv.Itoa(port)))
			if pface.Authorization != "" {
				header += fmt.Sprintf("Authorization: Basic %s\r\n", pface.Authorization)
			}
			header += "\r\n"
			request := []byte(header)
			n, err := conn.Write(request)
			if err != nil || n == 0 {
				return conn, err
			}
			var response [128]byte
			n, err = conn.Read(response[:])
			if err != nil || !strings.HasPrefix(string(response[:n]), "HTTP/1.1 200 ") {
				return conn, errors.New("failed to connect to proxy")
			}
		}
	case SOCKS4:
		{
			var b [264]byte
			if synpacket != nil {
				err := ModifyAndSendPacket(synpacket, b[:], hint, pface.TTL, 2)
				if err != nil {
					return conn, err
				}
			}

			copy(b[:], []byte{0x04, 0x01})
			binary.BigEndian.PutUint16(b[2:], uint16(port))

			requestLen := 0
			ip := net.ParseIP(host).To4()
			if ip != nil {
				copy(b[4:], ip[:4])
				b[8] = 0
				requestLen = 9
			} else {
				copy(b[4:], []byte{0, 0, 0, 1, 0})
				copy(b[9:], []byte(host))
				requestLen = 9 + len(host)
				b[requestLen] = 0
				requestLen++
			}
			n, err := conn.Write(b[:requestLen])
			if err != nil {
				return conn, err
			}
			proxy_seq += uint32(n)
			n, err = conn.Read(b[:8])
			if err != nil {
				return conn, err
			}
			if n < 8 || b[0] != 0 || b[1] != 90 {
				return conn, proxy_err
			}
		}
	case SOCKS5:
		{
			var b [264]byte
			if synpacket != nil {
				err := ModifyAndSendPacket(synpacket, b[:], hint, pface.TTL, 2)
				if err != nil {
					return conn, err
				}
			}

			n, err := conn.Write([]byte{0x05, 0x01, 0x00})
			if err != nil {
				return conn, err
			}
			proxy_seq += uint32(n)
			_, err = conn.Read(b[:])
			if err != nil {
				return conn, err
			}

			if b[0] != 0x05 {
				return nil, proxy_err
			}

			if pface.DNS != "" {
				_, ips := pface.NSLookup(host)
				if ips != nil {
					ip := ips[rand.Intn(len(ips))]
					ip4 := ip.To4()
					if ip4 != nil {
						copy(b[:], []byte{0x05, 0x01, 0x00, 0x01})
						copy(b[4:], ip4[:4])
						binary.BigEndian.PutUint16(b[8:], uint16(port))
						n, err = conn.Write(b[:10])
					} else {
						copy(b[:], []byte{0x05, 0x01, 0x00, 0x04})
						copy(b[4:], ip[:16])
						binary.BigEndian.PutUint16(b[20:], uint16(port))
						n, err = conn.Write(b[:22])
					}
					host = ""
				}
			}

			if host != "" {
				copy(b[:], []byte{0x05, 0x01, 0x00, 0x03})
				hostLen := len(host)
				b[4] = byte(hostLen)
				copy(b[5:], []byte(host))
				binary.BigEndian.PutUint16(b[5+hostLen:], uint16(port))
				n, err = conn.Write(b[:7+hostLen])
			}

			if err != nil {
				return conn, err
			}

			proxy_seq += uint32(n)

			n, err = conn.Read(b[:])
			if err != nil {
				return conn, err
			}
			if n < 2 || b[0] != 0x05 || b[1] != 0x00 {
				return nil, proxy_err
			}
		}
	}

	if synpacket != nil {
		synpacket.TCP.Seq += proxy_seq
	}

	if err == nil && header != nil {
		_, err = conn.Write(header)
	}

	return conn, err
}
