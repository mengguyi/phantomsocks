package phantomtcp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
)

type ServiceConfig struct {
	Name       string `json:"name,omitempty"`
	Device     string `json:"device,omitempty"`
	MTU        int    `json:"mtu,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	Method     string `json:"method,omitempty"`
	Address    string `json:"address,omitempty"`
	PrivateKey string `json:"privatekey,omitempty"`
	Profile    string `json:"profile,omitempty"`

	Peers []Peer `json:"peers,omitempty"`
}

type InterfaceConfig struct {
	Name   string `json:"name,omitempty"`
	Device string `json:"device,omitempty"`
	DNS    string `json:"dns,omitempty"`
	Hint   string `json:"hint,omitempty"`
	MTU    int    `json:"mtu,omitempty"`
	TTL    int    `json:"ttl,omitempty"`
	MaxTTL int    `json:"maxttl,omitempty"`

	Protocol   string `json:"protocol,omitempty"`
	Address    string `json:"address,omitempty"`
	PublicKey  string `json:"publickey,omitempty"`
	PrivateKey string `json:"privatekey,omitempty"`

	Peers []Peer `json:"peers,omitempty"`

	Timeout  int    `json:"timeout,omitempty"`
	Fallback string `json:"fallback,omitempty"`
}

type Peer struct {
	Name         string `json:"name,omitempty"`
	PublicKey    string `json:"publickey,omitempty"`
	PreSharedKey string `json:"presharedkey,omitempty"`
	Endpoint     string `json:"endpoint,omitempty"`
	KeepAlive    int    `json:"keepalive,omitempty"`
	AllowedIPs   string `json:"allowedips,omitempty"`
}

const (
	DIRECT   = 0x0
	REDIRECT = 0x1
	NAT64    = 0x2
	HTTP     = 0x3
	HTTPS    = 0x4
	SOCKS4   = 0x5
	SOCKS5   = 0x6
)

type PhantomInterface struct {
	Device string
	DNS    string
	Hint   uint32
	MTU    uint16
	TTL    byte
	MaxTTL byte

	Protocol      byte
	Address       string
	Authorization string

	Timeout  uint16
	Fallback *PhantomInterface
}

type IPv4Range struct {
	Start     uint32
	End       uint32
	Interface *PhantomInterface
}

type IPv6Range struct {
	Start     uint64
	End       uint64
	Interface *PhantomInterface
}

type PhantomProfile struct {
	DomainMap  map[string]*PhantomInterface
	IPv4Ranges []IPv4Range
	IPv6Ranges []IPv6Range
}

var DefaultProfile *PhantomProfile = nil
var DefaultInterface *PhantomInterface = nil

var SubdomainDepth = 2
var LogLevel = 0
var Forward bool = false
var PassiveMode = false

const (
	HINT_NONE = 0x0

	HINT_ALPN  = 0x1 << 1
	HINT_HTTPS = 0x1 << 2
	HINT_HTTP2 = 0x1 << 3
	HINT_HTTP3 = 0x1 << 4

	HINT_IPV4 = 0x1 << 5
	HINT_IPV6 = 0x1 << 6

	HINT_MOVE     = 0x1 << 7
	HINT_STRIP    = 0x1 << 8
	HINT_FRONTING = 0x1 << 9

	HINT_TTL   = 0x1 << 10
	HINT_WMD5  = 0x1 << 11
	HINT_NACK  = 0x1 << 12
	HINT_WACK  = 0x1 << 13
	HINT_WCSUM = 0x1 << 14
	HINT_WSEQ  = 0x1 << 15
	HINT_WTIME = 0x1 << 16

	HINT_TFO   = 0x1 << 17
	HINT_UDP   = 0x1 << 18
	HINT_NOTCP = 0x1 << 19
	HINT_DELAY = 0x1 << 20

	HINT_MODE2     = 0x1 << 21
	HINT_DF        = 0x1 << 22
	HINT_SAT       = 0x1 << 23
	HINT_RAND      = 0x1 << 24
	HINT_SSEG      = 0x1 << 25
	HINT_1SEG      = 0x1 << 26
	HINT_TLSFRAG   = 0x1 << 27
	HINT_HTFO      = 0x1 << 28
	HINT_KEEPALIVE = 0x1 << 29
	HINT_SYNX2     = 0x1 << 30
	HINT_ZERO      = 0x1 << 31
)

const HINT_DNS = HINT_ALPN | HINT_HTTPS | HINT_HTTP2 | HINT_HTTP3 | HINT_IPV4 | HINT_IPV6
const HINT_FAKE = HINT_TTL | HINT_WMD5 | HINT_NACK | HINT_WACK | HINT_WCSUM | HINT_WSEQ | HINT_WTIME
const HINT_MODIFY = HINT_FAKE | HINT_SSEG | HINT_1SEG | HINT_TLSFRAG | HINT_TFO | HINT_HTFO | HINT_MODE2 | HINT_MOVE | HINT_STRIP | HINT_FRONTING

var Logger *log.Logger

func logPrintln(level int, v ...interface{}) {
	if LogLevel >= level {
		fmt.Println(v...)
	}
}

func (profile *PhantomProfile) GetInterface(name string) (*PhantomInterface, int) {
	config, ok := profile.DomainMap[name]
	if ok {
		return config, 0
	}

	offset := 0
	for i := 0; i < SubdomainDepth; i++ {
		off := strings.Index(name[offset:], ".")
		if off == -1 {
			break
		}
		offset += off
		config, ok = profile.DomainMap[name[offset:]]
		if ok {
			return config, offset
		}
		offset++
	}

	return DefaultInterface, 0
}

func (profile *PhantomProfile) GetInterfaceByIP(ip net.IP) *PhantomInterface {
	ip4 := ip.To4()
	if ip4 != nil {
		ip := binary.BigEndian.Uint32(ip4)
		lenRanges := len(profile.IPv4Ranges)
		index := sort.Search(lenRanges, func(i int) bool {
			return profile.IPv4Ranges[i].End > ip
		})
		if index >= 0 && index < lenRanges && ip >= profile.IPv4Ranges[index].Start {
			return profile.IPv4Ranges[index].Interface
		}
	} else {
		lenRanges := len(profile.IPv6Ranges)
		ip := binary.BigEndian.Uint64(ip[:16])
		index := sort.Search(len(profile.IPv6Ranges), func(i int) bool {
			return profile.IPv6Ranges[i].End > ip
		})
		if index >= 0 && index < lenRanges && ip >= profile.IPv6Ranges[index].Start {
			return profile.IPv6Ranges[index].Interface
		}
	}

	return DefaultInterface
}

/*
func (profile *PhantomProfile) GetInterface(name string) *PhantomInterface {
	config, ok := profile.DomainMap[name]
	if ok {
		return config
	}

	return DefaultInterface
}
*/

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

func GetSNI(header []byte) (offset int, length int, ech bool) {
	headerLen := len(header)
	ech = false
	offset = 11 + 32
	if offset+1 > headerLen {
		return 0, 0, false
	}
	if header[0] != 0x16 {
		return 0, 0, false
	}
	Version := binary.BigEndian.Uint16(header[1:3])
	if (Version & 0xFFF8) != 0x0300 {
		return 0, 0, false
	}
	Length := binary.BigEndian.Uint16(header[3:5])
	if headerLen <= int(Length)-5 {
		return 0, 0, false
	}
	SessionIDLength := header[offset]
	offset += 1 + int(SessionIDLength)
	if offset+2 > headerLen {
		return 0, 0, false
	}
	CipherSuitersLength := binary.BigEndian.Uint16(header[offset : offset+2])
	offset += 2 + int(CipherSuitersLength)
	if offset >= headerLen {
		return 0, 0, false
	}
	CompressionMethodsLenght := header[offset]
	offset += 1 + int(CompressionMethodsLenght)
	if offset+4 > headerLen {
		return 0, 0, false
	}
	ExtensionsLength := binary.BigEndian.Uint16(header[offset : offset+2])
	offset += 2
	ExtensionsEnd := offset + int(ExtensionsLength)
	if ExtensionsEnd > headerLen {
		return 0, 0, false
	}
	for offset < ExtensionsEnd {
		if offset+4 > headerLen {
			return 0, 0, false
		}
		ExtensionType := binary.BigEndian.Uint16(header[offset : offset+2])
		offset += 2
		ExtensionLength := binary.BigEndian.Uint16(header[offset : offset+2])
		offset += 2
		if ExtensionType == 0 {
			if offset+5 > headerLen {
				return 0, 0, ech
			}
			offset += 3
			ServerNameLength := int(binary.BigEndian.Uint16(header[offset : offset+2]))
			offset += 2
			if offset+ServerNameLength >= headerLen {
				return 0, 0, ech
			}
			return offset, ServerNameLength, ech
		} else if ExtensionType == 65037 {
			ech = true
		}

		offset += int(ExtensionLength)
	}
	return 0, 0, ech
}

func TLSFragment(header []byte, frag_size int) []byte {
	headr_len := len(header)
	first_frag_offset := frag_size / 2
	fragmented_header := make([]byte, headr_len+10)

	copy(fragmented_header, header[:3])
	binary.BigEndian.PutUint16(fragmented_header[3:], uint16(first_frag_offset-5))
	copy(fragmented_header[5:], header[5:first_frag_offset])

	copy(fragmented_header[first_frag_offset:], header[:3])
	binary.BigEndian.PutUint16(fragmented_header[first_frag_offset+3:], uint16(frag_size-first_frag_offset))
	copy(fragmented_header[first_frag_offset+5:], header[first_frag_offset:frag_size])

	copy(fragmented_header[frag_size+5:], header[:3])
	binary.BigEndian.PutUint16(fragmented_header[frag_size+8:], uint16(headr_len-frag_size))
	copy(fragmented_header[frag_size+10:], header[frag_size:])
	return fragmented_header
}

func GetQUICSNI(b []byte) string {
	if b[0] == 0x0d {
		if !(len(b) > 23 && string(b[9:13]) == "Q043") {
			return ""
		}
		if !(len(b) > 26 && b[26] == 0xa0) {
			return ""
		}

		if !(len(b) > 38 && string(b[30:34]) == "CHLO") {
			return ""
		}
		TagNum := int(binary.LittleEndian.Uint16(b[34:36]))

		BaseOffset := 38 + 8*TagNum
		if !(len(b) > BaseOffset) {
			return ""
		}

		var SNIOffset uint16 = 0
		for i := 0; i < TagNum; i++ {
			offset := 38 + i*8
			TagName := b[offset : offset+4]
			OffsetEnd := binary.LittleEndian.Uint16(b[offset+4 : offset+6])
			if bytes.Equal(TagName, []byte{'S', 'N', 'I', 0}) {
				if len(b[BaseOffset:]) < int(OffsetEnd) {
					return ""
				}
				return string(b[BaseOffset:][SNIOffset:OffsetEnd])
			} else {
				SNIOffset = OffsetEnd
			}
		}
	} else if b[0]&0xc0 == 0xc0 {
		if !(len(b) > 5) {
			return ""
		}
		Version := string(b[1:5])
		switch Version {
		case "Q046":
		case "Q050":
			return "" //TODO
		default:
			return ""
		}
		if !(len(b) > 31 && b[30] == 0xa0) {
			return ""
		}

		if !(len(b) > 42 && string(b[34:38]) == "CHLO") {
			return ""
		}
		TagNum := int(binary.LittleEndian.Uint16(b[38:40]))

		BaseOffset := 42 + 8*TagNum
		if !(len(b) > BaseOffset) {
			return ""
		}

		var SNIOffset uint16 = 0
		for i := 0; i < TagNum; i++ {
			offset := 42 + i*8
			TagName := b[offset : offset+4]
			OffsetEnd := binary.LittleEndian.Uint16(b[offset+4 : offset+6])
			if bytes.Equal(TagName, []byte{'S', 'N', 'I', 0}) {
				if len(b[BaseOffset:]) < int(OffsetEnd) {
					return ""
				}
				return string(b[BaseOffset:][SNIOffset:OffsetEnd])
			} else {
				SNIOffset = OffsetEnd
			}
		}
	}

	return ""
}

func HttpMove(conn net.Conn, host string, b []byte) bool {
	data := make([]byte, 1460)
	n := 0
	if host == "" {
		logPrintln(5, string(b))
		copy(data[:], []byte("HTTP/1.1 200 OK"))
		n += 15
	} else if host == "https" || host == "h3" {
		copy(data[:], []byte("HTTP/1.1 302 Found\r\nLocation: https://"))
		n += 38

		header := string(b)
		start := strings.Index(header, "Host: ")
		if start < 0 {
			return false
		}
		start += 6
		end := strings.Index(header[start:], "\r\n")
		if end < 0 {
			return false
		}
		end += start
		copy(data[n:], []byte(header[start:end]))
		n += end - start

		start = 4
		end = strings.Index(header[start:], " ")
		if end < 0 {
			return false
		}
		end += start
		copy(data[n:], []byte(header[start:end]))
		n += end - start
	} else {
		copy(data[:], []byte("HTTP/1.1 302 Found\r\nLocation: "))
		n += 30
		copy(data[n:], []byte(host))
		n += len(host)

		start := 4
		if start >= len(b) {
			return false
		}
		header := string(b)
		end := strings.Index(header[start:], " ")
		if end < 0 {
			return false
		}
		end += start
		copy(data[n:], []byte(header[start:end]))
		n += end - start
	}

	cache_control := []byte("\r\nCache-Control: private")
	copy(data[n:], cache_control)
	n += len(cache_control)

	if host == "h3" {
		alt_svc := []byte("\r\nAlt-Svc: h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000; persist=1")
		copy(data[n:], alt_svc)
		n += len(alt_svc)
	}

	content_length := []byte("\r\nContent-Length: 0\r\n\r\n")
	copy(data[n:], content_length)
	n += len(content_length)

	conn.Write(data[:n])
	return true
}

func (pface *PhantomInterface) DialStrip(host string, fronting string) (*tls.Conn, error) {
	addr, err := pface.ResolveTCPAddr(host, 443)
	if err != nil {
		return nil, err
	}

	var conf *tls.Config
	if fronting == "" {
		conf = &tls.Config{
			InsecureSkipVerify: true,
		}
	} else {
		conf = &tls.Config{
			ServerName:         fronting,
			InsecureSkipVerify: true,
		}
	}

	return tls.Dial("tcp", addr.String(), conf)
}

func LoadProfile(filename string) error {
	conf, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer conf.Close()

	br := bufio.NewReader(conf)

	var CurrentInterface *PhantomInterface = DefaultInterface

	for {
		line, _, err := br.ReadLine()
		if err == io.EOF {
			break
		}

		if len(line) > 0 {
			if line[0] != '#' {
				l := strings.SplitN(string(line), "#", 2)[0]
				keys := strings.SplitN(l, "=", 2)
				if len(keys) > 1 {
					if keys[0] == "dns-min-ttl" {
						logPrintln(2, string(line))
						ttl, err := strconv.Atoi(keys[1])
						if err != nil {
							log.Println(string(line), err)
							return err
						}
						DNSMinTTL = uint32(ttl)
					} else if keys[0] == "subdomain" {
						SubdomainDepth, err = strconv.Atoi(keys[1])
						if err != nil {
							log.Println(string(line), err)
							return err
						}
					} else if keys[0] == "udpmapping" {
						mapping := strings.SplitN(keys[1], ">", 2)
						go UDPMapping(mapping[0], mapping[1])
					} else {
						if strings.HasPrefix(keys[1], "[") {
							quote := keys[1][1 : len(keys[1])-1]
							records, hasCache := DNSCache[quote]
							if hasCache {
								DNSCache[keys[0]] = records
							}
							s, ok := DefaultProfile.DomainMap[quote]
							if ok {
								DefaultProfile.DomainMap[keys[0]] = s
							}
							continue
						} else {
							ip := net.ParseIP(keys[0])
							records := new(DNSRecords)
							if CurrentInterface.Hint&HINT_MODIFY != 0 || CurrentInterface.Protocol != 0 {
								records.Index = AddDNSLie(keys[0], CurrentInterface)
								records.ALPN = CurrentInterface.Hint & HINT_DNS
							}

							addrs := strings.Split(keys[1], ",")
							for i := 0; i < len(addrs); i++ {
								ip := net.ParseIP(addrs[i])
								if ip == nil {
									result, hasCache := DNSCache[addrs[i]]
									if hasCache {
										if records.IPv4Hint != nil {
											if records.IPv4Hint == nil {
												records.IPv4Hint = new(RecordAddresses)
											}
											records.IPv4Hint.Addresses = append(records.IPv4Hint.Addresses, result.IPv4Hint.Addresses...)
										}
										if result.IPv6Hint != nil {
											if records.IPv6Hint == nil {
												records.IPv6Hint = new(RecordAddresses)
											}
											records.IPv6Hint.Addresses = append(records.IPv6Hint.Addresses, result.IPv6Hint.Addresses...)
										}
									} else {
										log.Println(keys[0], addrs[i], "bad address")
									}
								} else {
									ip4 := ip.To4()
									if ip4 != nil {
										if records.IPv4Hint == nil {
											records.IPv4Hint = new(RecordAddresses)
										}
										records.IPv4Hint.Addresses = append(records.IPv4Hint.Addresses, ip4)
									} else {
										if records.IPv6Hint == nil {
											records.IPv6Hint = new(RecordAddresses)
										}
										records.IPv6Hint.Addresses = append(records.IPv6Hint.Addresses, ip)
									}
								}
							}

							if ip == nil {
								DefaultProfile.DomainMap[keys[0]] = CurrentInterface
								DNSCache[keys[0]] = records
							} else {
								DefaultProfile.DomainMap[ip.String()] = CurrentInterface
								DNSCache[ip.String()] = records
							}
						}
					}
				} else {
					if keys[0][0] == '[' {
						pface, ok := InterfaceMap[keys[0][1:len(keys[0])-1]]
						if ok {
							CurrentInterface = pface
							logPrintln(1, keys[0], CurrentInterface)
						} else {
							logPrintln(1, keys[0], "invalid interface")
						}
					} else {
						addr, err := net.ResolveTCPAddr("tcp", keys[0])
						if err == nil {
							DefaultProfile.DomainMap[addr.String()] = CurrentInterface
						} else {
							ipnet, err := netip.ParsePrefix(keys[0])

							if err == nil {
								if ipnet.Addr().Is4() {
									length := uint32(1) << (32 - ipnet.Bits())
									start := binary.BigEndian.Uint32(ipnet.Masked().Addr().AsSlice())

									DefaultProfile.IPv4Ranges = append(
										DefaultProfile.IPv4Ranges,
										IPv4Range{start, start + length, CurrentInterface})
								} else if ipnet.Addr().Is6() {
									length := uint64(1) << (64 - ipnet.Bits())
									start := binary.BigEndian.Uint64(ipnet.Masked().Addr().AsSlice()[:16])

									DefaultProfile.IPv6Ranges = append(
										DefaultProfile.IPv6Ranges,
										IPv6Range{start, start + length, CurrentInterface})
								}
							} else {
								ip := net.ParseIP(keys[0])
								if ip != nil {
									DefaultProfile.DomainMap[ip.String()] = CurrentInterface
								} else {
									if CurrentInterface.DNS != "" || CurrentInterface.Protocol != 0 {
										DefaultProfile.DomainMap[keys[0]] = CurrentInterface
										records := new(DNSRecords)
										DNSCache[keys[0]] = records
									} else {
										DefaultProfile.DomainMap[keys[0]] = nil
									}
								}
							}
						}
					}
				}
			}
		}
	}

	sort.SliceStable(DefaultProfile.IPv4Ranges, func(i, j int) bool {
		return DefaultProfile.IPv4Ranges[i].Start < DefaultProfile.IPv4Ranges[j].Start
	})

	sort.SliceStable(DefaultProfile.IPv6Ranges, func(i, j int) bool {
		return DefaultProfile.IPv6Ranges[i].Start < DefaultProfile.IPv6Ranges[j].Start
	})

	logPrintln(1, "Profile:", filename)

	return nil
}

func LoadHosts(filename string) error {
	hosts, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer hosts.Close()

	br := bufio.NewReader(hosts)

	for {
		line, _, err := br.ReadLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			logPrintln(1, err)
		}

		if len(line) == 0 || line[0] == '#' {
			continue
		}

		k := strings.SplitN(string(line), "\t", 2)
		if len(k) == 2 {
			var records *DNSRecords

			name := k[1]
			_, ok := DNSCache[name]
			if ok {
				continue
			}
			offset := 0
			for i := 0; i < SubdomainDepth; i++ {
				off := strings.Index(name[offset:], ".")
				if off == -1 {
					break
				}
				offset += off
				result, ok := DNSCache[name[offset:]]
				if ok {
					records = new(DNSRecords)
					*records = *result
					DNSCache[name] = records
					continue
				}
				offset++
			}

			pface, _ := DefaultProfile.GetInterface(name)
			if ok && pface.Hint != 0 {
				records.Index = AddDNSLie(name, pface)
				records.ALPN = pface.Hint & HINT_DNS
			}
			ip := net.ParseIP(k[0])
			if ip == nil {
				fmt.Println(ip, "bad ip address")
				continue
			}
			ip4 := ip.To4()
			if ip4 != nil {
				records.IPv4Hint = &RecordAddresses{0x7FFFFFFFFFFFFFFF, []net.IP{ip4}}
			} else {
				records.IPv6Hint = &RecordAddresses{0x7FFFFFFFFFFFFFFF, []net.IP{ip}}
			}
		}
	}

	return nil
}

func GetPAC(address string, profile string) string {
	if profile == "" {
		Context := `function FindProxyForURL(url, host) {
	return '%s';
}`
		return fmt.Sprintf(Context, address)
	}

	rule := ""
	for host := range DefaultProfile.DomainMap {
		rule += fmt.Sprintf("\"%s\":1,\n", host)
	}
	Context := `var proxy = 'SOCKS %s';
var rules = {
%s}
function FindProxyForURL(url, host) {
	if (rules[host] != undefined) {
		return proxy;
	}
	for (var i = 0; i < %d; i++){
		var dot = host.indexOf(".");
		if (dot == -1) {return 'DIRECT';}
		host = host.slice(dot);
		if (rules[host] != undefined) {return proxy;}
		host = host.slice(1);
	}
	return 'DIRECT';
}
`
	return fmt.Sprintf(Context, address, rule, SubdomainDepth)
}

var InterfaceMap map[string]*PhantomInterface

func CreateInterfaces(Interfaces []InterfaceConfig) []string {
	DefaultProfile = &PhantomProfile{DomainMap: make(map[string]*PhantomInterface), IPv4Ranges: nil, IPv6Ranges: nil}
	InterfaceMap = make(map[string]*PhantomInterface)

	contains := func(a []string, x string) bool {
		for _, n := range a {
			if x == n {
				return true
			}
		}
		return false
	}

	var devices []string
	for _, config := range Interfaces {
		var Hint uint32 = HINT_NONE
		for _, h := range strings.Split(config.Hint, ",") {
			if h != "" {
				hint, ok := HintMap[h]
				if ok {
					Hint |= hint
				} else {
					logPrintln(1, "unsupported hint: "+h)
				}
			}
		}

		pface := new(PhantomInterface)
		pface.Device = config.Device
		pface.DNS = config.DNS
		pface.Hint = Hint
		pface.MTU = uint16(config.MTU)
		pface.TTL = byte(config.TTL)
		pface.MaxTTL = byte(config.MaxTTL)
		pface.Address = config.Address
		pface.Timeout = 65535
		pface.Fallback = nil

		if config.Fallback != "" {
			fallback, ok := InterfaceMap[config.Fallback]
			if ok {
				pface.Fallback = fallback
			}
		}

		if config.Timeout > 0 {
			pface.Timeout = uint16(config.Timeout)
		}

		switch config.Protocol {
		case "direct":
			pface.Protocol = DIRECT
		case "redirect":
			pface.Protocol = REDIRECT
		case "nat64":
			pface.Protocol = NAT64
		case "http":
			pface.Protocol = HTTP
			Authorization := []byte(fmt.Sprintf("%s:%s", config.PublicKey, config.PrivateKey))
			pface.Authorization = fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString(Authorization))
		case "https":
			pface.Protocol = HTTPS
			Authorization := []byte(fmt.Sprintf("%s:%s", config.PublicKey, config.PrivateKey))
			pface.Authorization = fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString(Authorization))
		case "socks4":
			pface.Protocol = SOCKS4
		case "socks5":
			pface.Protocol = SOCKS5
		case "socks":
			pface.Protocol = SOCKS5
		}

		InterfaceMap[config.Name] = pface

		if pface.Device != "" && Hint != 0 {
			_, ok := InterfaceMap[pface.Device]
			if !ok && !contains(devices, pface.Device) {
				devices = append(devices, pface.Device)
			}
		}
	}

	default_interface, ok := InterfaceMap["default"]
	if ok {
		DefaultInterface = default_interface
	} else {
		logPrintln(1, "no default interface")
	}

	go ConnectionMonitor(devices)
	return devices
}

func (config *ServiceConfig) StartService() {
}

func (config *InterfaceConfig) StartClient() error {
	return nil
}

func (pface *PhantomInterface) DialTCP(address *net.TCPAddr) (net.Conn, error) {
	return nil, nil
}

func (pface *PhantomInterface) DialUDP(address *net.UDPAddr) (net.Conn, error) {
	return nil, nil
}
