package main

import (
	"go.uber.org/zap"
	"net"
	"regexp"
)

type ProtocolMatchResult int

const (
	ProtocolMatched ProtocolMatchResult = iota
	ProtocolNotMatched
	ProtocolMatchUnspecified
)

const (
	DefaultBytesLength = 512 // Less than the required miminal MSS size for ipv4.
	SmallBytesLength   = 64  // For most eal world packet.
)

type ConnAuxInfo struct {
	ppi          *PROXYProtocolInfo
	initialBytes []byte
	connRemoteAddr net.Addr
}

func (auxInfo *ConnAuxInfo) GetUpstreamDialer() net.Dialer {
	clientAddr := auxInfo.connRemoteAddr
	if auxInfo.ppi != nil {
		clientAddr = auxInfo.ppi.SourceAddr
	}

	dialer := net.Dialer{}
	if Opts.EnableTransparentProxy {
		dialer.LocalAddr = clientAddr
		dialer.Control = DialUpstreamControl(dialer.LocalAddr.(*net.TCPAddr).Port)
	}
	return dialer
}

type ProtocolMatcher interface {
	Name() string
	UpstreamAddr() string
	TcpMatch(conn net.Conn, auxInfo *ConnAuxInfo) ProtocolMatchResult
	UdpMatch(conn net.PacketConn, auxInfo *ConnAuxInfo) ProtocolMatchResult
}

type RegexMatcher struct {
	upstreamAddr string
	matcher      regexMatcher
}

type bytesTransformation = func([]byte) []byte

type regexMatcher struct {
	name                  string
	numRequiredBytes      int
	transformInitialBytes bytesTransformation
	patterns              []*regexp.Regexp
}

func (m *RegexMatcher) Name() string {
	return m.matcher.name
}

func (m *RegexMatcher) UpstreamAddr() string {
	return m.upstreamAddr
}

func (m *RegexMatcher) TcpMatch(conn net.Conn, auxInfo *ConnAuxInfo) ProtocolMatchResult {
	if m.matcher.numRequiredBytes > len(auxInfo.initialBytes) {
		//TODO: Here we should read from conn again, and assign the result back to auxInfo
		return ProtocolMatchUnspecified
	}
	for _, pattern := range m.matcher.patterns {
		bytes := m.matcher.transformInitialBytes(auxInfo.initialBytes)
		if pattern.Match(bytes) {
			return ProtocolMatched
		}
	}
	return ProtocolNotMatched
}

//TODO: Port multiplexing for udp
func (m *RegexMatcher) UdpMatch(conn net.PacketConn, auxInfo *ConnAuxInfo) ProtocolMatchResult {
	return ProtocolNotMatched
}
func sameBytes(bytes []byte) []byte {
	return bytes
}

func bytesAfter(n int) bytesTransformation {
	return func(bytes []byte) []byte {
		return bytes[n:]
	}
}

func bytesBefore(n int) bytesTransformation {
	return func(bytes []byte) []byte {
		return bytes[:n]
	}
}

func bytesWithin(lower int, upper int) bytesTransformation {
	return func(bytes []byte) []byte {
		return bytes[lower:upper]
	}
}

var (
	tlsMatcher = regexMatcher{
		"tls",
		5,
		sameBytes,
		[]*regexp.Regexp{regexp.MustCompile("^\x16\x03\x01")},
	}
	httpMatcher = regexMatcher{
		"http",
		len(" HTTP "),
		bytesBefore(SmallBytesLength),
		[]*regexp.Regexp{regexp.MustCompile("^[A-Z]+ .+ HTTP/")},
	}
	sshMatcher = regexMatcher{
		"ssh",
		len("SSH-"),
		bytesBefore(SmallBytesLength),
		[]*regexp.Regexp{regexp.MustCompile("^SSH-")},
	}
	eternalTerminalMatcher = regexMatcher{
		"eternal terminal",
		8,
		bytesBefore(SmallBytesLength),
		[]*regexp.Regexp{regexp.MustCompile("^\x14\x00\x00\x00\x00\x00\x00\x00")},
	}
)

func NewTLSMatcher(upstreamAddr string) *RegexMatcher {
	return &RegexMatcher{
		upstreamAddr: upstreamAddr,
		matcher:      tlsMatcher,
	}
}

func NewHTTPMatcher(upstreamAddr string) *RegexMatcher {
	return &RegexMatcher{
		upstreamAddr: upstreamAddr,
		matcher:      httpMatcher,
	}
}

func NewSSHMatcher(upstreamAddr string) *RegexMatcher {
	return &RegexMatcher{
		upstreamAddr: upstreamAddr,
		matcher:      sshMatcher,
	}
}

func NewEternalTerminalMatcher(upstreamAddr string) *RegexMatcher {
	return &RegexMatcher{
		upstreamAddr: upstreamAddr,
		matcher:      eternalTerminalMatcher,
	}
}

func tcpGetTargetAddr(conn net.Conn, auxInfo *ConnAuxInfo, logger *zap.Logger) string {
	for _, matcher := range Opts.ProtocolMatchers {
		if matcher.TcpMatch(conn, auxInfo) == ProtocolMatched {
			logger.Debug("Successfully matched packet", zap.String("matcher.Name()", matcher.Name()), zap.String("matcher.UpstreamAddr()", matcher.UpstreamAddr()))
			return matcher.UpstreamAddr()
		}
	}
	logger.Debug("No matcher the packet, using default upstream addr", zap.String("Opts.UpstreamAddr)", Opts.UpstreamAddr))
	return Opts.UpstreamAddr
}

func tcpGetUpstreamConn(conn net.Conn, auxInfo *ConnAuxInfo, logger *zap.Logger) (net.Conn, error) {
	targetAddr := tcpGetTargetAddr(conn, auxInfo, logger)
	dialer := auxInfo.GetUpstreamDialer()
	return dialer.Dial("tcp", targetAddr)
}

func udpGetTargetAddr(conn net.PacketConn, auxInfo *ConnAuxInfo, logger *zap.Logger) string {
	for _, matcher := range Opts.ProtocolMatchers {
		if matcher.UdpMatch(conn, auxInfo) == ProtocolMatched {
			logger.Debug("Successfully matched packet", zap.String("matcher.Name()", matcher.Name()), zap.String("matcher.UpstreamAddr()", matcher.UpstreamAddr()))
			return matcher.UpstreamAddr()
		}
	}
	logger.Debug("No matcher the packet, using default upstream addr", zap.String("Opts.UpstreamAddr)", Opts.UpstreamAddr))
	return Opts.UpstreamAddr
}

func udpGetUpstreamConn(conn net.PacketConn, auxInfo *ConnAuxInfo, logger *zap.Logger) (net.Conn, error) {
	targetAddr := udpGetTargetAddr(conn, auxInfo, logger)
	dialer := auxInfo.GetUpstreamDialer()
	return dialer.Dial("udp", targetAddr)
}
