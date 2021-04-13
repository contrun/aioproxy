// Copyright 2019 Path Network, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"time"

	"go.uber.org/zap"
)

type options struct {
	Protocol                    string
	ListenAddr                  arrayFlags
	UpstreamAddr                string
	Fallback                    bool
	EnableTransparentProxy      bool
	Mark                        int
	Verbose                     int
	allowedSubnetsPath          string
	AllowedSubnets              []*net.IPNet
	Listeners                   int
	ProtocolMatchers            []ProtocolMatcher
	tlsUpstreamAddr             string
	httpUpstreamAddr            string
	sshUpstreamAddr             string
	eternalTerminalUpstreamAddr string
	Logger                      *zap.Logger
	udpCloseAfter               int
	UDPCloseAfter               time.Duration
}

type arrayFlags []string

func (i *arrayFlags) String() string {
	if i == nil {
		return "[]"
	}
	return fmt.Sprintf("%+q", *i)
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var Opts options

func init() {
	flag.StringVar(&Opts.Protocol, "p", "tcp", "Protocol that will be proxied: tcp, udp, both")
	flag.BoolVar(&Opts.Fallback, "fallback", true, "Whether to fallback when decode on decoding PROXY protocol failure")
	flag.BoolVar(&Opts.EnableTransparentProxy, "t", true, "Whether to enable transparent proxy")
	flag.Var(&(Opts.ListenAddr), "l", "Address the proxy listens on")
	flag.StringVar(&Opts.UpstreamAddr, "u", "127.0.0.1:443", "UpstreamAddr address to which traffic will be forwarded to")
	flag.StringVar(&Opts.httpUpstreamAddr, "http", "", "UpstreamAddr address to which http traffic will be forwarded to")
	flag.StringVar(&Opts.tlsUpstreamAddr, "tls", "", "UpstreamAddr address to which tls traffic will be forwarded to")
	flag.StringVar(&Opts.sshUpstreamAddr, "ssh", "", "UpstreamAddr address to which ssh traffic will be forwarded to")
	flag.StringVar(&Opts.eternalTerminalUpstreamAddr, "eternal-terminal", "", "UpstreamAddr address to which eternal terminal traffic will be forwarded to")
	flag.IntVar(&Opts.Mark, "mark", 0, "The mark that will be set on outbound packets")
	flag.IntVar(&Opts.Verbose, "v", 0, `0 - no logging of individual connections
1 - log errors occurring in individual connections
2 - log all state changes of individual connections`)
	flag.StringVar(&Opts.allowedSubnetsPath, "allowed-subnets", "",
		"Path to a file that contains allowed subnets of the proxy servers")
	flag.IntVar(&Opts.Listeners, "listeners", 1,
		"Number of listener sockets that will be opened for the listen address (Linux 3.9+)")
	flag.IntVar(&Opts.udpCloseAfter, "close-after", 60, "Number of seconds after which UDP socket will be cleaned up")
}

func listen(listenerNum int, errors chan<- error) {
	logger := Opts.Logger.With(zap.Int("listenerNum", listenerNum),
		zap.String("protocol", Opts.Protocol), zap.Stringer("listenAdr", &Opts.ListenAddr))

	listenConfig := net.ListenConfig{}
	if Opts.Listeners > 1 {
		listenConfig.Control = func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				soReusePort := 15
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1); err != nil {
					logger.Warn("failed to set SO_REUSEPORT - only one listener setup will succeed")
				}
			})
		}
	}

	for _, addr := range Opts.ListenAddr {
		if Opts.Protocol == "tcp" {
			go TCPListen(&listenConfig, addr, logger, errors)
		} else if Opts.Protocol == "udp" {
			go UDPListen(&listenConfig, addr, logger, errors)
		} else {
			go TCPListen(&listenConfig, addr, logger, errors)
			go UDPListen(&listenConfig, addr, logger, errors)
		}
	}
}

func loadAllowedSubnets() error {
	file, err := os.Open(Opts.allowedSubnetsPath)
	if err != nil {
		return err
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		_, ipNet, err := net.ParseCIDR(scanner.Text())
		if err != nil {
			return err
		}
		Opts.AllowedSubnets = append(Opts.AllowedSubnets, ipNet)
		Opts.Logger.Info("allowed subnet", zap.String("subnet", ipNet.String()))
	}

	return nil
}

func initLogger() error {
	logConfig := zap.NewProductionConfig()
	if Opts.Verbose > 0 {
		logConfig.Level.SetLevel(zap.DebugLevel)
	}

	l, err := logConfig.Build()
	if err == nil {
		Opts.Logger = l
	}
	return err
}

func main() {
	flag.Parse()
	if err := initLogger(); err != nil {
		log.Fatalf("Failed to initialize logging: %s", err.Error())
	}
	defer Opts.Logger.Sync()

	if Opts.tlsUpstreamAddr != "" {
		Opts.Logger.Debug("added tls forwarder", zap.String("upstreamAddr", Opts.tlsUpstreamAddr))
		Opts.ProtocolMatchers = append(Opts.ProtocolMatchers, NewTLSMatcher(Opts.tlsUpstreamAddr))
	}

	if Opts.httpUpstreamAddr != "" {
		Opts.Logger.Debug("added http forwarder", zap.String("upstreamAddr", Opts.httpUpstreamAddr))
		Opts.ProtocolMatchers = append(Opts.ProtocolMatchers, NewHTTPMatcher(Opts.httpUpstreamAddr))
	}

	if Opts.sshUpstreamAddr != "" {
		Opts.Logger.Debug("added ssh forwarder", zap.String("upstreamAddr", Opts.sshUpstreamAddr))
		Opts.ProtocolMatchers = append(Opts.ProtocolMatchers, NewSSHMatcher(Opts.sshUpstreamAddr))
	}

	if Opts.eternalTerminalUpstreamAddr != "" {
		Opts.Logger.Debug("added eternalTerminal forwarder", zap.String("upstreamAddr", Opts.eternalTerminalUpstreamAddr))
		Opts.ProtocolMatchers = append(Opts.ProtocolMatchers, NewEternalTerminalMatcher(Opts.eternalTerminalUpstreamAddr))
	}

	if Opts.allowedSubnetsPath != "" {
		if err := loadAllowedSubnets(); err != nil {
			Opts.Logger.Fatal("failed to load allowed subnets file",
				zap.String("path", Opts.allowedSubnetsPath), zap.Error(err))
		}
	}

	if Opts.Protocol != "tcp" && Opts.Protocol != "udp" && Opts.Protocol != "both" {
		Opts.Logger.Fatal("--protocol has to be one of udp, tcp, both", zap.String("protocol", Opts.Protocol))
	}

	if len(Opts.ListenAddr) == 0 {
		Opts.Logger.Fatal("-l not specifed, no listening port")
	}

	if Opts.Mark < 0 {
		Opts.Logger.Fatal("--mark has to be >= 0", zap.Int("mark", Opts.Mark))
	}

	if Opts.Verbose < 0 {
		Opts.Logger.Fatal("-v has to be >= 0", zap.Int("verbose", Opts.Verbose))
	}

	if Opts.Listeners < 1 {
		Opts.Logger.Fatal("--listeners has to be >= 1")
	}

	if Opts.udpCloseAfter < 0 {
		Opts.Logger.Fatal("--close-after has to be >= 0", zap.Int("close-after", Opts.udpCloseAfter))
	}
	Opts.UDPCloseAfter = time.Duration(Opts.udpCloseAfter) * time.Second

	listenErrors := make(chan error, Opts.Listeners)
	for i := 0; i < Opts.Listeners; i++ {
		go listen(i, listenErrors)
	}
	for i := 0; i < Opts.Listeners; i++ {
		<-listenErrors
	}
}
