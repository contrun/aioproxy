package main

import "net"

func GetTargetAddr(ppi *PROXYProtocolInfo, conn net.Conn) string {
	targetAddr := Opts.Upstream
	return targetAddr
}