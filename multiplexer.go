package main

import "net"

func GetTargetAddr(ppi *PROXYProtocolInfo, conn net.Conn) string {
	targetAddr := Opts.TargetAddr6
	if AddrVersion(conn.LocalAddr()) == 4 {
		targetAddr = Opts.TargetAddr4
	}
	return targetAddr
}
