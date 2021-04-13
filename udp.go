// Copyright 2019 Path Network, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/zap"
)

type udpConnection struct {
	lastActivity   *int64
	clientAddr     *net.UDPAddr
	downstreamAddr *net.UDPAddr
	upstream       *net.UDPConn
	logger         *zap.Logger
}

func udpCloseAfterInactivity(conn *udpConnection, socketClosures chan<- string) {
	for {
		lastActivity := atomic.LoadInt64(conn.lastActivity)
		<-time.After(Opts.UDPCloseAfter)
		if atomic.LoadInt64(conn.lastActivity) == lastActivity {
			break
		}
	}
	conn.upstream.Close()
	if conn.clientAddr != nil {
		socketClosures <- conn.clientAddr.String()
	} else {
		socketClosures <- ""
	}
}

func udpCopyFromUpstream(downstream net.PacketConn, conn *udpConnection) {
	rawConn, err := conn.upstream.SyscallConn()
	if err != nil {
		conn.logger.Error("failed to retrieve raw connection from upstream socket", zap.Error(err))
		return
	}

	var syscallErr error

	err = rawConn.Read(func(fd uintptr) bool {
		buf := GetBuffer()
		defer PutBuffer(buf)

		for {
			n, _, serr := syscall.Recvfrom(int(fd), buf, syscall.MSG_DONTWAIT)
			if serr == syscall.EWOULDBLOCK {
				return false
			}
			if serr != nil {
				syscallErr = serr
				return true
			}
			if n == 0 {
				return true
			}

			atomic.AddInt64(conn.lastActivity, 1)

			if _, serr := downstream.WriteTo(buf[:n], conn.downstreamAddr); serr != nil {
				syscallErr = serr
				return true
			}
		}
	})

	if err == nil {
		err = syscallErr
	}
	if err != nil {
		conn.logger.Debug("failed to read from upstream", zap.Error(err))
	}
}

func udpGetSocketFromMap(downstream net.PacketConn, auxInfo *ConnAuxInfo, logger *zap.Logger,
	connMap map[string]*udpConnection, socketClosures chan<- string) (*udpConnection, error) {
	connKey := ""
	if auxInfo.ppi != nil {
		connKey = auxInfo.ppi.SourceAddr.String()
	}
	if conn := connMap[connKey]; conn != nil {
		atomic.AddInt64(conn.lastActivity, 1)
		return conn, nil
	}

	conn, err := udpGetUpstreamConn(downstream, auxInfo, logger)
	if err != nil {
		logger.Debug("failed to connect to upstream", zap.Error(err))
		return nil, err
	}

	udpConn := &udpConnection{upstream: conn.(*net.UDPConn),
		logger:         logger,
		lastActivity:   new(int64),
		downstreamAddr: auxInfo.connRemoteAddr.(*net.UDPAddr)}
	saddr := auxInfo.connRemoteAddr
	if auxInfo.ppi != nil {
		saddr = auxInfo.ppi.SourceAddr
	}
	udpConn.clientAddr = saddr.(*net.UDPAddr)

	go udpCopyFromUpstream(downstream, udpConn)
	go udpCloseAfterInactivity(udpConn, socketClosures)

	connMap[connKey] = udpConn
	return udpConn, nil
}

func UDPListen(listenConfig *net.ListenConfig, listenAddr string, logger *zap.Logger, errors chan<- error) {
	ctx := context.Background()
	ln, err := listenConfig.ListenPacket(ctx, "udp", listenAddr)
	if err != nil {
		logger.Error("failed to bind listener", zap.Error(err))
		errors <- err
		return
	}

	logger.Info("listening")

	socketClosures := make(chan string, 1024)
	connectionMap := make(map[string]*udpConnection)

	buffer := GetBuffer()
	defer PutBuffer(buffer)

	for {
		n, remoteAddr, err := ln.ReadFrom(buffer)
		if err != nil {
			logger.Error("failed to read from socket", zap.Error(err))
			continue
		}

		if !CheckOriginAllowed(remoteAddr.(*net.UDPAddr).IP) {
			logger.Debug("packet origin not in allowed subnets", zap.String("remoteAddr", remoteAddr.String()))
			continue
		}

		ppi, restBytes, err := TryReadPROXYProtocol(buffer[:n], UDP)
		if err != nil {
			if !Opts.Fallback {
				logger.Debug("failed to parse PROXY header", zap.Error(err), zap.String("remoteAddr", remoteAddr.String()))
				continue
			} else {
				logger.Debug("packet treated as non-PROXY", zap.Error(err), zap.String("local address", ln.LocalAddr().String()), zap.String("remote address", remoteAddr.String()))
			}
		}

		for {
			doneClosing := false
			select {
			case mapKey := <-socketClosures:
				delete(connectionMap, mapKey)
			default:
				doneClosing = true
			}
			if doneClosing {
				break
			}
		}

		auxInfo := &ConnAuxInfo{ppi, restBytes, remoteAddr}
		conn, err := udpGetSocketFromMap(ln, auxInfo, logger, connectionMap, socketClosures)
		if err != nil {
			continue
		}

		_, err = conn.upstream.Write(restBytes)
		if err != nil {
			conn.logger.Error("failed to write to upstream socket", zap.Error(err))
		}
	}
}
