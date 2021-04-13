// Copyright 2019 Path Network, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"io"
	"net"

	"go.uber.org/zap"
)

func tcpCopyData(dst net.Conn, src net.Conn, ch chan<- error) {
	_, err := io.Copy(dst, src)
	ch <- err
}

func tcpHandleConnection(conn net.Conn, logger *zap.Logger) {
	defer conn.Close()
	logger = logger.With(zap.String("remoteAddr", conn.RemoteAddr().String()),
		zap.String("localAddr", conn.LocalAddr().String()))

	if !CheckOriginAllowed(conn.RemoteAddr().(*net.TCPAddr).IP) {
		logger.Debug("connection origin not in allowed subnets", zap.Bool("dropConnection", true))
		return
	}

	if Opts.Verbose > 1 {
		logger.Debug("new connection")
	}

	buffer := GetBuffer()
	defer func() {
		if buffer != nil {
			PutBuffer(buffer)
		}
	}()

	n, err := conn.Read(buffer)
	if err != nil {
		logger.Debug("failed to read PROXY header", zap.Error(err), zap.Bool("dropConnection", true))
		return
	}

	ppi, restBytes, err := TryReadPROXYProtocol(buffer[:n], TCP)
	if err != nil {
		if !Opts.Fallback {
			logger.Debug("failed to parse PROXY header", zap.Error(err), zap.Bool("dropConnection", true))
			return
		} else {
			logger.Debug("packet treated as non-PROXY", zap.Error(err), zap.String("local address", conn.LocalAddr().String()), zap.String("remote address", conn.RemoteAddr().String()))
		}
	} else {
		if Opts.Verbose > 1 {
			logger.Debug("successfully parsed PROXY header")
		}
	}

	targetAddr := GetTargetAddr(conn, &ConnAuxInfo{ppi, restBytes}, logger)

	clientAddr := conn.RemoteAddr()
	if ppi != nil {
		clientAddr = ppi.SourceAddr
		logger = logger.With(zap.String("clientAddr", clientAddr.String()), zap.String("targetAddr", targetAddr))
	}

	dialer := net.Dialer{}
	if Opts.EnableTransparentProxy {
		dialer.LocalAddr = clientAddr
		dialer.Control = DialUpstreamControl(dialer.LocalAddr.(*net.TCPAddr).Port)
	}
	upstreamConn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		logger.Debug("failed to establish upstream connection", zap.Error(err), zap.Bool("dropConnection", true))
		return
	}

	defer upstreamConn.Close()
	if Opts.Verbose > 1 {
		logger.Debug("successfully established upstream connection")
	}

	if err := conn.(*net.TCPConn).SetNoDelay(true); err != nil {
		logger.Debug("failed to set nodelay on downstream connection", zap.Error(err), zap.Bool("dropConnection", true))
	} else if Opts.Verbose > 1 {
		logger.Debug("successfully set NoDelay on downstream connection")
	}

	if err := upstreamConn.(*net.TCPConn).SetNoDelay(true); err != nil {
		logger.Debug("failed to set nodelay on upstream connection", zap.Error(err), zap.Bool("dropConnection", true))
	} else if Opts.Verbose > 1 {
		logger.Debug("successfully set NoDelay on upstream connection")
	}

	for len(restBytes) > 0 {
		n, err := upstreamConn.Write(restBytes)
		if err != nil {
			logger.Debug("failed to write data to upstream connection",
				zap.Error(err), zap.Bool("dropConnection", true))
			return
		}
		restBytes = restBytes[n:]
	}

	PutBuffer(buffer)
	buffer = nil

	outErr := make(chan error, 2)
	go tcpCopyData(upstreamConn, conn, outErr)
	go tcpCopyData(conn, upstreamConn, outErr)

	err = <-outErr
	if err != nil {
		logger.Debug("connection broken", zap.Error(err), zap.Bool("dropConnection", true))
	} else if Opts.Verbose > 1 {
		logger.Debug("connection closing")
	}
}

func TCPListen(listenConfig *net.ListenConfig, listenAddr string, logger *zap.Logger, errors chan<- error) {
	ctx := context.Background()
	ln, err := listenConfig.Listen(ctx, "tcp", listenAddr)
	if err != nil {
		logger.Error("failed to bind listener", zap.Error(err))
		errors <- err
		return
	}

	logger.Info("listening")

	for {
		conn, err := ln.Accept()
		if err != nil {
			logger.Error("failed to accept new connection", zap.Error(err))
			errors <- err
			return
		}

		go tcpHandleConnection(conn, logger)
	}
}
