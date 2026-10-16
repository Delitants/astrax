// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"astrax/internal/cert"
	"astrax/internal/httpapi"
	"astrax/internal/store"
)

//go:embed web/*
var webFS embed.FS

func main() {
	listen := flag.String("listen", "", "HTTP control web listen address (defaults to config control_listen)")
	httpsListen := flag.String("https-listen", "", "HTTPS control web listen address (defaults to config control_listen_https)")
	configPath := flag.String("config", "./astrax-config.json", "path to config file")
	force := flag.Bool("force", false, "allow multiple instances with the same config")
	flag.Parse()

	pidFile := pidFilePath(*configPath)
	if !*force {
		if pid, running := isProcessRunning(pidFile); running {
			log.Fatalf("another instance is already running with config %s (pid %d). use --force to override", *configPath, pid)
		}
	}

	if err := writePIDFile(pidFile); err != nil {
		log.Fatalf("failed to write pid file %s: %v", pidFile, err)
	}
	defer removePIDFile(pidFile)

	st, err := store.New(*configPath)
	if err != nil {
		log.Fatalf("failed to initialize store: %v", err)
	}

	appDir := filepath.Dir(*configPath)
	certMgr := cert.New(appDir)

	srv, err := httpapi.New(st, webFS, certMgr)
	if err != nil {
		log.Fatalf("failed to initialize http server: %v", err)
	}

	settings := st.Settings()

	// Resolve listen addresses from config when flags are not explicitly set.
	if *listen == "" {
		*listen = settings.ControlListen
		if *listen == "" {
			*listen = "0.0.0.0:8080"
		}
	}

	// Determine TLS config
	tlsCfg, _ := certMgr.TLSConfigWithVersion(settings.TLSMinVersion)
	certPath, keyPath := certMgr.Paths()
	hasCerts := certMgr.Exists()
	if tlsCfg != nil {
		st.SetStreamerTLSConfig(tlsCfg)
	}

	// Determine if redirect is enabled
	redirectHTTPS := settings.RedirectHTTPS && hasCerts

	// Determine HTTPS listen address
	httpsAddr := *httpsListen
	if httpsAddr == "" {
		httpsAddr = settings.ControlListenHTTPS
		if httpsAddr == "" {
			httpsAddr = "0.0.0.0:8443"
		}
	}

	// Reserve the actual flag-resolved management ports for the external API.
	externalAPI := srv.ConfigureExternalAPI(*listen, httpsAddr)

	// Create HTTP server
	httpHandler := srv.Handler()
	if redirectHTTPS {
		httpHandler = redirectHandler(httpsAddr, srv.Handler())
	}

	httpServer := &http.Server{
		Addr:         *listen,
		Handler:      httpHandler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 20 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	var httpsServer *http.Server
	if hasCerts {
		httpsServer = &http.Server{
			Addr:         httpsAddr,
			Handler:      srv.Handler(),
			TLSConfig:    tlsCfg,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 20 * time.Second,
			IdleTimeout:  60 * time.Second,
		}
	}

	go func() {
		log.Printf("AstraX web ui available at http://%s", *listen)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server failed: %v", err)
		}
	}()

	if httpsServer != nil {
		go func() {
			log.Printf("AstraX web ui available at https://%s", httpsAddr)
			if err := httpsServer.ListenAndServeTLS(certPath, keyPath); err != nil && err != http.ErrServerClosed {
				log.Fatalf("https server failed: %v", err)
			}
		}()
	}

	if err := externalAPI.StartConfigured(context.Background()); err != nil {
		log.Printf("external API unavailable (management remains active): %v", err)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Print("shutdown signal received")

	externalShutdown, cancelExternal := context.WithTimeout(context.Background(), 3*time.Second)
	if err := externalAPI.Close(externalShutdown); err != nil {
		log.Printf("external API shutdown: %v", err)
	}
	cancelExternal()
	// Close store next: stops all workers and streamers, which causes long-lived
	// HTTP connections (SSE, streaming) to hit EOF and close on their own.
	st.Close()

	// Then close the HTTP servers. Use a short timeout because streaming clients
	// may take a moment to notice EOF after the demux is closed.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("http server shutdown: %v", err)
	}
	if httpsServer != nil {
		if err := httpsServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("https server shutdown: %v", err)
		}
	}
}

func redirectHandler(httpsAddr string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Don't redirect API or health endpoints — some clients need HTTP.
		if r.URL.Path == "/api/v1/events" || r.URL.Path == "/api/v1/epg" {
			next.ServeHTTP(w, r)
			return
		}
		target := "https://" + httpsAddr + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusPermanentRedirect)
	})
}

func pidFilePath(configPath string) string {
	abs, _ := filepath.Abs(configPath)
	base := filepath.Base(abs)
	return filepath.Join(os.TempDir(), fmt.Sprintf("astrax-%s.pid", base))
}

func isProcessRunning(pidFile string) (int, bool) {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return 0, false
	}
	// Check if process exists by sending signal 0
	err = syscall.Kill(pid, 0)
	if err == nil {
		return pid, true
	}
	// Process does not exist — stale pid file
	_ = os.Remove(pidFile)
	return 0, false
}

func writePIDFile(pidFile string) error {
	return os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0644)
}

func removePIDFile(pidFile string) {
	_ = os.Remove(pidFile)
}
