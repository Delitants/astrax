// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package main

import (
	"context"
	"crypto/tls"
	"embed"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"astrax/internal/adminauth"
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

	prepared, err := prepareManagement(*configPath, *listen, *httpsListen)
	if err != nil {
		log.Fatalf("management preflight failed: %v", err)
	}
	defer prepared.Close()
	st := prepared.store
	srv, err := httpapi.NewWithManagementTransport(st, webFS, prepared.certManager, prepared.auth, prepared.admission)
	if err != nil {
		prepared.Close()
		log.Fatalf("failed to initialize http server: %v", err)
	}
	managementHandler := srv.Handler()
	var httpHandler http.Handler = managementHandler
	if prepared.redirectHTTPS {
		httpHandler = redirectHandler(prepared.redirectAddr)
	}
	externalAPI := srv.ConfigureExternalAPI(prepared.httpAddr, prepared.httpsAddr)

	httpServer := &http.Server{
		Addr:         prepared.httpAddr,
		Handler:      httpHandler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 20 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	var httpsServer *http.Server
	if prepared.httpsListener != nil {
		httpsServer = &http.Server{
			Addr:         prepared.httpsAddr,
			Handler:      managementHandler,
			TLSConfig:    prepared.tlsConfig,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 20 * time.Second,
			IdleTimeout:  60 * time.Second,
		}
	}
	if err := st.StartRuntime(); err != nil {
		prepared.Close()
		log.Fatalf("failed to activate store runtime: %v", err)
	}
	if prepared.tlsConfig != nil {
		st.SetStreamerTLSConfig(prepared.tlsConfig)
	}

	go func() {
		log.Printf("AstraX management HTTP listener reserved at %s", prepared.httpAddr)
		if err := httpServer.Serve(prepared.httpListener); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server failed: %v", err)
		}
	}()

	if httpsServer != nil {
		go func() {
			log.Printf("AstraX management HTTPS listener reserved at %s", prepared.httpsAddr)
			if err := httpsServer.ServeTLS(prepared.httpsListener, "", ""); err != nil && err != http.ErrServerClosed {
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

func redirectHandler(httpsAddr string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := "https://" + httpsAddr + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusPermanentRedirect)
	})
}

type preparedManagement struct {
	store         *store.Store
	auth          *adminauth.Manager
	certManager   *cert.Manager
	httpListener  net.Listener
	httpsListener net.Listener
	tlsConfig     *tls.Config
	httpAddr      string
	httpsAddr     string
	redirectAddr  string
	admission     adminauth.Admission
	redirectHTTPS bool
}

func (p *preparedManagement) Close() {
	if p == nil {
		return
	}
	if p.httpsListener != nil {
		_ = p.httpsListener.Close()
	}
	if p.httpListener != nil {
		_ = p.httpListener.Close()
	}
	if p.auth != nil {
		p.auth.Close()
	}
	if p.store != nil {
		p.store.Close()
	}
}

type managementDeps struct {
	storeOptions store.Options
	listen       func(network, address string) (net.Listener, error)
}

func prepareManagement(configPath, listenOverride, httpsOverride string) (*preparedManagement, error) {
	return prepareManagementWith(configPath, listenOverride, httpsOverride, managementDeps{})
}

func prepareManagementWith(configPath, listenOverride, httpsOverride string, deps managementDeps) (_ *preparedManagement, err error) {
	if deps.listen == nil {
		deps.listen = net.Listen
	}
	p := &preparedManagement{}
	defer func() {
		if err != nil {
			p.Close()
		}
	}()
	p.store, err = store.NewDormant(configPath, deps.storeOptions)
	if err != nil {
		return nil, fmt.Errorf("load dormant store: %w", err)
	}
	p.auth, err = adminauth.Open(configPath, p.store.AdminAuthInitialized())
	if err != nil {
		return nil, fmt.Errorf("open administrator state: %w", err)
	}
	settings := p.store.Settings()
	if settings.TLSMinVersion != "" && settings.TLSMinVersion != "1.2" && settings.TLSMinVersion != "1.3" {
		return nil, fmt.Errorf("management tls_min_version must be 1.2 or 1.3")
	}
	p.certManager = cert.New(filepath.Dir(configPath))
	p.tlsConfig, err = p.certManager.TLSConfigWithVersion(settings.TLSMinVersion)
	if err != nil {
		return nil, fmt.Errorf("load management TLS certificate: %w", err)
	}
	httpAddr := settings.ControlListen
	if listenOverride != "" {
		httpAddr = listenOverride
	}
	httpsAddr := settings.ControlListenHTTPS
	if httpsOverride != "" {
		httpsAddr = httpsOverride
	}
	if p.tlsConfig == nil && httpsOverride == "" && !settings.RedirectHTTPS && httpsAddr == modelDefaultHTTPSAddress {
		httpsAddr = ""
	}
	enrolled, err := p.auth.EnrollmentState()
	if err != nil {
		return nil, fmt.Errorf("verify administrator enrollment: %w", err)
	}
	if settings.RedirectHTTPS && !enrolled {
		return nil, fmt.Errorf("HTTPS redirect requires administrator enrollment")
	}
	admission, err := adminauth.AdmitManagement(httpAddr, httpsAddr, enrolled, p.tlsConfig, listenOverride != "")
	if err != nil {
		return nil, err
	}
	if settings.RedirectHTTPS && !admission.StartHTTPS {
		return nil, fmt.Errorf("HTTPS redirect requires an admitted HTTPS listener and certificate")
	}
	p.httpAddr, p.httpsAddr = admission.HTTPAddr, admission.HTTPSAddr
	p.redirectAddr = admission.RedirectHTTPSAddr
	p.admission = admission
	p.redirectHTTPS = settings.RedirectHTTPS
	p.httpListener, err = deps.listen("tcp", p.httpAddr)
	if err != nil {
		return nil, fmt.Errorf("reserve management HTTP %s: %w", p.httpAddr, err)
	}
	if admission.StartHTTPS {
		p.httpsListener, err = deps.listen("tcp", p.httpsAddr)
		if err != nil {
			return nil, fmt.Errorf("reserve management HTTPS %s: %w", p.httpsAddr, err)
		}
	}
	if err = p.store.MarkAdminAuthInitialized(); err != nil {
		return nil, fmt.Errorf("mark administrator initialized: %w", err)
	}
	return p, nil
}

const modelDefaultHTTPSAddress = "0.0.0.0:8443"

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
