package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/alexkhomych/zerossl-ip-cert/internal/certs"
	"github.com/alexkhomych/zerossl-ip-cert/internal/config"
	"github.com/alexkhomych/zerossl-ip-cert/internal/metrics"
	"github.com/alexkhomych/zerossl-ip-cert/pkg/file"
	"github.com/alexkhomych/zerossl-ip-cert/pkg/log"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const Version = "v1.1.0"

var (
	renewFlag bool
)

func init() {
	flag.Usage = func() {
		w := flag.CommandLine.Output()
		_, _ = fmt.Fprintf(w, "\nVersion: %v\n\nUsage: %v [ -renew ] -config CONFIG_FILE\n\n",
			Version, filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}

	flag.StringVar(&config.ConfigFilePath, "config", "", "Config file")
	flag.BoolVar(&renewFlag, "renew", false, "Renew existing certs only")

	flag.Parse()

	// TODO:
	// Log line numbers?
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
}

func main() {
	if config.ConfigFilePath == "" {
		flag.Usage()
		os.Exit(1)
	}

	cfg := config.GetConfig()

	err := file.CreateDirIfNotExists(cfg.DataDir, os.ModePerm)
	if err != nil {
		log.Fatal("couldn't create directory", "dir", cfg.DataDir, "error", err.Error())
	}

	metrics.Init()

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		addr := fmt.Sprintf(":%d", cfg.MetricsPort)
		log.Info(fmt.Sprintf("Starting metrics server at %s", addr))
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Info(fmt.Sprintf("Error starting metrics server: %v", err))
		}
	}()

	if renewFlag {
		certs.Renew()
	} else {
		certs.IssueCerts()
	}
}
