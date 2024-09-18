package certs

import (
	"fmt"
	"time"

	"github.com/alexkhomych/zerossl-ip-cert/internal/config"
	"github.com/alexkhomych/zerossl-ip-cert/internal/metrics"
	"github.com/alexkhomych/zerossl-ip-cert/internal/utils"
	"github.com/alexkhomych/zerossl-ip-cert/pkg/log"
	zerosslIPCert "github.com/tinkernels/zerossl-ip-cert"
)

func WaitCertToBeReady(client *zerosslIPCert.Client, certID string) error {
	cfg := config.GetConfig()
	maxWaitTime := time.Duration(cfg.MaxWaitTime) * time.Minute
	checkInterval := time.Duration(cfg.CheckInterval) * time.Second
	startTime := time.Now()

	for {
		var certInfo zerosslIPCert.CertificateInfoModel
		err := utils.RetryOperationWithConfig(func() error {
			var err error
			certInfo, err = client.GetCert(certID)
			return err
		})
		if err != nil {
			log.Info(fmt.Sprintf("get cert error after retries: %v", err))
			metrics.ApiErrors.Inc()
			return err
		}
		if certInfo.Status == zerosslIPCert.CertStatus.Issued {
			log.Info(fmt.Sprintf("cert is ready: %+v", certInfo))
			return nil
		} else {
			log.Info("awaiting cert to be ready", "status", certInfo.Status)
		}
		if time.Since(startTime) > maxWaitTime {
			return fmt.Errorf("timeout of waiting cert to be ready")
		}
		time.Sleep(checkInterval)
	}
}
