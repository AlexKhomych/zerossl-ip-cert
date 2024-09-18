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

func Renew() {
	cfg := config.GetConfig()
	data := config.GetData()
	log.Info("will renew current certs")
loopRenew:
	for _, cert := range data.Certs {
		log.Info(fmt.Sprintf("try renewing cert: %v", cert.CommonName))
		for _, c := range cfg.CertConfigs {
			if c.ConfID == cert.ConfID {
				err := renewCert(cert.CertID, &c)
				if err != nil {
					log.Info(fmt.Sprintf("Failed to renew cert for domain %v: %v", c.CommonName, err))
				}
				continue loopRenew
			}
		}
		log.Error("no config for renewing cert", "domain", cert.CommonName)
	}
}

func renewCert(id string, conf *config.CertConf) error {
	usingConfig := config.GetConfig()
	data := config.GetData()
	log.Info("renewing cert", "domain", conf.CommonName)
	client := &zerosslIPCert.Client{ApiKey: conf.ApiKey}

	var certInfo zerosslIPCert.CertificateInfoModel
	err := utils.RetryOperationWithConfig(func() error {
		var err error
		certInfo, err = client.GetCert(id)
		return err
	})
	if err != nil {
		log.Error("failed to get cert info", "error", err.Error())
		metrics.ApiErrors.Inc()
		return err
	}
	expireTime_, err := time.Parse("2006-01-02 15:04:05", certInfo.Expires)
	if err != nil {
		log.Info(fmt.Sprintf("Failed to convert expiring time: %v", err))
	} else {
		if certInfo.Status != zerosslIPCert.CertStatus.ExpiringSoon &&
			time.Now().Add(time.Hour*24*29).Before(expireTime_) {
			log.Info(fmt.Sprintf("Cert %v is not due for renewal, skip renewing.", conf.CommonName))
			return nil
		}
	}
	if usingConfig.CleanUnfinished {
		if err := client.CleanUnfinished(); err != nil {
			log.Error("failed to clean unfinished issuing certificate", "error", err.Error())
		}
	}
	certId, err := issueCertImpl(conf)
	if err == nil {
		log.Info("cert issued successfully", "domain", conf.CommonName)
		metrics.CertsRenewed.Inc()
		for i, c := range data.Certs {
			if c.CertID == id {
				data.Certs[i].ConfID = conf.ConfID
				data.Certs[i].CommonName = conf.CommonName
				data.Certs[i].CertID = certId
				data.Certs[i].CertFile = conf.CertFile
				data.Certs[i].KeyFile = conf.KeyFile
				break
			}
		}
		if err = config.WriteData(data); err != nil {
			log.Error("failed to write data", "error", err.Error())
		}
	}

	return nil
}
