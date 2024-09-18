package certs

import (
	"crypto/x509/pkix"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/alexkhomych/zerossl-ip-cert/internal/config"
	"github.com/alexkhomych/zerossl-ip-cert/internal/hooks"
	"github.com/alexkhomych/zerossl-ip-cert/internal/metrics"
	"github.com/alexkhomych/zerossl-ip-cert/pkg/file"
	"github.com/alexkhomych/zerossl-ip-cert/pkg/log"
	zerosslIPCert "github.com/tinkernels/zerossl-ip-cert"
)

func IssueCerts() {
	log.Info("Issuing certs")
	for _, c := range config.GetConfig().CertConfigs {
		log.Info(fmt.Sprintf("Issuing cert for domain: %v", c.CommonName))
		err := issueCert(&c)
		if err != nil {
			log.Info(fmt.Sprintf("Failed to issue cert for domain %v: %v\n", c.CommonName, err))
		}
	}
}

func issueCert(conf *config.CertConf) (err error) {
	usingConfig := config.GetConfig()
	currentData := config.GetData()
	for _, cert := range currentData.Certs {
		if cert.ConfID == conf.ConfID {
			log.Info("cert already exists, trying renew instead...", "domain", conf.CommonName)
			err = renewCert(cert.CertID, conf)
			return
		}
	}
	log.Info(fmt.Sprintf("Cert for domain %v does not exist, try issue.", conf.CommonName))
	client := &zerosslIPCert.Client{ApiKey: conf.ApiKey}
	if usingConfig.CleanUnfinished {
		if err := client.CleanUnfinished(); err != nil {
			log.Error("failed to clean unfinished issuing certificate", "error", err.Error())
		}
	}
	certId, err := issueCertImpl(conf)
	if err == nil {
		log.Info("cert issued successfully", "domain", conf.CommonName)
		metrics.CertsIssued.Inc()
		currentData.Certs = append(currentData.Certs, config.CertData{
			CommonName: conf.CommonName,
			CertID:     certId,
			CertFile:   conf.CertFile,
			KeyFile:    conf.KeyFile,
			ConfID:     conf.ConfID,
		})
		if err = config.WriteData(currentData); err != nil {
			log.Error("failed to write current data", "error", err.Error())
		}
	}
	return
}

func issueCertImpl(conf *config.CertConf) (string, error) {
	tempDir, err := os.MkdirTemp(config.GetConfig().DataDir, "temp")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tempDir)
	tempPrivKeyPath := filepath.Join(tempDir, "/privkey.pem")
	tempCertPath := filepath.Join(tempDir, "/cert-fullchain.pem")
	client := &zerosslIPCert.Client{ApiKey: conf.ApiKey}
	privKey := zerosslIPCert.KeyGeneratorWrapper(conf.KeyType, conf.KeyBits, conf.KeyCurve)
	subj := pkix.Name{
		Country:            []string{conf.Country},
		Province:           []string{conf.Province},
		Locality:           []string{conf.Locality},
		Organization:       []string{conf.Organization},
		OrganizationalUnit: []string{conf.OrganizationUnit},
		CommonName:         conf.CommonName,
	}
	csr, err := zerosslIPCert.CSRGeneratorWrapper(conf.KeyType, subj, privKey, conf.SigAlg)
	if err != nil {
		log.Error("error generating csr", "error", err.Error())
		return "", err
	}
	csrStr_ := zerosslIPCert.GetCSRString(csr)
	if csrStr_ == "" {
		log.Info("failed to get csr string")
		return "", err
	}
	if err = zerosslIPCert.WritePrivKeyWrapper(conf.KeyType, privKey, tempPrivKeyPath); err != nil {
		log.Error("error writing private key", "error", err.Error())
		return "", err
	}
	log.Info("creating cert", "common_name", conf.CommonName)
	certInfo, err := client.CreateCert(conf.CommonName, csrStr_, strconv.Itoa(conf.Days),
		strconv.Itoa(conf.StrictDomains))
	if err != nil {
		log.Error("error creating cert", "error", err.Error())
		return "", err
	}
	if err = hooks.RunVerifyHook(conf.VerifyHook, &certInfo); err != nil {
		log.Error("error running verify hook", "error", err.Error())
		return "", err
	}
	if err = verifyHttpCsrHash(client, &certInfo); err != nil {
		log.Error("verifying error", "error", err.Error())
		return "", err
	}
	cert_, err := client.DownloadCertInline(certInfo.ID, "1")
	if err != nil {
		log.Error("error downloading cert", "error", err.Error())
		return "", err
	}
	fullChainPem := fmt.Sprintf("%s\n%s\n", strings.TrimSpace(cert_.Certificate), strings.TrimSpace(cert_.CaBundle))
	tempCertFile, err := os.Create(tempCertPath)
	if err != nil {
		log.Error("error creating cert file", "error", err.Error())
		return "", err
	}
	_, err = tempCertFile.WriteString(fullChainPem)
	if err != nil {
		log.Error("error writing to cert file", "error", err.Error())
		return "", err
	}
	if err = file.CopyFile(tempCertPath, conf.CertFile, os.ModePerm); err != nil {
		log.Error("error copying cert file", "error", err.Error())
		return "", err
	}
	if err = file.CopyFile(tempPrivKeyPath, conf.KeyFile, os.ModePerm); err != nil {
		log.Error("error copying private key file", "error", err.Error())
		return "", err
	}
	if err = hooks.RunPostHook(conf); err != nil {
		log.Error("error running post hook", "error", err.Error())
		return "", err
	}
	return certInfo.ID, nil
}

func verifyHttpCsrHash(client *zerosslIPCert.Client, certInfo *zerosslIPCert.CertificateInfoModel) error {
	cfg := config.GetConfig()
	maxAttemps := cfg.RetryMaxAttempts
	waitTime := time.Duration(cfg.RetryWaitTime) * time.Second

	for retrying := 0; retrying < maxAttemps; retrying++ {
		verifyRsp, err := client.VerifyDomains(certInfo.ID, zerosslIPCert.VerifyDomainsMethod.HttpCsrHash, "")
		if err != nil {
			log.Info(fmt.Sprintf("verify error: %v", err))
			metrics.ApiErrors.Inc()
			time.Sleep(waitTime)
			waitTime = waitTime * 2
			continue
		}
		// NOTICE: ZeroSSL always return "Success:false" in HttpCsrHash verification.
		log.Info(fmt.Sprintf("domains verification result: %+v", verifyRsp))
		log.Info("retrieving certificate", "cert_id", certInfo.ID)
		certInfoTmp, err := client.GetCert(certInfo.ID)
		if err != nil {
			log.Info(fmt.Sprintf("get cert error: %v", err))
			metrics.ApiErrors.Inc()
			time.Sleep(waitTime)
			waitTime = waitTime * 2
			continue
		}
		if certInfoTmp.Status != zerosslIPCert.CertStatus.PendingValidation &&
			certInfoTmp.Status != zerosslIPCert.CertStatus.Issued {
			log.Info(fmt.Sprintf("cert in %v status", certInfoTmp.Status))
			time.Sleep(30 * time.Second)
			continue
		}
		break
	}
	if err := WaitCertToBeReady(client, certInfo.ID); err != nil {
		return err
	}
	return nil
}
