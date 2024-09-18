package config

import (
	"os"
	"path/filepath"

	"github.com/alexkhomych/zerossl-ip-cert/pkg/file"
	"gopkg.in/yaml.v3"
)

var (
	isGlobalConfigSet bool
	globalConfig      *Config
	ConfigFilePath    string

	isGlobalDataSet    bool
	globalData         *Data
	globalDataFilePath string
)

type Config struct {
	DataDir          string     `yaml:"dataDir"`
	LogFile          string     `yaml:"logFile"`
	CleanUnfinished  bool       `yaml:"cleanUnfinished"`
	MetricsPort      int        `yaml:"metricsPort"`
	MaxWaitTime      int        `yaml:"maxWaitTime"`
	CheckInterval    int        `yaml:"checkInterval"`
	RetryMaxAttempts int        `yaml:"retryMaxAttempts"`
	RetryWaitTime    int        `yaml:"retryWaitTime"`
	CertConfigs      []CertConf `yaml:"certConfigs"`
}

type CertConf struct {
	ConfID           string `yaml:"confId"`
	ApiKey           string `yaml:"apiKey"`
	Country          string `yaml:"country"`
	Province         string `yaml:"province"`
	City             string `yaml:"city"`
	Locality         string `yaml:"locality"`
	Organization     string `yaml:"organization"`
	OrganizationUnit string `yaml:"organizationUnit"`
	CommonName       string `yaml:"commonName"`
	Days             int    `yaml:"days"`
	KeyType          string `yaml:"keyType"`
	KeyBits          int    `yaml:"keyBits"`
	KeyCurve         string `yaml:"keyCurve"`
	SigAlg           string `yaml:"sigAlg"`
	StrictDomains    int    `yaml:"strictDomains"`
	VerifyMethod     string `yaml:"verifyMethod"`
	VerifyHook       string `yaml:"verifyHook"`
	PostHook         string `yaml:"postHook"`
	CertFile         string `yaml:"certFile"`
	KeyFile          string `yaml:"keyFile"`
}

type Data struct {
	Certs []CertData `yaml:"certs"`
}

type CertData struct {
	CommonName string `yaml:"commonName"`
	ConfID     string `yaml:"confId"`
	CertID     string `yaml:"certId"`
	CertFile   string `yaml:"certFile"`
	KeyFile    string `yaml:"keyFile"`
}

func GetConfig() *Config {
	if !isGlobalConfigSet {
		globalConfig = &Config{}
		if err := ReadConfig(ConfigFilePath, globalConfig); err != nil {
			panic(err)
		}

		if globalConfig.MetricsPort == 0 {
			globalConfig.MetricsPort = 2112
		}
		if globalConfig.MaxWaitTime == 0 {
			globalConfig.MaxWaitTime = 180
		}
		if globalConfig.CheckInterval == 0 {
			globalConfig.CheckInterval = 30
		}
		if globalConfig.RetryMaxAttempts == 0 {
			globalConfig.RetryMaxAttempts = 5
		}
		if globalConfig.RetryWaitTime == 0 {
			globalConfig.RetryWaitTime = 15
		}
	}
	isGlobalConfigSet = true
	return globalConfig
}

func ReadConfig(path string, config *Config) error {
	if !file.PathExists(path) {
		panic("Config file not found")
	}

	input_, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(input_, &config)
	if err != nil {
		return err
	}
	return nil
}

func GetData() *Data {
	if !isGlobalDataSet {
		globalDataFilePath = filepath.Join(globalConfig.DataDir, "/current.yaml")
		ReadData(globalDataFilePath)
	}
	isGlobalDataSet = true
	return globalData
}

func ReadData(path string) error {
	if !file.PathExists(path) {
		globalData = &Data{}
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(content, &globalData)
	if err != nil {
		return err
	}
	return nil
}

func WriteData(data *Data) error {
	output, err := yaml.Marshal(data)
	if err != nil {
		return err
	}
	err = os.WriteFile(globalDataFilePath, output, os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}
