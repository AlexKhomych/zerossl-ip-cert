package hooks

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/alexkhomych/zerossl-ip-cert/pkg/file"
	"github.com/alexkhomych/zerossl-ip-cert/pkg/log"
	zerosslIPCert "github.com/tinkernels/zerossl-ip-cert"
)

func RunVerifyHook(executable string, cerInfo *zerosslIPCert.CertificateInfoModel) error {
	if !file.PathExists(executable) {
		return fmt.Errorf("verify hook executable %v not exists", executable)
	}
	for k, v := range cerInfo.Validation.OtherMethods {
		if k == cerInfo.CommonName {
			validateHttpUrl, err := url.Parse(v.FileValidationUrlHttp)
			if err != nil {
				log.Error("url parse error", "error", err.Error())
				return err
			}
			host := validateHttpUrl.Host
			path := validateHttpUrl.Path
			port := validateHttpUrl.Port()
			if port == "" {
				port = "80"
			}
			content := strings.Join(v.FileValidationContent, "\n")
			cmd := exec.Command(executable)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stdout
			cmd.Env = append(cmd.Env, fmt.Sprintf("%v=%v", "ZEROSSL_HTTP_FV_HOST", host))
			cmd.Env = append(cmd.Env, fmt.Sprintf("%v=%v", "ZEROSSL_HTTP_FV_PATH", path))
			cmd.Env = append(cmd.Env, fmt.Sprintf("%v=%v", "ZEROSSL_HTTP_FV_PORT", port))
			cmd.Env = append(cmd.Env, fmt.Sprintf("%v=%v", "ZEROSSL_HTTP_FV_CONTENT", content))
			if err = cmd.Run(); err != nil {
				return err
			}
			return err
		}
	}
	return nil
}
