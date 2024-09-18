package hooks

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/alexkhomych/zerossl-ip-cert/internal/config"
	"github.com/alexkhomych/zerossl-ip-cert/pkg/file"
)

func RunPostHook(certConf *config.CertConf) error {
	if !file.PathExists(certConf.PostHook) {
		return fmt.Errorf("post hook executable %v doesn't exist", certConf.PostHook)
	}
	cmd := exec.Command(certConf.PostHook)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stdout
	cmd.Env = append(cmd.Env, fmt.Sprintf("%v=%v", "ZEROSSL_CERT_FPATH", certConf.CertFile))
	cmd.Env = append(cmd.Env, fmt.Sprintf("%v=%v", "ZEROSSL_KEY_FPATH", certConf.KeyFile))
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}
