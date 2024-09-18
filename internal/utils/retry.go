package utils

import (
	"fmt"
	"time"

	"github.com/alexkhomych/zerossl-ip-cert/internal/config"
	"github.com/alexkhomych/zerossl-ip-cert/pkg/log"
)

func RetryOperationWithConfig(operation func() error) error {
	cfg := config.GetConfig()
	maxAttempts := cfg.RetryMaxAttempts
	waitTime := time.Duration(cfg.RetryWaitTime) * time.Second
	return RetryOperation(operation, maxAttempts, waitTime)
}

func RetryOperation(operation func() error, maxAttempts int, waitTime time.Duration) error {
	var err error
	for i := 0; i < maxAttempts; i++ {
		err = operation()
		if err == nil {
			return nil
		}
		log.Error("operation failed. Retrying...", "error", err.Error(), "wait_time", waitTime)
		time.Sleep(waitTime)
		waitTime = waitTime * 2
	}
	return fmt.Errorf("operation failed after %d atempts: %v", maxAttempts, err)
}
