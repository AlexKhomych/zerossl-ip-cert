package file

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/alexkhomych/zerossl-ip-cert/pkg/log"
)

func PathExists(path string) bool {
	if _, err := os.Stat(path); err != nil {
		return false
	}
	return true
}

func CreateDirIfNotExists(dir string, perm os.FileMode) error {
	if PathExists(dir) {
		return nil
	}
	if err := os.MkdirAll(dir, perm); err != nil {
		return fmt.Errorf("failed to create directory: '%s', error: '%s'", dir, err.Error())
	}
	return nil
}

func CopyFile(srcFile, dstFile string, perm os.FileMode) error {
	dstDir := filepath.Dir(dstFile)
	err := CreateDirIfNotExists(dstDir, perm)
	if err != nil {
		return err
	}
	out, err := os.Create(dstFile)
	if err != nil {
		return err
	}
	defer func(out *os.File) {
		err := out.Close()
		if err != nil {
			log.Error("failed to close file", "file", dstFile, "error", err.Error())
		}
	}(out)
	in, err := os.Open(srcFile)
	defer func(in *os.File) {
		err := in.Close()
		if err != nil {
			log.Error("failed to close file", "file", srcFile, "error", err.Error())
		}
	}(in)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return nil
}
