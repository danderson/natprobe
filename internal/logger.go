package internal

import (
	"fmt"
	"os"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

func NewLogger() logr.Logger {
	var (
		logger *zap.Logger
		err    error
	)
	if isTerminal() {
		logger, err = zap.NewDevelopment()
	} else {
		logger, err = zap.NewProduction()
	}
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize logger: %s", err))
	}

	return zapr.NewLogger(logger)
}

func isTerminal() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdout.Fd()), unix.TCGETS)
	return err == nil
}
