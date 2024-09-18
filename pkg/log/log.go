package log

import (
	"log/slog"
	"os"
)

// Debug calls [slog.Debug].
func Debug(msg string, args ...any) {
	slog.Debug(msg, args...)
}

// Info calls [slog.Info].
func Info(msg string, args ...any) {
	slog.Info(msg, args...)
}

// Warn calls [slog.Warn].
func Warn(msg string, args ...any) {
	slog.Warn(msg, args...)
}

// Error calls [slog.Error].
func Error(msg string, args ...any) {
	slog.Error(msg, args...)
}

// Fatal calls [slog.Error] and [os.Exit(1)].
func Fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}
