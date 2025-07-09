package config

import (
	"os"
)

type Config struct {
	Environment    string
	Port           string
	MaxFileSize    int64
	AllowedOrigins []string
}

func Load() *Config {
	return &Config{
		Environment: getEnv("ENVIRONMENT", "development"),
		Port:        getEnv("PORT", "8080"),
		MaxFileSize: 10 * 1024 * 1024, // 10MB
		AllowedOrigins: []string{
			getEnv("FRONTEND_URL", "http://localhost:3000"),
		},
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
