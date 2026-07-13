package health

import (
	"encoding/json"
	"errors"
	"os"
	"regexp"
)

var gatusKeyPattern = regexp.MustCompile(`^[a-z0-9-]+_[a-z0-9-]+$`)

type CanaryConfig struct {
	Canaries []Canary `json:"canaries"`
}
type Canary struct {
	OperationKey     string `json:"operation_key"`
	GatusEndpointKey string `json:"gatus_endpoint_key"`
}

func LoadCanaryConfig(path string) (CanaryConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return CanaryConfig{}, err
	}
	var config CanaryConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return CanaryConfig{}, errors.New("invalid canary configuration")
	}
	seen := map[string]bool{}
	for _, canary := range config.Canaries {
		if !sha256Pattern.MatchString(canary.OperationKey) || !gatusKeyPattern.MatchString(canary.GatusEndpointKey) || seen[canary.OperationKey] {
			return CanaryConfig{}, errors.New("invalid canary configuration")
		}
		seen[canary.OperationKey] = true
	}
	return config, nil
}

func (c CanaryConfig) Resolve(receipt Receipt) (string, error) {
	for _, canary := range c.Canaries {
		if canary.OperationKey == receipt.Operation.OperationKey {
			return canary.GatusEndpointKey, nil
		}
	}
	return "", errors.New("receipt operation is not a configured public canary")
}
