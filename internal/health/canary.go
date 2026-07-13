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
	OperationKey                      string `json:"operation_key"`
	GatusEndpointKey                  string `json:"gatus_endpoint_key"`
	CatalogOperationID                string `json:"catalog_operation_id"`
	Tier                              string `json:"tier"`
	IntervalMinutes                   int    `json:"interval_minutes"`
	HeartbeatMinutes                  int    `json:"heartbeat_minutes"`
	ConsecutiveFailuresBeforeIncident int    `json:"consecutive_failures_before_incident"`
	MissedSchedulesBeforeHeartbeat    int    `json:"missed_schedules_before_heartbeat"`
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
		if !sha256Pattern.MatchString(canary.OperationKey) || !gatusKeyPattern.MatchString(canary.GatusEndpointKey) || !catalogOperationIDPattern.MatchString(canary.CatalogOperationID) || !validCadence(canary) || seen[canary.OperationKey] {
			return CanaryConfig{}, errors.New("invalid canary configuration")
		}
		seen[canary.OperationKey] = true
	}
	return config, nil
}

func validCadence(canary Canary) bool {
	if canary.ConsecutiveFailuresBeforeIncident != 2 || canary.MissedSchedulesBeforeHeartbeat != 2 || canary.HeartbeatMinutes != canary.IntervalMinutes*canary.MissedSchedulesBeforeHeartbeat {
		return false
	}
	switch canary.Tier {
	case "A":
		return canary.IntervalMinutes == 5
	case "B":
		return canary.IntervalMinutes == 10
	case "C":
		return canary.IntervalMinutes == 15
	default:
		return false
	}
}

func (c CanaryConfig) Resolve(receipt Receipt) (string, error) {
	canary, err := c.CanaryFor(receipt)
	if err != nil {
		return "", err
	}
	return canary.GatusEndpointKey, nil
}

func (c CanaryConfig) CanaryFor(receipt Receipt) (Canary, error) {
	for _, canary := range c.Canaries {
		if canary.OperationKey == receipt.Operation.OperationKey {
			return canary, nil
		}
	}
	return Canary{}, errors.New("receipt operation is not a configured public canary")
}
