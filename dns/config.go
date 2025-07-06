package dns

import (
	"bufio"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	configFilenameAllowExact    = "allow.exact"
	configFilenameDenyExact     = "deny.exact"
	configFilenameAllowTLDs     = "allow.tld"
	configFilenameDenyTLDs      = "deny.tld"
	configFilenameAllowSuffixes = "allow.suffix"
	configFilenameDenySuffixes  = "deny.suffix"
	configFilenameIPv4Allow     = "allow.ipv4"
	configFilenameIPv4Deny      = "deny.ipv4"
	configFilenameIPv6Allow     = "allow.ipv6"
	configFilenameIPv6Deny      = "deny.ipv6"
	configFilenameKnownTLDs     = "known.tld"

	defaultMinTTL uint32 = 0
	defaultMaxTTL uint32 = math.MaxUint32
)

type Config struct {
	DoHURL       string
	DoHIPs       []string
	MinTTL       uint32
	MaxTTL       uint32
	DenyPunycode bool
	RemoveECH    bool
	LogAllowed   bool
	LogDenied    bool
	LogLevel     slog.Level
}

func ReadConfigFile(configDirectory string) (*Config, error) {
	path := filepath.Join(configDirectory, "config")
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	return parseConfig(scanner)
}

type ConfigKey string

const (
	keyDohURL       ConfigKey = "DoHURL"
	keyDohIPs       ConfigKey = "DoHIPs"
	keyMinTTL       ConfigKey = "MinTTL"
	keyMaxTTL       ConfigKey = "MaxTTL"
	keyDenyPunycode ConfigKey = "DenyPunycode"
	keyRemoveECH    ConfigKey = "RemoveECH"
	keyLogAllowed   ConfigKey = "LogAllowed"
	keyLogDenied    ConfigKey = "LogDenied"
	keyLogLevel     ConfigKey = "LogLevel"
)

type ConfigMap struct {
	m map[ConfigKey]string
}

func NewConfigMap(keys ...ConfigKey) *ConfigMap {
	m := make(map[ConfigKey]string)

	for _, key := range keys {
		m[key] = ""
	}

	return &ConfigMap{m: m}
}

func (c *ConfigMap) Set(key ConfigKey, value string) {
	c.m[key] = value
}

func (c *ConfigMap) Get(key ConfigKey) (string, bool) {
	a, b := c.m[key]
	return a, b
}

func (c *ConfigMap) GetBool(key ConfigKey, defaultValue bool) (bool, error) {
	result := defaultValue

	stringValue := c.m[key]
	if stringValue != "" {
		v, err := strconv.ParseBool(stringValue)
		if err != nil {
			return false, fmt.Errorf("invalid bool config value '%s': %s", key, stringValue)
		}
		result = v
	}

	return result, nil
}

func (c *ConfigMap) GetLogLevel(key ConfigKey, defaultValue slog.Level) (slog.Level, error) {
	result := defaultValue

	stringValue := c.m[key]
	if stringValue != "" {
		switch stringValue {
		case "info":
			result = slog.LevelInfo
		case "debug":
			result = slog.LevelDebug
		default:
			return 0, fmt.Errorf("unsupported log level '%s'", stringValue)
		}
	}

	return result, nil
}

func (c *ConfigMap) GetUint32(key ConfigKey, defaultValue uint32) (uint32, error) {
	result := defaultValue

	stringValue := c.m[key]
	if stringValue != "" {
		v, err := strconv.ParseUint(stringValue, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid uint32 config value '%s': %s", key, stringValue)
		}
		result = uint32(v)
	}

	return result, nil
}

func (c *ConfigMap) GetRequiredString(key ConfigKey) (string, error) {
	stringValue := c.m[key]
	if stringValue == "" {
		return "", fmt.Errorf("required config '%s' missing", key)
	}

	return stringValue, nil
}

func (c *ConfigMap) GetRequiredListOfStrings(key ConfigKey) ([]string, error) {
	stringValue := c.m[key]
	if stringValue == "" {
		return nil, fmt.Errorf("required config '%s' missing", key)
	}

	result := strings.Split(stringValue, ",")
	if len(result) == 0 {
		return nil, fmt.Errorf("invalid required config '%s' missing", key)
	}

	return result, nil
}

func parseConfig(scanner *bufio.Scanner) (*Config, error) {
	configMap := NewConfigMap(keyDohURL,
		keyDohIPs,
		keyMinTTL,
		keyMaxTTL,
		keyDenyPunycode,
		keyRemoveECH,
		keyLogAllowed,
		keyLogDenied,
		keyLogLevel,
	)

	for scanner.Scan() {
		line := scanner.Text()

		if len(line) > 0 && !strings.HasPrefix(line, "#") {
			parts := strings.Split(line, "=")
			if len(parts) != 2 {
				return nil, fmt.Errorf("more than one = in config line: %s", line)
			}

			key := ConfigKey(parts[0])
			value := parts[1]

			s, found := configMap.Get(key)
			if !found {
				return nil, fmt.Errorf("unknown key '%s': %s", key, line)
			}

			if s != "" {
				return nil, fmt.Errorf("duplicate key '%s'", line)
			}

			configMap.Set(key, value)
		}
	}

	dohURL, err := configMap.GetRequiredString(keyDohURL)
	if err != nil {
		return nil, err
	}

	// TODO return []net.IP instead
	dohIPs, err := configMap.GetRequiredListOfStrings(keyDohIPs)
	if err != nil {
		return nil, err
	}

	minTTL, err := configMap.GetUint32(keyMinTTL, defaultMinTTL)
	if err != nil {
		return nil, err
	}

	maxTTL, err := configMap.GetUint32(keyMaxTTL, defaultMaxTTL)
	if err != nil {
		return nil, err
	}

	denyPunycode, err := configMap.GetBool(keyDenyPunycode, false)
	if err != nil {
		return nil, err
	}

	removeECH, err := configMap.GetBool(keyRemoveECH, false)
	if err != nil {
		return nil, err
	}

	logAllowed, err := configMap.GetBool(keyLogAllowed, true)
	if err != nil {
		return nil, err
	}

	logDenied, err := configMap.GetBool(keyLogDenied, true)
	if err != nil {
		return nil, err
	}

	logLevel, err := configMap.GetLogLevel(keyLogLevel, slog.LevelInfo)
	if err != nil {
		return nil, err
	}

	return &Config{
		DoHURL:       dohURL,
		DoHIPs:       dohIPs,
		MinTTL:       minTTL,
		MaxTTL:       maxTTL,
		DenyPunycode: denyPunycode,
		RemoveECH:    removeECH,
		LogAllowed:   logAllowed,
		LogDenied:    logDenied,
		LogLevel:     logLevel,
	}, nil
}

func readConfig(configDirectory string, filename string) (res []string, err error) {
	path := filepath.Join(configDirectory, filename)

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var result []string
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		line := sc.Text()

		if len(line) > 0 && !strings.HasPrefix(line, "#") {
			result = append(result, line)
		}
	}

	return result, err
}
