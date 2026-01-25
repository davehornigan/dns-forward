package outputs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
	"log/slog"
)

const (
	defaultRouterOSRestCacheRefresh = 5 * time.Minute
)

type RosRestApiAddressListConfig struct {
	Access               RosApiAccessConfig `yaml:"-"`
	ID                   string             `yaml:"id"`
	ListName             string             `yaml:"listName"`
	TTL                  *string            `yaml:"ttl"`
	UpdateTTL            *bool              `yaml:"updateTTL"`
	RecordType           string             `yaml:"recordType"`
	ConnectionAttempts   int                `yaml:"connectionAttempts"`
	ReconnectionAttempts *int               `yaml:"reconnectionAttempts"`
}

func (c *RosRestApiAddressListConfig) UnmarshalYAML(node *yaml.Node) error {
	type raw RosRestApiAddressListConfig
	var cfg raw
	if err := node.Decode(&cfg); err != nil {
		return err
	}
	c.ListName = cfg.ListName
	c.TTL = cfg.TTL
	c.UpdateTTL = cfg.UpdateTTL
	c.RecordType = cfg.RecordType
	c.ID = cfg.ID
	c.ConnectionAttempts = cfg.ConnectionAttempts
	c.ReconnectionAttempts = cfg.ReconnectionAttempts

	var access RosApiAccessConfig
	if err := node.Decode(&access); err != nil {
		return err
	}
	c.Access = access
	return nil
}

type RouterOSRestClient struct {
	cfg                  RosRestApiAddressListConfig
	client               *http.Client
	baseURL              string
	cache                map[string]string
	subnetCache          map[string][]*net.IPNet
	pending              map[string]bool
	subnetPending        map[string]bool
	listNames            map[string]bool
	mu                   sync.Mutex
	timeout              time.Duration
	reconnectionAttempts int
}

func NewRouterOSRestClient(cfg RosRestApiAddressListConfig, timeout time.Duration) (*RouterOSRestClient, error) {
	if cfg.Access.Host == "" {
		return nil, errors.New("routeros rest host is required")
	}
	if err := ApplyHostOverrides(&cfg.Access); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.RecordType) == "" {
		return nil, errors.New("routeros rest recordType is required")
	}
	cfg.RecordType = strings.ToLower(strings.TrimSpace(cfg.RecordType))
	if cfg.RecordType != "ip" && cfg.RecordType != "host" {
		return nil, fmt.Errorf("routeros rest recordType must be ip or host, got %q", cfg.RecordType)
	}
	if cfg.ListName == "" {
		return nil, errors.New("routeros rest listName is required")
	}
	if cfg.Access.Username == "" {
		cfg.Access.Username = os.Getenv("ROUTEROS_USER")
	}
	if cfg.Access.Password == "" {
		cfg.Access.Password = os.Getenv("ROUTEROS_PASS")
	}
	if cfg.Access.Username == "" || cfg.Access.Password == "" {
		return nil, errors.New("routeros rest credentials are required (username/password or env ROUTEROS_USER/ROUTEROS_PASS)")
	}

	baseURL := FormatRouterOSRestBaseURL(cfg.Access)
	connectionAttempts := cfg.ConnectionAttempts
	if connectionAttempts <= 0 {
		connectionAttempts = defaultRouterOSConnectionTrials
	}
	reconnectionAttempts := connectionAttempts
	if cfg.ReconnectionAttempts != nil {
		reconnectionAttempts = *cfg.ReconnectionAttempts
		if reconnectionAttempts < 0 {
			reconnectionAttempts = 0
		}
	}

	client := &http.Client{
		Timeout: timeout,
	}
	rest := &RouterOSRestClient{
		cfg:                  cfg,
		client:               client,
		baseURL:              baseURL + "/rest/ip/firewall/address-list",
		cache:                make(map[string]string),
		subnetCache:          make(map[string][]*net.IPNet),
		pending:              make(map[string]bool),
		subnetPending:        make(map[string]bool),
		listNames:            make(map[string]bool),
		timeout:              timeout,
		reconnectionAttempts: reconnectionAttempts,
	}

	if err := rest.ping(connectionAttempts); err != nil {
		return nil, err
	}
	rest.startCacheRefresher(defaultRouterOSRestCacheRefresh)
	return rest, nil
}

func (c *RouterOSRestClient) DefaultListName() string {
	return c.cfg.ListName
}

func (c *RouterOSRestClient) DefaultRecordType() string {
	return c.cfg.RecordType
}

func (c *RouterOSRestClient) OutputType() string {
	return OutputRouterOS
}

func (c *RouterOSRestClient) EnsureAddress(listName, domain, address string, ttl *string, updateTTL *bool) error {
	key := fmt.Sprintf("%s|%s", listName, address)
	effectiveTTL := ""
	if ttl != nil && strings.TrimSpace(*ttl) != "" {
		effectiveTTL = strings.TrimSpace(*ttl)
	} else if c.cfg.TTL != nil && strings.TrimSpace(*c.cfg.TTL) != "" {
		effectiveTTL = strings.TrimSpace(*c.cfg.TTL)
	}

	var refreshSubnets bool
	c.mu.Lock()
	if listName != "" {
		c.listNames[listName] = true
		if _, ok := c.subnetCache[listName]; !ok && !c.subnetPending[listName] {
			c.subnetPending[listName] = true
			refreshSubnets = true
		}
	}
	if id, ok := c.cache[key]; ok && id != "" {
		c.mu.Unlock()
		if effectiveTTL == "" || !shouldUpdateTTL(c.cfg.UpdateTTL, updateTTL) {
			return nil
		}
		return c.updateAddressTTL(id, effectiveTTL)
	}
	if c.pending[key] {
		c.mu.Unlock()
		return nil
	}
	c.pending[key] = true
	c.mu.Unlock()
	if refreshSubnets {
		_ = c.refreshSubnetCache(listName)
		c.mu.Lock()
		delete(c.subnetPending, listName)
		c.mu.Unlock()
	}
	defer func() {
		c.mu.Lock()
		delete(c.pending, key)
		c.mu.Unlock()
	}()

	if ip := parseAddressIP(address); ip != nil {
		c.mu.Lock()
		subnets := c.subnetCache[listName]
		c.mu.Unlock()
		for _, subnet := range subnets {
			if subnet != nil && subnet.Contains(ip) {
				return nil
			}
		}
	}

	id, err := c.findAddressID(listName, address)
	if err != nil {
		return err
	}
	if id != "" {
		c.mu.Lock()
		c.cache[key] = id
		c.mu.Unlock()
		if effectiveTTL == "" || !shouldUpdateTTL(c.cfg.UpdateTTL, updateTTL) {
			return nil
		}
		return c.updateAddressTTL(id, effectiveTTL)
	}
	payload := map[string]string{
		"list":    listName,
		"address": address,
		"comment": domain,
	}
	if effectiveTTL != "" {
		payload["timeout"] = effectiveTTL
	}
	if err := c.createAddress(payload); err != nil {
		id, findErr := c.findAddressID(listName, address)
		if findErr == nil && id != "" {
			c.mu.Lock()
			c.cache[key] = id
			c.mu.Unlock()
			return nil
		}
		return err
	}
	id, err = c.findAddressID(listName, address)
	if err != nil {
		return err
	}
	if id != "" {
		c.mu.Lock()
		c.cache[key] = id
		c.mu.Unlock()
	}
	return nil
}

func (c *RouterOSRestClient) updateAddressTTL(id, ttl string) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("routeros rest address id is required")
	}
	endpoint := c.baseURL + "/" + id
	if _, err := c.request(http.MethodPatch, endpoint, map[string]string{
		"timeout": ttl,
	}); err == nil {
		return nil
	} else if !isNoSuchCommand(err) {
		return err
	}

	entry, err := c.getAddressEntry(id)
	if err != nil {
		return err
	}
	payload := map[string]string{
		"timeout": ttl,
	}
	if value, ok := entry["list"]; ok && fmt.Sprint(value) != "" {
		payload["list"] = fmt.Sprint(value)
	}
	if value, ok := entry["address"]; ok && fmt.Sprint(value) != "" {
		payload["address"] = fmt.Sprint(value)
	}
	if value, ok := entry["comment"]; ok && fmt.Sprint(value) != "" {
		payload["comment"] = fmt.Sprint(value)
	}
	_, err = c.request(http.MethodPut, endpoint, payload)
	return err
}

func (c *RouterOSRestClient) refreshAllLists() {
	c.mu.Lock()
	keys := make([]string, 0, len(c.cache))
	for key := range c.cache {
		if c.pending[key] {
			continue
		}
		keys = append(keys, key)
	}
	listNames := make([]string, 0, len(c.listNames))
	for listName := range c.listNames {
		listNames = append(listNames, listName)
	}
	c.mu.Unlock()

	for _, key := range keys {
		listName, address, ok := splitCacheKey(key)
		if !ok {
			continue
		}
		id, err := c.findAddressID(listName, address)
		if err != nil {
			slog.Warn("routeros rest refresh cache failed", "list", listName, "address", address, "error", err)
			continue
		}
		c.mu.Lock()
		if id == "" {
			delete(c.cache, key)
		} else {
			c.cache[key] = id
		}
		c.mu.Unlock()
	}

	for _, listName := range listNames {
		_ = c.refreshSubnetCache(listName)
	}
}

func (c *RouterOSRestClient) startCacheRefresher(interval time.Duration) {
	if interval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			c.refreshAllLists()
		}
	}()
}

func (c *RouterOSRestClient) findAddressID(listName, address string) (string, error) {
	query := url.Values{}
	query.Set("list", listName)
	query.Set("address", address)
	endpoint, err := c.withQuery(c.baseURL, query)
	if err != nil {
		return "", err
	}
	body, err := c.request(http.MethodGet, endpoint, nil)
	if err != nil {
		if !isNoSuchCommand(err) {
			return "", err
		}
		body, err = c.request(http.MethodGet, c.baseURL, nil)
		if err != nil {
			return "", err
		}
	}
	entries, err := decodeRestEntries(body)
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if entry["list"] != listName || entry["address"] != address {
			continue
		}
		if id := readRestID(entry); id != "" {
			return id, nil
		}
	}
	return "", nil
}

func (c *RouterOSRestClient) refreshSubnetCache(listName string) error {
	if strings.TrimSpace(listName) == "" {
		return nil
	}
	query := url.Values{}
	query.Set("list", listName)
	endpoint, err := c.withQuery(c.baseURL, query)
	if err != nil {
		return err
	}
	body, err := c.request(http.MethodGet, endpoint, nil)
	if err != nil {
		if !isNoSuchCommand(err) {
			return err
		}
		body, err = c.request(http.MethodGet, c.baseURL, nil)
		if err != nil {
			return err
		}
	}
	entries, err := decodeRestEntries(body)
	if err != nil {
		return err
	}
	subnets := make([]*net.IPNet, 0, len(entries))
	for _, entry := range entries {
		if entry["list"] != listName {
			continue
		}
		entryAddress := fmt.Sprint(entry["address"])
		if ipNet := parseAddressCIDR(entryAddress); ipNet != nil {
			subnets = append(subnets, ipNet)
		}
	}
	c.mu.Lock()
	c.subnetCache[listName] = subnets
	c.mu.Unlock()
	return nil
}

func (c *RouterOSRestClient) ping(attempts int) error {
	if attempts <= 0 {
		attempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if _, err := c.requestOnce(http.MethodGet, c.baseURL, nil); err == nil {
			return nil
		} else {
			lastErr = err
			slog.Warn("routeros rest connect failed", "attempt", attempt, "max_attempts", attempts, "error", err)
		}
	}
	return lastErr
}

func (c *RouterOSRestClient) withQuery(endpoint string, query url.Values) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func (c *RouterOSRestClient) request(method, endpoint string, payload any) ([]byte, error) {
	maxAttempts := c.reconnectionAttempts
	if maxAttempts < 0 {
		maxAttempts = 0
	}
	var lastErr error
	for attempt := 0; attempt <= maxAttempts; attempt++ {
		body, err := c.requestOnce(method, endpoint, payload)
		if err == nil {
			return body, nil
		}
		if isNoSuchCommand(err) {
			return nil, err
		}
		lastErr = err
		if attempt < maxAttempts {
			slog.Warn("routeros rest request failed", "attempt", attempt+1, "max_attempts", maxAttempts+1, "error", err)
		}
	}
	return nil, lastErr
}

func (c *RouterOSRestClient) requestOnce(method, endpoint string, payload any) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.cfg.Access.Username, c.cfg.Access.Password)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("routeros rest status %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}
	return respBody, nil
}

func (c *RouterOSRestClient) createAddress(payload map[string]string) error {
	_, err := c.request(http.MethodPut, c.baseURL, payload)
	return err
}

func decodeRestEntries(body []byte) ([]map[string]any, error) {
	if len(body) == 0 {
		return nil, nil
	}
	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	switch value := payload.(type) {
	case []any:
		entries := make([]map[string]any, 0, len(value))
		for _, item := range value {
			if entry, ok := item.(map[string]any); ok {
				entries = append(entries, entry)
			}
		}
		return entries, nil
	case map[string]any:
		return []map[string]any{value}, nil
	default:
		return nil, fmt.Errorf("unexpected routeros rest response %T", payload)
	}
}

func readRestID(entry map[string]any) string {
	if entry == nil {
		return ""
	}
	if value, ok := entry[".id"]; ok {
		return fmt.Sprint(value)
	}
	if value, ok := entry["id"]; ok {
		return fmt.Sprint(value)
	}
	return ""
}

func (c *RouterOSRestClient) getAddressEntry(id string) (map[string]any, error) {
	body, err := c.request(http.MethodGet, c.baseURL+"/"+id, nil)
	if err != nil {
		return nil, err
	}
	entries, err := decodeRestEntries(body)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errors.New("routeros rest entry not found")
	}
	return entries[0], nil
}

func isNoSuchCommand(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "no such command")
}

func FormatRouterOSRestBaseURL(cfg RosApiAccessConfig) string {
	port := cfg.Port
	useTLS := effectiveUseTLS(cfg)
	if port == 0 {
		if useTLS {
			port = 443
		} else {
			port = 80
		}
	}
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", port)))
}
