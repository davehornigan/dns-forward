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
	"time"

	"gopkg.in/yaml.v3"
	"log/slog"
)

const (
	defaultRouterOSRestCacheRefresh = 5 * time.Minute
)

type RosRestApiAddressListConfig struct {
	Access                RosApiAccessConfig `yaml:"-"`
	ID                    string             `yaml:"id"`
	ListName              string             `yaml:"listName"`
	TTL                   *string            `yaml:"ttl"`
	UpdateTTL             *bool              `yaml:"updateTTL"`
	RecordType            string             `yaml:"recordType"`
	ConnectionAttempts    int                `yaml:"connectionAttempts"`
	ReconnectionAttempts  *int               `yaml:"reconnectionAttempts"`
	MaxConcurrentRequests int                `yaml:"maxConcurrentRequests"`
	MinRequestInterval    time.Duration      `yaml:"minRequestInterval"`
	RefreshInterval       time.Duration      `yaml:"refreshInterval"`
	RestoreClearedList    *bool              `yaml:"restoreClearedList"`
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
	c.MaxConcurrentRequests = cfg.MaxConcurrentRequests
	c.MinRequestInterval = cfg.MinRequestInterval
	c.RefreshInterval = cfg.RefreshInterval
	c.RestoreClearedList = cfg.RestoreClearedList

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
	cache                *addressCache
	limiter              *routerLimiter
	timeout              time.Duration
	reconnectionAttempts int
	restoreCleared       bool
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

	maxConcurrent := cfg.MaxConcurrentRequests
	if maxConcurrent <= 0 {
		maxConcurrent = defaultRouterOSMaxConcurrency
	}
	// Cap the connection pool at the same width as the limiter and keep those
	// connections alive: the router then sees a couple of long-lived sockets
	// instead of one new connection per resolved address.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxConnsPerHost = maxConcurrent
	transport.MaxIdleConnsPerHost = defaultRouterOSRestMaxIdleConns
	transport.IdleConnTimeout = defaultRouterOSRestIdleConnExpiry
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
	rest := &RouterOSRestClient{
		cfg:                  cfg,
		client:               client,
		baseURL:              baseURL + "/rest",
		cache:                newAddressCache(),
		limiter:              newRouterLimiter(maxConcurrent, cfg.MinRequestInterval),
		timeout:              timeout,
		reconnectionAttempts: reconnectionAttempts,
		restoreCleared:       cfg.RestoreClearedList == nil || *cfg.RestoreClearedList,
	}

	if err := rest.ping(connectionAttempts); err != nil {
		return nil, err
	}
	rest.startCacheRefresher(refreshInterval(cfg.RefreshInterval))
	return rest, nil
}

// listURL points at the address-list menu for an address family. RouterOS keeps
// IPv4 and IPv6 entries in separate menus, and the IPv4 one rejects an IPv6
// literal as "not a valid dns name".
func (c *RouterOSRestClient) listURL(family string) string {
	return c.baseURL + "/" + family + "/firewall/address-list"
}

func (c *RouterOSRestClient) addressURL(address string) string {
	return c.listURL(addressFamily(address))
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
	key := cacheKey(listName, address)
	effectiveTTL := ""
	if ttl != nil && strings.TrimSpace(*ttl) != "" {
		effectiveTTL = strings.TrimSpace(*ttl)
	} else if c.cfg.TTL != nil && strings.TrimSpace(*c.cfg.TTL) != "" {
		effectiveTTL = strings.TrimSpace(*c.cfg.TTL)
	}

	c.cache.trackList(listName)
	if entry, ok := c.cache.lookup(key); ok {
		return c.refreshTTL(key, address, entry, effectiveTTL, updateTTL)
	}
	if !c.cache.claim(key) {
		return nil
	}
	defer c.cache.release(key)

	// First address for this list: pull the list once instead of looking up
	// every address separately.
	if err := c.snapshotList(listName, true); err != nil {
		slog.Warn("routeros rest list snapshot failed", "list", listName, "error", err)
	}
	if entry, ok := c.cache.lookup(key); ok {
		return c.refreshTTL(key, address, entry, effectiveTTL, updateTTL)
	}
	if c.cache.coveredBySubnet(listName, address) {
		return nil
	}

	id, err := c.addAddress(listName, domain, address, effectiveTTL)
	if err != nil {
		return err
	}
	c.storeEntry(listName, address, id, domain, effectiveTTL)
	return nil
}

// refreshTTL rewrites an entry's timeout only when it is close to expiry, so a
// busy domain does not produce a router write on every single query.
func (c *RouterOSRestClient) refreshTTL(key, address string, entry cachedEntry, wantedTTL string, updateTTL *bool) error {
	if wantedTTL == "" || !shouldUpdateTTL(c.cfg.UpdateTTL, updateTTL) {
		return nil
	}
	if !needsTTLRefresh(entry, wantedTTL) {
		return nil
	}
	if err := c.updateAddressTTL(addressFamily(address), entry.id, wantedTTL); err != nil {
		return err
	}
	parsed, known := parseRouterOSDuration(wantedTTL)
	entry.timeout = parsed
	entry.hasTimeout = known && parsed > 0
	entry.observedAt = time.Now()
	c.cache.store(key, entry)
	return nil
}

func (c *RouterOSRestClient) updateAddressTTL(family, id, ttl string) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("routeros rest address id is required")
	}
	endpoint := c.listURL(family) + "/" + id
	if _, err := c.request(http.MethodPatch, endpoint, map[string]string{
		"timeout": ttl,
	}); err == nil {
		return nil
	} else if !isNoSuchCommand(err) {
		return err
	}

	entry, err := c.getAddressEntry(family, id)
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

// refreshAllLists re-reads every touched list, one request per list, so the
// periodic refresh does not scale with the number of cached addresses. A list
// that came back empty is repopulated from the last snapshot.
func (c *RouterOSRestClient) refreshAllLists() {
	for _, listName := range c.cache.listNames() {
		if err := c.snapshotList(listName, false); err != nil {
			slog.Warn("routeros rest refresh list failed", "list", listName, "error", err)
		}
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
	menu := c.addressURL(address)
	endpoint, err := c.withQuery(menu, query)
	if err != nil {
		return "", err
	}
	body, err := c.request(http.MethodGet, endpoint, nil)
	if err != nil {
		if !isNoSuchCommand(err) {
			return "", err
		}
		body, err = c.request(http.MethodGet, menu, nil)
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

// snapshotList reads a whole address list in one request and caches the item
// ids, comments and remaining timeouts. One request replaces a per-address
// lookup for every entry already on the router, which is what keeps a deploy
// quiet. A list that lost a large share of its entries at once is repopulated.
func (c *RouterOSRestClient) snapshotList(listName string, onlyIfMissing bool) error {
	if !c.cache.claimSnapshot(listName, onlyIfMissing) {
		return nil
	}

	// A list name spans both menus, so both are read and merged.
	var entries []listEntry
	for _, family := range addressFamilies {
		rows, err := c.fetchList(family, listName)
		if err != nil {
			if family == familyIPv6 && isMissingMenuErr(err) {
				// The router has no IPv6 menu; nothing to read there.
				continue
			}
			c.cache.releaseSnapshot(listName)
			return err
		}
		for _, row := range rows {
			if fmt.Sprint(row["list"]) != listName {
				continue
			}
			address := strings.TrimSpace(fmt.Sprint(row["address"]))
			if address == "" {
				continue
			}
			entries = append(entries, listEntry{
				id:      readRestID(row),
				address: address,
				comment: readRestString(row, "comment"),
				timeout: readRestString(row, "timeout"),
			})
		}
	}
	restore := c.cache.applySnapshot(listName, entries)
	c.cache.releaseSnapshot(listName)
	slog.Debug("routeros rest list snapshot", "list", listName, "entries", len(entries))

	if len(restore) > 0 && c.restoreCleared {
		c.restoreList(listName, restore)
	}
	return nil
}

// fetchList reads every row of an address list, falling back to an unfiltered
// read on RouterOS builds that reject query parameters.
func (c *RouterOSRestClient) fetchList(family, listName string) ([]map[string]any, error) {
	menu := c.listURL(family)
	query := url.Values{}
	query.Set("list", listName)
	endpoint, err := c.withQuery(menu, query)
	if err != nil {
		return nil, err
	}
	body, err := c.request(http.MethodGet, endpoint, nil)
	if err != nil {
		if !isNoSuchCommand(err) {
			return nil, err
		}
		body, err = c.request(http.MethodGet, menu, nil)
		if err != nil {
			return nil, err
		}
	}
	return decodeRestEntries(body)
}

// restoreList re-adds entries that vanished before their timeout was due,
// after the list lost a large share of its contents at once.
func (c *RouterOSRestClient) restoreList(listName string, entries []listEntry) {
	slog.Warn("routeros rest list shrank unexpectedly, restoring", "list", listName, "entries", len(entries))
	restored := 0
	for _, entry := range entries {
		id, err := c.addAddress(listName, entry.comment, entry.address, entry.timeout)
		if err != nil {
			slog.Error("routeros rest restore address", "list", listName, "address", entry.address, "error", err)
			continue
		}
		c.storeEntry(listName, entry.address, id, entry.comment, entry.timeout)
		restored++
	}
	slog.Info("routeros rest list restored", "list", listName, "restored", restored, "total", len(entries))
}

// WarmupLists preloads the given lists so the first wave of resolutions is
// served from cache instead of one lookup per address.
func (c *RouterOSRestClient) WarmupLists(names []string) {
	for _, listName := range normalizeListNames(names) {
		if err := c.snapshotList(listName, true); err != nil {
			slog.Warn("routeros rest warmup failed", "list", listName, "error", err)
		}
	}
}

func (c *RouterOSRestClient) storeEntry(listName, address, id, comment, timeout string) {
	parsed, known := parseRouterOSDuration(timeout)
	c.cache.store(cacheKey(listName, address), cachedEntry{
		id:         id,
		comment:    comment,
		timeout:    parsed,
		hasTimeout: known && parsed > 0,
	})
}

// addAddress creates an entry and returns its id, falling back to a lookup only
// when the router does not echo the created row.
func (c *RouterOSRestClient) addAddress(listName, domain, address, timeout string) (string, error) {
	payload := map[string]string{
		"list":    listName,
		"address": address,
		"comment": domain,
	}
	if timeout != "" {
		payload["timeout"] = timeout
	}
	id, err := c.createAddress(payload)
	if err != nil {
		// Another replica may have written the same address first; adopting
		// its entry is the correct outcome, not an error.
		if found, findErr := c.findAddressID(listName, address); findErr == nil && found != "" {
			return found, nil
		}
		if isDuplicateEntryErr(err) {
			return "", nil // it exists, we just could not learn its id
		}
		return "", err
	}
	if id != "" {
		return id, nil
	}
	return c.findAddressID(listName, address)
}

func readRestString(entry map[string]any, field string) string {
	value, ok := entry[field]
	if !ok || value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func (c *RouterOSRestClient) ping(attempts int) error {
	if attempts <= 0 {
		attempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if _, err := c.requestOnce(http.MethodGet, c.listURL(familyIPv4), nil); err == nil {
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
	c.limiter.acquire()
	defer c.limiter.release()

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

// createAddress adds an entry and returns the id from the response body, so the
// caller does not need a follow-up lookup to learn it.
func (c *RouterOSRestClient) createAddress(payload map[string]string) (string, error) {
	body, err := c.request(http.MethodPut, c.addressURL(payload["address"]), payload)
	if err != nil {
		return "", err
	}
	entries, err := decodeRestEntries(body)
	if err != nil || len(entries) == 0 {
		return "", nil
	}
	return readRestID(entries[0]), nil
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

func (c *RouterOSRestClient) getAddressEntry(family, id string) (map[string]any, error) {
	body, err := c.request(http.MethodGet, c.listURL(family)+"/"+id, nil)
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
