package outputs

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-routeros/routeros"
	"gopkg.in/yaml.v3"
	"log/slog"
)

const (
	OutputFile     = "file"
	OutputRouterOS = "routeros"
)

const defaultRouterOSCacheRefresh = 5 * time.Minute

type FileOutputConfig struct {
	ID       string `yaml:"id"`
	Path     string `yaml:"path"`
	ListName string `yaml:"listName"`
	Format   string `yaml:"format"`
}

type RosApiAddressListConfig struct {
	Access     RosApiAccessConfig `yaml:"-"`
	ID         string             `yaml:"id"`
	ListName   string             `yaml:"listName"`
	TTL        *string            `yaml:"ttl"`
	UpdateTTL  *bool              `yaml:"updateTTL"`
	RecordType string             `yaml:"recordType"`
}

func (c *RosApiAddressListConfig) UnmarshalYAML(node *yaml.Node) error {
	type raw RosApiAddressListConfig
	var cfg raw
	if err := node.Decode(&cfg); err != nil {
		return err
	}
	c.ListName = cfg.ListName
	c.TTL = cfg.TTL
	c.UpdateTTL = cfg.UpdateTTL
	c.RecordType = cfg.RecordType
	c.ID = cfg.ID

	var access RosApiAccessConfig
	if err := node.Decode(&access); err != nil {
		return err
	}
	c.Access = access
	return nil
}

type WebhookConfig struct {
	ID       string `yaml:"id"`
	Method   string `yaml:"method"`
	URL      string `yaml:"url"`
	ListName string `yaml:"listName"`
}

type RosApiAccessConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	UseTLS   *bool  `yaml:"useTLS"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type AddressWriter interface {
	EnsureAddress(listName, domain, address string, ttl *string, updateTTL *bool) error
	DefaultListName() string
	DefaultRecordType() string
	OutputType() string
}

type RouterOSClient struct {
	cfg    RosApiAddressListConfig
	conn   *routeros.Client
	cache  map[string]string
	loaded map[string]bool
	mu     sync.Mutex
}

type FileWriter struct {
	basePath    string
	listName    string
	format      string
	writers     map[string]*csv.Writer
	lineWriters map[string]*bufio.Writer
	files       map[string]*os.File
	cache       map[string]map[string]bool
	mu          sync.Mutex
}

type WebhookSender struct {
	listName string
	method   string
	url      string
	client   *http.Client
}

func (w *WebhookSender) URL() string {
	return w.url
}

type timeoutConn struct {
	net.Conn
	timeout time.Duration
}

func NewRouterOSClient(cfg RosApiAddressListConfig, timeout time.Duration) (*RouterOSClient, error) {
	if cfg.Access.Host == "" {
		return nil, errors.New("routeros host is required")
	}
	if err := ApplyHostOverrides(&cfg.Access); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.RecordType) == "" {
		return nil, errors.New("routeros recordType is required")
	}
	cfg.RecordType = strings.ToLower(strings.TrimSpace(cfg.RecordType))
	if cfg.RecordType != "ip" && cfg.RecordType != "host" {
		return nil, fmt.Errorf("routeros recordType must be ip or host, got %q", cfg.RecordType)
	}
	if cfg.ListName == "" {
		return nil, errors.New("routeros listName is required")
	}
	if cfg.Access.Username == "" {
		cfg.Access.Username = os.Getenv("ROUTEROS_USER")
	}
	if cfg.Access.Password == "" {
		cfg.Access.Password = os.Getenv("ROUTEROS_PASS")
	}
	if cfg.Access.Username == "" || cfg.Access.Password == "" {
		return nil, errors.New("routeros credentials are required (username/password or env ROUTEROS_USER/ROUTEROS_PASS)")
	}

	address := FormatRouterOSAddress(cfg.Access)

	conn, err := dialRouterOS(address, cfg.Access.Username, cfg.Access.Password, effectiveUseTLS(cfg.Access), timeout)
	if err != nil {
		return nil, err
	}

	client := &RouterOSClient{
		cfg:    cfg,
		conn:   conn,
		cache:  make(map[string]string),
		loaded: make(map[string]bool),
	}
	if err := client.ensureListCache(cfg.ListName); err != nil {
		return nil, err
	}
	client.startCacheRefresher(defaultRouterOSCacheRefresh)
	return client, nil
}

func (c *RouterOSClient) DefaultListName() string {
	return c.cfg.ListName
}

func (c *RouterOSClient) DefaultRecordType() string {
	return c.cfg.RecordType
}

func (c *RouterOSClient) OutputType() string {
	return OutputRouterOS
}

func NewFileWriter(cfg FileOutputConfig) (*FileWriter, error) {
	basePath := strings.TrimSpace(cfg.Path)
	if basePath == "" {
		return nil, errors.New("file output path is required")
	}
	listName := strings.TrimSpace(cfg.ListName)
	if listName == "" {
		return nil, errors.New("file output listName is required")
	}
	format := strings.ToLower(strings.TrimSpace(cfg.Format))
	if format == "" {
		format = "csv"
	}
	switch format {
	case "csv", "ipset", "nftset":
	default:
		return nil, fmt.Errorf("file output format must be csv, ipset, or nftset, got %q", format)
	}
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, err
	}
	writer := &FileWriter{
		basePath:    basePath,
		listName:    listName,
		format:      format,
		writers:     make(map[string]*csv.Writer),
		lineWriters: make(map[string]*bufio.Writer),
		files:       make(map[string]*os.File),
		cache:       make(map[string]map[string]bool),
	}
	return writer, nil
}

func NewWebhookSender(cfg WebhookConfig, client *http.Client) (*WebhookSender, error) {
	endpoint := strings.TrimSpace(cfg.URL)
	if endpoint == "" {
		return nil, errors.New("webhook url is required")
	}
	listName := strings.TrimSpace(cfg.ListName)
	if listName == "" {
		return nil, errors.New("webhook listName is required")
	}
	if _, err := url.ParseRequestURI(endpoint); err != nil {
		return nil, fmt.Errorf("invalid webhook url %q: %w", endpoint, err)
	}
	method := strings.ToUpper(strings.TrimSpace(cfg.Method))
	if method == "" {
		method = http.MethodPost
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &WebhookSender{
		listName: listName,
		method:   method,
		url:      endpoint,
		client:   client,
	}, nil
}

func FormatRouterOSAddress(cfg RosApiAccessConfig) string {
	port := cfg.Port
	if port == 0 {
		if effectiveUseTLS(cfg) {
			port = 8729
		} else {
			port = 8728
		}
	}
	return net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", port))
}

func (c *RouterOSClient) ensureListCache(listName string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.loaded[listName] {
		return nil
	}

	reply, err := c.conn.Run("/ip/firewall/address-list/print", fmt.Sprintf("?list=%s", listName))
	if err != nil {
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "no such item") {
			c.loaded[listName] = true
			return nil
		}
		if strings.Contains(lower, "routeros reply word: !empty") {
			c.loaded[listName] = true
			return nil
		}
		return err
	}
	for _, re := range reply.Re {
		id := re.Map[".id"]
		address := re.Map["address"]
		if address != "" && id != "" {
			key := fmt.Sprintf("%s|%s", listName, address)
			c.cache[key] = id
		}
	}
	c.loaded[listName] = true
	return nil
}

func (c *RouterOSClient) EnsureAddress(listName, domain, address string, ttl *string, updateTTL *bool) error {
	if err := c.ensureListCache(listName); err != nil {
		return err
	}

	key := fmt.Sprintf("%s|%s", listName, address)
	effectiveTTL := ""
	if ttl != nil && strings.TrimSpace(*ttl) != "" {
		effectiveTTL = strings.TrimSpace(*ttl)
	} else if c.cfg.TTL != nil && strings.TrimSpace(*c.cfg.TTL) != "" {
		effectiveTTL = strings.TrimSpace(*c.cfg.TTL)
	}

	c.mu.Lock()
	if id, ok := c.cache[key]; ok && id != "" {
		c.mu.Unlock()
		if effectiveTTL == "" || !shouldUpdateTTL(c.cfg.UpdateTTL, updateTTL) {
			return nil
		}
		return c.updateAddressTTL(id, effectiveTTL)
	} else if ok && id == "" {
		c.mu.Unlock()
		if err := c.refreshListCache(listName); err != nil {
			return err
		}
		if effectiveTTL == "" || !shouldUpdateTTL(c.cfg.UpdateTTL, updateTTL) {
			return nil
		}
		c.mu.Lock()
		id = c.cache[key]
		c.mu.Unlock()
		if id != "" {
			return c.updateAddressTTL(id, effectiveTTL)
		}
		return nil
	}
	c.mu.Unlock()

	args := []string{
		"/ip/firewall/address-list/add",
		fmt.Sprintf("=list=%s", listName),
		fmt.Sprintf("=address=%s", address),
		fmt.Sprintf("=comment=%s", domain),
	}
	if effectiveTTL != "" {
		args = append(args, fmt.Sprintf("=timeout=%s", effectiveTTL))
	}

	c.mu.Lock()
	if _, ok := c.cache[key]; ok {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	reply, err := c.conn.RunArgs(args)
	if err != nil {
		return err
	}
	if len(reply.Re) > 0 {
		if id := reply.Re[0].Map[".id"]; id != "" {
			c.mu.Lock()
			c.cache[key] = id
			c.mu.Unlock()
			return nil
		}
	}
	if err := c.refreshListCache(listName); err != nil {
		return err
	}
	return nil
}

func (c *RouterOSClient) updateAddressTTL(id, ttl string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.conn.RunArgs([]string{
		"/ip/firewall/address-list/set",
		fmt.Sprintf("=.id=%s", id),
		fmt.Sprintf("=timeout=%s", ttl),
	})
	return err
}

func (c *RouterOSClient) refreshListCache(listName string) error {
	c.mu.Lock()
	c.loaded[listName] = false
	c.mu.Unlock()
	return c.ensureListCache(listName)
}

func (c *RouterOSClient) refreshAllLists() {
	c.mu.Lock()
	listNames := make([]string, 0, len(c.loaded))
	for listName, loaded := range c.loaded {
		if loaded {
			listNames = append(listNames, listName)
		}
	}
	c.mu.Unlock()

	for _, listName := range listNames {
		if err := c.refreshListCache(listName); err != nil {
			slog.Error("routeros refresh list cache", "list", listName, "error", err)
		}
	}
}

func (c *RouterOSClient) startCacheRefresher(interval time.Duration) {
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

func (f *FileWriter) EnsureAddress(listName, domain, address string, ttl *string, updateTTL *bool) error {
	_ = ttl
	_ = updateTTL
	if listName == "" {
		return nil
	}
	key := fmt.Sprintf("%s|%s", listName, address)
	if f.format != "csv" {
		key = fmt.Sprintf("%s|%s", listName, domain)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if f.cache[listName] == nil {
		f.cache[listName] = make(map[string]bool)
	}
	if f.cache[listName][key] {
		return nil
	}

	if err := f.writeLine(listName, domain, address); err != nil {
		return err
	}
	f.cache[listName][key] = true
	return nil
}

func (f *FileWriter) DefaultListName() string {
	return f.listName
}

func (f *FileWriter) DefaultRecordType() string {
	return "ip"
}

func (f *FileWriter) OutputType() string {
	return OutputFile
}

func (f *FileWriter) writeLine(listName, domain, address string) error {
	switch f.format {
	case "ipset":
		return f.writePlainLine(listName, fmt.Sprintf("ipset=/%s/%s", domain, listName))
	case "nftset":
		return f.writePlainLine(listName, fmt.Sprintf("nftset=/%s/%s", domain, listName))
	default:
	}
	writer, err := f.getWriter(listName)
	if err != nil {
		return err
	}
	if err := writer.Write([]string{domain, address}); err != nil {
		return err
	}
	writer.Flush()
	return writer.Error()
}

func (f *FileWriter) getWriter(listName string) (*csv.Writer, error) {
	if writer, ok := f.writers[listName]; ok {
		return writer, nil
	}
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	filePath := filepath.Join(f.basePath, fmt.Sprintf("%s.csv", listName))
	file, err := os.OpenFile(filePath, flags, 0644)
	if err != nil {
		return nil, err
	}
	buf := bufio.NewWriter(file)
	writer := csv.NewWriter(buf)
	f.files[listName] = file
	f.writers[listName] = writer
	return writer, nil
}

func (f *FileWriter) writePlainLine(listName, line string) error {
	writer, err := f.getLineWriter(listName)
	if err != nil {
		return err
	}
	if _, err := writer.WriteString(line + "\n"); err != nil {
		return err
	}
	return writer.Flush()
}

func (f *FileWriter) getLineWriter(listName string) (*bufio.Writer, error) {
	if writer, ok := f.lineWriters[listName]; ok {
		return writer, nil
	}
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	ext := ".conf"
	filePath := filepath.Join(f.basePath, fmt.Sprintf("%s%s", listName, ext))
	file, err := os.OpenFile(filePath, flags, 0644)
	if err != nil {
		return nil, err
	}
	writer := bufio.NewWriter(file)
	f.files[listName] = file
	f.lineWriters[listName] = writer
	return writer, nil
}

func (w *WebhookSender) Send(ctx context.Context, listName, domain string, addresses []string) error {
	if listName == "" {
		listName = w.listName
	}
	var (
		req *http.Request
		err error
	)
	if w.method == http.MethodGet {
		endpoint, err := url.Parse(w.url)
		if err != nil {
			return err
		}
		values := endpoint.Query()
		values.Set("list", listName)
		values.Set("domain", domain)
		for _, address := range addresses {
			values.Add("addresses[]", address)
		}
		endpoint.RawQuery = values.Encode()
		req, err = http.NewRequestWithContext(ctx, w.method, endpoint.String(), nil)
		if err != nil {
			return err
		}
	} else {
		payload := struct {
			List      string   `json:"list"`
			Domain    string   `json:"domain"`
			Addresses []string `json:"addresses"`
		}{
			List:      listName,
			Domain:    domain,
			Addresses: addresses,
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		req, err = http.NewRequestWithContext(ctx, w.method, w.url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("webhook status %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

func shouldUpdateTTL(global *bool, override *bool) bool {
	if override != nil {
		return *override
	}
	if global == nil {
		return true
	}
	return *global
}

func (c *timeoutConn) Read(p []byte) (int, error) {
	if c.timeout > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.timeout))
	}
	return c.Conn.Read(p)
}

func (c *timeoutConn) Write(p []byte) (int, error) {
	if c.timeout > 0 {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(c.timeout))
	}
	return c.Conn.Write(p)
}

func dialRouterOS(address, username, password string, useTLS bool, timeout time.Duration) (*routeros.Client, error) {
	dialer := &net.Dialer{Timeout: timeout}
	var (
		conn net.Conn
		err  error
	)
	if useTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", address, &tls.Config{})
	} else {
		conn, err = dialer.Dial("tcp", address)
	}
	if err != nil {
		return nil, err
	}
	if timeout > 0 {
		conn = &timeoutConn{Conn: conn, timeout: timeout}
	}
	client, err := routeros.NewClient(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := client.Login(username, password); err != nil {
		client.Close()
		return nil, err
	}
	return client, nil
}

func ApplyHostOverrides(cfg *RosApiAccessConfig) error {
	if cfg == nil || cfg.Host == "" {
		return nil
	}
	entry := cfg.Host
	if !strings.Contains(entry, "://") {
		entry = "http://" + entry
	}
	parsed, err := url.Parse(entry)
	if err != nil {
		return fmt.Errorf("invalid routeros host %q: %w", cfg.Host, err)
	}
	if parsed.Hostname() == "" {
		return fmt.Errorf("invalid routeros host %q", cfg.Host)
	}
	schemeTLS := schemeUseTLS(parsed.Scheme)
	if schemeTLS == nil {
		return fmt.Errorf("unsupported routeros host scheme %q", parsed.Scheme)
	}
	if cfg.UseTLS == nil {
		cfg.UseTLS = schemeTLS
	}
	if cfg.Port == 0 && parsed.Port() != "" {
		port, err := strconv.Atoi(parsed.Port())
		if err != nil {
			return fmt.Errorf("invalid routeros port %q", parsed.Port())
		}
		cfg.Port = port
	}
	cfg.Host = parsed.Hostname()
	return nil
}

func effectiveUseTLS(cfg RosApiAccessConfig) bool {
	if cfg.UseTLS != nil {
		return *cfg.UseTLS
	}
	return false
}

func schemeUseTLS(scheme string) *bool {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "https":
		value := true
		return &value
	case "http":
		value := false
		return &value
	default:
		return nil
	}
}
