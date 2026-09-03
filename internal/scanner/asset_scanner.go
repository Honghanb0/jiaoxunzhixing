package scanner

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"security-agent/internal/models"
)

// AssetScanner 网络暴露面扫描器
// 参考 wanpinglingtan/src/secscan 实现：DNS解析 + 端口扫描 + 服务识别 + 子域名枚举
type AssetScanner struct {
	portTimeout    time.Duration // 端口探测超时
	httpTimeout    time.Duration // HTTP 指纹超时
	concurrency    int           // 并发扫描数
	commonPorts    []int         // 常见端口列表
	subdomainWords []string      // 子域名爆破字典
}

// NewAssetScanner 创建资产扫描器
func NewAssetScanner() *AssetScanner {
	return &AssetScanner{
		portTimeout: 1 * time.Second,
		httpTimeout: 3 * time.Second,
		concurrency: 50,
		commonPorts: []int{
			21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
			443, 445, 993, 995, 1433, 1521, 3306, 3389,
			5432, 5900, 6379, 8080, 8443, 8888, 9000, 9200,
			27017, 7001, 7002, 8000, 8009, 8081, 9090, 9999,
			7070, 5000, 5060, 4443, 8002, 8003, 8004, 8005,
			8006, 8007, 8008, 8010, 8800, 8880, 8099, 8888,
		},
		subdomainWords: []string{
			"www", "mail", "ftp", "admin", "test", "dev", "api",
			"blog", "shop", "app", "m", "wap", "cms", "oa", "crm",
			"erp", "hr", "finance", "vpn", "proxy", "git", "svn",
			"jenkins", "ci", "cdn", "static", "img", "upload",
			"backend", "front", "portal", "sso", "auth", "login",
			"db", "redis", "mq", "es", "kibana", "grafana",
		},
	}
}

// AssetScanResult 单次资产扫描结果
type AssetScanResult struct {
	Subdomains []*models.Subdomain
	IPs        []*models.IP
	Ports      []*models.Port
	Services   []*models.Service
	Errors     []string
}

// ScanDomain 对指定域名执行全面资产扫描
func (s *AssetScanner) ScanDomain(ctx context.Context, domain *models.Domain) (*AssetScanResult, error) {
	result := &AssetScanResult{}
	domainName := strings.TrimSpace(domain.Name)
	if domainName == "" {
		return nil, fmt.Errorf("域名为空")
	}
	// 移除协议前缀
	domainName = strings.TrimPrefix(domainName, "http://")
	domainName = strings.TrimPrefix(domainName, "https://")
	domainName = strings.Split(domainName, "/")[0]

	log.Printf("[AssetScanner] 开始扫描域名: %s", domainName)

	// 1. 子域名枚举（跳过裸 IP，对 IP 枚举子域名无意义）
	var subdomains []*models.Subdomain
	if net.ParseIP(domainName) == nil {
		subdomains = s.enumerateSubdomains(ctx, domainName)
	}
	result.Subdomains = subdomains
	log.Printf("[AssetScanner] 发现子域名: %d", len(subdomains))

	// 2. DNS 解析所有域名（主域名 + 子域名）
	var allHosts []string
	allHosts = append(allHosts, domainName)
	for _, sub := range subdomains {
		allHosts = append(allHosts, sub.Name)
	}

	ipMap := make(map[string]*models.IP) // address -> IP，去重
	for _, host := range allHosts {
		if ctx.Err() != nil {
			break
		}
		ips := s.resolveIPs(host)
		for _, ipStr := range ips {
			if _, exists := ipMap[ipStr]; !exists {
				ip := &models.IP{
					Address:     ipStr,
					Version:     detectIPVersion(ipStr),
					IsAlive:     true,
					LastScanned: time.Now(),
					CreatedAt:   time.Now(),
				}
				ipMap[ipStr] = ip
				result.IPs = append(result.IPs, ip)
			}
		}
	}
	log.Printf("[AssetScanner] 解析 IP: %d", len(result.IPs))

	// 3. 端口扫描（并发）
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, s.concurrency)

	for _, ip := range result.IPs {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(targetIP *models.IP) {
			defer wg.Done()
			defer func() { <-sem }()

			ports := s.scanPorts(ctx, targetIP.Address)
			mu.Lock()
			result.Ports = append(result.Ports, ports...)
			mu.Unlock()

			// 4. 服务识别（对开放端口）
			for _, port := range ports {
				if port.State != "open" {
					continue
				}
				service := s.identifyService(ctx, targetIP.Address, port)
				if service != nil {
					mu.Lock()
					result.Services = append(result.Services, service)
					mu.Unlock()
				}
			}
		}(ip)
	}
	wg.Wait()

	log.Printf("[AssetScanner] 开放端口: %d, 服务: %d", len(result.Ports), len(result.Services))
	return result, nil
}

// enumerateSubdomains 子域名枚举（crt.sh API + 小字典爆破）
func (s *AssetScanner) enumerateSubdomains(ctx context.Context, rootDomain string) []*models.Subdomain {
	var subs []*models.Subdomain
	seen := make(map[string]bool)

	// 方式 1: crt.sh 证书透明日志查询
	crtSubs := s.queryCRTSh(ctx, rootDomain)
	for _, name := range crtSubs {
		if !seen[name] && name != rootDomain {
			seen[name] = true
			subs = append(subs, &models.Subdomain{
				Name:        name,
				Source:      "crtsh",
				LastScanned: time.Now(),
				CreatedAt:   time.Now(),
			})
		}
	}

	// 方式 2: 字典爆破
	for _, word := range s.subdomainWords {
		if ctx.Err() != nil {
			break
		}
		name := word + "." + rootDomain
		if seen[name] {
			continue
		}
		ips := s.resolveIPs(name)
		if len(ips) > 0 {
			seen[name] = true
			subs = append(subs, &models.Subdomain{
				Name:        name,
				Source:      "brute",
				LastScanned: time.Now(),
				CreatedAt:   time.Now(),
			})
		}
	}

	return subs
}

// queryCRTSh 通过 crt.sh API 查询子域名
func (s *AssetScanner) queryCRTSh(ctx context.Context, domain string) []string {
	var names []string
	client := &http.Client{Timeout: 8 * time.Second}
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return names
	}
	resp, err := client.Do(req)
	if err != nil {
		return names
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return names
	}

	// 简单解析 JSON 中的 name_value 字段，避免引入 json.Unmarshal 的复杂结构
	re := regexp.MustCompile(`"name_value"\s*:\s*"([^"]+)"`)
	matches := re.FindAllStringSubmatch(string(body), -1)
	for _, m := range matches {
		if len(m) > 1 {
			// crt.sh 可能返回多个换行分隔的域名
			for _, n := range strings.Split(m[1], "\n") {
				n = strings.TrimSpace(n)
				if n != "" && strings.HasSuffix(n, domain) {
					names = append(names, n)
				}
			}
		}
	}
	return names
}

// resolveIPs DNS 解析域名到 IP 列表
func (s *AssetScanner) resolveIPs(host string) []string {
	var ips []string
	// 如果 host 本身就是 IP 地址，直接返回
	if ip := net.ParseIP(host); ip != nil {
		log.Printf("[AssetScanner] %s 是裸 IP，直接使用", host)
		return []string{host}
	}
	log.Printf("[AssetScanner] DNS 解析 %s ...", host)
	results, err := net.LookupIP(host)
	if err != nil {
		log.Printf("[AssetScanner] DNS 解析 %s 失败: %v", host, err)
		return ips
	}
	for _, ip := range results {
		ips = append(ips, ip.String())
	}
	log.Printf("[AssetScanner] DNS 解析 %s 得到 %d 个 IP", host, len(ips))
	return ips
}

// detectIPVersion 判断 IP 版本
func detectIPVersion(ipStr string) string {
	if strings.Contains(ipStr, ":") {
		return "ipv6"
	}
	return "ipv4"
}

// scanPorts 对单个 IP 进行 TCP 端口扫描（连接扫描）
func (s *AssetScanner) scanPorts(ctx context.Context, ip string) []*models.Port {
	var ports []*models.Port
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, s.concurrency)

	for _, port := range s.commonPorts {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			state := s.probeTCP(ip, p)
			if state == "open" {
				portObj := &models.Port{
					IPAddress:   ip,
					Port:        p,
					Protocol:    "tcp",
					State:       "open",
					ServiceName: commonPortService(p),
					LastScanned: time.Now(),
					CreatedAt:   time.Now(),
				}
				mu.Lock()
				ports = append(ports, portObj)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	return ports
}

// probeTCP TCP 连接探测
func (s *AssetScanner) probeTCP(ip string, port int) string {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, s.portTimeout)
	if err != nil {
		return "closed"
	}
	defer conn.Close()
	return "open"
}

// identifyService 对开放端口进行服务识别（banner 抓取 + HTTP 指纹）
func (s *AssetScanner) identifyService(ctx context.Context, ip string, port *models.Port) *models.Service {
	address := net.JoinHostPort(ip, strconv.Itoa(port.Port))
	service := &models.Service{
		IPAddress:   ip,
		PortNum:     port.Port,
		LastScanned: time.Now(),
		CreatedAt:   time.Now(),
	}

	// 1. Banner 抓取
	conn, err := net.DialTimeout("tcp", address, s.portTimeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(s.httpTimeout))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		banner := strings.TrimSpace(string(buf[:n]))
		port.Banner = banner
		service.Banner = banner
		service.Name = parseBannerService(banner)
	}

	// 2. HTTP 指纹识别（对 HTTP 端口发送 GET 请求）
	if isHTTPPort(port.Port) || (service.Name != "" && service.Name == "http") {
		https := port.Port == 443 || port.Port == 8443
		httpSvc := s.probeHTTP(ctx, ip, port.Port, https)
		if httpSvc != nil {
			if service.Name == "" {
				service.Name = httpSvc.Name
			}
			if httpSvc.Version != "" {
				service.Version = httpSvc.Version
			}
			service.Title = httpSvc.Title
			service.StatusCode = httpSvc.StatusCode
			if len(httpSvc.Tech) > 0 {
				service.Tech = httpSvc.Tech
			}
		}
	}

	if service.Name == "" {
		service.Name = commonPortService(port.Port)
	}

	return service
}

// HTTPFingerprint HTTP 指纹结果
type HTTPFingerprint struct {
	Name       string
	Version    string
	Title      string
	StatusCode int
	Tech       []string
}

// probeHTTP 发送 HTTP 请求识别 Web 服务
func (s *AssetScanner) probeHTTP(ctx context.Context, ip string, port int, https bool) *HTTPFingerprint {
	scheme := "http"
	if https {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/", scheme, ip, port)

	transport := &http.Transport{
		TLSHandshakeTimeout: s.httpTimeout,
		IdleConnTimeout:     s.httpTimeout,
	}
	client := &http.Client{
		Timeout:   s.httpTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 不跟随重定向
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024)) // 限制读取 512KB
	headers := resp.Header

	fp := &HTTPFingerprint{
		StatusCode: resp.StatusCode,
		Tech:       []string{},
	}

	// 服务器头分析
	server := headers.Get("Server")
	if server != "" {
		name, version := parseServerHeader(server)
		fp.Name = name
		fp.Version = version
		fp.Tech = append(fp.Tech, name)
	}

	// X-Powered-By 头
	if powered := headers.Get("X-Powered-By"); powered != "" {
		fp.Tech = append(fp.Tech, powered)
	}

	// 页面标题提取
	titleRe := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	if m := titleRe.FindStringSubmatch(string(body)); len(m) > 1 {
		fp.Title = strings.TrimSpace(m[1])
	}

	// 技术栈指纹
	fingerprints := identifyTechStack(string(body), headers)
	fp.Tech = append(fp.Tech, fingerprints...)

	return fp
}

// parseServerHeader 解析 Server 响应头
func parseServerHeader(server string) (name, version string) {
	server = strings.TrimSpace(server)
	parts := strings.SplitN(server, "/", 2)
	name = strings.ToLower(strings.TrimSpace(parts[0]))
	if len(parts) > 1 {
		version = strings.TrimSpace(parts[1])
	}
	return name, version
}

// parseBannerService 从 banner 解析服务名
func parseBannerService(banner string) string {
	lower := strings.ToLower(banner)
	switch {
	case strings.Contains(lower, "ssh"):
		return "ssh"
	case strings.Contains(lower, "ftp"):
		return "ftp"
	case strings.Contains(lower, "smtp"):
		return "smtp"
	case strings.Contains(lower, "pop3"):
		return "pop3"
	case strings.Contains(lower, "imap"):
		return "imap"
	case strings.Contains(lower, "mysql"):
		return "mysql"
	case strings.Contains(lower, "redis"):
		return "redis"
	default:
		return ""
	}
}

// identifyTechStack 识别页面技术栈
func identifyTechStack(body string, headers http.Header) []string {
	var tech []string
	seen := make(map[string]bool)
	add := func(t string) {
		if t != "" && !seen[t] {
			seen[t] = true
			tech = append(tech, t)
		}
	}

	bodyLower := strings.ToLower(body)

	// WordPress
	if strings.Contains(bodyLower, "wp-content") || strings.Contains(bodyLower, "wp-includes") {
		add("WordPress")
	}
	// jQuery
	if strings.Contains(bodyLower, "jquery") {
		add("jQuery")
	}
	// Vue
	if strings.Contains(bodyLower, "vue.js") || strings.Contains(bodyLower, "vue.min.js") || strings.Contains(bodyLower, "data-v-") {
		add("Vue.js")
	}
	// React
	if strings.Contains(bodyLower, "react") || strings.Contains(bodyLower, "_react") {
		add("React")
	}
	// Bootstrap
	if strings.Contains(bodyLower, "bootstrap") {
		add("Bootstrap")
	}
	// ThinkPHP
	if strings.Contains(bodyLower, "thinkphp") || headers.Get("X-Powered-By") == "ThinkPHP" {
		add("ThinkPHP")
	}
	// JQuery / Layui 等国内框架
	if strings.Contains(bodyLower, "layui") {
		add("Layui")
	}

	return tech
}

// isHTTPPort 判断是否为 HTTP 端口
func isHTTPPort(port int) bool {
	switch port {
	case 80, 443, 8080, 8443, 8888, 8000, 8800, 4443, 7070, 9090:
		return true
	}
	return false
}

// commonPortService 常见端口对应服务名
func commonPortService(port int) string {
	services := map[int]string{
		21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
		80: "http", 110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap",
		443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
		1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
		5432: "postgresql", 5900: "vnc", 6379: "redis",
		8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
		9000: "php-fpm", 9200: "elasticsearch", 27017: "mongodb",
		7001: "weblogic", 8000: "http-alt", 9090: "prometheus",
	}
	if svc, ok := services[port]; ok {
		return svc
	}
	return "unknown"
}
