package network

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Pixelcity-dev/Iris/internal/core"
)

type NetworkScanner struct {
	core.BaseScanner
	name string
}

func NewNetworkScanner() *NetworkScanner {
	return &NetworkScanner{
		BaseScanner: core.BaseScanner{Enabled: true},
		name:        "network",
	}
}

func (s *NetworkScanner) Name() string {
	return s.name
}

func (s *NetworkScanner) Type() core.ScanType {
	return core.ScanTypeNetwork
}

func (s *NetworkScanner) SupportedTargets() []core.TargetKind {
	return []core.TargetKind{core.TargetNetwork}
}

func (s *NetworkScanner) Scan(ctx context.Context, target core.Target, rules []core.Rule) ([]core.Finding, error) {
	var findings []core.Finding

	hosts := expandHosts(target.URI)

	for _, host := range hosts {
		hostFindings := scanHost(host)
		findings = append(findings, hostFindings...)
	}

	return findings, nil
}

func expandHosts(cidr string) []string {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return []string{cidr}
	}

	var hosts []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		hosts = append(hosts, ip.String())
	}

	if len(hosts) > 2 {
		hosts = hosts[1 : len(hosts)-1]
	}

	if len(hosts) > 256 {
		hosts = hosts[:256]
	}

	return hosts
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func scanHost(host string) []core.Finding {
	var findings []core.Finding

	commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017}

	for _, port := range commonPorts {
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			conn.Close()

			service := identifyService(port)
			findings = append(findings, core.Finding{
				RuleID:      "network-open-port",
				Severity:    getPortSeverity(port),
				Category:    "network",
				Title:       "Open port " + strconv.Itoa(port),
				Description: fmt.Sprintf("Port %d (%s) is open on %s", port, service, host),
				Metadata: map[string]interface{}{
					"host":    host,
					"port":    port,
					"service": service,
				},
				Confidence: 1.0,
			})

			if isDangerousPort(port) {
				findings = append(findings, core.Finding{
					RuleID:      "network-dangerous-port",
					Severity:    core.SeverityHigh,
					Category:    "network-security",
					Title:       "Dangerous service exposed: " + service,
					Description: fmt.Sprintf("%s service (%s) should not be exposed", service, host+":"+strconv.Itoa(port)),
					Fix:         fmt.Sprintf("Consider restricting access to port %d", port),
					Confidence:  0.9,
				})
			}
		}
	}

	return findings
}

func identifyService(port int) string {
	services := map[int]string{
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		80:    "HTTP",
		110:   "POP3",
		143:   "IMAP",
		443:   "HTTPS",
		993:   "IMAPS",
		995:   "POP3S",
		1433:  "MSSQL",
		1521:  "Oracle",
		3306:  "MySQL",
		3389:  "RDP",
		5432:  "PostgreSQL",
		5900:  "VNC",
		6379:  "Redis",
		8080:  "HTTP-Alt",
		8443:  "HTTPS-Alt",
		9200:  "Elasticsearch",
		27017: "MongoDB",
	}

	if service, ok := services[port]; ok {
		return service
	}
	return "Unknown"
}

func getPortSeverity(port int) core.Severity {
	highRiskPorts := map[int]bool{
		21: true, 23: true, 3389: true, 5900: true, 6379: true, 27017: true,
	}

	mediumRiskPorts := map[int]bool{
		22: true, 25: true, 1433: true, 1521: true, 3306: true, 5432: true, 9200: true,
	}

	if highRiskPorts[port] {
		return core.SeverityHigh
	}
	if mediumRiskPorts[port] {
		return core.SeverityMedium
	}
	return core.SeverityInfo
}

func isDangerousPort(port int) bool {
	dangerousPorts := map[int]bool{
		21: true, 23: true, 3389: true, 5900: true, 6379: true, 27017: true,
	}
	return dangerousPorts[port]
}

func init() {
	_ = strings.Contains
	_ = fmt.Sprintf
}
