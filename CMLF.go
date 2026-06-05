/*
CMLF.go - Customizable Modular Linux Firewall
A stateful firewall with TUI, anomaly detection, rate limiting, and learning mode.

Build: go build -ldflags="-s -w" -o CMLF CMLF.go
Run: sudo ./CMLF --tui

Dependencies:
  go get github.com/google/gopacket
  go get github.com/charmbracelet/bubbletea
  go get github.com/charmbracelet/lipgloss
  github.com/fatih/color (indirect via lipgloss)
*/

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ============================================================================
// Version & Banner
// ============================================================================

const version = "CMLF v1.0.0"

func printBanner() {
	asciiArt := `
   ▄████▄   ███▄ ▄███▓ ██▓     █████▒
  ▒██▀ ▀█  ▓██▒▀█▀ ██▒▓██▒   ▓██   ▒
  ▒▓█    ▄ ▓██    ▓██░▒██░   ▒████ ░
  ▒▓▓▄ ▄██▒▒██    ▒██ ▒██░   ░▓█▒  ░
  ▒ ▓███▀ ░▒██▒   ░██▒░██████▒░▒█░   
  ░ ░▒ ▒  ░░ ▒░   ░  ░░ ▒░▓  ░ ▒ ░   
    ░  ▒   ░  ░      ░░ ░ ▒  ░ ░     
  ░         ░      ░   ░ ░    ░ ░   
  ░ ░              ░     ░  ░       
  ░                                  
`
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
	red := lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	fmt.Println(green.Render(asciiArt))
	fmt.Println(red.Render(version))
	fmt.Println()
}

// ============================================================================
// Configuration & Types
// ============================================================================

// Config holds all firewall configuration
type Config struct {
	Interface     string `json:"interface"`
	RulesFile     string `json:"rules_file"`
	Daemon        bool   `json:"daemon"`
	Status        bool   `json:"status"`
	BlockAdd      string `json:"block_add"`
	BlockReason   string `json:"block_reason"`
	BlockList     bool   `json:"block_list"`
	BlockRemove   string `json:"block_remove"`
	Learn         bool   `json:"learn"`
	LearnDuration int    `json:"learn_duration"` // seconds
	DryRun        bool   `json:"dry_run"`
	DisableHTTP   bool   `json:"disable_http"`
	TUI           bool   `json:"tui"`

	// Anomaly thresholds
	PortScanThreshold   int `json:"port_scan_threshold"`    // ports in time window
	PortScanWindow      int `json:"port_scan_window"`       // seconds
	PortScanBlockTime   int `json:"port_scan_block_time"`   // minutes
	SSHBruteThreshold   int `json:"ssh_brute_threshold"`    // attempts
	SSHBruteWindow      int `json:"ssh_brute_window"`       // seconds
	SSHBruteBlockTime   int `json:"ssh_brute_block_time"`   // minutes
	ExfilThreshold      int `json:"exfil_threshold"`        // packets
	ExfilWindow         int `json:"exfil_window"`           // seconds
	ExfilBlockTime      int `json:"exfil_block_time"`       // minutes
	ExfilPacketSize     int `json:"exfil_packet_size"`      // bytes
	LearningProfileFile string
}

// Rule represents a firewall rule
type Rule struct {
	Action    string // "allow", "deny", "ratelimit", "whitelist", "blacklist"
	Src       string
	Dst       string
	SrcPort   int
	DstPort   int
	Proto     string // "tcp", "udp", "icmp", "any"
	Rate      float64 // tokens per second for ratelimit
	Burst     int     // burst capacity for ratelimit
}

// ConnectionState represents TCP state
type ConnectionState string

const (
	SynSent    ConnectionState = "SYN_SENT"
	Established                = "ESTABLISHED"
	FinWait                    = "FIN_WAIT"
	Closed                     = "CLOSED"
)

// Connection tracks a TCP flow
type Connection struct {
	SrcIP     string
	SrcPort   uint16
	DstIP     string
	DstPort   uint16
	Protocol  string
	State     ConnectionState
	StartTime time.Time
	LastSeen  time.Time
	BytesOut  uint64
	BytesIn   uint64
}

// ConnectionKey uniquely identifies a connection
type ConnectionKey struct {
	SrcIP, DstIP string
	SrcPort, DstPort uint16
	Protocol string
}

// BlacklistEntry represents a blocked IP
type BlacklistEntry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	BlockedAt time.Time `json:"blocked_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// TokenBucket implements rate limiting
type TokenBucket struct {
	rate       float64
	burst      int
	tokens     float64
	lastUpdate time.Time
	mu         sync.Mutex
}

// RateLimitKey identifies a rate limiter
type RateLimitKey struct {
	SrcIP  string
	DstPort int
	Proto  string
}

// LearningProfile stores learned traffic patterns
type LearningProfile struct {
	IPStats        map[string]*IPStats `json:"ip_stats"`
	TopDestPorts   []int               `json:"top_dest_ports"`
	AvgNewConnsPerSec float64          `json:"avg_new_conns_per_sec"`
	CollectedAt    time.Time           `json:"collected_at"`
	Duration       int                 `json:"duration_seconds"`
}

type IPStats struct {
	PacketsPerSec  float64   `json:"packets_per_sec"`
	DestPorts      map[int]int `json:"dest_ports"`
	TotalPackets   uint64    `json:"total_packets"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
}

// Firewall is the main structure
type Firewall struct {
	config            *Config
	rules             []Rule
	whitelist         map[string]bool
	blacklist         map[string]*BlacklistEntry
	connections       map[ConnectionKey]*Connection
	connMutex         sync.RWMutex
	rateLimiters      map[RateLimitKey]*TokenBucket
	rlMutex           sync.Mutex
	packetCount       uint64
	droppedCount      uint64
	startTime         time.Time
	ctx               context.Context
	cancel            context.CancelFunc
	iptablesRules     []string // track added rules for cleanup
	learningProfile   *LearningProfile
	learningMode      bool
	learningEnd       time.Time
	ipScanTracker     map[string]*ScanTracker
	scanMutex         sync.Mutex
	sshBruteTracker   map[string]*BruteTracker
	sshMutex          sync.Mutex
	exfilTracker      map[string]*ExfilTracker
	exfilMutex        sync.Mutex
	packetRate        uint64 // packets per second (atomic)
	packetRateHistory []uint64
	rateMutex         sync.Mutex
	msgArea           string
	msgMutex          sync.RWMutex
	handle            *pcap.Handle
	httpServer        *http.Server
}

type ScanTracker struct {
	Ports    map[uint16]bool
	FirstSeen time.Time
	LastSeen  time.Time
	Count     int
}

type BruteTracker struct {
	Attempts  int
	FirstSeen time.Time
	LastSeen  time.Time
}

type ExfilTracker struct {
	LargePackets int
	FirstSeen    time.Time
	LastSeen     time.Time
}

// ============================================================================
// TokenBucket Implementation
// ============================================================================

func NewTokenBucket(rate float64, burst int) *TokenBucket {
	return &TokenBucket{
		rate:       rate,
		burst:      burst,
		tokens:     float64(burst),
		lastUpdate: time.Now(),
	}
}

func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastUpdate).Seconds()
	tb.tokens += elapsed * tb.rate
	if tb.tokens > float64(tb.burst) {
		tb.tokens = float64(tb.burst)
	}
	tb.lastUpdate = now

	if tb.tokens >= 1.0 {
		tb.tokens -= 1.0
		return true
	}
	return false
}

// ============================================================================
// Rule Parsing & Loading
// ============================================================================

func parseRule(line string) (*Rule, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, nil
	}

	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid rule format")
	}

	rule := &Rule{Action: parts[0]}

	for i := 1; i < len(parts); i++ {
		switch parts[i] {
		case "src":
			if i+1 < len(parts) {
				rule.Src = parts[i+1]
				i++
			}
		case "dst":
			if i+1 < len(parts) {
				rule.Dst = parts[i+1]
				i++
			}
		case "port":
			if i+1 < len(parts) {
				port, _ := strconv.Atoi(parts[i+1])
				rule.DstPort = port
				i++
			}
		case "proto":
			if i+1 < len(parts) {
				rule.Proto = parts[i+1]
				i++
			}
		case "rate":
			if i+1 < len(parts) {
				fmt.Sscanf(parts[i+1], "%f/sec", &rule.Rate)
				i++
			}
		case "burst":
			if i+1 < len(parts) {
				fmt.Sscanf(parts[i+1], "%d", &rule.Burst)
				i++
			}
		case "ip":
			if i+1 < len(parts) {
				if rule.Action == "whitelist" {
					rule.Src = parts[i+1]
				} else if rule.Action == "blacklist" {
					rule.Src = parts[i+1]
				}
				i++
			}
		}
	}
	return rule, nil
}

func (fw *Firewall) loadRules() error {
	file, err := os.Open(fw.config.RulesFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no rules file is OK
		}
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	fw.rules = nil
	fw.whitelist = make(map[string]bool)

	for scanner.Scan() {
		rule, err := parseRule(scanner.Text())
		if err != nil {
			log.Printf("Error parsing rule: %v", err)
			continue
		}
		if rule == nil {
			continue
		}
		fw.rules = append(fw.rules, *rule)
		if rule.Action == "whitelist" && rule.Src != "" {
			fw.whitelist[rule.Src] = true
		}
		if rule.Action == "blacklist" && rule.Src != "" {
			fw.addToBlacklist(rule.Src, "from rules file", 0)
		}
	}
	return scanner.Err()
}

// ============================================================================
// Blacklist Management with iptables
// ============================================================================

func (fw *Firewall) addToBlacklist(ip, reason string, durationMinutes int) {
	fw.msgMutex.Lock()
	fw.msgArea = fmt.Sprintf("Blocked %s: %s", ip, reason)
	fw.msgMutex.Unlock()

	if _, exists := fw.blacklist[ip]; exists {
		return
	}

	expires := time.Now().Add(time.Duration(durationMinutes) * time.Minute)
	if durationMinutes == 0 {
		expires = time.Now().Add(24 * time.Hour) // default 24h
	}

	fw.blacklist[ip] = &BlacklistEntry{
		IP:        ip,
		Reason:    reason,
		BlockedAt: time.Now(),
		ExpiresAt: expires,
	}

	if !fw.config.DryRun && !fw.learningMode {
		cmd := exec.Command("iptables", "-I", "INPUT", "-s", ip, "-j", "DROP")
		if err := cmd.Run(); err != nil {
			log.Printf("Failed to add iptables rule for %s: %v", ip, err)
		} else {
			fw.iptablesRules = append(fw.iptablesRules, ip)
		}
	}
}

func (fw *Firewall) removeFromBlacklist(ip string) {
	if entry, exists := fw.blacklist[ip]; exists {
		fw.msgMutex.Lock()
		fw.msgArea = fmt.Sprintf("Unblocked %s (was: %s)", ip, entry.Reason)
		fw.msgMutex.Unlock()
		delete(fw.blacklist, ip)

		if !fw.config.DryRun {
			cmd := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
			cmd.Run() // ignore error
		}
	}
}

func (fw *Firewall) cleanupBlacklistExpired() {
	for ip, entry := range fw.blacklist {
		if time.Now().After(entry.ExpiresAt) {
			fw.removeFromBlacklist(ip)
		}
	}
}

func (fw *Firewall) saveBlacklist() error {
	data, err := json.MarshalIndent(fw.blacklist, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile("blacklist.json", data, 0644)
}

func (fw *Firewall) loadBlacklist() error {
	data, err := os.ReadFile("blacklist.json")
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var entries map[string]*BlacklistEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return err
	}
	for ip, entry := range entries {
		if time.Now().Before(entry.ExpiresAt) {
			fw.blacklist[ip] = entry
			if !fw.config.DryRun && !fw.learningMode {
				exec.Command("iptables", "-I", "INPUT", "-s", ip, "-j", "DROP").Run()
				fw.iptablesRules = append(fw.iptablesRules, ip)
			}
		}
	}
	return nil
}

func (fw *Firewall) cleanupIPTables() {
	for _, ip := range fw.iptablesRules {
		exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP").Run()
	}
}

// ============================================================================
// Anomaly Detection
// ============================================================================

func (fw *Firewall) checkPortScan(srcIP string, dstPort uint16) {
	fw.scanMutex.Lock()
	defer fw.scanMutex.Unlock()

	tracker, exists := fw.ipScanTracker[srcIP]
	if !exists {
		fw.ipScanTracker[srcIP] = &ScanTracker{
			Ports:     make(map[uint16]bool),
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		}
		tracker = fw.ipScanTracker[srcIP]
	}

	tracker.Ports[dstPort] = true
	tracker.LastSeen = time.Now()

	if time.Since(tracker.FirstSeen).Seconds() <= float64(fw.config.PortScanWindow) &&
		len(tracker.Ports) >= fw.config.PortScanThreshold {
		fw.addToBlacklist(srcIP, "port scan", fw.config.PortScanBlockTime)
		delete(fw.ipScanTracker, srcIP)
	}

	// Cleanup old trackers
	for ip, t := range fw.ipScanTracker {
		if time.Since(t.LastSeen) > time.Duration(fw.config.PortScanWindow)*time.Second {
			delete(fw.ipScanTracker, ip)
		}
	}
}

func (fw *Firewall) checkSSHBrute(srcIP string) {
	fw.sshMutex.Lock()
	defer fw.sshMutex.Unlock()

	tracker, exists := fw.sshBruteTracker[srcIP]
	if !exists {
		fw.sshBruteTracker[srcIP] = &BruteTracker{
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		}
		tracker = fw.sshBruteTracker[srcIP]
	}

	tracker.Attempts++
	tracker.LastSeen = time.Now()

	if time.Since(tracker.FirstSeen).Seconds() <= float64(fw.config.SSHBruteWindow) &&
		tracker.Attempts >= fw.config.SSHBruteThreshold {
		fw.addToBlacklist(srcIP, "ssh brute force", fw.config.SSHBruteBlockTime)
		delete(fw.sshBruteTracker, srcIP)
	}

	for ip, t := range fw.sshBruteTracker {
		if time.Since(t.LastSeen) > time.Duration(fw.config.SSHBruteWindow)*time.Second {
			delete(fw.sshBruteTracker, ip)
		}
	}
}

func (fw *Firewall) checkExfiltration(srcIP string, packetSize int) {
	if !strings.HasPrefix(srcIP, "192.168.") && !strings.HasPrefix(srcIP, "10.") && !strings.HasPrefix(srcIP, "172.") {
		return // only internal IPs for exfiltration detection
	}

	fw.exfilMutex.Lock()
	defer fw.exfilMutex.Unlock()

	tracker, exists := fw.exfilTracker[srcIP]
	if !exists {
		fw.exfilTracker[srcIP] = &ExfilTracker{
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		}
		tracker = fw.exfilTracker[srcIP]
	}

	if packetSize > fw.config.ExfilPacketSize {
		tracker.LargePackets++
	}
	tracker.LastSeen = time.Now()

	if time.Since(tracker.FirstSeen).Seconds() <= float64(fw.config.ExfilWindow) &&
		tracker.LargePackets >= fw.config.ExfilThreshold {
		fw.addToBlacklist(srcIP, "possible exfiltration", fw.config.ExfilBlockTime)
		delete(fw.exfilTracker, srcIP)
	}

	for ip, t := range fw.exfilTracker {
		if time.Since(t.LastSeen) > time.Duration(fw.config.ExfilWindow)*time.Second {
			delete(fw.exfilTracker, ip)
		}
	}
}

// ============================================================================
// Connection Tracking
// ============================================================================

func (fw *Firewall) getConnectionKey(packet gopacket.Packet, ip4 *layers.IPv4, tcp *layers.TCP) ConnectionKey {
	return ConnectionKey{
		SrcIP:    ip4.SrcIP.String(),
		DstIP:    ip4.DstIP.String(),
		SrcPort:  uint16(tcp.SrcPort),
		DstPort:  uint16(tcp.DstPort),
		Protocol: "tcp",
	}
}

func (fw *Firewall) updateConnectionState(key ConnectionKey, tcp *layers.TCP) {
	fw.connMutex.Lock()
	defer fw.connMutex.Unlock()

	conn, exists := fw.connections[key]
	if !exists {
		conn = &Connection{
			SrcIP:     key.SrcIP,
			SrcPort:   key.SrcPort,
			DstIP:     key.DstIP,
			DstPort:   key.DstPort,
			Protocol:  key.Protocol,
			StartTime: time.Now(),
			State:     SynSent,
		}
		fw.connections[key] = conn
	}

	conn.LastSeen = time.Now()

	if tcp.SYN && !tcp.ACK {
		conn.State = SynSent
	} else if tcp.SYN && tcp.ACK {
		conn.State = Established
	} else if tcp.FIN {
		conn.State = FinWait
	} else if tcp.RST {
		conn.State = Closed
	} else if conn.State == Established && (tcp.ACK || tcp.PSH) {
		conn.State = Established
	}
}

func (fw *Firewall) cleanupConnections() {
	fw.connMutex.Lock()
	defer fw.connMutex.Unlock()

	timeouts := map[ConnectionState]time.Duration{
		Established: 3600 * time.Second,
		FinWait:     60 * time.Second,
		Closed:      10 * time.Second,
		SynSent:     30 * time.Second,
	}

	for key, conn := range fw.connections {
		timeout, exists := timeouts[conn.State]
		if !exists {
			timeout = 60 * time.Second
		}
		if time.Since(conn.LastSeen) > timeout {
			delete(fw.connections, key)
		}
	}
}

// ============================================================================
// Packet Processing & Rule Evaluation
// ============================================================================

func (fw *Firewall) matchRule(rule *Rule, srcIP, dstIP string, dstPort int, proto string) bool {
	// Source match
	if rule.Src != "" && rule.Src != "any" {
		_, ipnet, err := net.ParseCIDR(rule.Src)
		if err == nil {
			if !ipnet.Contains(net.ParseIP(srcIP)) {
				return false
			}
		} else if rule.Src != srcIP {
			return false
		}
	}

	// Destination match
	if rule.Dst != "" && rule.Dst != "any" {
		_, ipnet, err := net.ParseCIDR(rule.Dst)
		if err == nil {
			if !ipnet.Contains(net.ParseIP(dstIP)) {
				return false
			}
		} else if rule.Dst != dstIP {
			return false
		}
	}

	// Port match
	if rule.DstPort != 0 && rule.DstPort != dstPort {
		return false
	}

	// Protocol match
	if rule.Proto != "" && rule.Proto != "any" && rule.Proto != proto {
		return false
	}

	return true
}

func (fw *Firewall) evaluateRules(srcIP, dstIP string, dstPort int, proto string) string {
	// Whitelist first
	if fw.whitelist[srcIP] {
		return "allow"
	}

	// Blacklist
	if _, blocked := fw.blacklist[srcIP]; blocked {
		return "deny"
	}

	// Apply rules in order
	for _, rule := range fw.rules {
		if fw.matchRule(&rule, srcIP, dstIP, dstPort, proto) {
			return rule.Action
		}
	}
	return "allow" // default allow
}

func (fw *Firewall) processPacket(packet gopacket.Packet) {
	atomic.AddUint64(&fw.packetCount, 1)

	// Update packet rate
	now := time.Now()
	staticNow := now // capture for rate calc

	go func(t time.Time) {
		var pps uint64
		fw.rateMutex.Lock()
		if len(fw.packetRateHistory) > 0 {
			// Simple rate calculation
			pps = 1
		}
		atomic.StoreUint64(&fw.packetRate, pps)
		fw.rateMutex.Unlock()
	}(staticNow)

	// Parse layers
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip4, _ := ipLayer.(*layers.IPv4)

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	udpLayer := packet.Layer(layers.LayerTypeUDP)

	var srcIP, dstIP string
	var dstPort int
	var proto string

	srcIP = ip4.SrcIP.String()
	dstIP = ip4.DstIP.String()

	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		dstPort = int(tcp.DstPort)
		proto = "tcp"

		// Connection tracking for TCP
		key := fw.getConnectionKey(packet, ip4, tcp)
		fw.updateConnectionState(key, tcp)

		// Check if this is an established connection return packet
		fw.connMutex.RLock()
		revKey := ConnectionKey{
			SrcIP:    dstIP,
			DstIP:    srcIP,
			SrcPort:  uint16(tcp.DstPort),
			DstPort:  uint16(tcp.SrcPort),
			Protocol: "tcp",
		}
		_, isEstablished := fw.connections[revKey]
		fw.connMutex.RUnlock()

		if isEstablished && tcp.ACK {
			// Allow established connection packets without rule check
			return
		}
	} else if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		dstPort = int(udp.DstPort)
		proto = "udp"
	} else {
		proto = "icmp"
	}

	// Learning mode - just collect stats
	if fw.learningMode && time.Now().Before(fw.learningEnd) {
		fw.collectLearningStats(srcIP, dstPort)
		return
	} else if fw.learningMode && time.Now().After(fw.learningEnd) {
		fw.learningMode = false
		fw.saveLearningProfile()
		fw.msgMutex.Lock()
		fw.msgArea = "Learning mode completed, profile saved"
		fw.msgMutex.Unlock()
	}

	// Anomaly detection
	fw.checkPortScan(srcIP, uint16(dstPort))
	if dstPort == 22 && proto == "tcp" {
		fw.checkSSHBrute(srcIP)
	}
	fw.checkExfiltration(srcIP, len(packet.Data()))

	// Rule evaluation
	action := fw.evaluateRules(srcIP, dstIP, dstPort, proto)

	if action == "deny" || action == "blacklist" {
		atomic.AddUint64(&fw.droppedCount, 1)
		return
	}

	if action == "ratelimit" {
		key := RateLimitKey{SrcIP: srcIP, DstPort: dstPort, Proto: proto}
		fw.rlMutex.Lock()
		rl, exists := fw.rateLimiters[key]
		if !exists {
			rl = NewTokenBucket(20.0, 30) // defaults
			fw.rateLimiters[key] = rl
		}
		fw.rlMutex.Unlock()

		if !rl.Allow() {
			atomic.AddUint64(&fw.droppedCount, 1)
			return
		}
	}
}

func (fw *Firewall) collectLearningStats(srcIP string, dstPort int) {
	fw.connMutex.Lock()
	defer fw.connMutex.Unlock()

	stats, exists := fw.learningProfile.IPStats[srcIP]
	if !exists {
		stats = &IPStats{
			DestPorts: make(map[int]int),
			FirstSeen: time.Now(),
		}
		fw.learningProfile.IPStats[srcIP] = stats
	}
	stats.TotalPackets++
	stats.LastSeen = time.Now()
	stats.DestPorts[dstPort]++

	// Calculate PPS
	elapsed := time.Since(stats.FirstSeen).Seconds()
	if elapsed > 0 {
		stats.PacketsPerSec = float64(stats.TotalPackets) / elapsed
	}
}

func (fw *Firewall) saveLearningProfile() error {
	// Calculate top ports
	portCounts := make(map[int]int)
	for _, stats := range fw.learningProfile.IPStats {
		for port, count := range stats.DestPorts {
			portCounts[port] += count
		}
	}

	type portCount struct {
		port  int
		count int
	}
	var sorted []portCount
	for p, c := range portCounts {
		sorted = append(sorted, portCount{p, c})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})

	fw.learningProfile.TopDestPorts = make([]int, 0)
	for i := 0; i < 10 && i < len(sorted); i++ {
		fw.learningProfile.TopDestPorts = append(fw.learningProfile.TopDestPorts, sorted[i].port)
	}

	fw.learningProfile.CollectedAt = time.Now()

	data, err := json.MarshalIndent(fw.learningProfile, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(fw.config.LearningProfileFile, data, 0644)
}

func (fw *Firewall) loadLearningProfile() error {
	data, err := os.ReadFile(fw.config.LearningProfileFile)
	if err != nil {
		if os.IsNotExist(err) {
			fw.learningProfile = &LearningProfile{
				IPStats: make(map[string]*IPStats),
			}
			return nil
		}
		return err
	}
	var profile LearningProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return err
	}
	profile.IPStats = make(map[string]*IPStats) // re-initialize for safety
	fw.learningProfile = &profile
	return nil
}

// ============================================================================
// Packet Capture Loop
// ============================================================================

func (fw *Firewall) packetCaptureLoop() error {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic in packet capture: %v", r)
		}
	}()

	var err error
	fw.handle, err = pcap.OpenLive(fw.config.Interface, 1600, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer fw.handle.Close()

	packetSource := gopacket.NewPacketSource(fw.handle, fw.handle.LinkType())

	// Cleanup tickers
	cleanupTicker := time.NewTicker(30 * time.Second)
	blacklistSaveTicker := time.NewTicker(30 * time.Second)
	rateLimitCleanupTicker := time.NewTicker(5 * time.Minute)

	go func() {
		for {
			select {
			case <-fw.ctx.Done():
				cleanupTicker.Stop()
				blacklistSaveTicker.Stop()
				rateLimitCleanupTicker.Stop()
				return
			case <-cleanupTicker.C:
				fw.cleanupConnections()
				fw.cleanupBlacklistExpired()
			case <-blacklistSaveTicker.C:
				fw.saveBlacklist()
			case <-rateLimitCleanupTicker.C:
				fw.rlMutex.Lock()
				// Clean up old rate limiters
				fw.rateLimiters = make(map[RateLimitKey]*TokenBucket)
				fw.rlMutex.Unlock()
			}
		}
	}()

	for {
		select {
		case <-fw.ctx.Done():
			return nil
		case packet := <-packetSource.Packets():
			fw.processPacket(packet)
		}
	}
}

// ============================================================================
// HTTP Status Server
// ============================================================================

func (fw *Firewall) startHTTPServer() {
	if fw.config.DisableHTTP {
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/status", fw.handleStatus)
	mux.HandleFunc("/blacklist", fw.handleBlacklist)
	mux.HandleFunc("/metrics", fw.handleMetrics)

	fw.httpServer = &http.Server{
		Addr:    "127.0.0.1:9090",
		Handler: mux,
	}

	go func() {
		if err := fw.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()
}

func (fw *Firewall) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := struct {
		Uptime            float64 `json:"uptime"`
		PacketsProcessed  uint64  `json:"packets_processed"`
		PacketsDropped    uint64  `json:"packets_dropped"`
		ActiveConnections int     `json:"active_connections"`
		BlacklistedIPs    int     `json:"blacklisted_ips"`
	}{
		Uptime:            time.Since(fw.startTime).Seconds(),
		PacketsProcessed:  atomic.LoadUint64(&fw.packetCount),
		PacketsDropped:    atomic.LoadUint64(&fw.droppedCount),
		ActiveConnections: len(fw.connections),
		BlacklistedIPs:    len(fw.blacklist),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (fw *Firewall) handleBlacklist(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(fw.blacklist)
}

func (fw *Firewall) handleMetrics(w http.ResponseWriter, r *http.Request) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# HELP cmlf_packets_processed Total packets processed\n"))
	sb.WriteString(fmt.Sprintf("# TYPE cmlf_packets_processed counter\n"))
	sb.WriteString(fmt.Sprintf("cmlf_packets_processed %d\n", atomic.LoadUint64(&fw.packetCount)))
	sb.WriteString(fmt.Sprintf("# HELP cmlf_packets_dropped Total packets dropped\n"))
	sb.WriteString(fmt.Sprintf("# TYPE cmlf_packets_dropped counter\n"))
	sb.WriteString(fmt.Sprintf("cmlf_packets_dropped %d\n", atomic.LoadUint64(&fw.droppedCount)))
	sb.WriteString(fmt.Sprintf("# HELP cmlf_active_connections Current active connections\n"))
	sb.WriteString(fmt.Sprintf("# TYPE cmlf_active_connections gauge\n"))
	sb.WriteString(fmt.Sprintf("cmlf_active_connections %d\n", len(fw.connections)))
	sb.WriteString(fmt.Sprintf("# HELP cmlf_blacklisted_ips Current blacklisted IPs\n"))
	sb.WriteString(fmt.Sprintf("# TYPE cmlf_blacklisted_ips gauge\n"))
	sb.WriteString(fmt.Sprintf("cmlf_blacklisted_ips %d\n", len(fw.blacklist)))
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.Write([]byte(sb.String()))
}

// ============================================================================
// TUI with BubbleTea
// ============================================================================

type TUIModel struct {
	fw                *Firewall
	width             int
	height            int
	lastUpdate        time.Time
	style             lipgloss.Style
	blockStyle        lipgloss.Style
	connStyle         lipgloss.Style
	rateStyle         lipgloss.Style
	msgStyle          lipgloss.Style
	helpStyle         lipgloss.Style
}

func NewTUIModel(fw *Firewall) TUIModel {
	style := lipgloss.NewStyle().
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("63")).
		Padding(1, 2)

	blockStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("9")).
		Bold(true)

	connStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("10"))

	rateStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("14"))

	msgStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("11")).
		Italic(true)

	helpStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("8"))

	return TUIModel{
		fw:         fw,
		lastUpdate: time.Now(),
		style:      style,
		blockStyle: blockStyle,
		connStyle:  connStyle,
		rateStyle:  rateStyle,
		msgStyle:   msgStyle,
		helpStyle:  helpStyle,
	}
}

func (m TUIModel) Init() tea.Cmd {
	return tea.Batch(
		tea.EnterAltScreen,
		tick(),
	)
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

type tickMsg time.Time

func (m TUIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "b":
			m.fw.msgMutex.Lock()
			m.fw.msgArea = "Showing blacklist (use --block-list for full output)"
			m.fw.msgMutex.Unlock()
		case "r":
			m.fw.loadRules()
			m.fw.msgMutex.Lock()
			m.fw.msgArea = "Rules reloaded"
			m.fw.msgMutex.Unlock()
		case "l":
			if !m.fw.learningMode {
				m.fw.learningMode = true
				m.fw.learningEnd = time.Now().Add(3600 * time.Second)
				m.fw.msgMutex.Lock()
				m.fw.msgArea = "Learning mode activated for 1 hour"
				m.fw.msgMutex.Unlock()
			}
		}
	case tickMsg:
		return m, tick()
	}
	return m, nil
}

func (m TUIModel) View() string {
	if m.width == 0 {
		return "Loading..."
	}

	// Header
	uptime := time.Since(m.fw.startTime).Round(time.Second).String()
	packets := atomic.LoadUint64(&m.fw.packetCount)
	header := lipgloss.JoinHorizontal(
		lipgloss.Top,
		m.style.Render(fmt.Sprintf(" CMLF Firewall ")),
		m.style.Render(fmt.Sprintf(" Uptime: %s ", uptime)),
		m.style.Render(fmt.Sprintf(" Packets: %d ", packets)),
	)

	// Connections table (last 10)
	connLines := []string{"Src IP:Port → Dst IP:Port (Proto, Age)"}
	m.fw.connMutex.RLock()
	connCount := 0
	for _, conn := range m.fw.connections {
		if connCount >= 10 {
			break
		}
		age := time.Since(conn.StartTime).Round(time.Second)
		connLines = append(connLines, fmt.Sprintf("%s:%d → %s:%d (%s, %s)",
			conn.SrcIP, conn.SrcPort, conn.DstIP, conn.DstPort, conn.Protocol, age))
		connCount++
	}
	m.fw.connMutex.RUnlock()
	connView := m.connStyle.Render(lipgloss.NewStyle().Width(m.width-4).Render(strings.Join(connLines, "\n")))

	// Blacklist table
	blockLines := []string{"IP (Reason, Time remaining)"}
	m.fw.connMutex.RLock()
	for _, entry := range m.fw.blacklist {
		remaining := time.Until(entry.ExpiresAt).Round(time.Second)
		if remaining > 0 {
			blockLines = append(blockLines, fmt.Sprintf("%s (%s, %s)", entry.IP, entry.Reason, remaining))
		}
	}
	m.fw.connMutex.RUnlock()
	blockView := m.blockStyle.Render(lipgloss.NewStyle().Width(m.width-4).Render(strings.Join(blockLines, "\n")))

	// Packet rate graph
	pps := atomic.LoadUint64(&m.fw.packetRate)
	graphWidth := 50
	barLength := int(float64(pps) / 1000.0 * float64(graphWidth))
	if barLength > graphWidth {
		barLength = graphWidth
	}
	bar := strings.Repeat("█", barLength)
	rateView := m.rateStyle.Render(fmt.Sprintf("Packet Rate: %d pps [%s]", pps, bar))

	// Message area
	m.fw.msgMutex.RLock()
	msg := m.fw.msgArea
	m.fw.msgMutex.RUnlock()
	msgView := m.msgStyle.Render(msg)

	// Footer
	helpView := m.helpStyle.Render("q: quit | b: blacklist | r: reload rules | l: learning mode")

	// Combine all
	body := lipgloss.JoinVertical(
		lipgloss.Left,
		header,
		"\n",
		m.style.Render("Active Connections (last 10):"),
		connView,
		"\n",
		m.style.Render("Blocked IPs:"),
		blockView,
		"\n",
		m.style.Render("Traffic Rate:"),
		rateView,
		"\n",
		m.style.Render("Messages:"),
		msgView,
		"\n",
		helpView,
	)

	return body
}

// ============================================================================
// Main & CLI Flag Handling
// ============================================================================

func loadConfig() *Config {
	cfg := &Config{
		Interface:            "eth0",
		RulesFile:            "/etc/cmlf/rules.conf",
		Daemon:               false,
		Status:               false,
		BlockList:            false,
		Learn:                false,
		LearnDuration:        3600,
		DryRun:               false,
		DisableHTTP:          false,
		TUI:                  false,
		PortScanThreshold:    10,
		PortScanWindow:       5,
		PortScanBlockTime:    10,
		SSHBruteThreshold:    5,
		SSHBruteWindow:       30,
		SSHBruteBlockTime:    30,
		ExfilThreshold:       50,
		ExfilWindow:          10,
		ExfilBlockTime:       5,
		ExfilPacketSize:      1400,
		LearningProfileFile:  "profile.json",
	}

	flag.StringVar(&cfg.Interface, "interface", cfg.Interface, "Network interface to monitor")
	flag.StringVar(&cfg.RulesFile, "config", cfg.RulesFile, "Rules configuration file")
	flag.BoolVar(&cfg.Daemon, "daemon", cfg.Daemon, "Run as daemon (no TUI)")
	flag.BoolVar(&cfg.Status, "status", cfg.Status, "Print status and exit")
	flag.StringVar(&cfg.BlockAdd, "block-add", cfg.BlockAdd, "Add IP to blacklist")
	flag.StringVar(&cfg.BlockReason, "reason", cfg.BlockReason, "Reason for blocking")
	flag.BoolVar(&cfg.BlockList, "block-list", cfg.BlockList, "List blacklisted IPs")
	flag.StringVar(&cfg.BlockRemove, "block-remove", cfg.BlockRemove, "Remove IP from blacklist")
	flag.BoolVar(&cfg.Learn, "learn", cfg.Learn, "Enable learning mode")
	flag.IntVar(&cfg.LearnDuration, "duration", cfg.LearnDuration, "Learning duration in seconds")
	flag.BoolVar(&cfg.DryRun, "dry-run", cfg.DryRun, "Don't actually block, just log")
	flag.BoolVar(&cfg.DisableHTTP, "disable-http", cfg.DisableHTTP, "Disable HTTP status server")
	flag.BoolVar(&cfg.TUI, "tui", cfg.TUI, "Run with TUI interface")

	flag.Parse()
	return cfg
}

func main() {
	printBanner()

	// Check root privileges
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "Error: This program must be run as root (for pcap and iptables)")
		os.Exit(1)
	}

	cfg := loadConfig()

	// Handle standalone commands
	if cfg.Status {
		// TODO: implement status output
		fmt.Println("CMLF Status - Use HTTP endpoint or TUI for live stats")
		return
	}

	if cfg.BlockList {
		data, err := os.ReadFile("blacklist.json")
		if err != nil {
			fmt.Printf("No blacklist file: %v\n", err)
			return
		}
		fmt.Println(string(data))
		return
	}

	if cfg.BlockAdd != "" {
		fw := &Firewall{
			config:        cfg,
			blacklist:     make(map[string]*BlacklistEntry),
			iptablesRules: make([]string, 0),
		}
		fw.loadBlacklist()
		fw.addToBlacklist(cfg.BlockAdd, cfg.BlockReason, 0)
		fw.saveBlacklist()
		fmt.Printf("Added %s to blacklist\n", cfg.BlockAdd)
		return
	}

	if cfg.BlockRemove != "" {
		fw := &Firewall{
			config:        cfg,
			blacklist:     make(map[string]*BlacklistEntry),
			iptablesRules: make([]string, 0),
		}
		fw.loadBlacklist()
		fw.removeFromBlacklist(cfg.BlockRemove)
		fw.saveBlacklist()
		fmt.Printf("Removed %s from blacklist\n", cfg.BlockRemove)
		return
	}

	// Initialize firewall
	fw := &Firewall{
		config:           cfg,
		whitelist:        make(map[string]bool),
		blacklist:        make(map[string]*BlacklistEntry),
		connections:      make(map[ConnectionKey]*Connection),
		rateLimiters:     make(map[RateLimitKey]*TokenBucket),
		startTime:        time.Now(),
		ipScanTracker:    make(map[string]*ScanTracker),
		sshBruteTracker:  make(map[string]*BruteTracker),
		exfilTracker:     make(map[string]*ExfilTracker),
		packetRateHistory: make([]uint64, 0),
		iptablesRules:    make([]string, 0),
		learningMode:     cfg.Learn,
	}

	if cfg.Learn {
		fw.learningEnd = time.Now().Add(time.Duration(cfg.LearnDuration) * time.Second)
		fw.learningProfile = &LearningProfile{
			IPStats: make(map[string]*IPStats),
			Duration: cfg.LearnDuration,
		}
	} else {
		fw.loadLearningProfile()
	}

	// Load rules and blacklist
	if err := fw.loadRules(); err != nil {
		log.Printf("Warning: Could not load rules: %v", err)
	}
	if err := fw.loadBlacklist(); err != nil {
		log.Printf("Warning: Could not load blacklist: %v", err)
	}

	// Setup context and signal handling
	fw.ctx, fw.cancel = context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, os.Kill)

	go func() {
		<-sigChan
		fmt.Println("\nShutting down...")
		fw.cancel()
		if fw.handle != nil {
			fw.handle.Close()
		}
		fw.saveBlacklist()
		fw.cleanupIPTables()
		if fw.httpServer != nil {
			fw.httpServer.Shutdown(context.Background())
		}
		os.Exit(0)
	}()

	// Start packet capture
	go func() {
		if err := fw.packetCaptureLoop(); err != nil {
			log.Printf("Packet capture error: %v", err)
		}
	}()

	// Start HTTP server
	fw.startHTTPServer()

	// Run TUI or daemon mode
	if cfg.TUI && !cfg.Daemon {
		p := tea.NewProgram(NewTUIModel(fw))
		if _, err := p.Run(); err != nil {
			fmt.Printf("Error running TUI: %v\n", err)
			os.Exit(1)
		}
	} else if cfg.Daemon {
		log.Println("CMLF running in daemon mode")
		<-fw.ctx.Done()
	} else {
		// Default: show status and exit (or run in foreground)
		fmt.Println("CMLF Firewall running. Use --tui for interactive mode, --daemon for background.")
		fmt.Println("Press Ctrl+C to exit")
		<-fw.ctx.Done()
	}
}