// MOXA 设备 IP 搜索工具 — Windows x64 单文件程序。
//
// 无参数启动图形界面；带 --scan 时执行一次无界面搜索并输出 JSON，供自动化
// 回归使用（REQUIREMENTS.md §6）：
//
//	MOXA_IP_Searcher.exe --scan --out result.json [--timeout 1500]
//
// 带 --lldp <ip> 时读取该设备的 LLDP 邻居表并打印为文本表格（v1.8，现场排障用）：
//
//	MOXA_IP_Searcher.exe --lldp 192.168.127.4
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"moxasearch/src/internal/discovery"
	"moxasearch/src/internal/lldp"
	"moxasearch/src/internal/ui"
)

// adapterJSON is one entry of the "adapters" array of the headless output.
type adapterJSON struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
	Mask string `json:"mask"`
}

// deviceJSON is one entry of the "devices" array of the headless output.
type deviceJSON struct {
	IP       string   `json:"ip"`
	MAC      string   `json:"mac"`
	Model    string   `json:"model"`
	Region   string   `json:"region"`
	Name     string   `json:"name"`
	Firmware string   `json:"firmware"`
	Protocol string   `json:"protocol"`
	Adapters []string `json:"adapters"`
}

// statJSON is one entry of the "stats" array of the headless output.
//
// The array answers the question "why does this machine see fewer fields than
// that one": Received == 0 means the reply never reached this host (firewall,
// wrong adapter, port held by another program), Received > 0 with Decoded == 0
// means it arrived but did not match a known frame layout.
type statJSON struct {
	Protocol  string `json:"protocol"`
	Port      int    `json:"port"`
	LocalPort int    `json:"local_port"`
	Adapter   string `json:"adapter"`
	Received  int    `json:"received"`
	Decoded   int    `json:"decoded"`
}

// resultJSON is the complete headless report (REQUIREMENTS.md §6).
type resultJSON struct {
	StartedAt string        `json:"started_at"`
	ElapsedMS int64         `json:"elapsed_ms"`
	Adapters  []adapterJSON `json:"adapters"`
	Devices   []deviceJSON  `json:"devices"`
	Stats     []statJSON    `json:"stats"`
	Errors    []string      `json:"errors"`
}

func main() {
	scanMode := flag.Bool("scan", false, "执行一次无界面搜索，输出 JSON 后退出")
	outPath := flag.String("out", "", "JSON 输出文件路径（留空则写到标准输出）")
	timeout := flag.Int("timeout", 1500, "搜索总时长，单位毫秒")
	lldpIP := flag.String("lldp", "", "读取指定设备（IPv4）的 LLDP 邻居表并打印，排障用")
	flag.Parse()

	if *scanMode {
		os.Exit(runHeadless(*outPath, *timeout))
	}
	if strings.TrimSpace(*lldpIP) != "" {
		os.Exit(runLLDP(*lldpIP))
	}

	code, err := ui.Run()
	if err != nil {
		// GUI 子系统没有控制台，出错时尽量写到标准错误并返回非零退出码。
		fmt.Fprintln(os.Stderr, "启动失败:", err)
		os.Exit(1)
	}
	os.Exit(int(code))
}

// runHeadless performs one scan without creating any window and writes the
// JSON report. The exit code is 0 even when no device answered: an empty device
// list is a valid result, not a failure.
func runHeadless(outPath string, timeoutMilliseconds int) int {
	result := discovery.Scan(context.Background(),
		discovery.OptionsFromTimeout(timeoutMilliseconds), nil)

	report := resultJSON{
		StartedAt: result.StartedAt.Format(time.RFC3339),
		ElapsedMS: result.Elapsed.Milliseconds(),
		Adapters:  make([]adapterJSON, 0, len(result.Adapters)),
		Devices:   make([]deviceJSON, 0, len(result.Devices)),
		Stats:     make([]statJSON, 0, len(result.Stats)),
		Errors:    result.Errors,
	}
	if report.Errors == nil {
		report.Errors = []string{}
	}
	for _, stat := range result.Stats {
		report.Stats = append(report.Stats, statJSON{
			Protocol:  stat.Name,
			Port:      stat.Port,
			LocalPort: stat.LocalPort,
			Adapter:   stat.Adapter,
			Received:  stat.Received,
			Decoded:   stat.Decoded,
		})
	}
	for _, adapter := range result.Adapters {
		report.Adapters = append(report.Adapters, adapterJSON{
			Name: adapter.Name,
			IP:   adapter.IP.String(),
			Mask: adapter.MaskString(),
		})
	}
	for _, device := range result.Devices {
		adapters := device.Adapters
		if adapters == nil {
			adapters = []string{}
		}
		report.Devices = append(report.Devices, deviceJSON{
			IP:       device.IP,
			MAC:      device.MAC,
			Model:    device.Model,
			Region:   device.Region,
			Name:     device.Name,
			Firmware: device.Firmware,
			Protocol: device.Protocol,
			Adapters: adapters,
		})
	}

	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "生成 JSON 失败:", err)
		return 1
	}
	encoded = append(encoded, '\n')

	if outPath == "" {
		if _, err := os.Stdout.Write(encoded); err != nil {
			return 1
		}
		return 0
	}
	if err := os.WriteFile(outPath, encoded, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "写入结果文件失败:", err)
		return 1
	}
	// The unit is "台" (devices), not rows: one device may own several IPs and
	// therefore produce several rows, so the count is taken per MAC address.
	fmt.Fprintf(os.Stderr, "搜索完成：%d 台设备（%d 行），耗时 %d ms，结果已写入 %s\n",
		discovery.DeviceCount(result.Devices), len(report.Devices), report.ElapsedMS, outPath)
	return 0
}

// runLLDP prints the LLDP neighbour table of one device as plain text.
//
// It is the headless twin of the panel: same package, same OIDs, same output
// order, so a field problem can be diagnosed from a shell without starting the
// window. It is completely independent of --scan.
//
// Exit codes: 0 for a table (even an empty one), 2 when the device does not
// answer SNMP, 1 for any other failure.
func runLLDP(ip string) int {
	started := time.Now()
	table, err := lldp.Fetch(context.Background(), ip, lldp.Options{})
	elapsed := time.Since(started)
	if err != nil {
		if errors.Is(err, lldp.ErrNoSNMP) {
			fmt.Fprintf(os.Stderr, "%s 未响应 SNMP（community=%s），无法读取 LLDP（耗时 %d ms）\n",
				ip, lldp.DefaultCommunity, elapsed.Milliseconds())
			return 2
		}
		fmt.Fprintf(os.Stderr, "读取 %s 的 LLDP 失败: %v\n", ip, err)
		return 1
	}
	if table == nil {
		fmt.Fprintf(os.Stderr, "读取 %s 的 LLDP 失败: 没有返回结果\n", ip)
		return 1
	}

	fmt.Printf("设备 %s\n", ip)
	fmt.Printf("  机箱 ID : %s\n", dashIfEmpty(table.ChassisID))
	fmt.Printf("  系统名  : %s\n", dashIfEmpty(table.SystemName))
	fmt.Printf("  描述    : %s\n", dashIfEmpty(table.SystemDesc))
	fmt.Printf("  邻居    : %d 条\n", len(table.Neighbors))
	for _, neighbor := range table.Neighbors {
		// One labelled line per neighbour: a column layout would be misaligned
		// by the double width Chinese labels in every console.
		fmt.Printf("  - 端口 %d | 邻居 ID %s | 邻居端口 %s | 描述 %s | 系统名 %s\n",
			neighbor.Port,
			dashIfEmpty(neighbor.ChassisID),
			dashIfEmpty(neighbor.PortID),
			dashIfEmpty(neighbor.PortDesc),
			dashIfEmpty(neighbor.SystemName))
	}
	fmt.Printf("耗时 %d ms\n", elapsed.Milliseconds())
	return 0
}

// dashIfEmpty renders an empty value as "-" so a printed table keeps its shape.
func dashIfEmpty(value string) string {
	if trimmed := strings.TrimSpace(value); trimmed != "" {
		return trimmed
	}
	return "-"
}
