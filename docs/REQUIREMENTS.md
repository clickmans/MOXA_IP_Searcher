# 需求与工程约束 — MOXA 全产品 IP 搜索工具（Windows x64 单文件 EXE）

## 1. 产品目标

一个**绿色免安装**的 Windows 64 位软件，点击「广播搜索」后，通过**本机全部网卡**向所在二层广播域发送多协议搜索包，列出**所有 MOXA 设备**的 IP 地址。不依赖任何运行时（无 Python/.NET/VC 运行库），单文件 `.exe` 双击即用。

## 2. 必须满足（P0）

| 编号 | 需求 | 验收方式 |
|---|---|---|
| R1 | 遍历本机**所有**已启用 IPv4 网卡，逐网卡发送广播（不限默认网卡） | 在 3 网卡机器上搜索时，抓包可见每个网卡都有源 IP 不同的请求帧 |
| R2 | 覆盖 4800 / 4000 / 40404 / 5800 四种协议（+ 29168 / 1029 / 22222 兜底） | 用 mock 应答四类帧，四类都能解析出 IP |
| R3 | **设备与本机不同网段也能搜到**（同二层广播域） | mock 用 192.168.100.x 源地址回包，本机 192.168.99.163，仍能列出 |
| R4 | **多个设备 IP 相同，全部列出**（禁止按 IP 去重） | mock 回两个不同 MAC、同一 IP，界面出现两行 |
| R5 | 点击「广播搜索」**不弹任何提示/确认对话框**，立即出现进度条窗口 | 点击即出现，无中间弹窗 |
| R6 | 搜索完成，进度窗口**自动关闭** | 完成后进度窗口消失，主窗口显示结果 |
| R7 | 单文件、无依赖、x64 | `dumpbin`/PowerShell 查看 PE 为 AMD64；干净机器双击可运行 |
| R8 | 搜索期间 UI 不卡死（可拖动、可重绘） | 搜索中拖动窗口正常 |
| R9 | **exe 图标 = 桌面 `logo.jpg`（MOXA 字标）**：资源管理器/任务栏/窗口标题栏三处都要显示 | 资源管理器看 exe 有 MOXA 图标；Alt+Tab/任务栏同图标 |

## 3. 技术栈（强制）

- **Go 1.24 / GOOS=windows / GOARCH=amd64 / CGO_ENABLED=0**
- **仅标准库**：`net`、`syscall`、`unsafe`、`unicode/utf16`、`encoding/binary`、`time`、`os`、`encoding/json`、`sort`、`sync`、`fmt`。
  **禁止** `golang.org/x/sys`、fyne、walk、lxn/walk 等任何第三方包（保证离线可编译、零依赖）。
- GUI：直接调 Win32 API（`user32.dll` / `gdi32.dll` / `comctl32.dll`），`syscall.NewLazyDLL` + `NewProc`。
- 产物：`-ldflags "-H=windowsgui -s -w"`，输出 `dist\MOXA_IP_Searcher.exe`（预期 2–4 MB）。
- 清单：内嵌 manifest 声明 `asInvoker` + `PerMonitorV2` DPI（用 `.syso`/`rsrc` 有依赖风险，改为运行时 `SetProcessDpiAwarenessContext`，或在 `init` 中调用 `SetProcessDPIAware`）。

## 4. 界面规格

### 4.0 图标（R9，已由架构侧准备好）

- 源图：`path/to/logo.jpg`（354×354，MOXA 青绿字标，白底）。
- 已生成：`assets\logo.ico`（9 档尺寸 16/20/24/32/40/48/64/128/256，字标裁边处理）。
- 已生成：`src\rsrc.syso`（由 `rsrc -ico assets\logo.ico -arch amd64` 产出，**已实测**：`go build` 后 PE 出现 `.rsrc` 段，含 RT_ICON(3) 与 RT_GROUP_ICON(14)）。
- **要求**：
  1. `src\rsrc.syso` 必须留在 `src\` 目录（与 `package main` 同目录），`go build` 会自动链接；**不要删除、不要改名、不要重复生成**。
  2. 主窗口与进度窗口都要 `WM_SETICON`（ICON_BIG + ICON_SMALL），图标句柄用 `LoadIconW(GetModuleHandle(nil), MAKEINTRESOURCE(1))`（rsrc 默认组图标 ID = 1）。
  3. 验收：`Get-Item dist\MOXA_IP_Searcher.exe` 在资源管理器中显示 MOXA 图标；任务栏/Alt+Tab 一致。

**主窗口**（标题：`MOXA 设备 IP 搜索工具`，初始 1000×640，可缩放，最小 820×480）

```
┌──────────────────────────────────────────────────────────────┐
│ MOXA 设备 IP 搜索工具                                          │
│ 已启用网卡：192.168.99.163/24 (WLAN) · 192.168.56.1/24 (VMnet1) │
│ ┌────────────┐                                    [广播搜索]  │
│ │            │                                                │
│ │  ListView  │  列：序号 | IP 地址 | MAC 地址 | 型号 |         │
│ │  (report)  │      设备名称 | 协议 | 接收网卡                  │
│ └────────────┘                                                │
│ 状态栏：就绪 / 正在搜索…（第 2/3 轮）/ 找到 5 台设备（1 台 IP 重复）│
└──────────────────────────────────────────────────────────────┘
```

- 列表行**选中可复制**：`Ctrl+C` 复制选中行（TSV）。**双击行用默认浏览器打开该设备的 WEB 界面**（v1.4 起真实可用：先并行探测 80/443 决定 `http`/`https`，结果只写状态栏；同 IP 多设备时提示浏览器访问的是 ARP 命中那台）。
- 不弹 MessageBox（**任何情况下**）。错误信息写状态栏。
- 搜索开始清空旧结果，按钮置灰，搜索结束恢复。

### 4.1 视图交互（v1.9，P0）

| 编号 | 需求 | 验收方式 |
|---|---|---|
| U8 | 设备表与 LLDP 表之间**可拖动分隔条**调整上下占比；LLDP 表**最小两行**，到最小高度后不可再压缩，两行内容完整可见、无错位、无滚动异常 | 鼠标拖动分隔条，两表高度随之变化；拖到底后再拖几何零变化；LLDP 表客户区 = 表头 + 2×行高，无横向滚动条、无半行 |
| U9 | 点 **产品型号** / **IP 地址** 表头切换升序/降序；型号相同按 IP、型号与 IP 均相同按 MAC；IP 相同按型号、IP 与型号均相同按 MAC；对全部结果生效；表头体现字段与方向 | 点表头后行序按三级键变化，表头出现 `▲/▼`；同列再点反向；换列回到升序 |
| U10 | 搜索完成后可按**「设备信息来源网卡」多选筛选**（v1.9.1 起唯一入口 = 点该列表头，无独立按钮）：仅显示一张或多张网卡来源的设备，默认全部；筛选与排序、占比互不影响；可随时清除恢复全部 | 点该列表头弹出勾选菜单，勾选/取消后行数随之变化，状态栏显示 `已筛选：显示 7/8 台`；`显示全部网卡` 后全部恢复；筛选后仍可排序 |

**进度窗口**（点击按钮 → 立即创建并显示，居中，置顶子窗口，无按钮）

```
┌───────────────────────────────┐
│  正在搜索 MOXA 设备…           │
│  ▓▓▓▓▓▓▓▓▓░░░░░░░░  45%       │
│  第 2/3 轮 · 已发现 3 台       │
└───────────────────────────────┘
```
- 用原生 `msctls_progress32` + `STATIC` + `Segoe UI 9pt`。
- 进度按 `(轮次 / 总轮次)` 推进，每轮结束刷新一次，另加 100 ms 定时器做平滑。
- 结束时 `DestroyWindow`，**自动消失**。

## 5. 文件结构（建议）

```
src/
  go.mod                  module moxasearch; go 1.24
  main.go                 入口：无参→GUI；--scan→headless
  internal/discovery/
    discover.go           网卡枚举、逐卡发送、收包循环、结果聚合（R1/R3/R4）
    protocol_4800.go      协议 A 编解码 + 型号查询
    protocol_4000.go      协议 B
    protocol_axom.go      协议 C
    protocol_wsu.go       协议 D
    protocol_extra.go     兜底端口
    model.go              Device 结构、去重合并、排序
    *_test.go             表驱动单测（夹具见 PROTOCOL_SPEC.md §9）
  internal/ui/
    app.go                窗口、消息循环、ListView、按钮
    progress.go           进度窗口
    win32.go              Win32 绑定（可拆 wndproc）
build.ps1 / build.bat     一键构建（go build -trimpath -ldflags ...）
dist/MOXA_IP_Searcher.exe
```

## 6. headless 模式（QA 用，必须有）

```
MOXA_IP_Searcher.exe --scan --out result.json [--timeout 1500]
```
- 无窗口，执行一轮完整搜索，写 JSON 后退出码 0。
- JSON schema：
```json
{"started_at":"2026-11-02T11:00:00+08:00","elapsed_ms":1523,
 "adapters":[{"name":"WLAN","ip":"192.168.99.163","mask":"255.255.255.0"}],
 "devices":[{"ip":"192.168.100.253","mac":"50:0B:88:00:00:DC","model":"AWK-1161A",
             "name":"awk-1161a","protocol":"AXOM/40404","adapters":["WLAN"]}],
 "errors":[]}
```
- 便于自动化回归，也方便用户排障。

## 7. 需写入说明的边界

- 只能发现**同一二层广播域**内设备（跨路由/跨 VLAN 不保证），与官方工具一致。
- 若官方工具（MXConfig/DSU 等）同时运行，可能端口抢占；本工具应容错并提示。
- 设备若关闭了发现服务/防火墙拦截，则搜不到。

## 8. 构建与验收命令

```powershell
set CGO_ENABLED=0
go build -trimpath -ldflags "-H=windowsgui -s -w" -o dist\MOXA_IP_Searcher.exe .\src
go test ./src/... -v
```

## 9. 交付物

1. `dist\MOXA_IP_Searcher.exe`（单文件）
2. `src\` 全部源码（含单测，`go test` 全绿）
3. `README.md`（使用说明 + 协议表 + 已知限制）
