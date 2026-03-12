# CLAUDE.md — NetFlow Collector CLI Tool

## 專案概述

一個以 Rust 開發的 CLI 工具，用於接收並處理 NetFlow v5 封包。工具透過 UDP Socket 監聽 NetFlow exporter 送出的封包，解析後根據使用者設定的 IP 範圍進行過濾，並將結果輸出至 stdout。

## 技術棧

- **語言**: Rust (2021 edition)
- **非同步框架**: Tokio (full features)
- **NetFlow 解析**: `netflow_parser` crate
- **CLI 參數解析**: `clap` (derive macro)
- **設定檔**: TOML 格式，使用 `serde` + `toml` crate
- **日誌框架**: `tracing` + `tracing-subscriber`（輸出至 stderr，與資料輸出分離）
- **Signal 處理**: `tokio::signal::unix` (SIGHUP)
- **資料庫**: `tokio-postgres`（async PostgreSQL client）+ TimescaleDB extension

## 支援的 NetFlow 版本

僅支援 **NetFlow v5**。v5 結構固定，每筆 flow record 格式一致，不需處理 template。

## 功能規格

### 1. UDP Socket Server

- 使用 Tokio `UdpSocket` 綁定指定位址與 Port 進行監聽
- 監聽位址透過 CLI 參數 `--bind` 指定（例如 `--bind 0.0.0.0:2055`）
- UDP 接收緩衝區大小可透過 CLI 參數 `--recv-buffer` 設定（單位 bytes），未指定時使用系統預設值
- 接收到的 raw data 交由 `netflow_parser` 解析

### 2. `--direct-print` 模式

此模式將過濾後的 flow 資料以人類可讀的純文字對齊排版**逐行追加**輸出至 stdout。適合 pipe 到其他工具或導向檔案記錄。與 `--live` 互斥。

#### 顯示欄位

每筆 flow record 顯示以下 6 個欄位：

| 欄位       | 說明                | NetFlow v5 欄位對應 |
|------------|---------------------|---------------------|
| 來源 IP    | Source IP Address   | `srcaddr`           |
| 來源 Port  | Source Port         | `srcport`           |
| 目標 IP    | Destination IP Addr | `dstaddr`           |
| 目標 Port  | Destination Port    | `dstport`           |
| 封包數     | Packet Count        | `d_pkts`            |
| 位元組數   | Byte Count          | `d_octets`          |

#### 輸出格式

純文字對齊排版，方便人類直接閱讀。範例：

```
SRC_IP            SRC_PORT  DST_IP            DST_PORT  PACKETS   BYTES
168.95.1.1        443       192.168.1.100     52341     15        12480
168.95.2.50       80        10.0.0.5          48872     3         1560
```

#### 色彩標記（`--color`）

透過 `--color` 旗標啟用，未指定時輸出純文字（無 ANSI 色碼）。

色彩規則：
- **黃色文字**：套用於過濾命中的 IP 欄位。當 src IP 命中過濾條件時，該 SRC_IP 欄位標黃；dst IP 命中時，DST_IP 欄位標黃；兩者皆命中則兩個欄位都標黃。
- **亮綠色文字**：套用於常用 Port 欄位（SRC_PORT 或 DST_PORT）。當 port 值出現在常用 Port 清單中時標亮綠色。

常用 Port 清單採用內建預設 + 設定檔可擴充的設計：

**內建預設清單**（程式碼內硬編碼）：
- 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS)
- 80 (HTTP), 110 (POP3), 143 (IMAP), 443 (HTTPS), 993 (IMAPS)
- 995 (POP3S), 3306 (MySQL), 3389 (RDP), 5432 (PostgreSQL), 8080 (HTTP-ALT)

**設定檔擴充**（TOML，於 `filter.toml` 中）：

```toml
# 常用 Port 設定（可選區段）
[highlighted_ports]
# mode 可選值:
#   "extend"  — 在內建清單基礎上新增（預設）
#   "override" — 完全取代內建清單，僅使用此處定義的 port
mode = "extend"
ports = [8443, 6379, 27017]
```

若設定檔中未包含 `[highlighted_ports]` 區段，則使用內建預設清單。

Port 清單同樣受 SIGHUP 重新載入影響，儲存為 `HashSet<u16>` 以 O(1) 查詢。

ANSI 色碼實作使用直接輸出 escape sequence（`\x1b[33m` 黃色、`\x1b[92m` 亮綠色、`\x1b[0m` 重置），不依賴外部 colored crate，保持輕量。

### 2.5 `--live` 即時監控模式

獨立於 `--direct-print` 的另一種顯示模式，採用固定區域刷新（非逐行追加），適合在 terminal 中即時監控流量狀態。`--live` 與 `--direct-print` 互斥，不可同時使用。`--color` 旗標同樣適用於 `--live` 模式。

#### 畫面佈局

```
╔══════════════════════════════════════════════════════════════════╗
  NetFlow Live Monitor
  NPS: 42          Total: 128,563     Filtered: 8,421
╚══════════════════════════════════════════════════════════════════╝
SRC_IP            SRC_PORT  DST_IP            DST_PORT  PACKETS   BYTES
168.95.1.1        443       192.168.1.100     52341     15        12480
168.95.2.50       80        10.0.0.5          48872     3         1560
10.0.1.33         22        203.0.113.1       61002     8         4320
...（最新 N 筆 flow records，N 由設定檔 [live].lines 控制，預設 10）
```

畫面分為兩個區域：

**頂部狀態列**：
- `NPS` — NetFlow Per Second，每 1 秒更新一次，顯示過去 1 秒內接收到的（過濾後）flow record 數量
- `Total` — 自啟動以來接收到的封包總數（含未通過過濾的）
- `Filtered` — 自啟動以來通過過濾的 flow record 總數

**下方資料區**：
- 顯示最新的 N 筆過濾命中的 flow record，N 由設定檔 `[live]` 區段的 `lines` 控制，預設 10
- 採用環形緩衝區（ring buffer）維護，容量為 `lines` 值，新資料進入時最舊的一筆被擠出
- 欄位與 `--direct-print` 相同（SRC_IP、SRC_PORT、DST_IP、DST_PORT、PACKETS、BYTES）
- `--color` 的色彩規則同樣適用

#### 設定檔（TOML）

在設定檔中新增可選的 `[live]` 區段：

```toml
# 即時監控模式設定（可選區段）
[live]
lines = 20   # 資料區顯示的 flow record 行數，預設 10
```

若設定檔中未包含 `[live]` 區段，或 `[live]` 存在但未設定 `lines`，則使用預設值 10。

`[live]` 區段同樣受 SIGHUP 重新載入影響，重載後環形緩衝區會依新的 `lines` 值重新建立。

#### 刷新機制

- 使用 ANSI escape sequence 進行畫面控制：
  - `\x1b[H` 游標移至左上角
  - `\x1b[2J` 清除整個畫面（僅啟動時執行一次）
  - `\x1b[K` 清除該行剩餘內容（每行刷新時使用，避免殘留舊文字）
- NPS 狀態列每 1 秒刷新一次（獨立的 `tokio::time::interval` 觸發）
- 資料區在每筆新的過濾命中 flow 進入時更新
- 兩個區域的刷新整合在同一次畫面重繪中，避免閃爍

### 3. IP 過濾機制

#### 設定檔格式（TOML）

設定檔路徑透過 CLI 參數指定（例如 `--config filter.toml`）。

```toml
# IP 過濾清單，支援 CIDR 表示法與單一 IP
# 每組 filter 可獨立設定 direction（比對方向）
#
# direction 可選值:
#   "src" — 僅比對來源 IP
#   "dst" — 僅比對目標 IP
#   "any" — 來源或目標任一符合即納入（OR 邏輯）
# direction 未指定時預設為 "any"

[[filters]]
cidr = "168.95.0.0/16"
direction = "src"        # 這組只檢查來源 IP

[[filters]]
cidr = "192.168.1.0/24"
direction = "dst"        # 這組只檢查目標 IP

[[filters]]
cidr = "10.0.0.0/8"
direction = "any"        # 這組來源或目標任一符合即納入

[[filters]]
cidr = "203.0.113.1"     # 無遮罩，等同 /32，直接雜湊比對
                         # direction 未指定，預設 "any"
```

#### 比對邏輯

啟動時（及設定檔重新載入時），根據每組 filter 的 `direction` 分類，建立三組獨立的查詢結構：

- **`src_only`** — 一組 HashSet + CIDR 清單，收集所有 `direction = "src"` 的 filter
- **`dst_only`** — 一組 HashSet + CIDR 清單，收集所有 `direction = "dst"` 的 filter
- **`any`** — 一組 HashSet + CIDR 清單，收集所有 `direction = "any"` 的 filter

每組查詢結構內部：
1. **帶遮罩的 CIDR 範圍**：將 CIDR 轉換為 `(network_address, mask)` 組合。比對時將 IP 與 mask 進行 AND 位元運算，再與 network_address 比較。例如 `168.95.0.0/16` → mask `0xFFFF0000`，IP `168.95.1.1 & 0xFFFF0000 = 168.95.0.0` → 匹配。
2. **單一 IP（無遮罩，視為 /32）**：直接存入 `HashSet<u32>` 進行 O(1) 查詢。

比對流程（對每筆 flow record）：
1. 取出該筆 record 的 src IP 與 dst IP
2. 用 **src IP** 查詢 `src_only` 組與 `any` 組
3. 用 **dst IP** 查詢 `dst_only` 組與 `any` 組
4. 以上任一命中即納入輸出
5. 每組內部先查 HashSet（精確匹配，O(1)），未命中再逐一比對 CIDR 清單

#### 設定檔動態重新載入

- **觸發方式**: 接收 `SIGHUP` 信號（`kill -HUP <pid>`）
- 收到信號後重新讀取並解析 TOML 設定檔
- 重新依 direction 分類建立三組 HashSet 與 CIDR 範圍清單（src_only / dst_only / any）
- 重新建立常用 Port 的 `HashSet<u16>`（根據 `[highlighted_ports]` 設定）
- 重新套用 `[live]` 區段設定（若 `lines` 變更則重建環形緩衝區）
- 使用 `Arc<ArcSwap<FilterConfig>>` 或類似機制實現無鎖讀取、原子替換，確保接收迴圈不被阻塞
- 載入成功或失敗均透過 tracing 輸出日誌至 stderr
- 載入失敗時保留舊設定繼續運作，不中斷服務

### 4. 封包解析失敗處理

- 解析失敗的封包不輸出至 stdout
- 維護錯誤計數器（`AtomicU64`）
- 定期（例如每 60 秒）透過 tracing 將統計摘要輸出至 stderr，包含：已接收封包總數、解析失敗數、過濾命中數、資料庫寫入成功數、資料庫寫入失敗數
- 若區間內無錯誤則不產生報告（避免雜訊）

### 5. 日誌策略

所有操作層級的訊息使用 `tracing` 輸出至 **stderr**，與 `--direct-print` 的 stdout 資料流完全分離。

日誌涵蓋事件：
- 應用程式啟動（綁定位址、載入設定檔路徑）
- 設定檔載入成功 / 失敗
- SIGHUP 信號接收
- 定期統計摘要
- 資料庫連線建立 / 失敗
- 資料庫批次寫入失敗（含丟棄筆數）
- Migration 執行結果
- 非預期錯誤

### 6. 資料庫寫入（PostgreSQL + TimescaleDB）

使用 `--db-store` 旗標啟用。可與 `--direct-print` 同時運行，兩者獨立運作。寫入的資料同樣套用 IP 過濾，僅命中的 flow 會被寫入。

#### 連線設定（TOML）

在設定檔中新增 `[database]` 區段：

```toml
[database]
host = "127.0.0.1"
port = 5432
user = "netflow"
password = "secret"
dbname = "netflow_db"
```

#### 寫入欄位

每筆寫入的 flow record 包含以下 8 個欄位：

| 欄位             | 型別                  | 說明                                      |
|------------------|-----------------------|-------------------------------------------|
| `received_at`    | `TIMESTAMPTZ`         | Collector 接收到封包的時間戳（hypertable 分區鍵）|
| `src_addr`       | `INET`                | 來源 IP                                   |
| `src_port`       | `INTEGER`             | 來源 Port                                 |
| `dst_addr`       | `INET`                | 目標 IP                                   |
| `dst_port`       | `INTEGER`             | 目標 Port                                 |
| `protocol`       | `SMALLINT`            | 協定號（6=TCP, 17=UDP, 1=ICMP 等）        |
| `packets`        | `BIGINT`              | 封包數                                    |
| `bytes`          | `BIGINT`              | 位元組數                                  |

`received_at` 為 Collector 收到 UDP 封包時的本機時間（`chrono::Utc::now()` 或 `std::time::SystemTime`），而非 NetFlow exporter header 中的時間戳。此欄位作為 TimescaleDB hypertable 的分區依據。

#### Table Schema

透過 `--migrate` 指令建立。執行後自動建立 table 並啟用 TimescaleDB hypertable：

```sql
CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE IF NOT EXISTS netflow_records (
    received_at  TIMESTAMPTZ  NOT NULL,
    src_addr     INET         NOT NULL,
    src_port     INTEGER      NOT NULL,
    dst_addr     INET         NOT NULL,
    dst_port     INTEGER      NOT NULL,
    protocol     SMALLINT     NOT NULL,
    packets      BIGINT       NOT NULL,
    bytes        BIGINT       NOT NULL
);

SELECT create_hypertable('netflow_records', 'received_at',
    if_not_exists => TRUE
);
```

`--migrate` 為獨立執行模式，執行完成後程式即結束，不進入監聽狀態。需要設定檔中的 `[database]` 區段提供連線資訊。

#### 批次寫入策略

使用固定參數的批次寫入，降低資料庫壓力：

- **批次上限**: 1000 筆
- **時間間隔**: 5 秒
- 任一條件先達到即觸發寫入（以先到者為準）
- 實作方式：獨立的 Tokio task 持有一個 buffer（`Vec`），透過 `tokio::sync::mpsc` channel 接收過濾後的 flow record，搭配 `tokio::time::interval` 計時
- 寫入使用 PostgreSQL 的 `COPY` 協定或拼接多筆 `INSERT ... VALUES` 以提升效能

#### 錯誤處理

- 資料庫連線失敗或寫入失敗時，透過 tracing 記錄錯誤日誌至 stderr
- 丟棄該批次資料，不進行重試
- 寫入失敗不影響 UDP 封包接收與 `--direct-print` 的運作
- 統計報告中新增資料庫寫入成功數與失敗數

## CLI 介面設計

```
netflow-collector [OPTIONS]

OPTIONS:
    --bind <ADDR:PORT>       UDP 監聽位址與 Port（必要，例如 0.0.0.0:2055）
    --config <PATH>          設定檔路徑（TOML 格式，必要）
    --direct-print           啟用逐行追加輸出模式，適合 pipe 或日誌記錄
    --live                   啟用即時監控模式（固定區域刷新 + NPS 狀態列 + 最新 10 筆）
    --color                  啟用色彩標記輸出（適用於 --direct-print 與 --live）
    --db-store               啟用資料庫寫入模式，將過濾後的 flow 寫入 PostgreSQL
    --recv-buffer <BYTES>    UDP Socket 接收緩衝區大小（可選，未指定則使用系統預設值）
    --migrate                執行資料庫 migration（建立 table 與 hypertable），完成後結束
    --help                   顯示使用說明
    --version                顯示版本資訊
```

使用範例：

```bash
# 逐行追加輸出（適合 pipe 或導向檔案）
netflow-collector --bind 0.0.0.0:2055 --config filter.toml --direct-print

# 逐行追加 + 色彩標記
netflow-collector --bind 0.0.0.0:2055 --config filter.toml --direct-print --color

# 即時監控模式（固定刷新 + NPS）
netflow-collector --bind 0.0.0.0:2055 --config filter.toml --live

# 即時監控 + 色彩標記
netflow-collector --bind 0.0.0.0:2055 --config filter.toml --live --color

# 僅資料庫寫入（不輸出至 stdout）
netflow-collector --bind 0.0.0.0:2055 --config filter.toml --db-store

# 即時監控 + 資料庫寫入同時運行
netflow-collector --bind 0.0.0.0:2055 --config filter.toml --live --color --db-store

# 逐行追加 + 資料庫寫入同時運行
netflow-collector --bind 0.0.0.0:2055 --config filter.toml --direct-print --color --db-store

# 指定較大的接收緩衝區
netflow-collector --bind 0.0.0.0:2055 --config filter.toml --live --color --db-store --recv-buffer 8388608

# 執行資料庫 migration（建立 table 與 hypertable 後結束）
netflow-collector --config filter.toml --migrate

# 動態重新載入設定（IP 過濾 + 常用 Port 清單皆重新載入）
kill -HUP $(pidof netflow-collector)
```

## 專案結構建議

```
src/
├── main.rs            # 進入點、CLI 解析、Tokio runtime 啟動
├── server.rs          # UDP socket 監聽與封包接收迴圈
├── parser.rs          # NetFlow v5 封包解析（封裝 netflow_parser）
├── filter.rs          # IP 過濾邏輯（三組 HashSet + CIDR 依 direction 分類、設定檔載入）
├── config.rs          # TOML 設定檔結構定義與反序列化
├── printer.rs         # --direct-print 逐行追加格式化輸出與色彩標記
├── live.rs            # --live 即時監控模式（固定區域刷新、NPS、ring buffer）
├── db.rs              # PostgreSQL 連線管理、批次寫入、migration
└── stats.rs           # 統計計數器與定期報告
```

## 預期依賴 (Cargo.toml)

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
netflow_parser = "*"          # 確認最新穩定版本
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
toml = "0.8"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
arc-swap = "1"                # 無鎖原子替換 FilterConfig
tokio-postgres = "0.7"        # async PostgreSQL client
chrono = { version = "0.4", features = ["serde"] }  # 時間戳處理
```

## 尚未實作（後續階段）

以下功能已在規劃中但不在當前階段實作：

- **Raw Data 儲存**: 將接收到的原始 NetFlow 封包寫入檔案系統
- **IPv6 支援**: 目前僅處理 IPv4，未來若需擴充 v9/IPFIX 時一併考慮
- **其他 NetFlow 版本**: v9、IPFIX 支援

## 編碼注意事項

- 所有 async 操作使用 Tokio runtime，不使用 `block_on` 在 async context 中
- IP 位址在內部以 `u32` 表示進行位元運算，避免不必要的字串轉換
- 過濾設定使用 `Arc<ArcSwap<>>` 共享，讀取路徑無鎖
- SIGHUP handler 以獨立 Tokio task 運行，透過 `tokio::signal::unix::signal(SignalKind::hangup())` 監聽
- 統計報告以獨立 Tokio task 運行，使用 `tokio::time::interval` 定期觸發
- 主接收迴圈應為 `loop { socket.recv_from().await }` 形式，不產生額外 task per packet
- 輸出格式使用 `format!` 搭配固定寬度對齊，不依賴外部 table 套件
- 色彩輸出使用原生 ANSI escape sequence，不依賴外部 colored crate
- `--live` 模式使用 `VecDeque<FlowRecord>` 作為環形緩衝區，容量由設定檔 `[live].lines` 決定（預設 10）
- `--live` 的 NPS 計算使用 `AtomicU64` 計數器，每秒讀取後歸零
- `--live` 與 `--direct-print` 在 clap 層級設定為互斥（`conflicts_with`）
- `--live` 的畫面刷新使用 `tokio::select!` 同時監聽 flow 資料進入與 1 秒 interval timer
- 資料庫寫入以獨立 Tokio task 運行，透過 `tokio::sync::mpsc` channel 接收資料，與主接收迴圈解耦
- 批次寫入 task 使用 `tokio::select!` 同時監聽 channel 與 interval timer，任一觸發條件達成即 flush
- `--migrate` 模式下僅建立 DB 連線、執行 SQL、結束程式，不啟動 UDP 監聽
- `--db-store` 需要設定檔中存在 `[database]` 區段，否則啟動時報錯退出
- IP 位址寫入資料庫時轉換為 `std::net::IpAddr`，由 tokio-postgres 自動對應 PostgreSQL `INET` 型別
