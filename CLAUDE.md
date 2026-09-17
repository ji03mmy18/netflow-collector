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
- **時間處理**: `chrono`（v5 相對時間戳換算、Asia/Taipei 日界線）

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

### 3. IP 過濾機制（顯示用）

> `[[filters]]` 是**唯一一份 IP 清單**：顯示、儲存、統計都用它（見 §6）。
> SIGHUP 可以熱重載，但中途變更會讓進行中的 5 分鐘桶前後半段語意不一致，
> 所以要改統計對象時建議重啟。

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
- 定期（每 60 秒）透過 tracing 將統計摘要輸出至 stderr，包含：已接收封包總數、解析失敗數、`flow_sequence` 推算的遺失筆數、命中數、資料庫寫入成功／失敗數、統計寫入失敗數
- 若區間內無失敗且無遺失則不產生報告（避免雜訊）
- stderr 的摘要是易失的；**永久版本記在 `collector_health_1m`**（見 §6）

### 5. 日誌策略

所有操作層級的訊息使用 `tracing` 輸出至 **stderr**，與 `--direct-print` 的 stdout 資料流完全分離。

日誌涵蓋事件：
- 應用程式啟動（綁定位址、載入設定檔路徑）
- 設定檔載入成功 / 失敗
- SIGHUP 信號接收
- 定期統計摘要
- 資料庫連線建立 / 失敗
- 資料庫批次寫入失敗（含丟棄筆數）
- IP 清單載入（位址數、`intra_cidr`；清單為空或有位址落在 CIDR 外時警告）
- Migration 執行結果
- `--recompute-day` 的 `drift`（非零代表白天的累加掉了東西）
- 非預期錯誤

### 6. 資料庫寫入與流量統計（PostgreSQL + TimescaleDB）

使用 `--db-store` 旗標啟用。可與 `--direct-print` / `--live` 同時運行。

#### 設定放在哪裡

**所有設定都在 `filter.toml`，資料庫只放資料。**

| 項目 | 位置 |
|---|---|
| 內網網段 `intra_cidr` | `[netflow].intra_cidr` |
| **IP 清單（唯一一份）** | `[[filters]]` |

`[[filters]]` 同時決定三件事：顯示什麼、儲存什麼、統計算在誰頭上。`FilterConfig::check()` 回傳的 `MatchResult { src_matched, dst_matched }` 正好就是 tx/rx 分類需要的——來源命中就是該位址的發送量，目標命中就是接收量。**不要為「要儲存哪些位址」另外開一份清單**，那只會讓同一件事有兩個設定入口。

`direction` 因此也適用於統計：`"any"`（預設）兩端任一符合、`"src"` 只計發送、`"dst"` 只計接收。**流量統計請一律用 `"any"`**，理由見下方的 OR 條件說明。

落在 `intra_cidr` 之外的位址**只警告、仍照常記錄**——四類欄位的命名是以「CIDR 內的主機」視角寫的，範圍外的項目標籤會讀起來相反，但不值得為此拒絕收資料。

**`FilterConfig::expand()`** 只給 `--recompute-5m` 用：它要把清單交給 PostgreSQL 做 join，而若用 `<<=` 比對幾千筆單一位址，查詢計劃只能走巢狀迴圈——實測一小時的原始資料要 **76 秒**，展開成位址用等值 join 是 **74 毫秒**。執行期比對仍然走 `check()`，`expand()` 是同一組位址的另一種表示法，不是第二份定義；`filter.rs` 有一個測試逐位址斷言兩者接受的集合完全相同。展開超過 1,048,576 個位址會拒絕（`/8` 等級的前綴幾乎一定是打錯）。

`app_config` **不是設定表**，是 collector 寫入的執行紀錄：啟動時把實際使用的 `intra_cidr` 寫進 `intra_cidr_last_used`，與上次不同就警告。統計表沒有任何欄位記錄它是用哪個網段算出來的，所以這一列是「報表出現無法解釋的階梯」時唯一的線索。改這張表的值不會有任何效果，下次啟動就被覆寫。

`[[filters]]` 的變更則不需要另外記——設定檔進了版控，`git log` 就是完整的變更履歷。

| | 來源 | 用途 |
|---|---|---|
#### ⚠ 過濾條件是 OR，不是 AND

一筆 flow 只要**任一端**在清單中就必須保留（這是 `direction = "any"` 的行為）。清單中的主機傳給 `10.10.9.9`（在 CIDR 內但不在清單中）的流量要算進該主機的 `intra_tx`；把 `direction` 限成 `"src"`/`"dst"`，或寫成「兩端都要命中」，都會讓這類流量整批消失，而且 `ext_*` 欄位看起來完全正常，報表上察覺不到。

#### 四類統計的語意

分類函數是 `f(flow, 監控IP) → 四類之一`，**不是** `f(flow) → 四類之一`。「發送／接收」只相對於某個特定監控 IP 才有意義，所以一筆 flow 會對每個被監控的端點各產生一列，兩端都被監控時就是兩列。

| 條件 | 計入欄位 |
|---|---|
| 監控 IP 是 srcaddr，dstaddr 在 intra_cidr 內 | `intra_tx_bytes` |
| 監控 IP 是 srcaddr，dstaddr 在 intra_cidr 外 | `ext_tx_bytes` |
| 監控 IP 是 dstaddr，srcaddr 在 intra_cidr 內 | `intra_rx_bytes` |
| 監控 IP 是 dstaddr，srcaddr 在 intra_cidr 外 | `ext_rx_bytes` |

**只統計 bytes，不統計封包數**（封包數仍保留在 `flow_raw`）。所有數值乘上 `sampling_interval` 還原。

**`intra_*` 有兩個必須寫進使用文件的限制：**

1. **母體不完整**——只涵蓋「經過核心交換器的內部流量」。在邊緣交換器就被 L3 轉發掉的部分完全看不到，所以它不能與 `ext_*` 並列比較。
2. **必然重複計算**——兩端都在清單中時，同一份流量同時記入 A 的 `intra_tx` 與 B 的 `intra_rx`。`SUM(intra_tx)+SUM(intra_rx)` 不等於實際內網流量。

**對外用量請一律使用 `ext_tx_bytes` / `ext_rx_bytes`**，那才是完整可信的。

#### 統計在 Rust 端計算，不使用資料庫觸發器

在記憶體中以 `(bucket, ip_id)` 聚合，每 60 秒（`[stats].flush_seconds`）把**增量**寫出。

- **為什麼不用觸發器**：1 秒 active timeout 下原始資料約每秒數百至上千筆，觸發器方案等於統計表每秒被觸碰數百個 key；記憶體聚合後是每 5 分鐘最多 3500 列（約每秒 12 列），差 50–100 倍。同時也避開了 TimescaleDB 對 hypertable transition table 的版本相依風險。
- **桶寬與寫出頻率是兩件獨立的事**：桶寬 300 秒固定（`aggregator::BUCKET_SECONDS`，決定曲線解析度）；`flush_seconds` 只影響查詢新鮮度與崩潰暴露面，不增加任何儲存成本——同一列被更新 5 次而非 1 次，且更新的欄位都不在索引中，走 PostgreSQL 的 HOT 路徑。
- **累加語意讓遲到記錄免處理**：兩張統計表都以 `+= EXCLUDED` 接收增量，所以已寫出的桶再來資料就是再加一筆增量。沒有寬限期要調，也沒有「桶已封存」的概念。
- **`flow_stat_1d` 在寫 5m 的同時一併累加**，所以「今日累積用量」是單列讀取，成本與「今天過了多久」無關（從 5m 匯聚的成本與已過去的桶數成正比，午夜前最慢）。
- **崩潰損失的不是資料**：原始資料早已落地（5 秒批次），記憶體裡只有一個可從 raw 重算的統計增量。

#### 重算（修補與對帳）

```bash
# 每日 rollup：從 5m 重建整天的 1d，冪等、可重跑。建議掛 cron。
netflow-collector --config filter.toml --recompute-day            # 預設昨天（Taipei）
netflow-collector --config filter.toml --recompute-day 2026-09-15

# 從 flow_raw 重建 5m（僅 28 天保留期內可行）
netflow-collector --config filter.toml \
  --recompute-5m "2026-09-15T00:00:00Z 2026-09-15T01:00:00Z"
```

兩者都是 DELETE + INSERT（取代語意）包在單一交易中，所以失敗會完整回滾。

**`--recompute-5m` 的 DELETE 限定在目前清單內的位址。** 沒有這個限定的話，對一段舊區間重算時，那些之後才從清單移除的主機會被刪掉歷史卻不再重建——今天的清單說明不了當初監控的是誰。

**`--recompute-day` 同時是對帳機制**：它會比較重建前後的總量並輸出 `drift`。非零代表白天的累加過程掉了東西——這個訊號本來完全看不見。跑完 `--recompute-5m` 之後，受影響的日期需要再跑一次 `--recompute-day`。

#### 時間戳：`ts` 由封包換算

```
ts = (unix_secs, unix_nsecs) − (sys_up_time − last)
       ↑ 絕對錨點（信任交換器 NTP）  ↑ 相對差值（只靠開機計時器，恆準）
```

- **必須用 `wrapping_sub`**：`sys_up_time` / `first` / `last` 是 u32 毫秒，每 2³² ms ≈ **49.71 天回捲一次**。核心交換器連續開機數年，這一年會發生約 7 次。
- **`received_at` 不逐列儲存，改當看門狗**：每筆比對 `received_at − ts`，min/max/last 記入 `collector_health_1m`。1s/1s timeout 下正常是 0～2 秒的窄帶，所以時鐘壞掉會立刻凸顯。超過 `clock_skew_threshold_seconds` 時該筆改用收包時間，讓壞時鐘最多退化成舊行為，而不是把資料寫進數小時外的桶。

#### `collector_health_1m`（每分鐘一列，永久保存）

回答「這個時段的數字可信度多高」。沒有它，UDP 掉包與時鐘偏差都是**無聲失效**。

- `seq_gap` 由 v5 header 的 `flow_sequence` 推算遺失筆數——這是唯一能知道自己在掉資料的方法。收集器會忽略 exporter 重啟與 u32 計數器回捲造成的假跳躍。
- **空窗也一定寫一列**：全零代表「collector 活著但沒收到東西」，而**缺列**代表 collector 本身掛了。兩者意義完全不同，不能被摺疊成同一個空隙。

#### 批次寫入

| | 批次上限 | 時間間隔 | 連線 |
|---|---|---|---|
| `flow_raw` | 1000 筆 | 5 秒 | 獨立連線 |
| 統計 + 健康 | 每 flush 一批 | `flush_seconds`（預設 60 秒） | 獨立連線 |

兩條路各用一條連線，慢的原始寫入不會拖到統計，反之亦然。寫入一律用多值 `INSERT`（`COPY` 對 transition table 的行為不確定，雖然現在沒有觸發器了，多值 INSERT 也已經夠快）。統計 upsert 每 statement 上限 2000 列（PostgreSQL 的 65535 個 bind parameter 限制）。

#### 斷線與重連

Collector 與資料庫同機，所以這條連線唯一的斷法是 PostgreSQL 自己重啟或掛掉。兩個寫入 task 各自持有一條會**自動重建的連線**（`db::Connection`），退避重試 1→2→4…→30 秒，**永不放棄**。

這同時解決了兩個情境：

- **開機競賽**：同機部署代表兩者一起開機，而這是 collector 必輸的競賽——PostgreSQL 要數秒才能接受連線，collector 微秒級就失敗。`After=postgresql.service` **修不了**（它只保證 unit 被啟動，不保證 socket 能接受連線），所以由應用程式自己等。systemd 那邊因此不需要調 `StartLimitBurst`，也不需要 `pg_isready` 的 wrapper。
- **維護重啟**：`Client` 一旦斷線就永久失效。沒有重連的話，行程會活著、收封包、寫不進任何東西，直到有人發現。

#### 停機期間為什麼統計不會掉

**寫入失敗的統計增量不丟棄，而是併回下一批重試**（`db::Carry`）。四個計數器本來就可加，所以「併回去」就是 `+=`，不需要重試佇列。

於是停機期間：

| | 結果 |
|---|---|
| UDP socket | 全程開啟，不漏封包 |
| **統計** | **完整正確**——正確的數字就在記憶體裡，資料庫回來後補寫 |
| `flow_raw` | 破洞。channel 在 production 速率下只能緩衝約 15 秒，之後 `try_send` 丟棄 |

實測（2000 flows/sec，資料庫停 60 秒，共 24 萬筆）：

```
統計 ext_tx 總和 = 240,000,000    ← 100% 完整
flow_raw 列數    = 127,711 / 240,000
健康表 db_failures 總計 = 112,289  ← 與缺口完全吻合
```

這個不對稱是刻意的：統計是這套系統的產品，raw 是「28 天內回答為什麼」的診斷窗口。保住前者比保住後者重要得多——**這也是選擇應用程式內重連、而非讓行程結束交給 systemd 重啟的理由**：重啟會關掉 UDP socket，等於把記憶體裡那份正確的統計丟掉。

記憶體上限：`CARRY_LIMIT` 為 100 萬組不重複 `(bucket, addr)`（約等於 3500 台主機停機一天），超過會警告並停止接收新增量，但保留已累積的部分。

#### 其他錯誤處理

- `flow_raw` 寫入失敗記錄 log、丟棄該批次、不重試；缺口記在 `collector_health_1m.db_failures`。
- 所有送往資料庫的 channel 都用 `try_send`，資料庫卡住永遠不會反壓到 UDP 接收迴圈。
- 不影響 UDP 接收與 `--direct-print` / `--live`。

#### NetFlow v5 的結構性盲點：IPv6

v5 的位址欄位固定 32 bit，**無法承載 IPv6**。雙棧環境下 IPv6 流量從一開始就不在匯出範圍內，不是「數字偏低」。目前學生網段未開放 IPv6，暫不處理；要涵蓋需改用 v9 / IPFIX。

## CLI 介面設計

```
netflow-collector [OPTIONS]

OPTIONS:
    --bind <ADDR:PORT>       UDP 監聽位址與 Port（正常運行必要，例如 0.0.0.0:2055）
    --config <PATH>          設定檔路徑（TOML 格式，所有模式皆必要）
    --direct-print           啟用逐行追加輸出模式，適合 pipe 或日誌記錄
    --live                   啟用即時監控模式（固定區域刷新 + NPS 狀態列）
    --color                  啟用色彩標記輸出（適用於 --direct-print 與 --live）
    --db-store               寫入 PostgreSQL 並維護 5m / 1d 統計
    --recv-buffer <BYTES>    UDP Socket 接收緩衝區大小（可選）

    --migrate                建立資料表、hypertable 與壓縮／保留政策，完成後結束
    --recompute-day [DATE]   從 flow_stat_5m 重建整天的 flow_stat_1d，完成後結束
                             不給值時為昨天（Asia/Taipei）。冪等，適合掛 cron。
    --recompute-5m "FROM TO" 從 flow_raw 重建區間內的 flow_stat_5m，完成後結束
                             兩個 RFC3339 時刻，空白分隔；會向外對齊到桶邊界

    --help                   顯示使用說明
    --version                顯示版本資訊
```

使用範例：

```bash
# 建立 schema（含 hypertable、壓縮政策、保留政策）
netflow-collector --config filter.toml --migrate

# IP 清單與內網網段都在 filter.toml，不需要碰資料庫

# 正式運行：寫入原始資料 + 維護統計
netflow-collector --bind 0.0.0.0:2055 --config filter.toml --db-store

# 即時監控 + 資料庫寫入同時運行
netflow-collector --bind 0.0.0.0:2055 --config filter.toml --live --color --db-store

# 逐行追加輸出（不寫資料庫）
netflow-collector --bind 0.0.0.0:2055 --config filter.toml --direct-print --color

# 每日 rollup（cron：10 分 0 時，Asia/Taipei）
# 10 0 * * *  netflow-collector --config /etc/netflow/filter.toml --recompute-day
netflow-collector --config filter.toml --recompute-day

# 修補：從原始資料重算某小時的 5m，再重算該日的 1d
netflow-collector --config filter.toml \
  --recompute-5m "2026-09-15T02:00:00Z 2026-09-15T03:00:00Z"
netflow-collector --config filter.toml --recompute-day 2026-09-15

# 熱重載 [[filters]]（intra_cidr 不在此列，見下）
kill -HUP $(pidof netflow-collector)
```

**SIGHUP 重載 `[[filters]]`、常用 Port 與 `[live].lines`**。`[netflow].intra_cidr` 在啟動時讀取一次：中途改動會讓進行中的桶前後半段語意不一致，所以要變更請重啟。

## 專案結構建議

```
src/
├── main.rs            # 進入點、CLI 解析、Tokio runtime 啟動
├── server.rs          # UDP socket 監聽與封包接收迴圈
├── parser.rs          # NetFlow v5 封包解析（封裝 netflow_parser）
├── filter.rs          # 唯一的 IP 清單：顯示/儲存/統計共用；expand() 供重算使用
├── config.rs          # TOML 設定檔結構定義與反序列化
├── printer.rs         # --direct-print 逐行追加格式化輸出與色彩標記
├── live.rs            # --live 即時監控模式（固定區域刷新、NPS、ring buffer）
├── aggregator.rs      # 記憶體 5 分鐘桶聚合（分類、bucket_of、Taipei 日界線）
├── db.rs              # 自動重連、migration、原始／統計批次寫入、recompute
└── stats.rs           # 計數器、SequenceTracker（掉包偵測）、HealthAccumulator

sql/
└── schema.sql         # 完整 schema，由 db.rs 以 include_str! 嵌入 --migrate

部署範例（非程式碼）：
netflow-collector.service.example   # systemd unit
netflow-rollup.service.example      # 每日 rollup
netflow-rollup.timer.example        # 00:10 Asia/Taipei 觸發
```

### 資料表

| 資料表 | 型態 | 用途 | 保留期 |
|---|---|---|---|
| `app_config` | 一般表 | collector 的執行紀錄（`intra_cidr_last_used`），**非設定來源** | 永久 |
| `flow_raw` | hypertable（1 小時 chunk） | 原始記錄，13 欄 | 28 天（3 天後壓縮） |
| `flow_stat_5m` | hypertable（1 天 chunk） | 5 分鐘四類 bytes，主鍵 `(bucket, addr)` | 13 個月（7 天後壓縮） |
| `flow_stat_1d` | 一般表 | 每日四類 bytes（Asia/Taipei 日界線），主鍵 `(day, addr)` | 永久 |
| `collector_health_1m` | 一般表 | 每分鐘可信度指標 | 永久 |

**統計表直接存 `inet`，沒有代理鍵、沒有維度表、沒有外鍵。** 早期版本用 `smallint ip_id` 參照一張 `monitored_ip` 表，實測那個代理鍵在 `flow_stat_5m` 省不到任何空間（`smallint` 省下的 6 bytes 被 `bigint` 的對齊填補原地吃掉，兩者都是 72 bytes/列、100 萬列都是表 74 MB + 索引 61 MB），卻換來 32767 的 id 上限、擋住清單重建的外鍵、以及每次查詢都要 JOIN。日表有 8 bytes/列的差距，但一年僅約 10 MB。

`flow_stat_5m` 的壓縮延遲到 **7 天**，確保寫入窗口（含遲到記錄與人工重算）早已結束——壓縮過的 chunk 不適合再被 UPSERT。

### `flow_raw` 欄位

`ts`（封包換算的 flow 結束時間）、`srcaddr`、`dstaddr`、`srcport`、`dstport`、`prot`、`d_pkts`、`d_octets`、`tcp_flags`、`input`、`output`、`tos`、`sampling_interval`。

刻意**不存**的欄位與理由：

| 欄位 | 理由 |
|---|---|
| `ts_start` | 1 秒 timeout 下恆等於 `ts` 減不到 1 秒，資訊量趨近於零 |
| `flow_sequence` | per-packet 值，逐列存浪費；改記入 `collector_health_1m.seq_gap` |
| `received_at` | 同上，改當時鐘看門狗記入健康表 |
| `next_hop` / `src_as` / `dst_as` / `src_mask` / `dst_mask` | FNF 以 v5 匯出時多為 0；上線前請實測零值比例再決定 |
| `src_ip_id` / `dst_ip_id` | 原設計是為了讓 DB 觸發器免 JOIN；已改為 Rust 端計算統計，不再需要 |

`tcp_flags` 在 1 秒 timeout 下等於**逐秒的 flag 快照**（而非長連線把所有 flag OR 成 `0x1f`），所以能分辨只有 SYN（掃描／連不上）、RST（被拒）、FIN（正常收尾）——這是 raw 從「流量帳本」變成「可做行為判斷的資料」的關鍵 1 個位元組。

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
- **IPv6 支援**: v5 的位址欄位固定 32 bit，結構上無法承載 IPv6；要涵蓋必須改用 v9 / IPFIX（需處理 template 狀態）。目前學生網段未開放 IPv6
- **其他 NetFlow 版本**: v9、IPFIX 支援
- **位址標籤**: 統計表只有 `inet`，沒有「實驗室 A」這類人類可讀標籤。判斷是這個標籤屬於資產盤點系統而非流量收集器；真要在 SQL 層用的話，加一張獨立的 `addr → note` 對照表即可——沒有任何東西會參照它，可隨意重建
- **`next_hop` / AS / mask 欄位**: 先實測 FNF 以 v5 匯出時的零值比例，非零才值得加回 `flow_raw`
- **對真實 Cisco 9600 封包的驗證**: 所有測試用的都是合成封包。上線後需確認 `first`/`last`、`tcp_flags`、`input`/`output` 在 v5 匯出模式下確實有填（`ts` 若不可信，60 秒看門狗會安全降級為收包時間）

## 實測環境數據與設備端待確認事項

> 以下來自原始設計文件（`refs/`，已刪除）。schema 部分已全部被本文取代，
> 但這些是關於**設備與實測環境**的事實，不隨 schema 改版而失效。

### 實測容量（2 個月累積，舊版單表結構）

| 指標 | 數值 |
|---|---|
| 原始大小 | 約 445 GB |
| TimescaleDB 壓縮後 | 約 153 GB |
| 壓縮比 | 約 2.9×（**偏低**，一般 flow 資料可達 8–15×） |
| 推估每日原始量 | 約 7.4 GB |
| 28 天保留期推估 | 原始約 208 GB / 壓縮後約 72–86 GB |

本文所有容量與吞吐推算都以此為基礎（每日 7.4 GB ≈ 每秒數百至上千筆）。

### 壓縮比偏低（尚未解決）

三個待驗證的假設，其中兩個已在現行 schema 處理：

1. **未設 `segmentby`** — 已改為 `segmentby = 'prot'`（值域小，適合）。`srcaddr` cardinality 太高，不可用作 segmentby。
2. **`orderby 'srcaddr, ts'` 的副作用** — 按 srcaddr 排序讓位址壓得好，但 `ts` 在群組內變得不連續，delta-of-delta 編碼效果打折。**值得 A/B 測試 `orderby 'ts'` 單欄版本。**
3. **`ts_start` 是純浪費** — 已在現行 schema 移除。

**另一個待釐清**：445 GB 這個數字是只算 table 還是含索引？壓縮後的 chunk 會丟掉原本索引——這是壓縮比被低估的常見原因。

診斷 SQL：

```sql
-- 各 chunk 壓縮前後實際大小
SELECT chunk_name,
       pg_size_pretty(before_compression_total_bytes) AS before,
       pg_size_pretty(after_compression_total_bytes)  AS after,
       round(before_compression_total_bytes::numeric
             / NULLIF(after_compression_total_bytes, 0), 2) AS ratio
FROM chunk_compression_stats('flow_raw')
WHERE after_compression_total_bytes IS NOT NULL
ORDER BY chunk_name DESC LIMIT 20;

-- 欄位零值比例（決定 next_hop / AS / mask 值不值得存）
SELECT count(*) FILTER (WHERE tcp_flags = 0) AS flags_zero,
       count(*) FILTER (WHERE input = 0)     AS input_zero,
       count(*) FILTER (WHERE tos = 0)       AS tos_zero,
       count(*) AS total
FROM flow_raw WHERE ts >= now() - INTERVAL '1 hour';
```

改 `segmentby` / `orderby` 需先 decompress 既有 chunk。**建議拿一兩個舊 chunk 做 A/B，別整批重壓。**

### 上線前的設備端確認

```
show flow monitor <name>              # active/inactive timeout 實際生效值
show flow exporter <name>             # 確認 export-protocol 是 netflow-v5
show sampler                          # 是否有採樣、rate 多少
show version / show module            # SUP-1 還是 C9600X-SUP-2
show flow monitor <name> statistics   # flows added/aged、export 失敗計數
```

**⚠ 若為 C9600X-SUP-2，前提完全不同**：FNF 只能設在 ingress、**只能搭配 sampler 使用**、全機同時只能有一種 sampler rate、NetFlow 為純軟體實作。此時所有統計值皆為推估，`[netflow].sampling_interval` 的還原從選配變成**必要**，不能留在 1。

**⚠ 硬體 NetFlow 使用 hash table**，即使有溢位 CAM，實際使用率約到 80% 就開始碰撞。加上 active timeout 1 秒使 cache 高速翻動——`show flow monitor <name> statistics` 是統計值失真的**唯一線索，資料庫端完全看不出來**（`collector_health_1m` 只看得到收集器這一側的遺失，看不到設備端沒送出來的部分）。

## 編碼注意事項

- 所有 async 操作使用 Tokio runtime，不使用 `block_on` 在 async context 中
- IP 位址在內部以 `u32` 表示進行位元運算，避免不必要的字串轉換
- 過濾設定使用 `Arc<ArcSwap<>>` 共享，讀取路徑無鎖
- SIGHUP handler 以獨立 Tokio task 運行，透過 `tokio::signal::unix::signal(SignalKind::hangup())` 監聽
- 統計報告以獨立 Tokio task 運行，使用 `tokio::time::interval` 定期觸發
- 主接收迴圈是 `tokio::select!` 同時等待 `socket.recv()` 與 flush timer，不產生額外 task per packet。flush 分支只把已建好的批次丟進 channel，不做資料庫往返
- 輸出格式使用 `format!` 搭配固定寬度對齊，不依賴外部 table 套件
- 色彩輸出使用原生 ANSI escape sequence，不依賴外部 colored crate
- `--live` 模式使用 `VecDeque<FlowRecord>` 作為環形緩衝區，容量由設定檔 `[live].lines` 決定（預設 10）
- `--live` 的 NPS 計算使用 `AtomicU64` 計數器，每秒讀取後歸零
- `--live` 與 `--direct-print` 在 clap 層級設定為互斥（`conflicts_with`）
- `--live` 的畫面刷新使用 `tokio::select!` 同時監聽 flow 資料進入與 1 秒 interval timer
- 資料庫寫入以獨立 Tokio task 運行，透過 `tokio::sync::mpsc` channel 接收資料，與主接收迴圈解耦
- 原始寫入 task 使用 `tokio::select!` 同時監聽 channel 與 interval timer，任一觸發條件達成即 flush
- 送往資料庫的 channel 一律 `try_send`：資料庫卡住絕不能反壓到 UDP 接收迴圈
- `--migrate` 與兩個 `--recompute-*` 模式僅建立 DB 連線、執行 SQL、結束程式，不啟動 UDP 監聽
- `--db-store` 需要設定檔中存在 `[database]` 區段，否則啟動時報錯退出
- IP 位址寫入資料庫時轉換為 `std::net::IpAddr`，由 tokio-postgres 自動對應 PostgreSQL `INET` 型別
- **`inet` 參數要寫成 `$n::text::inet`**：寫成 `$n::inet` 會讓 tokio-postgres 把該 bind parameter 本身推斷為 `inet`，而 Rust 端送的是 `&str`，執行期直接報型別錯誤
- v5 的 `srcport`/`dstport`/`input`/`output` 皆為 uint16，寫入時用 `i32` 不可用 `i16`；`prot`/`tos`/`tcp_flags` 為 uint8，用 `i16`
- 時間換算**必須用 `wrapping_sub`**：`sys_up_time`/`first`/`last` 是 u32 毫秒，每 49.71 天回捲一次
- 統計 upsert 的多值 `INSERT ... ON CONFLICT` **同一 statement 內不可有重複鍵**，否則 PostgreSQL 報「cannot affect row a second time」。`flow_stat_5m` 由 HashMap drain 而來天然唯一；`flow_stat_1d` 則必須先在 Rust 端依 `(day, ip_id)` 摺疊，因為一次 flush 可能含同一天的多個桶
- Asia/Taipei 自 1979 年起無日光節約時間，所以固定 +8 小時是精確的，也因此沒有任何 5 分鐘桶會跨越日界線
