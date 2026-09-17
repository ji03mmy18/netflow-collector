-- ============================================================
-- NetFlow v5 流量統計 Schema (PostgreSQL + TimescaleDB)
--
-- 環境：Cisco Catalyst 9600 (IOS-XE FNF, export-protocol netflow-v5)
--       單一 exporter；active/inactive timeout 皆為 1 秒
-- 原則：以設備輸出數值為準，不做 L2 補正
--
-- 統計由 collector 在記憶體聚合後寫入，不使用觸發器。
-- 兩張統計表都以「累加」語意接收增量，因此重複寫入與遲到記錄
-- 都能自然吸收；正確性由 recompute（見 db.rs）定期校正。
--
-- 本檔由 `netflow-collector --migrate` 以 include_str! 嵌入執行，
-- 全部語句必須是冪等的。
-- ============================================================

CREATE EXTENSION IF NOT EXISTS timescaledb;

-- ------------------------------------------------------------
-- 紀錄表（不是設定表）。
--
-- ⚠ 內網網段設定在 filter.toml 的 [netflow].intra_cidr，不在這裡。
--    這張表只保存「collector 上次實際使用的值」，用來在設定被改動時
--    發出警告——因為統計表本身沒有任何欄位記錄它是用哪個網段算出來的，
--    改了設定會讓 intra_*/ext_* 的語意從那一刻起悄悄改變。
--    改這裡的值不會有任何效果，下次啟動就會被覆寫。
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS app_config (
  key   text PRIMARY KEY,
  value text NOT NULL
);

COMMENT ON TABLE app_config IS
  'collector 寫入的執行紀錄，非設定來源；設定一律在 filter.toml';

-- 監控清單不在資料庫裡：它是設定，放在 filter.toml 的 [monitored]。
-- 統計表直接存 inet，沒有代理鍵、沒有維度表、沒有外鍵（理由見 CLAUDE.md）。

-- ============================================================
-- 表 1：原始資料（不做任何計算，保留 28 天）
--
-- ts 由封包換算（見 parser.rs），非 collector 收包時間。
-- collector 收包時間只用於監控 exporter 時鐘偏差，記錄在
-- collector_health_1m，不逐列儲存。
-- ============================================================
CREATE TABLE IF NOT EXISTS flow_raw (
  ts        timestamptz NOT NULL,   -- flow 結束時間（bucket 依據）
  srcaddr   inet     NOT NULL,
  dstaddr   inet     NOT NULL,
  srcport   integer  NOT NULL,      -- v5 為 uint16，用 integer 避免溢位
  dstport   integer  NOT NULL,
  prot      smallint NOT NULL,
  d_pkts    bigint   NOT NULL,
  d_octets  bigint   NOT NULL,
  tcp_flags smallint NOT NULL,      -- 1 秒 timeout 下等於逐秒 flag 快照
  input     integer  NOT NULL,      -- ifIndex，uint16
  output    integer  NOT NULL,
  tos       smallint NOT NULL,
  sampling_interval integer NOT NULL DEFAULT 1
);

SELECT create_hypertable('flow_raw', 'ts',
  chunk_time_interval => INTERVAL '1 hour', if_not_exists => TRUE);

ALTER TABLE flow_raw SET (
  timescaledb.compress,
  timescaledb.compress_segmentby = 'prot',
  timescaledb.compress_orderby   = 'srcaddr, ts'
);

SELECT add_compression_policy('flow_raw', INTERVAL '3 days', if_not_exists => TRUE);
SELECT add_retention_policy  ('flow_raw', INTERVAL '28 days', if_not_exists => TRUE);

COMMENT ON COLUMN flow_raw.d_octets IS
  'v5 dOctets，等同 FNF bytes long（L2 大小 - 18 bytes）。依設計決定不補正';

-- ============================================================
-- 表 2：5 分鐘統計
--
-- ⚠ intra_* 有兩個已知的語意限制，使用前務必理解：
--   1. 母體只有「經過核心交換器的內部流量」。在邊緣交換器就被 L3
--      轉發掉的部分完全不在其中，所以它是結構性不完整的量測。
--   2. 若一筆內部流量的兩端都在監控清單中，同一份流量會同時計入
--      A 的 intra_tx 與 B 的 intra_rx。SUM(intra_tx)+SUM(intra_rx)
--      不等於實際內網流量。
-- 對外用量請一律使用 ext_tx_bytes / ext_rx_bytes。
-- ============================================================
CREATE TABLE IF NOT EXISTS flow_stat_5m (
  bucket timestamptz NOT NULL,
  addr   inet        NOT NULL,

  intra_rx_bytes bigint NOT NULL DEFAULT 0,   -- 內網 → 本機
  intra_tx_bytes bigint NOT NULL DEFAULT 0,   -- 本機 → 內網
  ext_rx_bytes   bigint NOT NULL DEFAULT 0,   -- 外網 → 本機
  ext_tx_bytes   bigint NOT NULL DEFAULT 0,   -- 本機 → 外網

  PRIMARY KEY (bucket, addr)   -- hypertable 的唯一索引必須含時間欄位
);

SELECT create_hypertable('flow_stat_5m', 'bucket',
  chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE);

-- PK 的欄位順序不適合「單一 IP 查時間區間」，另外開一個
CREATE INDEX IF NOT EXISTS idx_5m_ip_time ON flow_stat_5m (addr, bucket DESC);

-- 必須長於 flow_raw，否則刪掉之後就無法重算
SELECT add_retention_policy('flow_stat_5m', INTERVAL '13 months', if_not_exists => TRUE);

-- 13 個月約 4 億列（實測 74 MB / 100 萬列），壓縮省下的量很可觀。
-- 延遲 7 天才壓，確保寫入窗口（含遲到記錄與人工重算）早已結束——
-- 壓縮過的 chunk 不適合再被 UPSERT。
ALTER TABLE flow_stat_5m SET (
  timescaledb.compress,
  timescaledb.compress_segmentby = 'addr',
  timescaledb.compress_orderby   = 'bucket'
);
SELECT add_compression_policy('flow_stat_5m', INTERVAL '7 days', if_not_exists => TRUE);

-- ============================================================
-- 表 3：1 天統計
--
-- 由 collector 在寫 5m 的同時以相同增量累加，所以查詢「今日累積
-- 用量」是單列讀取，成本與「今天過了多久」無關。
--
-- 每日的 recompute 會從 5m 重新彙總覆蓋，把白天累加過程中任何
-- 掉漏的部分校正回來——同時也是一道對帳訊號。
--
-- 一年約 128 萬列，不需要做成 hypertable，普通表即可；
-- 也刻意不設 retention，長期保留。
-- ============================================================
CREATE TABLE IF NOT EXISTS flow_stat_1d (
  day    date NOT NULL,            -- Asia/Taipei 日界線
  addr   inet NOT NULL,

  intra_rx_bytes bigint NOT NULL DEFAULT 0,
  intra_tx_bytes bigint NOT NULL DEFAULT 0,
  ext_rx_bytes   bigint NOT NULL DEFAULT 0,
  ext_tx_bytes   bigint NOT NULL DEFAULT 0,

  PRIMARY KEY (day, addr)
);

CREATE INDEX IF NOT EXISTS idx_1d_ip_day ON flow_stat_1d (addr, day DESC);

-- ============================================================
-- 表 4：collector 健康度（每個 flush 窗口一列）
--
-- 存在的理由：回答「這個時段的用量數字可信度多高」。
-- 沒有這張表的話，UDP 掉包與 exporter 時鐘偏差都是無聲失效——
-- 統計數字會安靜地偏低或落到錯誤的桶，報表上完全看不出來。
--
-- 每天約 1440 列，永久保存。
-- ============================================================
CREATE TABLE IF NOT EXISTS collector_health_1m (
  bucket           timestamptz PRIMARY KEY,
  packets_received bigint NOT NULL DEFAULT 0,  -- 收到的 UDP 封包數
  flows_parsed     bigint NOT NULL DEFAULT 0,
  parse_failures   bigint NOT NULL DEFAULT 0,
  seq_gap          bigint NOT NULL DEFAULT 0,  -- 依 flow_sequence 推算的遺失筆數
  flows_matched    bigint NOT NULL DEFAULT 0,  -- 命中監控清單
  rows_written     bigint NOT NULL DEFAULT 0,
  db_failures      bigint NOT NULL DEFAULT 0,
  -- exporter 時鐘看門狗：received_at - ts，1s/1s timeout 下應為 0~2 秒的窄帶
  clock_skew_min_ms  bigint,
  clock_skew_max_ms  bigint,
  clock_skew_last_ms bigint,
  clock_skew_rejects bigint NOT NULL DEFAULT 0  -- 超過閾值、改用收包時間的筆數
);

COMMENT ON COLUMN collector_health_1m.clock_skew_max_ms IS
  '突然從數百毫秒跳到數千萬毫秒，代表 exporter 的 NTP 壞了';
