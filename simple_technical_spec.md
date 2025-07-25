# クレマス攻撃検出スクリプト 簡易技術仕様書

## 1. システム構成

### 1.1 全体構成
```
[ログファイル] → [監視スクリプト] → [検出処理] → [通知]
                                      ↓
                                [ログ出力]
```

### 1.2 コンポーネント
- **ログ監視**: ログファイルの読み込み・解析
- **検出エンジン**: 攻撃パターンの検出
- **通知システム**: メール・Slack通知
- **ログ出力**: 検出結果の記録

## 2. データ構造

### 2.1 ログデータ例
```
192.168.1.100 - - [19/Dec/2024:10:30:00 +0900] "POST /login HTTP/1.1" 401 1234
192.168.1.100 - - [19/Dec/2024:10:30:01 +0900] "POST /login HTTP/1.1" 401 1234
192.168.1.100 - - [19/Dec/2024:10:30:02 +0900] "POST /login HTTP/1.1" 401 1234
```

### 2.2 検出結果データ
```json
{
  "timestamp": "2024-12-19T10:30:00",
  "attack_type": "rapid_login_attempts",
  "source_ip": "192.168.1.100",
  "count": 100,
  "time_window": "60s"
}
```

## 3. 検出アルゴリズム

### 3.1 大量リクエスト検出
```python
def detect_rapid_requests(log_entries, threshold=100, time_window=60):
    """
    短時間での大量リクエスト検出
    """
    ip_counts = {}
    for entry in log_entries:
        ip = entry['source_ip']
        timestamp = entry['timestamp']
        
        if ip not in ip_counts:
            ip_counts[ip] = []
        
        ip_counts[ip].append(timestamp)
    
    # 時間窓内のリクエスト数をカウント
    for ip, timestamps in ip_counts.items():
        recent_requests = [t for t in timestamps if is_within_window(t, time_window)]
        if len(recent_requests) > threshold:
            return True, ip, len(recent_requests)
    
    return False, None, 0
```

### 3.2 認証失敗検出
```python
def detect_auth_failures(log_entries, threshold=10, time_window=300):
    """
    認証失敗の検出
    """
    auth_failures = {}
    for entry in log_entries:
        if entry['status_code'] == 401 and '/login' in entry['request_url']:
            ip = entry['source_ip']
            timestamp = entry['timestamp']
            
            if ip not in auth_failures:
                auth_failures[ip] = []
            
            auth_failures[ip].append(timestamp)
    
    # 時間窓内の認証失敗数をカウント
    for ip, timestamps in auth_failures.items():
        recent_failures = [t for t in timestamps if is_within_window(t, time_window)]
        if len(recent_failures) > threshold:
            return True, ip, len(recent_failures)
    
    return False, None, 0
```

## 4. 設定ファイル

### 4.1 config.yaml
```yaml
# ログファイル設定
log_file:
  path: "/var/log/apache2/access.log"
  format: "apache"

# 検出ルール設定
detection:
  rapid_requests:
    enabled: true
    threshold: 100
    time_window: 60  # 秒
    
  auth_failures:
    enabled: true
    threshold: 10
    time_window: 300  # 秒
    
  session_anomaly:
    enabled: true
    threshold: 5
    time_window: 60  # 秒

# 通知設定
notifications:
  email:
    enabled: true
    smtp_server: "smtp.gmail.com"
    smtp_port: 587
    username: "your-email@gmail.com"
    password: "your-password"
    recipients: ["admin@example.com"]
    
  slack:
    enabled: false
    webhook_url: "https://hooks.slack.com/..."

# ログ設定
logging:
  level: "INFO"
  file: "/var/log/clemens-detector.log"
  max_size: "10MB"
  backup_count: 5
```

## 5. メインスクリプト構造

### 5.1 main.py
```python
#!/usr/bin/env python3
"""
クレマス攻撃検出スクリプト
"""

import yaml
import logging
from datetime import datetime
from log_parser import LogParser
from detector import AttackDetector
from notifier import Notifier

def main():
    # 設定読み込み
    with open('config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
    # ログ設定
    logging.basicConfig(
        level=getattr(logging, config['logging']['level']),
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(config['logging']['file']),
            logging.StreamHandler()
        ]
    )
    
    # コンポーネント初期化
    parser = LogParser(config['log_file'])
    detector = AttackDetector(config['detection'])
    notifier = Notifier(config['notifications'])
    
    # メインループ
    while True:
        try:
            # ログ読み込み
            log_entries = parser.read_logs()
            
            # 攻撃検出
            attacks = detector.detect(log_entries)
            
            # 通知送信
            for attack in attacks:
                notifier.send_alert(attack)
                logging.warning(f"攻撃検出: {attack}")
                
        except Exception as e:
            logging.error(f"エラー: {e}")
        
        # 待機
        time.sleep(10)

if __name__ == "__main__":
    main()
```

## 6. ファイル構成

```
clemens-detector/
├── main.py              # メインスクリプト
├── config.yaml          # 設定ファイル
├── log_parser.py        # ログ解析モジュール
├── detector.py          # 検出エンジン
├── notifier.py          # 通知モジュール
├── utils.py             # ユーティリティ
├── requirements.txt     # 依存関係
└── README.md           # 説明書
```

## 7. 依存関係

### 7.1 requirements.txt
```
PyYAML==6.0
requests==2.31.0
```

### 7.2 標準ライブラリ
- `re`: 正規表現
- `datetime`: 日時処理
- `logging`: ログ出力
- `smtplib`: メール送信
- `json`: JSON処理
- `time`: 時間処理

## 8. 実行方法

### 8.1 インストール
```bash
# 依存関係インストール
pip install -r requirements.txt

# 設定ファイル編集
cp config.yaml.example config.yaml
# config.yamlを編集
```

### 8.2 実行
```bash
# 直接実行
python3 main.py

# バックグラウンド実行
nohup python3 main.py > /dev/null 2>&1 &

# systemdサービスとして実行
sudo systemctl start clemens-detector
```

## 9. ログ出力例

```
2024-12-19 10:30:00 - INFO - スクリプト開始
2024-12-19 10:30:10 - WARNING - 攻撃検出: {'timestamp': '2024-12-19T10:30:00', 'attack_type': 'rapid_login_attempts', 'source_ip': '192.168.1.100', 'count': 150}
2024-12-19 10:30:20 - INFO - 通知送信完了
```

## 10. エラーハンドリング

### 10.1 主要なエラー
- ログファイルが見つからない
- 設定ファイルの形式エラー
- メール送信失敗
- 権限エラー

### 10.2 対処方法
- ログファイルの存在確認
- 設定ファイルの構文チェック
- メール設定の確認
- 実行権限の確認

---

**作成日**: 2024年12月
**バージョン**: 1.0