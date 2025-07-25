# EC-CUBE4 + ベリトランス決済 検出ルール詳細仕様書

## 1. 検出対象URLパターン

### 1.1 決済関連URL
```
# 決済フロー
/shopping/payment.php          # 決済方法選択ページ
/shopping/confirm.php          # 注文確認ページ
/shopping/complete.php         # 決済完了ページ
/shopping/veritrans/           # ベリトランス決済関連
/shopping/veritrans/process.php # ベリトランス決済処理
/shopping/veritrans/result.php # ベリトランス決済結果

# カード情報入力
/shopping/payment_credit.php   # クレジットカード情報入力
/shopping/payment_veritrans.php # ベリトランス決済入力
```

### 1.2 管理画面URL
```
# 管理画面
/admin/                        # 管理画面トップ
/admin/login.php               # 管理画面ログイン
/admin/order/                  # 注文管理
/admin/order/edit.php          # 注文編集
/admin/customer/               # 顧客管理
/admin/product/                # 商品管理
/admin/payment/                # 決済管理
```

### 1.3 会員機能URL
```
# 会員機能
/mypage/                       # マイページ
/mypage/login.php              # 会員ログイン
/mypage/change.php             # 会員情報変更
/entry/                        # 会員登録
/entry/confirm.php             # 会員登録確認
/entry/complete.php            # 会員登録完了
```

### 1.4 商品関連URL
```
# 商品関連
/products/detail.php           # 商品詳細
/products/list.php             # 商品一覧
/products/search.php           # 商品検索
/cart/                         # カート
/cart/add.php                  # カート追加
```

## 2. 検出ルール詳細

### 2.1 決済攻撃検出ルール

#### 2.1.1 決済ページ大量アクセス
```yaml
rule_name: "payment_page_attack"
description: "決済ページへの大量アクセス検出"
target_urls:
  - "/shopping/payment.php"
  - "/shopping/confirm.php"
  - "/shopping/complete.php"
threshold: 50
time_window: 60  # 秒
severity: "HIGH"
```

#### 2.1.2 ベリトランス決済攻撃
```yaml
rule_name: "veritrans_payment_attack"
description: "ベリトランス決済への攻撃検出"
target_urls:
  - "/shopping/veritrans/"
  - "/shopping/veritrans/process.php"
  - "/shopping/veritrans/result.php"
threshold: 30
time_window: 60
severity: "CRITICAL"
```

#### 2.1.3 カード情報入力攻撃
```yaml
rule_name: "credit_card_input_attack"
description: "カード情報入力ページへの攻撃検出"
target_urls:
  - "/shopping/payment_credit.php"
  - "/shopping/payment_veritrans.php"
threshold: 20
time_window: 60
severity: "CRITICAL"
```

### 2.2 管理画面攻撃検出ルール

#### 2.2.1 管理画面不正アクセス
```yaml
rule_name: "admin_unauthorized_access"
description: "管理画面への未認証アクセス検出"
target_urls:
  - "/admin/"
  - "/admin/order/"
  - "/admin/customer/"
  - "/admin/product/"
threshold: 10
time_window: 300
severity: "HIGH"
```

#### 2.2.2 管理画面ログイン攻撃
```yaml
rule_name: "admin_login_attack"
description: "管理画面ログインへの攻撃検出"
target_urls:
  - "/admin/login.php"
threshold: 20
time_window: 300
severity: "HIGH"
```

### 2.3 会員機能攻撃検出ルール

#### 2.3.1 会員ログイン攻撃
```yaml
rule_name: "member_login_attack"
description: "会員ログインへの攻撃検出"
target_urls:
  - "/mypage/login.php"
threshold: 40
time_window: 300
severity: "MEDIUM"
```

#### 2.3.2 会員登録攻撃
```yaml
rule_name: "member_registration_attack"
description: "会員登録への攻撃検出"
target_urls:
  - "/entry/"
  - "/entry/confirm.php"
threshold: 30
time_window: 300
severity: "MEDIUM"
```

### 2.4 商品関連攻撃検出ルール

#### 2.4.1 商品詳細攻撃
```yaml
rule_name: "product_detail_attack"
description: "商品詳細ページへの攻撃検出"
target_urls:
  - "/products/detail.php"
threshold: 100
time_window: 60
severity: "LOW"
```

## 3. ステータスコード別検出

### 3.1 認証失敗検出
```yaml
rule_name: "authentication_failure"
description: "認証失敗の検出"
status_codes:
  - 401  # Unauthorized
  - 403  # Forbidden
target_urls:
  - "/admin/login.php"
  - "/mypage/login.php"
threshold: 10
time_window: 300
severity: "HIGH"
```

### 3.2 決済エラー検出
```yaml
rule_name: "payment_error"
description: "決済エラーの検出"
status_codes:
  - 400  # Bad Request
  - 500  # Internal Server Error
target_urls:
  - "/shopping/veritrans/"
  - "/shopping/payment.php"
threshold: 5
time_window: 60
severity: "HIGH"
```

## 4. 時間帯別検出

### 4.1 深夜時間帯の異常アクセス
```yaml
rule_name: "night_time_attack"
description: "深夜時間帯の異常アクセス検出"
time_range:
  start: "23:00"
  end: "06:00"
target_urls:
  - "/admin/"
  - "/shopping/payment.php"
  - "/mypage/"
threshold: 5
time_window: 3600
severity: "MEDIUM"
```

### 4.2 営業時間外の決済攻撃
```yaml
rule_name: "off_hours_payment_attack"
description: "営業時間外の決済攻撃検出"
time_range:
  start: "22:00"
  end: "08:00"
target_urls:
  - "/shopping/veritrans/"
  - "/shopping/payment.php"
threshold: 10
time_window: 300
severity: "HIGH"
```

## 5. IPアドレス別検出

### 5.1 同一IPからの多様な攻撃
```yaml
rule_name: "multi_target_attack"
description: "同一IPからの多様な攻撃検出"
target_urls:
  - "/admin/"
  - "/shopping/payment.php"
  - "/mypage/login.php"
threshold: 3  # 3種類以上の異なるターゲット
time_window: 600
severity: "HIGH"
```

### 5.2 海外IPからの攻撃
```yaml
rule_name: "foreign_ip_attack"
description: "海外IPからの攻撃検出"
ip_whitelist:
  - "jp"  # 日本以外のIP
target_urls:
  - "/admin/"
  - "/shopping/payment.php"
threshold: 1
time_window: 300
severity: "HIGH"
```

## 6. User-Agent別検出

### 6.1 ボット攻撃検出
```yaml
rule_name: "bot_attack"
description: "ボットによる攻撃検出"
user_agent_patterns:
  - "bot"
  - "crawler"
  - "spider"
  - "scraper"
target_urls:
  - "/shopping/payment.php"
  - "/admin/"
threshold: 1
time_window: 300
severity: "MEDIUM"
```

### 6.2 自動化ツール攻撃検出
```yaml
rule_name: "automation_tool_attack"
description: "自動化ツールによる攻撃検出"
user_agent_patterns:
  - "curl"
  - "wget"
  - "python"
  - "java"
target_urls:
  - "/shopping/veritrans/"
  - "/admin/login.php"
threshold: 1
time_window: 300
severity: "HIGH"
```

## 7. 設定ファイル例

### 7.1 config.yaml
```yaml
# EC-CUBE4 + ベリトランス決済 検出設定
log_file:
  path: "/var/log/apache2/access.log"
  format: "apache"

detection:
  # 決済関連
  payment_page_attack:
    enabled: true
    target_urls:
      - "/shopping/payment.php"
      - "/shopping/confirm.php"
      - "/shopping/complete.php"
    threshold: 50
    time_window: 60
    severity: "HIGH"
    
  veritrans_payment_attack:
    enabled: true
    target_urls:
      - "/shopping/veritrans/"
      - "/shopping/veritrans/process.php"
    threshold: 30
    time_window: 60
    severity: "CRITICAL"
    
  # 管理画面
  admin_unauthorized_access:
    enabled: true
    target_urls:
      - "/admin/"
      - "/admin/order/"
    threshold: 10
    time_window: 300
    severity: "HIGH"
    
  # 会員機能
  member_login_attack:
    enabled: true
    target_urls:
      - "/mypage/login.php"
    threshold: 40
    time_window: 300
    severity: "MEDIUM"

notifications:
  email:
    enabled: true
    smtp_server: "smtp.gmail.com"
    smtp_port: 587
    username: "your-email@gmail.com"
    password: "your-password"
    recipients: ["admin@example.com"]
    
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/..."

logging:
  level: "INFO"
  file: "/var/log/clemens-detector.log"
  max_size: "10MB"
  backup_count: 5
```

## 8. 検出ロジック例

### 8.1 決済攻撃検出
```python
def detect_payment_attack(log_entries, config):
    """
    決済関連の攻撃を検出
    """
    payment_urls = config['detection']['payment_page_attack']['target_urls']
    threshold = config['detection']['payment_page_attack']['threshold']
    time_window = config['detection']['payment_page_attack']['time_window']
    
    ip_counts = {}
    for entry in log_entries:
        if any(url in entry['request_url'] for url in payment_urls):
            ip = entry['source_ip']
            timestamp = entry['timestamp']
            
            if ip not in ip_counts:
                ip_counts[ip] = []
            
            ip_counts[ip].append(timestamp)
    
    # 時間窓内のリクエスト数をカウント
    attacks = []
    for ip, timestamps in ip_counts.items():
        recent_requests = [t for t in timestamps if is_within_window(t, time_window)]
        if len(recent_requests) > threshold:
            attacks.append({
                'ip': ip,
                'count': len(recent_requests),
                'rule': 'payment_page_attack',
                'severity': 'HIGH'
            })
    
    return attacks
```

---

**作成日**: 2024年12月
**バージョン**: 1.0
**対象システム**: EC-CUBE4 + ベリトランス決済