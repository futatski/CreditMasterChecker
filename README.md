# Apacheログのみ クレマス攻撃検出スクリプト

## 概要

EC-CUBE4のApacheアクセスログのみを監視して、クレマス攻撃を検出するシンプルなPythonスクリプトです。EC-CUBE4自体には一切手を加えず、ログファイルの読み取りのみで攻撃を検出し、メールで通知します。

## 特徴

- **EC-CUBE4非侵入**: EC-CUBE4自体には一切変更を加えない
- **Apacheログのみ**: ログファイルの読み取りのみで完結
- **軽量**: 最小限のリソース使用
- **シンプル**: 設定が簡単で運用しやすい

## 機能

- **ログ監視**: Apacheアクセスログの読み込み・解析
- **攻撃検出**: クレマス攻撃の基本的なパターンを検出
- **メール通知**: 攻撃検出時にメールでアラート送信
- **ログ出力**: 検出結果をログファイルに記録

## 検出対象

### 1. 大量リクエスト検出
- 短時間での大量のリクエスト送信
- 設定可能な閾値と時間窓

### 2. 決済関連攻撃検出
- 決済ページへの集中アクセス
- ベリトランス決済関連URLへの攻撃

### 3. 認証失敗検出
- 401/403エラーの頻発
- ログイン試行の連続失敗

### 4. 怪しいUser-Agent検出
- 自動化ツールの使用
- ボットによる攻撃

## 必要な環境

- Python 3.7以上
- Linux（Ubuntu、CentOS等）
- Apache（ログファイルへの読み取り権限）
- メール送信機能（SMTP）

## インストール

```bash
# リポジトリのクローン
git clone <repository-url>
cd clemens-detector

# 依存関係インストール
pip install -r requirements.txt

# 設定ファイル編集
cp config.yaml.example config.yaml
# config.yamlを編集して必要な設定を行う
```

## 設定

`config.yaml`ファイルで以下の設定を行います：

```yaml
# ログファイル設定
log_file:
  path: "/var/log/apache2/access.log"
  format: "apache"

# 検出ルール設定
detection:
  rapid_requests:
    enabled: true
    threshold: 100  # 60秒間に100回以上のリクエスト
    time_window: 60
    
  payment_urls:
    enabled: true
    target_urls:
      - "/shopping/payment.php"
      - "/shopping/veritrans/"
    threshold: 50  # 60秒間に50回以上のアクセス
    time_window: 60
    
  auth_failures:
    enabled: true
    status_codes: [401, 403]
    threshold: 10  # 5分間に10回以上の認証失敗
    time_window: 300

# 通知設定
notifications:
  email:
    enabled: true
    smtp_server: "smtp.gmail.com"
    smtp_port: 587
    username: "your-email@gmail.com"
    password: "your-app-password"
    recipients: ["admin@example.com"]
```

## 実行

```bash
# 直接実行
python3 apache_log_detector.py

# バックグラウンド実行
nohup python3 apache_log_detector.py > /dev/null 2>&1 &

# systemdサービスとして実行
sudo systemctl start clemens-detector
```

## 検出パターン詳細

### 1. 大量リクエスト検出
- **対象**: 全てのリクエスト
- **閾値**: 60秒間に100回以上（設定可能）
- **重要度**: HIGH

### 2. 決済関連攻撃検出
- **対象URL**: 
  - `/shopping/payment.php`
  - `/shopping/confirm.php`
  - `/shopping/veritrans/`
  - `/shopping/veritrans/process.php`
- **閾値**: 60秒間に50回以上（設定可能）
- **重要度**: CRITICAL

### 3. 認証失敗検出
- **対象**: 401/403エラー
- **閾値**: 5分間に10回以上（設定可能）
- **重要度**: HIGH

### 4. 怪しいUser-Agent検出
- **対象**: bot, crawler, curl, wget等
- **閾値**: 5分間に5回以上（設定可能）
- **重要度**: MEDIUM

## ログ出力例

```
2024-12-19 10:30:00 - INFO - クレマス攻撃検出スクリプト開始
2024-12-19 10:30:10 - WARNING - 攻撃検出: {'timestamp': '2024-12-19T10:30:00', 'attack_type': 'payment_attack', 'source_ip': '192.168.1.100', 'count': 45, 'severity': 'CRITICAL'}
2024-12-19 10:30:20 - INFO - メールアラート送信完了: payment_attack
```

## ファイル構成

```
clemens-detector/
├── apache_log_detector.py    # メインスクリプト
├── config.yaml              # 設定ファイル
├── requirements.txt         # 依存関係
├── apache_log_only_requirements.md  # 要件定義書
└── README.md               # 説明書
```

## セキュリティ考慮事項

### ログファイルの取り扱い
- **読み取り権限**: 必要最小限の権限のみ
- **ログローテーション**: 既存のローテーションに影響しない
- **バックアップ**: 既存のバックアップに影響しない

### システムへの影響
- **CPU使用率**: 最小限に抑制
- **メモリ使用量**: 最小限に抑制
- **ディスクI/O**: 既存のI/Oに影響しない

## トラブルシューティング

### よくある問題

1. **ログファイルが見つからない**
   - Apacheログパスが正しいか確認
   - 読み取り権限があるか確認

2. **攻撃が検出されない**
   - 閾値設定が適切か確認
   - 時間窓設定が適切か確認

3. **メール送信が失敗する**
   - SMTP設定が正しいか確認
   - アプリパスワードが正しいか確認

4. **誤検知が多い**
   - 閾値を調整
   - ホワイトリストを設定

## 設定の調整

### 閾値の調整
```yaml
# 厳しい設定（誤検知が多いが、見逃しが少ない）
rapid_requests:
  threshold: 50
  time_window: 60

# 緩い設定（誤検知が少ないが、見逃しが多い）
rapid_requests:
  threshold: 200
  time_window: 60
```

### ホワイトリストの設定
```yaml
whitelist:
  ips:
    - "192.168.1.1"  # 内部ネットワーク
    - "10.0.0.1"     # 管理用IP
  user_agents:
    - "Googlebot"    # 検索エンジンボット
    - "Bingbot"
```

## ライセンス

MIT License

## 貢献

プルリクエストやイシューの報告を歓迎します。

---

**作成日**: 2024年12月
**バージョン**: 1.0
**対象システム**: Apacheログのみ（EC-CUBE4変更なし）