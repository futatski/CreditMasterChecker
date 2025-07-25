# クレマス攻撃検出スクリプト

## 概要

クレマス攻撃（Clemens Attack）を検出するシンプルなPythonスクリプトです。Webサーバーのアクセスログを監視して、攻撃パターンを検出し、メールやSlackで通知します。

## 機能

- **ログ監視**: Apache/Nginxのアクセスログを監視
- **攻撃検出**: 大量リクエスト、認証失敗、セッション異常を検出
- **通知**: メール・Slackでアラート送信
- **ログ出力**: 検出結果をログファイルに記録

## 必要な環境

- Python 3.7以上
- Linux（Ubuntu、CentOS等）
- Apache/Nginxのアクセスログ

## インストール

```bash
# リポジトリのクローン
git clone <repository-url>
cd clemens-detector

# 依存関係インストール
pip install -r requirements.txt

# 設定ファイル作成
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
    
  auth_failures:
    enabled: true
    threshold: 10   # 5分間に10回以上の認証失敗
    time_window: 300

# 通知設定
notifications:
  email:
    enabled: true
    smtp_server: "smtp.gmail.com"
    smtp_port: 587
    username: "your-email@gmail.com"
    password: "your-password"
    recipients: ["admin@example.com"]
```

## 実行

```bash
# 直接実行
python3 main.py

# バックグラウンド実行
nohup python3 main.py > /dev/null 2>&1 &

# systemdサービスとして実行
sudo systemctl start clemens-detector
```

## 検出パターン

### 1. 大量リクエスト
- 短時間での大量のリクエスト送信
- 設定可能な閾値と時間窓

### 2. 認証失敗
- ログイン試行の連続失敗
- 401エラーの頻発

### 3. セッション異常
- セッションIDの異常な使用パターン
- 複数IPからの同一セッション使用

## ログ出力例

```
2024-12-19 10:30:00 - INFO - スクリプト開始
2024-12-19 10:30:10 - WARNING - 攻撃検出: {'timestamp': '2024-12-19T10:30:00', 'attack_type': 'rapid_login_attempts', 'source_ip': '192.168.1.100', 'count': 150}
2024-12-19 10:30:20 - INFO - 通知送信完了
```

## ファイル構成

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

## トラブルシューティング

### よくある問題

1. **ログファイルが見つからない**
   - パスが正しいか確認
   - 読み取り権限があるか確認

2. **メール送信が失敗する**
   - SMTP設定が正しいか確認
   - ファイアウォールの設定確認

3. **権限エラー**
   - スクリプトに実行権限があるか確認
   - ログファイルへのアクセス権限確認

## ライセンス

MIT License

## 貢献

プルリクエストやイシューの報告を歓迎します。

---

**作成日**: 2024年12月
**バージョン**: 1.0