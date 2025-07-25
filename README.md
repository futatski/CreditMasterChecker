# EC-CUBE4 + ベリトランス決済 クレマス攻撃検出スクリプト

## 概要

EC-CUBE4でベリトランス決済を使用するクレジットカード決済システムに対するクレマス攻撃を検出するPythonスクリプトです。Apacheのアクセスログを監視して、決済関連の攻撃パターンを検出し、メールやSlackで通知します。

## 機能

- **EC-CUBE4特化監視**: EC-CUBE4のApacheアクセスログを監視
- **決済攻撃検出**: ベリトランス決済への不正アクセス検出
- **管理画面保護**: 管理画面への不正アクセス検出
- **会員機能保護**: 会員ログイン・登録への攻撃検出
- **通知**: メール・Slackでアラート送信
- **ログ出力**: 検出結果をログファイルに記録

## 検出対象

### 決済関連の攻撃
- **決済ページ大量アクセス**: `/shopping/payment.php`への集中アクセス
- **ベリトランス決済攻撃**: `/shopping/veritrans/`への不正アクセス
- **カード情報入力攻撃**: クレジットカード情報入力ページへの攻撃

### EC-CUBE4特有の攻撃
- **管理画面不正アクセス**: `/admin/`への未認証アクセス
- **会員ログイン攻撃**: `/mypage/login.php`への大量アクセス
- **会員登録攻撃**: `/entry/`への異常アクセス

## 必要な環境

- Python 3.7以上
- Linux（Ubuntu、CentOS等）
- EC-CUBE4 + Apache
- ベリトランス決済

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

# 決済関連検出ルール
detection:
  payment_page_attack:
    enabled: true
    target_urls:
      - "/shopping/payment.php"
      - "/shopping/confirm.php"
      - "/shopping/complete.php"
    threshold: 50  # 60秒間に50回以上のアクセス
    time_window: 60
    
  veritrans_payment_attack:
    enabled: true
    target_urls:
      - "/shopping/veritrans/"
      - "/shopping/veritrans/process.php"
    threshold: 30  # 60秒間に30回以上のアクセス
    time_window: 60
    
  admin_unauthorized_access:
    enabled: true
    target_urls:
      - "/admin/"
      - "/admin/order/"
    threshold: 10  # 5分間に10回以上のアクセス
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

## 検出パターン詳細

### 1. 決済攻撃検出
- **決済ページ大量アクセス**: 短時間での決済ページへの集中アクセス
- **ベリトランス決済攻撃**: ベリトランス決済処理への不正アクセス
- **カード情報入力攻撃**: クレジットカード情報入力フォームへの攻撃

### 2. 管理画面攻撃検出
- **管理画面不正アクセス**: 未認証での管理画面アクセス
- **管理画面ログイン攻撃**: 管理画面ログインへの大量アクセス

### 3. 会員機能攻撃検出
- **会員ログイン攻撃**: 会員ログインへの大量アクセス
- **会員登録攻撃**: 会員登録への異常アクセス

### 4. 高度な検出
- **認証失敗検出**: 401/403エラーの頻発
- **決済エラー検出**: 決済処理でのエラー頻発
- **時間帯別検出**: 深夜時間帯の異常アクセス
- **海外IP攻撃検出**: 海外IPからの攻撃

## ログ出力例

```
2024-12-19 10:30:00 - INFO - スクリプト開始
2024-12-19 10:30:10 - WARNING - 決済攻撃検出: {'timestamp': '2024-12-19T10:30:00', 'attack_type': 'veritrans_payment_attack', 'source_ip': '192.168.1.100', 'count': 45, 'severity': 'CRITICAL'}
2024-12-19 10:30:20 - WARNING - 管理画面攻撃検出: {'timestamp': '2024-12-19T10:30:15', 'attack_type': 'admin_unauthorized_access', 'source_ip': '192.168.1.101', 'count': 15, 'severity': 'HIGH'}
2024-12-19 10:30:30 - INFO - 通知送信完了
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
├── eccube4_requirements.md      # EC-CUBE4要件定義書
├── eccube4_detection_rules.md   # 検出ルール詳細仕様書
└── README.md           # 説明書
```

## セキュリティ考慮事項

### PCI DSS準拠
- クレジットカード情報の取り扱いに関する配慮
- 決済関連ログの暗号化
- アクセス制御の強化

### EC-CUBE4特有の配慮
- 管理画面の保護
- 会員情報の保護
- 商品情報の保護

## トラブルシューティング

### よくある問題

1. **ログファイルが見つからない**
   - EC-CUBE4のApacheログパスが正しいか確認
   - 読み取り権限があるか確認

2. **決済関連の攻撃が検出されない**
   - ベリトランス決済のURLパターンが正しいか確認
   - 閾値設定が適切か確認

3. **誤検知が多い**
   - 閾値を調整
   - 時間窓を調整
   - ホワイトリストの設定

## ライセンス

MIT License

## 貢献

プルリクエストやイシューの報告を歓迎します。

---

**作成日**: 2024年12月
**バージョン**: 1.0
**対象システム**: EC-CUBE4 + ベリトランス決済