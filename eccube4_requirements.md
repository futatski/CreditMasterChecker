# EC-CUBE4 + ベリトランス決済 クレマス攻撃検出要件定義書

## 1. プロジェクト概要

### 1.1 目的
EC-CUBE4でベリトランス決済を使用するクレジットカード決済システムに対するクレマス攻撃を検出するスクリプトを作成する。

### 1.2 背景
- EC-CUBE4の決済システムを狙った攻撃の増加
- ベリトランス決済の不正利用の検出
- クレジットカード情報の不正取得の防止

## 2. システム構成

### 2.1 対象システム
- **EC-CUBE4**: PHP製のECサイト構築システム
- **ベリトランス決済**: クレジットカード決済サービス
- **Apache**: Webサーバー

### 2.2 監視対象
- **EC-CUBE4のアクセスログ**: `/var/log/apache2/access.log`
- **ベリトランス決済関連のログ**: 決済処理のログ
- **EC-CUBE4のエラーログ**: `/var/log/apache2/error.log`

## 3. 機能要件

### 3.1 基本機能
- **ログ監視**: EC-CUBE4のApacheアクセスログを監視
- **攻撃検出**: クレマス攻撃の基本的なパターンを検出
- **決済関連検出**: ベリトランス決済への不正アクセス検出
- **アラート**: 攻撃検出時にメールやSlackで通知
- **ログ出力**: 検出結果をログファイルに記録

### 3.2 検出対象（EC-CUBE4特化）

#### 3.2.1 決済関連の攻撃パターン
- **決済ページへの大量アクセス**: `/shopping/payment.php`への集中アクセス
- **ベリトランス決済処理への攻撃**: 決済処理エンドポイントへの不正アクセス
- **クレジットカード情報入力ページの攻撃**: カード情報入力フォームへの不正アクセス

#### 3.2.2 EC-CUBE4特有の攻撃パターン
- **管理画面への不正アクセス**: `/admin/`への未認証アクセス
- **会員ログインへの攻撃**: `/mypage/login.php`への大量アクセス
- **商品詳細ページへの攻撃**: `/products/detail.php`への異常アクセス

#### 3.2.3 ベリトランス決済特有の攻撃パターン
- **決済処理の異常**: ベリトランスAPIへの異常なリクエスト
- **決済結果ページへの攻撃**: 決済完了ページへの不正アクセス
- **決済エラーページへの攻撃**: 決済失敗ページへの異常アクセス

## 4. 技術要件

### 4.1 開発環境
- **言語**: Python 3.7以上
- **ライブラリ**: 標準ライブラリ中心、必要最小限
- **OS**: Linux（Ubuntu、CentOS等）
- **Webサーバー**: Apache

### 4.2 外部連携
- **ログファイル**: EC-CUBE4のApacheアクセスログ
- **通知**: メール送信（SMTP）
- **設定**: 設定ファイル（JSON/YAML）

## 5. 検出ルール（EC-CUBE4特化）

### 5.1 決済関連の検出ルール
```yaml
detection:
  payment_attack:
    enabled: true
    patterns:
      - "/shopping/payment.php"
      - "/shopping/confirm.php"
      - "/shopping/complete.php"
    threshold: 50
    time_window: 60
    
  veritrans_attack:
    enabled: true
    patterns:
      - "/veritrans/"
      - "/payment/veritrans/"
      - "/shopping/veritrans/"
    threshold: 30
    time_window: 60
```

### 5.2 EC-CUBE4管理画面の検出ルール
```yaml
detection:
  admin_attack:
    enabled: true
    patterns:
      - "/admin/"
      - "/admin/login.php"
      - "/admin/order/"
    threshold: 20
    time_window: 300
```

### 5.3 会員機能の検出ルール
```yaml
detection:
  member_attack:
    enabled: true
    patterns:
      - "/mypage/login.php"
      - "/mypage/change.php"
      - "/entry/"
    threshold: 40
    time_window: 300
```

## 6. ログ解析パターン

### 6.1 EC-CUBE4のログ例
```
# 決済ページへのアクセス
192.168.1.100 - - [19/Dec/2024:10:30:00 +0900] "POST /shopping/payment.php HTTP/1.1" 200 1234

# ベリトランス決済処理
192.168.1.100 - - [19/Dec/2024:10:30:01 +0900] "POST /shopping/veritrans/process.php HTTP/1.1" 200 5678

# 管理画面へのアクセス
192.168.1.100 - - [19/Dec/2024:10:30:02 +0900] "GET /admin/login.php HTTP/1.1" 401 9012
```

### 6.2 検出対象のURLパターン
- **決済関連**: `/shopping/payment.php`, `/shopping/confirm.php`
- **ベリトランス**: `/veritrans/`, `/payment/veritrans/`
- **管理画面**: `/admin/`, `/admin/login.php`
- **会員機能**: `/mypage/`, `/entry/`
- **商品関連**: `/products/detail.php`, `/products/list.php`

## 7. 実装計画

### フェーズ1: 基本機能（1週間）
- EC-CUBE4ログファイル読み込み機能
- 基本的な検出ルール実装
- 決済関連パターンの検出

### フェーズ2: 決済特化機能（1週間）
- ベリトランス決済関連の検出強化
- 管理画面・会員機能の検出
- 通知機能の実装

## 8. 成功指標
- EC-CUBE4のログファイルを正常に読み込める
- 決済関連の攻撃パターンを検出できる
- ベリトランス決済への不正アクセスを検出できる
- 管理画面への不正アクセスを検出できる
- 検出時に通知が送信される

## 9. 制約事項
- 複雑な機械学習は使用しない
- データベースは使用しない
- 外部サービスへの依存は最小限にする
- EC-CUBE4の設定変更は最小限にする

## 10. セキュリティ考慮事項

### 10.1 決済関連の特別な配慮
- **PCI DSS準拠**: クレジットカード情報の取り扱い
- **決済ログの保護**: 決済関連ログの暗号化
- **アクセス制御**: 決済処理へのアクセス制限

### 10.2 EC-CUBE4特有の配慮
- **管理画面の保護**: 管理画面へのアクセス制限
- **会員情報の保護**: 会員データの取り扱い
- **商品情報の保護**: 商品データの取り扱い

---

**作成日**: 2024年12月
**バージョン**: 1.0
**対象システム**: EC-CUBE4 + ベリトランス決済