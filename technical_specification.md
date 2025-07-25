# クレマス攻撃検出システム 技術仕様書

## 1. システムアーキテクチャ

### 1.1 全体構成
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   ログ収集層    │    │   分析処理層    │    │   検出・対応層   │
│                 │    │                 │    │                 │
│ • rsyslog       │───▶│ • パターン分析  │───▶│ • 攻撃判定      │
│ • fluentd       │    │ • 異常検出      │    │ • スコアリング  │
│ • tcpdump       │    │ • 機械学習      │    │ • 自動対応      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │   データ層      │    │   通知・管理層   │
                       │                 │    │                 │
                       │ • PostgreSQL    │    │ • アラート      │
                       │ • Redis         │    │ • 通知          │
                       │ • Elasticsearch │    │ • 管理画面      │
                       └─────────────────┘    └─────────────────┘
```

### 1.2 コンポーネント詳細

#### 1.2.1 ログ収集層
- **rsyslog**: システムログ、アプリケーションログの収集
- **fluentd**: 構造化ログの収集・転送
- **tcpdump**: ネットワークパケットのキャプチャ
- **Filebeat**: ログファイルの監視・収集

#### 1.2.2 分析処理層
- **パターン分析エンジン**: 正規表現、シグネチャマッチング
- **異常検出エンジン**: 統計的異常検出、機械学習
- **行動分析エンジン**: ユーザー行動パターン分析

#### 1.2.3 検出・対応層
- **攻撃判定エンジン**: 複数指標の統合判定
- **スコアリングシステム**: 脅威レベルの定量化
- **自動対応エンジン**: 防御措置の自動実行

## 2. データモデル

### 2.1 ログデータ構造
```json
{
  "timestamp": "2024-12-19T10:30:00Z",
  "source_ip": "192.168.1.100",
  "destination_ip": "10.0.0.1",
  "user_agent": "Mozilla/5.0...",
  "request_method": "POST",
  "request_url": "/api/login",
  "response_code": 401,
  "session_id": "abc123def456",
  "user_id": "user123",
  "payload_size": 1024,
  "processing_time": 150
}
```

### 2.2 検出イベント構造
```json
{
  "event_id": "evt_20241219_001",
  "timestamp": "2024-12-19T10:30:00Z",
  "attack_type": "clemens_attack",
  "confidence_score": 0.95,
  "severity": "HIGH",
  "source_ip": "192.168.1.100",
  "indicators": [
    "rapid_login_attempts",
    "session_manipulation",
    "credential_stuffing"
  ],
  "mitigation_actions": [
    "ip_block",
    "session_invalidation",
    "alert_notification"
  ]
}
```

## 3. 検出アルゴリズム

### 3.1 クレマス攻撃の特徴
1. **高速な認証試行**: 短時間での大量ログイン試行
2. **セッション操作**: セッションIDの不正な操作
3. **認証情報の不正使用**: 漏洩した認証情報の利用
4. **分散攻撃**: 複数IPからの協調攻撃

### 3.2 検出ルール

#### 3.2.1 頻度ベース検出
```python
def detect_rapid_requests(ip_address, time_window=60, threshold=100):
    """
    短時間での大量リクエスト検出
    """
    request_count = get_request_count(ip_address, time_window)
    return request_count > threshold
```

#### 3.2.2 パターンベース検出
```python
def detect_session_manipulation(session_id):
    """
    セッション操作の検出
    """
    patterns = [
        r'session_id=([^&]+)',
        r'jsessionid=([^&]+)',
        r'PHPSESSID=([^&]+)'
    ]
    
    for pattern in patterns:
        if re.search(pattern, session_id):
            return analyze_session_behavior(session_id)
    
    return False
```

#### 3.2.3 機械学習ベース検出
```python
def detect_anomaly_with_ml(features):
    """
    機械学習による異常検出
    """
    model = load_anomaly_detection_model()
    prediction = model.predict([features])
    confidence = model.predict_proba([features])[0]
    
    return {
        'is_anomaly': prediction[0] == 1,
        'confidence': max(confidence)
    }
```

### 3.3 スコアリングシステム
```python
def calculate_threat_score(indicators):
    """
    脅威スコアの計算
    """
    weights = {
        'rapid_requests': 0.3,
        'session_manipulation': 0.25,
        'failed_auth': 0.2,
        'suspicious_patterns': 0.15,
        'geolocation_anomaly': 0.1
    }
    
    total_score = 0
    for indicator, weight in weights.items():
        if indicator in indicators:
            total_score += weight
    
    return min(total_score, 1.0)
```

## 4. API仕様

### 4.1 RESTful API

#### 4.1.1 エンドポイント一覧
```
POST   /api/v1/events          # イベント登録
GET    /api/v1/events          # イベント一覧取得
GET    /api/v1/events/{id}     # イベント詳細取得
POST   /api/v1/alerts          # アラート作成
GET    /api/v1/alerts          # アラート一覧取得
PUT    /api/v1/rules           # ルール更新
GET    /api/v1/statistics      # 統計情報取得
```

#### 4.1.2 イベント登録API
```python
@app.post("/api/v1/events")
async def create_event(event: EventCreate):
    """
    セキュリティイベントの登録
    """
    event_id = await event_service.create_event(event)
    return {"event_id": event_id, "status": "created"}
```

### 4.2 WebSocket API
```python
@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """
    リアルタイムアラート配信
    """
    await websocket.accept()
    try:
        while True:
            alert = await alert_queue.get()
            await websocket.send_json(alert)
    except WebSocketDisconnect:
        pass
```

## 5. データベース設計

### 5.1 テーブル構造

#### 5.1.1 events テーブル
```sql
CREATE TABLE events (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    source_ip INET,
    destination_ip INET,
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20),
    confidence_score DECIMAL(3,2),
    payload JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_events_timestamp ON events(timestamp);
CREATE INDEX idx_events_source_ip ON events(source_ip);
CREATE INDEX idx_events_event_type ON events(event_type);
```

#### 5.1.2 alerts テーブル
```sql
CREATE TABLE alerts (
    id SERIAL PRIMARY KEY,
    event_id INTEGER REFERENCES events(id),
    alert_type VARCHAR(50) NOT NULL,
    message TEXT,
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP
);
```

#### 5.1.3 rules テーブル
```sql
CREATE TABLE rules (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    pattern TEXT,
    threshold INTEGER,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## 6. 設定管理

### 6.1 設定ファイル構造
```yaml
# config/detection.yaml
detection:
  rules:
    rapid_requests:
      enabled: true
      threshold: 100
      time_window: 60
    session_manipulation:
      enabled: true
      patterns:
        - "session_id="
        - "jsessionid="
    failed_auth:
      enabled: true
      threshold: 10
      time_window: 300

alerts:
  email:
    enabled: true
    smtp_server: "smtp.example.com"
    recipients: ["admin@example.com"]
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/..."
  sms:
    enabled: false

database:
  postgresql:
    host: "localhost"
    port: 5432
    database: "clemens_detector"
    username: "detector_user"
  redis:
    host: "localhost"
    port: 6379
    database: 0
```

## 7. 監視・ログ

### 7.1 メトリクス
- **検出精度**: 真陽性率、偽陽性率
- **性能指標**: レスポンス時間、スループット
- **システム指標**: CPU使用率、メモリ使用率、ディスク使用率
- **ビジネス指標**: 検出イベント数、アラート数

### 7.2 ログレベル
```python
import logging

# ログ設定
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('clemens_detector.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)
```

## 8. セキュリティ考慮事項

### 8.1 認証・認可
- JWT トークンベース認証
- RBAC（Role-Based Access Control）
- API キー認証

### 8.2 データ保護
- 通信の暗号化（TLS 1.3）
- データベースの暗号化
- ログデータの暗号化

### 8.3 監査
- 全ての操作のログ記録
- アクセスログの保持
- 定期的なセキュリティ監査

## 9. デプロイメント

### 9.1 Docker化
```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### 9.2 Kubernetes設定
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: clemens-detector
spec:
  replicas: 3
  selector:
    matchLabels:
      app: clemens-detector
  template:
    metadata:
      labels:
        app: clemens-detector
    spec:
      containers:
      - name: clemens-detector
        image: clemens-detector:latest
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: url
```

## 10. テスト戦略

### 10.1 単体テスト
- 各検出アルゴリズムのテスト
- API エンドポイントのテスト
- データベース操作のテスト

### 10.2 統合テスト
- エンドツーエンドの検出フロー
- 外部システムとの連携
- パフォーマンステスト

### 10.3 セキュリティテスト
- ペネトレーションテスト
- 脆弱性スキャン
- 認証・認可のテスト

---

**作成日**: 2024年12月
**バージョン**: 1.0
**技術責任者**: [技術責任者名]