#!/usr/bin/env python3
"""
Apacheログのみを使用したクレマス攻撃検出スクリプト
EC-CUBE4のApacheアクセスログを監視して攻撃を検出
"""

import re
import yaml
import logging
import smtplib
import time
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from collections import defaultdict
from typing import Dict, List, Tuple, Optional

class ApacheLogParser:
    """Apacheログパーサー"""
    
    def __init__(self, log_file_path: str):
        self.log_file_path = log_file_path
        self.last_position = 0
        
    def parse_log_line(self, line: str) -> Optional[Dict]:
        """Apacheログの1行を解析"""
        # Apache Combined Log Format
        pattern = r'^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d+) (\d+)'
        match = re.match(pattern, line)
        
        if not match:
            return None
            
        ip, timestamp_str, request, status_code, bytes_sent = match.groups()
        
        # リクエストの解析
        request_parts = request.split()
        if len(request_parts) < 2:
            return None
            
        method, url = request_parts[0], request_parts[1]
        
        # User-Agentの抽出
        user_agent = ""
        if '"' in request:
            parts = request.split('"')
            if len(parts) >= 3:
                user_agent = parts[3] if len(parts) > 3 else ""
        
        return {
            'ip': ip,
            'timestamp': self.parse_timestamp(timestamp_str),
            'method': method,
            'url': url,
            'status_code': int(status_code),
            'bytes_sent': int(bytes_sent),
            'user_agent': user_agent
        }
    
    def parse_timestamp(self, timestamp_str: str) -> datetime:
        """タイムスタンプを解析"""
        # [19/Dec/2024:10:30:00 +0900] 形式
        return datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
    
    def read_new_logs(self) -> List[Dict]:
        """新しいログエントリを読み込み"""
        new_entries = []
        
        try:
            with open(self.log_file_path, 'r') as f:
                f.seek(self.last_position)
                
                for line in f:
                    entry = self.parse_log_line(line.strip())
                    if entry:
                        new_entries.append(entry)
                
                self.last_position = f.tell()
                
        except FileNotFoundError:
            logging.error(f"ログファイルが見つかりません: {self.log_file_path}")
        except Exception as e:
            logging.error(f"ログファイル読み込みエラー: {e}")
        
        return new_entries

class AttackDetector:
    """攻撃検出エンジン"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.ip_data = defaultdict(list)
        
    def detect_attacks(self, log_entries: List[Dict]) -> List[Dict]:
        """攻撃を検出"""
        attacks = []
        
        # ログエントリをIP別に整理
        for entry in log_entries:
            self.ip_data[entry['ip']].append(entry)
        
        # 各検出ルールを実行
        attacks.extend(self.detect_rapid_requests())
        attacks.extend(self.detect_payment_attacks())
        attacks.extend(self.detect_auth_failures())
        attacks.extend(self.detect_suspicious_user_agents())
        
        # 古いデータをクリア
        self.cleanup_old_data()
        
        return attacks
    
    def detect_rapid_requests(self) -> List[Dict]:
        """大量リクエスト検出"""
        attacks = []
        rule = self.config['detection']['rapid_requests']
        
        if not rule['enabled']:
            return attacks
        
        threshold = rule['threshold']
        time_window = rule['time_window']
        current_time = datetime.now().replace(tzinfo=None)
        
        for ip, entries in self.ip_data.items():
            # 時間窓内のリクエストをカウント
            recent_requests = [
                entry for entry in entries
                if (current_time - entry['timestamp'].replace(tzinfo=None)).seconds <= time_window
            ]
            
            if len(recent_requests) > threshold:
                attacks.append({
                    'timestamp': current_time.isoformat(),
                    'attack_type': 'rapid_requests',
                    'source_ip': ip,
                    'count': len(recent_requests),
                    'threshold': threshold,
                    'time_window': time_window,
                    'severity': rule['severity']
                })
        
        return attacks
    
    def detect_payment_attacks(self) -> List[Dict]:
        """決済関連攻撃検出"""
        attacks = []
        rule = self.config['detection']['payment_urls']
        
        if not rule['enabled']:
            return attacks
        
        target_urls = rule['target_urls']
        threshold = rule['threshold']
        time_window = rule['time_window']
        current_time = datetime.now().replace(tzinfo=None)
        
        for ip, entries in self.ip_data.items():
            # 決済関連URLへのアクセスをカウント
            payment_requests = [
                entry for entry in entries
                if any(url in entry['url'] for url in target_urls) and
                (current_time - entry['timestamp'].replace(tzinfo=None)).seconds <= time_window
            ]
            
            if len(payment_requests) > threshold:
                attacks.append({
                    'timestamp': current_time.isoformat(),
                    'attack_type': 'payment_attack',
                    'source_ip': ip,
                    'count': len(payment_requests),
                    'target_urls': [entry['url'] for entry in payment_requests],
                    'threshold': threshold,
                    'time_window': time_window,
                    'severity': rule['severity']
                })
        
        return attacks
    
    def detect_auth_failures(self) -> List[Dict]:
        """認証失敗検出"""
        attacks = []
        rule = self.config['detection']['auth_failures']
        
        if not rule['enabled']:
            return attacks
        
        status_codes = rule['status_codes']
        threshold = rule['threshold']
        time_window = rule['time_window']
        current_time = datetime.now().replace(tzinfo=None)
        
        for ip, entries in self.ip_data.items():
            # 認証失敗をカウント
            auth_failures = [
                entry for entry in entries
                if entry['status_code'] in status_codes and
                (current_time - entry['timestamp'].replace(tzinfo=None)).seconds <= time_window
            ]
            
            if len(auth_failures) > threshold:
                attacks.append({
                    'timestamp': current_time.isoformat(),
                    'attack_type': 'auth_failure',
                    'source_ip': ip,
                    'count': len(auth_failures),
                    'status_codes': [entry['status_code'] for entry in auth_failures],
                    'threshold': threshold,
                    'time_window': time_window,
                    'severity': rule['severity']
                })
        
        return attacks
    
    def detect_suspicious_user_agents(self) -> List[Dict]:
        """怪しいUser-Agent検出"""
        attacks = []
        rule = self.config['detection']['suspicious_user_agents']
        
        if not rule['enabled']:
            return attacks
        
        suspicious_patterns = rule['patterns']
        threshold = rule['threshold']
        time_window = rule['time_window']
        current_time = datetime.now().replace(tzinfo=None)
        
        for ip, entries in self.ip_data.items():
            # 怪しいUser-Agentをカウント
            suspicious_requests = [
                entry for entry in entries
                if any(pattern.lower() in entry['user_agent'].lower() for pattern in suspicious_patterns) and
                (current_time - entry['timestamp'].replace(tzinfo=None)).seconds <= time_window
            ]
            
            if len(suspicious_requests) > threshold:
                attacks.append({
                    'timestamp': current_time.isoformat(),
                    'attack_type': 'suspicious_user_agent',
                    'source_ip': ip,
                    'count': len(suspicious_requests),
                    'user_agents': [entry['user_agent'] for entry in suspicious_requests],
                    'threshold': threshold,
                    'time_window': time_window,
                    'severity': rule['severity']
                })
        
        return attacks
    
    def cleanup_old_data(self):
        """古いデータをクリア"""
        current_time = datetime.now().replace(tzinfo=None)
        max_age = 3600  # 1時間
        
        for ip in list(self.ip_data.keys()):
            self.ip_data[ip] = [
                entry for entry in self.ip_data[ip]
                if (current_time - entry['timestamp'].replace(tzinfo=None)).seconds <= max_age
            ]
            
            if not self.ip_data[ip]:
                del self.ip_data[ip]

class Notifier:
    """通知システム"""
    
    def __init__(self, config: Dict):
        self.config = config
    
    def send_email_alert(self, attack: Dict):
        """メールアラート送信"""
        email_config = self.config['notifications']['email']
        
        if not email_config['enabled']:
            return
        
        try:
            # メール本文作成
            subject = f"クレマス攻撃検出: {attack['attack_type']}"
            body = self.create_email_body(attack)
            
            # メール送信
            msg = MIMEText(body, 'plain', 'utf-8')
            msg['Subject'] = subject
            msg['From'] = email_config['username']
            msg['To'] = ', '.join(email_config['recipients'])
            
            with smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port']) as server:
                server.starttls()
                server.login(email_config['username'], email_config['password'])
                server.send_message(msg)
            
            logging.info(f"メールアラート送信完了: {attack['attack_type']}")
            
        except Exception as e:
            logging.error(f"メール送信エラー: {e}")
    
    def create_email_body(self, attack: Dict) -> str:
        """メール本文作成"""
        body = f"""
クレマス攻撃が検出されました

攻撃タイプ: {attack['attack_type']}
発生日時: {attack['timestamp']}
攻撃元IP: {attack['source_ip']}
検出回数: {attack['count']}
重要度: {attack['severity']}

詳細情報:
"""
        
        if 'target_urls' in attack:
            body += f"対象URL: {', '.join(attack['target_urls'])}\n"
        
        if 'status_codes' in attack:
            body += f"ステータスコード: {', '.join(map(str, attack['status_codes']))}\n"
        
        if 'user_agents' in attack:
            body += f"User-Agent: {', '.join(attack['user_agents'])}\n"
        
        body += f"""
閾値: {attack['threshold']}
時間窓: {attack['time_window']}秒

この攻撃に対して適切な対応を行ってください。
"""
        
        return body

def main():
    """メイン関数"""
    # 設定読み込み
    try:
        with open('config.yaml', 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        logging.error("config.yamlが見つかりません")
        return
    except Exception as e:
        logging.error(f"設定ファイル読み込みエラー: {e}")
        return
    
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
    parser = ApacheLogParser(config['log_file']['path'])
    detector = AttackDetector(config)
    notifier = Notifier(config)
    
    logging.info("クレマス攻撃検出スクリプト開始")
    
    # メインループ
    while True:
        try:
            # 新しいログを読み込み
            new_entries = parser.read_new_logs()
            
            if new_entries:
                # 攻撃検出
                attacks = detector.detect_attacks(new_entries)
                
                # 通知送信
                for attack in attacks:
                    logging.warning(f"攻撃検出: {attack}")
                    notifier.send_email_alert(attack)
            
            # 待機
            time.sleep(config['monitoring']['interval'])
            
        except KeyboardInterrupt:
            logging.info("スクリプト終了")
            break
        except Exception as e:
            logging.error(f"エラー: {e}")
            time.sleep(10)

if __name__ == "__main__":
    main()