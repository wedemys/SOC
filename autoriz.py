#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
AI АНАЛИЗАТОР БЕЗОПАСНОСТИ (SOC) - NiceGUI v7.0
============================================================================
Профессиональный дизайн дипломного уровня
============================================================================
Запуск: python soc_nicegui_v7.py
============================================================================
"""

import os, io, sys, time, json, sqlite3, hashlib, asyncio, secrets
import threading, queue, struct, tempfile, traceback
import datetime as dt
from collections import Counter
from functools import lru_cache
from pathlib import Path

import numpy as np
import pandas as pd
from nicegui import ui, app, events

try:
    from pymongo import MongoClient
    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False

from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler, LabelEncoder
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.ensemble import (
    IsolationForest, RandomForestClassifier,
    GradientBoostingClassifier, AdaBoostClassifier,
)
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.cluster import DBSCAN
from sklearn.decomposition import PCA
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (
    roc_curve, roc_auc_score, precision_recall_curve, average_precision_score,
    confusion_matrix, classification_report,
    accuracy_score, precision_score, recall_score, f1_score,
)

try:
    from xgboost import XGBClassifier
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

try:
    from lightgbm import LGBMClassifier
    LIGHTGBM_AVAILABLE = True
except ImportError:
    LIGHTGBM_AVAILABLE = False

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers, Model
    from tensorflow.keras.callbacks import EarlyStopping
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw, conf, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots


# ═══════════════════════════════════════════
# КОНСТАНТЫ
# ═══════════════════════════════════════════
KDD_COLUMNS = [
    "duration","protocol_type","service","flag",
    "src_bytes","dst_bytes","land","wrong_fragment","urgent",
    "hot","num_failed_logins","logged_in","num_compromised",
    "root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login",
    "count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate",
    "dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate",
]

MODEL_PATH = "models/"
os.makedirs(MODEL_PATH, exist_ok=True)

MODEL_INFO = {
    "isolation_forest": {"name": "Isolation Forest", "type": "Unsupervised", "icon": "🌲", "description": "Изоляция аномалий случайными деревьями"},
    "lof": {"name": "Local Outlier Factor", "type": "Unsupervised", "icon": "📍", "description": "Обнаружение на основе локальной плотности"},
    "ocsvm": {"name": "One-Class SVM", "type": "Unsupervised", "icon": "🎯", "description": "SVM для одного класса"},
    "random_forest": {"name": "Random Forest", "type": "Supervised", "icon": "🌳", "description": "Ансамбль решающих деревьев"},
    "gradient_boosting": {"name": "Gradient Boosting", "type": "Supervised", "icon": "🚀", "description": "Последовательный бустинг деревьев"},
    "xgboost": {"name": "XGBoost", "type": "Supervised", "icon": "⚡", "description": "Оптимизированный Gradient Boosting"},
    "lightgbm": {"name": "LightGBM", "type": "Supervised", "icon": "💡", "description": "Быстрый Gradient Boosting"},
    "adaboost": {"name": "AdaBoost", "type": "Supervised", "icon": "🔄", "description": "Адаптивный бустинг"},
    "autoencoder": {"name": "Autoencoder", "type": "Deep Learning", "icon": "🧠", "description": "Нейронная сеть реконструкции"},
}

SECURITY_RECOMMENDATIONS = {
    "Сканирование портов": {"icon": "🔍", "severity": "Средняя", "description": "Обнаружена попытка сканирования открытых портов",
        "recommendations": ["Закройте неиспользуемые порты", "Установите fail2ban", "Настройте rate limiting"],
        "commands": ["sudo netstat -tuln", "sudo iptables -A INPUT -p tcp --dport <ПОРТ> -j DROP"]},
    "Брутфорс": {"icon": "🔨", "severity": "Высокая", "description": "Множественные попытки подбора пароля",
        "recommendations": ["НЕМЕДЛЕННО заблокируйте IP", "Проверьте логи входов", "Включите 2FA"],
        "commands": ["sudo iptables -A INPUT -s <IP> -j DROP", "sudo grep 'Failed password' /var/log/auth.log"]},
    "DDoS / Флуд": {"icon": "💥", "severity": "Критическая", "description": "Аномально высокий объём трафика",
        "recommendations": ["Активируйте DDoS защиту", "Включите rate limiting", "Свяжитесь с провайдером"],
        "commands": ["sudo sysctl -w net.ipv4.tcp_syncookies=1"]},
    "SQL Injection": {"icon": "💉", "severity": "Критическая", "description": "Попытка внедрения SQL/XSS кода",
        "recommendations": ["Проверьте параметризацию запросов", "Обновите WAF правила", "Аудит кода"],
        "commands": ["sudo grep -iE 'union.*select|<script>' /var/log/nginx/access.log"]},
    "Несанкц. доступ": {"icon": "🚫", "severity": "Высокая", "description": "Попытка несанкционированного доступа",
        "recommendations": ["Проверьте логи доступа", "Обновите ACL"], "commands": ["last -n 20"]},
    "Вредоносное ПО": {"icon": "🦠", "severity": "Критическая", "description": "Обнаружена активность вредоносного ПО или C2",
        "recommendations": ["НЕМЕДЛЕННО изолируйте систему", "Запустите антивирус", "Проверьте процессы"],
        "commands": ["ps aux --sort=-%cpu | head -20", "sudo netstat -tulpn"]},
    "Утечка данных": {"icon": "📤", "severity": "Критическая", "description": "Подозрительная передача больших объёмов данных",
        "recommendations": ["Заблокируйте исходящие к подозрительному IP", "Настройте DLP"],
        "commands": ["sudo iftop -i eth0"]},
    "Повышение привилегий": {"icon": "⬆️", "severity": "Критическая", "description": "Попытка повышения привилегий",
        "recommendations": ["Проверьте sudo логи", "Ограничьте sudo права"],
        "commands": ["sudo grep sudo /var/log/auth.log | tail -50"]},
    "Разведка": {"icon": "🔭", "severity": "Средняя", "description": "Разведывательная активность (ICMP, fingerprinting)",
        "recommendations": ["Мониторьте IP", "Скройте версии ПО", "Настройте honeypot"],
        "commands": ["sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP"]},
    "DNS атака": {"icon": "🌐", "severity": "Высокая", "description": "Подозрительная DNS активность",
        "recommendations": ["Проверьте DNS запросы", "Настройте DNSSEC"],
        "commands": ["sudo tcpdump -i eth0 port 53"]},
    "DNS туннелирование": {"icon": "🕳️", "severity": "Критическая", "description": "DNS туннелирование — утечка данных через DNS",
        "recommendations": ["Заблокируйте подозрительные DNS", "Анализируйте длинные DNS записи"],
        "commands": ["sudo tcpdump -i eth0 'udp port 53 and udp[10:2] > 512'"]},
    "Подозр. активность": {"icon": "⚠️", "severity": "Средняя", "description": "Подозрительная сетевая активность",
        "recommendations": ["Проанализируйте логи", "Проверьте источник", "Обновите системы безопасности"],
        "commands": ["sudo tail -f /var/log/syslog", "sudo ss -tulpn"]},
}

PROTOCOL_COLORS = {
    'TCP': '#818cf8', 'UDP': '#38bdf8', 'DNS': '#34d399', 'ICMP': '#f472b6',
    'HTTP': '#a3e635', 'HTTPS': '#a3e635', 'TLS': '#a3e635', 'SSL': '#a3e635',
    'ARP': '#fbbf24', 'SSH': '#2dd4bf', 'FTP': '#fb923c', 'SMTP': '#f87171',
    'SYN': '#6366f1', 'RST': '#ef4444', 'FIN': '#22c55e',
}

PORT_SERVICES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 3389: 'RDP',
    5432: 'PostgreSQL', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
}


# ═══════════════════════════════════════════
# ГЛОБАЛЬНОЕ СОСТОЯНИЕ
# ═══════════════════════════════════════════
class AppState:
    def __init__(self):
        self.raw_df = None
        self.raw_X = None
        self.result_df = None
        self.has_results = False
        self.ground_truth = None
        self.feature_importance = None
        self.cv_results = None
        self.trained_pipeline = None
        self.file_name = None
        self.models_results = {}
        self.capture_running = False
        self.capture_packets = []
        self.capture_thread = None
        self.packet_counter = 0
        self.capture_start_time = None
        self.capture_filter = ""

state = AppState()


# ═══════════════════════════════════════════
# БАЗА ДАННЫХ (SQLite)
# ═══════════════════════════════════════════
DB_PATH = "soc_database.db"


def init_database():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS analysis_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT DEFAULT '', timestamp TEXT NOT NULL, filename TEXT,
        total_records INTEGER, total_anomalies INTEGER, anomaly_percent REAL,
        model_type TEXT, model_params TEXT, training_time REAL,
        accuracy REAL, precision_val REAL, recall REAL, f1_score REAL, roc_auc REAL, notes TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT DEFAULT '', session_id INTEGER, timestamp TEXT NOT NULL,
        src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER,
        protocol TEXT, service TEXT, attack_type TEXT, severity TEXT,
        anomaly_score REAL, status TEXT DEFAULT 'Новый', analyst_notes TEXT,
        FOREIGN KEY (session_id) REFERENCES analysis_sessions(id))""")
    c.execute("""CREATE TABLE IF NOT EXISTS ip_lists (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT DEFAULT '', ip_address TEXT NOT NULL,
        list_type TEXT NOT NULL CHECK(list_type IN ('blacklist','whitelist')),
        reason TEXT, added_date TEXT NOT NULL, added_by TEXT DEFAULT 'system', is_active INTEGER DEFAULT 1)""")
    c.execute("""CREATE TABLE IF NOT EXISTS model_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT DEFAULT '', timestamp TEXT NOT NULL, model_type TEXT, model_name TEXT,
        params TEXT, dataset_size INTEGER, accuracy REAL, precision_val REAL, recall REAL,
        f1_score REAL, roc_auc REAL, training_time REAL, cross_val_results TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT DEFAULT '', timestamp TEXT NOT NULL, alert_type TEXT,
        message TEXT, severity TEXT, source_ip TEXT,
        is_read INTEGER DEFAULT 0, is_resolved INTEGER DEFAULT 0,
        resolved_by TEXT, resolved_date TEXT)""")
    for table in ['analysis_sessions', 'incidents', 'ip_lists', 'model_history', 'alerts']:
        try:
            c.execute(f"ALTER TABLE {table} ADD COLUMN user_id TEXT DEFAULT ''")
        except:
            pass
    conn.commit(); conn.close()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def save_analysis_session(filename, total_records, total_anomalies, anomaly_percent,
                          model_type, model_params, training_time,
                          accuracy=None, precision_val=None, recall=None,
                          f1_score_val=None, roc_auc=None):
    uid = _get_current_user_id()
    conn = get_db(); c = conn.cursor()
    c.execute("""INSERT INTO analysis_sessions
        (user_id, timestamp, filename, total_records, total_anomalies, anomaly_percent,
         model_type, model_params, training_time, accuracy, precision_val, recall, f1_score, roc_auc)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (uid, dt.datetime.now().isoformat(), filename, total_records, total_anomalies, anomaly_percent,
         model_type, json.dumps(model_params or {}), training_time, accuracy, precision_val, recall, f1_score_val, roc_auc))
    sid = c.lastrowid; conn.commit(); conn.close()
    return sid


def save_incidents(session_id, result_df, max_inc=5000):
    uid = _get_current_user_id()
    conn = get_db(); c = conn.cursor()
    anomalies = result_df[result_df['anomaly'] == 1].head(max_inc)
    for _, row in anomalies.iterrows():
        c.execute("""INSERT INTO incidents (user_id,session_id,timestamp,src_ip,dst_ip,src_port,dst_port,
            protocol,service,attack_type,severity,anomaly_score,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (uid, session_id, dt.datetime.now().isoformat(),
             str(row.get('src_ip','')), str(row.get('dst_ip','')),
             int(row.get('src_port',0) or 0), int(row.get('dst_port',0) or 0),
             str(row.get('protocol_type', row.get('protocol',''))),
             str(row.get('service','')), str(row.get('attack_type','?')),
             str(row.get('severity','Средняя')), float(row.get('anomaly_score',0)), 'Новый'))
    conn.commit(); conn.close()
    return len(anomalies)


def save_model_history(model_type, model_name, params, dataset_size,
                       accuracy=None, precision_val=None, recall=None,
                       f1_score_val=None, roc_auc=None, training_time=None, cv_results=None):
    uid = _get_current_user_id()
    conn = get_db(); c = conn.cursor()
    c.execute("""INSERT INTO model_history (user_id,timestamp,model_type,model_name,params,dataset_size,
        accuracy,precision_val,recall,f1_score,roc_auc,training_time,cross_val_results)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (uid, dt.datetime.now().isoformat(), model_type, model_name, json.dumps(params or {}),
         dataset_size, accuracy, precision_val, recall, f1_score_val, roc_auc, training_time,
         json.dumps(cv_results) if cv_results else None))
    conn.commit(); conn.close()


def add_to_ip_list(ip_address, list_type, reason="", added_by="analyst"):
    uid = _get_current_user_id()
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT id FROM ip_lists WHERE user_id=? AND ip_address=? AND list_type=? AND is_active=1", (uid, ip_address, list_type))
    if c.fetchone(): conn.close(); return False
    c.execute("INSERT INTO ip_lists (user_id,ip_address,list_type,reason,added_date,added_by) VALUES (?,?,?,?,?,?)",
              (uid, ip_address, list_type, reason, dt.datetime.now().isoformat(), added_by))
    conn.commit(); conn.close(); return True


def remove_from_ip_list(ip_id):
    uid = _get_current_user_id()
    conn = get_db(); conn.execute("UPDATE ip_lists SET is_active=0 WHERE id=? AND user_id=?", (ip_id, uid)); conn.commit(); conn.close()


def get_ip_list(list_type):
    uid = _get_current_user_id()
    conn = get_db()
    rows = conn.execute("SELECT * FROM ip_lists WHERE user_id=? AND list_type=? AND is_active=1 ORDER BY added_date DESC", (uid, list_type)).fetchall()
    conn.close(); return [dict(r) for r in rows]


def create_alert(alert_type, message, severity, source_ip=""):
    uid = _get_current_user_id()
    conn = get_db()
    conn.execute("INSERT INTO alerts (user_id,timestamp,alert_type,message,severity,source_ip) VALUES (?,?,?,?,?,?)",
                 (uid, dt.datetime.now().isoformat(), alert_type, message, severity, source_ip))
    conn.commit(); conn.close()


def get_alerts(unread_only=False, limit=100):
    uid = _get_current_user_id()
    conn = get_db()
    if unread_only:
        q = "SELECT * FROM alerts WHERE user_id=? AND is_read=0 ORDER BY timestamp DESC LIMIT ?"
    else:
        q = "SELECT * FROM alerts WHERE user_id=? ORDER BY timestamp DESC LIMIT ?"
    rows = conn.execute(q, (uid, limit)).fetchall()
    conn.close(); return [dict(r) for r in rows]


def resolve_alert(alert_id):
    uid = _get_current_user_id()
    conn = get_db()
    conn.execute("UPDATE alerts SET is_resolved=1, is_read=1, resolved_date=? WHERE id=? AND user_id=?",
                 (dt.datetime.now().isoformat(), alert_id, uid))
    conn.commit(); conn.close()


def update_incident_status(incident_id, status, notes=""):
    uid = _get_current_user_id()
    conn = get_db()
    conn.execute("UPDATE incidents SET status=?, analyst_notes=? WHERE id=? AND user_id=?", (status, notes, incident_id, uid))
    conn.commit(); conn.close()


def get_incidents(session_id=None, severity=None, status=None, attack_type=None, limit=500):
    uid = _get_current_user_id()
    conn = get_db()
    q = "SELECT * FROM incidents WHERE user_id=?"; p = [uid]
    if session_id: q += " AND session_id=?"; p.append(session_id)
    if severity: q += " AND severity=?"; p.append(severity)
    if status: q += " AND status=?"; p.append(status)
    if attack_type: q += " AND attack_type=?"; p.append(attack_type)
    q += " ORDER BY anomaly_score DESC LIMIT ?"; p.append(limit)
    rows = conn.execute(q, p).fetchall(); conn.close()
    return [dict(r) for r in rows]


def get_analysis_history(limit=50):
    uid = _get_current_user_id()
    conn = get_db()
    rows = conn.execute("SELECT * FROM analysis_sessions WHERE user_id=? ORDER BY timestamp DESC LIMIT ?", (uid, limit)).fetchall()
    conn.close(); return [dict(r) for r in rows]


def get_model_history(limit=50):
    uid = _get_current_user_id()
    conn = get_db()
    rows = conn.execute("SELECT * FROM model_history WHERE user_id=? ORDER BY timestamp DESC LIMIT ?", (uid, limit)).fetchall()
    conn.close(); return [dict(r) for r in rows]


def get_db_stats():
    uid = _get_current_user_id()
    conn = get_db(); s = {}
    s['sessions'] = conn.execute("SELECT COUNT(*) FROM analysis_sessions WHERE user_id=?", (uid,)).fetchone()[0]
    s['incidents'] = conn.execute("SELECT COUNT(*) FROM incidents WHERE user_id=?", (uid,)).fetchone()[0]
    s['incidents_new'] = conn.execute("SELECT COUNT(*) FROM incidents WHERE user_id=? AND status='Новый'", (uid,)).fetchone()[0]
    s['blacklist'] = conn.execute("SELECT COUNT(*) FROM ip_lists WHERE user_id=? AND list_type='blacklist' AND is_active=1", (uid,)).fetchone()[0]
    s['whitelist'] = conn.execute("SELECT COUNT(*) FROM ip_lists WHERE user_id=? AND list_type='whitelist' AND is_active=1", (uid,)).fetchone()[0]
    s['alerts'] = conn.execute("SELECT COUNT(*) FROM alerts WHERE user_id=?", (uid,)).fetchone()[0]
    s['alerts_unread'] = conn.execute("SELECT COUNT(*) FROM alerts WHERE user_id=? AND is_read=0", (uid,)).fetchone()[0]
    s['models'] = conn.execute("SELECT COUNT(*) FROM model_history WHERE user_id=?", (uid,)).fetchone()[0]
    conn.close(); return s


def export_db_json():
    uid = _get_current_user_id()
    conn = get_db()
    data = {t: [dict(r) for r in conn.execute(f"SELECT * FROM {t} WHERE user_id=?", (uid,)).fetchall()]
            for t in ['analysis_sessions','incidents','ip_lists','model_history','alerts']}
    conn.close()
    return json.dumps(data, ensure_ascii=False, indent=2)


init_database()


# ═══════════════════════════════════════════
# MONGODB — АВТОРИЗАЦИЯ ПОЛЬЗОВАТЕЛЕЙ
# ═══════════════════════════════════════════
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB_NAME = "soc_analyzer"

try:
    if not PYMONGO_AVAILABLE:
        raise ImportError("pymongo не установлен")
    mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
    mongo_client.server_info()
    mongo_db = mongo_client[MONGO_DB_NAME]
    users_collection = mongo_db['users']
    users_collection.create_index('username', unique=True)
    MONGO_AVAILABLE = True
    print("✅ MongoDB подключена")
except Exception as e:
    print(f"⚠️ MongoDB недоступна: {e}")
    MONGO_AVAILABLE = False
    users_collection = None


def _hash_password(password):
    salt = secrets.token_hex(32)
    hashed = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
    return salt, hashed


def _verify_password(password, salt, stored_hash):
    return hashlib.sha256((salt + password).encode('utf-8')).hexdigest() == stored_hash


def register_user(username, password):
    if not MONGO_AVAILABLE:
        return False, "MongoDB не подключена"
    if len(username) < 3:
        return False, "Логин должен быть минимум 3 символа"
    if len(password) < 4:
        return False, "Пароль должен быть минимум 4 символа"
    salt, hashed = _hash_password(password)
    try:
        users_collection.insert_one({
            'username': username,
            'password_hash': hashed,
            'password_salt': salt,
            'registered_at': dt.datetime.now().isoformat(),
            'last_login': None,
        })
        return True, "Регистрация успешна!"
    except Exception as e:
        if 'duplicate' in str(e).lower() or 'E11000' in str(e):
            return False, "Пользователь с таким логином уже существует"
        return False, f"Ошибка: {e}"


def authenticate_user(username, password):
    if not MONGO_AVAILABLE:
        return False, "MongoDB не подключена", None
    user = users_collection.find_one({'username': username})
    if not user:
        return False, "Неверный логин или пароль", None
    if _verify_password(password, user['password_salt'], user['password_hash']):
        users_collection.update_one(
            {'_id': user['_id']},
            {'$set': {'last_login': dt.datetime.now().isoformat()}}
        )
        return True, "Авторизация успешна!", str(user['_id'])
    return False, "Неверный логин или пароль", None


def _get_current_user_id():
    try:
        return app.storage.user.get('user_id', '')
    except:
        return ''


def _get_current_username():
    try:
        return app.storage.user.get('username', '')
    except:
        return ''


# ═══════════════════════════════════════════
# ML УТИЛИТЫ
# ═══════════════════════════════════════════
def find_col(df, candidates):
    cols = list(df.columns)
    lower_map = {c.lower(): c for c in cols}
    for cand in candidates:
        if cand in cols: return cand
        if str(cand).lower() in lower_map: return lower_map[str(cand).lower()]
    for cand in candidates:
        cl = str(cand).lower()
        for col in cols:
            if cl in col.lower(): return col
    return None


def label_to_binary(df):
    if "label" not in df.columns: return None
    s = df["label"].astype(str).str.lower().str.strip()
    return (~s.str.contains("normal|benign", regex=True)).astype(int).values


def classify_attack_type(row):
    if row.get('anomaly', 0) == 0: return "Нормально"
    def sf(v, d=0):
        try:
            if pd.isna(v) or v is None: return d
            return float(v)
        except: return d
    def si(v, d=0):
        try:
            if pd.isna(v) or v is None: return d
            return int(float(v))
        except: return d

    count = sf(row.get('count',0)); srv_count = sf(row.get('srv_count',0))
    serror = sf(row.get('serror_rate',0)); diff_srv = sf(row.get('diff_srv_rate',0))
    same_srv = sf(row.get('same_srv_rate',0)); num_failed = si(row.get('num_failed_logins',0))
    dst_port = si(row.get('dst_port', row.get('Destination Port',0)))
    protocol = str(row.get('protocol', row.get('Protocol',''))).lower()
    length = si(row.get('Length', row.get('frame_len', row.get('src_bytes',0))))
    info = str(row.get('Info','')).lower()
    service = str(row.get('service','')).lower()
    if not service or service in ('other','nan'):
        service = PORT_SERVICES.get(dst_port, 'other').lower()

    if 'syn' in info and 'ack' not in info: return "Сканирование портов"
    if dst_port > 1024 and length < 100 and 'tcp' in protocol: return "Сканирование портов"
    if diff_srv > 0.5 or (srv_count > 10 and diff_srv > 0.3): return "Сканирование портов"
    if service in ('ssh','ftp','telnet','rdp','smb'):
        if num_failed > 3: return "Брутфорс"
        if same_srv > 0.8 and count > 10: return "Брутфорс"
    if dst_port in (22,21,23,3389,445) and length < 500: return "Брутфорс"
    if count > 100 or srv_count > 50: return "DDoS / Флуд"
    if serror > 0.8 and count > 50: return "DDoS / Флуд"
    if service in ('http','https') or dst_port in (80,443,8080):
        if length > 2000: return "SQL Injection"
    if length > 10000: return "Утечка данных"
    if sf(row.get('dst_bytes',0)) > 50000: return "Утечка данных"
    suspicious_ports = {4444,5555,6666,1337,31337,12345,54321,9001,6667}
    if dst_port in suspicious_ports: return "Вредоносное ПО"
    if si(row.get('num_shells',0)) > 0 or si(row.get('root_shell',0)) > 0: return "Вредоносное ПО"
    if si(row.get('su_attempted',0)) > 0: return "Повышение привилегий"
    if si(row.get('num_compromised',0)) > 0: return "Несанкц. доступ"
    if 'icmp' in protocol: return "Разведка"
    if serror > 0.3: return "Разведка"
    if dst_port == 53 or service == 'dns':
        return "DNS туннелирование" if length > 512 else "DNS атака"
    return "Подозр. активность"


def add_severity(df):
    df = df.copy()
    if "severity" in df.columns: df = df.drop(columns=["severity"])
    df["severity"] = "Нормально"
    if "anomaly" not in df.columns or "anomaly_score" not in df.columns: return df
    anom = df[df["anomaly"] == 1]
    if len(anom) == 0: return df
    q_high = anom["anomaly_score"].quantile(0.98)
    q_med = anom["anomaly_score"].quantile(0.90)
    df.loc[(df["anomaly"]==1)&(df["anomaly_score"]>=q_high), "severity"] = "Критическая"
    df.loc[(df["anomaly"]==1)&(df["anomaly_score"]>=q_med)&(df["anomaly_score"]<q_high), "severity"] = "Высокая"
    df.loc[(df["anomaly"]==1)&(df["anomaly_score"]<q_med), "severity"] = "Средняя"
    return df


def get_preprocessor(X):
    X = X.copy(); MAX_CARD = 50
    exclude_patterns = ["_ip","src_ip","dst_ip","srcip","dstip","ip_src","ip_dst","timestamp","time","date"]
    exclude_cols = []
    for col in X.columns:
        cl = col.lower()
        for p in exclude_patterns:
            if p in cl: exclude_cols.append(col); break
        if col not in exclude_cols:
            try:
                sample = X[col].dropna().head(100).astype(str)
                if sample.str.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$').sum() > 50: exclude_cols.append(col)
            except: pass
    X_clean = X.drop(columns=[c for c in exclude_cols if c in X.columns], errors='ignore')
    cat_cols = X_clean.select_dtypes(include=["object","category","bool"]).columns.tolist()
    for c in ["proto","protocol","protocol_type","service","flag","state"]:
        if c in X_clean.columns and c not in cat_cols: cat_cols.append(c)
    cols_to_remove = [c for c in cat_cols if c in X_clean.columns and X_clean[c].nunique() > MAX_CARD]
    for c in cols_to_remove: cat_cols.remove(c); X_clean = X_clean.drop(columns=[c], errors='ignore')
    for col in X_clean.columns:
        if col in cat_cols: X_clean[col] = X_clean[col].fillna('missing').astype(str)
        else:
            try: X_clean[col] = pd.to_numeric(X_clean[col], errors='coerce')
            except:
                if X_clean[col].nunique() <= MAX_CARD: cat_cols.append(col); X_clean[col] = X_clean[col].fillna('missing').astype(str)
                else: X_clean = X_clean.drop(columns=[col], errors='ignore')
    num_cols = [c for c in X_clean.columns if c not in cat_cols]
    verified = []
    for c in num_cols:
        if c in X_clean.columns:
            if X_clean[c].dtype in ['int64','float64','int32','float32']: verified.append(c)
            else:
                try: X_clean[c] = pd.to_numeric(X_clean[c], errors='coerce'); verified.append(c)
                except:
                    if X_clean[c].nunique() <= MAX_CARD: cat_cols.append(c)
    num_cols = verified or [c for c in X_clean.columns if c not in cat_cols]
    transformers = []
    if num_cols: transformers.append(("num", Pipeline([("imp", SimpleImputer(strategy="median")),("sc", StandardScaler())]), num_cols))
    if cat_cols: transformers.append(("cat", Pipeline([("imp", SimpleImputer(strategy="constant", fill_value="missing")),("oh", OneHotEncoder(handle_unknown="ignore", sparse_output=False, max_categories=50))]), cat_cols))
    return ColumnTransformer(transformers, remainder="drop"), num_cols, cat_cols


def build_pipeline(cont, trees, X, model_type="isolation_forest", params=None):
    pre, _, _ = get_preprocessor(X)
    models = {
        "isolation_forest": lambda: IsolationForest(n_estimators=trees, contamination=cont, random_state=42, n_jobs=-1),
        "lof": lambda: LocalOutlierFactor(n_neighbors=20, contamination=cont, novelty=True, n_jobs=-1),
        "ocsvm": lambda: OneClassSVM(nu=cont, kernel='rbf', gamma='auto'),
    }
    if model_type == "autoencoder" and TENSORFLOW_AVAILABLE:
        return {'preprocessor': pre, 'model_type': 'autoencoder', 'contamination': cont, 'params': params or {}}
    model = models.get(model_type, models["isolation_forest"])()
    return Pipeline([("pre", pre), ("model", model)])


def build_supervised_pipeline(X, model_type="random_forest", params=None):
    pre, _, _ = get_preprocessor(X); p = params or {}
    builders = {
        "random_forest": lambda: RandomForestClassifier(n_estimators=p.get('n_estimators',100), max_depth=p.get('max_depth',20), class_weight='balanced', random_state=42, n_jobs=-1),
        "gradient_boosting": lambda: GradientBoostingClassifier(n_estimators=p.get('n_estimators',100), max_depth=p.get('max_depth',5), learning_rate=p.get('learning_rate',0.1), random_state=42),
        "adaboost": lambda: AdaBoostClassifier(n_estimators=p.get('n_estimators',50), learning_rate=p.get('learning_rate',1.0), random_state=42),
    }
    if model_type == "xgboost" and XGBOOST_AVAILABLE:
        builders["xgboost"] = lambda: XGBClassifier(n_estimators=p.get('n_estimators',100), max_depth=p.get('max_depth',6), learning_rate=p.get('learning_rate',0.1), use_label_encoder=False, eval_metric='logloss', random_state=42, n_jobs=-1)
    if model_type == "lightgbm" and LIGHTGBM_AVAILABLE:
        builders["lightgbm"] = lambda: LGBMClassifier(n_estimators=p.get('n_estimators',100), max_depth=p.get('max_depth',-1), learning_rate=p.get('learning_rate',0.1), class_weight='balanced', random_state=42, n_jobs=-1, verbose=-1)
    model = builders.get(model_type, builders["random_forest"])()
    return Pipeline([("pre", pre), ("model", model)])


def get_feature_importance(pipeline, X):
    pre, num_cols, cat_cols = get_preprocessor(X)
    model = pipeline.named_steps['model']
    if not hasattr(model, 'feature_importances_'): return None
    imp = model.feature_importances_
    names = list(num_cols)
    try:
        preprocessor = pipeline.named_steps['pre']
        if hasattr(preprocessor, 'transformers_'):
            for name, transformer, cols in preprocessor.transformers_:
                if name == 'cat' and hasattr(transformer, 'named_steps'):
                    ohe = transformer.named_steps.get('oh')
                    if ohe and hasattr(ohe, 'get_feature_names_out'): names.extend(ohe.get_feature_names_out(cat_cols))
    except: pass
    if len(names) == len(imp): return pd.DataFrame({'feature': names, 'importance': imp}).sort_values('importance', ascending=False)
    return pd.DataFrame({'feature': [f'feature_{i}' for i in range(len(imp))], 'importance': imp}).sort_values('importance', ascending=False)


def calc_metrics(y_true, y_pred, y_scores=None):
    m = {}
    if y_true is not None:
        m['accuracy'] = accuracy_score(y_true, y_pred)
        m['precision'] = precision_score(y_true, y_pred, zero_division=0)
        m['recall'] = recall_score(y_true, y_pred, zero_division=0)
        m['f1_score'] = f1_score(y_true, y_pred, zero_division=0)
        if y_scores is not None:
            try: m['roc_auc'] = roc_auc_score(y_true, y_scores)
            except: m['roc_auc'] = None
    return m


class AnomalyAutoencoder:
    def __init__(self, input_dim, encoding_dim=32, contamination=0.1):
        self.input_dim = input_dim; self.encoding_dim = encoding_dim
        self.contamination = contamination; self.model = None; self.threshold = None
    def build_model(self):
        inp = layers.Input(shape=(self.input_dim,))
        x = layers.Dense(128, activation='relu')(inp)
        x = layers.Dropout(0.2)(x)
        x = layers.Dense(64, activation='relu')(x)
        x = layers.Dropout(0.2)(x)
        x = layers.Dense(self.encoding_dim, activation='relu')(x)
        x = layers.Dense(64, activation='relu')(x)
        x = layers.Dropout(0.2)(x)
        x = layers.Dense(128, activation='relu')(x)
        x = layers.Dropout(0.2)(x)
        x = layers.Dense(self.input_dim, activation='sigmoid')(x)
        self.model = Model(inp, x)
        self.model.compile(optimizer='adam', loss='mse')
        return self.model
    def fit(self, X, epochs=50, batch_size=256):
        if not self.model: self.build_model()
        self.model.fit(X, X, epochs=epochs, batch_size=batch_size, validation_split=0.1,
                       callbacks=[EarlyStopping(patience=5, restore_best_weights=True)], verbose=0)
        recon = self.model.predict(X, verbose=0)
        mse = np.mean(np.power(X - recon, 2), axis=1)
        self.threshold = np.percentile(mse, (1-self.contamination)*100)
    def predict(self, X):
        recon = self.model.predict(X, verbose=0)
        mse = np.mean(np.power(X - recon, 2), axis=1)
        return (mse > self.threshold).astype(int)
    def reconstruction_error(self, X):
        recon = self.model.predict(X, verbose=0)
        return np.mean(np.power(X - recon, 2), axis=1)


def read_csv_data(content, filename):
    for enc in ['utf-8','latin-1','cp1252']:
        try: df = pd.read_csv(io.BytesIO(content), encoding=enc); break
        except: continue
    else: raise Exception("Не удалось прочитать CSV")
    df = df.loc[:, ~df.columns.astype(str).str.startswith("Unnamed")].copy()
    df = df.dropna(axis=1, how="all")
    df.columns = [str(c).strip() for c in df.columns]
    if df.shape[1] == 41: df.columns = KDD_COLUMNS
    elif df.shape[1] == 42: df.columns = KDD_COLUMNS + ["label"]
    X = df.drop(columns=["label"], errors="ignore")
    return df, X


# ═══════════════════════════════════════════
# WIRESHARK CAPTURE
# ═══════════════════════════════════════════
def get_packet_info(packet):
    info = {'no': 0, 'time': 0.0, 'source': '', 'destination': '',
        'protocol': '', 'length': len(packet), 'info': '',
        'src_port': 0, 'dst_port': 0, 'flags': '', 'ttl': 0,
        'raw_hex': '', 'layers': []}
    try: info['raw_hex'] = bytes(packet).hex()[:200]
    except: pass
    if IP in packet:
        info['source'] = packet[IP].src; info['destination'] = packet[IP].dst
        info['ttl'] = packet[IP].ttl
        info['layers'].append(f"IPv4, Src: {packet[IP].src}, Dst: {packet[IP].dst}")
        if TCP in packet:
            sport = packet[TCP].sport; dport = packet[TCP].dport
            info['src_port'] = sport; info['dst_port'] = dport
            flags = str(packet[TCP].flags); info['flags'] = flags
            if dport == 80 or sport == 80: info['protocol'] = 'HTTP'
            elif dport == 443 or sport == 443: info['protocol'] = 'TLS'
            elif dport == 22 or sport == 22: info['protocol'] = 'SSH'
            elif dport == 21 or sport == 21: info['protocol'] = 'FTP'
            elif dport == 53 or sport == 53: info['protocol'] = 'DNS'
            else: info['protocol'] = 'TCP'
            seq = packet[TCP].seq; ack_n = packet[TCP].ack; win = packet[TCP].window
            info['info'] = f"{sport} → {dport} [{flags}] Seq={seq} Ack={ack_n} Win={win} Len={len(packet[TCP].payload)}"
            if 'S' in flags and 'A' not in flags: info['protocol'] = 'SYN'
            elif 'R' in flags: info['protocol'] = 'RST'
            elif 'F' in flags: info['protocol'] = 'FIN'
        elif UDP in packet:
            sport = packet[UDP].sport; dport = packet[UDP].dport
            info['src_port'] = sport; info['dst_port'] = dport
            if dport == 53 or sport == 53:
                info['protocol'] = 'DNS'
                if DNS in packet:
                    try:
                        qname = packet[DNS].qd.qname.decode() if packet[DNS].qd else ''
                        qtype = 'query' if packet[DNS].qr == 0 else 'response'
                        info['info'] = f"DNS {qtype}: {qname}"
                    except: info['info'] = f"{sport} → {dport} UDP"
                else: info['info'] = f"{sport} → {dport} DNS"
            else:
                info['protocol'] = 'UDP'
                info['info'] = f"{sport} → {dport} UDP Len={len(packet[UDP].payload)}"
        elif ICMP in packet:
            info['protocol'] = 'ICMP'
            t = packet[ICMP].type
            types_map = {0: 'Echo Reply', 8: 'Echo Request', 3: 'Dest Unreachable', 11: 'Time Exceeded'}
            info['info'] = f"ICMP {types_map.get(t, f'Type={t}')} code={packet[ICMP].code}"
        else:
            info['protocol'] = f'IP({packet[IP].proto})'; info['info'] = f"IP Protocol {packet[IP].proto}"
    else:
        info['protocol'] = packet.lastlayer().__class__.__name__
        info['info'] = f"{info['protocol']} packet, {len(packet)} bytes"
    return info


def start_capture(bpf_filter="", iface=None, count=0):
    state.capture_running = True; state.capture_packets = []
    state.packet_counter = 0; state.capture_start_time = time.time()
    def _capture():
        def callback(pkt):
            if not state.capture_running: return
            state.packet_counter += 1
            info = get_packet_info(pkt)
            info['no'] = state.packet_counter
            info['time'] = round(time.time() - state.capture_start_time, 6)
            state.capture_packets.append(info)
        try:
            kwargs = {'prn': callback, 'store': False}
            if bpf_filter: kwargs['filter'] = bpf_filter
            if iface and iface != 'any': kwargs['iface'] = iface
            if count > 0: kwargs['count'] = count
            else: kwargs['timeout'] = 600
            sniff(**kwargs)
        except Exception as e: print(f"Capture error: {e}")
        finally: state.capture_running = False
    state.capture_thread = threading.Thread(target=_capture, daemon=True)
    state.capture_thread.start()


def stop_capture():
    state.capture_running = False
    if state.capture_thread: state.capture_thread.join(timeout=2)


# ═══════════════════════════════════════════
# PLOTLY DARK THEME
# ═══════════════════════════════════════════
PLOTLY_LAYOUT = dict(
    paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
    font=dict(color='#94a3b8', family='JetBrains Mono, monospace', size=11),
    margin=dict(l=40, r=20, t=40, b=40),
    xaxis=dict(gridcolor='#1e293b', zerolinecolor='#1e293b'),
    yaxis=dict(gridcolor='#1e293b', zerolinecolor='#1e293b'),
    legend=dict(bgcolor='rgba(0,0,0,0)', font=dict(size=10)),
)

SEVERITY_COLORS = {'Критическая': '#dc2626', 'Высокая': '#f97316', 'Средняя': '#eab308', 'Нормально': '#22c55e'}
ATTACK_COLORS = ['#6366f1','#f43f5e','#f97316','#eab308','#22d3ee','#a855f7','#ec4899','#14b8a6','#84cc16','#64748b']


# ═══════════════════════════════════════════
# CSS СТИЛИ
# ═══════════════════════════════════════════
CUSTOM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&display=swap');

:root {
    --bg-base: #0c0e14;
    --bg-surface: #111318;
    --bg-card: #161921;
    --bg-elevated: #1c1f2b;
    --border: #1e2433;
    --border-hover: #2d3548;
    --text-primary: #e2e8f0;
    --text-secondary: #94a3b8;
    --text-muted: #475569;
    --accent: #6366f1;
    --accent-hover: #818cf8;
}

body, .q-page, .q-layout, .q-page-container {
    background: var(--bg-base) !important;
    font-family: 'JetBrains Mono', 'SF Mono', monospace !important;
}

/* Scrollbar */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg-base); }
::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #334155; }

/* Header */
.soc-header {
    background: var(--bg-surface) !important;
    border-bottom: 1px solid var(--border) !important;
    backdrop-filter: blur(12px);
}
.soc-header .q-toolbar { min-height: 48px !important; }

/* Sidebar / Drawer */
.soc-sidebar {
    background: var(--bg-surface) !important;
    border-right: 1px solid var(--border) !important;
}
.soc-sidebar .q-item {
    border-radius: 8px !important;
    margin: 2px 8px !important;
    min-height: 40px !important;
    padding: 4px 12px !important;
    color: var(--text-muted) !important;
    transition: all 0.15s ease !important;
}
.soc-sidebar .q-item:hover {
    background: rgba(99, 102, 241, 0.08) !important;
    color: var(--text-secondary) !important;
}
.soc-sidebar .q-item--active, .soc-sidebar .q-item.active-nav {
    background: rgba(99, 102, 241, 0.15) !important;
    color: #818cf8 !important;
    border: 1px solid rgba(99, 102, 241, 0.2) !important;
}
.soc-sidebar .q-item__label { font-size: 12px !important; font-weight: 500 !important; }
.soc-sidebar .q-icon { font-size: 18px !important; }

/* Cards */
.soc-card {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: 12px !important;
    box-shadow: none !important;
}
.soc-card .q-card__section { padding: 20px !important; }

/* Metric card */
.metric-card {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: 12px !important;
    padding: 16px 20px !important;
    box-shadow: none !important;
}
.metric-card.accent-indigo { border-color: rgba(99, 102, 241, 0.2) !important; background: linear-gradient(135deg, rgba(99,102,241,0.08), rgba(99,102,241,0.03)) !important; }
.metric-card.accent-red { border-color: rgba(239, 68, 68, 0.2) !important; background: linear-gradient(135deg, rgba(239,68,68,0.08), rgba(239,68,68,0.03)) !important; }
.metric-card.accent-amber { border-color: rgba(245, 158, 11, 0.2) !important; background: linear-gradient(135deg, rgba(245,158,11,0.08), rgba(245,158,11,0.03)) !important; }
.metric-card.accent-emerald { border-color: rgba(16, 185, 129, 0.2) !important; background: linear-gradient(135deg, rgba(16,185,129,0.08), rgba(16,185,129,0.03)) !important; }
.metric-card.accent-cyan { border-color: rgba(6, 182, 212, 0.2) !important; background: linear-gradient(135deg, rgba(6,182,212,0.08), rgba(6,182,212,0.03)) !important; }
.metric-card.accent-purple { border-color: rgba(168, 85, 247, 0.2) !important; background: linear-gradient(135deg, rgba(168,85,247,0.08), rgba(168,85,247,0.03)) !important; }

/* Tables */
.soc-table .q-table__top, .soc-table .q-table__bottom { background: transparent !important; }
.soc-table thead tr th {
    background: var(--bg-elevated) !important;
    color: var(--text-muted) !important;
    font-size: 11px !important;
    font-weight: 600 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.5px !important;
    border-bottom: 1px solid var(--border) !important;
    padding: 10px 14px !important;
}
.soc-table tbody tr td {
    color: var(--text-secondary) !important;
    font-size: 12px !important;
    border-bottom: 1px solid rgba(30,36,51,0.5) !important;
    padding: 8px 14px !important;
}
.soc-table tbody tr:hover td { background: rgba(99, 102, 241, 0.05) !important; }
.soc-table { background: var(--bg-surface) !important; border: 1px solid var(--border) !important; border-radius: 12px !important; overflow: hidden !important; }

/* Badges */
.severity-badge {
    display: inline-flex; align-items: center; padding: 2px 10px;
    border-radius: 999px; font-size: 10px; font-weight: 600;
    border: 1px solid transparent; letter-spacing: 0.3px;
}
.sev-critical { background: rgba(220,38,38,0.15); color: #f87171; border-color: rgba(220,38,38,0.3); }
.sev-high { background: rgba(249,115,22,0.15); color: #fb923c; border-color: rgba(249,115,22,0.3); }
.sev-medium { background: rgba(234,179,8,0.15); color: #facc15; border-color: rgba(234,179,8,0.3); }
.sev-normal { background: rgba(34,197,94,0.15); color: #4ade80; border-color: rgba(34,197,94,0.3); }

.status-badge {
    display: inline-flex; align-items: center; padding: 2px 10px;
    border-radius: 999px; font-size: 10px; font-weight: 600; border: 1px solid transparent;
}
.status-new { background: rgba(59,130,246,0.15); color: #60a5fa; border-color: rgba(59,130,246,0.3); }
.status-working { background: rgba(245,158,11,0.15); color: #fbbf24; border-color: rgba(245,158,11,0.3); }
.status-closed { background: rgba(100,116,139,0.15); color: #94a3b8; border-color: rgba(100,116,139,0.3); }

/* Buttons */
.soc-btn {
    border-radius: 8px !important; font-size: 12px !important;
    font-weight: 600 !important; letter-spacing: 0.3px !important;
    text-transform: none !important; padding: 6px 16px !important;
}

/* Upload */
.soc-upload .q-uploader { background: var(--bg-card) !important; border: 2px dashed var(--border) !important; border-radius: 12px !important; }
.soc-upload .q-uploader:hover { border-color: rgba(99,102,241,0.4) !important; }

/* Input */
.soc-input .q-field__control { background: var(--bg-surface) !important; border: 1px solid var(--border) !important; border-radius: 8px !important; }
.soc-input .q-field__native, .soc-input .q-field__label { color: var(--text-secondary) !important; font-size: 12px !important; }

/* Log panel */
.soc-log {
    background: #0a0c10 !important; border: 1px solid var(--border) !important;
    border-radius: 10px !important; font-family: 'JetBrains Mono', monospace !important;
    font-size: 11px !important; color: var(--text-muted) !important;
    padding: 12px !important;
}

/* Expansion */
.soc-expansion .q-expansion-item__container { background: var(--bg-surface) !important; border: 1px solid var(--border) !important; border-radius: 10px !important; margin-bottom: 8px !important; }
.soc-expansion .q-item { color: var(--text-primary) !important; }

/* Model selector cards */
.model-card {
    background: var(--bg-surface) !important; border: 1px solid var(--border) !important;
    border-radius: 10px !important; padding: 12px !important; cursor: pointer;
    transition: all 0.15s ease !important;
}
.model-card:hover { border-color: var(--border-hover) !important; }
.model-card.selected {
    background: rgba(99, 102, 241, 0.1) !important;
    border-color: rgba(99, 102, 241, 0.4) !important;
    box-shadow: 0 0 0 1px rgba(99,102,241,0.15) !important;
}

/* Slider */
.soc-slider .q-slider__track { background: #1e293b !important; }
.soc-slider .q-slider__inner { background: #6366f1 !important; }
.soc-slider .q-slider__thumb { color: #6366f1 !important; }

/* Plotly */
.js-plotly-plot { border-radius: 8px; }

/* Page section title */
.page-title { color: var(--text-primary); font-size: 22px; font-weight: 700; letter-spacing: -0.3px; }
.page-subtitle { color: var(--text-muted); font-size: 12px; margin-top: 4px; }

/* Section title */
.section-title { color: var(--text-secondary); font-size: 13px; font-weight: 600; }

/* Separator */
.q-separator { background: var(--border) !important; }

/* Code block */
.soc-code { background: #0a0c10 !important; border: 1px solid var(--border) !important; border-radius: 8px !important; padding: 12px !important; font-size: 11px !important; }

/* Notification */
.q-notification { border-radius: 10px !important; }

/* Tabs (for sub-tabs) */
.soc-tabs .q-tab { color: var(--text-muted) !important; font-size: 12px !important; text-transform: none !important; }
.soc-tabs .q-tab--active { color: var(--accent) !important; }
.soc-tabs .q-tab__indicator { background: var(--accent) !important; }
</style>
"""


# ═══════════════════════════════════════════
# УТИЛИТЫ UI
# ═══════════════════════════════════════════
def severity_html(sev):
    cls = {'Критическая':'sev-critical','Высокая':'sev-high','Средняя':'sev-medium','Нормально':'sev-normal'}.get(sev,'sev-medium')
    return f'<span class="severity-badge {cls}">{sev}</span>'

def status_html(st):
    cls = {'Новый':'status-new','В работе':'status-working','Закрыт':'status-closed','Ложное срабатывание':'status-closed'}.get(st,'status-new')
    return f'<span class="status-badge {cls}">{st}</span>'

def metric_card(label, value, accent='indigo', icon='', sub=''):
    with ui.element('div').classes(f'metric-card accent-{accent}'):
        with ui.row().classes('justify-between items-center'):
            ui.label(label).style('font-size:10px; text-transform:uppercase; letter-spacing:0.8px; color:#64748b; font-weight:600;')
            if icon:
                ui.label(icon).style('font-size:14px;')
        ui.label(str(value)).style('font-size:24px; font-weight:700; color:#e2e8f0; margin-top:4px; letter-spacing:-0.5px;')
        if sub:
            ui.label(sub).style('font-size:10px; color:#475569; margin-top:2px;')


# ═══════════════════════════════════════════
# CSS ДЛЯ СТРАНИЦЫ АВТОРИЗАЦИИ
# ═══════════════════════════════════════════
LOGIN_CSS = """
<style>
.login-bg {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #0c0e14;
}
.login-card {
    background: #161921;
    border: 1px solid #1e2433;
    border-radius: 20px;
    padding: 48px 40px;
    width: 400px;
    box-shadow: 0 25px 80px rgba(0,0,0,0.4);
}
.login-logo {
    width: 56px; height: 56px;
    border-radius: 14px;
    background: linear-gradient(135deg, #6366f1, #a855f7);
    display: flex; align-items: center; justify-content: center;
    margin: 0 auto 20px auto;
    font-size: 24px; color: white;
}
.login-title {
    font-size: 22px; font-weight: 700; color: #e2e8f0;
    text-align: center; letter-spacing: -0.3px;
    font-family: 'JetBrains Mono', monospace;
}
.login-subtitle {
    font-size: 12px; color: #475569;
    text-align: center; margin-top: 6px; margin-bottom: 28px;
    font-family: 'JetBrains Mono', monospace;
}
.login-input .q-field__control {
    background: #111318 !important;
    border: 1px solid #1e2433 !important;
    border-radius: 10px !important;
}
.login-input .q-field__control:focus-within {
    border-color: rgba(99, 102, 241, 0.5) !important;
}
.login-input .q-field__native {
    color: #e2e8f0 !important;
    font-size: 13px !important;
    font-family: 'JetBrains Mono', monospace !important;
}
.login-input .q-field__label {
    color: #64748b !important;
    font-size: 12px !important;
    font-family: 'JetBrains Mono', monospace !important;
}
.login-btn {
    width: 100%; height: 44px !important;
    border-radius: 10px !important;
    font-size: 13px !important;
    font-weight: 600 !important;
    text-transform: none !important;
    letter-spacing: 0.3px !important;
    font-family: 'JetBrains Mono', monospace !important;
}
.login-toggle {
    font-size: 12px; color: #475569;
    text-align: center; margin-top: 20px;
    font-family: 'JetBrains Mono', monospace;
}
.login-link {
    color: #6366f1 !important;
    cursor: pointer;
    font-weight: 600;
}
.login-link:hover { color: #818cf8 !important; }
.login-error {
    background: rgba(239,68,68,0.1);
    border: 1px solid rgba(239,68,68,0.3);
    border-radius: 8px;
    padding: 10px 14px;
    font-size: 12px;
    color: #f87171;
    text-align: center;
    font-family: 'JetBrains Mono', monospace;
}
.login-success {
    background: rgba(34,197,94,0.1);
    border: 1px solid rgba(34,197,94,0.3);
    border-radius: 8px;
    padding: 10px 14px;
    font-size: 12px;
    color: #4ade80;
    text-align: center;
    font-family: 'JetBrains Mono', monospace;
}
.login-divider {
    height: 1px;
    background: #1e2433;
    margin: 20px 0;
}
</style>
"""


# ═══════════════════════════════════════════
# NICEGUI — СТРАНИЦА АВТОРИЗАЦИИ
# ═══════════════════════════════════════════
@ui.page('/login')
def login_page():
    ui.add_head_html(CUSTOM_CSS)
    ui.add_head_html(LOGIN_CSS)
    ui.dark_mode().enable()

    if app.storage.user.get('authenticated'):
        ui.navigate.to('/')
        return

    mode = {'register': False}

    with ui.element('div').classes('login-bg'):
        with ui.element('div').classes('login-card'):
            ui.html('<div class="login-logo">🛡️</div>')

            form_container = ui.column().classes('w-full')

            def build_form():
                form_container.clear()
                with form_container:
                    if mode['register']:
                        ui.label('Регистрация').classes('login-title')
                        ui.label('Создайте новый аккаунт').classes('login-subtitle')
                    else:
                        ui.label('Вход в SOC Analyzer').classes('login-title')
                        ui.label('Введите логин и пароль для входа').classes('login-subtitle')

                    login_input = ui.input(label='Логин').classes('login-input w-full').props('outlined')
                    pass_input = ui.input(label='Пароль', password=True, password_toggle_button=True).classes('login-input w-full').props('outlined')

                    result_area = ui.column().classes('w-full')

                    async def submit():
                        result_area.clear()
                        uname = (login_input.value or '').strip()
                        pwd = pass_input.value or ''

                        if not uname or not pwd:
                            with result_area:
                                ui.html('<div class="login-error">Заполните все поля</div>')
                            return

                        if mode['register']:
                            try:
                                ok, message = register_user(uname, pwd)
                            except Exception as ex:
                                with result_area:
                                    ui.html(f'<div class="login-error">Ошибка: {ex}</div>')
                                return
                            if ok:
                                with result_area:
                                    ui.html(f'<div class="login-success">{message} Теперь войдите.</div>')
                                mode['register'] = False
                                await asyncio.sleep(1.5)
                                build_form()
                            else:
                                with result_area:
                                    ui.html(f'<div class="login-error">{message}</div>')
                        else:
                            try:
                                ok, message, user_id = authenticate_user(uname, pwd)
                            except Exception as ex:
                                with result_area:
                                    ui.html(f'<div class="login-error">Ошибка: {ex}</div>')
                                return
                            if ok:
                                app.storage.user['authenticated'] = True
                                app.storage.user['username'] = uname
                                app.storage.user['user_id'] = user_id
                                with result_area:
                                    ui.html(f'<div class="login-success">{message}</div>')
                                ui.navigate.to('/')
                            else:
                                with result_area:
                                    ui.html(f'<div class="login-error">{message}</div>')

                    btn_text = 'Зарегистрироваться' if mode['register'] else 'Войти'
                    ui.button(btn_text, on_click=submit).classes('login-btn').props('color=indigo unelevated no-caps')

                    pass_input.on('keydown.enter', submit)

                    ui.html('<div class="login-divider"></div>')

                    def toggle():
                        mode['register'] = not mode['register']
                        build_form()

                    toggle_text = 'Уже есть аккаунт? Войти' if mode['register'] else 'Нет аккаунта? Зарегистрироваться'
                    ui.button(toggle_text, on_click=toggle).props('flat no-caps').style(
                        'width:100%; color:#6366f1; font-size:12px; font-weight:600; text-transform:none;'
                    )

            build_form()

            ui.html('<div style="text-align:center; margin-top:24px; font-size:10px; color:#334155; font-family:JetBrains Mono, monospace;">SOC Analyzer v7.0 · MongoDB Auth</div>')


# ═══════════════════════════════════════════
# NICEGUI — ГЛАВНАЯ СТРАНИЦА
# ═══════════════════════════════════════════
@ui.page('/')
def main_page():
    if not app.storage.user.get('authenticated'):
        ui.navigate.to('/login')
        return

    ui.add_head_html(CUSTOM_CSS)
    ui.dark_mode().enable()

    current_user = app.storage.user.get('username', '?')
    user_initial = current_user[0].upper() if current_user else 'U'

    current_page = {'value': 'dashboard'}

    # ── HEADER ──
    with ui.header().classes('soc-header items-center justify-between px-4'):
        with ui.row().classes('items-center gap-3 no-wrap'):
            ui.icon('shield', size='sm').style('color:#6366f1;')
            ui.label('SOC Analyzer').style('font-size:14px; font-weight:700; color:#e2e8f0; letter-spacing:-0.3px;')
            ui.html('<span style="font-size:9px; padding:2px 8px; background:rgba(99,102,241,0.2); color:#818cf8; border-radius:4px; font-weight:700;">v7.0</span>')
        with ui.row().classes('items-center gap-2 no-wrap'):
            ui.input(placeholder='Поиск...').props('dense borderless').classes('soc-input').style('width:180px; font-size:12px;')
            try:
                s = get_db_stats()
                if s['alerts_unread'] > 0:
                    ui.badge(str(s['alerts_unread']), color='red').props('floating')
            except: pass
            ui.icon('notifications', size='sm').style('color:#64748b; cursor:pointer;')
            ui.label(current_user).style('font-size:11px; color:#94a3b8; font-family:monospace;')
            ui.html(f'<div style="width:28px; height:28px; border-radius:50%; background:linear-gradient(135deg,#6366f1,#a855f7); display:flex; align-items:center; justify-content:center; font-size:10px; font-weight:700; color:white;">{user_initial}</div>')

            def logout():
                app.storage.user.clear()
                ui.navigate.to('/login')
            ui.button('Выйти', on_click=logout).props('flat dense no-caps size=sm').style('color:#64748b; font-size:11px;')

    # ── SIDEBAR ──
    with ui.left_drawer(value=True, fixed=True, bordered=False).classes('soc-sidebar').style('width:200px; padding-top:8px;') as drawer:
        nav_items = [
            ('dashboard', 'space_dashboard', 'Дашборд'),
            ('analysis', 'psychology', 'Анализ'),
            ('capture', 'sensors', 'Захват'),
            ('incidents', 'warning', 'Инциденты'),
            ('ips', 'language', 'IP-адреса'),
            ('stats', 'bar_chart', 'Статистика'),
            ('database', 'storage', 'База данных'),
            ('settings', 'settings', 'Настройки'),
        ]
        nav_buttons = {}
        for key, icon, label in nav_items:
            item = ui.item(on_click=lambda k=key: navigate(k)).classes('active-nav' if key == 'dashboard' else '')
            with item:
                with ui.item_section().props('side'):
                    ui.icon(icon, size='xs')
                with ui.item_section():
                    ui.item_label(label)
            nav_buttons[key] = item

    # ── CONTENT CONTAINER ──
    content = ui.column().classes('w-full p-6').style('min-height: calc(100vh - 48px);')

    # ── NAVIGATE FUNCTION ──
    def navigate(page_key):
        current_page['value'] = page_key
        # Update active class
        for k, btn in nav_buttons.items():
            if k == page_key:
                btn.classes(add='active-nav')
            else:
                btn.classes(remove='active-nav')
        content.clear()
        with content:
            pages[page_key]()

    # ════════════════════════════════════════════
    # PAGE: ДАШБОРД
    # ════════════════════════════════════════════
    def page_dashboard():
        ui.label('Центр мониторинга безопасности').classes('page-title')
        ui.label('Обзор текущего состояния системы и последних событий').classes('page-subtitle')

        ui.space().style('height:16px')

        # Метрики
        with ui.row().classes('w-full gap-4'):
            with ui.column().classes('flex-1'):
                records = len(state.raw_df) if state.raw_df is not None else 0
                metric_card('Загружено записей', f'{records:,}', 'indigo', '📊', 'Текущий датасет')
            with ui.column().classes('flex-1'):
                anoms = int(state.result_df['anomaly'].sum()) if state.has_results else 0
                metric_card('Обнаружено аномалий', f'{anoms:,}', 'red', '⚠️', f'{100*anoms/max(records,1):.2f}% от общего' if records else '')
            with ui.column().classes('flex-1'):
                try: s = get_db_stats(); metric_card('Инцидентов в БД', f'{s["incidents"]:,}', 'amber', '🔔', f'Новых: {s["incidents_new"]}')
                except: metric_card('Инцидентов в БД', '0', 'amber', '🔔')
            with ui.column().classes('flex-1'):
                try: s = get_db_stats(); metric_card('IP в Blacklist', str(s['blacklist']), 'purple', '🔒', 'Заблокировано')
                except: metric_card('IP в Blacklist', '0', 'purple', '🔒')

        ui.space().style('height:16px')

        with ui.row().classes('w-full gap-4'):
            # Распределение атак
            with ui.card().classes('soc-card flex-[2]'):
                ui.label('Распределение атак').classes('section-title')
                if state.has_results:
                    anom = state.result_df[state.result_df['anomaly'] == 1]
                    if len(anom) > 0:
                        ad = anom['attack_type'].value_counts()
                        fig = px.bar(x=ad.values, y=ad.index, orientation='h',
                                     color=ad.index, color_discrete_sequence=ATTACK_COLORS)
                        fig.update_layout(**PLOTLY_LAYOUT, showlegend=False, height=320)
                        fig.update_traces(marker_line_width=0)
                        ui.plotly(fig).classes('w-full')
                    else:
                        ui.label('Аномалий не обнаружено').style('color:#475569; margin-top:20px;')
                else:
                    ui.label('Выполните анализ для отображения данных').style('color:#475569; margin-top:20px;')

            # Severity
            with ui.card().classes('soc-card flex-1'):
                ui.label('Severity').classes('section-title')
                if state.has_results:
                    anom = state.result_df[state.result_df['anomaly'] == 1]
                    if len(anom) > 0:
                        sd = anom['severity'].value_counts()
                        fig = px.pie(values=sd.values, names=sd.index,
                                     color=sd.index, color_discrete_map=SEVERITY_COLORS, hole=0.55)
                        fig.update_layout(**PLOTLY_LAYOUT, height=320, showlegend=True,
                                          legend=dict(orientation='h', y=-0.1))
                        fig.update_traces(textposition='inside', textinfo='value', textfont_size=11)
                        ui.plotly(fig).classes('w-full')

        ui.space().style('height:16px')

        with ui.row().classes('w-full gap-4'):
            # Последние инциденты
            with ui.card().classes('soc-card flex-1'):
                ui.label('Последние инциденты').classes('section-title')
                incidents = get_incidents(limit=6)
                if incidents:
                    for inc in incidents[:6]:
                        with ui.row().classes('items-center justify-between w-full py-2 px-3').style('background:rgba(10,12,16,0.5); border-radius:8px; margin-top:6px;'):
                            with ui.row().classes('items-center gap-3 no-wrap'):
                                ui.label(f'#{inc["id"]}').style('font-size:11px; color:#475569; font-family:monospace;')
                                ui.label(inc.get('attack_type', '?')).style('font-size:12px; color:#cbd5e1;')
                            with ui.row().classes('items-center gap-2 no-wrap'):
                                ui.label(inc.get('src_ip', '')).style('font-size:10px; color:#475569; font-family:monospace;')
                                ui.html(severity_html(inc.get('severity', 'Средняя')))
                else:
                    ui.label('Нет инцидентов').style('color:#475569; margin-top:12px;')

            # История анализа
            with ui.card().classes('soc-card flex-1'):
                ui.label('История анализа').classes('section-title')
                sessions = get_analysis_history(6)
                if sessions:
                    for s in sessions[:6]:
                        with ui.row().classes('items-center justify-between w-full py-2 px-3').style('background:rgba(10,12,16,0.5); border-radius:8px; margin-top:6px;'):
                            with ui.column().classes('gap-0'):
                                ui.label(s.get('filename', '?')[:30]).style('font-size:12px; color:#cbd5e1;')
                                ui.label(f'{s.get("model_type","")} · {(s.get("total_records",0) or 0):,} записей').style('font-size:10px; color:#475569;')
                            with ui.column().classes('items-end gap-0'):
                                ui.label(f'{(s.get("total_anomalies",0) or 0):,}').style('font-size:12px; color:#fbbf24; font-family:monospace;')
                                f1 = s.get('f1_score')
                                ui.label(f'F1: {f1:.4f}' if f1 else '').style('font-size:10px; color:#475569;')
                else:
                    ui.label('Нет данных').style('color:#475569; margin-top:12px;')

    # ════════════════════════════════════════════
    # PAGE: АНАЛИЗ
    # ════════════════════════════════════════════
    def page_analysis():
        ui.label('Анализ и обнаружение аномалий').classes('page-title')
        ui.label('Выберите модель, настройте параметры и запустите анализ').classes('page-subtitle')

        ui.space().style('height:16px')

        # Upload
        with ui.card().classes('soc-card w-full'):
            ui.label('Загрузка данных').classes('section-title')
            ui.space().style('height:8px')

            upload_log = ui.log().classes('soc-log w-full').style('height:60px;')

            async def handle_upload(e):
                f = e.file
                file_name = getattr(f, 'name', None) or getattr(f, 'filename', None) or 'uploaded.csv'
                upload_log.push(f"📂 Загрузка: {file_name}")
                try:
                    if hasattr(f, 'read'):
                        if hasattr(f, 'seek'): f.seek(0)
                        content = f.read()
                        if asyncio.iscoroutine(content): content = await content
                    elif isinstance(f, (bytes, bytearray)): content = bytes(f)
                    else: raise Exception(f"Неизвестный тип: {type(f)}")
                    if isinstance(content, str): content = content.encode('utf-8')
                    if file_name.lower().endswith('.csv'):
                        df, X = read_csv_data(content, file_name)
                    else:
                        upload_log.push("❌ Поддерживаются только CSV"); return
                    state.raw_df = df; state.raw_X = X; state.file_name = file_name
                    state.has_results = False; state.result_df = None
                    gt = label_to_binary(df); state.ground_truth = gt
                    upload_log.push(f"✅ {len(df):,} записей, {len(df.columns)} колонок")
                    if gt is not None: upload_log.push(f"✅ Метки найдены! Аномалий: {gt.mean()*100:.2f}%")
                    else: upload_log.push("ℹ️ Метки не найдены — только unsupervised")
                    preview_table.rows = df.head(8).fillna('').to_dict('records')
                    preview_table.columns = [{'name': c, 'label': c, 'field': c, 'sortable': True} for c in df.columns[:12]]
                    preview_table.update()
                except Exception as ex:
                    upload_log.push(f"❌ Ошибка: {ex}")

            ui.upload(on_upload=handle_upload, label='Перетащите CSV файл или нажмите для выбора', auto_upload=True).props('accept=.csv flat bordered').classes('soc-upload w-full')
            preview_table = ui.table(columns=[], rows=[]).classes('soc-table w-full mt-3').props('dense flat')

        ui.space().style('height:16px')

        # Выбор модели
        with ui.card().classes('soc-card w-full'):
            ui.label('Выбор модели').classes('section-title')
            ui.space().style('height:8px')

            available_models = ["isolation_forest","lof","ocsvm"]
            if XGBOOST_AVAILABLE: available_models.append("xgboost")
            if LIGHTGBM_AVAILABLE: available_models.append("lightgbm")
            available_models.extend(["random_forest","gradient_boosting","adaboost"])
            if TENSORFLOW_AVAILABLE: available_models.append("autoencoder")

            selected_model = {'value': 'isolation_forest'}
            model_cards = {}

            with ui.row().classes('w-full gap-2 flex-wrap'):
                for key in available_models:
                    info = MODEL_INFO[key]
                    card = ui.element('div').classes('model-card').style('min-width:140px; flex:1;')
                    with card:
                        ui.label(info['icon']).style('font-size:20px;')
                        ui.label(info['name']).style('font-size:11px; font-weight:600; color:#e2e8f0; margin-top:4px;')
                        ui.label(info['type']).style('font-size:10px; color:#475569;')
                    model_cards[key] = card

                    def on_select(k=key):
                        selected_model['value'] = k
                        for mk, mc in model_cards.items():
                            if mk == k: mc.classes(add='selected')
                            else: mc.classes(remove='selected')

                    card.on('click', on_select)

            # Выделим первую модель
            if model_cards:
                list(model_cards.values())[0].classes(add='selected')

        ui.space().style('height:16px')

        # Параметры
        with ui.card().classes('soc-card w-full'):
            ui.label('Параметры').classes('section-title')
            ui.space().style('height:8px')

            with ui.row().classes('w-full gap-6 items-end'):
                with ui.column().classes('flex-1'):
                    contam_label = ui.label('Контаминация: 10%').style('font-size:11px; color:#64748b;')
                    contam_slider = ui.slider(min=1, max=50, step=1, value=10).classes('soc-slider')
                    contam_slider.on('update:model-value', lambda e: contam_label.set_text(f'Контаминация: {e.args}%'))

                with ui.column().classes('flex-1'):
                    trees_label = ui.label('Деревьев: 100').style('font-size:11px; color:#64748b;')
                    trees_slider = ui.slider(min=50, max=300, step=10, value=100).classes('soc-slider')
                    trees_slider.on('update:model-value', lambda e: trees_label.set_text(f'Деревьев: {e.args}'))

                with ui.column().classes('flex-1'):
                    async def run_analysis():
                        if state.raw_df is None:
                            ui.notify('Сначала загрузите данные!', type='warning'); return
                        analysis_log.clear()
                        model_type = selected_model['value']
                        has_labels = state.ground_truth is not None
                        is_supervised = model_type in ("random_forest","gradient_boosting","xgboost","lightgbm","adaboost")
                        contamination = contam_slider.value / 100; n_trees = int(trees_slider.value)
                        params = {'n_estimators': n_trees}
                        mname = MODEL_INFO[model_type]['name']
                        analysis_log.push(f"🚀 Запуск: {MODEL_INFO[model_type]['icon']} {mname}")
                        try:
                            t0 = time.time()
                            if is_supervised:
                                if not has_labels: analysis_log.push("❌ Для supervised нужны метки!"); return
                                if len(np.unique(state.ground_truth)) < 2: analysis_log.push("❌ Нужно минимум 2 класса!"); return
                                X_train, X_test, y_train, y_test = train_test_split(
                                    state.raw_X, state.ground_truth, test_size=0.3, random_state=42, stratify=state.ground_truth)
                                pipeline = build_supervised_pipeline(X_train, model_type, params)
                                analysis_log.push("⏳ Обучение...")
                                pipeline.fit(X_train, y_train)
                                predictions = pipeline.predict(state.raw_X)
                                try: scores = pipeline.predict_proba(state.raw_X)[:, 1]
                                except: scores = predictions.astype(float)
                                anomalies = predictions
                                state.feature_importance = get_feature_importance(pipeline, state.raw_X)
                                state.trained_pipeline = pipeline
                            elif model_type == "autoencoder" and TENSORFLOW_AVAILABLE:
                                pre, _, _ = get_preprocessor(state.raw_X)
                                Xt = pre.fit_transform(state.raw_X)
                                analysis_log.push("🧠 Обучение Autoencoder...")
                                ae = AnomalyAutoencoder(Xt.shape[1], contamination=contamination)
                                ae.fit(Xt)
                                anomalies = ae.predict(Xt); scores = ae.reconstruction_error(Xt)
                                state.trained_pipeline = {'preprocessor': pre, 'model': ae, 'model_type': 'autoencoder'}
                            else:
                                pipeline = build_pipeline(contamination, n_trees, state.raw_X, model_type)
                                analysis_log.push("⏳ Обучение...")
                                pipeline.fit(state.raw_X)
                                pred = pipeline.predict(state.raw_X)
                                anomalies = (pred == -1).astype(int)
                                if hasattr(pipeline.named_steps['model'], 'score_samples'):
                                    scores = -pipeline.named_steps['model'].score_samples(pipeline.named_steps['pre'].transform(state.raw_X))
                                elif hasattr(pipeline.named_steps['model'], 'decision_function'):
                                    scores = -pipeline.named_steps['model'].decision_function(pipeline.named_steps['pre'].transform(state.raw_X))
                                else: scores = anomalies.astype(float)
                                state.trained_pipeline = pipeline
                            result_df = state.raw_df.copy()
                            result_df['anomaly'] = anomalies; result_df['anomaly_score'] = scores
                            result_df['attack_type'] = result_df.apply(classify_attack_type, axis=1)
                            result_df = add_severity(result_df)
                            state.result_df = result_df; state.has_results = True
                            t_total = time.time() - t0
                            n_anom = int(result_df['anomaly'].sum())
                            pct = 100 * result_df['anomaly'].mean()
                            analysis_log.push(f"✅ Готово за {t_total:.2f}с | Аномалий: {n_anom:,} ({pct:.2f}%)")
                            m = {}
                            if has_labels:
                                m = calc_metrics(state.ground_truth, anomalies, scores)
                                analysis_log.push(f"📊 Accuracy={m['accuracy']:.4f} Precision={m['precision']:.4f} Recall={m['recall']:.4f} F1={m['f1_score']:.4f}")
                                if m.get('roc_auc'): analysis_log.push(f"📊 ROC AUC={m['roc_auc']:.4f}")
                            try:
                                sid = save_analysis_session(state.file_name or "?", len(result_df), n_anom, pct,
                                    model_type, params, t_total, m.get('accuracy'), m.get('precision'),
                                    m.get('recall'), m.get('f1_score'), m.get('roc_auc'))
                                n_saved = save_incidents(sid, result_df)
                                save_model_history(model_type, mname, params, len(result_df), m.get('accuracy'),
                                    m.get('precision'), m.get('recall'), m.get('f1_score'), m.get('roc_auc'), t_total)
                                crit = result_df[result_df['severity']=='Критическая']
                                if len(crit) > 0:
                                    create_alert("Критические аномалии", f"{len(crit)} критических в сессии #{sid}", "Критическая")
                                analysis_log.push(f"💾 БД: сессия #{sid}, {n_saved} инцидентов")
                            except Exception as dbe:
                                analysis_log.push(f"⚠️ БД: {dbe}")
                            # Обновляем результаты
                            results_area.clear()
                            with results_area:
                                with ui.row().classes('w-full gap-4'):
                                    metric_card('Всего записей', f'{len(result_df):,}', 'indigo', '📊')
                                    metric_card('Аномалий', f'{n_anom:,}', 'red', '⚠️')
                                    metric_card('Доля аномалий', f'{pct:.2f}%', 'amber', '📈')
                                    metric_card('Время обучения', f'{t_total:.2f}с', 'emerald', '⏱')
                                if has_labels and m:
                                    ui.space().style('height:8px')
                                    with ui.row().classes('w-full gap-4'):
                                        metric_card('Accuracy', f'{m["accuracy"]:.4f}', 'indigo', '🎯')
                                        metric_card('Precision', f'{m["precision"]:.4f}', 'cyan', '🎯')
                                        metric_card('Recall', f'{m["recall"]:.4f}', 'purple', '🎯')
                                        metric_card('F1-Score', f'{m["f1_score"]:.4f}', 'emerald', '🎯')
                                ui.space().style('height:12px')
                                if n_anom > 0:
                                    with ui.row().classes('w-full gap-4'):
                                        with ui.card().classes('soc-card flex-1'):
                                            ad = result_df[result_df['anomaly']==1]['attack_type'].value_counts()
                                            fig = px.pie(values=ad.values, names=ad.index, hole=0.5,
                                                         color_discrete_sequence=ATTACK_COLORS)
                                            fig.update_layout(**PLOTLY_LAYOUT, height=300, title='Типы атак',
                                                              title_font_size=13, title_font_color='#94a3b8')
                                            ui.plotly(fig).classes('w-full')
                                        with ui.card().classes('soc-card flex-1'):
                                            sd = result_df[result_df['anomaly']==1]['severity'].value_counts()
                                            fig = px.bar(x=sd.index, y=sd.values, color=sd.index,
                                                         color_discrete_map=SEVERITY_COLORS)
                                            fig.update_layout(**PLOTLY_LAYOUT, height=300, showlegend=False,
                                                              title='Уровни критичности', title_font_size=13, title_font_color='#94a3b8')
                                            fig.update_traces(marker_line_width=0)
                                            ui.plotly(fig).classes('w-full')
                        except Exception as ex:
                            analysis_log.push(f"❌ Ошибка: {ex}")
                            analysis_log.push(traceback.format_exc())

                    ui.button('🚀 Запустить анализ', on_click=run_analysis).classes('soc-btn').props('color=indigo unelevated no-caps').style('width:100%; height:42px;')

        ui.space().style('height:12px')

        # Log
        analysis_log = ui.log().classes('soc-log w-full').style('height:100px;')

        # Результаты
        ui.space().style('height:12px')
        results_area = ui.column().classes('w-full gap-4')

    # ════════════════════════════════════════════
    # PAGE: ЗАХВАТ
    # ════════════════════════════════════════════
    def page_capture():
        ui.label('Захват пакетов').classes('page-title')
        ui.label('Мониторинг сетевого трафика в реальном времени (Wireshark-style)').classes('page-subtitle')

        ui.space().style('height:16px')

        if not SCAPY_AVAILABLE:
            with ui.card().classes('soc-card w-full'):
                ui.label('⚠️ Scapy не установлен').style('color:#f87171; font-size:14px; font-weight:600;')
                ui.label('Установите: pip install scapy').style('color:#64748b; font-size:12px;')
            return

        # Управление
        with ui.card().classes('soc-card w-full'):
            with ui.row().classes('w-full items-end gap-3 flex-wrap'):
                ifaces = ['any']
                try: ifaces += get_if_list()
                except: ifaces += ['eth0','wlan0','lo']
                iface_select = ui.select(ifaces, value='any', label='Интерфейс').classes('soc-input').style('width:140px;')
                filter_input = ui.input(label='BPF фильтр', placeholder='tcp port 80').classes('soc-input flex-1').style('min-width:200px;')
                max_packets = ui.number(label='Макс. пакетов', value=0, min=0).classes('soc-input').style('width:120px;')

                ui.button('▶ Старт', on_click=lambda: _start_cap()).classes('soc-btn').props('color=green unelevated no-caps')
                ui.button('⏹ Стоп', on_click=lambda: (stop_capture(), ui.notify('Остановлен'))).classes('soc-btn').props('color=red unelevated no-caps')
                ui.button('🗑', on_click=lambda: _clear_cap()).classes('soc-btn').props('color=grey unelevated')
                ui.button('CSV', on_click=lambda: _export_csv()).classes('soc-btn').props('color=teal unelevated no-caps')

        ui.space().style('height:8px')

        # Display filter + Stats
        with ui.row().classes('w-full items-center gap-3'):
            display_filter = ui.input(placeholder='Display filter: http, dns, 192.168...').classes('soc-input flex-1')
            ui.button('🔍 Фильтр', on_click=lambda: _apply_filter()).classes('soc-btn').props('color=indigo unelevated no-caps')
            pkt_label = ui.label('Пакетов: 0').style('font-size:11px; color:#64748b; font-family:monospace;')
            rate_label = ui.label('').style('font-size:11px; color:#475569; font-family:monospace;')

        ui.space().style('height:8px')

        # Таблица
        packet_columns = [
            {'name': 'no', 'label': 'No.', 'field': 'no', 'sortable': True, 'align': 'right', 'style': 'width:60px'},
            {'name': 'time', 'label': 'Time', 'field': 'time', 'sortable': True, 'style': 'width:100px'},
            {'name': 'source', 'label': 'Source', 'field': 'source', 'sortable': True},
            {'name': 'destination', 'label': 'Destination', 'field': 'destination', 'sortable': True},
            {'name': 'protocol', 'label': 'Protocol', 'field': 'protocol', 'sortable': True, 'style': 'width:80px'},
            {'name': 'length', 'label': 'Length', 'field': 'length', 'sortable': True, 'align': 'right', 'style': 'width:70px'},
            {'name': 'info', 'label': 'Info', 'field': 'info'},
        ]
        packet_table = ui.table(columns=packet_columns, rows=[], row_key='no',
                                pagination={'rowsPerPage': 50}).classes('soc-table w-full').props('dense flat virtual-scroll')

        detail_panel = ui.card().classes('soc-card w-full mt-3')
        detail_panel.set_visibility(False)
        with detail_panel:
            detail_title = ui.label('').style('font-size:12px; color:#e2e8f0; font-weight:600;')
            detail_content = ui.column().classes('w-full')

        def on_row_click(e):
            row = e.args[1] if isinstance(e.args, list) else e.args
            no = row.get('no', 0)
            if no > 0 and no <= len(state.capture_packets):
                pkt = state.capture_packets[no - 1]
                detail_panel.set_visibility(True)
                detail_title.set_text(f"📦 Пакет #{pkt['no']} | {pkt['protocol']} | {pkt['source']}:{pkt['src_port']} → {pkt['destination']}:{pkt['dst_port']}")
                detail_content.clear()
                with detail_content:
                    with ui.row().classes('w-full gap-4'):
                        with ui.element('div').style('flex:1; background:#0a0c10; border-radius:8px; padding:12px; border:1px solid #1e2433;'):
                            ui.label('Информация').style('font-size:11px; color:#64748b; font-weight:600; margin-bottom:6px;')
                            for k, v in [('Время', pkt['time']), ('Протокол', pkt['protocol']), ('Длина', pkt['length']), ('Флаги', pkt['flags']), ('TTL', pkt['ttl'])]:
                                ui.label(f'{k}: {v}').style('font-size:11px; color:#94a3b8; font-family:monospace;')
                        with ui.element('div').style('flex:1; background:#0a0c10; border-radius:8px; padding:12px; border:1px solid #1e2433;'):
                            ui.label('Hex dump').style('font-size:11px; color:#64748b; font-weight:600; margin-bottom:6px;')
                            if pkt.get('raw_hex'):
                                hex_str = pkt['raw_hex']
                                formatted = ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
                                ui.label(formatted[:200]).style('font-size:10px; color:#34d399; font-family:monospace; word-break:break-all; opacity:0.7;')

        packet_table.on('rowClick', on_row_click)

        # Timer
        update_timer = ui.timer(0.5, lambda: None, active=False)

        def update_packets():
            current_len = len(packet_table.rows)
            new_pkts = state.capture_packets[current_len:]
            if new_pkts:
                flt = display_filter.value.strip().lower() if display_filter.value else ""
                for pkt in new_pkts:
                    if flt:
                        searchable = f"{pkt['source']} {pkt['destination']} {pkt['protocol']} {pkt['info']}".lower()
                        if flt not in searchable: continue
                    packet_table.rows.append({
                        'no': pkt['no'], 'time': f"{pkt['time']:.6f}",
                        'source': pkt['source'], 'destination': pkt['destination'],
                        'protocol': pkt['protocol'], 'length': pkt['length'], 'info': pkt['info'][:120],
                    })
                packet_table.update()
            elapsed = time.time() - state.capture_start_time if state.capture_start_time else 0
            pkt_label.set_text(f"Пакетов: {state.packet_counter}")
            rate = state.packet_counter / elapsed if elapsed > 0 else 0
            rate_label.set_text(f"({rate:.1f} пакет/с | {elapsed:.0f}с)")
            if not state.capture_running and update_timer.active:
                update_timer.active = False; ui.notify('Захват завершён', type='info')

        update_timer.callback = update_packets

        def _start_cap():
            if state.capture_running: ui.notify('Уже запущен', type='warning'); return
            packet_table.rows.clear(); packet_table.update(); detail_panel.set_visibility(False)
            bpf = filter_input.value or ""
            iface = iface_select.value
            mx = int(max_packets.value or 0)
            start_capture(bpf_filter=bpf, iface=iface if iface != 'any' else None, count=mx)
            update_timer.active = True
            ui.notify(f'▶ Захват на {iface}', type='positive')

        def _clear_cap():
            state.capture_packets.clear(); state.packet_counter = 0
            packet_table.rows.clear(); packet_table.update(); detail_panel.set_visibility(False)

        def _apply_filter():
            flt = display_filter.value.strip().lower() if display_filter.value else ""
            packet_table.rows.clear()
            for pkt in state.capture_packets:
                if flt:
                    searchable = f"{pkt['source']} {pkt['destination']} {pkt['protocol']} {pkt['info']}".lower()
                    if flt not in searchable: continue
                packet_table.rows.append({
                    'no': pkt['no'], 'time': f"{pkt['time']:.6f}",
                    'source': pkt['source'], 'destination': pkt['destination'],
                    'protocol': pkt['protocol'], 'length': pkt['length'], 'info': pkt['info'][:120],
                })
            packet_table.update()
            ui.notify(f"Показано {len(packet_table.rows)} из {len(state.capture_packets)}")

        def _export_csv():
            if not state.capture_packets: ui.notify('Нет данных', type='warning'); return
            df = pd.DataFrame(state.capture_packets)
            path = f"/tmp/capture_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            df.to_csv(path, index=False); ui.download(path)

        # Capture stats
        ui.space().style('height:12px')
        with ui.expansion('📊 Статистика захвата').classes('soc-expansion w-full'):
            cap_stats = ui.column().classes('w-full')
            def refresh_cap_stats():
                cap_stats.clear()
                if not state.capture_packets:
                    with cap_stats: ui.label('Нет данных').style('color:#475569;')
                    return
                with cap_stats:
                    with ui.row().classes('w-full gap-4'):
                        with ui.element('div').style('flex:1; background:#0a0c10; border-radius:8px; padding:12px; border:1px solid #1e2433;'):
                            ui.label('По протоколам').style('font-size:11px; color:#64748b; font-weight:600; margin-bottom:6px;')
                            for proto, cnt in Counter(p['protocol'] for p in state.capture_packets).most_common(10):
                                ui.label(f'{proto}: {cnt}').style('font-size:11px; color:#94a3b8; font-family:monospace;')
                        with ui.element('div').style('flex:1; background:#0a0c10; border-radius:8px; padding:12px; border:1px solid #1e2433;'):
                            ui.label('Топ Source IP').style('font-size:11px; color:#64748b; font-weight:600; margin-bottom:6px;')
                            for ip, cnt in Counter(p['source'] for p in state.capture_packets if p['source']).most_common(8):
                                ui.label(f'{ip}: {cnt}').style('font-size:11px; color:#94a3b8; font-family:monospace;')
                        with ui.element('div').style('flex:1; background:#0a0c10; border-radius:8px; padding:12px; border:1px solid #1e2433;'):
                            ui.label('Топ Dest IP').style('font-size:11px; color:#64748b; font-weight:600; margin-bottom:6px;')
                            for ip, cnt in Counter(p['destination'] for p in state.capture_packets if p['destination']).most_common(8):
                                ui.label(f'{ip}: {cnt}').style('font-size:11px; color:#94a3b8; font-family:monospace;')
            ui.button('🔄 Обновить', on_click=refresh_cap_stats).classes('soc-btn mt-2').props('color=indigo unelevated no-caps size=sm')

    # ════════════════════════════════════════════
    # PAGE: ИНЦИДЕНТЫ
    # ════════════════════════════════════════════
    def page_incidents():
        ui.label('Инциденты безопасности').classes('page-title')
        ui.label('Детальный просмотр обнаруженных аномалий и рекомендации').classes('page-subtitle')

        ui.space().style('height:16px')
        container = ui.column().classes('w-full')

        def refresh():
            container.clear()
            with container:
                if not state.has_results:
                    ui.label('Сначала выполните анализ на странице «Анализ»').style('color:#64748b; font-size:13px;')
                    return
                df = state.result_df; anom = df[df['anomaly'] == 1]
                if len(anom) == 0:
                    ui.label('✅ Аномалий не обнаружено').style('color:#4ade80; font-size:14px;')
                    return

                # Counts
                with ui.row().classes('w-full gap-4'):
                    metric_card('Всего аномалий', f'{len(anom):,}', 'red', '⚠️')
                    crit = len(anom[anom['severity']=='Критическая'])
                    metric_card('Критических', f'{crit:,}', 'amber', '🔴')
                    high = len(anom[anom['severity']=='Высокая'])
                    metric_card('Высоких', f'{high:,}', 'purple', '🟠')

                ui.space().style('height:12px')

                # Table
                top = anom.sort_values('anomaly_score', ascending=False).head(100)
                cols_pref = ['attack_type','severity','anomaly_score','src_ip','dst_ip','dst_port','protocol_type','service']
                display_cols = [c for c in cols_pref if c in top.columns]
                if not display_cols: display_cols = [c for c in ['attack_type','severity','anomaly_score'] if c in top.columns]

                rows_data = []
                for _, r in top.iterrows():
                    row = {c: str(r[c]) if pd.notna(r[c]) else '' for c in display_cols}
                    if 'anomaly_score' in row:
                        try: row['anomaly_score'] = f"{float(r['anomaly_score']):.4f}"
                        except: pass
                    rows_data.append(row)

                cols_def = [{'name': c, 'label': c, 'field': c, 'sortable': True} for c in display_cols]
                ui.table(columns=cols_def, rows=rows_data,
                         pagination={'rowsPerPage': 20}).classes('soc-table w-full').props('dense flat')

                # Рекомендации
                ui.space().style('height:16px')
                ui.label('Рекомендации по безопасности').classes('section-title')
                ui.space().style('height:8px')
                attack_types = anom['attack_type'].value_counts()
                for at, cnt in attack_types.head(6).items():
                    advice = SECURITY_RECOMMENDATIONS.get(at, SECURITY_RECOMMENDATIONS['Подозр. активность'])
                    sev_class = {'Критическая':'sev-critical','Высокая':'sev-high','Средняя':'sev-medium'}.get(advice['severity'],'sev-medium')
                    with ui.expansion(f"{advice['icon']} {at} ({cnt}) — {advice['severity']}").classes('soc-expansion w-full'):
                        ui.label(advice['description']).style('color:#64748b; font-size:12px; margin-bottom:8px;')
                        for rec in advice['recommendations']:
                            ui.label(f'✅ {rec}').style('color:#94a3b8; font-size:12px; padding-left:8px; border-left:2px solid rgba(99,102,241,0.3); margin-bottom:4px;')
                        with ui.element('div').classes('soc-code mt-2'):
                            for cmd in advice['commands']:
                                ui.label(cmd).style('color:#34d399; font-size:11px; font-family:monospace;')

        refresh()
        ui.space().style('height:12px')
        ui.button('🔄 Обновить', on_click=refresh).classes('soc-btn').props('color=indigo unelevated no-caps')

    # ════════════════════════════════════════════
    # PAGE: IP-АДРЕСА
    # ════════════════════════════════════════════
    def page_ips():
        ui.label('Управление IP-адресами').classes('page-title')
        ui.label('Чёрный и белый списки, блокировка подозрительных адресов').classes('page-subtitle')

        ui.space().style('height:16px')
        ip_container = ui.column().classes('w-full')

        def refresh():
            ip_container.clear()
            with ip_container:
                # IP из анализа
                if state.has_results:
                    df = state.result_df; anom = df[df['anomaly']==1]
                    if len(anom) > 0:
                        ip_col = None
                        for c in ['src_ip','dst_ip','Source IP','Destination IP','ip.src']:
                            if c in df.columns: ip_col = c; break
                        if not ip_col:
                            for c in df.columns:
                                try:
                                    s = df[c].dropna().head(100).astype(str)
                                    if s.str.match(r'^\d+\.\d+\.\d+\.\d+$').sum() > 10: ip_col = c; break
                                except: pass
                        if ip_col:
                            with ui.row().classes('w-full gap-4'):
                                metric_card('Уникальных IP', str(anom[ip_col].nunique()), 'indigo', '🌐')
                                crit_ips = anom[anom['severity'].isin(['Критическая','Высокая'])][ip_col].unique()
                                metric_card('Критических IP', str(len(crit_ips)), 'red', '🔴')
                                metric_card('В Blacklist', str(len(get_ip_list('blacklist'))), 'purple', '🔒')
                                metric_card('В Whitelist', str(len(get_ip_list('whitelist'))), 'emerald', '🔓')

                            ui.space().style('height:12px')

                            # IP таблица
                            ip_stats = anom.groupby(ip_col).agg({
                                'attack_type': lambda x: x.mode().iloc[0] if len(x.mode())>0 else x.iloc[0],
                                'severity': lambda x: x.mode().iloc[0] if len(x.mode())>0 else x.iloc[0],
                                'anomaly_score': ['mean','count']
                            }).reset_index()
                            ip_stats.columns = ['IP','Тип атаки','Уровень','Score','Кол-во']
                            ip_stats = ip_stats.sort_values('Score', ascending=False)

                            cols = [{'name':c,'label':c,'field':c,'sortable':True} for c in ['IP','Тип атаки','Уровень','Score','Кол-во']]
                            rows = [{'IP':r['IP'],'Тип атаки':r['Тип атаки'],'Уровень':r['Уровень'],
                                     'Score':f"{r['Score']:.4f}",'Кол-во':int(r['Кол-во'])} for _, r in ip_stats.head(50).iterrows()]
                            ui.table(columns=cols, rows=rows, pagination={'rowsPerPage':20}).classes('soc-table w-full').props('dense flat')

                            ui.space().style('height:12px')
                            if len(crit_ips) > 0:
                                with ui.element('div').classes('soc-code'):
                                    for ip in crit_ips[:30]:
                                        ui.label(f'sudo iptables -A INPUT -s {ip} -j DROP').style('color:#34d399; font-size:11px; font-family:monospace;')

                                def add_all_bl():
                                    added = 0
                                    for ip in crit_ips[:100]:
                                        if add_to_ip_list(str(ip), 'blacklist', 'Авто из анализа'): added += 1
                                    ui.notify(f'✅ {added} IP добавлено в Blacklist', type='positive')
                                    refresh()
                                ui.button('🚫 Добавить все критические в Blacklist', on_click=add_all_bl).classes('soc-btn mt-2').props('color=red unelevated no-caps')

                ui.space().style('height:16px')

                # Списки
                with ui.row().classes('w-full gap-4'):
                    with ui.card().classes('soc-card flex-1').style('border-color: rgba(239,68,68,0.2) !important;'):
                        ui.label('🚫 Чёрный список').style('font-size:13px; font-weight:600; color:#f87171;')
                        bl = get_ip_list('blacklist')
                        if bl:
                            for entry in bl:
                                with ui.row().classes('items-center justify-between w-full py-1'):
                                    ui.html(f'<span style="font-size:11px; color:#f87171;">●</span> <span style="font-size:12px; color:#e2e8f0; font-family:monospace;">{entry["ip_address"]}</span> <span style="font-size:10px; color:#475569;">{entry.get("reason","")}</span>')
                                    def make_rm(eid=entry['id']): remove_from_ip_list(eid); ui.notify('Удалён'); refresh()
                                    ui.button('✕', on_click=make_rm).props('flat dense size=xs color=red')
                        else: ui.label('Пусто').style('color:#475569; font-size:12px;')

                    with ui.card().classes('soc-card flex-1').style('border-color: rgba(34,197,94,0.2) !important;'):
                        ui.label('✅ Белый список').style('font-size:13px; font-weight:600; color:#4ade80;')
                        wl = get_ip_list('whitelist')
                        if wl:
                            for entry in wl:
                                with ui.row().classes('items-center justify-between w-full py-1'):
                                    ui.html(f'<span style="font-size:11px; color:#4ade80;">●</span> <span style="font-size:12px; color:#e2e8f0; font-family:monospace;">{entry["ip_address"]}</span> <span style="font-size:10px; color:#475569;">{entry.get("reason","")}</span>')
                                    def make_rm(eid=entry['id']): remove_from_ip_list(eid); ui.notify('Удалён'); refresh()
                                    ui.button('✕', on_click=make_rm).props('flat dense size=xs color=red')
                        else: ui.label('Пусто').style('color:#475569; font-size:12px;')

                ui.space().style('height:12px')

                # Добавить
                with ui.card().classes('soc-card w-full'):
                    ui.label('Добавить IP-адрес').classes('section-title')
                    with ui.row().classes('items-end gap-3 mt-2'):
                        ip_input = ui.input(label='IP', placeholder='192.168.1.100').classes('soc-input').style('width:160px;')
                        lt_select = ui.select({'blacklist':'🚫 Blacklist','whitelist':'✅ Whitelist'}, value='blacklist', label='Список').classes('soc-input').style('width:160px;')
                        reason_input = ui.input(label='Причина').classes('soc-input flex-1')
                        def add_ip():
                            if ip_input.value:
                                if add_to_ip_list(ip_input.value, lt_select.value, reason_input.value):
                                    ui.notify('✅ Добавлен', type='positive'); refresh()
                                else: ui.notify('Уже в списке', type='warning')
                        ui.button('Добавить', on_click=add_ip).classes('soc-btn').props('color=indigo unelevated no-caps')

        refresh()

    # ════════════════════════════════════════════
    # PAGE: СТАТИСТИКА
    # ════════════════════════════════════════════
    def page_stats():
        ui.label('Статистика и визуализация').classes('page-title')
        ui.label('Комплексная аналитика по результатам обнаружения аномалий').classes('page-subtitle')

        ui.space().style('height:16px')
        stats_container = ui.column().classes('w-full')

        def refresh():
            stats_container.clear()
            with stats_container:
                if not state.has_results:
                    ui.label('Сначала выполните анализ').style('color:#64748b; font-size:13px;'); return
                df = state.result_df; anom = df[df['anomaly']==1]

                with ui.row().classes('w-full gap-4'):
                    metric_card('Всего записей', f'{len(df):,}', 'indigo', '📊')
                    metric_card('Аномалий', f'{len(anom):,}', 'red', '⚠️')
                    metric_card('% аномалий', f'{100*len(anom)/len(df):.2f}%', 'amber', '📈')
                    metric_card('Нормальных', f'{len(df)-len(anom):,}', 'emerald', '✅')

                if len(anom) > 0:
                    ui.space().style('height:16px')
                    with ui.row().classes('w-full gap-4'):
                        with ui.card().classes('soc-card flex-1'):
                            ad = anom['attack_type'].value_counts()
                            fig = px.pie(values=ad.values, names=ad.index, hole=0.5, color_discrete_sequence=ATTACK_COLORS)
                            fig.update_layout(**PLOTLY_LAYOUT, height=350, title='Типы атак', title_font_size=13, title_font_color='#94a3b8')
                            ui.plotly(fig).classes('w-full')
                        with ui.card().classes('soc-card flex-1'):
                            sd = anom['severity'].value_counts()
                            fig = px.bar(x=sd.index, y=sd.values, color=sd.index, color_discrete_map=SEVERITY_COLORS)
                            fig.update_layout(**PLOTLY_LAYOUT, height=350, showlegend=False, title='Уровни критичности', title_font_size=13, title_font_color='#94a3b8')
                            fig.update_traces(marker_line_width=0)
                            ui.plotly(fig).classes('w-full')

                    ui.space().style('height:12px')
                    with ui.row().classes('w-full gap-4'):
                        with ui.card().classes('soc-card flex-1'):
                            fig = px.histogram(df, x='anomaly_score', color='anomaly', nbins=50,
                                color_discrete_map={0:'#22c55e', 1:'#ef4444'})
                            fig.update_layout(**PLOTLY_LAYOUT, height=300, title='Распределение scores', title_font_size=13, title_font_color='#94a3b8')
                            ui.plotly(fig).classes('w-full')
                        with ui.card().classes('soc-card flex-1'):
                            fig = px.box(anom, x='attack_type', y='anomaly_score', color='severity',
                                color_discrete_map=SEVERITY_COLORS)
                            fig.update_layout(**PLOTLY_LAYOUT, height=300, xaxis_tickangle=-45,
                                title='Scores по типам', title_font_size=13, title_font_color='#94a3b8')
                            ui.plotly(fig).classes('w-full')

                    # Feature Importance
                    if state.feature_importance is not None:
                        ui.space().style('height:16px')
                        with ui.card().classes('soc-card w-full'):
                            ui.label('Feature Importance (TOP-20)').classes('section-title')
                            fi = state.feature_importance.head(20)
                            fig = px.bar(fi.iloc[::-1], x='importance', y='feature', orientation='h',
                                         color='importance', color_continuous_scale='Viridis')
                            fig.update_layout(**PLOTLY_LAYOUT, height=500, coloraxis_showscale=False)
                            fig.update_traces(marker_line_width=0)
                            ui.plotly(fig).classes('w-full')

        refresh()
        ui.space().style('height:12px')
        ui.button('🔄 Обновить', on_click=refresh).classes('soc-btn').props('color=indigo unelevated no-caps')

    # ════════════════════════════════════════════
    # PAGE: БАЗА ДАННЫХ
    # ════════════════════════════════════════════
    def page_database():
        ui.label('База данных SOC').classes('page-title')
        ui.label('Управление сессиями, инцидентами, алертами и моделями').classes('page-subtitle')

        ui.space().style('height:16px')
        db_container = ui.column().classes('w-full')

        def refresh():
            db_container.clear()
            with db_container:
                try:
                    s = get_db_stats()
                    with ui.row().classes('w-full gap-3'):
                        for label, val in [("Сессий",s['sessions']),("Инцидентов",s['incidents']),("Новых",s['incidents_new']),
                                           ("Алертов",s['alerts']),("Blacklist",s['blacklist']),("Моделей",s['models'])]:
                            with ui.element('div').style('flex:1; background:#161921; border:1px solid #1e2433; border-radius:10px; padding:12px; text-align:center;'):
                                ui.label(str(val)).style('font-size:20px; font-weight:700; color:#e2e8f0;')
                                ui.label(label).style('font-size:10px; color:#475569;')
                except: pass

                ui.space().style('height:16px')

                with ui.tabs().classes('soc-tabs w-full') as db_tabs:
                    t1 = ui.tab('Сессии')
                    t2 = ui.tab('Инциденты')
                    t3 = ui.tab('Алерты')
                    t4 = ui.tab('IP списки')
                    t5 = ui.tab('Модели')
                    t6 = ui.tab('Управление')

                with ui.tab_panels(db_tabs, value=t1).classes('w-full'):
                    with ui.tab_panel(t1):
                        sessions = get_analysis_history(50)
                        if sessions:
                            cols = [{'name':k,'label':k,'field':k,'sortable':True} for k in ['id','timestamp','filename','total_records','total_anomalies','anomaly_percent','model_type','f1_score']]
                            rows = [{k: (f"{v:.4f}" if isinstance(v,float) and k in ('f1_score','roc_auc','anomaly_percent') else (v if v is not None else ''))
                                     for k,v in s.items() if k in [c['name'] for c in cols]} for s in sessions]
                            ui.table(columns=cols, rows=rows, pagination={'rowsPerPage':15}).classes('soc-table w-full').props('dense flat')
                        else: ui.label('Нет данных').style('color:#475569;')

                    with ui.tab_panel(t2):
                        incidents = get_incidents(limit=200)
                        if incidents:
                            cols = [{'name':k,'label':k,'field':k,'sortable':True} for k in ['id','src_ip','dst_ip','dst_port','attack_type','severity','anomaly_score','status']]
                            rows = [{k: (f"{v:.4f}" if isinstance(v,float) and k=='anomaly_score' else (v if v is not None else ''))
                                     for k,v in inc.items() if k in [c['name'] for c in cols]} for inc in incidents]
                            ui.table(columns=cols, rows=rows, pagination={'rowsPerPage':20}).classes('soc-table w-full').props('dense flat')

                            ui.space().style('height:12px')
                            ui.label('Обновить статус инцидента').classes('section-title')
                            with ui.row().classes('items-end gap-3 mt-2'):
                                inc_id = ui.number(label='ID', value=1, min=1).classes('soc-input').style('width:80px;')
                                status_sel = ui.select(['В работе','Закрыт','Ложное срабатывание'], value='В работе', label='Статус').classes('soc-input').style('width:180px;')
                                note_inp = ui.input(label='Примечание').classes('soc-input flex-1')
                                def upd_inc():
                                    update_incident_status(int(inc_id.value), status_sel.value, note_inp.value)
                                    ui.notify(f'✅ #{int(inc_id.value)} обновлён', type='positive')
                                ui.button('Обновить', on_click=upd_inc).classes('soc-btn').props('color=indigo unelevated no-caps')
                        else: ui.label('Нет инцидентов').style('color:#475569;')

                    with ui.tab_panel(t3):
                        alerts = get_alerts(limit=100)
                        if alerts:
                            for alert in alerts[:30]:
                                sev_cls = {'Критическая':'sev-critical','Высокая':'sev-high','Средняя':'sev-medium'}.get(alert['severity'],'sev-medium')
                                read_mark = '' if alert['is_read'] else '● '
                                with ui.row().classes('items-center justify-between w-full py-2 px-3').style(
                                    f'background:{"rgba(99,102,241,0.05)" if not alert["is_read"] else "rgba(10,12,16,0.3)"}; border-radius:8px; margin-bottom:4px; border:1px solid {"#1e2433" if alert["is_read"] else "rgba(99,102,241,0.15)"};'):
                                    with ui.row().classes('items-center gap-2 no-wrap'):
                                        if not alert['is_read']: ui.html('<span style="width:6px;height:6px;border-radius:50%;background:#6366f1;display:inline-block;"></span>')
                                        ui.html(severity_html(alert['severity']))
                                        ui.label(alert['message'][:80]).style('font-size:12px; color:#cbd5e1;')
                                    with ui.row().classes('items-center gap-2 no-wrap'):
                                        ui.label(alert['timestamp'][:16]).style('font-size:10px; color:#475569; font-family:monospace;')
                                        if not alert['is_resolved']:
                                            def make_resolve(aid=alert['id']): resolve_alert(aid); ui.notify('✅ Разрешён'); refresh()
                                            ui.button('Разрешить', on_click=make_resolve).props('flat dense size=xs color=green no-caps')
                        else: ui.label('Нет алертов').style('color:#475569;')

                        ui.space().style('height:12px')
                        ui.label('Создать алерт').classes('section-title')
                        with ui.row().classes('items-end gap-3 mt-2'):
                            a_type = ui.input(label='Тип', value='Ручной').classes('soc-input').style('width:120px;')
                            a_sev = ui.select(['Средняя','Высокая','Критическая'], value='Средняя', label='Severity').classes('soc-input').style('width:140px;')
                            a_msg = ui.input(label='Сообщение').classes('soc-input flex-1')
                            def add_alert():
                                if a_msg.value: create_alert(a_type.value, a_msg.value, a_sev.value); ui.notify('✅ Создан', type='positive'); refresh()
                            ui.button('Создать', on_click=add_alert).classes('soc-btn').props('color=indigo unelevated no-caps')

                    with ui.tab_panel(t4):
                        with ui.row().classes('w-full gap-4'):
                            with ui.card().classes('soc-card flex-1').style('border-color:rgba(239,68,68,0.2) !important;'):
                                ui.label('🚫 Blacklist').style('font-size:13px; font-weight:600; color:#f87171;')
                                for entry in get_ip_list('blacklist'):
                                    with ui.row().classes('items-center justify-between w-full py-1'):
                                        ui.label(f"🔴 {entry['ip_address']} — {entry.get('reason','')}").style('font-size:12px; color:#e2e8f0; font-family:monospace;')
                                        def mk_rm(eid=entry['id']): remove_from_ip_list(eid); ui.notify('Удалён'); refresh()
                                        ui.button('✕', on_click=mk_rm).props('flat dense size=xs color=red')
                            with ui.card().classes('soc-card flex-1').style('border-color:rgba(34,197,94,0.2) !important;'):
                                ui.label('✅ Whitelist').style('font-size:13px; font-weight:600; color:#4ade80;')
                                for entry in get_ip_list('whitelist'):
                                    with ui.row().classes('items-center justify-between w-full py-1'):
                                        ui.label(f"🟢 {entry['ip_address']} — {entry.get('reason','')}").style('font-size:12px; color:#e2e8f0; font-family:monospace;')
                                        def mk_rm(eid=entry['id']): remove_from_ip_list(eid); ui.notify('Удалён'); refresh()
                                        ui.button('✕', on_click=mk_rm).props('flat dense size=xs color=red')

                    with ui.tab_panel(t5):
                        models = get_model_history(50)
                        if models:
                            cols = [{'name':k,'label':k,'field':k,'sortable':True} for k in ['id','timestamp','model_name','dataset_size','f1_score','roc_auc','training_time']]
                            rows = [{k: (f"{v:.4f}" if isinstance(v,float) and k in ('f1_score','roc_auc') else (v if v is not None else ''))
                                     for k,v in m.items() if k in [c['name'] for c in cols]} for m in models]
                            ui.table(columns=cols, rows=rows, pagination={'rowsPerPage':15}).classes('soc-table w-full').props('dense flat')
                        else: ui.label('Нет данных').style('color:#475569;')

                    with ui.tab_panel(t6):
                        ui.label('Управление базой данных').classes('section-title')
                        with ui.row().classes('gap-3 mt-4'):
                            def export_json():
                                path = f"/tmp/soc_export_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                                with open(path, 'w') as f: f.write(export_db_json())
                                ui.download(path)
                            ui.button('📥 Экспорт JSON', on_click=export_json).classes('soc-btn').props('color=teal unelevated no-caps')
                            def clear_alerts():
                                uid = _get_current_user_id()
                                conn = get_db(); conn.execute("DELETE FROM alerts WHERE user_id=?", (uid,)); conn.commit(); conn.close()
                                ui.notify('✅ Алерты очищены'); refresh()
                            ui.button('🗑 Очистить алерты', on_click=clear_alerts).classes('soc-btn').props('color=orange unelevated no-caps')
                            def clear_all():
                                uid = _get_current_user_id()
                                conn = get_db()
                                for t in ['analysis_sessions','incidents','ip_lists','model_history','alerts']:
                                    conn.execute(f"DELETE FROM {t} WHERE user_id=?", (uid,))
                                conn.commit(); conn.close(); ui.notify('✅ БД очищена'); refresh()
                            ui.button('🗑 Полная очистка', on_click=clear_all).classes('soc-btn').props('color=red unelevated no-caps')
                        try:
                            db_size = os.path.getsize(DB_PATH)
                            ui.label(f"Размер БД: {db_size/1024:.1f} КБ").style('color:#475569; font-size:11px; margin-top:12px;')
                        except: pass

        refresh()
        ui.space().style('height:12px')
        ui.button('🔄 Обновить', on_click=refresh).classes('soc-btn').props('color=indigo unelevated no-caps')

    # ════════════════════════════════════════════
    # PAGE: НАСТРОЙКИ
    # ════════════════════════════════════════════
    def page_settings():
        ui.label('Настройки и информация').classes('page-title')
        ui.label('Состояние системы, доступные модули и конфигурация').classes('page-subtitle')

        ui.space().style('height:16px')

        with ui.card().classes('soc-card w-full mb-4'):
            ui.label('Пользователь').classes('section-title')
            ui.space().style('height:8px')
            with ui.row().classes('items-center gap-3'):
                ui.html(f'<div style="width:40px; height:40px; border-radius:12px; background:linear-gradient(135deg,#6366f1,#a855f7); display:flex; align-items:center; justify-content:center; font-size:16px; font-weight:700; color:white;">{_get_current_username()[:1].upper() if _get_current_username() else "U"}</div>')
                with ui.column().classes('gap-0'):
                    ui.label(_get_current_username()).style('font-size:14px; font-weight:600; color:#e2e8f0;')
                    ui.label(f'ID: {_get_current_user_id()[:12]}...').style('font-size:10px; color:#475569; font-family:monospace;')

        with ui.row().classes('w-full gap-4'):
            with ui.card().classes('soc-card flex-1'):
                ui.label('Состояние системы').classes('section-title')
                ui.space().style('height:8px')
                for label, val, ok in [
                    ("Записей загружено", f'{len(state.raw_df):,}' if state.raw_df is not None else '0', state.raw_df is not None),
                    ("Результаты анализа", "Готовы" if state.has_results else "Нет", state.has_results),
                    ("Метки (labels)", "Найдены" if state.ground_truth is not None else "Нет", state.ground_truth is not None),
                    ("Feature Importance", "Рассчитан" if state.feature_importance is not None else "Нет", state.feature_importance is not None),
                ]:
                    with ui.row().classes('items-center justify-between w-full py-1'):
                        ui.label(label).style('font-size:12px; color:#94a3b8;')
                        ui.label(f'{"✅" if ok else "❌"} {val}').style(f'font-size:12px; color:{"#4ade80" if ok else "#64748b"};')

            with ui.card().classes('soc-card flex-1'):
                ui.label('Библиотеки').classes('section-title')
                ui.space().style('height:8px')
                for lib, ok in [("scikit-learn", True), ("XGBoost", XGBOOST_AVAILABLE), ("LightGBM", LIGHTGBM_AVAILABLE),
                                ("TensorFlow / Keras", TENSORFLOW_AVAILABLE), ("Scapy", SCAPY_AVAILABLE), ("Plotly", True),
                                ("MongoDB (pymongo)", MONGO_AVAILABLE)]:
                    with ui.row().classes('items-center justify-between w-full py-1'):
                        ui.label(lib).style('font-size:12px; color:#94a3b8;')
                        ui.label(f'{"✅ Доступна" if ok else "❌ Нет"}').style(f'font-size:12px; color:{"#4ade80" if ok else "#f87171"};')

            with ui.card().classes('soc-card flex-1'):
                ui.label('База данных').classes('section-title')
                ui.space().style('height:8px')
                try:
                    s = get_db_stats()
                    for k, v in s.items():
                        with ui.row().classes('items-center justify-between w-full py-1'):
                            ui.label(k).style('font-size:12px; color:#94a3b8;')
                            ui.label(str(v)).style('font-size:12px; color:#e2e8f0; font-family:monospace;')
                except: ui.label('Ошибка').style('color:#f87171;')

        ui.space().style('height:16px')

        with ui.card().classes('soc-card w-full'):
            ui.label('Доступные модели ML').classes('section-title')
            ui.space().style('height:8px')
            with ui.row().classes('w-full gap-2 flex-wrap'):
                for key, info in MODEL_INFO.items():
                    avail = True
                    if key == 'xgboost' and not XGBOOST_AVAILABLE: avail = False
                    if key == 'lightgbm' and not LIGHTGBM_AVAILABLE: avail = False
                    if key == 'autoencoder' and not TENSORFLOW_AVAILABLE: avail = False
                    with ui.element('div').style(f'flex:1; min-width:140px; background:#111318; border:1px solid {"#1e2433" if avail else "#2d1b1b"}; border-radius:10px; padding:12px; opacity:{"1" if avail else "0.5"};'):
                        ui.label(info['icon']).style('font-size:18px;')
                        ui.label(info['name']).style('font-size:11px; font-weight:600; color:#e2e8f0; margin-top:4px;')
                        ui.label(info['type']).style('font-size:10px; color:#475569;')
                        ui.label(info['description']).style('font-size:10px; color:#334155; margin-top:2px;')

        ui.space().style('height:16px')

        with ui.element('div').style('background:linear-gradient(135deg, rgba(99,102,241,0.1), rgba(168,85,247,0.08)); border:1px solid rgba(99,102,241,0.2); border-radius:12px; padding:20px;'):
            ui.label('AI Анализатор Безопасности (SOC) v7.0').style('font-size:14px; font-weight:700; color:#e2e8f0;')
            ui.label('Система обнаружения сетевых аномалий на основе машинного обучения').style('font-size:12px; color:#64748b; margin-top:4px;')
            ui.space().style('height:8px')
            with ui.row().classes('gap-2 flex-wrap'):
                for feat in ['Wireshark-style захват','9 ML моделей','Deep Learning','SQLite БД','MongoDB Auth','IP списки','Система алертов','NiceGUI']:
                    ui.html(f'<span style="font-size:10px; padding:3px 10px; background:rgba(99,102,241,0.1); border:1px solid rgba(99,102,241,0.2); border-radius:999px; color:#818cf8;">{feat}</span>')
            ui.label('© 2024–2025 · Дипломный проект').style('font-size:10px; color:#334155; margin-top:12px;')

        ui.space().style('height:12px')
        def clear_state():
            state.__init__(); ui.notify('✅ Состояние очищено', type='positive')
        ui.button('🗑 Очистить состояние', on_click=clear_state).classes('soc-btn').props('color=red unelevated no-caps')

    # ════════════════════════════════════════════
    # PAGE MAP
    # ════════════════════════════════════════════
    pages = {
        'dashboard': page_dashboard,
        'analysis': page_analysis,
        'capture': page_capture,
        'incidents': page_incidents,
        'ips': page_ips,
        'stats': page_stats,
        'database': page_database,
        'settings': page_settings,
    }

    # Initial page
    with content:
        page_dashboard()


# ═══════════════════════════════════════════
# ЗАПУСК
# ═══════════════════════════════════════════
if __name__ in {"__main__", "__mp_main__"}:
    ui.run(
        title='🛡️ SOC Analyzer v7.0',
        host='0.0.0.0',
        port=8080,
        dark=True,
        reload=False,
        storage_secret='soc_analyzer_v7_secret_key_2025',
    )
