import sqlite3
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)
DB_NAME = 'alerts.db'

def init_db():
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        # Create alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                severity TEXT NOT NULL
            )
        ''')

        # Create indices for faster queries
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_src_ip ON alerts(src_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON alerts(severity)')

        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {e}")

def insert_alert(timestamp, src_ip, attack_type, severity, dst_ip=None, dst_port=None, protocol=None, packet_count=1):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO alerts (timestamp, src_ip, attack_type, severity)
            VALUES (?, ?, ?, ?)
        ''', (timestamp, src_ip, attack_type, severity))
        conn.commit()
        conn.close()
        logger.debug(f"Alert logged: {attack_type} from {src_ip} ({severity})")
    except Exception as e:
        logger.error(f"Error inserting alert: {e}")

def get_alerts():
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM alerts ORDER BY id DESC')
        rows = cursor.fetchall()
        conn.close()
        return rows
    except Exception as e:
        logger.error(f"Error retrieving alerts: {e}")
        return []

def clear_alerts():
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM alerts')
        conn.commit()
        conn.close()
        logger.info("All alerts cleared")
    except Exception as e:
        logger.error(f"Error clearing alerts: {e}")

def get_stats():
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        # Total alerts
        cursor.execute('SELECT COUNT(*) FROM alerts')
        total = cursor.fetchone()[0]

        # By severity
        cursor.execute('SELECT severity, COUNT(*) FROM alerts GROUP BY severity')
        by_severity = [{"severity": r[0], "count": r[1]} for r in cursor.fetchall()]

        # By attack type
        cursor.execute('SELECT attack_type, COUNT(*) FROM alerts GROUP BY attack_type')
        by_type = [{"type": r[0], "count": r[1]} for r in cursor.fetchall()]

        # Top source IPs
        cursor.execute('''
            SELECT src_ip, COUNT(*) as count FROM alerts
            GROUP BY src_ip ORDER BY count DESC LIMIT 5
        ''')
        top_ips = [{"ip": r[0], "count": r[1]} for r in cursor.fetchall()]

        # Hourly distribution
        cursor.execute('''
            SELECT strftime('%H', timestamp) as hour, COUNT(*)
            FROM alerts GROUP BY hour ORDER BY hour
        ''')
        by_hour = [{"hour": r[0], "count": r[1]} for r in cursor.fetchall()]

        conn.close()
        return {
            "total": total,
            "by_severity": by_severity,
            "by_type": by_type,
            "top_ips": top_ips,
            "by_hour": by_hour
        }
    except Exception as e:
        logger.error(f"Error retrieving stats: {e}")
        return {}