import os
import pathlib
import re
from datetime import datetime, timezone, timedelta
import psycopg2
from psycopg2 import pool, extras

# 擁有全設備可見性的帳號（等同 admin 權限查詢，不受 user_group 過濾）
_SUPERUSER_IDS: frozenset[str] = frozenset({"admin", "user"})

# 从环境变量加载配置
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")

# 全局连接池
_pg_pool = None

def init_db_pool():
    global _pg_pool
    if _pg_pool is None:
        try:
            _pg_pool = psycopg2.pool.SimpleConnectionPool(
                minconn=1,
                maxconn=10,
                host=DB_HOST,
                port=DB_PORT,
                database=DB_NAME,
                user=DB_USER,
                password=DB_PASS
            )
            print(f"[DB] Connection pool initialized for {DB_HOST}")
        except Exception as e:
            print(f"[DB] Failed to initialize pool: {e}")

def get_db_connection():
    if _pg_pool is None:
        init_db_pool()
    return _pg_pool.getconn()

def release_db_connection(conn):
    if _pg_pool and conn:
        _pg_pool.putconn(conn)

def authenticate_user(username, password):
    """
    验证用户登录。
    Returns: user_dict {'id': int, 'sso_id': str} or None
    """
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=extras.DictCursor) as cur:
            # TODO: 未来应升级为 bcrypt 校验
            cur.execute("SELECT id, sso_id, password FROM app_user WHERE sso_id = %s", (username,))
            user = cur.fetchone()
            
            if user:
                # 明文比对
                if user['password'] == password:
                    return {'id': user['id'], 'sso_id': user['sso_id']}
    except Exception as e:
        print(f"[DB] Auth error: {e}")
    finally:
        release_db_connection(conn)
    return None

def get_user_allowed_devices(username):
    """
    获取用户有权访问的设备列表。
    Admin 账号拥有所有权限。
    Returns: List of dicts [{'device_id': str, 'mac_address': str}, ...]
    """
    conn = None
    devices = []
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=extras.DictCursor) as cur:
            if username in _SUPERUSER_IDS:
                # 超级管理员：获取所有设备
                cur.execute("SELECT device_id, mac_address FROM device_info")
            else:
                # 普通用户：根据组关联查询
                sql = """
                    SELECT d.device_id, d.mac_address 
                    FROM device_info d
                    JOIN user_group ug ON d.group_id = ug.group_id
                    JOIN app_user_user_group map ON ug.id = map.user_group_id
                    JOIN app_user u ON map.user_id = u.id
                    WHERE u.sso_id = %s
                """
                cur.execute(sql, (username,))
            
            rows = cur.fetchall()
            for row in rows:
                devices.append({
                    'device_id': row['device_id'],
                    'mac_address': row['mac_address']
                })
    except Exception as e:
        print(f"[DB] Permission query error: {e}")
    finally:
        release_db_connection(conn)
    return devices

def get_user_files(username):
    """
    获取用户有权下载的文件列表。
    """
    conn = None
    files = []
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=extras.DictCursor) as cur:
            if username in _SUPERUSER_IDS:
                cur.execute("""
                    SELECT f.file_name, f.file_path, f.mac_address, f.file_size, f.file_date
                    FROM data_files f
                    ORDER BY f.file_datetime DESC LIMIT 100
                """)
            else:
                # 仅查询用户所属组下的设备产生的文件
                sql = """
                    SELECT f.file_name, f.file_path, f.mac_address, f.file_size, f.file_date
                    FROM data_files f
                    JOIN device_info d ON f.mac_address = d.mac_address
                    JOIN user_group ug ON d.group_id = ug.group_id
                    JOIN app_user_user_group map ON ug.id = map.user_group_id
                    JOIN app_user u ON map.user_id = u.id
                    WHERE u.sso_id = %s
                    ORDER BY f.file_datetime DESC LIMIT 100
                """
                cur.execute(sql, (username,))
            
            rows = cur.fetchall()
            for row in rows:
                files.append(dict(row))
    except Exception as e:
        print(f"[DB] File query error: {e}")
    finally:
        release_db_connection(conn)
    return files

def get_device_dates(mac):
    """
    Get distinct dates for a device.
    """
    conn = None
    dates = []
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT DISTINCT file_date 
                FROM data_files 
                WHERE mac_address = %s
                ORDER BY file_date DESC
            """, (mac,))
            rows = cur.fetchall()
            dates = [row[0] for row in rows]
    except Exception as e:
        print(f"[DB] Date query error: {e}")
    finally:
        release_db_connection(conn)
    return dates

def get_device_files(mac, date_str):
    """
    Get files for a specific device and date.
    """
    conn = None
    files = []
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=extras.DictCursor) as cur:
            cur.execute("""
                SELECT file_name, file_path, file_size, file_time 
                FROM data_files 
                WHERE mac_address = %s AND file_date = %s
                ORDER BY file_time DESC
            """, (mac, date_str))
            rows = cur.fetchall()
            for row in rows:
                files.append(dict(row))
    except Exception as e:
        print(f"[DB] File list query error: {e}")
    finally:
        release_db_connection(conn)
    return files


def rebuild_file_index(root_dir: str) -> dict:
    """
    掃描 root_dir 下所有 CSV 文件，重建 data_files 表。
    僅處理已在 device_info 中登錄的 MAC。
    時間戳從路徑推導（<MAC>/<YYYYMMDD>/<HHMMSS>.csv），不開檔讀取，速度快。
    返回 {'inserted': int, 'error': str|None}
    """
    _JST = timezone(timedelta(hours=9))

    def _ts_from_path(p: pathlib.Path) -> datetime:
        """從路徑 .../YYYYMMDD/HHMMSS.csv 推導時間戳，失敗退回 mtime。"""
        try:
            date_part = p.parent.name   # YYYYMMDD
            time_part = p.stem          # HHMMSS
            if len(date_part) == 8 and len(time_part) == 6:
                return datetime.strptime(date_part + time_part, "%Y%m%d%H%M%S").replace(tzinfo=_JST)
        except Exception:
            pass
        return datetime.fromtimestamp(p.stat().st_mtime, _JST)

    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return {'inserted': 0, 'error': 'No DB connection'}

        root = pathlib.Path(root_dir)
        if not root.exists():
            return {'inserted': 0, 'error': f'Path not found: {root_dir}'}

        # 取得所有合法 MAC
        with conn.cursor() as cur:
            cur.execute("SELECT mac_address FROM device_info")
            valid_macs = {row[0] for row in cur.fetchall() if row[0]}

        rows = []
        for dn_dir in root.iterdir():
            if not dn_dir.is_dir():
                continue
            dn_hex = dn_dir.name
            if dn_hex not in valid_macs:
                continue
            for p in dn_dir.rglob('*.csv'):
                try:
                    dt = _ts_from_path(p)
                    rel_dir = str(p.parent.relative_to(root)).replace('\\', '/') + '/'
                    rows.append((
                        dn_hex, dt.date(), dt.time(), dt,
                        p.name, rel_dir, p.stat().st_size, None, 'Rescanned'
                    ))
                except Exception:
                    pass

        with conn:
            with conn.cursor() as cur:
                cur.execute("TRUNCATE TABLE data_files RESTART IDENTITY CASCADE;")
                extras.execute_values(
                    cur,
                    """
                    INSERT INTO data_files
                        (mac_address, file_date, file_time, file_datetime,
                         file_name, file_path, file_size, side_position, file_memo)
                    VALUES %s
                    """,
                    rows,
                    page_size=500
                )

        return {'inserted': len(rows), 'error': None}

    except Exception as e:
        return {'inserted': 0, 'error': str(e)}
    finally:
        release_db_connection(conn)
