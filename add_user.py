"""
一次性腳本：向 app_user 表新增用戶。
使用方式：
  DB_HOST=localhost DB_NAME=... DB_USER=... DB_PASS=... python add_user.py
"""
import os
import psycopg2

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")

NEW_USERNAME = "user"
NEW_PASSWORD = "uoacnlab"

def main():
    conn = psycopg2.connect(
        host=DB_HOST, port=DB_PORT,
        database=DB_NAME, user=DB_USER, password=DB_PASS
    )
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM app_user WHERE sso_id = %s", (NEW_USERNAME,))
            existing = cur.fetchone()
            if existing:
                print(f"[INFO] 用戶 '{NEW_USERNAME}' 已存在 (id={existing[0]})，跳過。")
                return
            cur.execute(
                "INSERT INTO app_user (sso_id, password) VALUES (%s, %s) RETURNING id",
                (NEW_USERNAME, NEW_PASSWORD)
            )
            new_id = cur.fetchone()[0]
            conn.commit()
            print(f"[OK] 用戶 '{NEW_USERNAME}' 新增成功，id={new_id}")
    finally:
        conn.close()

if __name__ == "__main__":
    main()
