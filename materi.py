import sqlite3
import datetime
from database import DB_FILE

#  Materials helpers 
# add materi di dahsboard dosen
def add_material(title: str, mtype: str, filepath: str, original_name: str, cipher: str, uploader_id: int, file_pw_salt=None, file_pw_hash=None):
    ts = datetime.datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        INSERT INTO materials (title, type, filepath, original_name, cipher, uploader_id, timestamp, file_password_salt, file_password_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (title, mtype, filepath, original_name, cipher, uploader_id, ts, file_pw_salt, file_pw_hash))
    conn.commit()
    conn.close()

#list materi sama di dosen dan mahasiswa
def list_materials():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT id, title, type, filepath, original_name, cipher, uploader_id, timestamp FROM materials ORDER BY timestamp DESC')
    rows = c.fetchall()
    conn.close()
    return rows

#ini buat ambil detail materinya 
def get_material(mid: int):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT id, title, type, filepath, original_name, cipher, uploader_id, timestamp, file_password_salt, file_password_hash FROM materials WHERE id = ?', (mid,))
    row = c.fetchone()
    conn.close()
    return row
