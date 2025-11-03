import sqlite3
import datetime
from database import DB_FILE

#  Messages DB helpers 
#add message dari dosen ke mahasiswa + masukin ke db 
def add_message(sender_id: int, recipient_id: int | None, subject: str, body: str, is_encrypted: int = 0, cipher: str = None, enc_key: str = None):
    ts = datetime.datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        INSERT INTO messages (sender_id, recipient_id, subject, body, timestamp, is_read, is_encrypted, cipher, enc_key)
        VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)
    ''', (sender_id, recipient_id, subject, body, ts, is_encrypted, cipher, enc_key))
    conn.commit()
    conn.close()

#ambil pesan oleh mahasiswa 
def get_inbox_for_user(uid: int):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        SELECT m.id, u.username AS sender, m.subject, m.body, m.timestamp, m.is_read, m.sender_id, m.is_encrypted, m.cipher, m.enc_key
        FROM messages m JOIN users u ON m.sender_id = u.id
        WHERE m.recipient_id IS NULL OR m.recipient_id = ?
        ORDER BY m.timestamp DESC
    ''', (uid,))
    rows = c.fetchall()
    conn.close()
    return rows

#boolean pesan telah dibaca
def mark_message_read(mid: int):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('UPDATE messages SET is_read = 1 WHERE id = ?', (mid,))
    conn.commit()
    conn.close()

#buat lihat role dari user ?? (dosen/mahasiswa)
def get_users_by_role(role: str):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT id, username FROM users WHERE LOWER(role)=LOWER(?)', (role,))
    rows = c.fetchall()
    conn.close()
    return rows
