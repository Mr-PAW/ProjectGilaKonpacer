import sqlite3
from hashPass import hash_password, verify_password
DB_FILE = 'cryptoguide.db'

#  Database section
def init_db():
    conn = sqlite3.connect(DB_FILE) #buat database (klo belom ada)
    c = conn.cursor() 
    # IF NOT EXISTS biar gak double
    # tabel user
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL,
            salt TEXT NOT NULL,
            passhash TEXT NOT NULL,
            face_hash TEXT
        )
    ''')
    #tabel pertanyaan/soal
    c.execute('''
        CREATE TABLE IF NOT EXISTS questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cipher TEXT NOT NULL,
            plain TEXT NOT NULL,
            key TEXT,
            answer TEXT
        )
    ''')
    #tabel pesan
    c.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            recipient_id INTEGER,
            subject TEXT,
            body TEXT,
            timestamp TEXT,
            is_read INTEGER DEFAULT 0,
            is_encrypted INTEGER DEFAULT 0,
            cipher TEXT,
            enc_key TEXT,
            FOREIGN KEY(sender_id) REFERENCES users(id),
            FOREIGN KEY(recipient_id) REFERENCES users(id)
        )
    ''')
    # tabel materi
    c.execute('''
        CREATE TABLE IF NOT EXISTS materials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            type TEXT,
            filepath TEXT,
            original_name TEXT,
            cipher TEXT,
            uploader_id INTEGER,
            timestamp TEXT,
            file_password_salt TEXT,
            file_password_hash TEXT,
            FOREIGN KEY(uploader_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

#create tabel "IF NOT EXISTS" selesai

#add user
#fungsi sql sama dengan mysql
def add_user(username, role, password, face_hash=None):
    salt, key = hash_password(password)
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('INSERT INTO users (username, role, salt, passhash, face_hash) VALUES (?, ?, ?, ?, ?)',
                  (username, role, salt, key, face_hash))
        conn.commit()
        return True, None
    except sqlite3.IntegrityError as e:
        return False, str(e)
    finally:
        conn.close()

#otentikasi user
def authenticate(username, password):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT id, role, salt, passhash FROM users WHERE username = ?', (username,))
    row = c.fetchone()
    conn.close()
    if not row:
        return False, 'User not found'
    uid, role, salt, phash = row
    if verify_password(password, salt, phash):
        return True, {'id': uid, 'username': username, 'role': role}
    else:
        return False, 'Incorrect password'
