from database import DB_FILE
from cipherGIla import caesar_encrypt_text, vigenere_encrypt_text, xor_encrypt_text, super_encrypt_text
import sqlite3


#--- section soal ---
#baru masukin soal, lalu sesuai apa yang dipillh akan di encrypt
#dari bagian dosen 
def compute_answer_for_cipher(cipher: str, plain: str, key: str) -> str:
    lc = cipher.lower()

    #masukin plain text + key ke masing masing funtion diatas
    if lc == 'caesar':
        try:
            k = int(key)
        except:
            k = 0
        return caesar_encrypt_text(plain, k)
    elif lc == 'vigenere':
        return vigenere_encrypt_text(plain, key)
    elif lc == 'xor':
        return xor_encrypt_text(plain, key)
    elif lc == 'super':
        return super_encrypt_text(plain, key)
    else:
        return ''

#masukin ke database 
def add_question(cipher, plain, key):
    answer = compute_answer_for_cipher(cipher, plain, key)
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('INSERT INTO questions (cipher, plain, key, answer) VALUES (?, ?, ?, ?)',
              (cipher, plain, key, answer))
    conn.commit()
    conn.close()
    return answer

#tampilin ke GUI soal untuk mahasiswa
def get_questions_by_cipher(cipher):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT id, plain, key FROM questions WHERE LOWER(cipher) = LOWER(?)', (cipher,))
    rows = c.fetchall()
    conn.close()
    return rows

#tampil semua soal (di dashboard dosen)
def get_all_questions(cipher=None):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    if cipher:
        c.execute('SELECT id, cipher, plain, key, answer FROM questions WHERE LOWER(cipher)=LOWER(?)', (cipher,))
    else:
        c.execute('SELECT id, cipher, plain, key, answer FROM questions')
    rows = c.fetchall()
    conn.close()
    return rows

#delete soal buat dosen 
def delete_question(qid):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('DELETE FROM questions WHERE id = ?', (qid,))
    conn.commit()
    conn.close()