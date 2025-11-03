import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import sqlite3
import datetime
from cipherGIla import caesar_decrypt_text, vigenere_decrypt_text, xor_decrypt_text, super_decrypt_text, decrypt_file_bytes, caesar_encrypt_text, encrypt_file_bytes, vigenere_encrypt_text, xor_encrypt_text, super_encrypt_text
from database import DB_FILE, add_user, authenticate, verify_password, init_db
from ideGilaRaffy import recognize_face_login, train_face_model, capture_face_samples, MATERIAL_DIR, FACE_MODEL_FILE, FACES_DIR
from hashPass import image_hash_bytes, verify_password, hash_password
from steganografi import extract_text_from_image, embed_text_in_image, extract_text_from_image, embed_text_in_image
from materi import add_material, list_materials, get_material
from soal import get_questions_by_cipher, add_question, get_all_questions, delete_question
from pesan import get_inbox_for_user, mark_message_read, get_users_by_role, add_message, get_inbox_for_user, mark_message_read, get_users_by_role
from tryImportCV2 import cv2, has_cv2_face


# ---------------------- GUI ----------------------
class App:
    def __init__(self, root):
        self.root = root
        self.root.title('EduCryption')
        self.user = None
        self.setup_style()
        self.build_login()

    def setup_style(self):
        # Color palette: Ungu, Ungu Tua, dan Biru Langit
        self.bg = '#E6E6FA'  # Lavender (ungu muda) untuk background
        self.card = '#ffffff'
        self.primary = '#6A5ACD'  # Slate Blue (ungu)
        self.accent = '#9370DB'  # Medium Purple (ungu sedang)
        self.dark_purple = '#4B0082'  # Indigo (ungu tua)
        self.sky_blue = '#87CEEB'  # Sky Blue (biru langit)
        self.text = '#2F2F4F'  # Dark slate untuk text
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except Exception:
            pass
        style.configure('TFrame', background=self.bg)
        style.configure('Card.TFrame', background=self.card, relief='flat')
        style.configure('TLabel', background=self.bg, foreground=self.text, font=('Segoe UI', 10))
        style.configure('Title.TLabel', font=('Segoe UI', 12, 'bold'), background=self.bg, foreground=self.dark_purple)
        self.root.configure(background=self.bg)

    def clear_root(self):
        for w in self.root.winfo_children():
            w.destroy()

    # --- Login / Register (modified to include face option) ---
    def build_login(self):
        self.clear_root()
        frm = ttk.Frame(self.root, padding=20, style='TFrame')
        frm.pack(expand=True, fill='both')
        card = ttk.Frame(frm, padding=16, style='Card.TFrame')
        card.place(relx=0.5, rely=0.45, anchor='center')
        ttk.Label(card, text='EduCryption - Landing Page', style='Title.TLabel').grid(row=0, column=0, columnspan=3, pady=(0,10))
        ttk.Label(card, text='Username:').grid(row=1, column=0, sticky='w', padx=4, pady=4)
        self.username_entry = ttk.Entry(card, width=30)
        self.username_entry.grid(row=1, column=1, padx=4, pady=4)
        ttk.Label(card, text='Password:').grid(row=2, column=0, sticky='w', padx=4, pady=4)
        self.password_entry = ttk.Entry(card, show='*', width=30)
        self.password_entry.grid(row=2, column=1, padx=4, pady=4)
        btn_frame = ttk.Frame(card, style='Card.TFrame')
        btn_frame.grid(row=3, column=0, columnspan=3, pady=(10,0))
        login_btn = tk.Button(btn_frame, text='Login', command=self.do_login, bg=self.primary, fg='white', width=12)
        login_btn.pack(side='left', padx=6)
        reg_btn = tk.Button(btn_frame, text='Register', command=self.build_register, bg=self.accent, fg='white', width=12)
        reg_btn.pack(side='left', padx=6)
        face_btn = tk.Button(btn_frame, text='Login with Face (Camera)...', command=self.do_login_with_face, bg=self.sky_blue, fg='white', width=20)
        face_btn.pack(side='left', padx=6)
        # small note if opencv not present
        if not cv2 or not has_cv2_face:
            ttk.Label(card, text='(Face login requires opencv-contrib-python)', foreground='red').grid(row=4, column=0, columnspan=3, pady=6)

    def build_register(self):
        self.clear_root()
        frm = ttk.Frame(self.root, padding=20, style='TFrame')
        frm.pack(expand=True, fill='both')
        card = ttk.Frame(frm, padding=16, style='Card.TFrame')
        card.place(relx=0.5, rely=0.45, anchor='center')
        ttk.Label(card, text='Register', style='Title.TLabel').grid(row=0, column=0, columnspan=3, pady=(0,10))
        ttk.Label(card, text='Username:').grid(row=1, column=0, sticky='w', padx=4, pady=4)
        uname = ttk.Entry(card, width=30)
        uname.grid(row=1, column=1, padx=4, pady=4)
        ttk.Label(card, text='Password:').grid(row=2, column=0, sticky='w', padx=4, pady=4)
        pwd = ttk.Entry(card, show='*', width=30)
        pwd.grid(row=2, column=1, padx=4, pady=4)
        role_var = tk.StringVar(value='mahasiswa')
        ttk.Radiobutton(card, text='Mahasiswa', variable=role_var, value='mahasiswa').grid(row=3, column=0, sticky='w', padx=4, pady=6)
        ttk.Radiobutton(card, text='Dosen', variable=role_var, value='dosen').grid(row=3, column=1, sticky='w', padx=4, pady=6)

        # Face registration optional via camera or upload
        self._reg_face_path = ''
        def choose_face():
            p = filedialog.askopenfilename(filetypes=[('Images','*.png;*.jpg;*.jpeg;*.bmp;*.gif'),('All files','*.*')])
            if p:
                self._reg_face_path = p
                face_label.config(text=os.path.basename(p))
        ttk.Button(card, text='(Optional) Upload Face Image...', command=choose_face).grid(row=4, column=0, sticky='w', padx=4, pady=6)
        face_label = ttk.Label(card, text='No face image selected')
        face_label.grid(row=4, column=1, sticky='w')

        # Camera-based face registration
        def register_with_camera():
            username = uname.get().strip()
            password = pwd.get().strip()
            role = role_var.get()
            if not username or not password:
                messagebox.showwarning('Error', 'Username & password required for face registration')
                return
            if not cv2 or not has_cv2_face:
                messagebox.showerror('Error', 'OpenCV (contrib) not available. Install opencv-contrib-python.')
                return
            ok, reason = capture_face_samples(username, samples=30)
            if not ok:
                messagebox.showerror('Error', f'Gagal capture: {reason}')
                return
            # after samples, train the model (retrain full dataset)
            ok2, reason2 = train_face_model()
            if not ok2:
                messagebox.showerror('Error', f'Gagal train model: {reason2}')
                return
            # store user with face marker '1' in face_hash column to indicate face-registered
            ok3, err = add_user(username, role, password, face_hash='1')
            if not ok3:
                messagebox.showerror('Error', f'Gagal register user: {err}')
                return
            messagebox.showinfo('Success', 'Registered with face. Model updated.')
            self.build_login()

        def do_reg():
            username = uname.get().strip()
            password = pwd.get().strip()
            role = role_var.get()
            if not username or not password:
                messagebox.showwarning('Error', 'Username & password required')
                return
            face_hash = None
            if getattr(self, '_reg_face_path', None):
                face_hash = image_hash_bytes(self._reg_face_path) or None
            ok, err = add_user(username, role, password, face_hash)
            if ok:
                messagebox.showinfo('Success', 'Registered. Please login.')
                self.build_login()
            else:
                messagebox.showerror('Error', f'Failed to register: {err}')
        btn_frame = ttk.Frame(card, style='Card.TFrame')
        btn_frame.grid(row=6, column=0, columnspan=3, pady=(8,0))
        tk.Button(btn_frame, text='Register (Normal)', command=do_reg, bg=self.primary, fg='white', width=16).pack(side='left', padx=6)
        tk.Button(btn_frame, text='Register with Face (Camera)', command=register_with_camera, bg=self.accent, fg='white', width=20).pack(side='left', padx=6)
        tk.Button(btn_frame, text='Back', command=self.build_login, bg=self.sky_blue, fg='white', width=12).pack(side='left', padx=6)

    def do_login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        ok, data = authenticate(username, password)
        if not ok:
            messagebox.showerror('Error', data)
            return
        self.user = data
        if self.user['role'] == 'mahasiswa':
            self.build_mahasiswa()
        else:
            self.build_dosen()

    def do_login_with_face(self):
        # camera-based recognition
        if not cv2 or not has_cv2_face:
            messagebox.showerror('Error', 'OpenCV with face module not available. Install opencv-contrib-python.')
            return
        ok, result = recognize_face_login(timeout_seconds=15, confidence_threshold=60.0)
        if not ok:
            messagebox.showerror('Error', result)
            return
        username = result
        # fetch user info by username
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT id, role FROM users WHERE username = ?', (username,))
        row = c.fetchone()
        conn.close()
        if not row:
            messagebox.showerror('Error', 'User hasil pengecocokan tidak ditemukan di DB')
            return
        uid, role = row
        self.user = {'id': uid, 'username': username, 'role': role}
        messagebox.showinfo('Success', f'Login berhasil sebagai {username}')
        if role == 'mahasiswa':
            self.build_mahasiswa()
        else:
            self.build_dosen()

    # --- Mahasiswa UI (extended materials access) ---
    def build_mahasiswa(self):
        self.clear_root()
        self.root.title(f"Mahasiswa - {self.user['username']}")
        main = ttk.Frame(self.root, padding=12, style='TFrame')
        main.pack(fill='both', expand=True)
        header = ttk.Label(main, text=f"Selamat datang, {self.user['username']}", style='Title.TLabel')
        header.pack(anchor='w', pady=(0,8))
        btns = ttk.Frame(main, style='TFrame')
        btns.pack(fill='x', pady=6)
        tk.Button(btns, text='Materi', width=20, command=self.show_materi_student, bg=self.primary, fg='white').pack(side='left', padx=6)
        tk.Button(btns, text='Soal', width=20, command=self.show_soal_student, bg=self.accent, fg='white').pack(side='left', padx=6)
        tk.Button(btns, text='Pesan', width=20, command=self.show_messages_student, bg=self.sky_blue, fg='white').pack(side='left', padx=6)
        tk.Button(btns, text='Logout', width=12, command=self.logout, bg='#DC143C', fg='white').pack(side='right', padx=6)

    def show_materi_student(self):
        w = tk.Toplevel(self.root)
        w.title('Daftar Materi')
        cols = ('ID','Title','Type','Uploaded','Cipher','File')
        tree = ttk.Treeview(w, columns=cols, show='headings')
        for c in cols:
            tree.heading(c, text=c)
        tree.column('ID', width=40)
        tree.pack(fill='both', expand=True, padx=8, pady=8)
        mapping = {}
        for row in list_materials():
            mid, title, mtype, filepath, original_name, cipher, uploader_id, ts = row
            tree.insert('', 'end', values=(mid, title, mtype, ts, cipher or '-', original_name or '-'))
            mapping[mid] = row

        def open_material():
            sel = tree.selection()
            if not sel:
                return
            vals = tree.item(sel[0])['values']
            mid = vals[0]
            # fetch full material incl password cols
            mat = get_material(mid)
            if not mat:
                messagebox.showerror('Error', 'Materi tidak ditemukan')
                return
            idd, title, mtype, filepath, original_name, cipher, uploader_id, ts, pw_salt, pw_hash = mat
            matw = tk.Toplevel(w)
            matw.title(f'Materi: {title}')
            ttk.Label(matw, text=f'{title} ({mtype})', style='Title.TLabel').pack(anchor='w', padx=8, pady=6)
            ttk.Label(matw, text=f'Uploaded: {ts} | File: {original_name or ""} | Cipher: {cipher or "-"}').pack(anchor='w', padx=8)
            def download_plain():
                dest = filedialog.asksaveasfilename(initialfile=(original_name or os.path.basename(filepath)))
                if not dest:
                    return
                try:
                    with open(filepath, 'rb') as fsrc, open(dest, 'wb') as fdst:
                        fdst.write(fsrc.read())
                    messagebox.showinfo('Downloaded', f'File saved to {dest}')
                except Exception as e:
                    messagebox.showerror('Error', f'Failed: {e}')
            ttk.Button(matw, text='Download (as stored)', command=download_plain).pack(pady=6)

            if mtype == 'stego':
                def extract():
                    txt = extract_text_from_image(filepath)
                    if txt is None:
                        messagebox.showerror('Error', 'Gagal ekstrak teks (kemungkinan rusak atau tidak ada teks)')
                    else:
                        top = tk.Toplevel(matw)
                        top.title('Extracted Text')
                        t = tk.Text(top, width=80, height=20)
                        t.pack(padx=8, pady=8)
                        t.insert('end', txt)
                        t.config(state='disabled')
                ttk.Button(matw, text='Extract Hidden Text', command=extract).pack(pady=4)
            elif mtype == 'file':
                # If this file is a PDF-lock (cipher == 'pdf_lock' and pw hash exists), ask for pwd to allow download
                if (cipher or '') == 'pdf_lock' and pw_salt and pw_hash:
                    def unlock_and_download():
                        pwd = simpledialog.askstring('Unlock PDF', 'Masukkan password untuk membuka file (seperti yang dikirim dosen):', parent=matw, show='*')
                        if pwd is None:
                            return
                        if verify_password(pwd, pw_salt, pw_hash):
                            dest = filedialog.asksaveasfilename(initialfile=(original_name or os.path.basename(filepath)))
                            if not dest:
                                return
                            try:
                                with open(filepath, 'rb') as fsrc, open(dest, 'wb') as fdst:
                                    fdst.write(fsrc.read())
                                messagebox.showinfo('Downloaded', f'File unlocked and saved to {dest}')
                            except Exception as e:
                                messagebox.showerror('Error', f'Failed: {e}')
                        else:
                            messagebox.showerror('Error', 'Password salah')
                    ttk.Button(matw, text='Unlock & Download (PDF locked)', command=unlock_and_download).pack(pady=6)
                else:
                    # normal encrypted file (bytes-level); ask for key to decrypt and save
                    def decrypt_action():
                        key = simpledialog.askstring('Decrypt', 'Masukkan key untuk dekripsi (sama seperti yang dipakai dosen):', parent=matw)
                        if key is None:
                            return
                        try:
                            with open(filepath, 'rb') as f:
                                enc = f.read()
                            dec = decrypt_file_bytes(enc, cipher, key)
                            save_to = filedialog.asksaveasfilename(initialfile=(original_name or 'decrypted.bin'))
                            if not save_to:
                                return
                            with open(save_to, 'wb') as out:
                                out.write(dec)
                            messagebox.showinfo('Saved', f'Decrypted file disimpan ke {save_to}')
                        except Exception as e:
                            messagebox.showerror('Error', f'Gagal dekripsi: {e}')
                    ttk.Button(matw, text='Decrypt & Save (masukkan key)', command=decrypt_action).pack(pady=4)

        ttk.Button(w, text='Open Selected', command=open_material).pack(pady=8)

    # --- Soal & Messages (keadaan tetap) ---
    def show_soal_student(self):
        self.clear_root()
        header = ttk.Label(self.root, text='Pilih tipe cipher', style='Title.TLabel')
        header.pack(pady=(8,4), anchor='w', padx=12)
        for c in ['Caesar', 'Vigenere', 'Xor', 'Super']:
            tk.Button(self.root, text=c, width=30, command=lambda cc=c: self.list_questions_student(cc),
                      bg=self.primary if c=='Super' else self.accent, fg='white').pack(pady=6, padx=12)
        ttk.Button(self.root, text='Back', command=self.build_mahasiswa).pack(pady=10)

    def list_questions_student(self, cipher):
        rows = get_questions_by_cipher(cipher)
        w = tk.Toplevel(self.root)
        w.title(f'Soal - {cipher}')
        lb = tk.Listbox(w, width=100)
        lb.pack(padx=8, pady=8)
        mapping = {}
        for r in rows:
            qid, plain, key = r
            title = f'ID {qid} | Plain: {plain} | Key: {key}'
            lb.insert('end', title)
            mapping[title] = qid
        def open_q(event=None):
            sel = lb.curselection()
            if not sel:
                return
            txt = lb.get(sel[0])
            qid = mapping[txt]
            self.open_question_student(qid)
        lb.bind('<Double-Button-1>', open_q)
        ttk.Button(w, text='Open (double-click)', command=open_q).pack(pady=6)

    def open_question_student(self, qid):
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT cipher, plain, key, answer FROM questions WHERE id = ?', (qid,))
        row = c.fetchone()
        conn.close()
        if not row:
            messagebox.showerror('Error', 'Soal tidak ditemukan')
            return
        cipher, plain, key, answer = row
        w = tk.Toplevel(self.root)
        w.title(f'Jawab Soal ID {qid} ({cipher})')
        ttk.Label(w, text=f'Plain Text: {plain}').pack(anchor='w', padx=8, pady=4)
        ttk.Label(w, text=f'Key: {key}').pack(anchor='w', padx=8, pady=4)
        ttk.Label(w, text='Masukkan jawaban (ciphertext):').pack(anchor='w', padx=8)
        ans_ent = ttk.Entry(w, width=80)
        ans_ent.pack(padx=8, pady=6)
        def normalize(s: str) -> str:
            return ''.join(s.split()).lower()
        def check():
            user_ans = ans_ent.get().strip()
            if normalize(user_ans) == normalize(answer):
                messagebox.showinfo('Benar', 'Jawaban benar!')
            else:
                messagebox.showerror('Salah', f'Jawaban salah. Jawaban benar: {answer}')
        ttk.Button(w, text='Check', command=check).pack(pady=6)

    def show_messages_student(self):
        inbox = get_inbox_for_user(self.user['id'])
        w = tk.Toplevel(self.root)
        w.title('Inbox')
        w.geometry('800x400')
        lbl = ttk.Label(w, text='Inbox Anda', style='Title.TLabel')
        lbl.pack(anchor='w', padx=8, pady=6)
        tree = ttk.Treeview(w, columns=('id','sender','subject','ts','read','enc'), show='headings')
        tree.heading('id', text='ID'); tree.heading('sender', text='Dari'); tree.heading('subject', text='Subject'); tree.heading('ts', text='Waktu (UTC)'); tree.heading('read', text='Read'); tree.heading('enc', text='Encrypted')
        tree.column('id', width=40); tree.pack(fill='both', expand=True, padx=8, pady=4)
        mapping = {}
        for row in inbox:
            mid, sender, subject, body, ts, is_read, sender_id, is_encrypted, cipher, enc_key = row
            tree.insert('', 'end', values=(mid, sender, subject, ts, 'Yes' if is_read else 'No', 'Yes' if is_encrypted else 'No'))
            mapping[mid] = (subject, body, ts, sender, sender_id, is_encrypted, cipher, enc_key)
        def open_msg():
            sel = tree.selection()
            if not sel:
                return
            vals = tree.item(sel[0])['values']
            mid = vals[0]
            subj, body, ts, sender, sender_id, is_encrypted, cipher, enc_key = mapping[mid]
            msgw = tk.Toplevel(w)
            msgw.title(f'Message {mid}')
            lblh = ttk.Label(msgw, text=f'From: {sender} | {ts}', style='Title.TLabel')
            lblh.pack(anchor='w', padx=8, pady=6)
            txt = tk.Text(msgw, width=80, height=12)
            txt.pack(padx=8, pady=4)

            # If encrypted, prompt for key to decrypt (recipient must provide key)
            if is_encrypted:
                def try_decrypt_and_show():
                    key = simpledialog.askstring('Decrypt Message', 'Pesan terenkripsi. Masukkan key untuk mendekripsi:', parent=msgw, show='*')
                    if key is None:
                        return
                    lc = (cipher or '').lower()
                    dec = ''
                    try:
                        if lc == 'caesar':
                            try:
                                k = int(key)
                            except:
                                k = 0
                            dec = caesar_decrypt_text(body, k)
                        elif lc == 'vigenere':
                            dec = vigenere_decrypt_text(body, key)
                        elif lc == 'xor':
                            dec = xor_decrypt_text(body, key)
                        elif lc == 'super':
                            dec = super_decrypt_text(body, key)
                        else:
                            dec = '[Unknown cipher]'
                        txt.insert('end', dec)
                        txt.config(state='disabled')
                        mark_message_read(mid)
                    except Exception as e:
                        messagebox.showerror('Error', f'Gagal dekripsi: {e}')
                ttk.Button(msgw, text='Decrypt (masukkan key)', command=try_decrypt_and_show).pack(pady=6)
            else:
                txt.insert('end', body)
                txt.config(state='disabled')
                mark_message_read(mid)
        ttk.Button(w, text='Open', command=open_msg).pack(pady=6)

    # --- Dosen UI (with materi upload) ---
    def build_dosen(self):
        self.clear_root()
        self.root.title(f"Dosen - {self.user['username']}")
        main = ttk.Frame(self.root, padding=12, style='TFrame')
        main.pack(fill='both', expand=True)
        header = ttk.Label(main, text=f"Panel Dosen - {self.user['username']}", style='Title.TLabel')
        header.pack(anchor='w', pady=(0,8))
        btns = ttk.Frame(main, style='TFrame')
        btns.pack(fill='x', pady=6)
        tk.Button(btns, text='Materi', width=16, command=self.show_materi_dosen, bg=self.primary, fg='white').pack(side='left', padx=6)
        tk.Button(btns, text='Upload Materi', width=16, command=self.show_upload_material_dosen, bg=self.accent, fg='white').pack(side='left', padx=6)
        tk.Button(btns, text='Soal (CRUD)', width=16, command=self.show_soal_dosen, bg=self.dark_purple, fg='white').pack(side='left', padx=6)
        tk.Button(btns, text='Kirim Pesan', width=16, command=self.show_send_message_dosen, bg=self.sky_blue, fg='white').pack(side='left', padx=6)
        tk.Button(btns, text='Logout', width=12, command=self.logout, bg='#DC143C', fg='white').pack(side='right', padx=6)

    def show_materi_dosen(self):
        w = tk.Toplevel(self.root)
        w.title('Daftar Materi (Admin view)')
        cols = ('ID','Title','Type','Uploaded','Cipher','File')
        tree = ttk.Treeview(w, columns=cols, show='headings')
        for c in cols:
            tree.heading(c, text=c)
        tree.column('ID', width=40)
        tree.pack(fill='both', expand=True, padx=8, pady=8)
        mapping = {}
        for row in list_materials():
            mid, title, mtype, filepath, original_name, cipher, uploader_id, ts = row
            tree.insert('', 'end', values=(mid, title, mtype, ts, cipher or '-', original_name or '-'))
            mapping[mid] = row
        def open_material_admin():
            sel = tree.selection()
            if not sel:
                return
            vals = tree.item(sel[0])['values']
            mid = vals[0]
            row = mapping[mid]
            _, title, mtype, filepath, original_name, cipher, uploader_id, ts = row
            matw = tk.Toplevel(w)
            matw.title(f'Materi: {title}')
            ttk.Label(matw, text=f'{title} ({mtype})', style='Title.TLabel').pack(anchor='w', padx=8, pady=6)
            ttk.Label(matw, text=f'Uploaded: {ts} | File: {original_name or ""} | Cipher: {cipher or "-"}').pack(anchor='w', padx=8)
            def download():
                dest = filedialog.asksaveasfilename(initialfile=os.path.basename(filepath))
                if not dest:
                    return
                try:
                    with open(filepath, 'rb') as fsrc, open(dest, 'wb') as fdst:
                        fdst.write(fsrc.read())
                    messagebox.showinfo('Downloaded', f'File saved to {dest}')
                except Exception as e:
                    messagebox.showerror('Error', f'Failed: {e}')
            ttk.Button(matw, text='Download (as stored)', command=download).pack(pady=6)
        ttk.Button(w, text='Open Selected', command=open_material_admin).pack(pady=8)

    def show_upload_material_dosen(self):
        dlg = tk.Toplevel(self.root)
        dlg.title('Upload Materi')
        ttk.Label(dlg, text='Title:').grid(row=0, column=0, sticky='w', padx=8, pady=6)
        title_ent = ttk.Entry(dlg, width=60)
        title_ent.grid(row=0, column=1, padx=8, pady=6)
        ttk.Label(dlg, text='Pilih Tipe:').grid(row=1, column=0, sticky='w', padx=8, pady=6)
        type_var = tk.StringVar(value='stego')
        ttk.Radiobutton(dlg, text='Gambar (Stego)', variable=type_var, value='stego').grid(row=1, column=1, sticky='w', padx=8)
        ttk.Radiobutton(dlg, text='File (Encrypted)', variable=type_var, value='file').grid(row=1, column=1, sticky='e', padx=8)
        ttk.Separator(dlg, orient='horizontal').grid(row=2, column=0, columnspan=2, sticky='ew', pady=6)
        ttk.Label(dlg, text='Untuk Stego: Pilih gambar (png disarankan) dan masukkan teks yang disembunyikan.').grid(row=3, column=0, columnspan=2, sticky='w', padx=8)
        ttk.Button(dlg, text='Pilih Gambar...', command=lambda: self._choose_stego_file(dlg)).grid(row=4, column=0, sticky='w', padx=8, pady=6)
        self._stego_path_var = tk.StringVar(value='')
        ttk.Label(dlg, textvariable=self._stego_path_var).grid(row=4, column=1, sticky='w')
        ttk.Label(dlg, text='Teks tersembunyi:').grid(row=5, column=0, sticky='w', padx=8)
        self._stego_text = tk.Text(dlg, width=60, height=6)
        self._stego_text.grid(row=5, column=1, padx=8, pady=4)
        ttk.Separator(dlg, orient='horizontal').grid(row=6, column=0, columnspan=2, sticky='ew', pady=6)
        ttk.Label(dlg, text='Untuk File terenkripsi: Pilih file (pdf,ppt,docx, dll), pilih cipher & masukkan key.').grid(row=7, column=0, columnspan=2, sticky='w', padx=8)
        ttk.Button(dlg, text='Pilih File...', command=lambda: self._choose_material_file(dlg)).grid(row=8, column=0, sticky='w', padx=8, pady=6)
        self._file_path_var = tk.StringVar(value='')
        ttk.Label(dlg, textvariable=self._file_path_var).grid(row=8, column=1, sticky='w')
        ttk.Label(dlg, text='Cipher:').grid(row=9, column=0, sticky='w', padx=8)
        self._file_cipher_var = tk.StringVar(value='xor')
        ttk.Combobox(dlg, values=['caesar','vigenere','xor'], textvariable=self._file_cipher_var, width=20).grid(row=9, column=1, sticky='w', padx=8)
        ttk.Label(dlg, text='Key:').grid(row=10, column=0, sticky='w', padx=8)
        self._file_key_ent = ttk.Entry(dlg, width=40)
        self._file_key_ent.grid(row=10, column=1, sticky='w', padx=8, pady=6)

        def do_upload():
            title = title_ent.get().strip()
            ttype = type_var.get()
            if not title:
                messagebox.showwarning('Error', 'Title diperlukan')
                return
            if ttype == 'stego':
                imgpath = self._stego_path_var.get().strip()
                hidden = self._stego_text.get('1.0','end').strip()
                if not imgpath or not hidden:
                    messagebox.showwarning('Error', 'Pilih gambar dan isi teks tersembunyi')
                    return
                bas = os.path.basename(imgpath)
                outname = f"{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{bas}.png"
                outpath = os.path.join(MATERIAL_DIR, outname)
                ok = embed_text_in_image(imgpath, outpath, hidden)
                if not ok:
                    messagebox.showerror('Error', 'Gagal menyembunyikan teks (mungkin ukuran terlalu besar); gunakan gambar lebih besar atau ringkas teks')
                    return
                add_material(title, 'stego', outpath, bas, None, self.user['id'])
                messagebox.showinfo('Uploaded', 'Gambar stego berhasil di-upload')
                dlg.destroy()
            else:
                fpath = self._file_path_var.get().strip()
                cipher = self._file_cipher_var.get().strip().lower()
                key = self._file_key_ent.get().strip()
                if not fpath:
                    messagebox.showwarning('Error', 'Pilih file untuk di-upload')
                    return
                orig = os.path.basename(fpath)
                # Special handling for PDFs: treat as "locked" file with per-file password
                if orig.lower().endswith('.pdf'):
                    # ask for password to lock PDF
                    pw = simpledialog.askstring('PDF Password', 'Masukkan password untuk mengunci file PDF (harus diingat):', parent=dlg, show='*')
                    if pw is None or pw.strip() == '':
                        messagebox.showwarning('Error', 'Password untuk PDF diperlukan (tidak boleh kosong)')
                        return
                    try:
                        outname = f"{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{orig}"
                        outpath = os.path.join(MATERIAL_DIR, outname)
                        with open(fpath, 'rb') as fsrc, open(outpath, 'wb') as fdst:
                            fdst.write(fsrc.read())
                        # store password hash (scrypt)
                        salt, phash = hash_password(pw)
                        add_material(title, 'file', outpath, orig, 'pdf_lock', self.user['id'], file_pw_salt=salt, file_pw_hash=phash)
                        messagebox.showinfo('Uploaded', 'PDF berhasil di-upload dan dikunci dengan password')
                        dlg.destroy()
                    except Exception as e:
                        messagebox.showerror('Error', f'Gagal upload: {e}')
                        return
                else:
                    # normal encryption for other file types: bytes-level encrypt
                    try:
                        with open(fpath, 'rb') as f:
                            data = f.read()
                        enc = encrypt_file_bytes(data, cipher, key)
                        outname = f"{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{orig}.enc"
                        outpath = os.path.join(MATERIAL_DIR, outname)
                        with open(outpath, 'wb') as out:
                            out.write(enc)
                        add_material(title, 'file', outpath, orig, cipher, self.user['id'])
                        messagebox.showinfo('Uploaded', 'File terenkripsi berhasil di-upload')
                        dlg.destroy()
                    except Exception as e:
                        messagebox.showerror('Error', f'Gagal encrypt/upload: {e}')
        ttk.Button(dlg, text='Upload', command=do_upload).grid(row=11, column=0, pady=12, padx=8)
        ttk.Button(dlg, text='Cancel', command=dlg.destroy).grid(row=11, column=1, pady=12, padx=8)

    def _choose_stego_file(self, parent):
        p = filedialog.askopenfilename(filetypes=[('Images','*.png;*.jpg;*.jpeg;*.bmp;*.gif'),('All files','*.*')])
        if p:
            self._stego_path_var.set(p)

    def _choose_material_file(self, parent):
        p = filedialog.askopenfilename(filetypes=[('All files','*.*')])
        if p:
            self._file_path_var.set(p)

    # --- Soal CRUD & Messages (kept similar to previous; modified send message UI for encryption) ---
    def show_soal_dosen(self):
        self.clear_root()
        ttk.Label(self.root, text='Soal (Kelola)', style='Title.TLabel').pack(pady=(8,6), anchor='w', padx=12)
        frame = ttk.Frame(self.root)
        frame.pack(fill='both', expand=True, padx=12, pady=6)
        tree = ttk.Treeview(frame, columns=('id', 'cipher', 'plain', 'key', 'answer'), show='headings')
        for col in ('id', 'cipher', 'plain', 'key', 'answer'):
            tree.heading(col, text=col)
            tree.column(col, width=120)
        tree.pack(fill='both', expand=True)
        def refresh():
            for r in tree.get_children():
                tree.delete(r)
            rows = get_all_questions()
            for row in rows:
                tree.insert('', 'end', values=row)
        refresh()
        def add_q():
            dlg = tk.Toplevel(self.root)
            dlg.title('Tambah Soal')
            ttk.Label(dlg, text='Cipher:').grid(row=0, column=0, sticky='w', padx=6, pady=6)
            cipher_var = tk.StringVar(value='Caesar')
            ttk.Combobox(dlg, values=['Caesar', 'Vigenere', 'Xor', 'Super'], textvariable=cipher_var).grid(row=0, column=1, padx=6, pady=6)
            ttk.Label(dlg, text='Plain Text:').grid(row=1, column=0, sticky='w', padx=6, pady=6)
            plain_ent = ttk.Entry(dlg, width=60)
            plain_ent.grid(row=1, column=1, padx=6, pady=6)
            ttk.Label(dlg, text='Key:').grid(row=2, column=0, sticky='w', padx=6, pady=6)
            key_ent = ttk.Entry(dlg, width=40)
            key_ent.grid(row=2, column=1, padx=6, pady=6)
            def do_add():
                cipher = cipher_var.get()
                plain = plain_ent.get()
                key = key_ent.get()
                if not plain:
                    messagebox.showwarning('Error', 'Plain text required')
                    return
                answer = add_question(cipher, plain, key)
                messagebox.showinfo('Added', f'Soal ditambahkan. Jawaban: {answer}')
                dlg.destroy()
                refresh()
            ttk.Button(dlg, text='Add', command=do_add).grid(row=3, column=0, padx=6, pady=8)
            ttk.Button(dlg, text='Cancel', command=dlg.destroy).grid(row=3, column=1, padx=6, pady=8)
        def delete_q():
            sel = tree.selection()
            if not sel:
                messagebox.showwarning('Error', 'Pilih soal untuk dihapus')
                return
            vals = tree.item(sel[0])['values']
            qid = vals[0]
            if messagebox.askyesno('Confirm', f'Hapus soal ID {qid}?'):
                delete_question(qid)
                refresh()
        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(pady=8)
        tk.Button(btn_frame, text='Add Question', command=add_q, bg=self.primary, fg='white', width=14).pack(side='left', padx=6)
        tk.Button(btn_frame, text='Delete Selected', command=delete_q, bg='#d36b6b', fg='white', width=14).pack(side='left', padx=6)
        tk.Button(btn_frame, text='Back', command=self.build_dosen, bg=self.sky_blue, fg='white', width=14).pack(side='left', padx=6)

    def show_send_message_dosen(self):
        students = get_users_by_role('mahasiswa')
        dlg = tk.Toplevel(self.root)
        dlg.title('Kirim Pesan ke Mahasiswa')
        ttk.Label(dlg, text='Pilih Mahasiswa (hold Ctrl untuk multi-select). Kosong = Broadcast').pack(anchor='w', padx=8, pady=6)
        lb = tk.Listbox(dlg, selectmode='extended', width=50, height=8)
        lb.pack(padx=8, pady=6)
        for sid, sname in students:
            lb.insert('end', f'{sid}: {sname}')
        ttk.Label(dlg, text='Subject:').pack(anchor='w', padx=8)
        subj_ent = ttk.Entry(dlg, width=60)
        subj_ent.pack(padx=8, pady=6)
        ttk.Label(dlg, text='Pesan:').pack(anchor='w', padx=8)
        body_txt = tk.Text(dlg, width=60, height=8)
        body_txt.pack(padx=8, pady=6)

        # Encryption options
        enc_var = tk.IntVar(value=0)
        def toggle_enc():
            if enc_var.get():
                cipher_cb.config(state='normal')
                key_ent.config(state='normal')
            else:
                cipher_cb.config(state='disabled')
                key_ent.config(state='disabled')
        chk = ttk.Checkbutton(dlg, text='Encrypt message?', variable=enc_var, command=toggle_enc)
        chk.pack(anchor='w', padx=8)
        enc_frame = ttk.Frame(dlg)
        enc_frame.pack(anchor='w', padx=8, pady=4)
        ttk.Label(enc_frame, text='Cipher:').grid(row=0, column=0, sticky='w')
        cipher_cb_var = tk.StringVar(value='xor')
        cipher_cb = ttk.Combobox(enc_frame, values=['caesar','vigenere','xor','super'], textvariable=cipher_cb_var, width=12)
        cipher_cb.grid(row=0, column=1, sticky='w', padx=6)
        ttk.Label(enc_frame, text='Key:').grid(row=0, column=2, sticky='w', padx=(12,0))
        key_ent = ttk.Entry(enc_frame, width=20)
        key_ent.grid(row=0, column=3, sticky='w', padx=6)
        cipher_cb.config(state='disabled')
        key_ent.config(state='disabled')

        def send():
            selected = lb.curselection()
            subject = subj_ent.get().strip()
            body = body_txt.get('1.0', 'end').strip()
            if not body:
                messagebox.showwarning('Error', 'Isi pesan diperlukan')
                return
            if enc_var.get():
                cipher = (cipher_cb_var.get() or 'xor').lower()
                key = key_ent.get().strip()
                # encrypt body according to selected cipher
                if cipher == 'caesar':
                    try:
                        k = int(key)
                    except:
                        k = 0
                    enc_body = caesar_encrypt_text(body, k)
                elif cipher == 'vigenere':
                    enc_body = vigenere_encrypt_text(body, key)
                elif cipher == 'xor':
                    enc_body = xor_encrypt_text(body, key)
                elif cipher == 'super':
                    enc_body = super_encrypt_text(body, key)
                else:
                    enc_body = body
                is_enc_flag = 1
            else:
                enc_body = body
                cipher = None
                key = None
                is_enc_flag = 0

            if not selected:
                add_message(self.user['id'], None, subject or '(no subject)', enc_body, is_encrypted=is_enc_flag, cipher=cipher, enc_key=key)
            else:
                for idx in selected:
                    item = lb.get(idx)
                    sid = int(item.split(':',1)[0])
                    add_message(self.user['id'], sid, subject or '(no subject)', enc_body, is_encrypted=is_enc_flag, cipher=cipher, enc_key=key)
            messagebox.showinfo('Sent', 'Pesan terkirim')
            dlg.destroy()
        ttk.Button(dlg, text='Send', command=send).pack(pady=6)

    def logout(self):
        self.user = None
        self.build_login()