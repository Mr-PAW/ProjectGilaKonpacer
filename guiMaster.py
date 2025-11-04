import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import sqlite3
import datetime
from cipherGIla import caesar_decrypt_text, vigenere_decrypt_text, xor_decrypt_text, super_decrypt_text, decrypt_file_bytes, caesar_encrypt_text, encrypt_file_bytes, vigenere_encrypt_text, xor_encrypt_text, super_encrypt_text
from database import DB_FILE, add_user, authenticate, verify_password, init_db
from ideGilaRaffy import recognize_face_login, train_face_model, capture_face_samples, MATERIAL_DIR, FACE_MODEL_FILE, FACES_DIR
from hashPass import image_hash_bytes, hash_password
from steganografi import extract_text_from_image, embed_text_in_image
from materi import add_material, list_materials, get_material
from soal import get_questions_by_cipher, add_question, get_all_questions, delete_question
from pesan import get_inbox_for_user, mark_message_read, get_users_by_role, add_message
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
        # macOS-like color palette and typography
        # Light macOS background, white cards, and system blue accent
        self.bg = '#F5F5F7'    # macOS light window background
        self.card = '#FFFFFF'
        self.primary = '#007AFF'  # macOS blue
        self.accent = '#0A84FF'
        # Additional palette variables used across the UI
        self.dark_purple = '#3A3A3C'
        self.sky_blue = '#5AC8FA'
        self.text = '#1D1D1F'  # primary text color
        self.subtext = '#6E6E73'

        style = ttk.Style()
        # Prefer a neutral theme that allows custom styling
        try:
            style.theme_use('clam')
        except Exception:
            try:
                style.theme_use('default')
            except Exception:
                pass

        # General frame/background
        style.configure('TFrame', background=self.bg)
        style.configure('Card.TFrame', background=self.card, relief='flat')

        # Labels & titles
        # Use macOS-like fonts where available; fall back to common fonts
        title_font = ('Helvetica Neue', 13, 'bold')
        normal_font = ('Helvetica Neue', 11)
        try:
            style.configure('TLabel', background=self.bg, foreground=self.text, font=normal_font)
            style.configure('Title.TLabel', font=title_font, background=self.bg, foreground=self.text)
        except Exception:
            style.configure('TLabel', background=self.bg, foreground=self.text)
            style.configure('Title.TLabel', background=self.bg, foreground=self.text)

        # Buttons - add an accent style for primary actions
        style.configure('TButton', font=normal_font, padding=6)
        style.configure('Accent.TButton', background=self.primary, foreground='white', font=normal_font, padding=6)
        # Small card visuals
        style.map('Accent.TButton', background=[('active', self.accent)])

        # Treeview and headings
        style.configure('Treeview', background='white', fieldbackground='white', foreground=self.text)
        style.configure('Treeview.Heading', font=normal_font)

        # Apply window background
        try:
            self.root.configure(background=self.bg)
        except Exception:
            pass

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
                if err and 'UNIQUE constraint failed' in err:
                    messagebox.showerror('Error', 'Username sudah digunakan. Pilih username lain.')
                else:
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
                # nicer message for duplicate username
                if err and 'UNIQUE constraint failed' in err:
                    messagebox.showerror('Error', 'Username sudah ada. Gunakan username lain.')
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

            if mtype == 'stego':
                def download_stego():
                    dest = filedialog.asksaveasfilename(initialfile=(original_name or os.path.basename(filepath)))
                    if not dest:
                        return
                    try:
                        with open(filepath, 'rb') as fsrc, open(dest, 'wb') as fdst:
                            fdst.write(fsrc.read())
                        messagebox.showinfo('Downloaded', f'File saved to {dest}')
                    except Exception as e:
                        messagebox.showerror('Error', f'Failed: {e}')
                ttk.Button(matw, text='Download Image', command=download_stego).pack(pady=6)
                
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
                # All encrypted files require password verification to decrypt and download
                if pw_salt and pw_hash:
                    def decrypt_and_download():
                        password = simpledialog.askstring('Password Required', 
                                                         'Masukkan password untuk mendekripsi file (tanyakan ke dosen):', 
                                                         parent=matw, show='*')
                        if password is None:
                            return
                        # Verify password
                        if not verify_password(password, pw_salt, pw_hash):
                            messagebox.showerror('Error', 'Password salah!')
                            return
                        # Password correct, decrypt file
                        try:
                            with open(filepath, 'rb') as f:
                                enc_data = f.read()
                            # Decrypt using stored cipher and provided password
                            dec_data = decrypt_file_bytes(enc_data, cipher, password)
                            # Save with original filename (restore extension)
                            dest = filedialog.asksaveasfilename(initialfile=original_name)
                            if not dest:
                                return
                            with open(dest, 'wb') as out:
                                out.write(dec_data)
                            messagebox.showinfo('Success', f'File berhasil didekripsi dan disimpan ke:\n{dest}')
                        except Exception as e:
                            messagebox.showerror('Error', f'Gagal dekripsi (mungkin password salah atau file rusak): {e}')
                    ttk.Button(matw, text='Decrypt & Download (butuh password)', command=decrypt_and_download).pack(pady=6)
                else:
                    # Fallback for old materials without password (shouldn't happen with new system)
                    ttk.Label(matw, text='File tidak dilindungi password (format lama)', foreground='red').pack(pady=6)

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

        def decrypt_answer():
            lc = (cipher or '').lower()
            try:
                if lc == 'vigenere':
                    k = simpledialog.askstring('Vigenere key', 'Masukkan Vigenere key untuk dekripsi:', parent=w)
                    if k is None:
                        return
                    if not k or not k.isalpha():
                        messagebox.showerror('Error', 'Vigenere key harus berisi huruf saja (A-Z).')
                        return
                    dec = vigenere_decrypt_text(answer, k)
                elif lc == 'caesar':
                    ks = simpledialog.askstring('Caesar key', 'Masukkan Caesar shift (integer):', parent=w)
                    if ks is None:
                        return
                    try:
                        k = int(ks)
                    except Exception:
                        messagebox.showerror('Error', 'Caesar key harus berupa angka (integer).')
                        return
                    dec = caesar_decrypt_text(answer, k)
                elif lc == 'xor':
                    k = simpledialog.askstring('XOR key', 'Masukkan XOR key untuk dekripsi (digits only):', parent=w)
                    if k is None:
                        return
                    if not k.isdigit():
                        messagebox.showerror('Error', 'XOR key harus berupa angka (digit sequence).')
                        return
                    dec = xor_decrypt_text(answer, k)
                elif lc == 'super':
                    use_separate = messagebox.askyesno('Super Cipher', 'Gunakan kunci terpisah untuk Caesar / Vigenere / XOR?')
                    if use_separate:
                        # Ask in order Caesar, Vigenere, XOR as requested
                        caes = simpledialog.askstring('Caesar shift', 'Masukkan Caesar shift (integer, leave empty to derive):', parent=w)
                        vig = simpledialog.askstring('Vigenere key', 'Masukkan Vigenere key (leave empty to skip):', parent=w)
                        xr = simpledialog.askstring('XOR key', 'Masukkan XOR key (leave empty to skip):', parent=w)
                        if caes is None and vig is None and xr is None:
                            return
                        # validate
                        if vig and not vig.isalpha():
                            messagebox.showerror('Error', 'Vigenere key harus berisi huruf saja (A-Z).')
                            return
                        if caes:
                            try:
                                int(caes)
                            except Exception:
                                messagebox.showerror('Error', 'Caesar shift harus berupa angka (integer).')
                                return
                        if xr and not xr.isdigit():
                            messagebox.showerror('Error', 'XOR key harus berupa angka (digit sequence).')
                            return
                        parts = []
                        if vig:
                            parts.append(f"vig={vig}")
                        if caes:
                            parts.append(f"caesar={caes}")
                        if xr:
                            parts.append(f"xor={xr}")
                        comp = ';'.join(parts)
                        dec = super_decrypt_text(answer, comp)
                    else:
                        k = simpledialog.askstring('Super key', 'Masukkan single key untuk super dekripsi (legacy):', parent=w)
                        if k is None:
                            return
                        if not k:
                            messagebox.showerror('Error', 'Key diperlukan untuk dekripsi.')
                            return
                        dec = super_decrypt_text(answer, k)
                else:
                    messagebox.showerror('Error', 'Cipher tidak dikenali')
                    return

                # Show decrypted text in a small viewer
                dv = tk.Toplevel(w)
                dv.title('Decrypted Answer')
                t = tk.Text(dv, width=80, height=12)
                t.pack(padx=8, pady=8)
                t.insert('end', dec)
                t.config(state='disabled')
            except Exception as e:
                messagebox.showerror('Error', f'Gagal dekripsi: {e}')

        btn_frame = ttk.Frame(w)
        btn_frame.pack(pady=6)
        ttk.Button(btn_frame, text='Check', command=check).pack(side='left', padx=6)
        ttk.Button(btn_frame, text='Decrypt Answer', command=decrypt_answer).pack(side='left', padx=6)

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
            
            # Show cipher info if encrypted
            if is_encrypted:
                ttk.Label(msgw, text=f'Pesan terenkripsi dengan: {(cipher or "unknown").upper()}', 
                         foreground=self.dark_purple, font=('Segoe UI', 9, 'italic')).pack(anchor='w', padx=8, pady=2)
            
            txt = tk.Text(msgw, width=80, height=12)
            txt.pack(padx=8, pady=4)

            # If encrypted, show ciphertext first, then allow decryption
            if is_encrypted:
                # Display ciphertext immediately
                txt.insert('end', body)
                txt.config(state='disabled')
                
                def try_decrypt():
                    key = simpledialog.askstring('Decrypt Message', 'Masukkan key untuk mendekripsi pesan:', parent=msgw)
                    if key is None:
                        return

                    lc = (cipher or '').lower()
                    try:
                        if lc == 'vigenere':
                            # validate alphabetic
                            if not key or not key.isalpha():
                                messagebox.showerror('Error', 'Vigenere key harus berisi huruf saja (A-Z).')
                                return
                            dec = vigenere_decrypt_text(body, key)
                        elif lc == 'caesar':
                            try:
                                k = int(key)
                            except Exception:
                                messagebox.showerror('Error', 'Caesar key harus berupa angka (integer).')
                                return
                            dec = caesar_decrypt_text(body, k)
                        elif lc == 'xor':
                            # require digits-only key (per requested validation)
                            if not key.isdigit():
                                messagebox.showerror('Error', 'XOR key harus berupa angka (digit sequence).')
                                return
                            dec = xor_decrypt_text(body, key)
                        elif lc == 'super':
                            # Ask whether to use separate keys for each stage or a single legacy key
                            use_separate = messagebox.askyesno('Super Cipher', 'Use separate keys for Vigenere / Caesar / XOR?')
                            if use_separate:
                                vig = simpledialog.askstring('Vigenere key', 'Masukkan Vigenere key (leave empty to skip):', parent=msgw)
                                caes = simpledialog.askstring('Caesar shift', 'Masukkan Caesar shift (integer, leave empty to derive):', parent=msgw)
                                xr = simpledialog.askstring('XOR key', 'Masukkan XOR key (leave empty to skip):', parent=msgw)
                                if vig is None and caes is None and xr is None:
                                    return
                                # validate provided parts
                                if vig and not vig.isalpha():
                                    messagebox.showerror('Error', 'Vigenere key harus berisi huruf saja (A-Z).')
                                    return
                                if caes:
                                    try:
                                        int(caes)
                                    except Exception:
                                        messagebox.showerror('Error', 'Caesar shift harus berupa angka (integer).')
                                        return
                                if xr and not xr.isdigit():
                                    messagebox.showerror('Error', 'XOR key harus berupa angka (digit sequence).')
                                    return
                                parts = []
                                if vig:
                                    parts.append(f"vig={vig}")
                                if caes:
                                    parts.append(f"caesar={caes}")
                                if xr:
                                    parts.append(f"xor={xr}")
                                comp = ';'.join(parts)
                                dec = super_decrypt_text(body, comp)
                            else:
                                # legacy single-key behavior: allow any non-empty key
                                if not key:
                                    messagebox.showerror('Error', 'Key diperlukan untuk dekripsi.')
                                    return
                                dec = super_decrypt_text(body, key)
                        else:
                            messagebox.showerror('Error', 'Cipher tidak dikenali')
                            return
                        
                        # Check if decryption seems successful (basic validation)
                        if dec and len(dec.strip()) > 0:
                            # Replace text box content with decrypted text
                            txt.config(state='normal')
                            txt.delete('1.0', 'end')
                            txt.insert('end', dec)
                            txt.config(state='disabled')
                            mark_message_read(mid)
                            messagebox.showinfo('Success', 'Pesan berhasil didekripsi!')
                        else:
                            messagebox.showwarning('Warning', 'Key mungkin salah - hasil dekripsi kosong')
                    except Exception as e:
                        messagebox.showerror('Error', f'Key salah atau gagal dekripsi: {e}')
                
                ttk.Button(msgw, text='Decrypt (masukkan key)', command=try_decrypt).pack(pady=6)
            else:
                # Plain text message
                txt.insert('end', body)
                txt.config(state='disabled')
                mark_message_read(mid)
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
        tk.Button(btns, text='Soal', width=16, command=self.show_soal_dosen, bg=self.dark_purple, fg='white').pack(side='left', padx=6)
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
        ttk.Label(dlg, text='Untuk File terenkripsi: Pilih file (pdf,ppt,docx, dll) dan masukkan password.').grid(row=7, column=0, columnspan=2, sticky='w', padx=8)
        ttk.Button(dlg, text='Pilih File...', command=lambda: self._choose_material_file(dlg)).grid(row=8, column=0, sticky='w', padx=8, pady=6)
        self._file_path_var = tk.StringVar(value='')
        ttk.Label(dlg, textvariable=self._file_path_var).grid(row=8, column=1, sticky='w')
        ttk.Label(dlg, text='Password (untuk mahasiswa decrypt):').grid(row=9, column=0, sticky='w', padx=8)
        self._file_password_ent = ttk.Entry(dlg, width=40, show='*')
        self._file_password_ent.grid(row=9, column=1, sticky='w', padx=8, pady=6)
        ttk.Label(dlg, text='(Cipher XOR akan digunakan secara otomatis)', foreground='gray').grid(row=10, column=0, columnspan=2, sticky='w', padx=8)

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
                # Encrypted file upload (unified approach for all file types)
                fpath = self._file_path_var.get().strip()
                password = self._file_password_ent.get().strip()
                if not fpath:
                    messagebox.showwarning('Error', 'Pilih file untuk di-upload')
                    return
                if not password:
                    messagebox.showwarning('Error', 'Password diperlukan untuk mengenkripsi file')
                    return
                orig = os.path.basename(fpath)
                try:
                    # Read original file
                    with open(fpath, 'rb') as f:
                        data = f.read()
                    # Encrypt using XOR cipher with the password as key
                    cipher = 'xor'
                    enc = encrypt_file_bytes(data, cipher, password)
                    # Save encrypted file with .enc extension, preserving original name
                    outname = f"{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{orig}.enc"
                    outpath = os.path.join(MATERIAL_DIR, outname)
                    with open(outpath, 'wb') as out:
                        out.write(enc)
                    # Store password hash (scrypt) for verification
                    salt, phash = hash_password(password)
                    add_material(title, 'file', outpath, orig, cipher, self.user['id'], file_pw_salt=salt, file_pw_hash=phash)
                    messagebox.showinfo('Uploaded', 'File terenkripsi berhasil di-upload dengan password')
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
            cb = ttk.Combobox(dlg, values=['Caesar', 'Vigenere', 'Xor', 'Super'], textvariable=cipher_var)
            cb.grid(row=0, column=1, padx=6, pady=6)
            ttk.Label(dlg, text='Plain Text:').grid(row=1, column=0, sticky='w', padx=6, pady=6)
            plain_ent = ttk.Entry(dlg, width=60)
            plain_ent.grid(row=1, column=1, padx=6, pady=6)
            ttk.Label(dlg, text='Key:').grid(row=2, column=0, sticky='w', padx=6, pady=6)
            # Single key entry (used for non-super ciphers)
            key_ent = ttk.Entry(dlg, width=40)
            key_ent.grid(row=2, column=1, padx=6, pady=6)

            # Additional entries for Super cipher (Caesar, Vigenere, XOR) in requested order
            caesar_label = ttk.Label(dlg, text='Caesar shift:')
            caesar_ent = ttk.Entry(dlg, width=10)
            vig_label = ttk.Label(dlg, text='Vigenere key:')
            vig_ent = ttk.Entry(dlg, width=30)
            xor_label = ttk.Label(dlg, text='XOR key:')
            xor_ent = ttk.Entry(dlg, width=30)

            # place them but hide initially (rows 3..5)
            caesar_label.grid(row=3, column=0, sticky='w', padx=6, pady=2)
            caesar_ent.grid(row=3, column=1, sticky='w', padx=6, pady=2)
            vig_label.grid(row=4, column=0, sticky='w', padx=6, pady=2)
            vig_ent.grid(row=4, column=1, sticky='w', padx=6, pady=2)
            xor_label.grid(row=5, column=0, sticky='w', padx=6, pady=2)
            xor_ent.grid(row=5, column=1, sticky='w', padx=6, pady=2)
            caesar_label.grid_remove(); caesar_ent.grid_remove(); vig_label.grid_remove(); vig_ent.grid_remove(); xor_label.grid_remove(); xor_ent.grid_remove()

            def _on_cipher_change(*args):
                val = (cipher_var.get() or '').lower()
                if val == 'super':
                    # hide single key, show the three keys
                    key_ent.grid_remove()
                    caesar_label.grid(); caesar_ent.grid(); vig_label.grid(); vig_ent.grid(); xor_label.grid(); xor_ent.grid()
                else:
                    # show single key, hide extras
                    key_ent.grid(); caesar_label.grid_remove(); caesar_ent.grid_remove(); vig_label.grid_remove(); vig_ent.grid_remove(); xor_label.grid_remove(); xor_ent.grid_remove()

            cipher_var.trace_add('write', _on_cipher_change)
            # call once to set initial visibility
            _on_cipher_change()
            def do_add():
                cipher = cipher_var.get()
                plain = plain_ent.get()
                # For Super cipher, compose a composite key string
                if (cipher or '').lower() == 'super':
                    vig = vig_ent.get().strip()
                    caes = caesar_ent.get().strip()
                    xr = xor_ent.get().strip()
                    parts = []
                    if vig:
                        parts.append(f"vig={vig}")
                    if caes:
                        parts.append(f"caesar={caes}")
                    if xr:
                        parts.append(f"xor={xr}")
                    key = ';'.join(parts)
                else:
                    key = key_ent.get()
                if not plain:
                    messagebox.showwarning('Error', 'Plain text required')
                    return

                # Validate keys according to cipher type
                lc = (cipher or '').lower()
                if lc == 'caesar':
                    # single key_ent must be integer
                    k = key_ent.get().strip()
                    try:
                        int(k)
                    except Exception:
                        messagebox.showerror('Error', 'Caesar key harus berupa angka (integer).')
                        return
                elif lc == 'vigenere':
                    k = key_ent.get().strip()
                    if not k or not k.isalpha():
                        messagebox.showerror('Error', 'Vigenere key harus berisi huruf saja (A-Z).')
                        return
                elif lc == 'xor':
                    k = key_ent.get().strip()
                    if not k or not k.isdigit():
                        messagebox.showerror('Error', 'XOR key harus berupa angka (digit sequence).')
                        return
                elif lc == 'super':
                    # validate provided parts (if any)
                    vig_val = vig_ent.get().strip()
                    caes_val = caesar_ent.get().strip()
                    xr_val = xor_ent.get().strip()
                    if vig_val and not vig_val.isalpha():
                        messagebox.showerror('Error', 'Vigenere key harus berisi huruf saja (A-Z).')
                        return
                    if caes_val:
                        try:
                            int(caes_val)
                        except Exception:
                            messagebox.showerror('Error', 'Caesar shift harus berupa angka (integer).')
                            return
                    if xr_val and not xr_val.isdigit():
                        messagebox.showerror('Error', 'XOR key harus berupa angka (digit sequence).')
                        return
                answer = add_question(cipher, plain, key)
                messagebox.showinfo('Added', f'Soal ditambahkan. Jawaban: {answer}')
                dlg.destroy()
                refresh()
            # Place Add/Cancel below the super key inputs (row 6)
            ttk.Button(dlg, text='Add', command=do_add).grid(row=6, column=0, padx=6, pady=8)
            ttk.Button(dlg, text='Cancel', command=dlg.destroy).grid(row=6, column=1, padx=6, pady=8)
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

        # Encryption with Vigenere cipher (automatic)
        ttk.Label(dlg, text='Pesan akan dienkripsi dengan Vigenere Cipher', foreground=self.dark_purple, font=('Segoe UI', 10, 'bold')).pack(anchor='w', padx=8, pady=(8,4))
        enc_frame = ttk.Frame(dlg)
        enc_frame.pack(anchor='w', padx=8, pady=4)
        ttk.Label(enc_frame, text='Key untuk enkripsi:').grid(row=0, column=0, sticky='w')
        key_ent = ttk.Entry(enc_frame, width=30)
        key_ent.grid(row=0, column=1, sticky='w', padx=6)

        def send():
            selected = lb.curselection()
            subject = subj_ent.get().strip()
            body = body_txt.get('1.0', 'end').strip()
            if not body:
                messagebox.showwarning('Error', 'Isi pesan diperlukan')
                return
            
            # Always encrypt with Vigenere cipher
            key = key_ent.get().strip()
            if not key:
                messagebox.showwarning('Error', 'Key untuk enkripsi diperlukan')
                return
            # Validate vigenere key: must be alphabetic
            if not key.isalpha():
                messagebox.showerror('Error', 'Vigenere key harus berisi huruf saja (A-Z).')
                return

            # Encrypt with Vigenere
            cipher = 'vigenere'
            enc_body = vigenere_encrypt_text(body, key)
            is_enc_flag = 1

            if not selected:
                add_message(self.user['id'], None, subject or '(no subject)', enc_body, is_encrypted=is_enc_flag, cipher=cipher, enc_key=key)
            else:
                for idx in selected:
                    item = lb.get(idx)
                    sid = int(item.split(':',1)[0])
                    add_message(self.user['id'], sid, subject or '(no subject)', enc_body, is_encrypted=is_enc_flag, cipher=cipher, enc_key=key)
            messagebox.showinfo('Sent', 'Pesan terkirim dengan enkripsi Vigenere')
            dlg.destroy()
        ttk.Button(dlg, text='Send', command=send).pack(pady=6)

    def logout(self):
        self.user = None
        self.build_login()