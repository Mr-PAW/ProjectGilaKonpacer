import tkinter as tk
from guiMaster import App
from database import init_db

if __name__ == '__main__':
    init_db()
    root = tk.Tk()
    root.geometry('1000x700')
    app = App(root)
    root.mainloop()