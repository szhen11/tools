#!/usr/bin/python3

from tkinter import *
import os

top=Tk()

top.geometry("210x620")
top.title("Demo Utils")

def taskCallback(cmd):
    os.system(cmd)

tasklist = [
        ("Install", "/home/wid/install.sh"),
        ("Config Input", "./config_input.sh"),
        ("Demo Basic", "/home/wid/demo1.sh"),
        ("Demo Games", "/home/wid/demo2.sh"),
        ("Android Clean", "/home/wid/cleanup.sh"),
        ("Stop Steam", "/home/wid/stop_steam.sh"),
        ("4K media playback", "/home/wid/4kmpv.sh"),
        ("Backup Config", "/home/wid/backup.sh"),
        ("Restore Config", "/home/wid/restore.sh")
        ]

for t, cmd in tasklist:
    bt = Button(top, text = t, height = "3", width ="90", command = lambda x=cmd: taskCallback(x))
    bt.pack()

top.mainloop()
