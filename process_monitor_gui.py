"""
Process Monitor GUI
===================
หน้าจอเฝ้าดูโปรเซสแบบ GUI ใช้กฎให้คะแนนจาก process_monitor.py (ต้องอยู่โฟลเดอร์เดียวกัน)

ติดตั้ง:  pip install psutil
รัน:      python process_monitor_gui.py
          (แนะนำ Run as administrator เพื่อเห็นโปรเซสระบบครบ)
"""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import time
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import process_monitor as pm  # noqa: E402
import psutil  # noqa: E402

FONT = ("Leelawadee UI", 10) if pm.IS_WINDOWS else ("TkDefaultFont", 10)
FONT_B = (FONT[0], 10, "bold")
FONT_TITLE = (FONT[0], 13, "bold")

COLORS = {
    "high": "#ffd6d6",
    "mid": "#fff2c2",
    "low": "#e3f0ff",
    "ok": "#ffffff",
    "trusted": "#e6f4ea",
}


def level_key(score: int) -> str:
    if score >= 60:
        return "high"
    if score >= 30:
        return "mid"
    if score > 0:
        return "low"
    return "ok"


LEVEL_TH = {"high": "สูง", "mid": "กลาง", "low": "ต่ำ", "ok": "ปกติ", "trusted": "เชื่อถือ"}


def is_admin() -> bool:
    if not pm.IS_WINDOWS:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def safe_int(var: tk.IntVar, default: int) -> int:
    try:
        return int(var.get())
    except (tk.TclError, ValueError):
        return default


class Scanner(threading.Thread):
    """สแกนโปรเซสใน thread แยก ส่งผลกลับผ่าน queue"""

    def __init__(self, out: queue.Queue, get_interval, use_sig: bool):
        super().__init__(daemon=True)
        self.out = out
        self.get_interval = get_interval
        self.sig = pm.SignatureCache(enabled=use_sig)
        self.running = threading.Event()
        self.alive = True
        self.seen: set[tuple[int, str]] | None = None

    def run(self) -> None:
        while self.alive:
            if not self.running.is_set():
                self.running.wait(0.5)
                continue
            t0 = time.time()
            try:
                procs = pm.analyze(self.sig)
            except Exception as exc:
                self.out.put(("error", str(exc)))
                time.sleep(2)
                continue
            keys = {(p.pid, p.created) for p in procs}
            if self.seen is None:
                fresh, first = [], True
            else:
                fresh, first = [p for p in procs if (p.pid, p.created) not in self.seen], False
            self.seen = keys
            self.out.put(("scan", procs, fresh, first, time.time() - t0))
            # รอจนครบรอบ แต่ตอบสนองต่อการกดหยุดทันที
            end = time.time() + self.get_interval()
            while self.alive and self.running.is_set() and time.time() < end:
                time.sleep(0.2)

    def start_monitor(self) -> None:
        self.seen = None
        self.running.set()

    def stop_monitor(self) -> None:
        self.running.clear()


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Process Monitor")
        self.geometry("1200x720")
        self.minsize(900, 560)
        self.option_add("*Font", FONT)

        self.q: queue.Queue = queue.Queue()
        self.procs: dict[int, pm.ProcInfo] = {}
        self.monitoring = False
        self.alert_count = 0
        self.alerted: set[tuple[int, str]] = set()

        self.var_interval = tk.IntVar(value=5)
        self.var_min = tk.IntVar(value=30)
        self.var_only_sus = tk.BooleanVar(value=True)
        self.var_popup = tk.BooleanVar(value=True)
        self.var_sound = tk.BooleanVar(value=True)
        self.var_sig = tk.BooleanVar(value=True)
        self.var_search = tk.StringVar()
        self.var_search.trace_add("write", lambda *_: self.refresh_table())

        self._build_ui()
        self.scanner = Scanner(self.q, lambda: max(1, safe_int(self.var_interval, 5)),
                               use_sig=self.var_sig.get())
        self.scanner.start()
        self.after(200, self.poll_queue)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # ------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        # ตั้งฟอนต์ระบบทุกตัวให้รองรับภาษาไทย (ttk Checkbutton/Notebook ใช้ named font)
        import tkinter.font as tkfont
        for fname in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont",
                      "TkCaptionFont", "TkSmallCaptionFont", "TkIconFont", "TkTooltipFont"):
            try:
                tkfont.nametofont(fname).configure(family=FONT[0], size=10)
            except tk.TclError:
                pass
        for st in ("TCheckbutton", "TLabel", "TButton", "TEntry", "TSpinbox",
                   "TNotebook.Tab"):
            style.configure(st, font=FONT)
        style.configure("Treeview", rowheight=24, font=FONT)
        style.configure("Treeview.Heading", font=FONT_B)

        # แถบบน: ปุ่มเปิดปิด + สถานะ
        top = tk.Frame(self, padx=12, pady=10)
        top.pack(fill="x")

        self.btn_toggle = tk.Button(
            top, text="▶  เริ่มเฝ้าดู", font=FONT_TITLE, width=14,
            bg="#2e7d32", fg="white", activebackground="#1b5e20",
            activeforeground="white", relief="flat", cursor="hand2",
            command=self.toggle)
        self.btn_toggle.pack(side="left")

        status_box = tk.Frame(top, padx=14)
        status_box.pack(side="left")
        self.lbl_state = tk.Label(status_box, text="● ปิดอยู่", fg="#9e9e9e", font=FONT_TITLE)
        self.lbl_state.pack(anchor="w")
        self.lbl_stats = tk.Label(status_box, text="ยังไม่ได้สแกน", fg="#555")
        self.lbl_stats.pack(anchor="w")

        tk.Button(top, text="สแกนครั้งเดียว", command=self.scan_once,
                  relief="groove", padx=10).pack(side="left", padx=4)

        admin = "Administrator" if is_admin() else "ผู้ใช้ทั่วไป (เห็นโปรเซสระบบไม่ครบ)"
        tk.Label(top, text=f"สิทธิ์: {admin}",
                 fg="#2e7d32" if is_admin() else "#c62828").pack(side="right")

        # แถบตั้งค่า
        opt = tk.Frame(self, padx=12)
        opt.pack(fill="x")
        tk.Label(opt, text="สแกนทุก").pack(side="left")
        ttk.Spinbox(opt, from_=1, to=120, width=4, textvariable=self.var_interval).pack(side="left", padx=3)
        tk.Label(opt, text="วินาที    แจ้งเตือนเมื่อคะแนน ≥").pack(side="left")
        ttk.Spinbox(opt, from_=1, to=100, width=4, textvariable=self.var_min,
                    command=self.refresh_table).pack(side="left", padx=3)
        for text, var in (("แสดงเฉพาะที่มีคะแนน", self.var_only_sus),
                          ("กล่องแจ้งเตือน", self.var_popup),
                          ("เสียง", self.var_sound),
                          ("ตรวจ signature", self.var_sig)):
            ttk.Checkbutton(opt, text=text, variable=var,
                            command=self._on_option).pack(side="left", padx=8)
        tk.Label(opt, text="ค้นหา:").pack(side="left", padx=(16, 2))
        ttk.Entry(opt, textvariable=self.var_search, width=18).pack(side="left")

        # พื้นที่หลัก: ตาราง (บน) + รายละเอียด/แจ้งเตือน (ล่าง)
        pane = ttk.PanedWindow(self, orient="vertical")
        pane.pack(fill="both", expand=True, padx=12, pady=8)

        table_frame = tk.Frame(pane)
        cols = ("pid", "name", "cpu", "ram", "net", "sig", "score", "level", "path")
        heads = ("PID", "ชื่อโปรเซส", "CPU%", "RAM MB", "NET", "SIG", "คะแนน", "ระดับ", "Path")
        widths = (70, 200, 60, 80, 50, 60, 60, 60, 520)
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        for c, h, w in zip(cols, heads, widths):
            self.tree.heading(c, text=h, command=lambda c=c: self.sort_by(c))
            anchor = "w" if c in ("name", "path") else "center"
            self.tree.column(c, width=w, anchor=anchor, stretch=(c == "path"))
        for key, color in COLORS.items():
            self.tree.tag_configure(key, background=color)
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.show_detail)
        pane.add(table_frame, weight=3)

        bottom = ttk.Notebook(pane)
        # แท็บรายละเอียด
        det = tk.Frame(bottom, padx=8, pady=6)
        self.txt_detail = tk.Text(det, height=8, wrap="word", relief="flat",
                                  bg="#fafafa", font=FONT)
        self.txt_detail.pack(side="left", fill="both", expand=True)
        btns = tk.Frame(det, padx=8)
        btns.pack(side="right", fill="y")
        tk.Button(btns, text="เปิดตำแหน่งไฟล์", width=16, relief="groove",
                  command=self.open_location).pack(pady=2)
        tk.Button(btns, text="คัดลอก path", width=16, relief="groove",
                  command=self.copy_path).pack(pady=2)
        self.btn_trust = tk.Button(btns, text="เชื่อถือโปรแกรมนี้", width=16, relief="groove",
                                   fg="#2e7d32", command=self.toggle_trust)
        self.btn_trust.pack(pady=(14, 2))
        tk.Button(btns, text="ปิดโปรเซสนี้", width=16, relief="groove", fg="#c62828",
                  command=self.kill_selected).pack(pady=2)
        bottom.add(det, text="  รายละเอียด  ")

        # แท็บประวัติแจ้งเตือน
        al = tk.Frame(bottom, padx=8, pady=6)
        self.lst_alert = tk.Listbox(al, font=FONT, activestyle="none")
        self.lst_alert.pack(side="left", fill="both", expand=True)
        asb = ttk.Scrollbar(al, orient="vertical", command=self.lst_alert.yview)
        self.lst_alert.configure(yscrollcommand=asb.set)
        asb.pack(side="left", fill="y")
        tk.Button(al, text="เปิดไฟล์ log", relief="groove",
                  command=self.open_log).pack(side="right", padx=8, anchor="n")
        bottom.add(al, text="  ประวัติแจ้งเตือน (0)  ")
        tr = tk.Frame(bottom, padx=8, pady=6)
        self.lst_trust = tk.Listbox(tr, font=FONT, activestyle="none")
        self.lst_trust.pack(side="left", fill="both", expand=True)
        tsb = ttk.Scrollbar(tr, orient="vertical", command=self.lst_trust.yview)
        self.lst_trust.configure(yscrollcommand=tsb.set)
        tsb.pack(side="left", fill="y")
        tk.Button(tr, text="ลบออกจากรายการ", relief="groove",
                  command=self.remove_trusted).pack(side="right", padx=8, anchor="n")
        bottom.add(tr, text="  รายการที่เชื่อถือ  ")
        self.notebook = bottom
        pane.add(bottom, weight=1)
        self.refresh_trust_list()

        self.sort_col, self.sort_rev = "score", True

    # ------------------------------------------------------------ เปิด/ปิด
    def toggle(self) -> None:
        if self.monitoring:
            self.scanner.stop_monitor()
            self.monitoring = False
            self.btn_toggle.config(text="▶  เริ่มเฝ้าดู", bg="#2e7d32", activebackground="#1b5e20")
            self.lbl_state.config(text="● ปิดอยู่", fg="#9e9e9e")
        else:
            self.scanner.start_monitor()
            self.monitoring = True
            self.btn_toggle.config(text="■  หยุดเฝ้าดู", bg="#c62828", activebackground="#8e0000")
            self.lbl_state.config(text="● กำลังเฝ้าดู", fg="#2e7d32")
            self.lbl_stats.config(text="กำลังสแกนรอบแรก (ตรวจ signature อาจใช้ 10-30 วินาที)...")

    def scan_once(self) -> None:
        if self.monitoring:
            return
        self.lbl_stats.config(text="กำลังสแกน...")

        def work():
            try:
                procs = pm.analyze(self.scanner.sig)
                self.q.put(("scan", procs, [], True, 0))
            except Exception as exc:
                self.q.put(("error", str(exc)))
        threading.Thread(target=work, daemon=True).start()

    def _on_option(self) -> None:
        self.scanner.sig.enabled = self.var_sig.get() and pm.IS_WINDOWS
        self.refresh_table()

    # ------------------------------------------------------------ รับผลสแกน
    def poll_queue(self) -> None:
        try:
            while True:
                msg = self.q.get_nowait()
                if msg[0] == "scan":
                    _, procs, fresh, first, took = msg
                    self.procs = {p.pid: p for p in procs}
                    self.refresh_table()
                    sus = sum(1 for p in procs if p.score >= safe_int(self.var_min, 30))
                    self.lbl_stats.config(
                        text=f"{len(procs)} โปรเซส | น่าสงสัย (≥{safe_int(self.var_min, 30)}) {sus} | "
                             f"อัปเดต {datetime.now():%H:%M:%S}"
                             + (f" ({took:.1f} วิ)" if took else ""))
                    min_s = safe_int(self.var_min, 30)
                    if first:
                        base = [p for p in procs if p.score >= min_s]
                        if base:
                            pm.log_rows(base, "baseline")
                            for p in base:
                                self.add_alert(p, "มีอยู่แล้ว")
                    for p in fresh:
                        if p.score >= min_s:
                            pm.log_rows([p], "new_suspicious")
                            self.add_alert(p, "ใหม่")
                            self.notify(p)
                elif msg[0] == "error":
                    self.lbl_stats.config(text=f"ผิดพลาด: {msg[1]}")
        except queue.Empty:
            pass
        self.after(200, self.poll_queue)

    def add_alert(self, p: pm.ProcInfo, kind: str) -> None:
        key = (p.pid, p.created)
        if key in self.alerted:
            return
        self.alerted.add(key)
        self.alert_count += 1
        lv = level_key(p.score)
        line = (f"{datetime.now():%H:%M:%S}  [{kind}] {p.name}  PID {p.pid}  "
                f"คะแนน {p.score} ({LEVEL_TH[lv]})  —  {'; '.join(p.reasons)}")
        self.lst_alert.insert(0, line)
        self.lst_alert.itemconfig(0, background=COLORS[lv])
        self.notebook.tab(1, text=f"  ประวัติแจ้งเตือน ({self.alert_count})  ")

    def notify(self, p: pm.ProcInfo) -> None:
        if self.var_sound.get() and pm.IS_WINDOWS:
            try:
                import winsound
                winsound.MessageBeep(winsound.MB_ICONHAND if p.score >= 60
                                     else winsound.MB_ICONEXCLAMATION)
            except Exception:
                pass
        if self.var_popup.get():
            pm.popup(f"Process Monitor - พบโปรเซสน่าสงสัย (คะแนน {p.score})",
                     f"{p.name}  (PID {p.pid})\nparent: {p.parent_name}\n"
                     f"path: {p.exe or '-'}\n\n" + "\n".join(f"- {r}" for r in p.reasons))
        self.notebook.select(1)

    # ------------------------------------------------------------ ตาราง
    def refresh_table(self) -> None:
        sel = self.tree.selection()
        sel_pid = int(sel[0]) if sel else None
        self.tree.delete(*self.tree.get_children())
        term = self.var_search.get().strip().lower()
        rows = list(self.procs.values())
        if self.var_only_sus.get():
            rows = [p for p in rows if p.score > 0]
        if term:
            rows = [p for p in rows if term in p.name.lower() or term in p.exe.lower()
                    or term == str(p.pid)]
        keyf = {
            "pid": lambda p: p.pid, "name": lambda p: p.name.lower(),
            "cpu": lambda p: p.cpu, "ram": lambda p: p.mem_mb, "net": lambda p: p.conns,
            "sig": lambda p: p.signed, "score": lambda p: p.score,
            "level": lambda p: p.score, "path": lambda p: p.exe.lower(),
        }[self.sort_col]
        rows.sort(key=keyf, reverse=self.sort_rev)
        for p in rows:
            lv = "trusted" if p.trusted else level_key(p.score)
            self.tree.insert("", "end", iid=str(p.pid), tags=(lv,), values=(
                p.pid, p.name, f"{p.cpu:.1f}", f"{p.mem_mb:.1f}", p.conns, p.signed,
                p.score, LEVEL_TH[lv], p.exe or "-"))
        if sel_pid is not None and self.tree.exists(str(sel_pid)):
            self.tree.selection_set(str(sel_pid))

    def sort_by(self, col: str) -> None:
        self.sort_rev = not self.sort_rev if self.sort_col == col else col in (
            "score", "cpu", "ram", "net", "level")
        self.sort_col = col
        self.refresh_table()

    def selected(self) -> pm.ProcInfo | None:
        sel = self.tree.selection()
        return self.procs.get(int(sel[0])) if sel else None

    def show_detail(self, _evt=None) -> None:
        p = self.selected()
        self.txt_detail.config(state="normal")
        self.txt_detail.delete("1.0", "end")
        if p:
            self.btn_trust.config(text="เลิกเชื่อถือ" if p.trusted else "เชื่อถือโปรแกรมนี้")
            lines = [
                f"{p.name}   PID {p.pid}   คะแนน {p.score} ({LEVEL_TH[level_key(p.score)]})",
                f"Path     : {p.exe or '-'}",
                f"Command  : {p.cmdline or '-'}",
                f"Parent   : {p.parent_name} (PID {p.ppid})",
                f"User     : {p.user or '-'}      เริ่มเมื่อ: {p.created}",
                f"Signature: {p.signed}  {p.signer}",
                "",
                "เหตุผล:" if p.reasons else "ไม่พบสิ่งผิดปกติ",
            ] + [f"  - {r}" for r in p.reasons]
            self.txt_detail.insert("1.0", "\n".join(lines))
        self.txt_detail.config(state="disabled")

    # ------------------------------------------------------------ ปุ่มจัดการ
    def open_location(self) -> None:
        p = self.selected()
        if p and p.exe and os.path.exists(p.exe):
            subprocess.Popen(["explorer", "/select,", p.exe])

    def copy_path(self) -> None:
        p = self.selected()
        if p and p.exe:
            self.clipboard_clear()
            self.clipboard_append(p.exe)

    def toggle_trust(self) -> None:
        p = self.selected()
        if not p or not p.exe:
            return
        if p.trusted:
            pm.TRUST.remove(p.exe)
            p.trusted = False
            messagebox.showinfo("เลิกเชื่อถือแล้ว", f"{p.name} จะถูกตรวจตามปกติตั้งแต่รอบสแกนถัดไป")
        else:
            sig = {"yes": "มี signature ถูกต้อง", "no": "ไม่มี signature",
                   "store": "แอปจาก Store"}.get(p.signed, "ไม่ทราบสถานะ signature")
            if not messagebox.askyesno(
                    "ยืนยันการเชื่อถือโปรแกรม",
                    f"เชื่อถือ {p.name} ใช่ไหม?\n\n{p.exe}\n({sig})\n\n"
                    "ทำเฉพาะโปรแกรมที่คุณรู้จักและติดตั้งเองเท่านั้น\n"
                    "ถ้าไฟล์นี้ถูกแก้ไขภายหลัง ระบบจะกลับมาแจ้งเตือนอีกครั้ง"):
                return
            if not pm.TRUST.add(p.exe, p.name):
                messagebox.showerror("ไม่สำเร็จ", "อ่านไฟล์ไม่ได้ ลองเปิดโปรแกรมแบบ Run as administrator")
                return
            p.trusted, p.score, p.reasons = True, 0, ["อยู่ในรายการที่เชื่อถือ"]
        self.refresh_trust_list()
        self.refresh_table()
        self.show_detail()

    def refresh_trust_list(self) -> None:
        self.lst_trust.delete(0, "end")
        self._trust_keys = []
        for key, e in sorted(pm.TRUST.items.items(), key=lambda kv: kv[1].get("name", "").lower()):
            self._trust_keys.append(key)
            self.lst_trust.insert("end", f"{e.get('name')}   —   {e.get('path')}   (เพิ่มเมื่อ {e.get('added', '-')})")
        self.notebook.tab(2, text=f"  รายการที่เชื่อถือ ({len(self._trust_keys)})  ")

    def remove_trusted(self) -> None:
        sel = self.lst_trust.curselection()
        if not sel:
            return
        key = self._trust_keys[sel[0]]
        pm.TRUST.remove(key)
        for p in self.procs.values():
            if p.exe.lower() == key:
                p.trusted = False
        self.refresh_trust_list()
        self.refresh_table()

    def kill_selected(self) -> None:
        p = self.selected()
        if not p:
            return
        if not messagebox.askyesno(
                "ยืนยันการปิดโปรเซส",
                f"ต้องการปิด {p.name} (PID {p.pid}) ใช่ไหม?\n\n{p.exe}\n\n"
                "งานที่ยังไม่บันทึกในโปรแกรมนี้จะหายไป", icon="warning"):
            return
        try:
            proc = psutil.Process(p.pid)
            proc.terminate()
            proc.wait(timeout=3)
            messagebox.showinfo("สำเร็จ", f"ปิด {p.name} แล้ว")
        except psutil.TimeoutExpired:
            psutil.Process(p.pid).kill()
            messagebox.showinfo("สำเร็จ", f"บังคับปิด {p.name} แล้ว")
        except psutil.AccessDenied:
            messagebox.showerror("ไม่มีสิทธิ์", "ต้องเปิดโปรแกรมนี้แบบ Run as administrator")
        except psutil.NoSuchProcess:
            messagebox.showinfo("แจ้ง", "โปรเซสนี้ปิดไปแล้ว")
        self.procs.pop(p.pid, None)
        self.refresh_table()

    def open_log(self) -> None:
        if pm.LOG_FILE.exists():
            os.startfile(pm.LOG_FILE) if pm.IS_WINDOWS else None
        else:
            messagebox.showinfo("Log", "ยังไม่มีไฟล์ log")

    def on_close(self) -> None:
        self.scanner.alive = False
        self.scanner.running.set()
        self.destroy()


if __name__ == "__main__":
    App().mainloop()
