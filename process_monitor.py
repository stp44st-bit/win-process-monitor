"""
Process Monitor สำหรับ Windows
================================
เฝ้าดูโปรเซสที่รันอยู่ ให้คะแนนความน่าสงสัย และแจ้งเตือนเมื่อมีโปรเซสใหม่ที่น่าสงสัย

ติดตั้ง:   pip install psutil
ใช้งาน:
    python process_monitor.py                 สแกนครั้งเดียว แสดงเฉพาะที่น่าสงสัย
    python process_monitor.py --all           สแกนครั้งเดียว แสดงทุกโปรเซส
    python process_monitor.py --watch         เฝ้าดูต่อเนื่อง แจ้งเมื่อมีโปรเซสใหม่
    python process_monitor.py --watch --interval 3 --min-score 30
    python process_monitor.py --no-sig        ข้ามการตรวจ digital signature (เร็วขึ้น)

แนะนำให้รันใน Command Prompt แบบ "Run as administrator"
เพื่อให้อ่าน path ของโปรเซสระบบได้ครบ

Log จะถูกบันทึกที่ process_monitor_log.csv ในโฟลเดอร์เดียวกับสคริปต์
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

try:
    import psutil
except ImportError:
    print("ต้องติดตั้ง psutil ก่อน:  pip install psutil")
    sys.exit(1)

IS_WINDOWS = os.name == "nt"
SCRIPT_DIR = Path(__file__).resolve().parent
LOG_FILE = SCRIPT_DIR / "process_monitor_log.csv"
TRUST_FILE = SCRIPT_DIR / "trusted.json"

# ---------------------------------------------------------------- สี ANSI
if IS_WINDOWS and sys.stdout is not None:
    os.system("")  # เปิดโหมด ANSI escape บน Windows 10+ (ข้ามเมื่อรันด้วย pythonw)
RED, YEL, GRN, CYN, DIM, RST = (
    "\033[91m", "\033[93m", "\033[92m", "\033[96m", "\033[2m", "\033[0m"
)

# ---------------------------------------------------------------- กฎการให้คะแนน
WINDIR = os.environ.get("WINDIR", r"C:\Windows").lower()
SYSTEM32 = os.path.join(WINDIR, "system32")
SYSWOW64 = os.path.join(WINDIR, "syswow64")

# ชื่อโปรเซสระบบที่มัลแวร์ชอบปลอมตัวเป็น -> โฟลเดอร์ที่ถูกต้อง
SYSTEM_PROCESS_HOMES = {
    "svchost.exe": (SYSTEM32, SYSWOW64),
    "lsass.exe": (SYSTEM32,),
    "csrss.exe": (SYSTEM32,),
    "winlogon.exe": (SYSTEM32,),
    "services.exe": (SYSTEM32,),
    "smss.exe": (SYSTEM32,),
    "wininit.exe": (SYSTEM32,),
    "spoolsv.exe": (SYSTEM32,),
    "taskhostw.exe": (SYSTEM32,),
    "dllhost.exe": (SYSTEM32, SYSWOW64),
    "conhost.exe": (SYSTEM32,),
    "rundll32.exe": (SYSTEM32, SYSWOW64),
    "explorer.exe": (WINDIR,),
}

# ชื่อที่สะกดคล้ายของระบบ (typosquatting)
LOOKALIKE_NAMES = {
    "svch0st.exe", "scvhost.exe", "svhost.exe", "svchosts.exe", "svchost32.exe",
    "lsas.exe", "lsasss.exe", "isass.exe", "csrs.exe", "crss.exe",
    "explore.exe", "explorer32.exe", "expl0rer.exe", "winlogin.exe",
    "taskmgr32.exe", "services32.exe", "smss32.exe",
}

# โฟลเดอร์ที่โปรแกรมปกติไม่ค่อยรันจาก
SUSPICIOUS_DIR_HINTS = (
    "\\appdata\\local\\temp\\",
    "\\windows\\temp\\",
    "\\users\\public\\",
    "\\downloads\\",
    "\\$recycle.bin\\",
    "\\programdata\\",          # มีโปรแกรมปกติบ้าง ให้คะแนนต่ำ
    "\\appdata\\roaming\\",     # มีโปรแกรมปกติบ้าง ให้คะแนนต่ำ
)
DIR_WEIGHTS = {
    "\\appdata\\local\\temp\\": 30,
    "\\windows\\temp\\": 30,
    "\\users\\public\\": 30,
    "\\downloads\\": 20,
    "\\$recycle.bin\\": 40,
    "\\programdata\\": 10,
    "\\appdata\\roaming\\": 10,
}

# โปรแกรมไม่พึงประสงค์ (PUP / proxyware) ที่มักติดมากับโปรแกรมฟรี
KNOWN_PUP = {
    "brightdata.exe": "Bright Data SDK (proxyware ใช้เน็ตของเครื่องเป็น proxy ให้คนอื่น)",
    "luminati.exe": "Luminati (proxyware ชื่อเดิมของ Bright Data)",
    "honeygain.exe": "Honeygain (แชร์เน็ตแลกเงิน)",
    "iproyal pawns.exe": "IPRoyal Pawns (แชร์เน็ตแลกเงิน)",
    "packetstream.exe": "PacketStream (แชร์เน็ตแลกเงิน)",
    "net_updater64.exe": "ตัวเรียก Bright Data SDK (มักมากับโปรแกรมฟรี เช่น Format Factory)",
    "net_updater32.exe": "ตัวเรียก Bright Data SDK (มักมากับโปรแกรมฟรี เช่น Format Factory)",
}

# โปรแกรมที่มัลแวร์ชอบใช้เป็นตัวช่วย (LOLBins) เมื่อถูกเรียกด้วยคำสั่งแปลก ๆ
LOLBINS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    "bitsadmin.exe", "wmic.exe",
}
SUSPICIOUS_CMD_TOKENS = (
    "-enc", "-encodedcommand", "frombase64string", "downloadstring",
    "invoke-webrequest", "iwr ", "invoke-expression", "iex ", "-w hidden",
    "-windowstyle hidden", "bypass", "urlcache", "javascript:", "http://",
    "https://", "/transfer",
)


@dataclass
class ProcInfo:
    pid: int
    name: str
    exe: str
    cmdline: str
    user: str
    ppid: int
    parent_name: str
    cpu: float
    mem_mb: float
    conns: int
    created: str
    signed: str = "?"          # "yes" / "no" / "?" (ไม่ทราบ)
    signer: str = ""
    trusted: bool = False
    score: int = 0
    reasons: list[str] = field(default_factory=list)


# ---------------------------------------------------------------- ตรวจ signature
class SignatureCache:
    """ตรวจ Authenticode signature ผ่าน PowerShell แบบรวดเดียวหลายไฟล์ แล้ว cache ไว้"""

    def __init__(self, enabled: bool):
        self.enabled = enabled and IS_WINDOWS
        self.cache: dict[str, tuple[str, str]] = {}

    def check_many(self, paths: list[str]) -> None:
        if not self.enabled:
            return
        todo = sorted({p for p in paths if p and p.lower() not in self.cache})
        if not todo:
            return
        # ส่งรายชื่อไฟล์ผ่าน stdin เป็น JSON เพื่อเลี่ยงปัญหา path มีช่องว่าง/อักขระพิเศษ
        ps = (
            "$ErrorActionPreference='SilentlyContinue';"
            "$p = [Console]::In.ReadToEnd() | ConvertFrom-Json;"
            "$r = foreach($f in $p){ $s = Get-AuthenticodeSignature -LiteralPath $f;"
            "[pscustomobject]@{p=$f; st=[string]$s.Status;"
            "sg=if($s.SignerCertificate){$s.SignerCertificate.GetNameInfo('SimpleName',$false)}else{''}} };"
            "@($r) | ConvertTo-Json -Compress"
        )
        for i in range(0, len(todo), 150):
            chunk = todo[i:i + 150]
            try:
                out = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                    input=json.dumps(chunk), capture_output=True, text=True,
                    timeout=120, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                ).stdout.strip()
                data = json.loads(out) if out else []
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    status = "yes" if item.get("st") == "Valid" else "no"
                    self.cache[item["p"].lower()] = (status, item.get("sg") or "")
            except Exception as exc:  # PowerShell ใช้ไม่ได้ -> ไม่ทราบ
                print(f"{DIM}[!] ตรวจ signature ไม่สำเร็จ: {exc}{RST}")
                for p in chunk:
                    self.cache.setdefault(p.lower(), ("?", ""))

    def get(self, path: str) -> tuple[str, str]:
        if not self.enabled or not path:
            return ("?", "")
        return self.cache.get(path.lower(), ("?", ""))


# ---------------------------------------------------------------- เก็บข้อมูลโปรเซส
def _safe(fn, default):
    try:
        return fn()
    except (psutil.Error, OSError):
        return default


def collect_processes() -> list[ProcInfo]:
    # วัด CPU ต้องเรียก cpu_percent สองรอบห่างกัน
    procs = list(psutil.process_iter())
    for p in procs:
        _safe(lambda: p.cpu_percent(None), 0.0)
    time.sleep(0.5)

    names = {p.pid: _safe(p.name, "?") for p in procs}
    ncpu = psutil.cpu_count() or 1
    result: list[ProcInfo] = []
    for p in procs:
        if p.pid in (0, 4):  # System Idle / System
            continue
        with p.oneshot():
            name = _safe(p.name, "?")
            exe = _safe(p.exe, "")
            cmd = " ".join(_safe(p.cmdline, []) or [])
            ppid = _safe(p.ppid, 0)
            created = _safe(
                lambda: datetime.fromtimestamp(p.create_time()).strftime("%H:%M:%S"), "")
            result.append(ProcInfo(
                pid=p.pid,
                name=name,
                exe=exe,
                cmdline=cmd,
                user=_safe(p.username, ""),
                ppid=ppid,
                parent_name=names.get(ppid, "?"),
                cpu=_safe(lambda: p.cpu_percent(None), 0.0) / ncpu,
                mem_mb=_safe(lambda: p.memory_info().rss / 1_048_576, 0.0),
                conns=len(_safe(lambda: p.net_connections(kind="inet"), [])),
                created=created,
            ))
    return result


# ---------------------------------------------------------------- ให้คะแนน
def score_process(pi: ProcInfo) -> None:
    name = pi.name.lower()
    exe = pi.exe.lower()
    folder = os.path.dirname(exe)
    cmd = pi.cmdline.lower()

    def add(points: int, why: str) -> None:
        pi.score += points
        pi.reasons.append(why)

    # โปรเซสเทียมของ kernel (Registry, MemCompression ฯลฯ) ไม่มีไฟล์จริง -> ข้าม
    if exe and "\\" not in exe:
        pi.signed = "-"
        return

    # แอปจาก Microsoft Store ลงลายเซ็นไว้ที่ตัวแพ็กเกจ ไม่ใช่ที่ไฟล์ .exe
    if "\\windowsapps\\" in exe and pi.signed == "no":
        pi.signed = "store"

    if name in KNOWN_PUP:
        add(40, f"โปรแกรมไม่พึงประสงค์: {KNOWN_PUP[name]}")

    # 1) ปลอมเป็นโปรเซสระบบแต่อยู่ผิดที่
    if name in SYSTEM_PROCESS_HOMES and exe:
        if folder not in SYSTEM_PROCESS_HOMES[name]:
            add(60, f"ชื่อเหมือนโปรเซสระบบแต่รันจาก {folder}")

    # 2) ชื่อสะกดคล้ายของระบบ
    if name in LOOKALIKE_NAMES:
        add(60, "ชื่อสะกดเลียนแบบโปรเซสระบบ")

    # 3) รันจากโฟลเดอร์แปลก
    for hint, w in DIR_WEIGHTS.items():
        if hint in exe and not (pi.signed == "yes" and w <= 10):
            add(w, f"รันจากโฟลเดอร์ ...{hint.rstrip(chr(92))}")
            break

    # 4) นามสกุลซ้อน เช่น invoice.pdf.exe
    base = os.path.basename(exe or name)
    parts = base.split(".")
    if len(parts) >= 3 and parts[-2] in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt", "mp4"}:
        add(40, "นามสกุลไฟล์ซ้อน (หลอกว่าเป็นเอกสาร)")

    # 5) ไม่มี digital signature (เฉพาะไฟล์นอก Windows)
    if pi.signed == "no" and exe and not exe.startswith(WINDIR):
        add(20, "ไม่มี digital signature ที่ถูกต้อง")
    elif pi.signed == "no" and exe.startswith(WINDIR):
        add(40, "ไฟล์ในโฟลเดอร์ Windows แต่ signature ไม่ถูกต้อง")

    # 6) LOLBin ที่ถูกเรียกด้วยคำสั่งน่าสงสัย
    if name in LOLBINS:
        hits = [t.strip() for t in SUSPICIOUS_CMD_TOKENS if t in cmd]
        if hits:
            add(35, f"{pi.name} ถูกเรียกด้วยคำสั่งน่าสงสัย: {', '.join(hits[:3])}")

    # 7) Office / browser เปิดเชลล์ (พฤติกรรมของเอกสารแนบมัลแวร์)
    parent = pi.parent_name.lower()
    if parent in {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                  "acrord32.exe"} and name in LOLBINS:
        add(50, f"{pi.parent_name} เปิด {pi.name} (พฤติกรรมเอกสารอันตราย)")

    # 8) อ่าน path ไม่ได้ทั้งที่ไม่ใช่โปรเซสระบบ
    if not exe and pi.user and "system" not in pi.user.lower() \
            and "service" not in pi.user.lower():
        add(10, "อ่าน path ของไฟล์ไม่ได้")

    # 9) ใช้ทรัพยากรสูง (อาจเป็น crypto miner)
    if pi.cpu >= 50:
        add(15, f"ใช้ CPU สูง {pi.cpu:.0f}%")

    # 10) เชื่อมต่อเครือข่ายเยอะจากโฟลเดอร์แปลก
    if pi.conns >= 5 and any(h in exe for h in DIR_WEIGHTS):
        add(15, f"เชื่อมต่อเครือข่าย {pi.conns} ช่องทางจากโฟลเดอร์แปลก")

    pi.score = min(pi.score, 100)


# ---------------------------------------------------------------- รายการที่เชื่อถือ (whitelist)
class TrustStore:
    """เก็บ path + SHA-256 ของโปรแกรมที่ผู้ใช้เชื่อถือ ถ้าไฟล์ถูกแก้ไข hash จะไม่ตรงและกลับมาแจ้งเตือน"""

    def __init__(self, path: Path = TRUST_FILE):
        self.path = path
        self.items: dict[str, dict] = {}
        self._hash_cache: dict[str, tuple[float, int, str]] = {}
        self.load()

    def load(self) -> None:
        try:
            self.items = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.items = {}

    def save(self) -> None:
        self.path.write_text(json.dumps(self.items, ensure_ascii=False, indent=2),
                             encoding="utf-8")

    def file_hash(self, exe: str) -> str:
        try:
            st = os.stat(exe)
        except OSError:
            return ""
        key = exe.lower()
        cached = self._hash_cache.get(key)
        if cached and cached[0] == st.st_mtime and cached[1] == st.st_size:
            return cached[2]
        h = hashlib.sha256()
        try:
            with open(exe, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
        except OSError:
            return ""
        digest = h.hexdigest()
        self._hash_cache[key] = (st.st_mtime, st.st_size, digest)
        return digest

    def add(self, exe: str, name: str = "") -> bool:
        digest = self.file_hash(exe)
        if not digest:
            return False
        self.items[exe.lower()] = {
            "path": exe, "name": name or os.path.basename(exe), "sha256": digest,
            "added": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.save()
        return True

    def remove(self, exe: str) -> None:
        if self.items.pop(exe.lower(), None) is not None:
            self.save()

    def apply(self, pi: ProcInfo) -> None:
        entry = self.items.get(pi.exe.lower()) if pi.exe else None
        if not entry:
            return
        if self.file_hash(pi.exe) == entry.get("sha256"):
            pi.trusted = True
            pi.score = 0
            pi.reasons = ["อยู่ในรายการที่เชื่อถือ"]
        else:
            pi.score = min(pi.score + 40, 100)
            pi.reasons.append("ไฟล์ถูกแก้ไขหลังจากตั้งเป็นที่เชื่อถือ (hash ไม่ตรง)")


TRUST = TrustStore()


def analyze(sig: SignatureCache) -> list[ProcInfo]:
    procs = collect_processes()
    sig.check_many([p.exe for p in procs])
    for p in procs:
        p.signed, p.signer = sig.get(p.exe)
        score_process(p)
        TRUST.apply(p)
    return sorted(procs, key=lambda x: (-x.score, -x.cpu))


# ---------------------------------------------------------------- แสดงผล / บันทึก
def level(score: int) -> tuple[str, str]:
    if score >= 60:
        return RED, "สูง"
    if score >= 30:
        return YEL, "กลาง"
    if score > 0:
        return CYN, "ต่ำ"
    return GRN, "ปกติ"


def print_table(procs: list[ProcInfo], min_score: int) -> None:
    shown = [p for p in procs if p.score >= min_score]
    print(f"\n{'PID':>6}  {'ชื่อ':<26}{'CPU%':>6}{'RAM MB':>9}{'NET':>5}  {'SIG':<4}{'คะแนน':>6}  ระดับ")
    print("-" * 80)
    for p in shown:
        col, lv = level(p.score)
        print(f"{p.pid:>6}  {p.name[:25]:<26}{p.cpu:>6.1f}{p.mem_mb:>9.1f}{p.conns:>5}  "
              f"{p.signed:<4}{col}{p.score:>6}  {lv}{RST}")
        if p.score > 0:
            print(f"{DIM}        path  : {p.exe or '-'}{RST}")
            for r in p.reasons:
                print(f"{col}        - {r}{RST}")
    print("-" * 80)
    sus = sum(1 for p in procs if p.score >= 30)
    print(f"ทั้งหมด {len(procs)} โปรเซส | น่าสงสัยระดับกลางขึ้นไป {sus} | แสดง {len(shown)}")


def log_rows(procs: list[ProcInfo], event: str) -> None:
    new = not LOG_FILE.exists()
    with LOG_FILE.open("a", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["time", "event", "pid", "name", "score", "reasons", "exe",
                        "cmdline", "parent", "user", "signed", "signer"])
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for p in procs:
            w.writerow([now, event, p.pid, p.name, p.score, " | ".join(p.reasons),
                        p.exe, p.cmdline, f"{p.parent_name}({p.ppid})", p.user,
                        p.signed, p.signer])


NOTIFY = False


def popup(title: str, text: str) -> None:
    """แสดงกล่องแจ้งเตือนบนหน้าจอ (ไม่บล็อกการเฝ้าดู)"""
    if not IS_WINDOWS:
        return
    import ctypes
    import threading
    flags = 0x30 | 0x40000 | 0x10000  # ICONWARNING | TOPMOST | SETFOREGROUND
    threading.Thread(
        target=lambda: ctypes.windll.user32.MessageBoxW(None, text, title, flags),
        daemon=True,
    ).start()


def alert(p: ProcInfo) -> None:
    col, lv = level(p.score)
    print(f"\n{col}[แจ้งเตือน {datetime.now():%H:%M:%S}] โปรเซสใหม่ระดับ{lv} "
          f"(คะแนน {p.score}){RST}")
    print(f"  {p.name}  PID {p.pid}  parent: {p.parent_name}({p.ppid})")
    print(f"  path: {p.exe or '-'}")
    if p.cmdline:
        print(f"  cmd : {p.cmdline[:200]}")
    for r in p.reasons:
        print(f"{col}  - {r}{RST}")
    if NOTIFY:
        popup(
            f"Process Monitor - พบโปรเซสน่าสงสัย (คะแนน {p.score})",
            f"{p.name}  (PID {p.pid})\nparent: {p.parent_name}\npath: {p.exe or '-'}\n\n"
            + "\n".join(f"- {r}" for r in p.reasons)
            + f"\n\nรายละเอียดใน {LOG_FILE}",
        )
    if IS_WINDOWS and p.score >= 60:
        try:
            import winsound
            winsound.MessageBeep(winsound.MB_ICONHAND)
        except Exception:
            pass


# ---------------------------------------------------------------- โหมดเฝ้าดู
def watch(sig: SignatureCache, interval: float, min_score: int) -> None:
    print(f"{CYN}กำลังสแกนรอบแรก...{RST}")
    procs = analyze(sig)
    print_table(procs, max(min_score, 1))
    base_sus = [p for p in procs if p.score >= min_score]
    log_rows(base_sus, "baseline")
    if NOTIFY and base_sus:
        popup("Process Monitor - พบโปรเซสน่าสงสัยตอนเริ่มเครื่อง",
              "\n".join(f"{p.name} (คะแนน {p.score}): {p.exe or '-'}" for p in base_sus[:10])
              + f"\n\nรายละเอียดใน {LOG_FILE}")
    seen = {(p.pid, p.created) for p in procs}
    print(f"\n{CYN}เริ่มเฝ้าดูทุก {interval} วินาที (แจ้งเมื่อคะแนน >= {min_score}) "
          f"กด Ctrl+C เพื่อหยุด{RST}")

    while True:
        time.sleep(interval)
        procs = analyze(sig)
        current = {(p.pid, p.created) for p in procs}
        fresh = [p for p in procs if (p.pid, p.created) not in seen]
        for p in fresh:
            if p.score >= min_score:
                alert(p)
                log_rows([p], "new_suspicious")
            else:
                print(f"{DIM}[{datetime.now():%H:%M:%S}] ใหม่: {p.name} "
                      f"(PID {p.pid}) คะแนน {p.score}{RST}")
        seen = current


# ---------------------------------------------------------------- main
def main() -> None:
    ap = argparse.ArgumentParser(description="Windows Process Monitor")
    ap.add_argument("--watch", action="store_true", help="เฝ้าดูต่อเนื่อง")
    ap.add_argument("--interval", type=float, default=5, help="วินาทีต่อรอบ (default 5)")
    ap.add_argument("--min-score", type=int, default=30, help="คะแนนขั้นต่ำที่แจ้งเตือน")
    ap.add_argument("--all", action="store_true", help="แสดงทุกโปรเซส")
    ap.add_argument("--no-sig", action="store_true", help="ข้ามการตรวจ signature")
    ap.add_argument("--notify", action="store_true",
                    help="แสดงกล่องแจ้งเตือนบนหน้าจอ (ใช้คู่กับ --watch ตอนรันเบื้องหลัง)")
    args = ap.parse_args()
    global NOTIFY
    NOTIFY = args.notify

    if not IS_WINDOWS:
        print(f"{YEL}[!] สคริปต์นี้ออกแบบสำหรับ Windows กฎบางข้อจะไม่ทำงาน{RST}")

    sig = SignatureCache(enabled=not args.no_sig)
    try:
        if args.watch:
            watch(sig, args.interval, args.min_score)
        else:
            print(f"{CYN}กำลังสแกน (ตรวจ signature ครั้งแรกอาจใช้เวลา 10-30 วินาที)...{RST}")
            procs = analyze(sig)
            print_table(procs, 0 if args.all else 1)
            log_rows([p for p in procs if p.score >= args.min_score], "scan")
            print(f"{DIM}บันทึก log ที่ {LOG_FILE}{RST}")
    except KeyboardInterrupt:
        print("\nหยุดการทำงาน")


if __name__ == "__main__":
    main()
