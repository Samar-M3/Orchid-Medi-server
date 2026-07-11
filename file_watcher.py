import json
import threading
import time
from collections import deque
from pathlib import Path
from typing import Callable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from entropy import calculate_entropy
from models import Alert

PROJECT_ROOT = Path(__file__).resolve().parent
PROTECTED_DIR = PROJECT_ROOT / "protected_files"
HONEYFILES_DIR = PROTECTED_DIR / "honeyfiles"
HONEYFILES_JSON = HONEYFILES_DIR / "honeyfiles.json"
DEMO_FILES_DIR = PROJECT_ROOT / "demo_files"


def ensure_demo_downloads() -> None:
    DEMO_FILES_DIR.mkdir(exist_ok=True)
    report_path = DEMO_FILES_DIR / "report1.pdf"
    if not report_path.exists():
        report_path.write_text(
            "%PDF-1.4\n"
            "1 0 obj\n"
            "<< /Type /Catalog /Pages 2 0 R >>\n"
            "endobj\n"
            "2 0 obj\n"
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n"
            "endobj\n"
            "3 0 obj\n"
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 144] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\n"
            "endobj\n"
            "4 0 obj\n"
            "<< /Length 44 >>\n"
            "stream\n"
            "BT /F1 18 Tf 72 72 Td (MediShield demo report) Tj ET\n"
            "endstream\n"
            "endobj\n"
            "5 0 obj\n"
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\n"
            "endobj\n"
            "xref\n"
            "0 6\n"
            "0000000000 65535 f \n"
            "0000000010 00000 n \n"
            "0000000060 00000 n \n"
            "0000000120 00000 n \n"
            "0000000243 00000 n \n"
            "0000000339 00000 n \n"
            "trailer\n"
            "<< /Size 6 /Root 1 0 R >>\n"
            "startxref\n"
            "406\n"
            "%%EOF\n",
            encoding="ascii",
        )

class RansomwareFileWatcher:
    def __init__(self, alert_callback: Callable[[Alert], None]) -> None:
        self.alert_callback = alert_callback
        self.baseline_entropy: dict[Path, float] = {}
        self.honeyfile_names: set[str] = set()
        self.modified_events: deque[tuple[float, Path]] = deque()
        self.entropy_spikes: deque[tuple[float, Path]] = deque()
        self.recent_alert_keys: dict[str, float] = {}
        self.observer = None

    def start(self) -> None:
        ensure_demo_files()
        self._load_honeyfile_names()
        self._build_entropy_baseline()

        handler = ProtectedFileEventHandler(self)
        self.observer = Observer()
        self.observer.schedule(handler, str(PROTECTED_DIR), recursive=True)
        self.observer.start()

    def stop(self) -> None:
        if not self.observer:
            return
        self.observer.stop()
        self.observer.join(timeout=5)

    def handle_event(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return

        path = Path(event.src_path)
        event_type = event.event_type

        if self._is_honeyfile(path) and event_type in {"modified", "moved", "deleted"}:
            self._emit_once(
                "honeyfile",
                Alert(
                    source="ransomware",
                    severity="critical",
                    title="Honeyfile touched",
                    description="A decoy patient record was modified, moved, or deleted.",
                    affected_device="local-filesystem-monitor",
                    affected_file=str(path),
                    details={"action": event_type, "filepath": str(path)},
                ),
            )
            return

        if event_type == "modified" and self._is_regular_protected_file(path):
            self._record_regular_file_modification(path)

    def _record_regular_file_modification(self, path: Path) -> None:
        now = time.time()
        self.modified_events.append((now, path))
        self._trim_window(self.modified_events, now)

        if len({file_path for _, file_path in self.modified_events}) > 5:
            self._emit_once(
                "mass-modification",
                Alert(
                    source="ransomware",
                    severity="high",
                    title="Mass file modification warning",
                    description="More than 5 protected files changed within 10 seconds.",
                    affected_device="local-filesystem-monitor",
                    details={"modified_files": list(set(str(p) for _, p in self.modified_events))},
                ),
            )

        baseline = self.baseline_entropy.get(path)
        if baseline is None or baseline == 0:
            return

        try:
            current_entropy = calculate_entropy(str(path))
        except OSError:
            return

        if current_entropy > baseline * 1.3:
            self.entropy_spikes.append((now, path))
            self._trim_window(self.entropy_spikes, now)

        if len({file_path for _, file_path in self.entropy_spikes}) >= 3:
            self._emit_once(
                "entropy-spike",
                Alert(
                    source="ransomware",
                    severity="critical",
                    title="Mass encryption pattern detected",
                    description="Entropy jumped by more than 30% for 3 or more files within 10 seconds.",
                    affected_device="local-filesystem-monitor",
                    details={"entropy_spikes": list(set(str(p) for _, p in self.entropy_spikes))},
                ),
            )

    def _build_entropy_baseline(self) -> None:
        self.baseline_entropy.clear()
        for path in PROTECTED_DIR.glob("*.txt"):
            self.baseline_entropy[path] = calculate_entropy(str(path))

    def _load_honeyfile_names(self) -> None:
        try:
            self.honeyfile_names = set(json.loads(HONEYFILES_JSON.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            self.honeyfile_names = {
                "patient_record_P-1008.txt",
                "patient_record_P-1011.txt",
            }

    def _is_honeyfile(self, path: Path) -> bool:
        try:
            resolved = path.resolve()
        except OSError:
            return False
        return resolved.parent == HONEYFILES_DIR and resolved.name in self.honeyfile_names

    @staticmethod
    def _is_regular_protected_file(path: Path) -> bool:
        return path.suffix == ".txt" and path.parent == PROTECTED_DIR

    @staticmethod
    def _trim_window(events: deque[tuple[float, Path]], now: float) -> None:
        while events and events[0][0] < now - 10:
            events.popleft()

    def _emit_once(self, key: str, alert: Alert) -> None:
        now = time.time()
        last_emitted = self.recent_alert_keys.get(key, 0)
        if now - last_emitted < 5:
            return
        self.recent_alert_keys[key] = now
        self.alert_callback(alert)


class ProtectedFileEventHandler(FileSystemEventHandler):
    def __init__(self, watcher: RansomwareFileWatcher) -> None:
        self.watcher = watcher

    def on_modified(self, event: FileSystemEvent) -> None:
        self.watcher.handle_event(event)

    def on_moved(self, event: FileSystemEvent) -> None:
        self.watcher.handle_event(event)

    def on_deleted(self, event: FileSystemEvent) -> None:
        self.watcher.handle_event(event)


def ensure_demo_files() -> None:
    PROTECTED_DIR.mkdir(exist_ok=True)
    HONEYFILES_DIR.mkdir(exist_ok=True)

    patients = [
        ("P-1001", "Aarav Sharma", "Kathmandu", "Blood pressure stable. Follow up in 30 days."),
        ("P-1002", "Sita Tamang", "Lalitpur", "Recovering from appendectomy. No infection signs."),
        ("P-1003", "Bikash Gurung", "Pokhara", "Diabetes review. Medication adherence good."),
        ("P-1004", "Maya Shrestha", "Bhaktapur", "Pregnancy checkup normal. Iron prescribed."),
        ("P-1005", "Nabin Rai", "Dharan", "Asthma symptoms controlled with inhaler."),
        ("P-1006", "Laxmi Magar", "Butwal", "Fracture healing. Physiotherapy recommended."),
        ("P-1007", "Karma Lama", "Solukhumbu", "High altitude headache resolved."),
        ("P-1008", "Anita Thapa", "Biratnagar", "Cardiology consult. ECG normal."),
        ("P-1009", "Ramesh Karki", "Janakpur", "Fever improved. Lab results pending."),
        ("P-1010", "Pratiksha Bista", "Chitwan", "Routine pediatric visit. Vaccines updated."),
    ]

    for patient_id, name, address, note in patients:
        path = PROTECTED_DIR / f"patient_record_{patient_id}.txt"
        if not path.exists():
            path.write_text(
                f"Patient ID: {patient_id}\nName: {name}\nAddress: {address}\nClinical note: {note}\n",
                encoding="utf-8",
            )

    honeyfiles = [
        HONEYFILES_DIR / "patient_record_P-1008.txt",
        HONEYFILES_DIR / "patient_record_P-1011.txt",
    ]
    for path in honeyfiles:
        if not path.exists():
            path.write_text(
                "Patient ID: restricted\nName: decoy record\nClinical note: do not modify\n",
                encoding="utf-8",
            )

    HONEYFILES_JSON.write_text(
        json.dumps([path.name for path in honeyfiles], indent=2),
        encoding="utf-8",
    )


def start_watcher_in_thread(alert_callback: Callable[[Alert], None]) -> RansomwareFileWatcher:
    watcher = RansomwareFileWatcher(alert_callback)
    thread = threading.Thread(target=watcher.start, daemon=True)
    thread.start()
    return watcher
