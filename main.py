import json
import mmap
import os
import struct
import sys
from dataclasses import dataclass

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QIntValidator
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QProgressBar,
    QSplitter,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)


INDEX_VERSION = 1
CHUNK_SIZE = 4 * 1024 * 1024
PREVIEW_LIMIT = 10000
NEARBY_WINDOW = 50


@dataclass
class IndexMeta:
    source_path: str
    source_size: int
    source_mtime: float
    line_count: int
    version: int


class JsonlIndex:
    def __init__(self, source_path: str):
        self.source_path = source_path
        self.idx_path = source_path + ".idx"
        self.meta_path = source_path + ".idx.meta"
        self.file_size = os.path.getsize(source_path)
        self._mmap = None
        self._idx_file = None
        self._line_count = 0

    @property
    def line_count(self) -> int:
        return self._line_count

    def _read_meta(self) -> IndexMeta | None:
        if not os.path.exists(self.meta_path):
            return None
        try:
            with open(self.meta_path, "r", encoding="utf-8") as meta_file:
                data = json.load(meta_file)
            return IndexMeta(
                source_path=data.get("source_path", ""),
                source_size=int(data.get("source_size", -1)),
                source_mtime=float(data.get("source_mtime", 0.0)),
                line_count=int(data.get("line_count", 0)),
                version=int(data.get("version", 0)),
            )
        except (OSError, ValueError, json.JSONDecodeError):
            return None

    def _write_meta(self, meta: IndexMeta) -> None:
        payload = {
            "source_path": meta.source_path,
            "source_size": meta.source_size,
            "source_mtime": meta.source_mtime,
            "line_count": meta.line_count,
            "version": meta.version,
        }
        with open(self.meta_path, "w", encoding="utf-8") as meta_file:
            json.dump(payload, meta_file)

    def _is_meta_valid(self, meta: IndexMeta | None) -> bool:
        if meta is None:
            return False
        if meta.version != INDEX_VERSION:
            return False
        if meta.source_path != self.source_path:
            return False
        if meta.source_size != self.file_size:
            return False
        if meta.source_mtime != os.path.getmtime(self.source_path):
            return False
        if not os.path.exists(self.idx_path):
            return False
        return True

    def load_or_build(self, progress_callback=None) -> None:
        meta = self._read_meta()
        if self._is_meta_valid(meta):
            self._load_index(meta.line_count)
            return
        self._build_index(progress_callback)

    def _build_index(self, progress_callback=None) -> None:
        temp_path = self.idx_path + ".tmp"
        total = self.file_size
        offsets_written = 0
        with open(self.source_path, "rb") as source, open(temp_path, "wb") as idx_file:
            idx_file.write(struct.pack("<Q", 0))
            offsets_written = 1
            processed = 0
            while True:
                chunk = source.read(CHUNK_SIZE)
                if not chunk:
                    break
                start = 0
                while True:
                    pos = chunk.find(b"\n", start)
                    if pos == -1:
                        break
                    offset = processed + pos + 1
                    idx_file.write(struct.pack("<Q", offset))
                    offsets_written += 1
                    start = pos + 1
                processed += len(chunk)
                if progress_callback:
                    progress_callback(processed, total)
        os.replace(temp_path, self.idx_path)
        line_count = offsets_written
        if self._last_offset_is_eof():
            line_count -= 1
        meta = IndexMeta(
            source_path=self.source_path,
            source_size=self.file_size,
            source_mtime=os.path.getmtime(self.source_path),
            line_count=line_count,
            version=INDEX_VERSION,
        )
        self._write_meta(meta)
        self._load_index(line_count)

    def _last_offset_is_eof(self) -> bool:
        try:
            with open(self.idx_path, "rb") as idx_file:
                idx_file.seek(-8, os.SEEK_END)
                last = struct.unpack("<Q", idx_file.read(8))[0]
            return last == self.file_size
        except OSError:
            return False

    def _load_index(self, line_count: int) -> None:
        if self._mmap:
            self._mmap.close()
        if self._idx_file:
            self._idx_file.close()
        self._idx_file = open(self.idx_path, "rb")
        self._mmap = mmap.mmap(self._idx_file.fileno(), 0, access=mmap.ACCESS_READ)
        self._line_count = line_count

    def get_offset(self, line_number: int) -> int:
        return struct.unpack_from("<Q", self._mmap, line_number * 8)[0]

    def get_line_bytes(self, line_number: int) -> bytes:
        if line_number < 0 or line_number >= self._line_count:
            return b""
        start = self.get_offset(line_number)
        if line_number + 1 < self._line_count:
            end = self.get_offset(line_number + 1)
        else:
            end = self.file_size
        length = max(0, end - start)
        if length == 0:
            return b""
        with open(self.source_path, "rb") as source:
            source.seek(start)
            data = source.read(length)
        if data.endswith(b"\n"):
            data = data[:-1]
        return data


class IndexWorker(QThread):
    progress = pyqtSignal(int, int)
    finished = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, source_path: str):
        super().__init__()
        self.source_path = source_path

    def run(self) -> None:
        try:
            index = JsonlIndex(self.source_path)
            index.load_or_build(progress_callback=self._emit_progress)
            self.finished.emit(index)
        except Exception as exc:
            self.failed.emit(str(exc))

    def _emit_progress(self, current: int, total: int) -> None:
        self.progress.emit(current, total)


class SearchWorker(QThread):
    progress = pyqtSignal(int, int)
    result = pyqtSignal(int, str)
    finished = pyqtSignal()
    failed = pyqtSignal(str)

    def __init__(self, source_path: str, query: str, case_sensitive: bool, limit: int = 5000):
        super().__init__()
        self.source_path = source_path
        self.query = query
        self.case_sensitive = case_sensitive
        self.limit = limit
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:
        try:
            file_size = os.path.getsize(self.source_path)
            processed = 0
            results = 0
            needle = self.query if self.case_sensitive else self.query.lower()
            with open(self.source_path, "rb") as source:
                for line_number, raw_line in enumerate(source):
                    if self._stop:
                        break
                    processed += len(raw_line)
                    text = raw_line.decode("utf-8", errors="replace")
                    haystack = text if self.case_sensitive else text.lower()
                    if needle in haystack:
                        snippet = text.strip()
                        if len(snippet) > 200:
                            snippet = snippet[:200] + "..."
                        self.result.emit(line_number, snippet)
                        results += 1
                        if results >= self.limit:
                            break
                    if line_number % 1000 == 0:
                        self.progress.emit(processed, file_size)
            self.progress.emit(processed, file_size)
            self.finished.emit()
        except Exception as exc:
            self.failed.emit(str(exc))


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("JSONL Tree Viewer")
        self.resize(1200, 800)
        self.index: JsonlIndex | None = None
        self.current_line = 0
        self.full_line_text = ""
        self.current_value = None
        self.current_is_line = True

        self.open_button = QPushButton("Open JSONL")
        self.open_button.clicked.connect(self.open_file)
        self.file_label = QLabel("No file loaded")
        self.file_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.hide()

        self.jump_input = QLineEdit()
        self.jump_input.setPlaceholderText("Line number")
        self.jump_input.setValidator(QIntValidator(0, 2_147_483_647))
        self.jump_button = QPushButton("Jump")
        self.jump_button.clicked.connect(self.jump_to_line)
        self.prev_button = QPushButton("Prev")
        self.prev_button.clicked.connect(lambda: self.jump_relative(-1))
        self.next_button = QPushButton("Next")
        self.next_button.clicked.connect(lambda: self.jump_relative(1))

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search in file")
        self.search_case = QCheckBox("Case sensitive")
        self.search_button = QPushButton("Search")
        self.search_button.clicked.connect(self.start_search)
        self.search_stop = QPushButton("Stop")
        self.search_stop.clicked.connect(self.stop_search)
        self.search_stop.setEnabled(False)

        self.nearby_list = QListWidget()
        self.nearby_list.itemClicked.connect(self.handle_nearby_click)
        self.search_results = QListWidget()
        self.search_results.itemClicked.connect(self.handle_search_click)

        self.tab_widget = QTabWidget()
        self.tab_widget.addTab(self.nearby_list, "Nearby")
        self.tab_widget.addTab(self.search_results, "Search Results")

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Key", "Value"])
        self.tree.itemExpanded.connect(self.expand_item)
        self.tree.itemSelectionChanged.connect(self.update_preview_from_selection)

        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        mono = QFont("Consolas")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self.preview.setFont(mono)

        self.preview_json = QCheckBox("Preview as JSON")
        self.preview_json.setChecked(True)
        self.preview_json.stateChanged.connect(self.refresh_preview)

        self.preview_wrap = QCheckBox("Wrap preview text")
        self.preview_wrap.setChecked(False)
        self.preview_wrap.stateChanged.connect(self.update_wrap_mode)

        self.preview_newlines = QCheckBox("Render \\n as newlines")
        self.preview_newlines.setChecked(False)
        self.preview_newlines.stateChanged.connect(self.refresh_preview)

        self.status_label = QLabel("")

        top_row = QHBoxLayout()
        top_row.addWidget(self.open_button)
        top_row.addWidget(self.file_label, 1)

        nav_row = QHBoxLayout()
        nav_row.addWidget(QLabel("Jump:"))
        nav_row.addWidget(self.jump_input)
        nav_row.addWidget(self.jump_button)
        nav_row.addWidget(self.prev_button)
        nav_row.addWidget(self.next_button)
        nav_row.addStretch(1)

        search_row = QHBoxLayout()
        search_row.addWidget(self.search_input, 1)
        search_row.addWidget(self.search_case)
        search_row.addWidget(self.search_button)
        search_row.addWidget(self.search_stop)

        left_layout = QVBoxLayout()
        left_layout.addLayout(nav_row)
        left_layout.addLayout(search_row)
        left_layout.addWidget(self.tab_widget, 1)

        left_panel = QWidget()
        left_panel.setLayout(left_layout)

        preview_controls = QHBoxLayout()
        preview_controls.addWidget(self.preview_json)
        preview_controls.addWidget(self.preview_wrap)
        preview_controls.addWidget(self.preview_newlines)
        preview_controls.addStretch(1)

        right_splitter = QSplitter(Qt.Orientation.Vertical)
        right_splitter.addWidget(self.tree)

        preview_container = QWidget()
        preview_layout = QVBoxLayout()
        preview_layout.addLayout(preview_controls)
        preview_layout.addWidget(self.preview)
        preview_layout.setContentsMargins(0, 0, 0, 0)
        preview_container.setLayout(preview_layout)

        right_splitter.addWidget(preview_container)
        right_splitter.setStretchFactor(0, 3)
        right_splitter.setStretchFactor(1, 2)

        right_panel = QWidget()
        right_layout = QVBoxLayout()
        right_layout.addWidget(right_splitter)
        right_panel.setLayout(right_layout)

        splitter = QSplitter()
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setStretchFactor(1, 1)

        layout = QVBoxLayout()
        layout.addLayout(top_row)
        layout.addWidget(self.progress)
        layout.addWidget(splitter, 1)
        layout.addWidget(self.status_label)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.index_worker = None
        self.search_worker = None

    def open_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open JSONL File",
            "",
            "JSONL Files (*.jsonl *.ndjson *.json);;All Files (*.*)",
        )
        if not path:
            return
        self.load_file(path)

    def load_file(self, path: str) -> None:
        self.file_label.setText(path)
        self.status_label.setText("Building index...")
        self.progress.setValue(0)
        self.progress.show()
        self.index_worker = IndexWorker(path)
        self.index_worker.progress.connect(self.update_progress)
        self.index_worker.finished.connect(self.index_ready)
        self.index_worker.failed.connect(self.index_failed)
        self.index_worker.start()

    def update_progress(self, current: int, total: int) -> None:
        if total > 0:
            self.progress.setValue(int(current / total * 100))

    def index_ready(self, index: JsonlIndex) -> None:
        self.index = index
        self.progress.hide()
        self.status_label.setText(f"Indexed {index.line_count} lines")
        if index.line_count > 0:
            self.current_line = 0
            self.jump_input.setText("0")
            self.load_line(0)

    def index_failed(self, message: str) -> None:
        self.progress.hide()
        self.status_label.setText("Index failed")
        QMessageBox.critical(self, "Index failed", message)

    def jump_to_line(self) -> None:
        if not self.index:
            return
        text = self.jump_input.text().strip()
        if not text:
            return
        line = int(text)
        self.load_line(line)

    def jump_relative(self, delta: int) -> None:
        if not self.index:
            return
        self.load_line(self.current_line + delta)

    def load_line(self, line_number: int) -> None:
        if not self.index:
            return
        if line_number < 0 or line_number >= self.index.line_count:
            return
        self.current_line = line_number
        self.jump_input.setText(str(line_number))
        raw = self.index.get_line_bytes(line_number)
        text = raw.decode("utf-8", errors="replace")
        self.full_line_text = text
        self.current_is_line = True
        parsed = self.populate_tree(text)
        self.current_value = parsed if parsed is not None else text
        self.refresh_preview()
        self.populate_nearby()
        self.status_label.setText(f"Line {line_number} / {self.index.line_count - 1}")

    def populate_nearby(self) -> None:
        if not self.index:
            return
        self.nearby_list.clear()
        start = max(0, self.current_line - NEARBY_WINDOW)
        end = min(self.index.line_count, self.current_line + NEARBY_WINDOW + 1)
        for line in range(start, end):
            raw = self.index.get_line_bytes(line)
            text = raw.decode("utf-8", errors="replace").strip()
            if len(text) > 120:
                text = text[:120] + "..."
            label = f"{line}: {text}"
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, line)
            if line == self.current_line:
                item.setSelected(True)
            self.nearby_list.addItem(item)

    def handle_nearby_click(self, item: QListWidgetItem) -> None:
        line = item.data(Qt.ItemDataRole.UserRole)
        self.load_line(line)

    def start_search(self) -> None:
        if not self.index:
            return
        query = self.search_input.text().strip()
        if not query:
            return
        if self.search_worker and self.search_worker.isRunning():
            return
        self.search_results.clear()
        self.tab_widget.setCurrentWidget(self.search_results)
        self.search_button.setEnabled(False)
        self.search_stop.setEnabled(True)
        self.status_label.setText("Searching...")
        self.search_worker = SearchWorker(
            self.index.source_path, query, self.search_case.isChecked()
        )
        self.search_worker.result.connect(self.add_search_result)
        self.search_worker.progress.connect(self.update_progress)
        self.search_worker.finished.connect(self.search_finished)
        self.search_worker.failed.connect(self.search_failed)
        self.progress.setValue(0)
        self.progress.show()
        self.search_worker.start()

    def stop_search(self) -> None:
        if self.search_worker and self.search_worker.isRunning():
            self.search_worker.stop()

    def add_search_result(self, line_number: int, snippet: str) -> None:
        item = QListWidgetItem(f"{line_number}: {snippet}")
        item.setData(Qt.ItemDataRole.UserRole, line_number)
        self.search_results.addItem(item)

    def handle_search_click(self, item: QListWidgetItem) -> None:
        line = item.data(Qt.ItemDataRole.UserRole)
        self.load_line(line)

    def search_finished(self) -> None:
        self.progress.hide()
        self.search_button.setEnabled(True)
        self.search_stop.setEnabled(False)
        self.status_label.setText("Search finished")

    def search_failed(self, message: str) -> None:
        self.progress.hide()
        self.search_button.setEnabled(True)
        self.search_stop.setEnabled(False)
        self.status_label.setText("Search failed")
        QMessageBox.critical(self, "Search failed", message)

    def populate_tree(self, text: str):
        self.tree.clear()
        if not text.strip():
            return None
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            root = QTreeWidgetItem(["<invalid JSON>", str(exc)])
            self.tree.addTopLevelItem(root)
            return None
        root = QTreeWidgetItem(["<root>", self._format_value(data)])
        root.setData(0, Qt.ItemDataRole.UserRole, data)
        self.tree.addTopLevelItem(root)
        if isinstance(data, (dict, list)):
            root.addChild(QTreeWidgetItem(["...", ""]))
        root.setExpanded(True)
        return data

    def expand_item(self, item: QTreeWidgetItem) -> None:
        if item.childCount() == 1 and item.child(0).text(0) == "...":
            item.takeChild(0)
            value = item.data(0, Qt.ItemDataRole.UserRole)
            self._populate_children(item, value)

    def _populate_children(self, parent: QTreeWidgetItem, value) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                node = QTreeWidgetItem([str(key), self._format_value(child)])
                node.setData(0, Qt.ItemDataRole.UserRole, child)
                parent.addChild(node)
                if isinstance(child, (dict, list)):
                    node.addChild(QTreeWidgetItem(["...", ""]))
        elif isinstance(value, list):
            for idx, child in enumerate(value):
                node = QTreeWidgetItem([f"[{idx}]", self._format_value(child)])
                node.setData(0, Qt.ItemDataRole.UserRole, child)
                parent.addChild(node)
                if isinstance(child, (dict, list)):
                    node.addChild(QTreeWidgetItem(["...", ""]))

    def _format_value(self, value) -> str:
        if isinstance(value, dict):
            return f"object ({len(value)})"
        if isinstance(value, list):
            return f"array ({len(value)})"
        if isinstance(value, str):
            return value if len(value) <= 200 else value[:200] + "..."
        return str(value)

    def update_preview(self, text: str) -> None:
        self.preview.setPlainText(text)

    def update_preview_from_selection(self) -> None:
        items = self.tree.selectedItems()
        if not items:
            return
        self.current_is_line = False
        self.current_value = items[0].data(0, Qt.ItemDataRole.UserRole)
        self.refresh_preview()

    # def refresh_preview(self) -> None:
    #     if self.current_value is None:
    #         self.preview.clear()
    #         return
    #     if self.preview_json.isChecked():
    #         try:
    #             text = json.dumps(self.current_value, ensure_ascii=False, indent=2)
    #         except TypeError:
    #             print("Failed to serialize current value as JSON")
    #             text = str(self.current_value)
    #     else:
    #         if self.current_is_line:
    #             text = self.full_line_text
    #         elif isinstance(self.current_value, (dict, list)):
    #             text = json.dumps(self.current_value, ensure_ascii=False)
    #         else:
    #             text = str(self.current_value)
    #     if self.preview_newlines.isChecked():
    #         text = text.replace("\\r\\n", "\n").replace("\\n", "\n")
    #     self.update_preview(text)
    
    def refresh_preview(self) -> None:
        if self.current_value is None:
            self.preview.clear()
            return
        else:
            if self.current_is_line:
                if self.preview_json.isChecked():
                    try:
                        parsed = json.loads(self.full_line_text)
                        text = json.dumps(parsed, ensure_ascii=False, indent=2)
                    except json.JSONDecodeError:
                        text = self.full_line_text
                else:
                    text = self.full_line_text
            elif isinstance(self.current_value, (dict, list)):
                if self.preview_json.isChecked():
                    try:
                        text = json.dumps(self.current_value, ensure_ascii=False, indent=2)
                    except TypeError:
                        text = str(self.current_value)
                else:
                    text = str(self.current_value)
            else:
                text = str(self.current_value)
                
        if self.preview_newlines.isChecked():
            text = text.replace("\\r\\n", "\n").replace("\\n", "\n")
        self.update_preview(text)

    def update_wrap_mode(self) -> None:
        if self.preview_wrap.isChecked():
            self.preview.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        else:
            self.preview.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)


def main() -> None:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
