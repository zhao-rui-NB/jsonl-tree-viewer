JSONL Tree Viewer (PyQt6)

Desktop app for browsing huge JSON Lines files without loading the entire file into memory.

Features
- Streaming index build for fast jump-to-line
- Tree view for a selected record
- Search with clickable results
- Long text preview
- Drag-and-drop file open

Usage
1) Install PyQt6:
   pip install PyQt6
2) Run:
   python main.py
3) Open a .jsonl/.ndjson file. The app will build a sidecar index:
   <file>.idx and <file>.idx.meta
4) You can also drag and drop a file onto the window.

Notes
- First open builds the index; later opens reuse it unless the file changes.
- The search is streaming and can be stopped.

Packaging (Windows)
Use PyInstaller to build a standalone .exe.

1) Install:
   ```bash
   pip install pyinstaller
   ```
2) Build:
   ```bash
   pyinstaller --name JSONLTreeViewer --windowed --onefile --add-data "assets;assets" --icon "assets\\app_icon.ico" main.py
   ```
3) Output:
   dist\\JSONLTreeViewer.exe

Tips
- Single-file exe (--onefile) has slower startup; remove it if you want faster launch.
- Windows icons require .ico; SVG is not supported by PyInstaller.
