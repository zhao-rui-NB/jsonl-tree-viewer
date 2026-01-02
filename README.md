JSONL Tree Viewer (PyQt6)

Desktop app for browsing huge JSON Lines files without loading the entire file into memory.

Features
- Streaming index build for fast jump-to-line
- Tree view for a selected record
- Search with clickable results
- Long text preview with truncation toggle

Usage
1) Install PyQt6:
   pip install PyQt6
2) Run:
   python main.py
3) Open a .jsonl/.ndjson file. The app will build a sidecar index:
   <file>.idx and <file>.idx.meta

Notes
- First open builds the index; later opens reuse it unless the file changes.
- The search is streaming and can be stopped.
