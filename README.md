# Professional Process Manager - Malware Analysis Edition

A beautiful, modern GUI application to display all running processes at launch, designed for malware analysis and advanced process inspection.

## Features
- Gorgeous, modern UI (PyQt5)
- All process details: PID, Name, Status, User, Created, CPU%, Mem%, Threads, Children, Priority, Location, Network
- Column sorting by clicking headers
- Search/filter bar for quick lookup
- Alternating row colors, bold headers, modern color palette
- No auto-refresh: shows all processes as they were at launch

## Installation
```
pip install -r requirements.txt
```

## Usage
```
python process_manager_gui.py
```

## Requirements
- Python 3.x
- psutil
- PyQt5
