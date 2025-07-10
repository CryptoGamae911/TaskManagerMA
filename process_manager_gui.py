import sys
import psutil
import time
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, 
    QHBoxLayout, QWidget, QLineEdit, QLabel, QHeaderView, QComboBox, 
    QFrame, QPushButton, QMenu, QTreeWidget, QTreeWidgetItem, QDialog,
    QGraphicsView, QGraphicsScene, QGraphicsRectItem, QGraphicsTextItem,
    QGraphicsLineItem, QTabWidget, QTextEdit, QScrollArea, QAbstractScrollArea
)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal, QRectF, QPointF
from PyQt5.QtGui import QFont, QColor, QBrush, QPainter
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal

def classify_process(username, exe):
    system_users = {'SYSTEM', 'root', 'LocalService', 'NetworkService'}
    exe = exe or ''
    if username in system_users:
        return 'Internal'
    # Check for Windows system directories
    if exe.lower().startswith(r'c:\windows\system32') or exe.lower().startswith(r'c:\windows\syswow64'):
        return 'Internal'
    return 'External'

import time

def load_essential_processes(filepath='essential_processes.txt'):
    essentials = set()
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    essentials.add(line.lower())
    except Exception:
        pass
    return essentials

def get_process_info(proc):
    """Get process information with optimized error handling"""
    try:
        with proc.oneshot():
            pid = proc.pid
            ppid = proc.ppid()
            name = proc.name()
            ext = name.split('.')[-1] if '.' in name else ''
            status = proc.status()
            username = proc.username()
            create_time = proc.create_time()
            
            # Only calculate CPU for visible processes
            cpu_percent = proc.cpu_percent(interval=None)
            
            memory_percent = proc.memory_percent()
            num_threads = proc.num_threads()
            num_children = len(proc.children(recursive=False))  # Only direct children
            nice = proc.nice()
            
            try:
                exe = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                exe = ''
                
            # Only check for network status if needed
            network_status = 'No'
            try:
                if hasattr(proc, 'connections'):
                    if proc.connections():
                        network_status = 'Yes'
                elif hasattr(proc, 'net_connections'):
                    if proc.net_connections():
                        network_status = 'Yes'
            except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                pass
                
            return [
                pid, ppid, name, ext, status, username, create_time, 
                cpu_percent, memory_percent, num_threads, num_children, 
                nice, exe, network_status, '', ''  # Type and Known will be filled later
            ]
    except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
        return None

def get_all_processes():
    """Get all processes with optimized performance"""
    try:
        essentials = load_essential_processes('c:/Users/ashwi/Downloads/essential_processes.txt')
        all_procs = list(psutil.process_iter())
        
        # Get CPU usage baseline (non-blocking)
        for p in all_procs[:100]:  # Limit to first 100 processes to be quick
            try:
                p.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        processes = []
        for proc in all_procs:
            proc_info = get_process_info(proc)
            if proc_info:
                name = proc_info[2].lower()
                username = proc_info[5]
                exe = proc_info[12]
                
                # Fill in type and known status
                proc_info[14] = classify_process(username, exe)
                proc_info[15] = 'Essential' if name in essentials else 'Unknown'
                
                processes.append(proc_info)
        
        return processes
    except Exception as e:
        print(f"Error getting processes: {e}")
        return []

class ProcessTable(QTableWidget):
    HEADERS = [
        "PID", "PPID", "Name", "Ext", "Status", "User", "Created", "CPU%", "Mem%", "Threads", "Children", "Priority", "Location", "Network", "Type", "Known"
    ]

    def __init__(self, processes=None):
        super().__init__()
        self.setColumnCount(len(self.HEADERS))
        self.setHorizontalHeaderLabels(self.HEADERS)
        
        # Enable right-click context menu
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)
        self.setFont(QFont('Segoe UI', 10))
        self.setStyleSheet("""
            QTableWidget {
                background-color: #fff;
                gridline-color: #e1e4e8;
            }
            QTableWidget::item:selected {
                background-color: #e3f2fd;
                color: #000;
            }
            QHeaderView::section {
                background-color: #f5f5f5;
                padding: 6px;
                border: 1px solid #ddd;
                font-weight: bold;
            }
            .new-process { background-color: #e6ffe6; }
            .terminated-process { text-decoration: line-through; color: #999; }
        """)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(self.SelectRows)
        self.setEditTriggers(self.NoEditTriggers)
        self.setRowCount(0)
        self.verticalHeader().setVisible(False)
        self.setSortingEnabled(True)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.horizontalHeader().setStretchLastSection(True)
        self.process_rows = {}  # Track processes by PID for updates
        self.process_data = {}  # Store process data for context menu
        if processes:
            self.populate_table(processes)
            
    def show_context_menu(self, position):
        """Show context menu on right-click"""
        item = self.itemAt(position)
        if not item:
            return
            
        menu = QMenu()
        show_tree_action = menu.addAction("Show Process Tree")
        action = menu.exec_(self.viewport().mapToGlobal(position))
        
        if action == show_tree_action:
            row = item.row()
            pid = int(self.item(row, 0).text())  # Get PID from first column
            
            # Get the main window instance
            parent = self.parent()
            while parent and not isinstance(parent, QMainWindow):
                parent = parent.parent()
                
            if parent and hasattr(parent, 'show_process_tree'):
                parent.show_process_tree(pid)
            else:
                print("Error: Could not find main window or show_process_tree method")

    def populate_table(self, processes, is_refresh=False):
        if not is_refresh:
            # First population
            self.process_rows = {}
            self.setRowCount(0)
            
        current_pids = set()
        new_processes = []
        
        # Identify new processes
        for proc in processes:
            pid = proc[0]  # PID is the first element
            current_pids.add(pid)
            if pid not in self.process_rows:
                new_processes.append(proc)
        
        # Mark terminated processes
        terminated_pids = set(self.process_rows.keys()) - current_pids
        for pid in terminated_pids:
            row = self.process_rows[pid]
            for col in range(self.columnCount()):
                if self.item(row, col):
                    self.item(row, col).setData(Qt.UserRole, 'terminated')
                    self.item(row, col).setToolTip('Process terminated')
                    self.item(row, col).setBackground(QColor('#ffebee'))
                    self.item(row, col).setForeground(QColor('#999'))
                    self.item(row, col).setText(f"{self.item(row, col).text()} (Terminated)")
            del self.process_rows[pid]
        
        # Add new processes
        for proc in new_processes:
            row_position = self.rowCount()
            self.insertRow(row_position)
            pid = proc[0]  # PID is the first element
            self.process_rows[pid] = row_position
            
            for col, value in enumerate(proc):
                try:
                    if col == 6:  # Created time
                        import datetime
                        value = datetime.datetime.fromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S')
                    
                    item = QTableWidgetItem(str(value))
                    item.setFlags(item.flags() ^ Qt.ItemIsEditable)
                    
                    # Highlight CPU and memory usage
                    if col == 7:  # CPU%
                        cpu_usage = float(value)
                        item.setText(f"{cpu_usage:.1f}")
                        if cpu_usage > 20:
                            item.setForeground(QBrush(QColor('#d9534f')))
                    elif col == 8:  # Mem%
                        mem_usage = float(value)
                        item.setText(f"{mem_usage:.1f}")
                        if mem_usage > 10:
                            item.setForeground(QBrush(QColor('#f0ad4e')))
                    
                    # Highlight new processes
                    if is_refresh:
                        item.setBackground(QColor('#e6ffe6'))
                        item.setToolTip('New process')
                    
                    self.setItem(row_position, col, item)
                except Exception as e:
                    print(f"Error setting table item at row {row_position}, col {col}: {e}")
                    self.setItem(row_position, col, QTableWidgetItem("ERR"))

class ProcessMonitor(QThread):
    """Background thread to monitor process changes"""
    process_changed = pyqtSignal()  # Signal emitted when process list changes
    
    def __init__(self):
        super().__init__()
        self.running = True
        self.last_pids = set()
    
    def run(self):
        """Main monitoring loop"""
        while self.running:
            try:
                current_pids = set(psutil.pids())
                if current_pids != self.last_pids:
                    self.last_pids = current_pids
                    self.process_changed.emit()  # Notify main thread
            except Exception as e:
                print(f"Error in process monitor: {e}")
            self.msleep(1000)  # Check every second
    
    def stop(self):
        """Stop the monitoring thread"""
        self.running = False
        self.wait()


class MainWindow(QMainWindow):
    class ProcessNode(QGraphicsRectItem):
        def __init__(self, name, pid, ppid, children_count, x, y, width=200, height=80, parent=None):
            super().__init__(x, y, width, height, parent)
            self.name = name
            self.pid = pid
            self.ppid = ppid
            self.children_count = children_count
            self.width = width
            self.height = height
            self.setBrush(Qt.white)
            self.setPen(Qt.black)
            self.setZValue(1)
            
            # Add text with process details
            details = (
                f"{name}\n"
                f"PID: {pid}\n"
                f"Parent PID: {ppid}\n"
                f"Children: {children_count}"
            )
            
            self.title = QGraphicsTextItem(details, self)
            self.title.setPos(x + 5, y + 5)
            self.title.setTextWidth(width - 10)
            
            # Highlight the selected process
            self.is_selected = False
            self.setFlag(QGraphicsRectItem.ItemIsMovable)
            self.setFlag(QGraphicsRectItem.ItemIsSelectable)
            
            # Add tooltip with more details
            self.setToolTip(f"Process: {name}\nPID: {pid}\nParent PID: {ppid}\nChildren: {children_count}")
            
        def mousePressEvent(self, event):
            super().mousePressEvent(event)
            self.setBrush(Qt.lightGray)
            self.is_selected = True
            self.update()
            
        def mouseReleaseEvent(self, event):
            super().mouseReleaseEvent(event)
            self.setBrush(Qt.white)
            self.is_selected = False
            self.update()
    
    def draw_process_tree(self, scene, pid, x, y, level=0, parent_node=None):
        """Recursively draw process tree"""
        try:
            proc = psutil.Process(pid)
            with proc.oneshot():
                name = proc.name()
                ppid = proc.ppid()
                
                # Get children count
                try:
                    children = proc.children(recursive=False)
                    children_count = len(children)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    children_count = 0
                
                # Create node with parent and children info
                node = self.ProcessNode(name, pid, ppid, children_count, x, y)
                scene.addItem(node)
                
                # Draw connection to parent
                if parent_node:
                    line = QGraphicsLineItem(
                        parent_node.x() + parent_node.width/2,
                        parent_node.y() + parent_node.height,
                        x + node.width/2,
                        y
                    )
                    line.setPen(Qt.darkGray)
                    scene.addItem(line)
                
                # Position children with better spacing
                try:
                    children = sorted(proc.children(recursive=False), key=lambda p: p.pid)
                    child_count = len(children)
                    
                    # Calculate spacing based on number of children
                    spacing = min(150, max(100, 800 // (child_count + 1)))
                    start_x = x - ((child_count - 1) * spacing) / 2
                    
                    for i, child in enumerate(children):
                        child_x = start_x + i * spacing
                        child_y = y + 120  # Fixed vertical spacing
                        self.draw_process_tree(scene, child.pid, child_x, child_y, level + 1, node)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                
                return node
                
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            # Create a red node for inaccessible processes
            node = self.ProcessNode(f"[Process {pid} not accessible]", pid, "", 0, x, y)
            node.setBrush(QColor(255, 200, 200))  # Light red for errors
            scene.addItem(node)
            return node
    
    def get_process_connections(self, pid):
        """Get network connections for a process"""
        try:
            conns = psutil.Process(pid).net_connections()
            connections = []
            for conn in conns:
                if conn.status != 'NONE' and hasattr(conn, 'laddr') and conn.laddr:
                    if hasattr(conn, 'raddr') and conn.raddr:
                        connections.append(f"{conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port} ({conn.status})")
                    else:
                        connections.append(f"{conn.laddr.ip}:{conn.laddr.port} (LISTENING)")
            return connections
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []

    def build_complete_tree(self, pid, visited=None, depth=0, max_depth=3):
        """Recursively build complete process tree with connections"""
        if visited is None:
            visited = {}
            
        if pid in visited:
            return [visited[pid]]
            
        try:
            proc = psutil.Process(pid)
            with proc.oneshot():
                name = proc.name()
                ppid = proc.ppid()
                
                # Get process details
                try:
                    cmdline = " ".join(proc.cmdline())
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    cmdline = ""
                
                # Get process connections
                connections = self.get_process_connections(pid)
                
                # Create process node
                node = {
                    'pid': pid,
                    'name': name,
                    'ppid': ppid,
                    'cmdline': cmdline,
                    'connections': connections,
                    'depth': depth,
                    'children': []
                }
                
                # Store in visited
                visited[pid] = node
                
                # Only go deeper if we haven't hit max depth
                if depth < max_depth:
                    # Get children
                    try:
                        children = []
                        for child in proc.children(recursive=False):
                            children.extend(self.build_complete_tree(child.pid, visited, depth + 1, max_depth))
                        node['children'] = children
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                return [node]
                
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            node = {
                'pid': pid,
                'name': f'[Process {pid} not accessible]',
                'ppid': -1,
                'cmdline': str(e),
                'connections': [],
                'depth': depth,
                'children': []
            }
            visited[pid] = node
            return [node]
    
    def draw_process_node(self, scene, node, x, y, level=0, parent_x=None, parent_y=None):
        """Draw a process node with connections"""
        node_width = 250
        node_height = 100
        h_spacing = 50
        v_spacing = 120
        
        # Draw connection to parent
        if parent_x is not None and parent_y is not None:
            line = QGraphicsLineItem(
                parent_x,
                parent_y + 15,  # Connect to top of child node
                x + node_width/2,
                y
            )
            line.setPen(Qt.darkGray)
            scene.addItem(line)
        
        # Draw the node
        rect = QGraphicsRectItem(x, y, node_width, node_height)
        rect.setBrush(Qt.white)
        rect.setPen(Qt.black)
        
        # Highlight suspicious processes
        if node['name'].lower() in ['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe']:
            rect.setBrush(QColor(255, 200, 200))  # Light red for suspicious
        
        scene.addItem(rect)
        
        # Add process info
        title = f"{node['name']} (PID: {node['pid']})"
        if node['ppid'] != -1:
            title += f"\nParent: {node['ppid']}"
        
        # Add command line preview
        cmd_preview = node['cmdline'][:50] + ('...' if len(node['cmdline']) > 50 else '')
        title += f"\n{cmd_preview}"
        
        # Add network connections
        if node['connections']:
            title += "\n\nNetwork:"
            for conn in node['connections'][:2]:  # Show first 2 connections
                title += f"\n- {conn}"
            if len(node['connections']) > 2:
                title += f"\n... and {len(node['connections']) - 2} more"
        
        title_item = QGraphicsTextItem(title)
        title_item.setPos(x + 5, y + 5)
        title_item.setTextWidth(node_width - 10)
        title_item.setFont(QFont("Consolas", 8))
        scene.addItem(title_item)
        
        # Draw children
        child_x = x - ((len(node['children']) - 1) * (node_width + h_spacing)) / 2
        
        for i, child in enumerate(node['children']):
            # Draw child node
            self.draw_process_node(scene, child, child_x, y + node_height + v_spacing, 
                                 level + 1, x + node_width/2, y + node_height)
            child_x += node_width + h_spacing
    
    def show_process_tree(self, pid):
        """Show process tree in a Procexp-style dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Process Explorer - PID: {pid}")
        dialog.setMinimumSize(1400, 900)
        
        # Create main layout
        layout = QVBoxLayout()
        
        # Create tab widget
        tab_widget = QTabWidget()
        
        # Tab 1: Process Tree
        tree_tab = QWidget()
        tree_layout = QVBoxLayout()
        
        # Create graphics view with scroll area
        scene = QGraphicsScene()
        view = QGraphicsView(scene)
        view.setRenderHints(QPainter.Antialiasing | QPainter.TextAntialiasing | QPainter.SmoothPixmapTransform)
        view.setViewportUpdateMode(QGraphicsView.FullViewportUpdate)
        view.setDragMode(QGraphicsView.ScrollHandDrag)
        view.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        view.setResizeAnchor(QGraphicsView.AnchorUnderMouse)
        
        # Build complete process tree
        process_tree = self.build_complete_tree(pid, max_depth=3)  # Limit depth for performance
        
        if process_tree:
            # Draw the complete tree
            root_node = process_tree[0]
            self.draw_process_node(scene, root_node, 50, 30)
            
            # Fit view to scene
            scene.setSceneRect(scene.itemsBoundingRect())
            
            # Add zoom controls
            def zoom_in():
                view.scale(1.2, 1.2)
                
            def zoom_out():
                view.scale(0.8, 0.8)
                
            def reset_zoom():
                view.resetTransform()
                view.fitInView(scene.itemsBoundingRect(), Qt.KeepAspectRatio)
            
            # Add zoom buttons
            zoom_layout = QHBoxLayout()
            
            zoom_in_btn = QPushButton("+")
            zoom_in_btn.setFixedSize(30, 30)
            zoom_in_btn.clicked.connect(zoom_in)
            
            zoom_out_btn = QPushButton("-")
            zoom_out_btn.setFixedSize(30, 30)
            zoom_out_btn.clicked.connect(zoom_out)
            
            reset_btn = QPushButton("Reset View")
            reset_btn.clicked.connect(reset_zoom)
            
            zoom_layout.addWidget(zoom_in_btn)
            zoom_layout.addWidget(zoom_out_btn)
            zoom_layout.addWidget(reset_btn)
            zoom_layout.addStretch()
            
            tree_layout.addLayout(zoom_layout)
            
            # Initial zoom
            reset_zoom()
        
        tree_layout.addWidget(view)
        tree_tab.setLayout(tree_layout)
        
        # Create details tab with proper layout
        details_tab = QWidget()
        details_layout = QVBoxLayout(details_tab)
        details_layout.setContentsMargins(0, 0, 0, 0)
        details_layout.setSpacing(0)
        
        # Create a scroll area to handle large content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        
        # Create a container widget for the table
        container = QWidget()
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(8, 8, 8, 8)
        
        def format_process_details(node, parent_widget):
            # Create a table widget
            table = QTableWidget()
            table.setColumnCount(2)
            table.setHorizontalHeaderLabels(["Property", "Value"])
            table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
            table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
            table.verticalHeader().setVisible(False)
            table.setEditTriggers(QTableWidget.NoEditTriggers)
            table.setShowGrid(False)
            table.setAlternatingRowColors(True)
            table.setWordWrap(True)
            table.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContents)
            
            # Style the table
            table.setStyleSheet("""
                QTableWidget {
                    border: 1px solid #e0e0e0;
                    border-radius: 4px;
                    font-family: 'Segoe UI', Arial, sans-serif;
                    font-size: 11px;
                    background: white;
                    gridline-color: #f0f0f0;
                }
                QTableWidget::item {
                    padding: 6px 8px;
                    border: none;
                    border-bottom: 1px solid #f0f0f0;
                }
                QTableWidget::item:last {
                    border-bottom: none;
                }
                QHeaderView::section {
                    background-color: #f8f9fa;
                    padding: 8px;
                    border: none;
                    border-bottom: 1px solid #e0e0e0;
                    font-weight: 600;
                    color: #444;
                }
                QScrollBar:vertical {
                    border: none;
                    background: #f8f9fa;
                    width: 10px;
                    margin: 0px;
                }
                QScrollBar::handle:vertical {
                    background: #d1d5db;
                    min-height: 20px;
                    border-radius: 5px;
                }
                QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                    height: 0px;
                }
            """)
            
            # Add process details
            details = [
                ("Process Name", node['name']),
                ("PID", str(node['pid'])),
                ("Parent PID", str(node['ppid'])),
                ("Command Line", node['cmdline'] if node['cmdline'] else "N/A")
            ]
            
            # Add network connections if any
            if node['connections']:
                connections = "\n".join([f"• {conn}" for conn in node['connections']])
                details.append(("Network Connections", connections))
            
            # Populate the table
            table.setRowCount(len(details))
            for row, (key, value) in enumerate(details):
                key_item = QTableWidgetItem(key)
                value_item = QTableWidgetItem(value)
                key_item.setToolTip(key)
                value_item.setToolTip(value)
                table.setItem(row, 0, key_item)
                table.setItem(row, 1, value_item)
            
            # Adjust row heights for multi-line content
            table.resizeRowsToContents()
            
            # Set minimum width for better appearance
            table.setMinimumWidth(600)
            
            # Adjust column widths
            table.resizeColumnsToContents()
            
            return table
        
        if process_tree:
            details_table = format_process_details(process_tree[0], details_tab)
            container_layout.addWidget(details_table)
            
            # Add stretch to push content to the top
            container_layout.addStretch()
            
            # Set up the scroll area
            scroll.setWidget(container)
            details_layout.addWidget(scroll)
            
            # Set the tab layout
            details_tab.setLayout(details_layout)
        
        # Add tabs
        tab_widget.addTab(tree_tab, "Process Tree")
        tab_widget.addTab(details_tab, "Process Details")
        
        # Add widgets to layout
        layout.addWidget(tab_widget)
        
        # Add close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        
        # Add navigation buttons
        zoom_in_btn = QPushButton("Zoom In (+)")
        zoom_out_btn = QPushButton("Zoom Out (-)")
        
        def zoom_in():
            view.scale(1.2, 1.2)
            
        def zoom_out():
            view.scale(0.8, 0.8)
            
        zoom_in_btn.clicked.connect(zoom_in)
        zoom_out_btn.clicked.connect(zoom_out)
        
        # Button layout
        button_layout = QHBoxLayout()
        button_layout.addWidget(zoom_in_btn)
        button_layout.addWidget(zoom_out_btn)
        button_layout.addStretch()
        button_layout.addWidget(close_btn)
        
        layout.addWidget(tab_widget)
        layout.addLayout(button_layout)
        dialog.setLayout(layout)
        
        # Add mouse wheel zoom for the view
        def wheelEvent(event):
            zoom_in_factor = 1.15
            zoom_out_factor = 1 / zoom_in_factor
            
            old_pos = view.mapToScene(event.pos())
            
            if event.angleDelta().y() > 0:
                zoom_factor = zoom_in_factor
            else:
                zoom_factor = zoom_out_factor
                
            view.scale(zoom_factor, zoom_factor)
            
            new_pos = view.mapToScene(event.pos())
            delta = new_pos - old_pos
            view.translate(delta.x(), delta.y())
            
        view.wheelEvent = wheelEvent
        
        # Show the dialog
        dialog.exec_()
        
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Professional Process Manager - Malware Analysis Edition")
        self.setGeometry(100, 100, 1500, 900)
        # Initialize process lists
        self.processes = []
        self.previous_pids = set()  # Track PIDs from previous refresh
        self.system_processes = []
        self.non_system_processes = []
        self.unknown_processes = []
        self.system_users = {'SYSTEM', 'root', 'LocalService', 'NetworkService'}
        self.process_changes = {'added': [], 'removed': []}  # Track process changes
        
        # Set up UI
        self.setStyleSheet("""
            QMainWindow {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #c3dafe, stop:1 #f5fafd);
            }
            QFrame#GlassPanel {
                background: rgba(255,255,255,0.65);
                border-radius: 32px;
                box-shadow: 0 8px 36px 0 rgba(60,60,120,0.13), 0 1.5px 12px 0 rgba(0,0,0,0.07);
                border: 1.5px solid #e4e9f7;
            }
            QLabel#TitleLabel {
                color: #0078d7;
                font-size: 2.7em;
                font-weight: bold;
                margin-top: 24px;
                margin-bottom: 0px;
                letter-spacing: 1.5px;
                text-shadow: 0 2px 12px #b0d0fa;
            }
            QLabel#SubtitleLabel {
                color: #6f42c1;
                font-size: 1.3em;
                margin-bottom: 18px;
                margin-top: 0px;
                font-weight: 500;
                letter-spacing: 0.8px;
            }
            QLabel#FooterLabel {
                color: #6f42c1;
                font-size: 1.13em;
                font-style: italic;
                margin-top: 22px;
                margin-bottom: 12px;
                qproperty-alignment: AlignRight | AlignBottom;
                text-shadow: 0 1px 8px #e0e0fa;
            }
            QTableWidget {
                border: 1px solid #ddd;
                gridline-color: #eee;
            }
            QHeaderView::section {
                background: #f5f5f5;
                padding: 6px;
                border: 1px solid #ddd;
            }
            QPushButton {
                padding: 6px 12px;
                background: #f0f0f0;
                border: 1px solid #ccc;
                border-radius: 4px;
            }
            QPushButton:hover {
                background: #e0e0e0;
            }
            QLineEdit, QComboBox {
                padding: 6px;
                border: 1px solid #ccc;
                border-radius: 4px;
            }
            QLineEdit:focus, QComboBox:focus {
                border: 1px solid #7ab8ff;
            }
        """)

        # Create main layout
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(12)
        
        # Title
        title = QLabel("Windows Process Manager")
        title.setFont(QFont('Segoe UI', 18, QFont.Bold))
        main_layout.addWidget(title)
        
        # Subtitle
        subtitle = QLabel("Malware Analysis Edition")
        subtitle.setFont(QFont('Segoe UI', 10))
        main_layout.addWidget(subtitle)
        
        # Add a separator line
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        main_layout.addWidget(line)
        
        # Filter and search controls
        control_layout = QHBoxLayout()
        
        # Filter dropdown
        self.filter_box = QComboBox()
        self.filter_box.addItems(["All", "Internal", "External"])
        self.filter_box.currentIndexChanged.connect(self.apply_filters)
        control_layout.addWidget(QLabel("Filter:"))
        control_layout.addWidget(self.filter_box)
        
        # Add stretch to push search to the right
        control_layout.addStretch()
        
        # Search bar
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search processes...")
        self.search_bar.textChanged.connect(self.apply_filters)
        control_layout.addWidget(QLabel("Search:"))
        control_layout.addWidget(self.search_bar)
        
        main_layout.addLayout(control_layout)
        
        # Get processes
        self.processes = get_all_processes()
        
        # Split processes into system and non-system
        self.system_users = {'SYSTEM', 'root', 'LocalService', 'NetworkService'}
        self.unknown_processes = [p for p in self.processes if p[15]=='Unknown' and p[5] not in self.system_users]
        self.system_processes = [p for p in self.processes if p[5] in self.system_users]
        self.non_system_processes = [p for p in self.processes if p[5] not in self.system_users]
        
        # Main process table (for unknown and non-system)
        self.table = ProcessTable(self.non_system_processes)
        main_layout.addWidget(self.table, 1)  # Add stretch factor to make table expandable
        
        # System process table
        self.system_table = ProcessTable(self.system_processes)
        self.system_table.hide()
        main_layout.addWidget(self.system_table, 1)  # Add stretch factor to make table expandable
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(8)
        
        self.unknown_button = QPushButton("Show Unknown Processes Only")
        self.unknown_button.clicked.connect(self.show_unknown_processes)
        button_layout.addWidget(self.unknown_button)
        
        self.system_button = QPushButton("Show System Processes Only")
        self.system_button.clicked.connect(self.show_system_processes)
        button_layout.addWidget(self.system_button)
        
        self.all_button = QPushButton("Show All Processes")
        self.all_button.clicked.connect(self.show_all_processes)
        button_layout.addWidget(self.all_button)
        
        main_layout.addLayout(button_layout)
        
        # Footer
        footer = QLabel("Designed by Ashwin")
        footer.setFont(QFont('Segoe UI', 9, QFont.StyleItalic))
        main_layout.addWidget(footer, 0, Qt.AlignRight)
        
        # Add refresh button
        refresh_button = QPushButton("Refresh Processes")
        refresh_button.clicked.connect(self.refresh_processes)
        button_layout.addWidget(refresh_button)
        
        # Set the central widget
        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)
        
        # Add auto-refresh toggle button
        self.auto_refresh_btn = QPushButton("Enable Auto-Refresh")
        self.auto_refresh_btn.setCheckable(True)
        self.auto_refresh_btn.toggled.connect(self.toggle_auto_refresh)
        button_layout.addWidget(self.auto_refresh_btn)
        
        # Set up process monitor
        self.auto_refresh = False
        self.process_monitor = ProcessMonitor()
        self.process_monitor.process_changed.connect(self.on_processes_changed)
        self.process_monitor.start()
        
        # Initial load
        self.refresh_processes()

    def show_unknown_processes(self):
        # Hide system table, show main table
        self.system_table.hide()
        self.table.show()
        # Reload essential process list
        essentials = set(x.strip().lower() for x in load_essential_processes('c:/Users/ashwi/Downloads/essential_processes.txt'))
        # Normalize user and process name for comparison
        def is_system_user(user):
            if not user:
                return False
            user = user.lower()
            if '\\' in user:
                user = user.split('\\', 1)[-1]
            return user in [u.lower() for u in self.system_users]
        unknowns = []
        for p in self.processes:
            pname = str(p[2]).strip().lower()
            user = str(p[5]).strip()
            # Debug print
            print(f"DEBUG: Process '{pname}' user '{user}' essentials={pname in essentials} system={is_system_user(user)}")
            if pname not in essentials and not is_system_user(user):
                unknowns.append(p)
        self.unknown_processes = unknowns
        self.table.clearContents()
        self.table.setRowCount(0)
        self.table.populate_table(self.unknown_processes)

    def show_system_processes(self):
        # Hide main table, show system table
        self.table.hide()
        self.system_table.show()
        # Rebuild system process list (by user, normalize domain/case)
        def is_system_user(user):
            if not user:
                return False
            user = user.lower()
            if '\\' in user:
                user = user.split('\\', 1)[-1]
            return user in [u.lower() for u in self.system_users]
        system_procs = []
        for p in self.processes:
            user = str(p[5]).strip()
            # Debug print
            print(f"DEBUG: SYSTEM CHECK: '{user}' is_system={is_system_user(user)}")
            if is_system_user(user):
                system_procs.append(p)
        self.system_processes = system_procs
        self.system_table.clearContents()
        self.system_table.setRowCount(0)
        self.system_table.populate_table(self.system_processes)

    def show_process_changes(self, added, removed):
        """Show a dialog with process changes"""
        if not added and not removed:
            return
            
        dialog = QDialog(self)
        dialog.setWindowTitle("Process Changes Detected")
        dialog.setMinimumSize(600, 400)
        
        layout = QVBoxLayout()
        
        # Create tab widget
        tab_widget = QTabWidget()
        
        # Tab for new processes
        if added:
            new_tab = QWidget()
            new_layout = QVBoxLayout()
            
            table = QTableWidget()
            table.setColumnCount(3)
            table.setHorizontalHeaderLabels(["PID", "Name", "User"])
            table.setRowCount(len(added))
            
            for row, proc in enumerate(added):
                table.setItem(row, 0, QTableWidgetItem(str(proc[0])))  # PID
                table.setItem(row, 1, QTableWidgetItem(proc[2]))      # Name
                table.setItem(row, 2, QTableWidgetItem(proc[5]))      # User
            
            table.resizeColumnsToContents()
            new_layout.addWidget(QLabel(f"{len(added)} New Processes:"))
            new_layout.addWidget(table)
            new_tab.setLayout(new_layout)
            tab_widget.addTab(new_tab, f"New Processes ({len(added)})")
        
        # Tab for terminated processes
        if removed:
            term_tab = QWidget()
            term_layout = QVBoxLayout()
            
            table = QTableWidget()
            table.setColumnCount(3)
            table.setHorizontalHeaderLabels(["PID", "Name", "User"])
            table.setRowCount(len(removed))
            
            for row, proc in enumerate(removed):
                table.setItem(row, 0, QTableWidgetItem(str(proc[0])))  # PID
                table.setItem(row, 1, QTableWidgetItem(proc[2]))      # Name
                table.setItem(row, 2, QTableWidgetItem(proc[5]))      # User
            
            table.resizeColumnsToContents()
            term_layout.addWidget(QLabel(f"{len(removed)} Terminated Processes:"))
            term_layout.addWidget(table)
            term_tab.setLayout(term_layout)
            tab_widget.addTab(term_tab, f"Terminated ({len(removed)})")
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        
        # Add to layout
        layout.addWidget(tab_widget)
        layout.addWidget(close_btn, 0, Qt.AlignRight)
        
        dialog.setLayout(layout)
        dialog.exec_()

    def refresh_processes(self):
        """Manually refresh the process list"""
        try:
            # Store previous PIDs before refresh
            previous_pids = {p[0] for p in self.processes} if self.processes else set()
            
            # Get current processes
            self.processes = get_all_processes()
            current_pids = {p[0] for p in self.processes}
            
            # Find added and removed processes
            added_pids = current_pids - previous_pids
            removed_pids = previous_pids - current_pids
            
            # Get full process info for changes
            added_processes = [p for p in self.processes if p[0] in added_pids]
            removed_processes = [p for p in self.processes if p[0] in removed_pids]
            
            # Show changes if not the first run
            if previous_pids and (added_processes or removed_processes):
                self.show_process_changes(added_processes, removed_processes)
            
            # Update process lists
            self.unknown_processes = [p for p in self.processes if p[15]=='Unknown' and p[5] not in self.system_users]
            self.system_processes = [p for p in self.processes if p[5] in self.system_users]
            self.non_system_processes = [p for p in self.processes if p[5] not in self.system_users]
            
            # Update the current view
            if self.system_table.isVisible():
                self.system_table.populate_table(self.system_processes)
            elif self.table.isVisible():
                if hasattr(self, 'showing_unknown') and self.showing_unknown:
                    self.table.populate_table(self.unknown_processes)
                else:
                    self.table.populate_table(self.non_system_processes)
            
            # Show refresh time in status bar
            from datetime import datetime
            self.statusBar().showMessage(f"Last refreshed: {datetime.now().strftime('%H:%M:%S')}")
            
        except Exception as e:
            print(f"Error refreshing processes: {e}")
            self.statusBar().showMessage(f"Error: {str(e)}", 5000)
    
    def toggle_auto_refresh(self, checked):
        """Toggle auto-refresh on/off"""
        self.auto_refresh = checked
        self.auto_refresh_btn.setText("Auto-Refresh: " + ("On" if checked else "Off"))
        if checked:
            self.refresh_processes()  # Do an immediate refresh when enabling
    
    def on_processes_changed(self):
        """Called when the process monitor detects changes"""
        if self.auto_refresh:
            self.refresh_processes()
    
    def closeEvent(self, event):
        """Clean up when closing the application"""
        if hasattr(self, 'process_monitor'):
            self.process_monitor.stop()
        super().closeEvent(event)
    
    def show_all_processes(self):
        self.system_table.hide()
        self.table.show()
        self.table.populate_table(self.non_system_processes)
        self.showing_unknown = False
        # Apply any active filters
        self.apply_filters()

    def apply_filters(self):
        filter_type = self.filter_box.currentText()
        text = self.search_bar.text().lower()
        # Decide which table is visible
        table = self.table if self.table.isVisible() else self.system_table if self.system_table.isVisible() else None
        if not table:
            return
        type_col = 14  # 'Type' column
        name_col = 2   # Name
        user_col = 5   # User
        loc_col = 12   # Location
        for row in range(table.rowCount()):
            show = True
            # Filter by type
            if filter_type != "All":
                type_item = table.item(row, type_col)
                if not (type_item and type_item.text() == filter_type):
                    show = False
            # Search filter
            match = False
            for col in [name_col, user_col, loc_col]:
                item = table.item(row, col)
                if item and text in item.text().lower():
                    match = True
                    break
            if text and not match:
                show = False
            table.setRowHidden(row, not show)

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
