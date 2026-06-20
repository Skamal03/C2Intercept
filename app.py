import sys
import os
import asyncio
import pyshark
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QTableWidget, QTableWidgetItem,
                             QLabel, QLineEdit, QTextEdit, QHeaderView, QStatusBar,
                             QFileDialog, QFrame, QSplitter, QGraphicsOpacityEffect,
                             QProgressBar)
from PyQt6.QtCore import QThread, pyqtSignal, Qt, QTimer
from PyQt6.QtGui import QColor, QCursor
from core_analyzer import C2Detector


class FileProcessorWorker(QThread):
    analysis_complete  = pyqtSignal(list, list)
    error_triggered    = pyqtSignal(str)
    progress_update    = pyqtSignal(int, int)   # (packets_processed, threats_found)

    def __init__(self, file_path):
        super().__init__()
        self.file_path   = file_path
        self.tshark_path = r"C:\Users\ROARSCHACH\Downloads\Installs\Wireshark\tshark.exe"
        self.detector    = C2Detector()
        self.running     = True

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            cap = pyshark.FileCapture(
                self.file_path,
                display_filter='ip',
                tshark_path=self.tshark_path,
                eventloop=loop
            )

            packet_buffer     = []
            found_threats     = []
            malicious_packets = []
            flagged_flow_keys = set()
            total_processed   = 0

            for packet in cap:
                if not self.running:
                    break
                try:
                    proto_layer = packet.transport_layer
                    if not proto_layer or proto_layer not in ['TCP', 'UDP']:
                        continue

                    sport = int(packet[proto_layer].srcport)
                    dport = int(packet[proto_layer].dstport)

                    pkt = {
                        'time':  float(packet.sniff_time.timestamp()),
                        'src':   str(packet.ip.src),
                        'dst':   str(packet.ip.dst),
                        'sport': sport,
                        'dport': dport,
                        'proto': str(proto_layer),
                        'size':  int(packet.length)
                    }
                    packet_buffer.append(pkt)
                    total_processed += 1

                    if total_processed % 100 == 0:
                        self.progress_update.emit(total_processed, len(found_threats))

                    if len(packet_buffer) >= 200:
                        alerts = self.detector.analyze_buffer(packet_buffer)
                        for alert in alerts:
                            flow_key = (alert['src'], alert['dst'], alert['dport'])
                            if flow_key not in flagged_flow_keys:
                                flagged_flow_keys.add(flow_key)
                                found_threats.append(alert)
                                for p in packet_buffer:
                                    if (p['src'] == alert['src'] and p['dst'] == alert['dst']) or \
                                       (p['src'] == alert['dst'] and p['dst'] == alert['src']):
                                        malicious_packets.append(p)

                        packet_buffer = packet_buffer[50:]

                except Exception:
                    continue

            # Final flush
            if packet_buffer and self.running:
                alerts = self.detector.analyze_buffer(packet_buffer)
                for alert in alerts:
                    flow_key = (alert['src'], alert['dst'], alert['dport'])
                    if flow_key not in flagged_flow_keys:
                        flagged_flow_keys.add(flow_key)
                        found_threats.append(alert)
                        for p in packet_buffer:
                            if (p['src'] == alert['src'] and p['dst'] == alert['dst']) or \
                               (p['src'] == alert['dst'] and p['dst'] == alert['src']):
                                malicious_packets.append(p)

            cap.close()
            self.progress_update.emit(total_processed, len(found_threats))

            if self.running:
                self.analysis_complete.emit(found_threats, malicious_packets)
            else:
                self.analysis_complete.emit([], [])

        except Exception as e:
            self.error_triggered.emit(str(e))
        finally:
            loop.close()

    def stop(self):
        self.running = False


class SnifferWorker(QThread):
    packet_received = pyqtSignal(dict)
    alert_received  = pyqtSignal(dict)

    def __init__(self, interface):
        super().__init__()
        self.interface     = interface
        self.running       = True
        self.detector      = C2Detector()
        self.packet_buffer = []
        self.tshark_path   = r"C:\Users\ROARSCHACH\Downloads\Installs\Wireshark\tshark.exe"
        self.flagged_flows = set()

        self.scan_dir = "scans"
        os.makedirs(self.scan_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_pcap_path = os.path.join(self.scan_dir, f"live_capture_{ts}.pcap")

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            capture = pyshark.LiveCapture(
                interface=self.interface,
                bpf_filter='ip and (tcp or udp)',
                eventloop=loop,
                tshark_path=self.tshark_path,
                output_file=self.output_pcap_path
            )
            self._capture = capture

            for packet in capture.sniff_continuously():
                if not self.running:
                    break
                try:
                    proto_layer = packet.transport_layer
                    if not proto_layer or proto_layer not in ['TCP', 'UDP']:
                        continue

                    pkt = {
                        'time':  float(packet.sniff_time.timestamp()),
                        'src':   str(packet.ip.src),
                        'dst':   str(packet.ip.dst),
                        'sport': int(packet[proto_layer].srcport),
                        'dport': int(packet[proto_layer].dstport),
                        'proto': str(proto_layer),
                        'size':  int(packet.length)
                    }

                    self.packet_received.emit(pkt)
                    self.packet_buffer.append(pkt)

                    if len(self.packet_buffer) >= 200:
                        alerts = self.detector.analyze_buffer(list(self.packet_buffer))
                        for alert in alerts:
                            flow_key = (alert['src'], alert['dst'], alert['dport'])
                            if flow_key not in self.flagged_flows:
                                self.flagged_flows.add(flow_key)
                                self.alert_received.emit(alert)

                        self.packet_buffer = self.packet_buffer[50:]

                except Exception:
                    pass

            capture.close()

        except Exception as e:
            print(f"[-] Live Sniffer Exception: {e}")
        finally:
            loop.close()

    def stop(self):
        self.running = False
        try:
            if hasattr(self, '_capture') and self._capture:
                self._capture.close()
        except Exception:
            pass


class SafeScanApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SafeScan AI-Driven C2 Interceptor Platform")
        self.setGeometry(100, 100, 1200, 850)
        self.total_packets_displayed = 0
        self.worker         = None
        self.file_worker    = None
        self._dot_count     = 0
        self._spinner_timer = QTimer()
        self._spinner_timer.timeout.connect(self._tick_spinner)
        self.init_ui()
        self.apply_dark_theme()

    def init_ui(self):
        main_widget   = QWidget()
        self.setCentralWidget(main_widget)
        window_layout = QVBoxLayout(main_widget)
        window_layout.setContentsMargins(10, 10, 10, 10)
        window_layout.setSpacing(6)

        # ── Top control bar ───────────────────────────────────────────────────
        top_bar = QFrame()
        top_bar.setObjectName("topBar")
        top_layout = QHBoxLayout(top_bar)
        top_layout.setContentsMargins(10, 5, 10, 5)

        top_layout.addWidget(QLabel("Network Interface:"))
        self.interface_input = QLineEdit()
        self.interface_input.setPlaceholderText(
            "e.g.  Wi-Fi  |  Ethernet  |  \\Device\\NPF_{GUID}")
        self.interface_input.setFixedWidth(340)
        top_layout.addWidget(self.interface_input)

        self.btn_start = QPushButton("▶  Start Live Capture")
        self.btn_start.setObjectName("btnStart")
        self.btn_start.clicked.connect(self.start_live_capture)
        top_layout.addWidget(self.btn_start)

        self.btn_stop = QPushButton("■  Stop Capture")
        self.btn_stop.setObjectName("btnStop")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_live_capture)
        top_layout.addWidget(self.btn_stop)

        top_layout.addSpacing(20)

        self.btn_upload = QPushButton("📂  Analyze PCAP File")
        self.btn_upload.setObjectName("btnUpload")
        self.upload_opacity_effect = QGraphicsOpacityEffect()
        self.upload_opacity_effect.setOpacity(1.0)
        self.btn_upload.setGraphicsEffect(self.upload_opacity_effect)
        self.btn_upload.clicked.connect(self.process_offline_file)
        top_layout.addWidget(self.btn_upload)

        self.btn_stop_file = QPushButton("✖  Abort Scan")
        self.btn_stop_file.setObjectName("btnStopFile")
        self.btn_stop_file.setEnabled(False)
        self.btn_stop_file.clicked.connect(self.stop_file_analysis)
        top_layout.addWidget(self.btn_stop_file)

        top_layout.addStretch()
        self.btn_clear = QPushButton("🗑  Clear Console")
        self.btn_clear.setObjectName("btnClear")
        self.btn_clear.clicked.connect(self.clear_ui_displays)
        top_layout.addWidget(self.btn_clear)

        top_layout.addStretch()
        window_layout.addWidget(top_bar)

        # ── Progress bar row (hidden until file scan starts) ──────────────────
        self.progress_frame = QFrame()
        self.progress_frame.setObjectName("progressFrame")
        progress_layout = QHBoxLayout(self.progress_frame)
        progress_layout.setContentsMargins(10, 4, 10, 4)
        progress_layout.setSpacing(10)

        self.spinner_label = QLabel("⬤")
        self.spinner_label.setFixedWidth(60)
        self.spinner_label.setStyleSheet("color: #00e5ff; font-size: 11px; font-family: monospace;")
        progress_layout.addWidget(self.spinner_label)

        self.progress_label = QLabel("Initializing scan engine...")
        self.progress_label.setStyleSheet("color: #00e5ff; font-weight: bold;")
        progress_layout.addWidget(self.progress_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)        # indeterminate bouncing bar
        self.progress_bar.setFixedHeight(14)
        self.progress_bar.setTextVisible(False)
        progress_layout.addWidget(self.progress_bar)

        self.threats_label = QLabel("Threats found: 0")
        self.threats_label.setStyleSheet("color: #ff5555; font-weight: bold;")
        self.threats_label.setFixedWidth(150)
        progress_layout.addWidget(self.threats_label)

        self.progress_frame.setVisible(False)
        window_layout.addWidget(self.progress_frame)

        # ── Main splitter ─────────────────────────────────────────────────────
        splitter = QSplitter(Qt.Orientation.Vertical)
        window_layout.addWidget(splitter)

        packet_container = QWidget()
        packet_layout    = QVBoxLayout(packet_container)
        packet_layout.setContentsMargins(0, 5, 0, 0)

        self.console_title_label = QLabel(
            "<b>📡 Isolated C2 Streams View (Targeted Triage Mode):</b>")
        packet_layout.addWidget(self.console_title_label)

        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(6)
        self.packet_table.setHorizontalHeaderLabels(
            ["Source Host", "Destination Host", "Src Port", "Dst Port", "Protocol", "Length (Bytes)"])
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.packet_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.packet_table.setAlternatingRowColors(True)
        packet_layout.addWidget(self.packet_table)
        splitter.addWidget(packet_container)

        alert_container = QWidget()
        alert_layout    = QVBoxLayout(alert_container)
        alert_layout.setContentsMargins(0, 5, 0, 0)

        alert_layout.addWidget(
            QLabel("<b>🚨 Active Security Timeline / Machine Learning Detections:</b>"))
        self.alert_console = QTextEdit()
        self.alert_console.setReadOnly(True)
        self.alert_console.setStyleSheet(
            "background-color: #1e1e1e; color: #ff5555;"
            "font-family: 'Consolas', 'Courier New', monospace;")
        alert_layout.addWidget(self.alert_console)
        splitter.addWidget(alert_container)

        splitter.setSizes([400, 400])

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage(
            "System Check: Engine Standby. Ready to analyze network footprints.")

    def apply_dark_theme(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #121212; }
            QWidget { background-color: #121212; color: #e0e0e0; font-size: 12px; }
            QFrame { border: 1px solid #2d2d2d; background-color: #1a1a1a; }
            QFrame#progressFrame { border: 1px solid #00e5ff44;
                                   background-color: #0a1a1f; border-radius: 4px; }
            QLabel { border: none; background: transparent; color: #b0b0b0; }
            QLineEdit { background-color: #262626; border: 1px solid #3d3d3d;
                        color: #ffffff; padding: 4px; border-radius: 3px; }
            QPushButton { background-color: #2a2a2a; border: 1px solid #3d3d3d;
                          color: #e0e0e0; padding: 6px 12px; border-radius: 3px;
                          font-weight: bold; }
            QPushButton:hover { background-color: #353535; }
            QPushButton#btnStart    { background-color: #1b5e20; color: #fff; border: 1px solid #2e7d32; }
            QPushButton#btnStop     { background-color: #b71c1c; color: #fff; border: 1px solid #c62828; }
            QPushButton#btnUpload   { background-color: #0d47a1; color: #fff; border: 1px solid #1565c0; }
            QPushButton#btnStopFile { background-color: #d84315; color: #fff; border: 1px solid #e64a19; }
            QPushButton#btnStopFile:disabled { background-color: #2d1e1a; color: #5c433c;
                                               border: 1px solid #3d2b27; }
            QPushButton#btnClear { background-color: #4a4a00; color: #fff; border: 1px solid #6a6a00; }
            QTableWidget { background-color: #1a1a1a; alternate-background-color: #112233;
                           border: 1px solid #2d2d2d; gridline-color: #2d2d2d; color: #ffffff; }
            QHeaderView::section { background-color: #2d2d2d; color: #b0b0b0;
                                   padding: 5px; border: 1px solid #1a1a1a; }
            QStatusBar { background-color: #1a1a1a; border-top: 1px solid #2d2d2d; color: #888; }
            QProgressBar { background-color: #1a2a2a; border: 1px solid #00e5ff44;
                           border-radius: 3px; }
            QProgressBar::chunk { background-color: #00e5ff; border-radius: 3px; }
        """)

    # ── Spinner ───────────────────────────────────────────────────────────────
    def _tick_spinner(self):
        frames = ["█░░░", "░█░░", "░░█░", "░░░█", "░░█░", "░█░░"]
        self.spinner_label.setText(frames[self._dot_count % len(frames)])
        self._dot_count += 1

    def _start_progress(self, filename):
        self.progress_frame.setVisible(True)
        self.progress_label.setText(f"Scanning: {filename}")
        self.threats_label.setText("Threats found: 0")
        self.spinner_label.setStyleSheet("color: #00e5ff; font-size: 11px; font-family: monospace;")
        self._dot_count = 0
        self._spinner_timer.start(200)

    def _stop_progress(self):
        self._spinner_timer.stop()
        self.spinner_label.setText("DONE")
        self.spinner_label.setStyleSheet("color: #00ff88; font-size: 11px; font-weight: bold;")
        QTimer.singleShot(3000, lambda: self.progress_frame.setVisible(False))

    def _update_progress(self, packets_done, threats_found):
        self.progress_label.setText(f"Packets analyzed: {packets_done:,}")
        self.threats_label.setText(f"Threats found: {threats_found}")

    # ── Live capture ──────────────────────────────────────────────────────────
    def start_live_capture(self):
        iface = self.interface_input.text().strip()
        if not iface:
            self.status_bar.showMessage("Enter a network interface name first.")
            return
        self.clear_ui_displays()
        self.btn_start.setEnabled(False)
        self.btn_upload.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.interface_input.setReadOnly(True)
        self.upload_opacity_effect.setOpacity(0.35)

        self.worker = SnifferWorker(iface)
        self.worker.packet_received.connect(self.add_packet_row)
        self.worker.alert_received.connect(self.display_threat_alert)
        self.worker.start()
        self.status_bar.showMessage(f"Live capture running on: {iface}")

    def stop_live_capture(self):
        if self.worker:
            self.worker.stop()
            self.worker.wait()
            pcap_path = self.worker.output_pcap_path
            self.worker = None
        else:
            pcap_path = None

        self.btn_start.setEnabled(True)
        self.btn_upload.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.interface_input.setReadOnly(False)
        self.upload_opacity_effect.setOpacity(1.0)
        self.status_bar.showMessage("Live capture stopped.")

        if pcap_path and os.path.exists(pcap_path):
            from PyQt6.QtWidgets import QToolTip
            from PyQt6.QtGui import QCursor
            QToolTip.showText(
                QCursor.pos(),
                f"Capture saved to:\n{pcap_path}",
                self,
                msecDelay=4000
            )

    # ── Table row ─────────────────────────────────────────────────────────────
    def add_packet_row(self, pkt, highlight=False):
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        values = [pkt['src'], pkt['dst'], str(pkt['sport']),
                  str(pkt['dport']), pkt['proto'], str(pkt['size'])]
        for col, val in enumerate(values):
            item = QTableWidgetItem(val)
            if highlight:
                item.setForeground(QColor("#ff5555"))
                item.setBackground(QColor("#2a0a0a"))
            self.packet_table.setItem(row, col, item)
        self.packet_table.scrollToBottom()
        self.total_packets_displayed += 1

    # ── Alert display ─────────────────────────────────────────────────────────
    def display_threat_alert(self, alert):
        msg = (
            f"⚠️  [C2 DETECTED] — Confidence: {alert['confidence']}\n"
            f"▶  SRC: {alert['src']}:{alert['sport']}  →  "
            f"DST: {alert['dst']}:{alert['dport']}\n"
            f"  Packets: {alert.get('pkt_count', 'N/A')}  |  "
            f"Bytes: {alert.get('byte_count', 'N/A')}\n"
            f"  {alert['reason']}\n"
            f"{'-' * 80}\n"
        )
        self.alert_console.append(msg)

    def display_c2_packet_details(self, threats, malicious_packets):
        """Full per-packet breakdown printed to console after file scan completes."""
        if not threats:
            return

        self.alert_console.append(
            "\n" + "═" * 80 + "\n"
            "   📋  C2 PACKET DETAIL REPORT — FULL FLOW BREAKDOWN\n" +
            "═" * 80 + "\n"
        )

        # Group malicious packets by flow key
        flow_map = {}
        for pkt in malicious_packets:
            fwd = (pkt['src'], pkt['dst'], pkt['dport'])
            if fwd not in flow_map:
                flow_map[fwd] = []
            flow_map[fwd].append(pkt)

        for i, threat in enumerate(threats, 1):
            fwd_key = (threat['src'], threat['dst'], threat['dport'])
            rev_key = (threat['dst'], threat['src'], threat['sport'])

            all_pkts = sorted(
                flow_map.get(fwd_key, []) + flow_map.get(rev_key, []),
                key=lambda p: p['time']
            )

            self.alert_console.append(
                f"┌─ THREAT #{i} {'─' * 67}\n"
                f"│  Flow       : {threat['src']}:{threat['sport']}  →  "
                f"{threat['dst']}:{threat['dport']}\n"
                f"│  Confidence : {threat['confidence']}\n"
                f"│  Analysis   : {threat['reason']}\n"
                f"│  Pkt count  : {threat.get('pkt_count', len(all_pkts))}   "
                f"Total bytes: {threat.get('byte_count', 'N/A')}\n"
                f"├─ PACKET TIMELINE {'─' * 61}"
            )

            if all_pkts:
                base_time    = all_pkts[0]['time']
                display_pkts = all_pkts[:50]
                for idx, pkt in enumerate(display_pkts, 1):
                    rel   = pkt['time'] - base_time
                    direc = "→ OUT" if pkt['src'] == threat['src'] else "← IN "
                    self.alert_console.append(
                        f"│  [{idx:>3}]  +{rel:>8.3f}s  {direc}  "
                        f"{pkt['src']}:{pkt['sport']}  →  "
                        f"{pkt['dst']}:{pkt['dport']}  "
                        f"[{pkt['proto']}]  {pkt['size']} B"
                    )
                if len(all_pkts) > 50:
                    self.alert_console.append(
                        f"│  ... {len(all_pkts) - 50} more packets not shown (limit 50 per flow)."
                    )
            else:
                self.alert_console.append(
                    "│  (No individual packet records for this flow)")

            self.alert_console.append("└" + "─" * 79 + "\n")

    # ── PCAP file scan ────────────────────────────────────────────────────────
    def process_offline_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open PCAP File", "",
            "Network Captures (*.pcap *.pcapng)")
        if not file_path:
            return

        self.clear_ui_displays()
        fname = os.path.basename(file_path)
        self.console_title_label.setText(f"<b>📡 Analysing: {fname}</b>")
        self.status_bar.showMessage(f"Scanning '{fname}' — please wait...")
        self._start_progress(fname)

        self.btn_upload.setEnabled(False)
        self.btn_start.setEnabled(False)
        self.btn_stop_file.setEnabled(True)

        self.file_worker = FileProcessorWorker(file_path)
        self.file_worker.progress_update.connect(self._update_progress)
        self.file_worker.analysis_complete.connect(self.finalize_file_analysis)
        self.file_worker.error_triggered.connect(self.handle_file_error)
        self.file_worker.start()

    def stop_file_analysis(self):
        if self.file_worker and self.file_worker.isRunning():
            self.file_worker.stop()

    def finalize_file_analysis(self, found_threats, malicious_packets):
        self._stop_progress()

        if self.file_worker and not self.file_worker.running:
            self.status_bar.showMessage("Scan aborted by user.")
            self._reset_file_buttons()
            return

        if found_threats:
            self.status_bar.showMessage(
                f"Scan complete — {len(found_threats)} C2 flow(s) detected.")
            for threat in found_threats:
                self.display_threat_alert(threat)
            self.display_c2_packet_details(found_threats, malicious_packets)

            self.packet_table.setRowCount(0)
            for pkt in malicious_packets:
                self.add_packet_row(pkt, highlight=True)
        else:
            self.status_bar.showMessage("Scan complete — no C2 activity detected.")
            self.alert_console.append(
                "[+] Traffic matches standard baseline. No C2 indicators found.\n")

        self._reset_file_buttons()

    def handle_file_error(self, error_message):
        self._stop_progress()
        self.status_bar.showMessage("Scan failed — see console.")
        self.alert_console.append(f"[-] Error: {error_message}\n")
        self._reset_file_buttons()

    def _reset_file_buttons(self):
        self.btn_upload.setEnabled(True)
        self.btn_start.setEnabled(True)
        self.btn_stop_file.setEnabled(False)
        self.console_title_label.setText(
            "<b>📡 Isolated C2 Streams View (Targeted Triage Mode):</b>")

    def clear_ui_displays(self):
        self.packet_table.setRowCount(0)
        self.alert_console.clear()
        self.total_packets_displayed = 0
        self.spinner_label.setStyleSheet("color: #00e5ff; font-size: 11px; font-family: monospace;")
        self.console_title_label.setText(
            "<b>📡 Isolated C2 Streams View (Targeted Triage Mode):</b>")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = SafeScanApp()
    window.show()
    sys.exit(app.exec())
