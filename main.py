import sys
import os
import site
import subprocess
import pandas as pd
import numpy as np

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget,
                             QVBoxLayout, QHBoxLayout, QPushButton,
                             QFileDialog, QTableView, QMessageBox, QLabel)
from PyQt5.QtCore import Qt, QAbstractTableModel
from PyQt5.QtGui import QColor

from scapy.all import conf
conf.use_pcap = True


class PandasModel(QAbstractTableModel):
    def __init__(self, data):
        super().__init__()
        self._data = data
        self.anomalies = set()

    def rowCount(self, parent=None):
        return self._data.shape[0]

    def columnCount(self, parent=None):
        return self._data.shape[1]

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid(): return None
        if role == Qt.DisplayRole:
            return str(self._data.iloc[index.row(), index.column()])
        if role == Qt.BackgroundRole:
            if index.row() in self.anomalies:
                return QColor(255, 150, 150)
        return None

    def headerData(self, col, orientation, role):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return str(self._data.columns[col])
        return None

    def set_anomalies(self, anomalies):
        self.anomalies = set(anomalies)
        self.layoutChanged.emit()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Detektor Anomalii Sieciowych")
        self.df = None

        self.setStyleSheet("""
            QMainWindow { background-color: #f5f5f5; }
            QTableView { font-size: 10pt; background-color: white; }
            QPushButton { font-size: 11pt; font-weight: bold; padding: 10px; border-radius: 6px; background-color: #e0e0e0; }
            QPushButton:enabled { background-color: #2196F3; color: white; }
        """)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        self.table_view = QTableView()
        main_layout.addWidget(self.table_view)

        btn_layout = QHBoxLayout()

        self.btn_import_csv = QPushButton("Importuj CSV")
        self.btn_import_pcap = QPushButton("Importuj PCAP")
        self.btn_analyze = QPushButton("Znajdź anomalie")
        self.btn_analyze.setEnabled(False)

        btn_layout.addWidget(self.btn_import_csv)
        btn_layout.addWidget(self.btn_import_pcap)
        btn_layout.addWidget(self.btn_analyze)

        main_layout.addLayout(btn_layout)

        self.btn_import_csv.clicked.connect(self.load_csv)
        self.btn_import_pcap.clicked.connect(self.load_pcap)
        self.btn_analyze.clicked.connect(self.run_analysis)

    def show_custom_message(self, title, text, icon_type):
        msg = QMessageBox(self)
        msg.setWindowTitle(title)
        msg.setText(text)
        msg.setIcon(icon_type)
        msg.setStyleSheet("QLabel{min-width: 500px; font-size: 16px;} QPushButton{font-size: 16px; min-width: 100px;}")
        label = msg.findChild(QLabel, "qt_msgbox_label")
        if label: label.setWordWrap(True)
        msg.exec_()

    def load_csv(self):
        path, _ = QFileDialog.getOpenFileName(self, "CSV", "", "CSV (*.csv)")
        if not path: return
        try:
            self.df = pd.read_csv(path)
            self.df.columns = self.df.columns.str.strip()

            self.table_model = PandasModel(self.df)
            self.table_view.setModel(self.table_model)
            self.btn_analyze.setEnabled(True)
        except Exception as e:
            self.show_custom_msg("Błąd", str(e), QMessageBox.Critical)

    def load_pcap(self):
        pcap, _ = QFileDialog.getOpenFileName(
            self, "PCAP", "", "PCAP (*.pcap *.pcapng)"
        )
        if not pcap:
            return

        try:
            output = pcap + "_tshark.csv"

            tshark_cmd = [
                "tshark",
                "-r", pcap,
                "-T", "fields",
                "-E", "header=y",
                "-E", "separator=,",
                "-e", "frame.time_epoch",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "tcp.srcport",
                "-e", "tcp.dstport",
                "-e", "udp.srcport",
                "-e", "udp.dstport",
                "-e", "frame.len",
                "-e", "ip.proto"
            ]

            with open(output, "w", encoding="utf-8") as f:
                result = subprocess.run(
                    tshark_cmd,
                    stdout=f,
                    stderr=subprocess.PIPE,
                    text=True
                )

            if result.stderr:
                print("TSHARK STDERR:", result.stderr)

            if not os.path.exists(output) or os.path.getsize(output) < 50:
                raise Exception("tshark nie wygenerował danych")

            self.df = pd.read_csv(output)

            self.df = self.df.fillna(0)

            self.table_model = PandasModel(self.df)
            self.table_view.setModel(self.table_model)
            self.btn_analyze.setEnabled(True)

            self.show_custom_msg("Sukces", "PCAP został wczytany przez tshark", QMessageBox.Information)

        except Exception as e:
            self.show_custom_msg("Błąd PCAP", str(e), QMessageBox.Critical)
            print(str(e))

    def run_analysis(self):
        if self.df is None: return
        try:
            from xgboost import XGBClassifier

            X = self.df.select_dtypes(include=[np.number]).fillna(0)

            model = XGBClassifier()
            model.load_model("model_xgboost.json")

            preds = model.predict(X)
            anomalies = np.where(preds == 1)[0]

            self.table_model.set_anomalies(anomalies)
            self.show_custom_message("Wynik", f"Znaleziono {len(anomalies)} anomalii! Zostały zaznaczone na czerwono", QMessageBox.Warning)

        except Exception as e:
            self.show_custom_msg("Błąd", str(e), QMessageBox.Critical)
            print(str(e))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.showMaximized()
    sys.exit(app.exec_())
