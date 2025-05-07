import logging
import json
from datetime import datetime
import tkinter as tk
from tkinter import messagebox

class AlertSystem:
    def __init__(self, log_file="ids_alerts.log"):
        self.logger = logging.getLogger("IDS_Alerts")
        self.logger.setLevel(logging.INFO)

        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def generate_alert(self, threat, packet_info):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat['type'],
            'source_ip': packet_info.get('source_ip'),
            'destination_ip': packet_info.get('destination_ip'),
            'confidence': threat.get('confidence', 0.0),
            'details': threat
        }

        self.logger.warning(json.dumps(alert))

        if threat['confidence'] > 0.8:
            self.logger.critical(
                f"High confidence threat detected: {json.dumps(alert)}"
            )

            # Show alert message box
            try:
                root = tk.Tk()
                root.withdraw()  # Hide main window
                messagebox.showwarning(
                    "Intrusion Detected!",
                    f"Threat Type: {alert['threat_type']}\n"
                    f"Source IP: {alert['source_ip']}\n"
                    f"Destination IP: {alert['destination_ip']}\n"
                    f"Confidence: {alert['confidence']:.2f}"
                )
                root.destroy()
            except Exception as e:
                self.logger.error(f"Error displaying alert: {e}")

