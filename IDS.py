from packet_capture import PacketCapture
from traffic_analyzer import TrafficAnalyzer
from detection_engine import DetectionEngine
from alert_system import AlertSystem
from scapy.all import IP, TCP
import queue

class IntrusionDetectionSystem:
    def __init__(self, interface=""):
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem()
        self.interface = interface

    def start(self):
        print(f"Starting IDS on {self.interface}")
        self.packet_capture.start_capture(self.interface)

        while True:
            try:
                packet = self.packet_capture.packet_queue.get(timeout=1)
                features = self.traffic_analyzer.analyze_packet(packet)

                if features:
                    threats = self.detection_engine.detect_threats(features)
                    for threat in threats:
                        packet_info = {
                            'source_ip': packet[IP].src,
                            'destination_ip': packet[IP].dst,
                            'source_port': packet[TCP].sport,
                            'destination_port': packet[TCP].dport
                        }
                        self.alert_system.generate_alert(threat, packet_info)

            except queue.Empty:
                continue
            except KeyboardInterrupt:
                print("Shutting down IDS...")
                self.packet_capture.stop()
                break

'''if __name__ == "__main__":
    ids = IntrusionDetectionSystem()

    # Dummy training data
    import numpy as np
    dummy_data = np.random.normal(loc=100, scale=10, size=(100, 3))
    ids.detection_engine.train_anomaly_detector(dummy_data)

    
    ids.start()
'''
import argparse
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the Intrusion Detection System.")
    parser.add_argument(
        "-i", "--interface",
        type=str,
        required=True,
        help="The network interface to monitor (e.g., eth0, wlan0)"
    )
    args = parser.parse_args()

    ids = IntrusionDetectionSystem(interface=args.interface)
    ids.start()


