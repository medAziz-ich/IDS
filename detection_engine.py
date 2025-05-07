from sklearn.ensemble import IsolationForest
import numpy as np

class DetectionEngine:
    def __init__(self):
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.signature_rules = self.load_signature_rules()
        self.trained = False

    def load_signature_rules(self):
        return {
            'syn_flood': {
                'condition': lambda f: f['tcp_flags'] == 2 and f['packet_rate'] > 100
            },
            'port_scan': {
                'condition': lambda f: f['packet_size'] < 100 and f['packet_rate'] > 50
            }
        }

    def train_anomaly_detector(self, normal_data):
        self.anomaly_detector.fit(normal_data)
        self.trained = True

    def detect_threats(self, features):
        threats = []

        for name, rule in self.signature_rules.items():
            if rule['condition'](features):
                threats.append({
                    'type': 'signature',
                    'rule': name,
                    'confidence': 1.0
                })

        if self.trained:
            vec = np.array([[
                features['packet_size'],
                features['packet_rate'],
                features['byte_rate']
            ]])
            score = self.anomaly_detector.score_samples(vec)[0]
            if score < -0.5:
                threats.append({
                    'type': 'anomaly',
                    'score': score,
                    'confidence': min(1.0, abs(score))
                })

        return threats
