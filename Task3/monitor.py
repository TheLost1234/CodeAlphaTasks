import json
import time
from datetime import datetime
import matplotlib.pyplot as plt
from collections import defaultdict

class IDSMonitor:
    def __init__(self):
        self.alert_counts = defaultdict(int)
        self.time_series = []
        self.alert_series = []

    def parse_eve_log(self, file_path="/var/log/suricata/eve.json"):
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line)
                        if 'alert' in event:
                            self.process_alert(event)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"Error reading log file: {e}")

    def process_alert(self, event):
        timestamp = event.get('timestamp', '')
        alert = event.get('alert', {})
        signature = alert.get('signature', 'Unknown')
        
        self.alert_counts[signature] += 1
        self.time_series.append(datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%f%z'))
        self.alert_series.append(self.alert_counts[signature])

    def visualize_alerts(self):
        plt.figure(figsize=(12, 6))
        for signature in self.alert_counts:
            mask = [s == signature for s in self.alert_series]
            plt.plot(
                [t for t, m in zip(self.time_series, mask) if m],
                [c for c, m in zip(self.alert_series, mask) if m],
                label=signature
            )
        
        plt.title('IDS Alerts Over Time')
        plt.xlabel('Time')
        plt.ylabel('Number of Alerts')
        plt.legend()
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig('ids_alerts.png')

def main():
    monitor = IDSMonitor()
    
    while True:
        monitor.parse_eve_log()
        monitor.visualize_alerts()
        time.sleep(60)  # Update every minute

if __name__ == "__main__":
    main() 