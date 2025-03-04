import json
import smtplib
from email.message import EmailMessage
import subprocess

class AlertHandler:
    def __init__(self, config_file="config.json"):
        self.load_config(config_file)
        self.alert_thresholds = {
            "SSH_BRUTE_FORCE": 5,
            "PORT_SCAN": 50,
            "SQL_INJECTION": 1
        }

    def load_config(self, config_file):
        with open(config_file) as f:
            self.config = json.load(f)

    def handle_alert(self, alert):
        alert_type = alert.get('alert', {}).get('signature', '')
        source_ip = alert.get('src_ip', '')

        if self.should_block_ip(alert_type, source_ip):
            self.block_ip(source_ip)
            self.send_notification(f"Blocked IP: {source_ip} for {alert_type}")

    def should_block_ip(self, alert_type, source_ip):
        if alert_type in self.alert_thresholds:
            # Check alert frequency for this IP
            return self.check_alert_frequency(source_ip) >= self.alert_thresholds[alert_type]
        return False

    def block_ip(self, ip):
        try:
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
            print(f"Blocked IP: {ip}")
        except Exception as e:
            print(f"Error blocking IP {ip}: {e}")

    def send_notification(self, message):
        try:
            msg = EmailMessage()
            msg.set_content(message)
            msg['Subject'] = 'IDS Alert'
            msg['From'] = self.config['email']['from']
            msg['To'] = self.config['email']['to']

            with smtplib.SMTP(self.config['email']['smtp_server']) as server:
                server.login(self.config['email']['username'], 
                           self.config['email']['password'])
                server.send_message(msg)
        except Exception as e:
            print(f"Error sending notification: {e}")

def main():
    handler = AlertHandler()
    with open("/var/log/suricata/eve.json", "r") as f:
        for line in f:
            try:
                alert = json.loads(line)
                if 'alert' in alert:
                    handler.handle_alert(alert)
            except json.JSONDecodeError:
                continue

if __name__ == "__main__":
    main() 