# Email Spoofing Detector
# Author: Ryan Feneley
# Date: August 2024

import re

class EmailSpoofingDetector:
    def __init__(self, email_headers):
        self.headers = email_headers

    def parse_headers(self):
        """Extracts relevant fields from email headers."""
        from_field = self.get_header('From')
        received_fields = self.get_header('Received')
        return from_field, received_fields

    def get_header(self, field):
        """Returns the value of a specific header field."""
        for header in self.headers:
            if header.startswith(field):
                return header.split(':', 1)[1].strip()
        return None

    def detect_spoofing(self):
        """Analyzes headers for signs of spoofing."""
        from_field, received_fields = self.parse_headers()
        
        if from_field is None or received_fields is None:
            print("Error: Missing necessary headers.")
            return

        # Extract the sender domain
        sender_domain = self.extract_domain(from_field)
        
        # Check each 'Received' field for mismatched domains
        for received in received_fields.splitlines():
            ip_address = self.extract_ip(received)
            if ip_address:
                print(f"Received from IP: {ip_address}")

            # Simple logic to check for domain mismatch
            if sender_domain not in received:
                print(f"Potential spoofing detected: {from_field} from {received}")
            else:
                print("Sender domain matches received domain.")

    def extract_domain(self, email):
        """Extracts the domain from the email address."""
        match = re.search(r'@([\w.-]+)', email)
        return match.group(1) if match else None

    def extract_ip(self, received_field):
        """Extracts IP address from the 'Received' field."""
        match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', received_field)
        return match.group(1) if match else None

if __name__ == "__main__":
    # template
    example_headers = [
        "From: spoofed.sender@example.com",
        "Received: from mail.example.com (mail.example.com. [192.0.2.1]) by mailserver.com; Tue, 21 Sep 2024 12:00:00 +0000",
        "Received: from anothermail.com (anothermail.com. [198.51.100.2]) by mailserver.com; Tue, 21 Sep 2024 12:00:01 +0000"
    ]

    detector = EmailSpoofingDetector(example_headers)
    detector.detect_spoofing()
