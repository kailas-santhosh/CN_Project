# CN_Project

# 🔒 P2P Secure Chat Application

A peer-to-peer encrypted chat application with text messaging, file transfer, and video call capabilities, designed for secure local network communication.

## ✨ Features

- **End-to-End Encryption**
  - RSA-2048 with OAEP padding for all communications
  - Automatic key exchange and verification
  - SHA-256 file integrity checking

- **Automatic Network Discovery**
  - UDP broadcast for peer discovery on local network
  - Public key exchange during discovery

- **Multi-mode Communication**
  - 💬 Encrypted text chat with timestamps
  - 📁 Secure file transfers with hash verification
  - 📹 Video calls with audio (WebRTC-like functionality)
  - 🔊 Low-latency voice communication

- **Security Features**
  - Public key verification before connection
  - Encrypted metadata for file transfers
  - Connection timeout handling

## 🛠 System Requirements

### Software
- Python 3.6 or higher
- Required packages:

pip install cryptography opencv-python numpy sounddevice pyaudio



Hardware:
Webcam (for video calls)
Microphone (for voice calls)
Speakers/headphones


>>Getting Started

Installation:
git clone https://github.com/kailas-santhosh/CN_Project.git
cd CN_Project
pip install -r requirements.txt



Running the Application:

python p2p_chat.py <your_username> OR python3 p2p_chat.py <your_username>


Basic Commands:
/help               - Show all commands
/list               - List available peers
/connect <username> - Connect to a peer
/msg <message>      - Send a text message
/sendfile <path>    - Send a file
/videocall          - Start video/voice call
/disconnect         - End current connection
/exit               - Quit the application



Technical Details

Network Architecture:

Uses both TCP (reliable) and UDP (real-time) protocols
TCP for text messages and file transfers
UDP for video/audio streaming
Encryption Scheme

RSA-2048 for key exchange
OAEP padding with SHA-256 hashing
Each message encrypted individually
Port Usage

Main chat port: Auto-selected (5000-6000)
Discovery port: 37020 (UDP)
Video port: Main port + 100 (UDP)
Audio port: Main port + 101 (UDP)
📝 Notes

The application works best on local networks (LAN)
Firewalls may need adjustment to allow UDP traffic
First run may be slow due to RSA key generation
🤝 Contributing

Contributions are welcome! Please open an issue or pull request for any:

Bug fixes
Security improvements
Feature enhancements


Key improvements made:
Added more detailed feature descriptions
Included hardware requirements
Added complete installation and usage instructions
Expanded technical details section
Added port usage information
Included contribution guidelines
Added license information
Improved formatting and organization
Added notes about network requirements
Included command reference directly in README

The README now provides a more comprehensive overview of the project while maintaining good readability and including all essential information for users and developers.
