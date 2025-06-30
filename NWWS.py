#!/usr/bin/env python3
"""
NWWS Hazards Monitor - Command Line Version
Enhanced for Windows CMD executable building
"""

import socket
import ssl
import base64
import xml.etree.ElementTree as ET
import json
import time
from datetime import datetime
import re
import os
import getpass
import sys
import subprocess
import platform
from pathlib import Path

# Try to import cryptography, handle if not installed
try:
    from cryptography.fernet import Fernet
    import hashlib
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

class Colors:
    """ANSI color codes for better CMD output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'
    
    @staticmethod
    def enable_windows_colors():
        """Enable ANSI colors in Windows CMD"""
        if platform.system() == "Windows":
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            except:
                pass

def print_banner():
    """Print application banner"""
    Colors.enable_windows_colors()
    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("╔══════════════════════════════════════════╗")
    print("║        NWWS HAZARDS MONITOR v2.0         ║")
    print("║      National Weather Service Monitor    ║")
    print("╚══════════════════════════════════════════╝")
    print(f"{Colors.END}")

def print_status(message, status="INFO"):
    """Print colored status messages"""
    colors = {
        "INFO": Colors.BLUE,
        "SUCCESS": Colors.GREEN,
        "WARNING": Colors.YELLOW,
        "ERROR": Colors.RED,
        "HIGHLIGHT": Colors.MAGENTA
    }
    color = colors.get(status, Colors.WHITE)
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"{color}[{timestamp}] {message}{Colors.END}")

def check_dependencies():
    """Check and install required dependencies"""
    global Fernet, hashlib, CRYPTO_AVAILABLE  # Fixed: moved to top
    
    print_status("Checking dependencies...", "INFO")
    
    missing_deps = []
    
    # Check for cryptography
    if not CRYPTO_AVAILABLE:
        missing_deps.append("cryptography")
    
    if missing_deps:
        print_status(f"Missing dependencies: {', '.join(missing_deps)}", "WARNING")
        install = input(f"{Colors.YELLOW}Install missing dependencies? (y/n): {Colors.END}").strip().lower()
        
        if install in ['y', 'yes']:
            for dep in missing_deps:
                print_status(f"Installing {dep}...", "INFO")
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", dep])
                    print_status(f"Successfully installed {dep}", "SUCCESS")
                except subprocess.CalledProcessError:
                    print_status(f"Failed to install {dep}", "ERROR")
                    return False
            
            # Re-import after installation
            try:
                from cryptography.fernet import Fernet
                import hashlib
                CRYPTO_AVAILABLE = True
            except ImportError:
                print_status("Failed to import cryptography after installation", "ERROR")
                return False
        else:
            print_status("Cannot continue without required dependencies", "ERROR")
            return False
    
    print_status("All dependencies satisfied", "SUCCESS")
    return True

class CredentialManager:
    """Enhanced credential management with better error handling"""
    
    def __init__(self, config_file="nwws_config.json"):
        self.config_file = Path(config_file)
        self.app_dir = Path.cwd()
    
    def _generate_key(self, password):
        """Generate encryption key from master password"""
        if not CRYPTO_AVAILABLE:
            raise Exception("Cryptography library not available")
        return base64.urlsafe_b64encode(
            hashlib.pbkdf2_hmac('sha256', password.encode(), b'nwws_salt_2024', 100000)[:32]
        )
    
    def save_credentials(self, username, password, server="nwws-oi.weather.gov", port=5223):
        """Save credentials with enhanced security"""
        if not CRYPTO_AVAILABLE:
            print_status("Cryptography not available - credentials will not be saved", "WARNING")
            return False
        
        print_status("Setting up secure credential storage...", "INFO")
        
        # Get master password with confirmation
        while True:
            master_password = getpass.getpass(f"{Colors.CYAN}Create master password: {Colors.END}")
            if len(master_password) < 4:
                print_status("Master password must be at least 4 characters", "ERROR")
                continue
            
            confirm_password = getpass.getpass(f"{Colors.CYAN}Confirm master password: {Colors.END}")
            if master_password == confirm_password:
                break
            print_status("Passwords don't match - try again", "ERROR")
        
        try:
            # Generate encryption key
            key = self._generate_key(master_password)
            cipher = Fernet(key)
            
            # Prepare credentials
            credentials = {
                "username": username,
                "password": password,
                "server": server,
                "port": port,
                "created": datetime.now().isoformat(),
                "app_version": "2.0"
            }
            
            # Encrypt and save
            encrypted_data = cipher.encrypt(json.dumps(credentials).encode())
            config = {
                "encrypted_credentials": base64.b64encode(encrypted_data).decode(),
                "setup_date": datetime.now().isoformat(),
                "version": "2.0"
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            print_status(f"Credentials saved to {self.config_file}", "SUCCESS")
            print_status("Remember your master password - it cannot be recovered!", "HIGHLIGHT")
            return True
            
        except Exception as e:
            print_status(f"Error saving credentials: {e}", "ERROR")
            return False
    
    def load_credentials(self):
        """Load credentials with better error handling"""
        if not self.config_file.exists():
            return None
        
        if not CRYPTO_AVAILABLE:
            print_status("Cryptography not available - cannot load saved credentials", "ERROR")
            return None
        
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
            
            # Get master password
            master_password = getpass.getpass(f"{Colors.CYAN}Enter master password: {Colors.END}")
            
            # Decrypt
            key = self._generate_key(master_password)
            cipher = Fernet(key)
            encrypted_data = base64.b64decode(config["encrypted_credentials"])
            decrypted_data = cipher.decrypt(encrypted_data)
            credentials = json.loads(decrypted_data.decode())
            
            print_status("Credentials loaded successfully", "SUCCESS")
            return credentials
            
        except Exception as e:
            print_status(f"Failed to load credentials: {e}", "ERROR")
            print_status("This could be due to wrong password or corrupted file", "WARNING")
            return None
    
    def credentials_exist(self):
        """Check if credentials file exists"""
        return self.config_file.exists()
    
    def delete_credentials(self):
        """Delete saved credentials"""
        try:
            if self.config_file.exists():
                self.config_file.unlink()
                print_status("Credentials deleted successfully", "SUCCESS")
            else:
                print_status("No saved credentials found", "WARNING")
        except Exception as e:
            print_status(f"Error deleting credentials: {e}", "ERROR")

class NWWSHazardMonitor:
    """Enhanced NWWS monitor with better connection handling"""
    
    def __init__(self, username, password, server="nwws-oi.weather.gov", port=5223):
        self.username = username
        self.password = password
        self.server = server
        self.port = port
        self.socket = None
        self.connected = False
        
        # Enhanced hazard detection
        self.hazard_types = [
            'Tornado Warning', 'Tornado Watch', 'Severe Thunderstorm Warning',
            'Flash Flood Warning', 'Hurricane Warning', 'Hurricane Watch',
            'Blizzard Warning', 'Ice Storm Warning', 'High Wind Warning',
            'Extreme Cold Warning', 'Heat Warning', 'Flood Warning',
            'Winter Storm Warning', 'Dust Storm Warning'
        ]
    
    def test_connectivity(self):
        """Test basic network connectivity"""
        print_status(f"Testing connectivity to {self.server}:{self.port}...", "INFO")
        
        try:
            # Test basic socket connection
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(10)
            result = test_socket.connect_ex((self.server, self.port))
            test_socket.close()
            
            if result == 0:
                print_status("Network connectivity OK", "SUCCESS")
                return True
            else:
                print_status(f"Cannot reach {self.server}:{self.port}", "ERROR")
                print_status("Check firewall settings and internet connection", "WARNING")
                return False
                
        except Exception as e:
            print_status(f"Connectivity test failed: {e}", "ERROR")
            return False
    
    def connect(self):
        """Enhanced connection with better error handling"""
        if not self.test_connectivity():
            return False
        
        print_status("Establishing secure connection...", "INFO")
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False  # NWWS doesn't use standard hostname
            context.verify_mode = ssl.CERT_NONE  # NWWS uses self-signed certs
            
            # Create and connect socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)  # Longer timeout for initial connection
            self.socket = context.wrap_socket(sock)
            
            self.socket.connect((self.server, self.port))
            print_status("SSL connection established", "SUCCESS")
            
            # Initialize XMPP
            if self._initialize_xmpp():
                self.connected = True
                print_status("NWWS connection ready", "SUCCESS")
                return True
            else:
                return False
                
        except socket.timeout:
            print_status("Connection timed out - check firewall settings", "ERROR")
            return False
        except ssl.SSLError as e:
            print_status(f"SSL error: {e}", "ERROR")
            return False
        except Exception as e:
            print_status(f"Connection failed: {e}", "ERROR")
            return False
    
    def _initialize_xmpp(self):
        """Initialize XMPP stream with better error handling"""
        try:
            # Send initial stream
            stream_header = f'''<?xml version="1.0"?>
<stream:stream to="{self.server}" xmlns="jabber:client" xmlns:stream="http://etherx.jabber.org/streams" version="1.0">'''
            
            self.socket.send(stream_header.encode())
            print_status("XMPP stream initiated", "INFO")
            
            # Receive server features
            response = self._receive_data(timeout=10)
            if not response:
                print_status("No response from server", "ERROR")
                return False
            
            # Authenticate
            return self._authenticate()
            
        except Exception as e:
            print_status(f"XMPP initialization failed: {e}", "ERROR")
            return False
    
    def _receive_data(self, timeout=5):
        """Receive data with timeout"""
        try:
            self.socket.settimeout(timeout)
            data = self.socket.recv(4096).decode('utf-8', errors='ignore')
            return data
        except socket.timeout:
            return None
        except Exception as e:
            print_status(f"Receive error: {e}", "ERROR")
            return None
    
    def _authenticate(self):
        """Enhanced authentication"""
        try:
            # SASL PLAIN authentication
            auth_string = f"\0{self.username}\0{self.password}"
            auth_b64 = base64.b64encode(auth_string.encode()).decode()
            
            auth_request = f'<auth xmlns="urn:ietf:params:xml:ns:xmpp-sasl" mechanism="PLAIN">{auth_b64}</auth>'
            self.socket.send(auth_request.encode())
            
            # Check auth response
            response = self._receive_data(timeout=15)
            if response and "success" in response.lower():
                print_status("Authentication successful", "SUCCESS")
                
                # Restart stream and bind
                self._complete_connection()
                return True
            else:
                print_status("Authentication failed - check credentials", "ERROR")
                return False
                
        except Exception as e:
            print_status(f"Authentication error: {e}", "ERROR")
            return False
    
    def _complete_connection(self):
        """Complete XMPP connection setup"""
        # Restart stream
        stream_header = f'''<?xml version="1.0"?>
<stream:stream to="{self.server}" xmlns="jabber:client" xmlns:stream="http://etherx.jabber.org/streams" version="1.0">'''
        self.socket.send(stream_header.encode())
        
        # Bind resource
        bind_request = '''<iq type="set" id="bind_1">
<bind xmlns="urn:ietf:params:xml:ns:xmpp-bind">
<resource>hazard_monitor_v2</resource>
</bind>
</iq>'''
        self.socket.send(bind_request.encode())
        
        # Set presence
        self.socket.send(b'<presence/>')
        print_status("XMPP session established", "SUCCESS")
    
    def monitor_hazards(self, duration_minutes=60):
        """Enhanced hazard monitoring"""
        if not self.connect():
            print_status("Failed to connect to NWWS", "ERROR")
            return []
        
        print_status(f"Monitoring hazards for {duration_minutes} minutes", "HIGHLIGHT")
        print_status("Watching for these hazard types:", "INFO")
        for hazard in self.hazard_types[:5]:  # Show first 5
            print(f"  • {hazard}")
        print(f"  • ... and {len(self.hazard_types)-5} more types")
        
        start_time = time.time()
        hazards_found = []
        last_activity = time.time()
        
        try:
            while time.time() - start_time < (duration_minutes * 60):
                data = self._receive_data(timeout=10)
                
                if data:
                    last_activity = time.time()
                    hazard = self._parse_hazard_message(data)
                    
                    if hazard and hazard['hazard_type']:
                        self._display_hazard_alert(hazard)
                        hazards_found.append(hazard)
                        self._save_hazard(hazard)
                else:
                    # Show activity indicator
                    elapsed = int(time.time() - start_time)
                    print(f"\r{Colors.BLUE}[{elapsed//60:02d}:{elapsed%60:02d}] Monitoring... {Colors.END}", end="", flush=True)
                
                # Check for connection timeout
                if time.time() - last_activity > 60:
                    print_status("Connection seems idle, checking...", "WARNING")
                    if not self._check_connection():
                        break
                    last_activity = time.time()
                    
        except KeyboardInterrupt:
            print_status("\nMonitoring stopped by user", "WARNING")
        except Exception as e:
            print_status(f"Monitoring error: {e}", "ERROR")
        finally:
            self._cleanup()
        
        return hazards_found
    
    def _parse_hazard_message(self, message):
        """Enhanced message parsing"""
        try:
            # Look for message content
            if '<body>' in message and '</body>' in message:
                body_start = message.find('<body>') + 6
                body_end = message.find('</body>')
                content = message[body_start:body_end]
                
                hazard_info = {
                    'timestamp': datetime.now().isoformat(),
                    'raw_content': content,
                    'hazard_type': None,
                    'location': None,
                    'severity': None,
                    'expires': None
                }
                
                # Enhanced hazard detection
                content_upper = content.upper()
                for hazard in self.hazard_types:
                    if hazard.upper() in content_upper:
                        hazard_info['hazard_type'] = hazard
                        break
                
                # Enhanced location parsing
                location_patterns = [
                    r'FOR\s+([A-Z\s,]+?)(?:\s+UNTIL|\s+FROM|\.|$)',
                    r'IN\s+([A-Z\s,]+?)(?:\s+UNTIL|\s+FROM|\.|$)',
                    r'COUNTY[:\s]+([A-Z\s,]+?)(?:\s+UNTIL|\s+FROM|\.|$)'
                ]
                
                for pattern in location_patterns:
                    match = re.search(pattern, content_upper)
                    if match:
                        hazard_info['location'] = match.group(1).strip()
                        break
                
                return hazard_info if hazard_info['hazard_type'] else None
                
        except Exception as e:
            print_status(f"Parse error: {e}", "ERROR")
        
        return None
    
    def _display_hazard_alert(self, hazard):
        """Display hazard with enhanced formatting"""
        print(f"\n{Colors.RED}{Colors.BOLD}{'='*60}")
        print(f"🚨 WEATHER HAZARD DETECTED 🚨")
        print(f"{'='*60}{Colors.END}")
        print(f"{Colors.YELLOW}Type:{Colors.END} {Colors.BOLD}{hazard['hazard_type']}{Colors.END}")
        print(f"{Colors.YELLOW}Location:{Colors.END} {hazard['location'] or 'Not specified'}")
        print(f"{Colors.YELLOW}Time:{Colors.END} {hazard['timestamp']}")
        print(f"{Colors.YELLOW}Content:{Colors.END}")
        print(f"  {hazard['raw_content'][:200]}...")
        print(f"{Colors.RED}{'='*60}{Colors.END}\n")
    
    def _save_hazard(self, hazard):
        """Save hazard to JSON file"""
        filename = f"hazards_{datetime.now().strftime('%Y_%m_%d')}.json"
        try:
            # Load existing data
            hazards = []
            if Path(filename).exists():
                with open(filename, 'r') as f:
                    hazards = json.load(f)
            
            hazards.append(hazard)
            
            with open(filename, 'w') as f:
                json.dump(hazards, f, indent=2)
                
        except Exception as e:
            print_status(f"Save error: {e}", "ERROR")
    
    def _check_connection(self):
        """Check if connection is still alive"""
        try:
            self.socket.send(b' ')  # Send whitespace keepalive
            return True
        except:
            print_status("Connection lost", "ERROR")
            return False
    
    def _cleanup(self):
        """Clean up connection"""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.connected = False
        print_status("Connection closed", "INFO")

def build_executable():
    """Build script as Windows executable"""
    print_status("Building Windows executable...", "INFO")
    
    try:
        # Check if PyInstaller is available
        subprocess.check_call([sys.executable, "-c", "import PyInstaller"], 
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print_status("PyInstaller not found, installing...", "INFO")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "PyInstaller"])
        except subprocess.CalledProcessError:
            print_status("Failed to install PyInstaller", "ERROR")
            return False
    
    # Build executable
    script_path = Path(__file__).resolve()
    build_cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--console",
        "--name", "NWWS_Monitor",
        "--icon", "NONE",
        str(script_path)
    ]
    
    try:
        print_status("Building executable (this may take a few minutes)...", "INFO")
        result = subprocess.run(build_cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            exe_path = Path("dist/NWWS_Monitor.exe")
            if exe_path.exists():
                print_status(f"Executable built successfully: {exe_path.resolve()}", "SUCCESS")
                print_status(f"Size: {exe_path.stat().st_size / (1024*1024):.1f} MB", "INFO")
                return True
            else:
                print_status("Build completed but executable not found", "ERROR")
                return False
        else:
            print_status("Build failed:", "ERROR")
            print(result.stderr)
            return False
            
    except Exception as e:
        print_status(f"Build error: {e}", "ERROR")
        return False

def show_menu():
    """Display main menu"""
    print(f"\n{Colors.CYAN}┌─────────────────────────────────────┐")
    print(f"│              MAIN MENU              │")
    print(f"├─────────────────────────────────────┤")
    print(f"│ 1. Monitor Weather Hazards          │")
    print(f"│ 2. Manage Saved Credentials         │")
    print(f"│ 3. Test Network Connection          │")
    print(f"│ 4. Build Windows Executable         │")
    print(f"│ 5. View Help & Information          │")
    print(f"│ 6. Exit                             │")
    print(f"└─────────────────────────────────────┘{Colors.END}")

def show_help():
    """Display help information"""
    print(f"\n{Colors.GREEN}NWWS Hazards Monitor - Help{Colors.END}")
    print("="*40)
    print("\nThis tool monitors the NOAA Weather Wire Service for weather hazards.")
    print("\nREQUIREMENTS:")
    print("• NWWS-OI credentials from NOAA (email: NWWS.Issue@noaa.gov)")
    print("• Internet connection")
    print("• Windows Firewall configured to allow connections")
    print("\nFEATURES:")
    print("• Real-time weather hazard monitoring")
    print("• Secure credential storage")
    print("• Automatic hazard logging")
    print("• Network connectivity testing")
    print("• Windows executable building")
    print("\nTROUBLESHOOTING:")
    print("• Connection timeout: Check firewall settings")
    print("• Authentication failed: Verify NWWS credentials")
    print("• Missing dependencies: Use option to auto-install")

def main():
    """Enhanced main function with menu system"""
    print_banner()
    
    # Check dependencies first
    if not check_dependencies():
        input("\nPress Enter to exit...")
        return
    
    cred_manager = CredentialManager()
    
    while True:
        show_menu()
        choice = input(f"\n{Colors.CYAN}Select option (1-6): {Colors.END}").strip()
        
        if choice == "1":
            # Monitor hazards
            credentials = None
            
            if cred_manager.credentials_exist():
                print_status("Found saved credentials", "INFO")
                use_saved = input(f"{Colors.CYAN}Use saved credentials? (y/n): {Colors.END}").strip().lower()
                
                if use_saved in ['y', 'yes']:
                    credentials = cred_manager.load_credentials()
            
            if not credentials:
                print_status("Enter NWWS-OI credentials", "INFO")
                print("(If you don't have them, email: NWWS.Issue@noaa.gov)")
                
                username = input(f"{Colors.CYAN}Username: {Colors.END}").strip()
                if not username:
                    print_status("Username required", "ERROR")
                    continue
                
                password = getpass.getpass(f"{Colors.CYAN}Password: {Colors.END}")
                if not password:
                    print_status("Password required", "ERROR")
                    continue
                
                # Offer to save
                if CRYPTO_AVAILABLE:
                    save = input(f"{Colors.CYAN}Save credentials securely? (y/n): {Colors.END}").strip().lower()
                    if save in ['y', 'yes']:
                        cred_manager.save_credentials(username, password)
                
                credentials = {
                    "username": username,
                    "password": password,
                    "server": "nwws-oi.weather.gov",
                    "port": 5223
                }
            
            if credentials:
                try:
                    duration = int(input(f"{Colors.CYAN}Monitor duration (minutes, default 60): {Colors.END}") or "60")
                except ValueError:
                    duration = 60
                
                monitor = NWWSHazardMonitor(
                    credentials["username"],
                    credentials["password"],
                    credentials.get("server", "nwws-oi.weather.gov"),
                    credentials.get("port", 5223)
                )
                
                hazards = monitor.monitor_hazards(duration)
                
                if hazards:
                    print_status(f"Monitoring complete - {len(hazards)} hazards detected", "SUCCESS")
                else:
                    print_status("Monitoring complete - no hazards detected", "INFO")
        
        elif choice == "2":
            # Manage credentials
            print(f"\n{Colors.CYAN}Credential Management{Colors.END}")
            if cred_manager.credentials_exist():
                print("1. Load saved credentials")
                print("2. Delete saved credentials")
                print("3. Save new credentials")
                cred_choice = input("Choice (1-3): ").strip()
                
                if cred_choice == "1":
                    creds = cred_manager.load_credentials()
                    if creds:
                        print_status(f"Loaded credentials for: {creds['username']}", "SUCCESS")
                elif cred_choice == "2":
                    cred_manager.delete_credentials()
                elif cred_choice == "3":
                    username = input("New username: ").strip()
                    password = getpass.getpass("New password: ")
                    if username and password:
                        cred_manager.save_credentials(username, password)
            else:
                print_status("No saved credentials found", "INFO")
                username = input("Username: ").strip()
                password = getpass.getpass("Password: ")
                if username and password:
                    cred_manager.save_credentials(username, password)
        
        elif choice == "3":
            # Test connection
            monitor = NWWSHazardMonitor("test", "test")
            monitor.test_connectivity()
        
        elif choice == "4":
            # Build executable
            build_executable()
        
        elif choice == "5":
            # Show help
            show_help()
        
        elif choice == "6":
            # Exit
            print_status("Goodbye!", "SUCCESS")
            break
        
        else:
            print_status("Invalid choice", "ERROR")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Program interrupted by user{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}Unexpected error: {e}{Colors.END}")
        input("Press Enter to exit...")