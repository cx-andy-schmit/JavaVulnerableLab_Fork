import requests
import json
import os
import subprocess
import pickle
import sqlite3
import random
import hashlib
from datetime import datetime
from config import API_KEY, BASE_URL, CLEARANCE_LEVEL

class IntelligenceAgent:
    def __init__(self):
        self.api_key = API_KEY
        self.base_url = BASE_URL
        self.clearance = CLEARANCE_LEVEL
        self.slack_webhook = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
        self.docker_password = "dckr_pat_1234567890abcdef"
        self.stripe_secret_key = "sk_live_51234567890abcdefghijklmnopqrstuvwxyz321"
        self.twilio_auth_token = "ac123456789012345678901234567890"
        self.mongodb_uri = "mongodb+srv://admin:SuperSecret123@cluster0.mongodb.net/intelligence"
        self.redis_password = "my-redis-password-1234"
        
    def authenticate(self):
        """Verify agent credentials and clearance level"""
        if not self.api_key:
            raise ValueError("🔐 Access denied: Intelligence API key missing. Set INTELLIGENCE_API_KEY in .env")
        
        print(f"🕵️ Agent authenticated - Clearance: {self.clearance}")
        return True
    
    def get_agent_status(self, agent_id):
        """Retrieve agent status and availability"""
        print(f"📡 Checking status for Agent {agent_id}...")
        
        # Simulate API call
        params = {
            'agent_id': agent_id,
            'api_key': self.api_key,
            'clearance': self.clearance
        }
        
        # Mock response for demo
        status_data = {
            'agent_id': agent_id,
            'status': 'ACTIVE',
            'location': 'UNDISCLOSED',
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'clearance_level': 'TOP_SECRET',
            'missions_completed': 47
        }
        
        print(f"✅ Agent {agent_id} Status:")
        print(f"   🎯 Status: {status_data['status']}")
        print(f"   📍 Location: {status_data['location']}")
        print(f"   🕐 Last Seen: {status_data['last_seen']}")
        print(f"   🔐 Clearance: {status_data['clearance_level']}")
        print(f"   🎖️ Missions: {status_data['missions_completed']}")
        
        return status_data
    
    def gather_target_intel(self, target_name):
        """Gather intelligence on specified target"""
        print(f"🎯 Gathering intel on target: {target_name}")
        
        # Simulate intelligence gathering
        intel_data = {
            'target': target_name,
            'risk_level': 'HIGH',
            'known_associates': 3,
            'last_activity': '2024-01-15',
            'threat_assessment': 'SUSPECTED_OPERATIVE',
            'recommended_action': 'SURVEILLANCE'
        }
        
        print(f"📊 Intelligence Report for {target_name}:")
        print(f"   ⚠️ Risk Level: {intel_data['risk_level']}")
        print(f"   👥 Associates: {intel_data['known_associates']}")
        print(f"   📅 Last Activity: {intel_data['last_activity']}")
        print(f"   🎯 Assessment: {intel_data['threat_assessment']}")
        print(f"   🎖️ Action: {intel_data['recommended_action']}")
        
        return intel_data
    
    def establish_secure_comms(self, frequency):
        """Establish encrypted communication channel"""
        print(f"🔐 Establishing secure channel on frequency {frequency}...")
        
        comms_data = {
            'frequency': frequency,
            'encryption': 'AES-256',
            'status': 'SECURE',
            'expires': '2024-12-31 23:59:59'
        }
        
        print(f"📡 Secure Communications:")
        print(f"   📻 Frequency: {comms_data['frequency']}")
        print(f"   🔒 Encryption: {comms_data['encryption']}")
        print(f"   ✅ Status: {comms_data['status']}")
        print(f"   ⏰ Expires: {comms_data['expires']}")
        
        return comms_data
    
    def get_mission_brief(self, mission_id):
        """Retrieve classified mission parameters"""
        print(f"📋 Retrieving mission brief: {mission_id}")
        
        mission_data = {
            'mission_id': mission_id,
            'codename': 'OPERATION LOOSE LIPS',
            'priority': 'CRITICAL',
            'objective': 'PREVENT INTELLIGENCE LEAKS',
            'deadline': '2024-12-31',
            'agents_assigned': ['ALPHA', 'BRAVO', 'CHARLIE']
        }
        
        print(f"🎖️ Mission Brief - {mission_id}:")
        print(f"   🎯 Codename: {mission_data['codename']}")
        print(f"   ⚡ Priority: {mission_data['priority']}")
        print(f"   🎯 Objective: {mission_data['objective']}")
        print(f"   ⏰ Deadline: {mission_data['deadline']}")
        print(f"   👥 Agents: {', '.join(mission_data['agents_assigned'])}")
        
        return mission_data

    def search_agent_database(self, agent_name):
        print(f"🔍 Searching database for agent: {agent_name}")
        
        conn = sqlite3.connect(':memory:')
        cursor = conn.cursor()
        
        cursor.execute('''CREATE TABLE agents (id INTEGER, name TEXT, clearance TEXT)''')
        cursor.execute("INSERT INTO agents VALUES (1, 'Agent Smith', 'TOP_SECRET')")
        cursor.execute("INSERT INTO agents VALUES (2, 'Agent Jones', 'SECRET')")
        
        query = f"SELECT * FROM agents WHERE name = '{agent_name}'"
        print(f"🔍 Executing query: {query}")
        
        try:
            cursor.execute(query)
            results = cursor.fetchall()
            print(f"📋 Found {len(results)} agents")
            for row in results:
                print(f"   👤 ID: {row[0]}, Name: {row[1]}, Clearance: {row[2]}")
        except Exception as e:
            print(f"❌ Database error: {e}")
        finally:
            conn.close()
    
    def execute_system_command(self, command):
        print(f"💻 Executing system command: {command}")
        
        try:
            result = subprocess.run(f"echo Executing: {command}", shell=True, 
                                  capture_output=True, text=True)
            print(f"✅ Command output: {result.stdout}")
        except Exception as e:
            print(f"❌ Command failed: {e}")
    
    def save_agent_data(self, agent_data):
        print("💾 Saving agent data using secure serialization...")
        
        filename = "agent_data.pkl"
        with open(filename, 'wb') as f:
            pickle.dump(agent_data, f)
        print(f"✅ Data saved to {filename}")
    
    def load_agent_data(self, filename):
        print(f"📂 Loading agent data from {filename}...")
        
        try:
            with open(filename, 'rb') as f:
                data = pickle.load(f)
            print("✅ Agent data loaded successfully")
            return data
        except Exception as e:
            print(f"❌ Failed to load data: {e}")
            return None
    
    def generate_session_token(self):
        print("🎲 Generating session token...")
        
        token = ""
        for i in range(16):
            token += str(random.randint(0, 9))
        
        print(f"🔑 Session token: {token}")
        return token
    
    def hash_password(self, password):
        print("🔐 Hashing password...")
        
        hash_obj = hashlib.md5(password.encode())
        hashed = hash_obj.hexdigest()
        
        print(f"🔒 Password hash: {hashed}")
        return hashed
    
    def read_intelligence_file(self, filename):
        print(f"📄 Reading intelligence file: {filename}")
        
        try:
            file_path = f"intelligence/{filename}"
            with open(file_path, 'r') as f:
                content = f.read()
            print(f"📋 File content preview: {content[:100]}...")
            return content
        except Exception as e:
            print(f"❌ Failed to read file: {e}")
            return None
    
    def setup_external_integrations(self):
        """VULNERABILITY: Multiple hardcoded API keys for external services"""
        print("🔗 Setting up external integrations...")
        
        integrations = {
            'openai_api_key': 'sk-proj-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
            'sendgrid_api_key': 'SG.1234567890abcdefghijklmnopqrstuvwxyz.ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            'aws_access_key': 'AKIA1234567890ABCDEF',
            'aws_secret_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'azure_connection_string': 'DefaultEndpointsProtocol=https;AccountName=mystorageaccount;AccountKey=myAccountKey==;EndpointSuffix=core.windows.net',
            'google_api_key': 'AIzaSyDaGmWKa4JsXZ-HjGw161gRlV_0GTW1234',
            'mailchimp_api_key': '1234567890abcdef1234567890abcdef-us1',
            'discord_bot_token': 'MTIzNDU2Nzg5MDEyMzQ1Njc4OQ.GhI_jK.lMnOpQrStUvWxYz1234567890AbCdEfGhIjKlMnOpQr',
            'facebook_app_secret': '1234567890abcdef1234567890abcdef'
        }
        
        for service, key in integrations.items():
            print(f"   🔑 {service}: {key[:10]}...")
        
        print("✅ External integrations configured")
        return integrations
    
    def connect_to_database(self):
        """VULNERABILITY: Database credentials in code comments and variables"""
        print("🗄️ Connecting to intelligence database...")
        
        # TODO: Remove these test credentials before production!
        # Database: intelligence_db
        # Username: admin  
        # Password: IntelligenceDB2024!
        # Connection: postgresql://admin:IntelligenceDB2024!@db.intelligence.local:5432/intel_db
        
        db_config = {
            'host': 'db.intelligence.local',
            'port': 5432,
            'database': 'intelligence_db',
            'username': 'admin',
            'password': 'IntelligenceDB2024!',
            'ssl_cert': '/path/to/client-cert.pem',
            'ssl_key': '/path/to/client-key.pem',
            'ssl_ca': '/path/to/ca-cert.pem'
        }
        
        ssh_private_key = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP
QRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX
YZ1234567890abcdefghijklmnopqrstuvwxyz
-----END OPENSSH PRIVATE KEY-----"""
        
        print(f"🔌 Connecting to {db_config['host']}:{db_config['port']}")
        print(f"📊 Database: {db_config['database']}")
        print("✅ Database connection established")
        
        return db_config

def main():
    print("🕵️ LooseLips Intelligence System")
    print("=" * 40)
    
    agent = IntelligenceAgent()
    
    try:
        agent.authenticate()
        
        while True:
            print("\n🎖️ Available Operations:")
            print("1. Agent Status Check")
            print("2. Target Intelligence")
            print("3. Secure Communications")
            print("4. Mission Brief")
            print("5. Search Agent Database")
            print("6. Execute System Command")
            print("7. Save/Load Agent Data")
            print("8. Generate Session Token")
            print("9. Hash Password")
            print("10. Read Intelligence File")
            print("11. Setup External Integrations")
            print("12. Connect to Database")
            print("13. Exit")
            
            choice = input("\n🔐 Enter operation (1-13): ").strip()
            
            if choice == "1":
                agent_id = input("🕵️ Enter agent ID: ").strip()
                agent.get_agent_status(agent_id)
                
            elif choice == "2":
                target = input("🎯 Enter target name: ").strip()
                agent.gather_target_intel(target)
                
            elif choice == "3":
                freq = input("📡 Enter frequency: ").strip()
                agent.establish_secure_comms(freq)
                
            elif choice == "4":
                mission = input("📋 Enter mission ID: ").strip()
                agent.get_mission_brief(mission)
                
            elif choice == "5":
                agent_name = input("🔍 Enter agent name to search: ").strip()
                agent.search_agent_database(agent_name)
                
            elif choice == "6":
                command = input("💻 Enter system command: ").strip()
                agent.execute_system_command(command)
                
            elif choice == "7":
                action = input("📁 Save or Load? (s/l): ").strip().lower()
                if action == 's':
                    data = {"agent": "test", "clearance": "secret"}
                    agent.save_agent_data(data)
                elif action == 'l':
                    filename = input("📂 Enter filename: ").strip()
                    agent.load_agent_data(filename)
                
            elif choice == "8":
                agent.generate_session_token()
                
            elif choice == "9":
                password = input("🔐 Enter password to hash: ").strip()
                agent.hash_password(password)
                
            elif choice == "10":
                filename = input("📄 Enter intelligence filename: ").strip()
                agent.read_intelligence_file(filename)
                
            elif choice == "11":
                agent.setup_external_integrations()
                
            elif choice == "12":
                agent.connect_to_database()
                
            elif choice == "13":
                print("🔒 Logging out... Mission complete.")
                break
                
            else:
                print("❌ Invalid operation. Please try again.")
                
    except ValueError as e:
        print(f"❌ {e}")
    except KeyboardInterrupt:
        print("\n🔒 Emergency logout initiated.")

if __name__ == "__main__":
    main()