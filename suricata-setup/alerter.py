#!/usr/bin/env python3
"""
Enhanced Suricata Alerter with OpenAI Classification for Orange Tunisie
Integrates AI-powered incident classification with your existing system
"""
import json
import time
import requests
import os
import sys
import datetime
import openai
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class OpenAIClassifier:
    """OpenAI-powered incident classifier for cybersecurity alerts"""
    
    def __init__(self, api_key: str):
        self.client = openai.OpenAI(api_key=api_key)
        self.model = "gpt-3.5-turbo"  # Cost-effective for classification
        
    def classify_incident(self, alert_data: dict, attack_type: str) -> dict:
        """
        Classify incident severity and generate recommendations using OpenAI
        """
        try:
            prompt = self._build_classification_prompt(alert_data, attack_type)
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": """Tu es un expert en cybersécurité pour Orange Tunisie.
                        Analyse les incidents et fournis une classification JSON avec :
                        - severity: 1-4 (1=Low, 2=Medium, 3=High, 4=Critical)
                        - confidence: 0.0-1.0
                        - reasoning: explication courte en français
                        - immediate_actions: liste d'actions immédiates
                        - business_impact: impact métier potentiel
                        - threat_level: "Low"|"Medium"|"High"|"Critical"
                        
                        Réponds UNIQUEMENT en JSON valide sans markdown."""
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.1,
                max_tokens=400
            )
            
            ai_response = json.loads(response.choices[0].message.content)
            return self._validate_response(ai_response, attack_type)
            
        except Exception as e:
            print(f"⚠️  OpenAI Classification Error: {e}")
            return self._fallback_classification(attack_type)
    
    def _build_classification_prompt(self, alert_data: dict, attack_type: str) -> str:
        """Build contextualized prompt for Orange Tunisie"""
        src_ip = alert_data.get('src_ip', 'unknown')
        dest_ip = alert_data.get('dest_ip', 'unknown')
        dest_port = alert_data.get('dest_port', 'unknown')
        signature = alert_data.get('alert', {}).get('signature', 'unknown')
        
        return f"""
Analyse cet incident de cybersécurité détecté par Suricata pour Orange Tunisie :

TYPE DÉTECTÉ: {attack_type}
SIGNATURE: {signature}
IP SOURCE: {src_ip}
IP DESTINATION: {dest_ip} 
PORT CIBLE: {dest_port}
PROTOCOLE: {alert_data.get('proto', 'unknown')}
TIMESTAMP: {alert_data.get('timestamp', 'unknown')}

CONTEXTE ORANGE TUNISIE:
- Infrastructure critique télécoms
- Services mobiles et internet
- Millions de clients
- Conformité ANSI requise

TYPES D'ATTAQUES DÉTECTÉES:
- ddos: Déni de service distribué
- c2_malware: Communication C&C/Malware  
- dns_attack: Attaques DNS (tunneling/exfiltration)
- lateral_movement: Mouvement latéral/escalade
- data_exfiltration: Exfiltration de données
- cryptomining: Mining de cryptomonnaies
- web_attack: Attaques d'applications web
- reconnaissance: Reconnaissance réseau

Fournis ta classification en JSON strict:
{{
    "severity": 1-4,
    "confidence": 0.0-1.0,
    "reasoning": "explication claire en français",
    "immediate_actions": ["action1", "action2"],
    "business_impact": "impact métier",
    "threat_level": "Low|Medium|High|Critical"
}}
        """
    
    def _validate_response(self, ai_response: dict, attack_type: str) -> dict:
        """Validate and enrich OpenAI response"""
        required_fields = ['severity', 'confidence', 'reasoning', 'threat_level']
        
        # Validate required fields
        for field in required_fields:
            if field not in ai_response:
                return self._fallback_classification(attack_type)
        
        # Validate severity range
        if not isinstance(ai_response['severity'], int) or not 1 <= ai_response['severity'] <= 4:
            ai_response['severity'] = self._get_default_severity(attack_type)
        
        # Validate confidence
        if not isinstance(ai_response['confidence'], (int, float)) or not 0 <= ai_response['confidence'] <= 1:
            ai_response['confidence'] = 0.8
        
        # Enrich with metadata
        ai_response.update({
            'classification_timestamp': datetime.datetime.now().isoformat(),
            'classifier': 'OpenAI-GPT3.5',
            'original_attack_type': attack_type
        })
        
        return ai_response
    
    def _fallback_classification(self, attack_type: str) -> dict:
        """Fallback classification based on your existing logic"""
        severity_mapping = {
            'ddos': 4,              # Critical - service impact
            'c2_malware': 4,        # Critical - compromise
            'lateral_movement': 4,   # Critical - spread
            'data_exfiltration': 3, # High - data theft
            'dns_attack': 3,        # High - stealth attack
            'cryptomining': 3,      # High - resource theft
            'web_attack': 2,        # Medium - app attack
            'reconnaissance': 2,    # Medium - scanning
        }
        
        severity = severity_mapping.get(attack_type, 2)
        threat_levels = ['', 'Low', 'Medium', 'High', 'Critical']
        
        return {
            'severity': severity,
            'confidence': 0.75,
            'reasoning': f'Classification automatique pour {attack_type}',
            'threat_level': threat_levels[severity],
            'immediate_actions': ['Bloquer IP source', 'Analyser trafic'],
            'business_impact': 'Impact à évaluer',
            'classifier': 'Fallback-v1.0',
            'original_attack_type': attack_type
        }
    
    def _get_default_severity(self, attack_type: str) -> int:
        """Get default severity for attack type"""
        return {
            'ddos': 4, 'c2_malware': 4, 'lateral_movement': 4,
            'data_exfiltration': 3, 'dns_attack': 3, 'cryptomining': 3,
            'web_attack': 2, 'reconnaissance': 2
        }.get(attack_type, 2)


class EnhancedSuricataAlertHandler(FileSystemEventHandler):
    """Enhanced alert handler with OpenAI classification"""
    
    def __init__(self):
        # Existing initialization
        self.thehive_url = os.getenv('THEHIVE_URL')
        self.api_key = os.getenv('THEHIVE_API_KEY')
        self.headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        
        # OpenAI integration
        openai_key = os.getenv('OPENAI_API_KEY')
        self.ai_classifier = OpenAIClassifier(openai_key) if openai_key else None
        
        # Existing session management
        self.last_position = 0
        self.processed_alerts = set()
        self.initialized = False
        self.session_window = int(os.getenv('SESSION_WINDOW_SECONDS', '300'))
        self.testing_mode = os.getenv('TESTING_MODE', 'false').lower() == 'true'
        
        if self.testing_mode:
            self.session_window = int(os.getenv('TEST_SESSION_WINDOW', '30'))
        
        # Enhanced logging
        ai_status = "✅ ENABLED" if self.ai_classifier else "❌ DISABLED (no API key)"
        print(f"🤖 AI Classification: {ai_status}")
        print(f"🚀 Enhanced Threat Monitor starting...")
        print(f"🔗 TheHive URL: {self.thehive_url}")
        print(f"🔑 API Key: {self.api_key[:10]}..." if self.api_key else "❌ No API key found")
        print(f"📋 Session window: {self.session_window} seconds")
        
        self.initialize_position()
    
    def initialize_position(self):
        """Initialize monitoring position - keep existing logic"""
        print("🔄 Waiting for Suricata to start and create eve.json...")
        
        max_wait = 60
        wait_count = 0
        while wait_count < max_wait:
            try:
                with open('/var/log/suricata/eve.json', 'r') as f:
                    f.seek(0, 2)
                    self.last_position = f.tell()
                    self.initialized = True
                    print(f"✅ Monitoring initialized at file position: {self.last_position}")
                    print("🎯 Will ONLY alert on NEW attack sessions")
                    print("🤖 AI-powered classification ready!")
                    return
            except FileNotFoundError:
                if wait_count % 10 == 0:
                    print(f"⏳ Waiting for Suricata to create eve.json... ({wait_count}/{max_wait})")
                time.sleep(1)
                wait_count += 1
        
        print("⚠️  Eve.json not created within timeout, will monitor when available")
        self.last_position = 0
        self.initialized = True
    
    def on_modified(self, event):
        """File modification handler - keep existing logic"""
        if event.src_path.endswith('eve.json') and self.initialized:
            if self.testing_mode:
                print(f"📝 File modified: {event.src_path}")
            self.process_new_alerts()
    
    def process_new_alerts(self):
        """Process new alerts - keep existing logic"""  
        try:
            with open('/var/log/suricata/eve.json', 'r') as f:
                f.seek(self.last_position)
                new_lines = f.readlines()
                
                if new_lines:
                    if self.testing_mode:
                        print(f"📊 Found {len(new_lines)} new log entries")
                    
                    attack_sessions = 0
                    for line in new_lines:
                        if line.strip():
                            try:
                                alert = json.loads(line)
                                if self.handle_alert(alert):
                                    attack_sessions += 1
                            except json.JSONDecodeError:
                                continue
                    
                    if attack_sessions > 0:
                        print(f"📊 Processed {len(new_lines)} entries → {attack_sessions} NEW attack sessions")
                    elif self.testing_mode and len(new_lines) > 0:
                        print(f"📊 Processed {len(new_lines)} entries → 0 new attack sessions")
                
                self.last_position = f.tell()
                
        except FileNotFoundError:
            if self.testing_mode:
                print("⏳ Eve.json file not available yet...")
        except Exception as e:
            print(f"❌ Error processing alerts: {e}")
    
    def handle_alert(self, alert):
        """FIXED: Enhanced alert handling with proper session deduplication"""
        if alert.get('event_type') == 'alert':
            signature = alert.get('alert', {}).get('signature', '')
            src_ip = alert.get('src_ip', 'unknown')
            timestamp = alert.get('timestamp', '')
            
            if self.testing_mode:
                print(f"🔍 Alert: {signature} from {src_ip}")
            
            # Use existing attack classification
            attack_type = self._classify_attack(signature)
            
            if self.testing_mode:
                print(f"   {'✅' if attack_type else '❌'} Attack classification: {attack_type or 'None'}")
            
            if attack_type:
                # FIXED SESSION MANAGEMENT
                try:
                    # Handle timestamp parsing more robustly
                    if timestamp.endswith('Z'):
                        timestamp_clean = timestamp[:-1] + '+00:00'
                    elif '+' not in timestamp and 'T' in timestamp:
                        timestamp_clean = timestamp + '+00:00'
                    else:
                        timestamp_clean = timestamp
                    
                    alert_time = datetime.datetime.fromisoformat(timestamp_clean)
                    session_time = int(alert_time.timestamp() // self.session_window) * self.session_window
                except Exception as e:
                    if self.testing_mode:
                        print(f"   ⚠️  Timestamp parsing error: {e}, using current time")
                    # Fallback to current time
                    current_time = time.time()
                    session_time = int(current_time // self.session_window) * self.session_window
                
                # Create session ID
                session_id = f"{attack_type}_{src_ip}_{session_time}"
                
                if self.testing_mode:
                    print(f"   🔍 Debug Session Info:")
                    print(f"      Attack Type: {attack_type}")
                    print(f"      Source IP: {src_ip}")
                    print(f"      Session Time: {session_time}")
                    print(f"      Session ID: {session_id}")
                    print(f"      Already Processed: {session_id in self.processed_alerts}")
                
                # FIXED: Check if session already processed BEFORE doing anything else
                if session_id not in self.processed_alerts:
                    # Add to processed alerts IMMEDIATELY to prevent duplicates
                    self.processed_alerts.add(session_id)
                    
                    print(f"🚨 NEW {attack_type.upper()} ATTACK SESSION!")
                    print(f"   📋 Signature: {signature}")
                    print(f"   🌐 Source IP: {src_ip}")
                    print(f"   ⏰ Session started: {timestamp}")
                    print(f"   🆔 Session ID: {session_id}")
                    
                    # AI Classification
                    if self.ai_classifier:
                        print(f"🤖 Analyzing with OpenAI...")
                        ai_result = self.ai_classifier.classify_incident(alert, attack_type)
                        print(f"   🎯 AI Severity: {ai_result['threat_level']} ({ai_result['severity']}/4)")
                        print(f"   🎯 AI Confidence: {ai_result['confidence']*100:.1f}%")
                    else:
                        ai_result = None
                        print(f"   ⚠️  AI disabled - using fallback classification")
                    
                    # Send to TheHive
                    self.send_to_thehive_enhanced(alert, session_id, attack_type, ai_result)
                    
                    # Cleanup old sessions (keep memory usage reasonable)
                    if len(self.processed_alerts) > 100:
                        # Remove oldest 50 sessions
                        old_sessions = list(self.processed_alerts)[:50]
                        for old_session in old_sessions:
                            self.processed_alerts.discard(old_session)
                        
                        if self.testing_mode:
                            print(f"   🧹 Cleaned up {len(old_sessions)} old sessions")
                    
                    return True
                else:
                    # Session already processed - suppress
                    if self.testing_mode:
                        print(f"   🔇 Session suppressed: {session_id}")
                        print(f"      Reason: Already processed within {self.session_window}s window")
                    else:
                        print(f"🔇 Suppressing duplicate {attack_type} session from {src_ip}")
                    
                    return False
        
        return False
    
    def _classify_attack(self, signature):
        """Keep your existing attack classification logic"""
        signature_lower = signature.lower()
        
        # Your existing classification patterns
        c2_patterns = [
            'c2', 'command and control', 'command & control', 'beaconing',
            'suspicious c2 check-in', 'malware communication', 'bot communication',
            'trojan communication', 'rat communication', 'backdoor communication'
        ]
        
        dns_patterns = [
            'dns tunneling', 'dns exfiltration', 'suspicious dns', 'dns amplification',
            'malicious dns', 'dns over https abuse', 'dns over tls abuse'
        ]
        
        lateral_patterns = [
            'lateral movement', 'smb enumeration', 'ssh brute force', 'rdp brute force',
            'privilege escalation', 'credential dumping', 'pass the hash',
            'kerberoasting', 'golden ticket', 'silver ticket'
        ]
        
        exfil_patterns = [
            'data exfiltration', 'suspicious upload', 'data theft', 'file theft',
            'sensitive data', 'credential theft', 'information disclosure'
        ]
        
        crypto_patterns = [
            'cryptocurrency', 'mining pool', 'cryptominer', 'bitcoin mining',
            'monero mining', 'ethereum mining', 'stratum', 'mining software'
        ]
        
        webapp_patterns = [
            'sql injection', 'xss', 'cross-site scripting', 'csrf', 'file inclusion',
            'directory traversal', 'command injection', 'web shell', 'file upload'
        ]
        
        recon_patterns = [
            'port scan', 'network scan', 'reconnaissance', 'enumeration',
            'service discovery', 'vulnerability scan', 'fingerprinting'
        ]
        
        ddos_patterns = [
            'ddos', 'dos attack', 'denial of service', 'syn flood', 'udp flood',
            'icmp flood', 'tcp flood', 'http flood', 'slowloris', 'amplification attack',
            'reflection attack', 'volumetric attack', 'protocol attack',
            'application layer attack', 'botnet attack', 'excessive connections',
            'connection flood', 'request flood', 'bandwidth consumption',
            'resource exhaustion', 'high connection rate', 'multiple connections'
        ]
        
        attack_categories = [
            ('c2_malware', c2_patterns),
            ('dns_attack', dns_patterns),
            ('lateral_movement', lateral_patterns),
            ('data_exfiltration', exfil_patterns),
            ('cryptomining', crypto_patterns),
            ('web_attack', webapp_patterns),
            ('reconnaissance', recon_patterns),
            ('ddos', ddos_patterns)
        ]
        
        for attack_type, patterns in attack_categories:
            for pattern in patterns:
                if pattern in signature_lower:
                    return attack_type
        
        # Custom signatures
        custom_signatures = {
            'possible dns tunneling - long txt query': 'dns_attack',
            'dns exfiltration attempt': 'dns_attack',
            'suspicious dns query - long domain': 'dns_attack',
            'suspicious https upload': 'data_exfiltration',
            'suspicious http upload': 'data_exfiltration',
            'mining pool connection': 'cryptomining',
            'smb enumeration attempt': 'lateral_movement',
            'ssh brute force attempt': 'lateral_movement',
            'suspicious c2 authorization header': 'c2_malware',
            'suspicious c2 check-in': 'c2_malware',
            'c2 beacon request': 'c2_malware',
            'sql injection attempt': 'web_attack',
            'sql injection drop table': 'web_attack',
            'sql injection union': 'web_attack',
            'xss attack attempt': 'web_attack',  
            'port scan detection': 'reconnaissance',
            'service enumeration': 'reconnaissance'
        }
        
        for custom_sig, attack_type in custom_signatures.items():
            if custom_sig in signature_lower:
                return attack_type
        
        return None
    
    def send_to_thehive_enhanced(self, alert, session_id, attack_type, ai_result):
        """FIXED: Enhanced TheHive alert creation with correct title prefix"""
        try:
            src_ip = alert.get('src_ip', 'unknown')
            dest_ip = alert.get('dest_ip', 'unknown')
            signature = alert.get('alert', {}).get('signature', 'Advanced Attack Alert')
            timestamp = alert.get('timestamp', '')
            dest_port = alert.get('dest_port', 'unknown')
            protocol = alert.get('proto', 'unknown')
            
            unique_ref = f"{attack_type}_session_{abs(hash(session_id)) % 100000}_{int(time.time())}"
            
            # Use AI result or fallback
            if ai_result:
                severity = ai_result['severity']
                threat_level = ai_result['threat_level']
                ai_reasoning = ai_result['reasoning']
                ai_confidence = ai_result['confidence']
                ai_actions = ai_result.get('immediate_actions', [])
                business_impact = ai_result.get('business_impact', 'À évaluer')
            else:
                # Fallback to existing logic
                severity_map = {'ddos': 4, 'c2_malware': 4, 'lateral_movement': 4, 'data_exfiltration': 3, 
                               'dns_attack': 3, 'cryptomining': 3, 'web_attack': 2, 'reconnaissance': 2}
                severity = severity_map.get(attack_type, 2)
                threat_levels = ['', 'Low', 'Medium', 'High', 'Critical']
                threat_level = threat_levels[severity]
                ai_reasoning = f"Classification automatique pour {attack_type}"
                ai_confidence = 0.75
                ai_actions = ['Bloquer IP source', 'Analyser trafic']
                business_impact = 'Impact à évaluer'
            
            # Your existing emoji and descriptions
            attack_emojis = {
                'ddos': '🚨', 'c2_malware': '🦠', 'dns_attack': '🔍',
                'lateral_movement': '🔄', 'data_exfiltration': '📤', 'cryptomining': '💰',
                'web_attack': '🌐', 'reconnaissance': '🔭'
            }
            
            attack_descriptions = {
                'ddos': 'Distributed Denial of Service Attack',
                'c2_malware': 'Command & Control / Malware Communication',
                'dns_attack': 'DNS-based Attack (Tunneling/Exfiltration)',
                'lateral_movement': 'Lateral Movement / Privilege Escalation',
                'data_exfiltration': 'Data Exfiltration Attempt',
                'cryptomining': 'Cryptocurrency Mining Activity',
                'web_attack': 'Web Application Attack',
                'reconnaissance': 'Network Reconnaissance'
            }
            
            emoji = attack_emojis.get(attack_type, '⚠️')
            attack_desc = attack_descriptions.get(attack_type, 'Advanced Security Threat')
            
            # Enhanced description with AI analysis
            ai_section = f"""
🤖 **ANALYSE IA OPENAI:**
• **Sévérité:** {threat_level} ({severity}/4)
• **Confiance:** {ai_confidence*100:.1f}%
• **Raisonnement:** {ai_reasoning}
• **Impact Métier:** {business_impact}

⚡ **ACTIONS RECOMMANDÉES IA:**
{chr(10).join(f"• {action}" for action in ai_actions)}
            """ if ai_result else f"""
⚠️  **CLASSIFICATION AUTOMATIQUE:**
• **Sévérité:** {threat_level} ({severity}/4)
• **Confiance:** {ai_confidence*100:.1f}%
• **Note:** Classification basée sur les règles (IA indisponible)
            """
            
            window_description = f"{self.session_window} seconds"
            if self.session_window >= 60:
                minutes = self.session_window // 60
                seconds = self.session_window % 60
                window_description = f"{minutes}:{seconds:02d} minutes"
        
            # FIXED: Correct classification prefix in title
            classification_prefix = "AI" if ai_result else "Auto"
            title = f'{emoji} [{classification_prefix}-{threat_level}] {attack_desc}: {signature}'
            
            thehive_alert = {
                'title': title,  # Now correctly shows [AI-High] or [Auto-Medium]
                'description': f'''
{emoji} **NOUVELLE SESSION {attack_desc.upper()} DÉTECTÉE**

**Détails de l'Attaque:**
• **Type:** {attack_desc}
• **Signature:** {signature}
• **IP Source:** {src_ip}
• **IP Destination:** {dest_ip}
• **Port Cible:** {dest_port}
• **Protocole:** {protocol}
• **Session Démarrée:** {timestamp}
• **Système:** Suricata + {"OpenAI GPT-3.5" if ai_result else "Classification automatique"}

{ai_section}

**Contexte Orange Tunisie:**
Infrastructure critique télécoms - Évaluation immédiate requise

**Actions Immédiates:**
1. **Investiguer l'IP source:** {src_ip}
2. **Vérifier le service cible** sur {dest_ip}:{dest_port}
3. **Évaluer l'impact** sur les systèmes affectés
4. **Considérer le blocage IP** si confirmé malveillant
5. **Surveiller l'escalade** ou la persistance
6. **Chercher des IOC liés** dans l'environnement

**Intelligence des Menaces:**
• **Vecteur d'Attaque:** {attack_type.replace('_', ' ').title()}
• **Niveau de Risque:** {threat_level}
• **Persistance:** Surveiller les activités récurrentes

**Note:** Alertes similaires de cette IP supprimées pendant {window_description}.
                ''',
                'type': f'{attack_type}_attack_session',
                'source': 'suricata_openai_monitor',
                'sourceRef': unique_ref,
                'severity': severity,
                'tlp': 2,
                'tags': [
                    attack_type, 
                    'attack-session', 
                    'realtime', 
                    'suricata',
                    f'ai-severity-{threat_level.lower()}',
                    f'ai-confidence-{int(ai_confidence*100)}'
                ] + (['openai-classified'] if ai_result else ['auto-classified']) + (['testing'] if self.testing_mode else []),
                'observables': [
                    {
                        'dataType': 'ip',
                        'data': src_ip,
                        'message': f'{attack_desc} source: {signature}',
                        'tags': ['malicious', f'{attack_type}-source', f'severity-{severity}']
                    }
                ]
            }
            
            # Add destination IP observable if different
            if dest_ip != 'unknown' and dest_ip != src_ip:
                thehive_alert['observables'].append({
                    'dataType': 'ip',
                    'data': dest_ip,
                    'message': f'{attack_desc} target',
                    'tags': ['victim', f'{attack_type}-target']
                })
            
            print(f"📤 Sending {classification_prefix}-enhanced {attack_type} alert to TheHive...")
            if self.testing_mode:
                print(f"   🌐 URL: {self.thehive_url}/api/alert")
                print(f"   🆔 Ref: {unique_ref}")
                print(f"   🤖 Classification: {classification_prefix} Severity: {threat_level} ({severity}/4)")
            
            response = requests.post(
                f'{self.thehive_url}/api/alert',
                headers=self.headers,
                json=thehive_alert,
                timeout=10
            )
            
            if response.status_code == 201:
                print(f"✅ SUCCESS: {classification_prefix}-enhanced {attack_desc} alert sent to TheHive!")
                print(f"   🎯 Severity: {threat_level} ({classification_prefix} Confidence: {ai_confidence*100:.1f}%)")
                print(f"   🔇 Will suppress similar alerts from {src_ip} for {window_description}")
            elif response.status_code == 400:
                if self.testing_mode:
                    print(f"ℹ️  Response: {response.text}")
                print(f"ℹ️  Session already reported (duplicate prevention working)")
            else:
                print(f"❌ Failed: {response.status_code} - {response.text}")
                
        except Exception as e:
            print(f"❌ Error sending to TheHive: {e}")


def main():
    """Main function with OpenAI integration"""
    testing_mode = os.getenv('TESTING_MODE', 'false').lower() == 'true'
    
    if testing_mode:
        print("🧪 ========================================")
        print("🧪          TESTING MODE ACTIVE         ")
        print("🧪 ========================================")
    
    print("🚀 Starting AI-Enhanced Threat Monitor...")
    print("🤖 OpenAI-powered incident classification")
    print("📋 Session-based alerting: Prevents alert spam")
    print("🎯 Monitoring: DDoS, C2, Lateral Movement, Data Exfil, Mining, Web Attacks, Recon")
    
    # Check for OpenAI API key
    if not os.getenv('OPENAI_API_KEY'):
        print("⚠️  WARNING: OPENAI_API_KEY not found - AI classification disabled")
        print("   Set OPENAI_API_KEY environment variable to enable AI features")
    
    handler = EnhancedSuricataAlertHandler()
    observer = Observer()
    observer.schedule(handler, '/var/log/suricata', recursive=False)
    observer.start()
    
    check_interval = 10 if testing_mode else 60
    status_interval = 60 if testing_mode else 600
    
    try:
        while True:
            time.sleep(check_interval)
            
            if int(time.time()) % status_interval == 0:
                sessions_count = len(handler.processed_alerts)
                ai_status = "🤖 AI ENABLED" if handler.ai_classifier else "⚠️  AI DISABLED"
                if testing_mode:
                    print(f"🧪 TEST STATUS: {sessions_count} attack sessions tracked - {ai_status}")
                else:
                    print(f"💓 Monitor active - {sessions_count} attack sessions tracked - {ai_status}")
                    
            if testing_mode:
                handler.process_new_alerts()
                
    except KeyboardInterrupt:
        print("🛑 Stopping AI-enhanced threat monitor...")
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
