#!/usr/bin/env python3
"""
AI-Enhanced IPTables IP Blocker Responder for TheHive/Cortex
Integrates OpenAI decision-making for intelligent IP blocking
Based on your existing SuricataIPBlocker with AI enhancements
"""

import json
import sys
import os
import subprocess
import re
import openai
from datetime import datetime
from cortexutils.responder import Responder

class AIEnhancedSuricataIPBlocker(Responder):
    def __init__(self):
        Responder.__init__(self)
        
        # Existing configuration
        self.target_port = self.get_param('config.target_port', '8081')
        self.block_duration_hours = int(self.get_param('config.block_duration_hours', 24))
        
        # AI Configuration
        openai_key = os.getenv('OPENAI_API_KEY')
        self.ai_enabled = openai_key is not None
        if self.ai_enabled:
            self.client = openai.OpenAI(api_key=openai_key)
            self.model = "gpt-3.5-turbo"
        
        self._debug_log("AI-Enhanced Responder initialized", {
            'target_port': self.target_port,
            'block_duration_hours': self.block_duration_hours,
            'ai_enabled': self.ai_enabled,
            'user': os.getenv('USER', 'unknown'),
            'uid': os.getuid() if hasattr(os, 'getuid') else 'unknown'
        })
        
    def _debug_log(self, message, data=None):
        """Debug logging function - keep your existing implementation"""
        debug_info = {
            'timestamp': datetime.now().isoformat(),
            'message': message
        }
        if data:
            debug_info.update(data)
        
        print(f"DEBUG: {json.dumps(debug_info)}", file=sys.stderr)
        
        try:
            with open('/tmp/ai_responder_debug.log', 'a') as f:
                f.write(f"DEBUG: {json.dumps(debug_info)}\n")
        except:
            pass
    
    def _ai_should_block_ip(self, ip, alert_context):
        """
        Use OpenAI to intelligently decide if an IP should be blocked
        """
        if not self.ai_enabled:
            return True, "AI disabled - proceeding with block", 0.8
        
        try:
            prompt = f"""
Analyse cette requête de blocage IP pour Orange Tunisie:

IP À BLOQUER: {ip}
CONTEXTE ALERTE: {json.dumps(alert_context, indent=2)}

CRITÈRES DE DÉCISION:
1. Sévérité de l'attaque (Critical/High = bloquer immédiatement)
2. Réputation de l'IP (connue malveillante vs potentiel faux positif)
3. Type d'attaque (DDoS/C2 = bloquer, reconnaissance = surveiller)
4. Impact métier Orange Tunisie (service critique vs test)
5. Géolocalisation suspecte
6. Patterns d'attaque sophistiqués

RÉPONSE JSON REQUISE:
{{
    "should_block": true/false,
    "reasoning": "explication détaillée en français",
    "confidence": 0.0-1.0,
    "alternative_action": "action alternative si pas de blocage",
    "urgency": "Low|Medium|High|Critical"
}}

Réponds UNIQUEMENT en JSON valide.
            """
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": """Tu es un expert en cybersécurité pour Orange Tunisie.
                        Décide intelligemment si une IP doit être bloquée ou non.
                        Considère les faux positifs et l'impact métier.
                        Sois conservateur - mieux vaut surveiller que bloquer à tort."""
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.1,
                max_tokens=300
            )
            
            ai_decision = json.loads(response.choices[0].message.content)
            
            should_block = ai_decision.get('should_block', True)
            reasoning = ai_decision.get('reasoning', 'Décision IA non disponible')
            confidence = ai_decision.get('confidence', 0.8)
            
            self._debug_log("AI Decision", {
                'ip': ip,
                'should_block': should_block,
                'reasoning': reasoning,
                'confidence': confidence
            })
            
            return should_block, reasoning, confidence
            
        except Exception as e:
            self._debug_log("AI Decision Error", {'error': str(e)})
            # Fallback to block (conservative approach)
            return True, f"Erreur IA: {str(e)} - Blocage par défaut", 0.6
    
    def _extract_alert_context(self):
        """
        Extract context from TheHive alert for AI decision making
        """
        try:
            alert_data = self.get_param('data', {})
            
            context = {
                'title': alert_data.get('title', ''),
                'description': alert_data.get('description', ''),
                'severity': alert_data.get('severity', 2),
                'type': alert_data.get('type', 'unknown'),
                'tags': alert_data.get('tags', []),
                'source': alert_data.get('source', 'unknown'),
                'tlp': alert_data.get('tlp', 2)
            }
            
            # Extract AI analysis if present in custom fields
            custom_fields = alert_data.get('customFields', {})
            if 'ai-severity' in custom_fields:
                context['ai_severity'] = custom_fields['ai-severity'].get('integer', 2)
            if 'ai-confidence' in custom_fields:
                context['ai_confidence'] = custom_fields['ai-confidence'].get('float', 0.8)
            if 'ai-threat-level' in custom_fields:
                context['ai_threat_level'] = custom_fields['ai-threat-level'].get('string', 'Medium')
            if 'attack-type' in custom_fields:
                context['attack_type'] = custom_fields['attack-type'].get('string', 'unknown')
            
            return context
            
        except Exception as e:
            self._debug_log("Context extraction error", {'error': str(e)})
            return {'error': str(e)}
    
    def run(self):
        """Enhanced main responder execution with AI decision making"""
        try:
            self._debug_log("Starting AI-enhanced responder execution")
            
            # Check manual IP input first
            manual_ip = self.get_param('config.ip_to_block', '').strip()
            self._debug_log("Manual IP check", {'manual_ip': manual_ip})
            
            if manual_ip:
                self._block_single_ip_with_ai(manual_ip, "Manual input")
            else:
                # Auto-detect from data type
                data_type = self.get_param('dataType')
                self._debug_log("Data type detected", {'data_type': data_type})
                
                if data_type in ['thehive:case', 'thehive:alert', 'thehive:case_task']:
                    self._handle_alert_level_with_ai()
                elif data_type == 'ip':
                    observable_value = self.get_param('data')
                    self._debug_log("IP observable", {'ip': observable_value})
                    self._block_single_ip_with_ai(observable_value, "IP observable")
                else:
                    self._debug_log("Unsupported data type, trying description extraction", {'data_type': data_type})
                    self._extract_ips_from_description_with_ai()
                
        except Exception as e:
            self._debug_log("Exception in run()", {'error': str(e), 'type': type(e).__name__})
            self.error(f"AI-Enhanced responder execution failed: {str(e)}")
    
    def _block_single_ip_with_ai(self, ip, source):
        """Enhanced single IP blocking with AI decision making"""
        self._debug_log("Starting AI-enhanced _block_single_ip", {'ip': ip, 'source': source})
        
        # Validate IP format
        if not self._is_valid_ip(ip):
            self.error(f"Invalid IP address format: {ip}")
            return
        
        # Check if internal IP
        if self._is_internal_ip(ip):
            self.report({
                'status': 'skipped',
                'message': f'IP {ip} is internal/private and will not be blocked',
                'ip': ip,
                'source': source,
                'timestamp': datetime.now().isoformat()
            })
            return
        
        # Check if already blocked
        if self._is_ip_blocked(ip):
            self.report({
                'status': 'already_blocked',
                'message': f'IP {ip} is already blocked on port {self.target_port}',
                'ip': ip,
                'port': self.target_port,
                'source': source,
                'timestamp': datetime.now().isoformat()
            })
            return
        
        # NEW: AI Decision Making
        alert_context = self._extract_alert_context()
        should_block, ai_reasoning, ai_confidence = self._ai_should_block_ip(ip, alert_context)
        
        self._debug_log("AI Decision Result", {
            'ip': ip,
            'should_block': should_block,
            'ai_reasoning': ai_reasoning,
            'ai_confidence': ai_confidence
        })
        
        if should_block:
            # Proceed with blocking
            result = self._block_ip(ip)
            if result:
                self.report({
                    'status': 'blocked',
                    'message': f'✅ AI-approved block: Successfully blocked IP {ip} on port {self.target_port}',
                    'ip': ip,
                    'port': self.target_port,
                    'source': source,
                    'ai_decision': {
                        'should_block': True,
                        'reasoning': ai_reasoning,
                        'confidence': ai_confidence,
                        'ai_enabled': self.ai_enabled
                    },
                    'timestamp': datetime.now().isoformat(),
                    'duration_hours': self.block_duration_hours,
                    'command_executed': f'iptables-legacy -I INPUT -s {ip} -p tcp --dport {self.target_port} -j DROP'
                })
            else:
                self.error(f"❌ Failed to block AI-approved IP {ip}")
        else:
            # AI recommends not blocking
            self.report({
                'status': 'ai_denied',
                'message': f'🤖 AI Decision: IP {ip} NOT blocked - {ai_reasoning}',
                'ip': ip,
                'port': self.target_port,
                'source': source,
                'ai_decision': {
                    'should_block': False,
                    'reasoning': ai_reasoning,
                    'confidence': ai_confidence,
                    'ai_enabled': self.ai_enabled
                },
                'alternative_action': 'Monitoring recommended instead of blocking',
                'timestamp': datetime.now().isoformat()
            })
    
    def _handle_alert_level_with_ai(self):
        """Enhanced alert level handling with AI decisions"""
        self._debug_log("Starting AI-enhanced _handle_alert_level")
        
        alert_data = self.get_param('data', {})
        observables = alert_data.get('artifacts', [])
        self._debug_log("Observables retrieved", {'count': len(observables)})
        
        ip_observables = [obs for obs in observables if obs.get('dataType') == 'ip']
        self._debug_log("IP observables found", {'count': len(ip_observables)})
        
        if not ip_observables:
            self._debug_log("No IP observables found, trying description extraction")
            self._extract_ips_from_description_with_ai()
            return
        
        blocked_ips = []
        denied_ips = []
        failed_ips = []
        already_blocked = []
        
        alert_context = self._extract_alert_context()
        
        for observable in ip_observables:
            ip = observable.get('data')
            self._debug_log("Processing observable with AI", {'ip': ip})
            
            if self._is_valid_ip(ip) and not self._is_internal_ip(ip):
                if self._is_ip_blocked(ip):
                    already_blocked.append(ip)
                else:
                    # AI Decision for each IP
                    should_block, ai_reasoning, ai_confidence = self._ai_should_block_ip(ip, alert_context)
                    
                    if should_block:
                        result = self._block_ip(ip)
                        if result:
                            blocked_ips.append({'ip': ip, 'reasoning': ai_reasoning, 'confidence': ai_confidence})
                        else:
                            failed_ips.append(ip)
                    else:
                        denied_ips.append({'ip': ip, 'reasoning': ai_reasoning, 'confidence': ai_confidence})
        
        # Enhanced reporting with AI decisions
        self._debug_log("AI-enhanced alert processing complete", {
            'blocked': len(blocked_ips),
            'ai_denied': len(denied_ips),
            'already_blocked': len(already_blocked),
            'failed': len(failed_ips)
        })
        
        success_count = len(blocked_ips) + len(already_blocked)
        
        if success_count > 0 or denied_ips:
            report_data = {
                'status': 'ai_enhanced_complete',
                'message': f'🤖 AI-Enhanced Processing: {len(blocked_ips)} blocked, {len(denied_ips)} AI-denied, {len(already_blocked)} already blocked',
                'ai_blocked_ips': blocked_ips,
                'ai_denied_ips': denied_ips,
                'already_blocked_ips': already_blocked,
                'failed_ips': failed_ips,
                'port': self.target_port,
                'source': 'Alert observables with AI analysis',
                'ai_enabled': self.ai_enabled,
                'timestamp': datetime.now().isoformat()
            }
            
            self.report(report_data)
        else:
            self.error(f"No actionable IPs found. Failed: {failed_ips}")
    
    def _extract_ips_from_description_with_ai(self):
        """Enhanced IP extraction with AI decision making"""
        try:
            alert_data = self.get_param('data', {})
            title = alert_data.get('title', '')
            description = alert_data.get('description', '')
            
            self._debug_log("AI-enhanced IP extraction from description", {
                'title_length': len(title),
                'description_length': len(description)
            })
            
            text_to_search = f"{title} {description}"
            ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
            found_ips = re.findall(ip_pattern, text_to_search)
            
            unique_ips = []
            for ip in set(found_ips):
                if not self._is_internal_ip(ip):
                    unique_ips.append(ip)
            
            self._debug_log("IPs extracted for AI analysis", {
                'found_ips': found_ips,
                'unique_external_ips': unique_ips
            })
            
            if unique_ips:
                blocked_ips = []
                denied_ips = []
                failed_ips = []
                already_blocked = []
                
                alert_context = self._extract_alert_context()
                
                for ip in unique_ips:
                    if self._is_ip_blocked(ip):
                        already_blocked.append(ip)
                    else:
                        # AI Decision
                        should_block, ai_reasoning, ai_confidence = self._ai_should_block_ip(ip, alert_context)
                        
                        if should_block:
                            result = self._block_ip(ip)
                            if result:
                                blocked_ips.append({'ip': ip, 'reasoning': ai_reasoning, 'confidence': ai_confidence})
                            else:
                                failed_ips.append(ip)
                        else:
                            denied_ips.append({'ip': ip, 'reasoning': ai_reasoning, 'confidence': ai_confidence})
                
                # Report AI-enhanced results
                success_count = len(blocked_ips) + len(already_blocked)
                if success_count > 0 or denied_ips:
                    self.report({
                        'status': 'ai_enhanced_extraction_complete',
                        'message': f'🤖 AI-Enhanced extraction: {len(blocked_ips)} blocked, {len(denied_ips)} AI-denied, {len(already_blocked)} already blocked',
                        'ai_blocked_ips': blocked_ips,
                        'ai_denied_ips': denied_ips,
                        'already_blocked_ips': already_blocked,
                        'failed_ips': failed_ips,
                        'port': self.target_port,
                        'source': 'Alert description extraction with AI analysis',
                        'ai_enabled': self.ai_enabled,
                        'timestamp': datetime.now().isoformat()
                    })
                else:
                    self.error(f"No IPs approved for blocking by AI. Failed: {failed_ips}")
            else:
                self.error("No external IP addresses found in alert title or description")
                
        except Exception as e:
            self._debug_log("Exception in AI-enhanced IP extraction", {'error': str(e)})
            self.error(f"Failed to extract IPs from description with AI: {str(e)}")
    
    # Keep all your existing helper methods
    def _is_internal_ip(self, ip):
        """Keep your existing implementation"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            
            private_ranges = [
                ipaddress.ip_network('10.0.0.0/8'),
                ipaddress.ip_network('172.16.0.0/12'),
                # ipaddress.ip_network('192.168.0.0/16'),  # Commented as in your original
                ipaddress.ip_network('127.0.0.0/8'),
                ipaddress.ip_network('169.254.0.0/16'),
                ipaddress.ip_network('224.0.0.0/4'),
            ]
            
            for network in private_ranges:
                if ip_obj in network:
                    return True
            
            return False
            
        except ValueError:
            return True
    
    def _is_valid_ip(self, ip):
        """Keep your existing implementation"""
        try:
            import ipaddress
            ipaddress.ip_address(ip)
            return True
        except ValueError as e:
            self._debug_log("IP validation failed", {'ip': ip, 'error': str(e)})
            return False
    
    def _is_ip_blocked(self, ip):
        """Keep your existing implementation"""
        try:
            self._debug_log("Checking if IP is blocked", {'ip': ip})
            
            result = subprocess.run([
                'iptables-legacy', '-C', 'INPUT', 
                '-s', ip, 
                '-p', 'tcp', 
                '--dport', self.target_port, 
                '-j', 'DROP'
            ], capture_output=True, text=True)
            
            is_blocked = result.returncode == 0
            self._debug_log("Block check complete", {
                'ip': ip,
                'is_blocked': is_blocked,
                'returncode': result.returncode
            })
            
            return is_blocked
            
        except Exception as e:
            self._debug_log("Exception in _is_ip_blocked", {
                'ip': ip,
                'error': str(e),
                'type': type(e).__name__
            })
            return False
    
    def _block_ip(self, ip):
        """Keep your existing implementation"""
        try:
            self._debug_log("Starting _block_ip", {'ip': ip})
            
            cmd = [
                'iptables-legacy', '-I', 'INPUT', 
                '-s', ip, 
                '-p', 'tcp', 
                '--dport', self.target_port, 
                '-j', 'DROP'
            ]
            
            self._debug_log("Executing command", {'cmd': ' '.join(cmd)})
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            self._debug_log("Command executed successfully", {
                'ip': ip,
                'returncode': result.returncode
            })
            
            return True
            
        except subprocess.CalledProcessError as e:
            self._debug_log("CalledProcessError in _block_ip", {
                'ip': ip,
                'returncode': e.returncode,
                'stderr': e.stderr
            })
            self.error(f"Failed to block IP {ip}: {e.stderr}")
            return False
        except Exception as e:
            self._debug_log("Exception in _block_ip", {
                'ip': ip,
                'error': str(e),
                'type': type(e).__name__
            })
            self.error(f"Error blocking IP {ip}: {str(e)}")
            return False


if __name__ == '__main__':
    AIEnhancedSuricataIPBlocker().run()
