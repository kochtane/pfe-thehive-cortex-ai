# 🔐 Plateforme Intelligente de Gestion et de Réponse aux Incidents de Cybersécurité

**Système de détection et de réponse automatisée aux cyberattaques enrichi par l'Intelligence Artificielle**

Ce projet intègre Suricata, TheHive, Cortex et OpenAI pour créer une solution complète de détection, d'analyse et de réponse automatisée aux menaces de cybersécurité.

## 📋 Table des matières

- [Vue d'ensemble](#-vue-densemble)
- [Architecture](#️-architecture)
- [Fonctionnalités](#-fonctionnalités)
- [Structure du projet](#-structure-du-projet)
- [Prérequis](#-prérequis)
- [Installation](#-installation)
- [Configuration](#️-configuration)
- [Utilisation](#-utilisation)
- [Tests d'intrusion](#-tests-dintrusion)
- [Responder SuricataIPBlocker](#️-responder-suricataipblocker)
- [Dépannage](#-dépannage)

## 🎯 Vue d'ensemble

Cette solution fournit une plateforme de cybersécurité intelligente qui :

- **Détecte** les menaces en temps réel avec Suricata IDS/IPS
- **Analyse** et **classifie** automatiquement les incidents avec OpenAI GPT-3.5
- **Enrichit** les alertes avec des recommandations contextuelles
- **Répond** automatiquement aux menaces via Cortex Responders
- **Gère** les incidents de manière centralisée avec TheHive

## 🏗️ Architecture

```
Trafic Réseau (interface réseau:8081)
    ↓
Nginx (serveur web cible)
    ↓
Suricata (IDS/IPS) - Détection des attaques
    ↓
eve.json (Logs JSON)
    ↓
alerter.py (Script Python) - Classification IA + Enrichissement
    ↓
OpenAI GPT-3.5 - Analyse contextuelle et recommandations
    ↓
TheHive API - Création d'alertes enrichies
    ↓
Cortex Responders - Réponse automatisée (SuricataIPBlocker)
    ↓
iptables - Blocage IP automatique
```

## ✨ Fonctionnalités

### 🤖 Classification Intelligente par IA

- **Scoring automatique** : Attribution de sévérité 1-4 (Low/Medium/High/Critical)
- **Analyse contextuelle** : Évaluation adaptée aux infrastructures télécoms Orange Tunisie
- **Confiance mesurée** : Score de confiance 0.0-1.0 pour chaque décision
- **Recommandations** : Actions immédiates suggérées par l'IA
- **Impact métier** : Évaluation de l'impact sur les services critiques
- **Décisions de blocage intelligentes** : L'IA décide si une IP doit être bloquée ou simplement surveillée

### 🔍 Détection Multi-types

Le système détecte 8 catégories d'attaques :

- **DDoS** : Attaques par déni de service (HTTP flood, connection flood)
- **Injections SQL** : DROP, UNION, SELECT, OR/AND bypass
- **XSS** : Cross-site scripting attacks
- **Command Injection** : Injection de commandes système
- **Directory Traversal** : Tentatives d'accès aux fichiers système
- **Brute Force** : Attaques de force brute sur login/auth
- **Reconnaissance** : Scans de ports et énumération
- **Outils de sécurité** : Détection de Nikto, SQLMap, Nmap, Burp Suite

### 📊 Gestion des Sessions

- **Déduplication intelligente** : Fenêtre de session configurable (défaut: 300 secondes)
- **Prévention du spam** : Une seule alerte par session d'attaque
- **Traçabilité** : ID de session unique pour chaque incident
- **Mode test** : Fenêtre réduite (10 secondes) pour validation rapide

### 🛡️ Réponse Automatisée

- **Blocage IP intelligent** via iptables-legacy
- **Décisions basées sur l'IA** : L'IA évalue si le blocage est nécessaire
- **Filtrage des IPs internes** : Protection contre l'auto-blocage
- **Rapports détaillés** : Logs complets de chaque action
- **Mode fallback** : Fonctionnement sans IA avec règles par défaut

## 📁 Structure du projet

```
pfe-thehive-cortex-ai/
├── README.md
│
├── suricata-setup/
│   ├── alerter.py                    # Script d'alerting enrichi par IA
│   ├── docker-compose.yml            # Orchestration Suricata + Nginx + Alerter
│   ├── nginx.conf                    # Configuration serveur web cible (port 8081)
│   ├── suricata.yaml                 # Configuration Suricata IDS
│   └── rules/
│       └── suricata.rules            # Règles de détection personnalisées
│
└── the-hive-cortex/
    ├── docker-compose.yml            # Orchestration TheHive ecosystem
    └── cortex/
        ├── application.conf          # Configuration Cortex avec AI
        └── responders/
            └── SuricataIPBlocker/
                ├── SuricataIPBlocker.json       # Métadonnées du responder
                ├── suricata_ip_blocker.py       # Responder enrichi par IA
                └── requirements.txt              # Dépendances Python
```

## 📦 Prérequis

### Systèmes requis

- **Ubuntu/Debian** (testé sur Ubuntu 20.04+)
- **Docker** (version 20.10+)
- **Docker Compose** (version 1.29+)
- **TheHive** (instance existante configurée)
- **Interface réseau** configurée pour la surveillance

### Clés API requises

- **Clé API OpenAI** (GPT-3.5-turbo) : [Obtenir une clé](https://platform.openai.com/api-keys)
- **Clé API TheHive** : Générée depuis votre instance TheHive existante

### Dépendances Python

Automatiquement installées via les containers Docker :
```
openai>=1.0.0
requests
watchdog
cortexutils
ipaddress
```

## 🚀 Installation

### 1. Cloner le repository

```bash
cd /opt
sudo git clone https://github.com/kochtane/pfe-thehive-cortex-ai.git
cd pfe-thehive-cortex-ai
```

### 2. Configuration de TheHive (prérequis)

Assurez-vous d'avoir une instance TheHive fonctionnelle. Si ce n'est pas le cas, installez TheHive en suivant la [documentation officielle](https://docs.strangebee.com/thehive/).

Créer une clé API dans TheHive :

1. Se connecter à TheHive en tant qu'administrateur
2. Aller dans **Organization** → **Users**
3. Créer un utilisateur dédié (ex: `suricata-alerter`)
4. Générer une clé API pour cet utilisateur
5. Noter la clé API générée

### 3. Déploiement du stack Suricata

```bash
cd suricata-setup
```

**Éditer `docker-compose.yml`** et remplacer les valeurs suivantes :

```yaml
environment:
  - THEHIVE_URL=http://your-thehive-ip:9000
  - THEHIVE_API_KEY=your_thehive_api_key
  - OPENAI_API_KEY=your_openai_api_key
```

**Important** : Vérifiez que l'interface réseau dans `suricata.yaml` correspond à votre configuration :

```yaml
af-packet:
  - interface: ens33  # Changez selon votre interface (utiliser: ip a)
```

**Démarrer le stack** :

```bash
docker-compose up -d
```

**Vérifier les containers** :

```bash
docker ps
# Vous devriez voir : nginx-server, suricata-monitor, thehive-alerter
```

**Vérifier les logs de l'alerter** :

```bash
docker logs -f thehive-alerter
```

Vous devriez voir :
```
🚀 Starting AI-Enhanced Threat Monitor...
🤖 AI Classification: ✅ ENABLED
🔗 TheHive URL: http://your-thehive:9000
✅ Monitoring initialized at file position: ...
🤖 AI-powered classification ready!
```

### 4. Déploiement du stack Cortex

```bash
cd ../the-hive-cortex
```

**Créer le script d'initialisation** :

```bash
mkdir -p scripts
cat > scripts/cortex-init.sh << 'EOF'
#!/bin/bash
set -e

echo "🚀 Starting Cortex initialization..."

# Install Python dependencies for responders
echo "📦 Installing Python dependencies..."
pip3 install --no-cache-dir -r /opt/cortex/responders/SuricataIPBlocker/requirements.txt

echo "✅ All dependencies installed"
echo "🎯 Starting Cortex..."

# Start Cortex
exec /opt/cortex/entrypoint
EOF

chmod +x scripts/cortex-init.sh
```

**Éditer `docker-compose.yml`** et remplacer les valeurs :

```yaml
environment:
  - OPENAI_API_KEY=your_openai_api_key
  - THEHIVE_URL=http://your-thehive-ip:9000
  - THEHIVE_API_KEY=your_thehive_api_key
```

**Éditer `cortex/application.conf`** et remplacer :

```conf
play.http.secret.key="YourRandomSecretKey"  # Générez une clé aléatoire

search {
  index = cortex
  uri = "http://localhost:9200"  # URL Elasticsearch
}
```

**Démarrer le stack** :

```bash
docker-compose up -d
```

**Vérifier les containers** :

```bash
docker ps
# Vous devriez voir : elasticsearch, cortex, n8n
```

**Accéder à Cortex** :

Ouvrir `http://localhost:9001` dans votre navigateur.

### 5. Configuration du Responder dans Cortex

1. Se connecter à Cortex (`http://localhost:9001`)
2. Créer une organisation si nécessaire
3. Aller dans **Organization** → **Responders**
4. Le responder **SuricataIPBlocker** devrait apparaître automatiquement
5. Cliquer sur **Enable** pour l'activer
6. Configurer les paramètres si nécessaire

### 6. Lier Cortex à TheHive

Dans votre instance TheHive :

1. Aller dans **Admin** → **Cortex Servers**
2. Cliquer sur **Add Cortex Server**
3. Remplir les champs :
   - **Name** : Cortex-AI
   - **URL** : `http://localhost:9001` (ou IP de votre serveur Cortex)
   - **API Key** : Générer une clé API dans Cortex (Organization → Users)
4. Tester la connexion

## ⚙️ Configuration

### Variables d'environnement importantes

#### Pour l'alerter (suricata-setup/docker-compose.yml)

```yaml
environment:
  - THEHIVE_URL=http://thehive:9000              # URL de TheHive
  - THEHIVE_API_KEY=your_thehive_api_key         # Clé API TheHive
  - OPENAI_API_KEY=sk-your-openai-key            # Clé API OpenAI
  - OPENAI_MODEL=gpt-3.5-turbo                   # Modèle OpenAI
  - SESSION_WINDOW_SECONDS=300                   # Fenêtre de déduplication (secondes)
  - TESTING_MODE=false                           # Mode debug (true/false)
  - TEST_SESSION_WINDOW=10                       # Fenêtre en mode test
```

#### Pour Cortex (the-hive-cortex/docker-compose.yml)

```yaml
environment:
  - OPENAI_API_KEY=sk-your-openai-key            # Clé API OpenAI
  - THEHIVE_URL=http://thehive:9000              # URL de TheHive
  - THEHIVE_API_KEY=your_thehive_api_key         # Clé API TheHive
  - AI_DEBUG=false                               # Debug IA (true/false)
  - AI_TIMEOUT=30                                # Timeout requêtes IA
  - AI_MAX_TOKENS=500                            # Tokens max par requête
```

### Configuration Suricata

Le fichier `suricata-setup/rules/suricata.rules` contient toutes les règles de détection :

- **SQL Injection** : DROP, UNION, SELECT, OR/AND bypass
- **XSS** : Scripts, javascript protocol
- **Command Injection** : Pipes, semicolons
- **Directory Traversal** : ../
- **HTTP Floods** : Seuils configurables
- **Scanners** : Nikto, SQLMap, Nmap

**Modifier les seuils de détection** :

```bash
# Exemple : HTTP flood (actuellement 25 requêtes en 5 secondes)
alert http any any -> any 8081 (msg:"HTTP flood on port 8081"; 
  flow:to_server; 
  content:"GET"; 
  http_method; 
  threshold: type limit, track by_src, count 25, seconds 5;  # Modifier ici
  sid:1000023; 
  rev:1;)
```

### Configuration Nginx cible

Le serveur Nginx écoute sur le port **8081** (configurable dans `nginx.conf`).

Pour changer le port :

1. Éditer `suricata-setup/nginx.conf`
2. Éditer `suricata-setup/rules/suricata.rules` (remplacer tous les `8081`)
3. Redémarrer les containers

## 🎬 Utilisation

### Démarrage complet du système

```bash
# 1. Démarrer Suricata + Alerter
cd /opt/pfe-thehive-cortex-ai/suricata-setup
docker-compose up -d

# 2. Démarrer Cortex (si pas déjà fait)
cd ../the-hive-cortex
docker-compose up -d

# 3. Vérifier que tout fonctionne
docker ps
docker logs -f thehive-alerter
```

### Surveillance des logs

**Logs de l'alerter IA** :

```bash
docker logs -f thehive-alerter
```

**Logs Suricata** :

```bash
docker exec suricata-monitor tail -f /var/log/suricata/suricata.log
```

**Logs eve.json (alertes)** :

```bash
docker exec suricata-monitor tail -f /var/log/suricata/eve.json
```

**Logs Cortex** :

```bash
docker logs -f cortex
```

### Workflow complet

1. **Une attaque est lancée** contre `http://server-ip:8081`
2. **Suricata détecte** l'attaque et écrit dans `eve.json`
3. **alerter.py** lit l'événement, le classifie par type
4. **OpenAI analyse** l'incident et génère recommandations
5. **Alerte créée** dans TheHive avec enrichissement IA
6. **Analyste examine** l'alerte dans TheHive
7. **Responder lancé** sur l'IP malveillante
8. **IA décide** si blocage nécessaire
9. **iptables bloque** l'IP (si approuvé par IA)

## 🧪 Tests d'intrusion

### Depuis une machine Windows

Ouvrir PowerShell ou CMD et remplacer `SERVER_IP` par l'IP de votre serveur.

#### Test 1 : Attaque DDoS (HTTP Flood)

```powershell
# Générer 20 requêtes rapides
for ($i=1; $i -le 20; $i++) { 
    Start-Job { curl http://SERVER_IP:8081/ } 
}
```

**Résultat attendu** : Alerte `[AI-Critical] Distributed Denial of Service Attack: HTTP flood on port 8081`

#### Test 2 : Injection SQL - DROP TABLE

```powershell
curl "http://SERVER_IP:8081/?query=DROP%20TABLE%20users"
```

**Résultat attendu** : Alerte `[AI-High] Web Application Attack: SQL injection DROP attempt`

#### Test 3 : Injection SQL - OR Bypass

```powershell
curl "http://SERVER_IP:8081/?id=1' OR 1=1--"
```

**Résultat attendu** : Alerte SQL injection (OR bypass)

#### Test 4 : XSS Attack

```powershell
curl "http://SERVER_IP:8081/?search=<script>alert(1)</script>"
```

**Résultat attendu** : Alerte XSS

#### Test 5 : Scan de ports (Reconnaissance)

```powershell
for ($port=8000; $port -le 8010; $port++) { 
    Start-Job { curl -TimeoutSec 1 http://SERVER_IP:$port/ } 
}
```

**Résultat attendu** : Alerte reconnaissance réseau

### Depuis Linux/Mac

```bash
# Test DDoS
for i in {1..20}; do curl http://SERVER_IP:8081/ & done

# Test SQL Injection
curl "http://SERVER_IP:8081/?query=DROP%20TABLE%20users"

# Test XSS
curl "http://SERVER_IP:8081/?q=<script>alert(1)</script>"

# Test Port Scan
for port in {8000..8010}; do 
  curl -m 1 http://SERVER_IP:$port/ 2>/dev/null & 
done
```

### Vérification dans TheHive

1. Ouvrir TheHive (`http://thehive-ip:9000`)
2. Aller dans **Alerts**
3. Observer les alertes avec préfixes `[AI-High]`, `[AI-Critical]`, etc.
4. Examiner la description enrichie par l'IA
5. Noter les recommandations d'actions

### Lancer le Responder

1. Ouvrir une alerte dans TheHive
2. Cliquer sur l'observable **IP** malveillante
3. Cliquer sur **Run Responder**
4. Sélectionner **SuricataIPBlocker_1_0**
5. Observer le rapport d'exécution avec décision IA

## 🛡️ Responder SuricataIPBlocker

### Fonctionnalités avancées

- ✅ **Blocage IP automatique** via iptables-legacy
- 🤖 **Décision IA** : L'IA évalue si le blocage est justifié
- 🔍 **Analyse contextuelle** : Considère type d'attaque, sévérité, réputation IP
- 🛡️ **Protection anti-faux-positifs** : Filtrage IPs internes, décision conservatrice
- 📊 **Rapports détaillés** : Logs complets avec raisonnement IA
- 🔄 **Mode fallback** : Fonctionne sans IA avec règles par défaut

### Décision IA intelligente

L'IA évalue plusieurs critères avant de bloquer :

- **Sévérité de l'attaque** : Critical/High → blocage immédiat
- **Type d'attaque** : DDoS/C2 → bloquer, Reconnaissance → surveiller
- **Réputation IP** : Connue malveillante vs potentiel faux positif
- **Impact métier** : Service critique vs environnement de test
- **Géolocalisation** : Pays suspects
- **Patterns sophistiqués** : Attaques avancées vs scan basique

### Exemples de décisions IA

**Blocage approuvé** :
```json
{
  "status": "blocked",
  "message": "✅ AI-approved block: Successfully blocked IP X.X.X.X",
  "ai_decision": {
    "should_block": true,
    "reasoning": "Attaque DDoS critique détectée avec confiance élevée...",
    "confidence": 0.95
  }
}
```

**Blocage refusé** :
```json
{
  "status": "ai_denied",
  "message": "🤖 AI Decision: IP X.X.X.X NOT blocked",
  "ai_decision": {
    "should_block": false,
    "reasoning": "Probable scan de vulnérabilité légitime, surveiller...",
    "confidence": 0.82
  },
  "alternative_action": "Monitoring recommended instead of blocking"
}
```

### Vérification des blocages

```bash
# Voir toutes les règles iptables
docker exec suricata-monitor iptables-legacy -L INPUT -v -n

# Voir uniquement les IPs bloquées sur port 8081
docker exec suricata-monitor iptables-legacy -L INPUT -v -n | grep 8081
```

### Débloquer une IP manuellement

```bash
# Débloquer une IP spécifique
docker exec suricata-monitor iptables-legacy -D INPUT -s X.X.X.X -p tcp --dport 8081 -j DROP

# Supprimer tous les blocages
docker exec suricata-monitor iptables-legacy -F INPUT
```

## 🔧 Dépannage

### L'alerter ne démarre pas

**Vérifier les logs** :

```bash
docker logs thehive-alerter
```

**Erreurs communes** :

1. **"No module named 'openai'"** : Les dépendances ne sont pas installées
   ```bash
   docker-compose down
   docker-compose up -d --build
   ```

2. **"THEHIVE_API_KEY not found"** : Variable d'environnement manquante
   ```bash
   # Éditer docker-compose.yml et ajouter la clé API
   docker-compose up -d
   ```

3. **"Eve.json file not available"** : Suricata n'a pas encore créé le fichier
   ```bash
   # Attendre 1-2 minutes puis vérifier
   docker exec suricata-monitor ls -lh /var/log/suricata/
   ```

### Aucune alerte n'apparaît dans TheHive

**Vérifier la connectivité TheHive** :

```bash
# Depuis le container alerter
docker exec thehive-alerter curl -H "Authorization: Bearer YOUR_API_KEY" http://thehive-ip:9000/api/alert
```

**Activer le mode debug** :

Éditer `suricata-setup/docker-compose.yml` :

```yaml
environment:
  - TESTING_MODE=true
  - TEST_SESSION_WINDOW=10
```

Redémarrer :

```bash
docker-compose up -d
docker logs -f thehive-alerter
```

### OpenAI ne fonctionne pas

**Vérifier la clé API** :

```bash
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer YOUR_OPENAI_KEY"
```

**Vérifier les quotas** : Se connecter à [platform.openai.com](https://platform.openai.com/usage)

**Mode fallback** : Le système fonctionne sans OpenAI, mais sans analyse IA :

```
⚠️  WARNING: OPENAI_API_KEY not found - AI classification disabled
⚠️  AI disabled - using fallback classification
```

### Le responder ne bloque pas les IPs

**Vérifier les privilèges iptables** :

```bash
docker exec cortex iptables-legacy -L
```

**Erreur "Operation not permitted"** : Le container Cortex n'a pas les privilèges NET_ADMIN

Vérifier dans `the-hive-cortex/docker-compose.yml` :

```yaml
cortex:
  cap_add:
    - NET_ADMIN
    - NET_RAW
```

**Vérifier les logs du responder** :

1. Aller dans Cortex → **Jobs History**
2. Cliquer sur le job du responder
3. Examiner le rapport d'exécution

**Logs de debug** :

```bash
docker exec cortex tail -f /tmp/ai_responder_debug.log
```

### Suricata ne détecte pas les attaques

**Vérifier que Suricata surveille la bonne interface** :

```bash
# Lister les interfaces
ip a

# Vérifier la config Suricata
cat suricata-setup/suricata.yaml | grep interface
```

**Vérifier les règles chargées** :

```bash
docker exec suricata-monitor suricata -T -c /etc/suricata/suricata.yaml
```

**Vérifier les logs Suricata** :

```bash
docker exec suricata-monitor tail -f /var/log/suricata/suricata.log
```

### Les sessions ne sont pas dédupliquées

**Vérifier la fenêtre de session** :

```bash
docker exec thehive-alerter env | grep SESSION_WINDOW
```

**Nettoyer et redémarrer** :

```bash
docker-compose restart thehive-alerter
```

## 📊 Monitoring et Métriques

### Statistiques temps réel

```bash
# Nombre d'alertes générées
docker exec thehive-alerter grep "NEW.*ATTACK SESSION" /proc/1/fd/1 | wc -l

# IPs actuellement bloquées
docker exec suricata-monitor iptables-legacy -L INPUT -v -n | grep 8081 | wc -l

# Sessions traitées
docker logs thehive-alerter | grep "attack sessions tracked"
```

### Logs importants

```bash
# Logs alerter avec timestamps
docker logs -f --timestamps thehive-alerter

# Logs Suricata
docker exec suricata-monitor tail -f /var/log/suricata/suricata.log

# Logs JSON Suricata (eve.json)
docker exec suricata-monitor tail -f /var/log/suricata/eve.json | jq

# Logs Cortex
docker logs -f cortex
```

## 🔒 Sécurité et Bonnes Pratiques

### Protection des clés API

**Ne jamais committer les clés** dans Git :

```bash
# Créer .gitignore
cat > .gitignore << EOF
*.env
**/application.conf
docker-compose.override.yml
logs/
*.log
EOF
```

**Utiliser des variables d'environnement** :

```bash
# Créer un fichier .env (pas commité)
cat > .env << EOF
THEHIVE_API_KEY=your_key
OPENAI_API_KEY=your_key
EOF

# Référencer dans docker-compose.yml
env_file:
  - .env
```

### Whitelist d'IPs critiques

Éditer `the-hive-cortex/cortex/responders/SuricataIPBlocker/suricata_ip_blocker.py` :

```python
INTERNAL_NETWORKS = [
    '10.0.0.0/8',
    '172.16.0.0/12',
    '127.0.0.0/8',
]

WHITELIST_IPS = [
    '8.8.8.8',               # Google DNS
    '1.1.1.1',               # Cloudflare DNS
    'your.management.ip',    # Votre IP de gestion
]
```

### Surveillance des coûts OpenAI

- Suivre l'utilisation sur [platform.openai.com](https://platform.openai.com/usage)
- Configurer des alertes de budget
- Limiter `AI_MAX_TOKENS` dans la configuration Cortex
- Utiliser le mode fallback pour réduire les appels API

### Sauvegarde de la configuration

```bash
# Sauvegarder les règles iptables
docker exec suricata-monitor iptables-legacy-save > iptables-backup.txt

# Sauvegarder la configuration
tar -czf backup-config-$(date +%Y%m%d).tar.gz \
  suricata-setup/ \
  the-hive-cortex/cortex/application.conf \
  the-hive-cortex/cortex/responders/
```

## 📚 Documentation Technique

### Types d'attaques détectées

| Type | Sévérité | SID Range | Exemples |
|------|----------|-----------|----------|
| **SQL Injection** | High (3) | 1000001-1000007 | DROP, UNION, SELECT, OR/AND |
| **XSS** | Medium (2) | 1000008-1000011 | <script>, javascript:, alert() |
| **Command Injection** | High (3) | 1000012-1000015 | \|, ;, \`, & |
| **Directory Traversal** | Medium (2) | 1000016-1000017 | ../, ..\\ |
| **DDoS** | Critical (4) | 1000022-1000024 | HTTP/POST flood |
| **Reconnaissance** | Low (2) | 1000027-1000029 | /admin, .conf, .bak |
| **Brute Force** | Medium (2) | 1000033-1000034 | /login, /auth |

### Modèle de données des alertes

Les alertes créées dans TheHive contiennent :

```json
{
  "title": "🚨 [AI-Critical] Distributed Denial of Service Attack: HTTP flood",
  "severity": 4,
  "tags": [
    "ddos",
    "attack-session",
    "realtime",
    "suricata",
    "ai-severity-critical",
    "ai-confidence-95",
    "openai-classified"
  ],
  "observables": [
    {
      "dataType": "ip",
      "data": "attacker_ip",
      "tags": ["malicious", "ddos-source", "severity-4"]
    }
  ]
}
```

### API utilisées

- **TheHive API** : `POST /api/alert` - Création d'alertes
- **OpenAI API** : `POST /v1/chat/completions` - Classification IA
- **Cortex API** : Communication via cortexutils

## 🤝 Contribution

Les contributions sont les bienvenues ! Pour contribuer :

1. Forker le projet
2. Créer une branche (`git checkout -b feature/amelioration`)
3. Committer les changements (`git commit -m 'Ajout fonctionnalité'`)
4. Pusher vers la branche (`git push origin feature/amelioration`)
5. Ouvrir une Pull Request

## 📄 Licence

Ce projet est développé dans le cadre d'un Projet de Fin d'Études (PFE) pour Orange Tunisie.

## 👤 Auteur

**Maryam Kochtane**  
Projet de Fin d'Études - Orange Tunisie  
Email: kochtane.maryam@gmail.com  
GitHub: [@kochtane](https://github.com/kochtane)

## 🙏 Remerciements

- **Orange Tunisie** - Pour l'opportunité et le support du projet
- **TheHive Project** - Pour l'excellente plateforme de gestion d'incidents
- **Suricata** - Pour le puissant moteur IDS/IPS open source
- **OpenAI** - Pour les capacités d'analyse intelligente GPT-3.5

---

**⚠️ Avertissement** : Ce système est conçu pour détecter et répondre aux menaces de sécurité. Assurez-vous de le déployer dans un environnement contrôlé et de respecter les politiques de sécurité de votre organisation. Ne testez jamais sur des systèmes de production sans autorisation appropriée.
