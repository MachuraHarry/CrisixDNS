# 🚀 Crisix DNS Tunnel Server auf Render.com deployen

## Schritt-für-Schritt Anleitung

### 1. Auf render.com einloggen
- Gehe zu https://dashboard.render.com
- Mit GitHub anmelden

### 2. Neuen Web Service erstellen
- Klicke auf **"New +"** → **"Web Service"**
- Wähle **"Build and deploy from a Git repository"**
- Verbinde GitHub und wähle **`MachuraHarry/CrisixDNS`**

### 3. Service konfigurieren

| Feld | Wert |
|------|------|
| **Name** | `crisix-dns` |
| **Region** | `Frankfurt (EU Central)` |
| **Branch** | `main` |
| **Runtime** | `Docker` (wird automatisch erkannt) |
| **Plan** | `Free` |

### 4. Health Check Path
- Erweitere **"Advanced"** (unten aufklappen)
- **Health Check Path:** `/health`

### 5. Environment Variables
Füge unter **"Environment Variables"** hinzu:

| Key | Value |
|-----|-------|
| `SERVER_DOMAIN` | `crisix-dns.onrender.com` |
| `DNS_PORT` | `8053` |
| `HTTP_PORT` | `8080` |

### 6. Deployen
- Klicke auf **"Create Web Service"**
- Warte ~2-3 Minuten bis der Build fertig ist
- Die URL ist dann: `https://crisix-dns.onrender.com`

### 7. Testen
Nach dem Deployment:

```bash
# Health-Check
curl https://crisix-dns.onrender.com/health

# Senden einer Test-Nachricht
curl "https://crisix-dns.onrender.com/dns-query?domain=send.test123.receiver-id.crisix-dns.onrender.com"

# Polling
curl "https://crisix-dns.onrender.com/dns-query?domain=poll.receiver-id.crisix-dns.onrender.com"
```

### 8. Android-App konfigurieren
In `DnsTunnelTransport.kt` muss `serverDomain` auf deine Render-URL zeigen:

```kotlin
class DnsTunnelTransport(
    private val localPeerId: String,
    private val serverDomain: String = "crisix-dns.onrender.com", // ← Deine URL
    private val useHttpApi: Boolean = true,
) : Transport {
```

---

## ⚠️ Wichtig: Free Tier Einschränkungen

- Der Service **schläft nach 15 Minuten Inaktivität** ein
- Beim nächsten Request dauert es ~30s bis er wieder aufwacht
- **Lösung:** Der Health-Check und das Polling (alle 5s) halten ihn wach
- Monatliches Limit: 750 Stunden (reicht für 24/7 Betrieb)

## 🔧 Alternative: Eigenen Server

Wenn du Render.com nicht nutzen willst, kannst du den Server auch lokal oder auf einem VPS starten:

```bash
cd dns-tunnel-server
pip install -r requirements.txt
python3 dns_server.py
```

Dann musst du nur die `serverDomain` in der Android-App auf deine Server-IP/URL ändern.
