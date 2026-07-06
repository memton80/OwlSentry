# OwlSentry 🦉

**Système de détection d'intrusion (IDS) pour Fedora**, écrit en Rust :
un démon durci (systemd + SELinux + seccomp) surveille le système en temps
réel et une interface graphique légère (egui) affiche les alertes avec, pour
chaque détection : **quoi**, **pourquoi**, et **comment** réagir.

*An intrusion detection system for Fedora written in Rust — hardened root
daemon + unprivileged egui GUI. Alert messages are available in French and
English (`general.language` in the config).*

---

## Sommaire

1. [Architecture](#architecture)
2. [Fonctionnalités de détection](#fonctionnalités-de-détection)
3. [Installation](#installation)
4. [Configuration et règles](#configuration-et-règles)
5. [Sécurité](#sécurité)
6. [Tests et validation](#tests-et-validation)
7. [Dépannage](#dépannage)
8. [Plan de développement](#plan-de-développement)

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ owlsentry-daemon (root, capabilities réduites, seccomp)      │
│                                                              │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐         │
│  │ audit.rs │ │  fs.rs   │ │  net.rs  │ │process.rs│  moniteurs
│  │ auditd/  │ │ inotify  │ │/proc/net │ │  /proc   │         │
│  │ SELinux  │ │          │ │firewalld │ │          │         │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘         │
│       └─────────┬──┴───────┬────┴────────────┘               │
│                 ▼ mpsc     │                                 │
│           ┌────────────┐   │                                 │
│           │ dispatcher │───┼─► /var/log/owlsentry/*.jsonl    │
│           └─────┬──────┘   │   (rotation quotidienne)        │
│                 ▼ broadcast                                  │
│           ┌────────────┐                                     │
│           │ ipc_server │  socket Unix 0660 root:owlsentry    │
│           └─────┬──────┘  /run/owlsentry/owlsentry.sock      │
└─────────────────┼────────────────────────────────────────────┘
                  ▼ NDJSON (serde, validé)
        ┌───────────────────┐
        │  owlsentry-gui    │  utilisateur non privilégié,
        │  (egui, notify-   │  membre du groupe `owlsentry`
        │   rust)           │
        └───────────────────┘
```

Trois crates dans un workspace Cargo :

| Crate | Rôle |
|---|---|
| `owlsentry-common` | Types partagés : `Alert`, protocole IPC, configuration, i18n |
| `owlsentry-daemon` | Démon : moniteurs, dispatcher, serveur IPC, journalisation |
| `owlsentry-gui` | Interface egui : liste filtrable, détails, tableau de bord, notifications |

### Choix de conception (et alternatives évaluées)

- **Socket Unix + NDJSON** plutôt que D-Bus ou gRPC : zéro dépendance
  système, contrôle d'accès par les permissions du fichier socket (le noyau
  vérifie le mode du socket au `connect(2)`), désérialisation `serde`
  stricte avec limite de taille. Le mode demandé « 0600 root:ids-user »
  interdirait en réalité tout accès au client non root ; le schéma correct
  et équivalent est **0660 root:owlsentry** — seuls root et les membres du
  groupe `owlsentry` peuvent se connecter. `SO_PEERCRED` est journalisé
  pour la traçabilité.
- **Parsing direct de `/var/log/audit/audit.log`** (équivalent `tail -F`
  avec gestion de rotation) plutôt que la libaudit : format `key=value`
  stable, pas de dépendance C. Le point d'entrée est isolé pour permettre
  une évolution vers le multicast netlink (`CAP_AUDIT_READ`) ou eBPF.
- **seccomp via systemd** (`SystemCallFilter=@system-service`) plutôt qu'un
  filtre embarqué : audité, maintenu, et indépendant du code. Idem pour les
  capabilities (`CapabilityBoundingSet`) et l'isolation du système de
  fichiers (`ProtectSystem=strict`).
- **Aucune exécution dynamique** : le seul programme externe invoqué est
  `firewall-cmd` (optionnel, désactivé par défaut), sans shell, avec des
  arguments construits à partir d'une `IpAddr` validée.

## Fonctionnalités de détection

| Catégorie | Détection | Gravité |
|---|---|---|
| SELinux | Refus AVC (`denied`) ; critique si le type cible est sensible (`shadow_t`…) | Élevée/Critique |
| SELinux | `setenforce 0` (MAC_STATUS) | Critique |
| SELinux | Chargement de politique/module (MAC_POLICY_LOAD) | Moyenne |
| SELinux | Usage de `chcon`, `restorecon`, `semodule`… (via auditd) | Moyenne |
| Fichiers | Modification/chmod/suppression de fichiers critiques (`/etc/shadow`, `sudoers`…) | Élevée/Critique |
| Fichiers | Création de scripts (`.sh`, `.py`, `.so`…) dans `/tmp`, `/var/tmp`, `/dev/shm` | Moyenne |
| Fichiers | Suppression de journaux dans `/var/log` (hors rotation logrotate) | Élevée |
| Réseau | Scan de ports (N ports distincts sondés par IP dans une fenêtre glissante) + blocage firewalld optionnel | Élevée |
| Réseau | Nouveau port en écoute | Moyenne |
| Réseau | Connexion sortante d'un interpréteur (`bash`, `nc`… → reverse shell) | Élevée |
| Réseau | Connexion vers un port de porte dérobée connu (4444, 31337…) | Élevée |
| Processus | `LD_PRELOAD` non vide dans l'environnement d'un processus | Élevée |
| Processus | Binaire supprimé encore en exécution | Élevée |
| Processus | Exécutable lancé depuis `/tmp` ou `/dev/shm` | Élevée |
| Processus | Processus caché (présent dans `/proc/<pid>` mais absent de l'énumération) | Critique |

## Installation

### Via le script

```bash
git clone https://github.com/memton80/OwlSentry.git
cd OwlSentry
sudo ./install.sh
# Autoriser votre utilisateur à lire les alertes :
sudo usermod -aG owlsentry "$USER"   # puis se déconnecter/reconnecter
owlsentry-gui
```

Options : `--no-deps` (ne pas lancer dnf), `--no-selinux` (ne pas charger le
module), `--no-start` (ne pas démarrer le service).

### Via RPM

```bash
sudo dnf install rpm-build rust cargo systemd-rpm-macros checkpolicy selinux-policy-devel
git archive --format=tar.gz --prefix=owlsentry-0.1.0/ -o ~/rpmbuild/SOURCES/owlsentry-0.1.0.tar.gz HEAD
rpmbuild -ba packaging/owlsentry.spec
sudo dnf install ~/rpmbuild/RPMS/x86_64/owlsentry-0.1.0-1.*.rpm \
                 ~/rpmbuild/RPMS/x86_64/owlsentry-gui-0.1.0-1.*.rpm
```

### Compilation seule

```bash
cargo build --release            # binaires dans target/release/
cargo test --workspace           # tests unitaires + intégration
target/release/owlsentry-daemon --config config/owlsentry.conf --check-config
```

## Configuration et règles

- `/etc/owlsentry/owlsentry.conf` — paramètres du démon (langue, chemins,
  intervalles, activation du blocage firewalld…). Voir
  [`config/owlsentry.conf`](config/owlsentry.conf) : chaque clé y est
  commentée ; toute clé absente reprend sa valeur par défaut.
- `/etc/owlsentry/rules.toml` — règles personnalisables. Exemples :

```toml
# Surveiller aussi les clés SSH de root et un fichier applicatif :
[filesystem]
sensitive_paths = ["/etc/shadow", "/root/.ssh", "/opt/monapp/secret.conf"]

# Ne jamais bloquer le superviseur, cibler d'autres ports :
[network]
never_block = ["127.0.0.1", "::1", "192.0.2.10"]
suspicious_ports = [4444, 31337, 8081]

# Type SELinux applicatif à traiter comme critique :
[selinux]
critical_types = ["shadow_t", "monapp_secret_t"]
```

Après modification : `sudo systemctl restart owlsentry-daemon` (validez
d'abord avec `owlsentry-daemon --check-config`).

Le blocage automatique (`network.firewalld_block = true`) crée une règle
riche **temporaire** (`--timeout`), jamais permanente, et respecte la liste
`never_block`.

## Sécurité

- **Rust sans `unsafe`** dans tout le projet ; erreurs via
  `thiserror`/`anyhow`, aucun `unwrap()` hors tests.
- **Entrées validées** : configuration TOML désérialisée puis validée ;
  requêtes IPC limitées à 4 Kio et parsées par `serde` (une requête invalide
  reçoit une erreur, jamais d'évaluation).
- **Démon** : root mais confiné —
  `CapabilityBoundingSet=CAP_AUDIT_READ CAP_NET_ADMIN CAP_DAC_READ_SEARCH
  CAP_CHOWN CAP_FOWNER CAP_SYS_PTRACE`, `NoNewPrivileges`,
  `SystemCallFilter=@system-service` (seccomp), `ProtectSystem=strict`
  (système en lecture seule sauf `/var/log/owlsentry` et `/run/owlsentry`),
  `PrivateTmp`, `MemoryDenyWriteExecute`, `RestrictNamespaces`…
- **Module SELinux dédié** (`packaging/selinux/owlsentry.te`) : domaine
  `owlsentry_t` limité à la lecture d'`auditd_log_t`, ses journaux, son
  socket, `/proc`, et le dialogue avec firewalld.
- **Permissions** : binaire démon `0750 root:root`, configs
  `0640 root:owlsentry`, socket `0660 root:owlsentry`, journaux
  `0750 root:owlsentry`.
- **Aucun secret dans le dépôt** : pas de clé, pas de token, pas de mot de
  passe. Ne collez jamais de jeton d'accès dans un fichier suivi par git.

## Tests et validation

```bash
cargo test --workspace
```

- **Unitaires** : parsing auditd (AVC, SYSCALL, MAC_STATUS…), parsing
  `/proc/net/tcp{,6}`, classification des événements fichiers (y compris
  faux positifs logrotate), extraction `LD_PRELOAD`, configuration/règles,
  protocole IPC.
- **Intégration** (`crates/owlsentry-daemon/tests/ipc_integration.rs`) :
  démarre le serveur IPC sur un socket temporaire, simule une alerte
  « /etc/shadow modifié », vérifie sa réception par un client abonné.

### Simulation d'intrusion sur une machine de test

```bash
# 1. AVC SELinux (depuis un utilisateur confiné) :
runcon -t user_t cat /etc/shadow           # → alerte SELinux critique
# 2. Fichier sensible :
sudo touch /etc/shadow                     # → alerte Fichiers élevée
# 3. Script suspect :
echo 'echo pwned' > /tmp/payload.sh        # → alerte Fichiers moyenne
# 4. Reverse shell simulé :
bash -c 'exec 3<>/dev/tcp/example.org/80'  # → alerte Réseau élevée
# 5. Scan (depuis une autre machine) :
nmap -p 1-200 <ip-de-test>                 # → alerte scan + blocage optionnel
```

### Performances

Le démon est essentiellement en attente d'événements (inotify, tail) ; les
balayages périodiques (`/proc/net` toutes les 5 s, `/proc` toutes les 30 s)
se mesurent avec :

```bash
systemd-cgtop system.slice/owlsentry-daemon.service
# ou
pidstat -p $(pgrep owlsentry-daemon) 5
```

Ordre de grandeur attendu : < 1 % CPU et ~10–20 Mo de RSS sur une machine
de bureau. Augmentez les intervalles dans la configuration si nécessaire.

## Dépannage

| Symptôme | Cause probable / correctif |
|---|---|
| GUI : « Démon injoignable » | Service arrêté (`systemctl status owlsentry-daemon`) ou utilisateur pas dans le groupe `owlsentry` (`id`, puis `usermod -aG owlsentry $USER` + reconnexion). |
| Aucune alerte SELinux | `auditd` non démarré (`systemctl start auditd`) ou SELinux permissif (`getenforce`). |
| Alertes en rafale sur `/var/log` | Rotation non standard : ajoutez le chemin à `filesystem.ignore_paths` dans `rules.toml`. |
| Le démon ne démarre pas après édition de la conf | `owlsentry-daemon --check-config` affiche l'erreur exacte ; `journalctl -u owlsentry-daemon -e`. |
| Refus SELinux visant `owlsentry_t` (ex. `add_name` sur `daemon.log.*`) | Souvent un étiquetage résiduel d'une installation antérieure au chargement du module. Corrigez : `sudo restorecon -RF /var/log/owlsentry /run/owlsentry /etc/owlsentry /usr/bin/owlsentry-daemon` puis `sudo systemctl restart owlsentry-daemon`. Vérifiez que le module ≥ 1.0.2 est chargé : `semodule -l \| grep owlsentry`. Pour un refus restant : `ausearch -m avc -c owlsentry-daemon -i`, complétez le `.te` et rechargez, ou passez temporairement le domaine en permissif le temps du diagnostic : `sudo semanage permissive -a owlsentry_t` (retour : `-d`). |
| Blocage firewalld inopérant | `firewalld` arrêté, ou `network.firewalld_block = false` (défaut). Vérifiez `firewall-cmd --list-rich-rules`. |
| Notifications absentes | Pas de session D-Bus (SSH) ou case « Notifications » décochée dans la GUI. |

## Plan de développement

- **Phase 1 (fait)** : démon de base — auditd/SELinux + inotify, dispatcher,
  journaux JSON avec rotation.
- **Phase 2 (fait)** : réseau — /proc/net, scans, listeners, reverse shells,
  blocage firewalld temporaire optionnel.
- **Phase 3 (fait)** : GUI egui + IPC socket Unix + notifications bureau,
  i18n fr/en.
- **Phase 4 (fait)** : durcissement — capabilities, seccomp (systemd),
  module SELinux, permissions, validation des entrées.
- **Phase 5 (fait)** : tests unitaires/intégration, packaging RPM,
  documentation.

### Extensions envisagées (le projet est modulaire : un moniteur = un module)

- Lecture des événements audit via netlink (`CAP_AUDIT_READ`) ou **eBPF**
  (crate `aya`) pour la surveillance fine des appels système.
- Moniteur **nftables** natif (netlink `nfnetlink_log`) au lieu de
  l'échantillonnage /proc/net.
- Intégration **ClamAV** (scan des fichiers créés suspects via `clamd`).
- Base d'empreintes (AIDE-like) des binaires système.
- Export **syslog/SIEM** (RFC 5424) des alertes.
