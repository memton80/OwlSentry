#!/usr/bin/env bash
# install.sh — installation d'OwlSentry sur Fedora 38+.
#
# Ce script :
#   1. installe les dépendances (dnf) ;
#   2. crée le groupe système `owlsentry` ;
#   3. compile le projet en mode release ;
#   4. installe binaires, configuration, service systemd, logrotate ;
#   5. compile et charge le module SELinux (si les outils sont présents) ;
#   6. active et démarre le service.
#
# Usage : sudo ./install.sh [--no-deps] [--no-selinux] [--no-start]

set -euo pipefail

NO_DEPS=0
NO_SELINUX=0
NO_START=0
for arg in "$@"; do
    case "$arg" in
        --no-deps)    NO_DEPS=1 ;;
        --no-selinux) NO_SELINUX=1 ;;
        --no-start)   NO_START=1 ;;
        *) echo "option inconnue: $arg" >&2; exit 2 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "Ce script doit être lancé en root (sudo ./install.sh)." >&2
    exit 1
fi

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SRC_DIR"

echo "==> 1/6 Dépendances"
if [[ $NO_DEPS -eq 0 ]]; then
    dnf install -y rust cargo audit selinux-policy firewalld nftables \
        checkpolicy policycoreutils selinux-policy-devel \
        gtk3 libxkbcommon || {
        echo "Installation des dépendances échouée." >&2; exit 1;
    }
else
    echo "    (ignoré : --no-deps)"
fi

echo "==> 2/6 Groupe système owlsentry"
if ! getent group owlsentry >/dev/null; then
    groupadd -r owlsentry
    echo "    groupe 'owlsentry' créé"
else
    echo "    groupe 'owlsentry' déjà présent"
fi
echo "    Ajoutez les utilisateurs autorisés à lire les alertes :"
echo "        usermod -aG owlsentry <utilisateur>"

echo "==> 3/6 Compilation (release)"
# La compilation est faite avec l'utilisateur appelant si possible, pour ne
# pas remplir ~/.cargo de root.
if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
    sudo -u "$SUDO_USER" cargo build --release --workspace
else
    cargo build --release --workspace
fi

echo "==> 4/6 Installation des fichiers"
install -D -m 0750 -o root -g root target/release/owlsentry-daemon /usr/bin/owlsentry-daemon
install -D -m 0755 -o root -g root target/release/owlsentry-gui /usr/bin/owlsentry-gui
install -d -m 0750 -o root -g owlsentry /etc/owlsentry
install -m 0640 -o root -g owlsentry config/owlsentry.conf /etc/owlsentry/owlsentry.conf.new
install -m 0640 -o root -g owlsentry config/rules.toml /etc/owlsentry/rules.toml.new
# Ne pas écraser une configuration existante.
for f in owlsentry.conf rules.toml; do
    if [[ -f /etc/owlsentry/$f ]]; then
        echo "    /etc/owlsentry/$f conservé (nouvelle version: $f.new)"
    else
        mv /etc/owlsentry/$f.new /etc/owlsentry/$f
    fi
done
install -d -m 0750 -o root -g owlsentry /var/log/owlsentry
install -D -m 0644 packaging/systemd/owlsentry-daemon.service \
    /etc/systemd/system/owlsentry-daemon.service
install -D -m 0644 packaging/logrotate/owlsentry /etc/logrotate.d/owlsentry
systemctl daemon-reload

echo "==> 5/6 Module SELinux"
if [[ $NO_SELINUX -eq 0 ]] && command -v checkmodule >/dev/null 2>&1; then
    if [[ -f /usr/share/selinux/devel/Makefile ]]; then
        make -f /usr/share/selinux/devel/Makefile -C packaging/selinux owlsentry.pp
        semodule -i packaging/selinux/owlsentry.pp
        # -F : force le ré-étiquetage même si seul l'utilisateur SELinux
        # diffère (rattrape les répertoires créés avant le chargement du
        # module, qui portaient var_log_t / var_run_t).
        restorecon -RF /usr/bin/owlsentry-daemon /usr/bin/owlsentry-gui \
            /etc/owlsentry /var/log/owlsentry 2>/dev/null || true
        [[ -d /run/owlsentry ]] && restorecon -RF /run/owlsentry || true
        echo "    module SELinux 'owlsentry' chargé et contextes restaurés"
    else
        echo "    selinux-policy-devel absent : module SELinux non compilé" >&2
    fi
else
    echo "    (ignoré)"
fi

echo "==> 6/6 Service systemd"
"/usr/bin/owlsentry-daemon" --config /etc/owlsentry/owlsentry.conf --check-config
systemctl enable owlsentry-daemon.service
if [[ $NO_START -eq 0 ]]; then
    systemctl restart owlsentry-daemon.service
    systemctl --no-pager --lines 5 status owlsentry-daemon.service || true
else
    echo "    (démarrage ignoré : --no-start)"
fi

cat <<'EOF'

Installation terminée.
  - Démon   : systemctl status owlsentry-daemon
  - Journaux: /var/log/owlsentry/ (daemon.log.*, alerts.jsonl.*)
  - GUI     : owlsentry-gui   (l'utilisateur doit être membre du groupe
              'owlsentry' — déconnexion/reconnexion nécessaire après usermod)
EOF
