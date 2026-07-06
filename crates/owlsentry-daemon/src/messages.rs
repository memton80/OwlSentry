//! Messages d'alerte localisés (fr/en) : pour chaque détection, un triplet
//! (quoi, pourquoi, comment) prêt à afficher.

use owlsentry_common::Lang;

pub struct Msg {
    pub title: String,
    pub what: String,
    pub why: String,
    pub how: String,
}

pub fn avc_denial(
    lang: Lang,
    comm: &str,
    perms: &str,
    target: &str,
    tclass: &str,
    scontext: &str,
    tcontext: &str,
) -> Msg {
    match lang {
        Lang::Fr => Msg {
            title: format!("Refus SELinux (AVC) : {comm} → {target}"),
            what: format!(
                "Le processus « {comm} » (contexte {scontext}) s'est vu refuser \
                 {{ {perms} }} sur « {target} » (classe {tclass}, contexte {tcontext})."
            ),
            why: "SELinux a bloqué un accès non autorisé par la politique. Cela peut \
                  révéler un programme compromis, une élévation de privilèges ou une \
                  mauvaise configuration."
                .into(),
            how: format!(
                "Vérifiez la légitimité du processus : `ausearch -m avc -c '{comm}'`. \
                 Si l'accès est illégitime, arrêtez le processus et inspectez son \
                 origine. N'assouplissez la politique (`audit2allow`) qu'après analyse."
            ),
        },
        Lang::En => Msg {
            title: format!("SELinux denial (AVC): {comm} → {target}"),
            what: format!(
                "Process \"{comm}\" (context {scontext}) was denied {{ {perms} }} on \
                 \"{target}\" (class {tclass}, context {tcontext})."
            ),
            why: "SELinux blocked an access not allowed by policy. This may indicate a \
                  compromised program, privilege escalation, or misconfiguration."
                .into(),
            how: format!(
                "Check the process legitimacy: `ausearch -m avc -c '{comm}'`. If the \
                 access is illegitimate, stop the process and investigate. Only relax \
                 the policy (`audit2allow`) after analysis."
            ),
        },
    }
}

pub fn selinux_tool_used(lang: Lang, exe: &str, auid: &str) -> Msg {
    match lang {
        Lang::Fr => Msg {
            title: format!("Outil SELinux exécuté : {exe}"),
            what: format!("La commande « {exe} » a été exécutée (auid={auid})."),
            why: "Les changements de contexte ou de politique SELinux (chcon, \
                  restorecon, semodule…) peuvent préparer une élévation de privilèges \
                  ou masquer une compromission."
                .into(),
            how: format!(
                "Vérifiez qui a lancé la commande : `ausearch -x {exe} -i`. Restaurez \
                 les contextes si nécessaire : `restorecon -Rv <chemin>`."
            ),
        },
        Lang::En => Msg {
            title: format!("SELinux tool executed: {exe}"),
            what: format!("Command \"{exe}\" was executed (auid={auid})."),
            why: "SELinux context or policy changes (chcon, restorecon, semodule…) can \
                  stage privilege escalation or hide a compromise."
                .into(),
            how: format!(
                "Check who ran it: `ausearch -x {exe} -i`. Restore contexts if \
                 needed: `restorecon -Rv <path>`."
            ),
        },
    }
}

pub fn enforcing_disabled(lang: Lang) -> Msg {
    match lang {
        Lang::Fr => Msg {
            title: "SELinux passé en mode permissif".into(),
            what: "Le mode « enforcing » de SELinux a été désactivé (setenforce 0).".into(),
            why: "Désactiver SELinux est une action typique d'un attaquant qui veut \
                  neutraliser les protections avant d'agir."
                .into(),
            how: "Réactivez immédiatement : `setenforce 1`. Identifiez l'auteur : \
                  `ausearch -m MAC_STATUS -i`. Vérifiez `/etc/selinux/config`."
                .into(),
        },
        Lang::En => Msg {
            title: "SELinux switched to permissive".into(),
            what: "SELinux enforcing mode was disabled (setenforce 0).".into(),
            why: "Disabling SELinux is a typical attacker move to neutralize \
                  protections before acting."
                .into(),
            how: "Re-enable immediately: `setenforce 1`. Identify the author: \
                  `ausearch -m MAC_STATUS -i`. Check `/etc/selinux/config`."
                .into(),
        },
    }
}

pub fn policy_loaded(lang: Lang) -> Msg {
    match lang {
        Lang::Fr => Msg {
            title: "Politique SELinux (re)chargée".into(),
            what: "Un module ou une politique SELinux a été chargé (MAC_POLICY_LOAD).".into(),
            why: "Un module malveillant peut ouvrir des permissions dans la politique.".into(),
            how: "Listez les modules récents : `semodule -l`. Comparez avec votre \
                  référence et supprimez tout module inconnu : `semodule -r <module>`."
                .into(),
        },
        Lang::En => Msg {
            title: "SELinux policy (re)loaded".into(),
            what: "A SELinux module or policy was loaded (MAC_POLICY_LOAD).".into(),
            why: "A malicious module can open permissions in the policy.".into(),
            how: "List modules: `semodule -l`. Compare against your baseline and \
                  remove unknown modules: `semodule -r <module>`."
                .into(),
        },
    }
}

pub fn sensitive_file_changed(lang: Lang, path: &str, action: &str) -> Msg {
    match lang {
        Lang::Fr => Msg {
            title: format!("Fichier sensible modifié : {path}"),
            what: format!("Le fichier critique « {path} » a subi : {action}."),
            why: "Les fichiers d'authentification et de configuration système sont des \
                  cibles privilégiées (persistance, création de comptes, portes dérobées)."
                .into(),
            how: format!(
                "Comparez avec la base RPM : `rpm -Vf {path}`. Vérifiez le contexte \
                 SELinux : `ls -Z {path}` puis `restorecon -v {path}` si besoin. \
                 Identifiez l'auteur via auditd : `ausearch -f {path} -i`."
            ),
        },
        Lang::En => Msg {
            title: format!("Sensitive file changed: {path}"),
            what: format!("Critical file \"{path}\" underwent: {action}."),
            why: "Authentication and system configuration files are prime targets \
                  (persistence, account creation, backdoors)."
                .into(),
            how: format!(
                "Compare with the RPM database: `rpm -Vf {path}`. Check the SELinux \
                 context: `ls -Z {path}` then `restorecon -v {path}` if needed. \
                 Identify the author via auditd: `ausearch -f {path} -i`."
            ),
        },
    }
}

pub fn suspicious_file_created(lang: Lang, path: &str) -> Msg {
    match lang {
        Lang::Fr => Msg {
            title: format!("Fichier suspect créé : {path}"),
            what: format!(
                "Un fichier exécutable/script « {path} » est apparu dans un répertoire temporaire."
            ),
            why: "Les logiciels malveillants déposent souvent leurs charges dans /tmp, \
                  /var/tmp ou /dev/shm avant exécution."
                .into(),
            how: format!(
                "Inspectez le fichier sans l'exécuter : `file {path}`, `stat {path}`. \
                 Identifiez le créateur : `ausearch -f {path} -i`. Supprimez-le si \
                 illégitime et recherchez le processus déposant."
            ),
        },
        Lang::En => Msg {
            title: format!("Suspicious file created: {path}"),
            what: format!(
                "An executable/script file \"{path}\" appeared in a temporary directory."
            ),
            why: "Malware often drops payloads in /tmp, /var/tmp or /dev/shm before \
                  execution."
                .into(),
            how: format!(
                "Inspect without executing: `file {path}`, `stat {path}`. Identify the \
                 creator: `ausearch -f {path} -i`. Remove if illegitimate and hunt the \
                 dropping process."
            ),
        },
    }
}

pub fn log_deleted(lang: Lang, path: &str) -> Msg {
    match lang {
        Lang::Fr => Msg {
            title: format!("Suppression de journal : {path}"),
            what: format!("Le fichier de journal « {path} » a été supprimé."),
            why: "La suppression de journaux est une technique classique d'effacement \
                  de traces après intrusion."
                .into(),
            how: "Vérifiez s'il s'agit d'une rotation légitime (logrotate). Sinon, \
                  identifiez l'auteur : `ausearch -f <chemin> -i` et considérez la \
                  machine comme potentiellement compromise."
                .into(),
        },
        Lang::En => Msg {
            title: format!("Log deletion: {path}"),
            what: format!("Log file \"{path}\" was deleted."),
            why: "Deleting logs is a classic trace-wiping technique after an intrusion.".into(),
            how: "Check whether this is legitimate rotation (logrotate). Otherwise \
                  identify the author: `ausearch -f <path> -i` and treat the host as \
                  potentially compromised."
                .into(),
        },
    }
}

pub fn new_listener(lang: Lang, proto: &str, port: u16) -> Msg {
    match lang {
        Lang::Fr => Msg {
            title: format!("Nouveau port en écoute : {port}/{proto}"),
            what: format!("Un service s'est mis en écoute sur le port {port}/{proto}."),
            why: "Un port en écoute inattendu peut être une porte dérobée ou un service \
                  non autorisé."
                .into(),
            how: format!(
                "Identifiez le processus : `ss -tlnp | grep :{port}`. Si illégitime, \
                 arrêtez-le et bloquez le port : `firewall-cmd --remove-port={port}/{proto}`."
            ),
        },
        Lang::En => Msg {
            title: format!("New listening port: {port}/{proto}"),
            what: format!("A service started listening on port {port}/{proto}."),
            why: "An unexpected listening port can be a backdoor or unauthorized service.".into(),
            how: format!(
                "Identify the process: `ss -tlnp | grep :{port}`. If illegitimate, stop \
                 it and block the port: `firewall-cmd --remove-port={port}/{proto}`."
            ),
        },
    }
}

pub fn port_scan(lang: Lang, ip: &str, ports: usize, blocked: bool) -> Msg {
    let (fr_block, en_block) = if blocked {
        (
            " L'IP a été bloquée temporairement via firewalld.".to_string(),
            " The IP was temporarily blocked via firewalld.".to_string(),
        )
    } else {
        (
            format!(
                " Pour bloquer manuellement : `firewall-cmd --add-rich-rule='rule \
                 family=ipv4 source address={ip} drop' --timeout=3600`."
            ),
            format!(
                " To block manually: `firewall-cmd --add-rich-rule='rule family=ipv4 \
                 source address={ip} drop' --timeout=3600`."
            ),
        )
    };
    match lang {
        Lang::Fr => Msg {
            title: format!("Scan de ports depuis {ip}"),
            what: format!("L'adresse {ip} a sondé {ports} ports distincts en peu de temps."),
            why: "Un balayage de ports précède généralement une tentative d'intrusion \
                  ciblée sur les services découverts."
                .into(),
            how: format!("Vérifiez les connexions actives : `ss -tn | grep {ip}`.{fr_block}"),
        },
        Lang::En => Msg {
            title: format!("Port scan from {ip}"),
            what: format!("Address {ip} probed {ports} distinct ports in a short time."),
            why: "A port sweep usually precedes a targeted intrusion attempt on \
                  discovered services."
                .into(),
            how: format!("Check active connections: `ss -tn | grep {ip}`.{en_block}"),
        },
    }
}

pub fn shell_connection(lang: Lang, comm: &str, pid: i32, remote: &str) -> Msg {
    match lang {
        Lang::Fr => Msg {
            title: format!("Connexion sortante d'un interpréteur : {comm}"),
            what: format!(
                "Le processus « {comm} » (pid {pid}) a une connexion établie vers {remote}."
            ),
            why: "Un shell qui ouvre une connexion réseau est le signe typique d'un \
                  « reverse shell » ou d'une exfiltration."
                .into(),
            how: format!(
                "Inspectez le processus : `ls -l /proc/{pid}/exe`, `cat /proc/{pid}/cmdline`. \
                 Si illégitime : `kill -9 {pid}` puis bloquez la destination via firewalld."
            ),
        },
        Lang::En => Msg {
            title: format!("Outbound connection from interpreter: {comm}"),
            what: format!(
                "Process \"{comm}\" (pid {pid}) has an established connection to {remote}."
            ),
            why: "A shell opening a network connection is the typical sign of a reverse \
                  shell or data exfiltration."
                .into(),
            how: format!(
                "Inspect the process: `ls -l /proc/{pid}/exe`, `cat /proc/{pid}/cmdline`. \
                 If illegitimate: `kill -9 {pid}` then block the destination via firewalld."
            ),
        },
    }
}

pub fn suspicious_port_connection(lang: Lang, remote: &str, port: u16) -> Msg {
    match lang {
        Lang::Fr => Msg {
            title: format!("Connexion vers un port suspect : {remote}"),
            what: format!("Une connexion est établie vers {remote} (port {port}, associé à des portes dérobées connues)."),
            why: "Certains ports (4444, 31337…) sont traditionnellement utilisés par des \
                  outils d'attaque (Metasploit, backdoors IRC…)."
                .into(),
            how: format!("Identifiez le processus : `ss -tnp | grep {port}` puis inspectez-le."),
        },
        Lang::En => Msg {
            title: format!("Connection to suspicious port: {remote}"),
            what: format!("A connection is established to {remote} (port {port}, associated with known backdoors)."),
            why: "Some ports (4444, 31337…) are traditionally used by attack tooling \
                  (Metasploit, IRC backdoors…)."
                .into(),
            how: format!("Identify the process: `ss -tnp | grep {port}` and inspect it."),
        },
    }
}

pub fn ld_preload(lang: Lang, pid: i32, comm: &str, value: &str) -> Msg {
    match lang {
        Lang::Fr => Msg {
            title: format!("LD_PRELOAD détecté : {comm} (pid {pid})"),
            what: format!("Le processus « {comm} » (pid {pid}) tourne avec LD_PRELOAD={value}."),
            why: "LD_PRELOAD permet d'injecter une bibliothèque dans un processus : \
                  technique classique de rootkit en espace utilisateur."
                .into(),
            how: format!(
                "Vérifiez la bibliothèque : `ls -lZ {value}` et `rpm -qf {value}`. \
                 Vérifiez aussi `/etc/ld.so.preload`. Tuez le processus si illégitime."
            ),
        },
        Lang::En => Msg {
            title: format!("LD_PRELOAD detected: {comm} (pid {pid})"),
            what: format!("Process \"{comm}\" (pid {pid}) runs with LD_PRELOAD={value}."),
            why: "LD_PRELOAD injects a library into a process: a classic userspace \
                  rootkit technique."
                .into(),
            how: format!(
                "Check the library: `ls -lZ {value}` and `rpm -qf {value}`. Also check \
                 `/etc/ld.so.preload`. Kill the process if illegitimate."
            ),
        },
    }
}

pub fn deleted_exe(lang: Lang, pid: i32, comm: &str) -> Msg {
    match lang {
        Lang::Fr => Msg {
            title: format!("Exécutable supprimé en cours d'exécution : {comm}"),
            what: format!("Le processus « {comm} » (pid {pid}) s'exécute depuis un binaire supprimé du disque."),
            why: "Les malwares se suppriment souvent après lancement pour échapper à \
                  l'analyse (fileless persistence)."
                .into(),
            how: format!(
                "Récupérez le binaire pour analyse : `cp /proc/{pid}/exe /root/quarantine_{pid}`. \
                 Puis inspectez et tuez le processus si illégitime."
            ),
        },
        Lang::En => Msg {
            title: format!("Deleted executable still running: {comm}"),
            what: format!("Process \"{comm}\" (pid {pid}) runs from a binary deleted from disk."),
            why: "Malware often deletes itself after launch to evade analysis \
                  (fileless persistence)."
                .into(),
            how: format!(
                "Recover the binary for analysis: `cp /proc/{pid}/exe /root/quarantine_{pid}`. \
                 Then inspect and kill the process if illegitimate."
            ),
        },
    }
}

pub fn tmp_exec(lang: Lang, pid: i32, comm: &str, path: &str) -> Msg {
    match lang {
        Lang::Fr => Msg {
            title: format!("Processus lancé depuis un répertoire temporaire : {comm}"),
            what: format!("Le processus « {comm} » (pid {pid}) s'exécute depuis {path}."),
            why: "Les binaires légitimes ne s'exécutent pas depuis /tmp ou /dev/shm ; \
                  c'est un emplacement de prédilection pour les charges malveillantes."
                .into(),
            how: format!(
                "Inspectez : `cat /proc/{pid}/cmdline`, `ls -lZ {path}`. Tuez le \
                 processus et supprimez le binaire si illégitime."
            ),
        },
        Lang::En => Msg {
            title: format!("Process running from temporary directory: {comm}"),
            what: format!("Process \"{comm}\" (pid {pid}) is executing from {path}."),
            why: "Legitimate binaries do not run from /tmp or /dev/shm; it is a \
                  favorite location for malicious payloads."
                .into(),
            how: format!(
                "Inspect: `cat /proc/{pid}/cmdline`, `ls -lZ {path}`. Kill the process \
                 and remove the binary if illegitimate."
            ),
        },
    }
}

pub fn hidden_process(lang: Lang, pid: i32) -> Msg {
    match lang {
        Lang::Fr => Msg {
            title: format!("Processus caché détecté : pid {pid}"),
            what: format!(
                "Le pid {pid} existe (référencé comme parent et présent dans /proc) \
                 mais n'apparaît pas dans l'énumération du répertoire /proc."
            ),
            why: "Masquer un processus de l'énumération est un comportement de rootkit.".into(),
            how: format!(
                "Vérifiez : `cat /proc/{pid}/status`, `ls -l /proc/{pid}/exe`. \
                 Comparez `ps aux` et /proc. En cas de doute, isolez la machine et \
                 analysez-la hors ligne."
            ),
        },
        Lang::En => Msg {
            title: format!("Hidden process detected: pid {pid}"),
            what: format!(
                "Pid {pid} exists (referenced as a parent and present in /proc) but \
                 does not appear when enumerating the /proc directory."
            ),
            why: "Hiding a process from enumeration is rootkit behavior.".into(),
            how: format!(
                "Check: `cat /proc/{pid}/status`, `ls -l /proc/{pid}/exe`. Compare \
                 `ps aux` with /proc. If in doubt, isolate the machine and analyze it \
                 offline."
            ),
        },
    }
}
