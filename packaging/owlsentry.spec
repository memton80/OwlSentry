Name:           owlsentry
Version:        0.1.0
Release:        1%{?dist}
Summary:        Intrusion detection system for Fedora (SELinux, auditd, firewalld)
License:        MIT
URL:            https://github.com/memton80/OwlSentry
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  rust >= 1.80
BuildRequires:  cargo
BuildRequires:  systemd-rpm-macros
BuildRequires:  checkpolicy
BuildRequires:  selinux-policy-devel

Requires:       audit
Requires:       selinux-policy
Requires:       firewalld
Requires:       nftables
Requires(pre):  shadow-utils
%{?systemd_requires}

%description
OwlSentry is a lightweight intrusion detection system for Fedora. A root
daemon (with reduced capabilities and seccomp filtering via systemd) watches
SELinux denials through auditd, sensitive file changes through inotify,
network anomalies through /proc/net and firewalld, and suspicious processes
through /proc. Alerts are streamed over a group-restricted Unix socket to an
unprivileged egui GUI with desktop notifications (French and English).

%package gui
Summary:        GUI for OwlSentry (egui-based alert viewer and dashboard)
Requires:       %{name} = %{version}-%{release}

%description gui
Real-time alert viewer, filters, and dashboard for OwlSentry. Runs as an
unprivileged user; membership in the "owlsentry" group is required to read
the daemon socket.

%prep
%autosetup

%build
cargo build --release --workspace
# Module SELinux
make -f /usr/share/selinux/devel/Makefile -C packaging/selinux owlsentry.pp

%install
install -D -m 0750 target/release/owlsentry-daemon %{buildroot}%{_bindir}/owlsentry-daemon
install -D -m 0755 target/release/owlsentry-gui %{buildroot}%{_bindir}/owlsentry-gui
install -D -m 0640 config/owlsentry.conf %{buildroot}%{_sysconfdir}/owlsentry/owlsentry.conf
install -D -m 0640 config/rules.toml %{buildroot}%{_sysconfdir}/owlsentry/rules.toml
install -D -m 0644 packaging/systemd/owlsentry-daemon.service %{buildroot}%{_unitdir}/owlsentry-daemon.service
install -D -m 0644 packaging/logrotate/owlsentry %{buildroot}%{_sysconfdir}/logrotate.d/owlsentry
install -D -m 0644 packaging/selinux/owlsentry.pp %{buildroot}%{_datadir}/selinux/packages/owlsentry.pp
install -d -m 0750 %{buildroot}%{_localstatedir}/log/owlsentry

%pre
getent group owlsentry >/dev/null || groupadd -r owlsentry
exit 0

%post
%systemd_post owlsentry-daemon.service
semodule -i %{_datadir}/selinux/packages/owlsentry.pp 2>/dev/null || :
restorecon -R %{_bindir}/owlsentry-daemon %{_sysconfdir}/owlsentry \
    %{_localstatedir}/log/owlsentry 2>/dev/null || :

%preun
%systemd_preun owlsentry-daemon.service

%postun
%systemd_postun_with_restart owlsentry-daemon.service
if [ $1 -eq 0 ]; then
    semodule -r owlsentry 2>/dev/null || :
fi

%files
%{_bindir}/owlsentry-daemon
%dir %attr(0750, root, owlsentry) %{_sysconfdir}/owlsentry
%config(noreplace) %attr(0640, root, owlsentry) %{_sysconfdir}/owlsentry/owlsentry.conf
%config(noreplace) %attr(0640, root, owlsentry) %{_sysconfdir}/owlsentry/rules.toml
%{_unitdir}/owlsentry-daemon.service
%config(noreplace) %{_sysconfdir}/logrotate.d/owlsentry
%{_datadir}/selinux/packages/owlsentry.pp
%dir %attr(0750, root, owlsentry) %{_localstatedir}/log/owlsentry

%files gui
%{_bindir}/owlsentry-gui

%changelog
* Mon Jul 06 2026 OwlSentry contributors <owlsentry@example.invalid> - 0.1.0-1
- Initial package
