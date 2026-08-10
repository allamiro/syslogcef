Name:           syslogcef
Version:        0.1.3
Release:        1%{?dist}
Summary:        Convert syslog events to ArcSight CEF

License:        MIT
URL:            https://github.com/allamiro/syslogcef
Source0:        %{pypi_source syslog2cef}
Source1:        syslogcef.service
Source2:        syslogcef.conf
Source3:        syslogcef.1

# EPEL 9's default Python (3.9) ships setuptools 53, too old for PEP 621
# metadata, so build against the python3.11 stack there.
%if 0%{?el9}
%global python3_pkgversion 3.11
%endif

BuildArch:      noarch
BuildRequires:  python%{python3_pkgversion}-devel
BuildRequires:  pyproject-rpm-macros
BuildRequires:  systemd-rpm-macros

%description
syslogcef converts syslog events (RFC3164, RFC5424, rsyslog, and systemd
journal exports) into ArcSight Common Event Format (CEF), with bundled
vendor mappings for Cisco ASA/IOS, F5, Linux, and VMware sources. This
package installs the syslogcef command line tool and a systemd service
that follows a configured log file and appends CEF output.

%prep
%autosetup -n syslog2cef-%{version}

%generate_buildrequires
%pyproject_buildrequires

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files syslogcef

install -D -m 0644 %{SOURCE1} %{buildroot}%{_unitdir}/syslogcef.service
install -D -m 0644 %{SOURCE2} %{buildroot}%{_sysconfdir}/syslogcef/syslogcef.conf
install -D -m 0644 %{SOURCE3} %{buildroot}%{_mandir}/man1/syslogcef.1

%check
%pyproject_check_import syslogcef

%post
%systemd_post syslogcef.service

%preun
%systemd_preun syslogcef.service

%postun
%systemd_postun_with_restart syslogcef.service

%files -f %{pyproject_files}
%license LICENSE
%doc README.md
%{_bindir}/syslogcef
%{_mandir}/man1/syslogcef.1*
%{_unitdir}/syslogcef.service
%dir %{_sysconfdir}/syslogcef
%config(noreplace) %{_sysconfdir}/syslogcef/syslogcef.conf

%changelog
* Tue Aug 11 2026 Tamir Suliman <allamiro@gmail.com> - 0.1.3-1
- Receive syslog over the network (--listen udp/tcp)
- Forward CEF to a SIEM (--send udp/tcp, optional kafka) with --eps
- Validate CEF extensions against the ArcSight dictionary
- Comprehensive man page; unit gains CAP_NET_BIND_SERVICE

* Tue Aug 11 2026 Tamir Suliman <allamiro@gmail.com> - 0.1.2-1
- Parse RFC3164 timestamps with a year (real Cisco ASA/FTD format)
- Parse hosts with trailing or standalone colons
- Extract Cisco event codes anywhere in the message and derive severity
- Preserve PRI in the raw fallback parser

* Mon Aug 10 2026 Tamir Suliman <allamiro@gmail.com> - 0.1.1-1
- Add syslogcef(1) man page
- Restore Python 3.9 compatibility (remove dataclass slots)
- Build against the python3.11 stack on EPEL 9

* Mon Aug 10 2026 Tamir Suliman <allamiro@gmail.com> - 0.1.0-1
- Initial RPM release with systemd service and configuration file
