Name:           syslogcef
Version:        0.1.0
Release:        1%{?dist}
Summary:        Convert syslog events to ArcSight CEF

License:        MIT
URL:            https://github.com/allamiro/syslogcef
Source0:        %{pypi_source syslog2cef}
Source1:        syslogcef.service
Source2:        syslogcef.conf
Source3:        syslogcef.1

BuildArch:      noarch
BuildRequires:  python3-devel
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
* Mon Aug 10 2026 Tamir Suliman <allamiro@gmail.com> - 0.1.0-1
- Initial RPM release with systemd service and configuration file
