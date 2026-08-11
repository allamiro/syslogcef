Name:           syslogcef
Version:        0.3.0
Release:        1%{?dist}
Summary:        Convert syslog events to ArcSight CEF

License:        MIT
URL:            https://github.com/allamiro/syslogcef
Source0:        %{pypi_source syslog2cef}
Source1:        syslogcef.service
Source2:        syslogcef.conf
Source3:        syslogcef.1
Source4:        syslogcef@.service
Source5:        syslogcef-instance.conf
Source6:        syslogcef.logrotate
Source7:        syslogcef.sysusers

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
%pyproject_buildrequires -x test

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files syslogcef

install -D -m 0644 %{SOURCE1} %{buildroot}%{_unitdir}/syslogcef.service
install -D -m 0644 %{SOURCE2} %{buildroot}%{_sysconfdir}/syslogcef/syslogcef.conf
install -D -m 0644 %{SOURCE3} %{buildroot}%{_mandir}/man1/syslogcef.1
install -D -m 0644 %{SOURCE4} %{buildroot}%{_unitdir}/syslogcef@.service
install -D -m 0644 %{SOURCE5} %{buildroot}%{_sysconfdir}/syslogcef/conf.d/example.conf.sample
install -D -m 0644 %{SOURCE6} %{buildroot}%{_sysconfdir}/logrotate.d/syslogcef
install -D -m 0644 %{SOURCE7} %{buildroot}%{_sysusersdir}/syslogcef.conf

%check
%pyproject_check_import syslogcef
%pytest

%pre
%sysusers_create_compat %{SOURCE7}

%post
%systemd_post syslogcef.service
%systemd_post syslogcef@.service

%preun
%systemd_preun syslogcef.service
%systemd_preun syslogcef@.service

%postun
%systemd_postun_with_restart syslogcef.service
%systemd_postun_with_restart syslogcef@.service

%files -f %{pyproject_files}
%license LICENSE
%doc README.md
%{_bindir}/syslogcef
%{_mandir}/man1/syslogcef.1*
%{_unitdir}/syslogcef.service
%{_unitdir}/syslogcef@.service
%dir %{_sysconfdir}/syslogcef
%dir %{_sysconfdir}/syslogcef/conf.d
%config(noreplace) %{_sysconfdir}/syslogcef/syslogcef.conf
%config(noreplace) %{_sysconfdir}/syslogcef/conf.d/example.conf.sample
%config(noreplace) %{_sysconfdir}/logrotate.d/syslogcef
%{_sysusersdir}/syslogcef.conf

%changelog
* Tue Aug 11 2026 Tamir Suliman <allamiro@gmail.com> - 0.3.0-1
- Parse macOS install.log compact UTC offsets (+02); split app[pid]
  tags in journald formats; adaptive parser learns program tags
- Continuation lines inherit host/app/pid/timestamp from the
  preceding event; emit rt= event time and dvcpid= in CEF output

* Tue Aug 11 2026 Tamir Suliman <allamiro@gmail.com> - 0.2.1-1
- Fix zipapp package-data loading (dictionary.json path, Python 3.9
  zipimport anchor); add a zipimport regression test

* Tue Aug 11 2026 Tamir Suliman <allamiro@gmail.com> - 0.2.0-1
- Add the CEF field dictionary: 176 keys with producer/consumer scopes
  and 56 source-field aliases applied during normalization
- Default mapping carries the raw line via cs1/cs1Label instead of the
  consumer-only rawEvent key; validation warns on consumer-side keys

* Tue Aug 11 2026 Tamir Suliman <allamiro@gmail.com> - 0.1.6-1
- Fix eleven parser/renderer robustness bugs found by fuzzing: JSON
  dialect routing, kv/rsyslog timestamp aliases, severity resolution
  crashes, Feb 29 handling, tz offsets, non-string JSON scalars
- Add ClusterFuzzLite PR fuzzing, structure-aware harness, seed corpus

* Tue Aug 11 2026 Tamir Suliman <allamiro@gmail.com> - 0.1.5-1
- strftime-templated output paths (hourly/daily files, validated codes)
- syslogcef@.service template unit with per-pipeline conf.d files
- Logrotate snippet for flat CEF archives
- Empty OUTPUT_FILE means stdout; unsplit ${OUTPUT_FILE} in units
- User-defined parsers: --patterns pattern files and register_parser()
- Run the full test suite during the RPM build checks

* Tue Aug 11 2026 Tamir Suliman <allamiro@gmail.com> - 0.1.4-1
- Cap TCP listener buffers; drop flooding connections
- Surface asynchronous Kafka delivery failures; fix EPS edge cases
- Stricter CEF validation: IPv4-only fields, oldFile keys, real
  timestamp parsing
- Correct man page and unit privilege documentation

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
