Name:		pam_mariadb
Summary:	PAM module for authentication with MariaDB data
Version:	0.1
Release:	1%{?dist}
License:	MIT
URL:		https://github.com/eriklundin/pam_mariadb
Source:		https://github.com/eriklundin/pam_mariadb/archive/v%{version}.tar.gz#/%{name}-%{version}.tar.gz
BuildRequires:	gcc, mariadb-devel, pam-devel, openssl-devel
Requires:	pam

%description
A PAM module for authentication with user information from a MariaDB database.

%prep
%setup -q

%build
%{__make}

%install
%{__make} install DESTDIR=%{buildroot}

%files
%doc LICENSE README.md
%{_libdir}/security/%{name}.so

%changelog
* Sun Jan 01 2017 Erik Lundin <erik at coretech dot se>
- Initial package
