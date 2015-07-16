cfgdir = $(datadir)/vyatta-cfg/templates
opdir = $(datadir)/vyatta-op/templates
sharedir = $(datadir)/hostapd-radius
dictdir = $(datadir)/radius
curverdir = $(sysconfdir)/config-migrate/current
bin_sudo_usersdir = $(bindir)/sudo-users
httpsharedir = $(datadir)/lighttpd-portal
wwwdir = /var/www/captive-portal

vprefix = /opt/vyatta
vsbindir = $(vprefix)/sbin

sbin_SCRIPTS = scripts/vyatta-hostapd-radius.pl \
               scripts/vyatta-hlr_auc_gw.pl \
               scripts/vyatta-radius.pl \
               scripts/vyatta-radius-info.pl \
               scripts/vyatta-lighttpd-portal.pl

bin_sudo_users_SCRIPTS =

curver_DATA =

share_DATA = certs/ca.pem certs/server-key.pem certs/server.pem

dict_DATA = dicts/dictionary \
            dicts/dictionary.base \
            dicts/dictionary.tunnel \
            dicts/dictionary.wispr \
            dicts/dictionary.cisco \
            dicts/dictionary.microsoft

www_DATA = http/index.php http/style.css

www_SCRIPTS = http/authorize.cgi

httpshare_DATA = http/lighttpd.conf

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
  cpio -0pd

install-exec-hook:
	mkdir -p $(DESTDIR)$(cfgdir)
	cd templates-cfg; $(cpiop) $(DESTDIR)$(cfgdir)
	mkdir -p $(DESTDIR)$(opdir)
	cd templates-op; $(cpiop) $(DESTDIR)$(opdir)
