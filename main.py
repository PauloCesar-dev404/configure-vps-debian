import glob
import os
import platform
import subprocess
import sys
import time

import colorama
import requests
from colorama import init, Fore, Style

# Inicializa o colorama
init(autoreset=True)


def print_info(message):
    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} {message}")


def print_success(message):
    print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {message}")


def print_error(message):
    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {message}")


class Configure:

    def __init__(self, data_base, pass_user_data_base, user_data_base, data_base_host='localhost') -> None:
        self.data_base = data_base
        self.data_base_host = data_base_host
        self.user_data_base = user_data_base
        self.pass_user = pass_user_data_base

    def install_wordpress(self, data_base, user_data_base, pass_user_data_base, data_base_host='localhost'):

        """Instala o WordPress e todos os plugins necessários no Linux. O Apache deve estar configurado e o banco de
        dados também."""
        try:
            # Instala pacotes necessários
            print_info("Instalando pacotes PHP necessários...")
            subprocess.run(
                ["apt", "install", "-y", "php", "libapache2-mod-php", "php-mysql", "php-curl", "php-gd", "php-mbstring",
                 "php-xml", "php-xmlrpc", "php-intl", "php-zip"], check=True)
            print_success("Pacotes PHP instalados com sucesso.")

            # Navega até o diretório de instalação
            print_info("Navegando para o diretório de instalação...")
            os.chdir('/var/www/html')

            # Remove todos os arquivos e diretórios no diretório atual
            print_info("Removendo arquivos existentes no diretório de instalação...")
            subprocess.run(["rm", "-rf", "/var/www/html/*"], check=True)
            print_success("Diretório limpo.")

            print(f"{colorama.Fore.LIGHTCYAN_EX}Baixando WordPress...", end=" ")
            response = requests.get('https://wordpress.org/latest.tar.gz', stream=True)
            with open('latest.tar.gz', 'wb') as f:
                f.write(response.content)
            print(f" {colorama.Fore.LIGHTGREEN_EX}Baixado com sucesso!{colorama.Style.RESET_ALL}")

            print_info("Extraindo WordPress...")
            subprocess.run(["tar", "xvf", "latest.tar.gz"], check=True)
            subprocess.run(["rm", "latest.tar.gz"], check=True)
            print_success("WordPress extraído.")

            # Move arquivos do diretório wordpress para o diretório atual
            print_info("Movendo arquivos do WordPress para o diretório atual...")
            wordpress_files = glob.glob('/var/www/html/wordpress/*')
            for file in wordpress_files:
                subprocess.run(["mv", file, "."], check=True)
            subprocess.run(["rmdir", "/var/www/html/wordpress"], check=True)
            print_success("Arquivos movidos com sucesso.")

            # Copia e configura arquivos
            print_info("Copiando e configurando arquivos de configuração do WordPress...")
            subprocess.run(["cp", "-v", "wp-config-sample.php", "wp-config.php"], check=True)
            subprocess.run(["mkdir", "-v", "wp-content/upgrade"], check=True)
            print_success("Arquivos configurados.")

            # Altera permissões
            print_info("Alterando permissões de arquivos e diretórios...")
            subprocess.run(["chown", "-R", "www-data:www-data", "."], check=True)
            subprocess.run(["find", ".", "-type", "f", "-exec", "chmod", "640", "{}", ";"], check=True)
            subprocess.run(["find", ".", "-type", "d", "-exec", "chmod", "750", "{}", ";"], check=True)
            print_success("Permissões alteradas.")

            # Obtém tokens do WordPress
            print_info("Obtendo tokens de autenticação do WordPress...")
            response = requests.get("https://api.wordpress.org/secret-key/1.1/salt/")
            tokens = response.text
            print_success("Tokens de autenticação obtidos.")
            # Cria o wp-config.php com as configurações
            wp_config_php = f"""<?php
                /**
                * The base configuration for WordPress
                *
                * The wp-config.php creation script uses this file during the installation.
                * You don't have to use the website, you can copy this file to "wp-config.php"
                * and fill in the values.
                *
                * This file contains the following configurations:
                *
                * * Database settings
                * * Secret keys
                * * Database table prefix
                * * ABSPATH
                *
                * @link https://developer.wordpress.org/advanced-administration/wordpress/wp-config/
                *
                * @package WordPress
                */

                // ** Database settings - You can get this info from your web host ** //
                /** The name of the database for WordPress */
                define( 'DB_NAME', '{data_base}' );

                /** Database username */
                define( 'DB_USER', '{user_data_base}' );

                /** Database password */
                define( 'DB_PASSWORD', '{pass_user_data_base}' );

                /** Database hostname */
                define( 'DB_HOST', '{data_base_host}' );

                /** Database charset to use in creating database tables. */
                define( 'DB_CHARSET', 'utf8' );

                /** The database collate type. Don't change this if in doubt. */
                define( 'DB_COLLATE', '' );

                define('FS_METHOD','direct');

                /**#@+
                * Authentication unique keys and salts.
                *
                * Change these to different unique phrases! You can generate these using
                * the {{@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}}.
                *
                * You can change these at any point in time to invalidate all existing cookies.
                * This will force all users to have to log in again.
                *
                * @since 2.6.0
                */

                {tokens}

                /**#@-*/

                /**
                * WordPress database table prefix.
                *
                * You can have multiple installations in one database if you give each
                * a unique prefix. Only numbers, letters, and underscores please!
                */
                $table_prefix = 'wp_';

                /**
                * For developers: WordPress debugging mode.
                *
                * Change this to true to enable the display of notices during development.
                * It is strongly recommended that plugin and theme developers use WP_DEBUG
                * in their development environments.
                *
                * For information on other constants that can be used for debugging,
                * visit the documentation.
                *
                * @link https://developer.wordpress.org/advanced-administration/debug/debug-wordpress/
                */
                define( 'WP_DEBUG', false );

                /* Add any custom values between this line and the "stop editing" line. */

                /* That's all, stop editing! Happy publishing. */

                /** Absolute path to the WordPress directory. */
                if ( ! defined( 'ABSPATH' ) ) {{
                        define( 'ABSPATH', __DIR__ . '/' );
                }}

                /** Sets up WordPress vars and included files. */
                require_once ABSPATH . 'wp-settings.php';"""

            with open("wp-config.php", "w") as wp_config_file:
                wp_config_file.write(wp_config_php)
                print_success("arquivo de wp-config.php configurado...")

        except subprocess.CalledProcessError as e:
            print(f"An error occurred: {e}")

        except requests.RequestException as e:
            print(f"An error occurred while downloading WordPress: {e}")

    @staticmethod
    def install_apache():
        """instala o pache e configura na vps"""
        print_info("Atualizando sistema...")
        subprocess.run(['apt', 'update', ], check=True)
        print_info("Baixando Apache2...")
        subprocess.run(['apt', 'install', 'apache2'], check=True)
        apache2_conf = r"""# This is the main Apache server configuration file.  It contains the
# configuration directives that give the server its instructions.
# See http://httpd.apache.org/docs/2.4/ for detailed information about
# the directives and /usr/share/doc/apache2/README.Debian about Debian specific
# hints.
#
#
# Summary of how the Apache 2 configuration works in Debian:
# The Apache 2 web server configuration in Debian is quite different to
# upstream's suggested way to configure the web server. This is because Debian's
# default Apache2 installation attempts to make adding and removing modules,
# virtual hosts, and extra configuration directives as flexible as possible, in
# order to make automating the changes and administering the server as easy as
# possible.

# It is split into several files forming the configuration hierarchy outlined
# below, all located in the /etc/apache2/ directory:
#
#	/etc/apache2/
#	|-- apache2.conf
#	|	`--  ports.conf
#	|-- mods-enabled
#	|	|-- *.load
#	|	`-- *.conf
#	|-- conf-enabled
#	|	`-- *.conf
# 	`-- sites-enabled
#	 	`-- *.conf
#
#
# * apache2.conf is the main configuration file (this file). It puts the pieces
#   together by including all remaining configuration files when starting up the
#   web server.
#
# * ports.conf is always included from the main configuration file. It is
#   supposed to determine listening ports for incoming connections which can be
#   customized anytime.
#
# * Configuration files in the mods-enabled/, conf-enabled/ and sites-enabled/
#   directories contain particular configuration snippets which manage modules,
#   global configuration fragments, or virtual host configurations,
#   respectively.
#
#   They are activated by symlinking available configuration files from their
#   respective *-available/ counterparts. These should be managed by using our
#   helpers a2enmod/a2dismod, a2ensite/a2dissite and a2enconf/a2disconf. See
#   their respective man pages for detailed information.
#
# * The binary is called apache2. Due to the use of environment variables, in
#   the default configuration, apache2 needs to be started/stopped with
#   /etc/init.d/apache2 or apache2ctl. Calling /usr/bin/apache2 directly will not
#   work with the default configuration.


# Global configuration
#

#
# ServerRoot: The top of the directory tree under which the server's
# configuration, error, and log files are kept.
#
# NOTE!  If you intend to place this on an NFS (or otherwise network)
# mounted filesystem then please read the Mutex documentation (available
# at <URL:http://httpd.apache.org/docs/2.4/mod/core.html#mutex>);
# you will save yourself a lot of trouble.
#
# Do NOT add a slash at the end of the directory path.
#
#ServerRoot "/etc/apache2"

#
# The accept serialization lock file MUST BE STORED ON A LOCAL DISK.
#
#Mutex file:${APACHE_LOCK_DIR} default

#
# The directory where shm and other runtime files will be stored.
#

DefaultRuntimeDir ${APACHE_RUN_DIR}

#
# PidFile: The file in which the server should record its process
# identification number when it starts.
# This needs to be set in /etc/apache2/envvars
#
PidFile ${APACHE_PID_FILE}

#
# Timeout: The number of seconds before receives and sends time out.
#
Timeout 40

#
# KeepAlive: Whether or not to allow persistent connections (more than
# one request per connection). Set to "Off" to deactivate.
#
KeepAlive On

#
# MaxKeepAliveRequests: The maximum number of requests to allow
# during a persistent connection. Set to 0 to allow an unlimited amount.
# We recommend you leave this number high, for maximum performance.
#
MaxKeepAliveRequests 50

#
# KeepAliveTimeout: Number of seconds to wait for the next request from the
# same client on the same connection.
#
KeepAliveTimeout 5


# These need to be set in /etc/apache2/envvars
User ${APACHE_RUN_USER}
Group ${APACHE_RUN_GROUP}

#
# HostnameLookups: Log the names of clients or just their IP addresses
# e.g., www.apache.org (on) or 204.62.129.132 (off).
# The default is off because it'd be overall better for the net if people
# had to knowingly turn this feature on, since enabling it means that
# each client request will result in AT LEAST one lookup request to the
# nameserver.
#
HostnameLookups Off

# ErrorLog: The location of the error log file.
# If you do not specify an ErrorLog directive within a <VirtualHost>
# container, error messages relating to that virtual host will be
# logged here.  If you *do* define an error logfile for a <VirtualHost>
# container, that host's errors will be logged there and not here.
#
ErrorLog ${APACHE_LOG_DIR}/error.log

#
# LogLevel: Control the severity of messages logged to the error_log.
# Available values: trace8, ..., trace1, debug, info, notice, warn,
# error, crit, alert, emerg.
# It is also possible to configure the log level for particular modules, e.g.
# "LogLevel info ssl:warn"
#
LogLevel warn

# Include module configuration:
IncludeOptional mods-enabled/*.load
IncludeOptional mods-enabled/*.conf

# Include list of ports to listen on
Include ports.conf


# Sets the default security model of the Apache2 HTTPD server. It does
# not allow access to the root filesystem outside of /usr/share and /var/www.
# The former is used by web applications packaged in Debian,
# the latter may be used for local directories served by the web server. If
# your system is serving content from a sub-directory in /srv you must allow
# access here, or in any related virtual host.
<Directory />
Options FollowSymLinks
AllowOverride None
Require all denied
</Directory>

<Directory /usr/share>
AllowOverride None
Require all granted
</Directory>

<Directory /var/www/>
Options -FollowSymLinks
Options -Indexes
Options -ExecCGI	
AllowOverride All
Require all granted
</Directory>

#<Directory /srv/>
#	Options Indexes FollowSymLinks
#	AllowOverride None
#	Require all granted
#</Directory>




# AccessFileName: The name of the file to look for in each directory
# for additional configuration directives.  See also the AllowOverride
# directive.
#
AccessFileName .htaccess

#
# The following lines prevent .htaccess and .htpasswd files from being
# viewed by Web clients.
#
<FilesMatch "^\.ht">
Require all denied
</FilesMatch>


#
# The following directives define some format nicknames for use with
# a CustomLog directive.
#
# These deviate from the Common Log Format definitions in that they use %O
# (the actual bytes sent including headers) instead of %b (the size of the
# requested file), because the latter makes it impossible to detect partial
# requests.
#
# Note that the use of %{X-Forwarded-For}i instead of %h is not recommended.
# Use mod_remoteip instead.
#
LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" vhost_combined
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%h %l %u %t \"%r\" %>s %O" common
LogFormat "%{Referer}i -> %U" referer
LogFormat "%{User-agent}i" agent

# Include of directories ignores editors' and dpkg's backup files,
# see README.Debian for details.

# Include generic snippets of statements
IncludeOptional conf-enabled/*.conf

# Include the virtual host configurations:
IncludeOptional sites-enabled/*.conf
"""
        security_conf = """
# Changing the following options will not really affect the security of the
# server, but might make attacks slightly more difficult in some cases.

#
# ServerTokens
# This directive configures what you return as the Server HTTP response
# Header. The default is 'Full' which sends information about the OS-Type
# and compiled in modules.
# Set to one of:  Full | OS | Minimal | Minor | Major | Prod
# where Full conveys the most information, and Prod the least.
ServerTokens Prod
#ServerTokens OS
#ServerTokens Full

#
# Optionally add a line containing the server version and virtual host
# name to server-generated pages (internal error documents, FTP directory
# listings, mod_status and mod_info output etc., but not CGI generated
# documents or custom error documents).
# Set to "EMail" to also include a mailto: link to the ServerAdmin.
# Set to one of:  On | Off | EMail
ServerSignature Off
#ServerSignature On

#
# Allow TRACE method
#
# Set to "extended" to also reflect the request body (only for testing and
# diagnostic purposes).
#
# Set to one of:  On | Off | extended
TraceEnable Off
#TraceEnable On

#
# Forbid access to version control directories
#
# If you use version control systems in your document root, you should
# probably deny access to their directories.
#
# Examples:
#
#RedirectMatch 404 /\\.git
#RedirectMatch 404 /\\.svn

#
# Setting this header will prevent MSIE from interpreting files as something
# else than declared by the content type in the HTTP headers.
# Requires mod_headers to be enabled.
#
#Header set X-Content-Type-Options: "nosniff"

#
# Setting this header will prevent other sites from embedding pages from this
# site as frames. This defends against clickjacking attacks.
# Requires mod_headers to be enabled.
#
#Header set Content-Security-Policy "frame-ancestors 'self';"
"""
        # Caminhos dos arquivos de configuração
        path1 = "/etc/apache2/apache2.conf"
        path2 = "/etc/apache2/conf-available/security.conf"
        print_info("removendo files origem...")
        subprocess.run(['rm', '-f', path1], check=True)
        subprocess.run(['rm', '-f', path2], check=True)
        print_success("limpos....")
        # Escreve as configurações no arquivo apache2.conf
        try:
            with open(path1, 'w') as file1:
                file1.write(apache2_conf)
            print_success(f"Arquivo de configuração principal {path1} atualizado com sucesso.")
        except PermissionError:
            print_error(f"Permissão negada ao tentar escrever em {path1}.")

        # Escreve as configurações no arquivo security.conf
        try:
            with open(path2, 'w') as file2:
                file2.write(security_conf)
            print_success(f"Arquivo de configuração de segurança {path2} atualizado com sucesso.")
        except PermissionError:
            print_error(f"Permissão negada ao tentar escrever em {path2}.")

        # Reinicia o Apache para aplicar as novas configurações
        subprocess.run(['a2enmod', 'rewrite'], check=True)
        subprocess.run(['systemctl', 'restart', 'apache2'], check=True)
        print_success("Serviço Apache reiniciado com sucesso.")

    @staticmethod
    def config_ssh(port=22):
        sshd_conf = f"""# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/local/bin:/usr/bin:/bin:/usr/games

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

Include /etc/ssh/sshd_config.d/*.conf

Port {port}
#AddressFamily any# This is the sshd server system-wide configuration file.  See

#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
LogLevel INFO

# Authentication:

#LoginGraceTime 2m
#StrictModes yes
MaxAuthTries 3
MaxSessions 3

#PubkeyAuthentication yes

# Expect .ssh/authorized_keys2 to be disregarded by default in future.
#AuthorizedKeysFile	.ssh/authorized_keys .ssh/authorized_keys2

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
#PasswordAuthentication no
PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
KbdInteractiveAuthentication no

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the KbdInteractiveAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via KbdInteractiveAuthentication may bypass
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and KbdInteractiveAuthentication to 'no'.
UsePAM yes

#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
X11Forwarding no
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
PrintMotd no
#PrintLastLog yes
#TCPKeepAlive yes
#PermitUserEnvironment no
#Compression delayed
ClientAliveInterval 0
ClientAliveCountMax 3
#UseDNS no
#PidFile /run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
Banner none

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

# override default of no subsystems
Subsystem	sftp	/usr/lib/openssh/sftp-server

# CONFIG PauloCesar-dev404
ClientAliveInterval 400
PermitRootLogin no



"""
        print_info("atualizando ou baixando ssh")
        subprocess.run(['apt', 'install', 'ssh'], check=True)
        path = "/etc/ssh/sshd_.conf"
        print_info("removendo files de conf...")
        subprocess.run(['rm', '-f', path], check=True)
        try:
            with open(path, 'w') as file2:
                file2.write(sshd_conf)
            print_success(f"Arquivo de configuração de segurança {path} atualizado com sucesso.")
        except PermissionError:
            print_error(f"Permissão negada ao tentar escrever em {path}.")

        subprocess.run(['systemctl', 'restart', 'ssh'], check=True)

    @staticmethod
    def config_fail2ban(ssh_port=22):
        """configura o fail2ban"""

        fail2ban_local = """# Fail2Ban main configuration file
#
# Comments: use '#' for comment lines and ';' (following a space) for inline comments
#
# Changes:  in most of the cases you should not modify this
#           file, but provide customizations in fail2ban.local file, e.g.:
#
# [DEFAULT]
# loglevel = DEBUG
#

[DEFAULT]

# Option: loglevel
# Notes.: Set the log level output.
#         CRITICAL
#         ERROR
#         WARNING
#         NOTICE
#         INFO
#         DEBUG
# Values: [ LEVEL ]  Default: INFO
#
loglevel = INFO

# Option: logtarget
# Notes.: Set the log target. This could be a file, SYSTEMD-JOURNAL, SYSLOG, STDERR or STDOUT.
#         Only one log target can be specified.
#         If you change logtarget from the default value and you are
#         using logrotate -- also adjust or disable rotation in the
#         corresponding configuration file
#         (e.g. /etc/logrotate.d/fail2ban on Debian systems)
# Values: [ STDOUT | STDERR | SYSLOG | SYSOUT | SYSTEMD-JOURNAL | FILE ]  Default: STDERR
#
logtarget = /var/log/fail2ban.log

# Option: syslogsocket
# Notes: Set the syslog socket file. Only used when logtarget is SYSLOG
#        auto uses platform.system() to determine predefined paths
# Values: [ auto | FILE ]  Default: auto
syslogsocket = auto

# Option: socket
# Notes.: Set the socket file. This is used to communicate with the daemon. Do
#         not remove this file when Fail2ban runs. It will not be possible to
#         communicate with the server afterwards.
# Values: [ FILE ]  Default: /var/run/fail2ban/fail2ban.sock
#
socket = /var/run/fail2ban/fail2ban.sock

# Option: pidfile
# Notes.: Set the PID file. This is used to store the process ID of the
#         fail2ban server.
# Values: [ FILE ]  Default: /var/run/fail2ban/fail2ban.pid
#
pidfile = /var/run/fail2ban/fail2ban.pid

# Option: allowipv6
# Notes.: Allows IPv6 interface:
#         Default: auto
# Values: [ auto yes (on, true, 1) no (off, false, 0) ] Default: auto
#allowipv6 = auto

# Options: dbfile
# Notes.: Set the file for the fail2ban persistent data to be stored.
#         A value of ":memory:" means database is only stored in memory 
#         and data is lost when fail2ban is stopped.
#         A value of "None" disables the database.
# Values: [ None :memory: FILE ] Default: /var/lib/fail2ban/fail2ban.sqlite3
dbfile = /var/lib/fail2ban/fail2ban.sqlite3

# Options: dbpurgeage
# Notes.: Sets age at which bans should be purged from the database
# Values: [ SECONDS ] Default: 86400 (24hours)
dbpurgeage = 1d

# Options: dbmaxmatches
# Notes.: Number of matches stored in database per ticket (resolvable via 
#         tags <ipmatches>/<ipjailmatches> in actions)
# Values: [ INT ] Default: 10
dbmaxmatches = 10

[Definition]


[Thread]

# Options: stacksize
# Notes.: Specifies the stack size (in KiB) to be used for subsequently created threads,
#         and must be 0 or a positive integer value of at least 32.
# Values: [ SIZE ] Default: 0 (use platform or configured default)
#stacksize = 0
"""
        jail_local = f"""#
# Comments: use '#' for comment lines and ';' (following a space) for inline comments
[INCLUDES]

before = paths-debian.conf

# The DEFAULT allows a global definition of the options. They can be overridden
# in each jail afterwards.

[DEFAULT]

#
# MISCELLANEOUS OPTIONS
#

# "bantime.increment" allows to use database for searching of previously banned ip's to increase a 
# default ban time using special formula, default it is banTime * 1, 2, 4, 8, 16, 32...
#bantime.increment = true

# "bantime.rndtime" is the max number of seconds using for mixing with random time 
# to prevent "clever" botnets calculate exact time IP can be unbanned again:
#bantime.rndtime = 

# "bantime.maxtime" is the max number of seconds using the ban time can reach (doesn't grow further)
#bantime.maxtime = 

# "bantime.factor" is a coefficient to calculate exponent growing of the formula or common multiplier,
# default value of factor is 1 and with default value of formula, the ban time 
# grows by 1, 2, 4, 8, 16 ...
#bantime.factor = 1

# "bantime.formula" used by default to calculate next value of ban time, default value below,
# the same ban time growing will be reached by multipliers 1, 2, 4, 8, 16, 32...
#bantime.formula = ban.Time * (1<<(ban.Count if ban.Count<20 else 20)) * banFactor
#
# more aggressive example of formula has the same values only for factor "2.0 / 2.885385" :
#bantime.formula = ban.Time * math.exp(float(ban.Count+1)*banFactor)/math.exp(1*banFactor)

# "bantime.multipliers" used to calculate next value of ban time instead of formula, corresponding
# previously ban count and given "bantime.factor" (for multipliers default is 1);
# following example grows ban time by 1, 2, 4, 8, 16 ... and if last ban count greater as multipliers count, 
# always used last multiplier (64 in example), for factor '1' and original ban time 600 - 10.6 hours
#bantime.multipliers = 1 2 4 8 16 32 64
# following example can be used for small initial ban time (bantime=60) - it grows more aggressive at begin,
# for bantime=60 the multipliers are minutes and equal: 1 min, 5 min, 30 min, 1 hour, 5 hour, 12 hour, 1 day, 2 day
#bantime.multipliers = 1 5 30 60 300 720 1440 2880

# "bantime.overalljails" (if true) specifies the search of IP in the database will be executed 
# cross over all jails, if false (default), only current jail of the ban IP will be searched
#bantime.overalljails = false

# --------------------

# "ignoreself" specifies whether the local resp. own IP addresses should be ignored
# (default is true). Fail2ban will not ban a host which matches such addresses.
#ignoreself = true

# "ignoreip" can be a list of IP addresses, CIDR masks or DNS hosts. Fail2ban
# will not ban a host which matches an address in this list. Several addresses
# can be defined using space (and/or comma) separator.
#ignoreip = 127.0.0.1/8 ::1

# External command that will take an tagged arguments to ignore, e.g. <ip>,
# and return true if the IP is to be ignored. False otherwise.
#
# ignorecommand = /path/to/command <ip>
ignorecommand =

# "bantime" is the number of seconds that a host is banned.
bantime  = -1

# A host is banned if it has generated "maxretry" during the last "findtime"
# seconds.
findtime  = 4m

# "maxretry" is the number of failures before a host get banned.
maxretry = 5

# "maxmatches" is the number of matches stored in ticket (resolvable via tag <matches> in actions).
maxmatches = %(maxretry)s

backend = auto

# "usedns" specifies if jails should trust hostnames in log
usedns = warn

# "logencoding" specifies the encoding of the log files handled by the jail
#   This is used to decode the lines from the log file.
#   Typical examples:  "ascii", "utf-8"
#
#   auto:   will use the system locale setting
logencoding = auto
# true:  jail will be enabled and log files will get monitored for changes
# false: jail is not enabled
enabled = false


# "mode" defines the mode of the filter (see corresponding filter implementation for more info).
mode = normal

# "filter" defines the filter to use by the jail.
#  By default jails have names matching their filter name
#
filter = %(__name__)s[mode=%(mode)s]


#
# ACTIONS
#

# Some options used for actions

# Destination email address used solely for the interpolations in
# jail.{{conf,local,d/*}} configuration files.
destemail = root@localhost

# Sender email address used solely for some actions
sender = root@<fq-hostname>

# E-mail action. Since 0.8.1 Fail2Ban uses sendmail MTA for the
# mailing. Change mta configuration parameter to mail if you want to
# revert to conventional 'mail'.
mta = sendmail

# Default protocol
protocol = tcp

# Specify chain where jumps would need to be added in ban-actions expecting parameter chain
chain = <known/chain>

# Ports to be banned
# Usually should be overridden in a particular jail
port = 0:65535

# Format of user-agent https://tools.ietf.org/html/rfc7231#section-5.5.3
fail2ban_agent = Fail2Ban/%(fail2ban_version)s

#
# Action shortcuts. To be used to define action parameter

# Default banning action (e.g. iptables, iptables-new,
# iptables-multiport, shorewall, etc) It is used to define
# action_* variables. Can be overridden globally or per
# section within jail.local file
banaction = iptables-multiport
banaction_allports = iptables-allports

# The simplest action to take: ban only
action_ = %(banaction)s[port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]

# ban & send an e-mail with whois report to the destemail.
action_mw = %(action_)s
            %(mta)s-whois[sender="%(sender)s", dest="%(destemail)s", protocol="%(protocol)s", chain="%(chain)s"]

# ban & send an e-mail with whois report and relevant log lines
# to the destemail.
action_mwl = %(action_)s
             %(mta)s-whois-lines[sender="%(sender)s", dest="%(destemail)s", logpath="%(logpath)s", chain="%(chain)s"]

# See the IMPORTANT note in action.d/xarf-login-attack for when to use this action
#
# ban & send a xarf e-mail to abuse contact of IP address and include relevant log lines
# to the destemail.
action_xarf = %(action_)s
             xarf-login-attack[service=%(__name__)s, sender="%(sender)s", logpath="%(logpath)s", port="%(port)s"]

# ban & send a notification to one or more of the 50+ services supported by Apprise.
# See https://github.com/caronc/apprise/wiki for details on what is supported.
#
# You may optionally over-ride the default configuration line (containing the Apprise URLs)
# by using 'apprise[config="/alternate/path/to/apprise.cfg"]' otherwise
# /etc/fail2ban/apprise.conf is sourced for your supported notification configuration.
# action = %(action_)s
#          apprise

# ban IP on CloudFlare & send an e-mail with whois report and relevant log lines
# to the destemail.
action_cf_mwl = cloudflare[cfuser="%(cfemail)s", cftoken="%(cfapikey)s"]
                %(mta)s-whois-lines[sender="%(sender)s", dest="%(destemail)s", logpath="%(logpath)s", chain="%(chain)s"]

# Report block via blocklist.de fail2ban reporting service API
# 
# See the IMPORTANT note in action.d/blocklist_de.conf for when to use this action.
# Specify expected parameters in file action.d/blocklist_de.local or if the interpolation
# `action_blocklist_de` used for the action, set value of `blocklist_de_apikey`
# in your `jail.local` globally (section [DEFAULT]) or per specific jail section (resp. in 
# corresponding jail.d/my-jail.local file).
#
action_blocklist_de  = blocklist_de[email="%(sender)s", service="%(__name__)s", apikey="%(blocklist_de_apikey)s",
agent="%(fail2ban_agent)s"]

# Report ban via abuseipdb.com.
#
# See action.d/abuseipdb.conf for usage example and details.
#
action_abuseipdb = abuseipdb

# Choose default action.  To change, just override value of 'action' with the
# interpolation to the chosen action shortcut (e.g.  action_mw, action_mwl, etc) in jail.local
# globally (section [DEFAULT]) or per specific section
action = %(action_)s


#
# JAILS
#

#
# SSH servers
#

[sshd]

# To use more aggressive sshd modes set filter parameter "mode" in jail.local:
# normal (default), ddos, extra or aggressive (combines all).
# See "tests/files/logs/sshd" or "filter.d/sshd.conf" for usage example and details.
enabled = true
mode   = normal
port    = {ssh_port}
logpath = %(sshd_log)s
backend = %(sshd_backend)s


[dropbear]

port     = {ssh_port}
logpath  = %(dropbear_log)s
backend  = %(dropbear_backend)s


[selinux-ssh]

port     = {ssh_port}
logpath  = %(auditd_log)s


#
# HTTP servers
#

[apache-auth]
enabled = true
port     = http,https
logpath  = %(apache_error_log)s


[apache-badbots]
# Ban hosts which agent identifies spammer robots crawling the web
# for email addresses. The mail outputs are buffered.
enabled = true
port     = http,https
logpath  = %(apache_access_log)s
bantime  = 48h
maxretry = 1


[apache-noscript]
enabled = true
port     = http,https
logpath  = %(apache_error_log)s


[apache-overflows]
enabled = true
port     = http,https
logpath  = %(apache_error_log)s
maxretry = 2


[apache-nohome]

port     = http,https
logpath  = %(apache_error_log)s
maxretry = 2


[apache-botsearch]
enabled = true
port     = http,https
logpath  = %(apache_error_log)s
maxretry = 2


[apache-fakegooglebot]
enabled = true
port     = http,https
logpath  = %(apache_access_log)s
maxretry = 1
ignorecommand = %(fail2ban_confpath)s/filter.d/ignorecommands/apache-fakegooglebot <ip>


[apache-modsecurity]
enabled = true
port     = http,https
logpath  = %(apache_error_log)s
maxretry = 2


[apache-shellshock]
enabled = true
port    = http,https
logpath = %(apache_error_log)s
maxretry = 1


[openhab-auth]

filter = openhab
banaction = %(banaction_allports)s
logpath = /opt/openhab/logs/request.log


# To use more aggressive http-auth modes set filter parameter "mode" in jail.local:
# normal (default), aggressive (combines all), auth or fallback
# See "tests/files/logs/nginx-http-auth" or "filter.d/nginx-http-auth.conf" for usage example and details.
[nginx-http-auth]
# mode = normal
port    = http,https
logpath = %(nginx_error_log)s

# To use 'nginx-limit-req' jail you should have `ngx_http_limit_req_module` 
# and define `limit_req` and `limit_req_zone` as described in nginx documentation
# http://nginx.org/en/docs/http/ngx_http_limit_req_module.html
# or for example see in 'config/filter.d/nginx-limit-req.conf'
[nginx-limit-req]
port    = http,https
logpath = %(nginx_error_log)s

[nginx-botsearch]

port     = http,https
logpath  = %(nginx_error_log)s

[nginx-bad-request]
port    = http,https
logpath = %(nginx_access_log)s

# Ban attackers that try to use PHP's URL-fopen() functionality
# through GET/POST variables. - Experimental, with more than a year
# of usage in production environments.

[php-url-fopen]

port    = http,https
logpath = %(nginx_access_log)s
          %(apache_access_log)s


[suhosin]

port    = http,https
logpath = %(suhosin_log)s


[lighttpd-auth]
# Same as above for Apache's mod_auth
# It catches wrong authentifications
port    = http,https
logpath = %(lighttpd_error_log)s


#
# Webmail and groupware servers
#

[roundcube-auth]

port     = http,https
logpath  = %(roundcube_errors_log)s
# Use following line in your jail.local if roundcube logs to journal.
#backend = %(syslog_backend)s


[openwebmail]

port     = http,https
logpath  = /var/log/openwebmail.log


[horde]

port     = http,https
logpath  = /var/log/horde/horde.log


[groupoffice]

port     = http,https
logpath  = /home/groupoffice/log/info.log


[sogo-auth]
# Monitor SOGo groupware server
# without proxy this would be:
# port    = 20000
port     = http,https
logpath  = /var/log/sogo/sogo.log


[tine20]

logpath  = /var/log/tine20/tine20.log
port     = http,https


#
# Web Applications
#
#

[drupal-auth]

port     = http,https
logpath  = %(syslog_daemon)s
backend  = %(syslog_backend)s

[guacamole]

port     = http,https
logpath  = /var/log/tomcat*/catalina.out
#logpath  = /var/log/guacamole.log

[monit]
#Ban clients brute-forcing the monit gui login
port = 2812
logpath  = /var/log/monit
           /var/log/monit.log


[webmin-auth]

port    = 10000
logpath = %(syslog_authpriv)s
backend = %(syslog_backend)s


[froxlor-auth]

port    = http,https
logpath  = %(syslog_authpriv)s
backend  = %(syslog_backend)s


#
# HTTP Proxy servers
#
#

[squid]

port     =  80,443,3128,8080
logpath = /var/log/squid/access.log


[3proxy]

port    = 3128
logpath = /var/log/3proxy.log


#
# FTP servers
#


[proftpd]

port     = ftp,ftp-data,ftps,ftps-data
logpath  = %(proftpd_log)s
backend  = %(proftpd_backend)s


[pure-ftpd]

port     = ftp,ftp-data,ftps,ftps-data
logpath  = %(pureftpd_log)s
backend  = %(pureftpd_backend)s


[gssftpd]

port     = ftp,ftp-data,ftps,ftps-data
logpath  = %(syslog_daemon)s
backend  = %(syslog_backend)s


[wuftpd]

port     = ftp,ftp-data,ftps,ftps-data
logpath  = %(wuftpd_log)s
backend  = %(wuftpd_backend)s


[vsftpd]
# or overwrite it in jails.local to be
# logpath = %(syslog_authpriv)s
# if you want to rely on PAM failed login attempts
# vsftpd's failregex should match both of those formats
port     = ftp,ftp-data,ftps,ftps-data
logpath  = %(vsftpd_log)s


#
# Mail servers
#

# ASSP SMTP Proxy Jail
[assp]

port     = smtp,465,submission
logpath  = /root/path/to/assp/logs/maillog.txt


[courier-smtp]

port     = smtp,465,submission
logpath  = %(syslog_mail)s
backend  = %(syslog_backend)s


[postfix]
# To use another modes set filter parameter "mode" in jail.local:
mode    = more
port    = smtp,465,submission
logpath = %(postfix_log)s
backend = %(postfix_backend)s


[postfix-rbl]

filter   = postfix[mode=rbl]
port     = smtp,465,submission
logpath  = %(postfix_log)s
backend  = %(postfix_backend)s
maxretry = 1


[sendmail-auth]

port    = submission,465,smtp
logpath = %(syslog_mail)s
backend = %(syslog_backend)s


[sendmail-reject]
# To use more aggressive modes set filter parameter "mode" in jail.local:
# normal (default), extra or aggressive
# See "tests/files/logs/sendmail-reject" or "filter.d/sendmail-reject.conf" for usage example and details.
#mode    = normal
port     = smtp,465,submission
logpath  = %(syslog_mail)s
backend  = %(syslog_backend)s


[qmail-rbl]

filter  = qmail
port    = smtp,465,submission
logpath = /service/qmail/log/main/current


# dovecot defaults to logging to the mail syslog facility
# but can be set by syslog_facility in the dovecot configuration.
[dovecot]

port    = pop3,pop3s,imap,imaps,submission,465,sieve
logpath = %(dovecot_log)s
backend = %(dovecot_backend)s


[sieve]

port   = smtp,465,submission
logpath = %(dovecot_log)s
backend = %(dovecot_backend)s


[solid-pop3d]

port    = pop3,pop3s
logpath = %(solidpop3d_log)s


[exim]
# see filter.d/exim.conf for further modes supported from filter:
#mode = normal
port   = smtp,465,submission
logpath = %(exim_main_log)s


[exim-spam]

port   = smtp,465,submission
logpath = %(exim_main_log)s


[kerio]

port    = imap,smtp,imaps,465
logpath = /opt/kerio/mailserver/store/logs/security.log


#
# Mail servers authenticators: might be used for smtp,ftp,imap servers, so
# all relevant ports get banned
#

[courier-auth]

port     = smtp,465,submission,imap,imaps,pop3,pop3s
logpath  = %(syslog_mail)s
backend  = %(syslog_backend)s


[postfix-sasl]

filter   = postfix[mode=auth]
port     = smtp,465,submission,imap,imaps,pop3,pop3s
# You might consider monitoring /var/log/mail.warn instead if you are
# running postfix since it would provide the same log lines at the
# "warn" level but overall at the smaller filesize.
logpath  = %(postfix_log)s
backend  = %(postfix_backend)s


[perdition]

port   = imap,imaps,pop3,pop3s
logpath = %(syslog_mail)s
backend = %(syslog_backend)s


[squirrelmail]

port = smtp,465,submission,imap,imap2,imaps,pop3,pop3s,http,https,socks
logpath = /var/lib/squirrelmail/prefs/squirrelmail_access_log


[cyrus-imap]

port   = imap,imaps
logpath = %(syslog_mail)s
backend = %(syslog_backend)s


[uwimap-auth]

port   = imap,imaps
logpath = %(syslog_mail)s
backend = %(syslog_backend)s


#
#
# DNS servers
#


# !!! WARNING !!!
#   Since UDP is connection-less protocol, spoofing of IP and imitation
#   of illegal actions is way too simple.  Thus enabling of this filter
#   might provide an easy way for implementing a DoS against a chosen
#   victim. See
#    http://nion.modprobe.de/blog/archives/690-fail2ban-+-dns-fail.html
#   Please DO NOT USE this jail unless you know what you are doing.
#
# IMPORTANT: see filter.d/named-refused for instructions to enable logging
# This jail blocks UDP traffic for DNS requests.
# [named-refused-udp]
#
# filter   = named-refused
# port     = domain,953
# protocol = udp
# logpath  = /var/log/named/security.log

# IMPORTANT: see filter.d/named-refused for instructions to enable logging
# This jail blocks TCP traffic for DNS requests.

[named-refused]

port     = domain,953
logpath  = /var/log/named/security.log


[nsd]

port     = 53
action_  = %(default/action_)s[name=%(__name__)s-tcp, protocol="tcp"]
           %(default/action_)s[name=%(__name__)s-udp, protocol="udp"]
logpath = /var/log/nsd.log


#
# Miscellaneous
#

[asterisk]

port     = 5060,5061
action_  = %(default/action_)s[name=%(__name__)s-tcp, protocol="tcp"]
           %(default/action_)s[name=%(__name__)s-udp, protocol="udp"]
logpath  = /var/log/asterisk/messages
maxretry = 10


[freeswitch]

port     = 5060,5061
action_  = %(default/action_)s[name=%(__name__)s-tcp, protocol="tcp"]
           %(default/action_)s[name=%(__name__)s-udp, protocol="udp"]
logpath  = /var/log/freeswitch.log
maxretry = 10


# enable adminlog; it will log to a file inside znc's directory by default.
[znc-adminlog]

port     = 6667
logpath  = /var/lib/znc/moddata/adminlog/znc.log


# To log wrong MySQL access attempts add to /etc/my.cnf in [mysqld] or
# equivalent section:
# log-warnings = 2
#
# for syslog (daemon facility)
# [mysqld_safe]
# syslog
#
# for own logfile
# [mysqld]
# log-error=/var/log/mysqld.log
[mysqld-auth]

port     = 3306
logpath  = %(mysql_log)s
backend  = %(mysql_backend)s


[mssql-auth]
# Default configuration for Microsoft SQL Server for Linux
# See the 'mssql-conf' manpage how to change logpath or port
logpath = /var/opt/mssql/log/errorlog
port = 1433
filter = mssql-auth


# Log wrong MongoDB auth (for details see filter 'filter.d/mongodb-auth.conf')
[mongodb-auth]
# change port when running with "--shardsvr" or "--configsvr" runtime operation
port     = 27017
logpath  = /var/log/mongodb/mongodb.log


# Jail for more extended banning of persistent abusers
# !!! WARNINGS !!!
# 1. Make sure that your loglevel specified in fail2ban.conf/.local
#    is not at DEBUG level -- which might then cause fail2ban to fall into
#    an infinite loop constantly feeding itself with non-informative lines
# 2. Increase dbpurgeage defined in fail2ban.conf to e.g. 648000 (7.5 days)
#    to maintain entries for failed logins for sufficient amount of time
[recidive]

logpath  = /var/log/fail2ban.log
banaction = %(banaction_allports)s
bantime  = 1w
findtime = 1d


# Generic filter for PAM. Has to be used with action which bans all
# ports such as iptables-allports, shorewall

[pam-generic]
# pam-generic filter can be customized to monitor specific subset of 'tty's
banaction = %(banaction_allports)s
logpath  = %(syslog_authpriv)s
backend  = %(syslog_backend)s


[xinetd-fail]

banaction = iptables-multiport-log
logpath   = %(syslog_daemon)s
backend   = %(syslog_backend)s
maxretry  = 2


# stunnel - need to set port for this
[stunnel]

logpath = /var/log/stunnel4/stunnel.log


[ejabberd-auth]

port    = 5222
logpath = /var/log/ejabberd/ejabberd.log


[counter-strike]

logpath = /opt/cstrike/logs/L[0-9]*.log
tcpport = 27030,27031,27032,27033,27034,27035,27036,27037,27038,27039
udpport = 1200,27000,27001,27002,27003,27004,27005,27006,27007,27008,27009,27010,27011,27012,27013,27014,27015
action_  = %(default/action_)s[name=%(__name__)s-tcp, port="%(tcpport)s", protocol="tcp"]
           %(default/action_)s[name=%(__name__)s-udp, port="%(udpport)s", protocol="udp"]

[softethervpn]
port     = 500,4500
protocol = udp
logpath  = /usr/local/vpnserver/security_log/*/sec.log

[gitlab]
port    = http,https
logpath = /var/log/gitlab/gitlab-rails/application.log

[grafana]
port    = http,https
logpath = /var/log/grafana/grafana.log

[bitwarden]
port    = http,https
logpath = /home/*/bwdata/logs/identity/Identity/log.txt

[centreon]
port    = http,https
logpath = /var/log/centreon/login.log

# consider low maxretry and a long bantime
# nobody except your own Nagios server should ever probe nrpe
[nagios]

logpath  = %(syslog_daemon)s     ; nrpe.cfg may define a different log_facility
backend  = %(syslog_backend)s
maxretry = 1


[oracleims]
# see "oracleims" filter file for configuration requirement for Oracle IMS v6 and above
logpath = /opt/sun/comms/messaging64/log/mail.log_current
banaction = %(banaction_allports)s

[directadmin]
logpath = /var/log/directadmin/login.log
port = 2222

[portsentry]
logpath  = /var/lib/portsentry/portsentry.history
maxretry = 1

[pass2allow-ftp]
# this pass2allow example allows FTP traffic after successful HTTP authentication
port         = ftp,ftp-data,ftps,ftps-data
# knocking_url variable must be overridden to some secret value in jail.local
knocking_url = /knocking/
filter       = apache-pass[knocking_url="%(knocking_url)s"]
# access log of the website with HTTP auth
logpath      = %(apache_access_log)s
blocktype    = RETURN
returntype   = DROP
action       = %(action_)s[blocktype=%(blocktype)s, returntype=%(returntype)s,
                        actionstart_on_demand=false, actionrepair_on_unban=true]
bantime      = 1h
maxretry     = 1
findtime     = 1


[murmur]
# AKA mumble-server
port     = 64738
action_  = %(default/action_)s[name=%(__name__)s-tcp, protocol="tcp"]
           %(default/action_)s[name=%(__name__)s-udp, protocol="udp"]
logpath  = /var/log/mumble-server/mumble-server.log


[screensharingd]
# For Mac OS Screen Sharing Service (VNC)
logpath  = /var/log/system.log
logencoding = utf-8

[haproxy-http-auth]
# HAProxy by default doesn't log to file you'll need to set it up to forward
# logs to a syslog server which would then write them to disk.
# See "haproxy-http-auth" filter for a brief cautionary note when setting
# maxretry and findtime.
logpath  = /var/log/haproxy.log

[slapd]
port    = ldap,ldaps
logpath = /var/log/slapd.log

[domino-smtp]
port    = smtp,ssmtp
logpath = /home/domino01/data/IBM_TECHNICAL_SUPPORT/console.log

[phpmyadmin-syslog]
port    = http,https
logpath = %(syslog_authpriv)s
backend = %(syslog_backend)s


[zoneminder]
# Zoneminder HTTP/HTTPS web interface auth
# Logs auth failures to apache2 error log
port    = http,https
logpath = %(apache_error_log)s

[traefik-auth]
# to use 'traefik-auth' filter you have to configure your Traefik instance,
# see `filter.d/traefik-auth.conf` for details and service example.
port    = http,https
logpath = /var/log/traefik/access.log

[scanlogd]
logpath = %(syslog_local0)s
banaction = %(banaction_allports)s

[monitorix]
port	= 8080
logpath = /var/log/monitorix-httpd
"""
        # Instalar Fail2Ban
        print_info("baixando ou atualizando fail2ban.....")
        subprocess.run(['apt', 'install', 'fail2ban', '-y'], check=True)
        # Copiar arquivos de configuração
        print_info("removendo files de conf.....")
        subprocess.run(['cp', '/etc/fail2ban/jail.conf', '/etc/fail2ban/jail.local'], check=True)
        subprocess.run(['cp', '/etc/fail2ban/fail2ban.conf', '/etc/fail2ban/fail2ban.local'], check=True)

        # Atualizar fail2ban.local
        try:
            with open('/etc/fail2ban/fail2ban.local', 'w') as file2:
                file2.write(fail2ban_local)
            print_success("Arquivo fail2ban.local atualizado com sucesso.")
        except PermissionError:
            print_error("Permissão negada para fail2ban.local")

        # Atualizar jail.local
        try:
            with open('/etc/fail2ban/jail.local', 'w') as file2:
                file2.write(jail_local)
            print_success("Arquivo jail.local atualizado com sucesso.")
        except PermissionError:
            print_error("Permissão negada para jail.local")

        # Reiniciar o serviço SSH
        subprocess.run(['systemctl', 'restart', 'ssh'], check=True)


class DatabaseSetup:
    def __init__(self, db_name, db_user, user_password, db_host='localhost'):
        self.db_name = db_name
        self.db_user = db_user
        self.user_password = user_password
        self.db_host = db_host

    def install_mariadb(self):
        """Instala e configura o MariaDB no Debian."""
        try:
            subprocess.run(['apt-get', 'update'], check=True)
            subprocess.run(['apt-get', 'install', '-y', 'mariadb-server'], check=True)
            subprocess.run(['systemctl', 'start', 'mariadb'], check=True)
            subprocess.run(['systemctl', 'enable', 'mariadb'], check=True)
            subprocess.run(['mysql_secure_installation'], check=True)
            print("MariaDB instalado e configurado com sucesso.")
        except subprocess.CalledProcessError as e:
            print(f"Erro durante a instalação ou configuração: {e}")

    def config_database(self):
        """Cria um banco de dados e um usuário no MariaDB."""
        try:
            # Conectando ao MariaDB como root
            command = f"mysql -u root -p{self.user_password} -e "

            # Comandos SQL para criar banco de dados, usuário e conceder permissões
            create_db_command = (f"\"CREATE DATABASE {self.db_name} DEFAULT CHARACTER SET utf8 COLLATE"
                                 f" utf8_unicode_ci;\"")
            create_user_command = (f"\"GRANT ALL ON {self.db_name}.* TO '{self.db_user}'@'{self.db_host}'"
                                   f" IDENTIFIED BY '{self.user_password}';\"")
            flush_privileges_command = "\"FLUSH PRIVILEGES;\""

            # Executando os comandos SQL
            subprocess.run(command + create_db_command, shell=True, check=True)
            subprocess.run(command + create_user_command, shell=True, check=True)
            subprocess.run(command + flush_privileges_command, shell=True, check=True)

            print(f"Banco de dados '{self.db_name}' e usuário '{self.db_user}' criados com sucesso.")
        except subprocess.CalledProcessError as e:
            print(f"Erro ao configurar o banco de dados: {e}")


class UfwConfig:
    def __init__(self):
        subprocess.run(['apt', 'install', 'ufw'], check=True)
        subprocess.run(['ufw', 'default', 'deny', 'incoming'], check=True)
        subprocess.run(['ufw', 'default', 'deny', 'outgoing'], check=True)

    @staticmethod
    def open_port_incoming(port):
        subprocess.run(['ufw', 'allow', f'in {port}'], check=True)

    @staticmethod
    def open_port_outgoing(port):
        subprocess.run(['ufw', 'allow', f' {port}'], check=True)

    @staticmethod
    def close_port_incoming(port):
        subprocess.run(['ufw', 'deny', f'in {port}'], check=True)

    @staticmethod
    def close_port_outgoing(port):
        subprocess.run(['ufw', 'deny', f'out {port}'], check=True)

    @staticmethod
    def close_all_incoming():
        subprocess.run(['ufw', 'default', 'deny', 'incoming'], check=True)

    @staticmethod
    def close_all_outgoing():
        subprocess.run(['ufw', 'default', 'deny', 'outgoing'], check=True)

    @staticmethod
    def reset_config():
        subprocess.run(['ufw', 'reset'], check=True)

    @staticmethod
    def enable_firewall():
        subprocess.run(['ufw', 'enable'], check=True)

    @staticmethod
    def disable_firewall():
        subprocess.run(['ufw', 'disable'], check=True)

    @staticmethod
    def list_rules():
        subprocess.run(['ufw', 'status', 'verbose'], check=True)


def painel():
    print(
        f"{colorama.Fore.LIGHTGREEN_EX}CONFIGURE SEU SERVIDOR DEBIAN COM {colorama.Fore.LIGHTCYAN_EX}"
        f"WORDPRESS{colorama.Fore.LIGHTBLUE_EX} APACHE {colorama.Fore.LIGHTRED_EX}MARIADB"
        f" {colorama.Fore.LIGHTMAGENTA_EX}UFW{colorama.Fore.LIGHTYELLOW_EX} PHP{colorama.Style.RESET_ALL}")


def main_ufw():
    f = UfwConfig()
    while True:
        op = int(input("1. Abrir porta de entrada\n"
                       "2. Abrir porta de saída\n"
                       "3. Fechar porta de entrada\n"
                       "4. Fechar porta de saída\n"
                       "5. Fechar todas entradas\n"
                       "6. Fechar todas saídas\n"
                       "7. Apagar configurações\n"
                       "8. Habilitar firewall\n"
                       "9. Desabilitar firewall\n"
                       "10. Listar regras\n"
                       "0. Sair\n"
                       "Escolha uma opção: "))

        if op == 1:
            port = int(input("\nDigite a porta para abrir na entrada: "))
            f.open_port_incoming(port)
        elif op == 2:
            port = int(input("\nDigite a porta para abrir na saída: "))
            f.open_port_outgoing(port)
        elif op == 3:
            port = int(input("\nDigite a porta para fechar na entrada: "))
            f.close_port_incoming(port)
        elif op == 4:
            port = int(input("\nDigite a porta para fechar na saída: "))
            f.close_port_outgoing(port)
        elif op == 5:
            f.close_all_incoming()
        elif op == 6:
            f.close_all_outgoing()
        elif op == 7:
            f.reset_config()
        elif op == 8:
            f.enable_firewall()
        elif op == 9:
            f.disable_firewall()
        elif op == 10:
            f.list_rules()
        elif op == 0:
            break
        else:
            print("\n\nOpção inválida, tente novamente.")


def main_server():
    while True:
        try:
            opcao = int(input("1. Configurar server\n"
                              "2. Configurar firewall\n"
                              "3. Configurar individualmente\n"
                              "Opção: "))
        except ValueError:
            print("Opção inválida. Por favor, digite um número válido.")
            continue

        if opcao == 1:
            # Validar nome do banco de dados
            while True:
                db_name = input("\nNome do banco de dados: ").strip()
                if db_name:
                    break
                print_error("Nome do banco de dados não pode ser vazio.")

            # Validar nome de usuário
            while True:
                db_user = input(f"\nNome de usuário do {db_name}: ").strip()
                if db_user:
                    break
                print_error("Nome de usuário não pode ser vazio.")

            # Validar senha do usuário
            while True:
                user_password = input(f"\nSenha do usuário {db_user}: ").strip()
                if user_password:
                    break
                print_error("Senha não pode ser vazia.")

            # Instalação e configuração do banco de dados
            db = DatabaseSetup(db_name=db_name,
                               db_user=db_user,
                               user_password=user_password)
            db.install_mariadb()
            db.config_database()

            # Configuração do servidor
            c = Configure(data_base=db_name, pass_user_data_base=user_password,
                          user_data_base=db_user)
            c.install_apache()

            # Validar porta do SSH
            while True:
                try:
                    port_ssh = int(input("\nPorta do SSH: "))
                    if 1 <= port_ssh <= 65535:
                        break
                    print("Porta SSH deve estar entre 1 e 65535.")
                except ValueError:
                    print_error("Porta SSH inválida. Digite um número inteiro válido.")

            c.config_ssh(port_ssh)
            c.config_fail2ban(ssh_port=port_ssh)
            c.install_wordpress(data_base=db_name, user_data_base=db_user, pass_user_data_base=user_password)

        elif opcao == 2:
            main_ufw()
        elif opcao == 3:
            c = Configure(data_base=0, pass_user_data_base=0, user_data_base=0)
            print("qual desejas\n\n1.ssh\n"
                  "1.apache\n"
                  "2.wordpress\n"
                  "3.fail2ban\n"
                  "0. sair\n")
            o = int(input("opção::"))
            if o == 1:
                c.install_apache()
            elif o == 2:
                # Validar nome do banco de dados
                while True:
                    db_name = input("\nNome do banco de dados: ").strip()
                    if db_name:
                        break
                    print_error("Nome do banco de dados não pode ser vazio.")

                # Validar nome de usuário
                while True:
                    db_user = input(f"\nNome de usuário do {db_name}: ").strip()
                    if db_user:
                        break
                    print_error("Nome de usuário não pode ser vazio.")

                # Validar senha do usuário
                while True:
                    user_password = input(f"\nSenha do usuário {db_user}: ").strip()
                    if user_password:
                        break
                    print("Senha não pode ser vazia.")
                c.install_wordpress(data_base=db_name, user_data_base=db_user, pass_user_data_base=user_password)
            elif o == 3:
                c.config_fail2ban()
            elif o == 0:
                break
            else:
                print_error("OPÇÃO INVÁLIDA....")
                continue
        else:
            print_error("Opção inválida. Tente novamente.")
            time.sleep(2)
            continue


if __name__ == "__main__":
    system = platform.system().lower()
    if system != "linux":
        print_error(f"sistema deve ser linux! você estar em um {colorama.Fore.LIGHTYELLOW_EX}"
                    f"{system}{colorama.Style.RESET_ALL}")
        sys.exit(1)
    painel()
    main_server()
