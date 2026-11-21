#!/usr/bin/env bash
# Servidor de mail do site de Lisboa: Postfix + Dovecot + SpamAssassin, com
# agente Wazuh (grupo "mail": /var/log/mail.log).
source "$(dirname "$0")/lib.sh"

c=lis-mail
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

log "$c"
launch "$c"
incus exec "$c" -- sh -c "echo 'postfix postfix/main_mailer_type select Local only' | debconf-set-selections &&
    echo 'postfix postfix/mailname string $c.incus' | debconf-set-selections"
apt_install "$c" "postfix dovecot-imapd dovecot-pop3d spamassassin spamd spamc mailutils rsyslog iptables"

render "$ROOT/mail/main.cf" HOST="$c" > "$tmp"
push "$tmp" "$c/etc/postfix/main.cf"
ip=$(incus exec "$c" -- hostname -I | awk '{print $1}')
render "$ROOT/mail/local.cf" IP="$ip" > "$tmp"
push "$tmp" "$c/etc/spamassassin/local.cf"
push "$ROOT/mail/header_checks" "$c/etc/postfix/header_checks"
push "$ROOT/mail/spamfilter" "$c/usr/local/bin/spamfilter"

incus exec "$c" -- sh -c '
    set -e
    chmod 755 /usr/local/bin/spamfilter
    # main.cf tem de ser legivel pelo utilizador spamfilter: o sendmail da
    # re-injecao corre como esse utilizador e abre o main.cf (senao: deferred).
    chown root:root /etc/postfix/main.cf /etc/postfix/header_checks /etc/spamassassin/local.cf
    chmod 644 /etc/postfix/main.cf /etc/postfix/header_checks /etc/spamassassin/local.cf
    useradd --system --create-home --home-dir /var/lib/spamfilter --shell /usr/sbin/nologin spamfilter 2>/dev/null || true
    useradd --create-home --shell /bin/bash alice 2>/dev/null || true
    useradd --create-home --shell /bin/bash bob 2>/dev/null || true

    # Todo o correio recebido por SMTP passa pelo filtro
    postconf -M "smtp/inet=smtp inet n - n - - smtpd -o content_filter=spamfilter:dummy"
    postconf -M "spamfilter/unix=spamfilter unix - n n - 10 pipe flags=Rq user=spamfilter null_sender= argv=/usr/local/bin/spamfilter \${client_address} \${sender} \${recipient}"

    sed -i "s|^OPTIONS=.*|OPTIONS=\"--create-prefs --max-children 5 --helper-home-dir\"|" /etc/default/spamd
    newaliases
    postfix check
    systemctl enable --now spamd rsyslog
    systemctl restart spamd postfix
'
install_wazuh_agent "$c" mail
