#!/bin/bash

TIMESTAMP="$(date +%s)"
UNAME="$(uname -a | awk -F' ' '{print $1_$3_$4}')"
ARGUMENTS="$@"
ARG_NUM="$#"

BLUE='\e[0;34m'
GREEN='\e[0;32m'
CYAN='\e[0;36m'
RED='\e[0;31m'
LIGHTBLUE='\e[1;34m'
LIGHTGREEN='\e[1;32m'
LIGHTCYAN='\e[1;36m'
LIGHTRED='\e[1;31m'
LIGHTPURPLE='\e[1;35m'
YELLOW='\e[1;33m'
NC='\e[0m'

# Change this to suit your needs
INTERFACE="eth0"

DISABLE_ICMP=1
LIMIT_TTL=1
LIMIT_TTL_HIGH=64
LIMIT_TTL_LOW=63
IPTABLES="$(which iptables)"
SYSTEMD="$(which systemctl)"
PSAD="$(which psad)"
FAILBAN="$(which fail2ban)"

function echo_info ( ) {
    echo -n -e "[${TIMESTAMP}]${GREEN} ${1} ${NC}\n"
}

function echo_warn ( ) {
    echo -n -e "[${TIMESTAMP}]${YELLOW} ${1} ${NC}\n"
}

function echo_fail ( ) {
    echo -n -e "[${TIMESTAMP}]${RED} ${1} ${NC}\n"
}

function echo_cyan ( ) {
    echo -n -e "${LIGHTCYAN}${1}${NC}"
}

function reset_table ( ) {
    echo_info "[ + ] Reset table rules"
    $IPTABLES -P INPUT ACCEPT
    $IPTABLES -P FORWARD ACCEPT
    $IPTABLES -P OUTPUT ACCEPT
    $IPTABLES -t nat -F
    $IPTABLES -t mangle -F
    $IPTABLES -F
    $IPTABLES -X
}

function block_prerouting ( ) {
    echo_info "[ + ] Prerouting blocking"
    echo_info "[ + ] Block INVALID packets"
    $IPTABLES -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP
    echo_info "[ + ] Block weird MSS valued packets"
    $IPTABLES -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
    echo_info "[ + ] Blocking private IP address ranges"
    $IPTABLES -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP
    $IPTABLES -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP
    #$IPTABLES -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP
    $IPTABLES -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP
    #$IPTABLES -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP 
    $IPTABLES -t mangle -A PREROUTING -s 10.0.0.0/8 -j DROP
    $IPTABLES -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP
    $IPTABLES -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP
    $IPTABLES -t mangle -A PREROUTING -s 127.0.0.0/8 -i lo -j DROP
    echo_info "[ + ] Block bogus packets"
    $IPTABLES -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
    $IPTABLES -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
    $IPTABLES -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
    $IPTABLES -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
    $IPTABLES -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
    $IPTABLES -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
    $IPTABLES -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
    $IPTABLES -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
    $IPTABLES -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
    $IPTABLES -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
    $IPTABLES -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
    $IPTABLES -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
    $IPTABLES -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG
    echo_info "[ + ] Blocking non-tcp based nmap scans"
    $IPTABLES -A INPUT -p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
    $IPTABLES -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
    $IPTABLES -A INPUT -p tcp -m tcp --tcp-flags ALL NONE -j DROP
    $IPTABLES -A INPUT -p tcp -m tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
    $IPTABLES -A INPUT -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP
    $IPTABLES -A INPUT -p tcp -m tcp --tcp-flags ACK,FIN FIN -j DROP
    $IPTABLES -A INPUT -p tcp -m tcp --tcp-flags ACK,PSH PSH -j DROP
    $IPTABLES -A INPUT -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP
}

function limit_connections ( ) {
    echo_info "[ + ] Limiting connections per IP"
    $IPTABLES -A INPUT -p tcp --syn -m multiport --dports $@ -m connlimit --connlimit-above 30 -j REJECT --reject-with tcp-reset
}

function limit_ttl_le ( ) {
    echo_info "[ + ] Limiting connections for certain IPs less than TTL"
    $IPTABLES -A INPUT -m ttl --ttl-lt ${1} -j DROP
    $IPTABLES -A OUTPUT -m ttl --ttl-lt ${1} -j DROP
}

function limit_ttl_ge ( ) {
    echo_info "[ + ] Limiting connections for certain IPs greater than TTL"
    $IPTABLES -A INPUT -m ttl --ttl-gt ${1} -j DROP
    $IPTABLES -A OUTPUT -m ttl --ttl-gt ${1} -j DROP
}

function enable_logging ( ) {
    echo_info "[ + ] Create logging for PSAD"
    $IPTABLES -A INPUT -j LOG
    $IPTABLES -A FORWARD -j LOG
    echo_info "[ + ] Creating and setting up fail2ban rules"
    $IPTABLES -N f2b-sshd
    $IPTABLES -A INPUT -p tcp -m multiport --dports 65534 -j f2b-sshd
    $IPTABLES -A f2b-sshd -j RETURN
}

function allow_connections ( ) {
    echo_info "[ + ] Allowing connection to services"
    $IPTABLES -A INPUT -i lo -j ACCEPT -m comment --comment 'Allow connections on local interface: lo'
    $IPTABLES -A INPUT -i ${INTERFACE} -p tcp -m multiport --dports ${1} -m state --state NEW,ESTABLISHED -j ACCEPT
    $IPTABLES -A INPUT -i ${INTERFACE} -p tcp -m multiport --dports ${1} -m state --state ESTABLISHED -j ACCEPT
    $IPTABLES -A OUTPUT -o ${INTERFACE} -p tcp -m multiport --dports ${1} -m state --state NEW,ESTABLISHED -j ACCEPT
    $IPTABLES -A OUTPUT -o ${INTERFACE} -p tcp -m multiport --dports ${1} -m state --state ESTABLISHED -j ACCEPT
}

function disable_icmp ( ) {
    if [[ "${1}" == "1" ]];
    then
        echo_info "[ + ] Deny icmp requests from outside"
        $IPTABLES -A OUTPUT -p icmp --icmp-type echo-request -j DROP
        $IPTABLES -A INPUT -p icmp --icmp-type echo-reply -j DROP
    elif [[ "${1}" == "0" ]];
    then
        echo_info "[ + ] Allow icmp requests from outside"
        $IPTABLES -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
        $IPTABLES -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
    fi
}

function default_drop ( ) {
    echo_info "[ + ] Default to DROP"
    $IPTABLES -A INPUT -j DROP
}

function restart_services ( ) {
    echo_info "[ + ] Resetting services, psad & fail2ban"
    systemctl restart psad.service
    systemctl restart fail2ban.service
    systemctl status psad.service
    systemctl status fail2ban.service
}

function usage ( ) {
    echo_warn """
    ./iptables_run.sh {PORTS}
    - - - - - - - - - - - - -
    PORTS : Like 80,22,53
    """
}

function main ( ) {
    echo_fail "Using ports: ${ARGUMENTS}"

    if [[ "${ARG_NUM}" -ne 1 ]];
    then
        usage
        exit 1
    fi

    if [[ -z "$IPTABLES" ]];
    then
        echo_fail "[ ! ] iptables is not installed"
        exit 1
    fi
    IPTABLES_SAVE="$(which iptables-save)"
    if [[ -z "$IPTABLES_SAVE" ]];
    then
        echo_warn "[ ! ] iptables-save is not installed, no backups available"
    fi

    echo_warn "[ - ] Booting Up Menu..."
    sleep 1
    echo_info "[ - ] Loading Menu [${LIGHTGREEN}########               ${LIGHTRED}](38%)"
    sleep 1
    echo_info "[ - ] Loading Menu [${LIGHTGREEN}################       ${LIGHTRED}](80%)"
    sleep 1
    echo_info "[ - ] Loading Menu [${LIGHTCYAN}#######################${LIGHTRED}](100%)"

    if [[ ! -z "$IPTABLES_SAVE" ]];
    then
        echo_info "[ + ] Backing up current rules"
        $IPTABLES_SAVE > "${UNAME}_${TIMESTAMP}_iptables.bak.log"
    fi

    echo_info "[ + ] Using: $($IPTABLES --version)"
    reset_table
    block_prerouting
    if [[ "${LIMIT_TTL}" == "1" ]];
    then
        limit_ttl_le ${LIMIT_TTL_LOW}
        limit_ttl_ge ${LIMIT_TTL_HIGH}
    fi
    limit_connections ${ARGUMENTS}
    allow_connections ${ARGUMENTS}
    disable_icmp ${DISABLE_ICMP}
    if [[ ! -z "${PSAD} " && ! -z "${FAILBAN}" ]];
    then
        enable_logging
        restart_services
    fi
    default_drop
    echo_warn "$($IPTABLES -L)"
    echo_fail "[ + ] Finished \n"
}

echo ""
main