#!/bin/bash

# Change this to suit your needs
INTERFACE="eth0"
DISABLE_ICMP=1

TIMESTAMP="$(date +%s)"
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
IPTABLES="$(which iptables)"
if [[ -z "$IPTABLES" ]];
then
    echo -n -e "${RED}[ ! ] iptables is not installed${NC}"
    exit 1
fi
IPTABLES_SAVE="$(which iptables-save)"
if [[ -z "$IPTABLES_SAVE" ]];
then
    echo -n -e "${YELLOW}[ ! ] iptables-save is not installed, no backups available${NC}"
fi

function echo_info ( ) {
    echo -n -e "${GREEN} ${1} ${NC}"
}

function echo_warn ( ) {
    echo -n -e "${YELLOW} ${1} ${NC}"
}

function echo_fail ( ) {
    echo -n -e "${RED} ${1} ${NC}"
}

function echo_cyan ( ) {
    echo -n -e "${LIGHTCYAN}${1}${NC}"
}

echo_cyan "[ - ] Booting Up Menu.. \n"
sleep 1
echo_info "[ - ] Loading Menu [${LIGHTGREEN}########                ${LIGHTRED}(38%)\n"
sleep 1
echo_info "[ - ] Loading Menu [${LIGHTGREEN}################         ${LIGHTRED}(80%)\r"
sleep 1
echo_info "[ - ] Loading Menu [${LIGHTCYAN}#######################  ${LIGHTRED}] (100%)\n${GREEN}Finished\n"
sleep 1
if [[ ! -z "$IPTABLES_SAVE" ]];
then
    echo_info"[ + ] Backing up current rules\n"
    $IPTABLES_SAVE > "${TIMESTAMP}_iptables.bak"
fi

function reset_table ( ) {
    echo_info "[+] Reset table rules\n"
    $IPTABLES -P INPUT ACCEPT
    $IPTABLES -P FORWARD ACCEPT
    $IPTABLES -P OUTPUT ACCEPT
    $IPTABLES -t nat -F
    $IPTABLES -t mangle -F
    $IPTABLES -F
    $IPTABLES -X
}

function block_prerouting ( ) {
    echo_info "[ + ] Prerouting blocking\n"
    echo_info "[ + ] Block INVALID packets\n"
    $IPTABLES -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP
    echo_info "[ + ] Block weird MSS valued packets\n"
    $IPTABLES -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
    echo_info "[ + ] Blocking private IP address ranges\n"
    $IPTABLES -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP
    $IPTABLES -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP
    #$IPTABLES -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP
    $IPTABLES -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP
    #$IPTABLES -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP 
    $IPTABLES -t mangle -A PREROUTING -s 10.0.0.0/8 -j DROP
    $IPTABLES -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP
    $IPTABLES -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP
    $IPTABLES -t mangle -A PREROUTING -s 127.0.0.0/8 -i lo -j DROP
    echo_info "[ + ] Block bogus packets\n"
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
    echo -e "${GREEN}[+] Blocking non-tcp based nmap scans ${RESET}"
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
    echo_info "[+] Limiting connections per IP\n"
    $IPTABLES -A INPUT -p tcp --syn -m multiport --dports $@ -m connlimit --connlimit-above 30 -j REJECT --reject-with tcp-reset
}

function enable_logging ( ) {
    echo_info "[+] Create logging for PSAD\n"
    $IPTABLES -A INPUT -j LOG
    $IPTABLES -A FORWARD -j LOG
    echo -e "${GREEN}[+] Creating and setting up fail2ban rules ${RESET}"
    $IPTABLES -N f2b-sshd
    $IPTABLES -A INPUT -p tcp -m multiport --dports 65534 -j f2b-sshd
    $IPTABLES -A f2b-sshd -j RETURN
}

function allow_connections ( ) {
    echo_info "[+] Allowing connection to services\n"
    $IPTABLES -A INPUT -i lo -j ACCEPT -m comment --comment 'Allow connections on local interface: lo'
    $IPTABLES -A INPUT -i ${INTERFACE} -p tcp -m multiport --dports ${1} -m state --state NEW,ESTABLISHED -j ACCEPT
    $IPTABLES -A INPUT -i ${INTERFACE} -p tcp -m multiport --dports ${1} -m state --state ESTABLISHED -j ACCEPT
    $IPTABLES -A OUTPUT -o ${INTERFACE} -p tcp -m multiport --dports ${1} -m state --state NEW,ESTABLISHED -j ACCEPT
    $IPTABLES -A OUTPUT -o ${INTERFACE} -p tcp -m multiport --dports ${1} -m state --state ESTABLISHED -j ACCEPT
}

function disable_icmp ( ) {
    if [[ "${1}" == "1" ]];
    then
        echo_info "[+] Deny icmp requests from outside\n"
        $IPTABLES -A OUTPUT -p icmp --icmp-type echo-request -j DROP
        $IPTABLES -A INPUT -p icmp --icmp-type echo-reply -j DROP
    elif [[ "${1}" == "0" ]];
    then
        echo_info "[+] Allow icmp requests from outside\n"
        $IPTABLES -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
        $IPTABLES -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
    fi
}

function default_drop ( ) {
    echo_info "[+] Default to DROP\n"
    $IPTABLES -A INPUT -j DROP
}

function restart_services ( ) {
    echo_info "[+] Resetting services, psad & fail2ban\n"
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

ARGUMENTS="$@"

if [[ "$#" -ne 2 ]];
then
    usage
    exit 1
fi

echo_info "[+] Using: $($IPTABLES --version)"
reset_table
block_prerouting
limit_connections ${ARGUMENTS}
allow_connections ${ARGUMENTS}
disable_icmp ${DISABLE_ICMP}
echo_warn "$($IPTABLES -L)"
echo_fail "[+] Finished \n"
