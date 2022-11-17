#!/bin/bash

if  [ $UID -ne 0 ]
then
    echo "[ERROR] You must run this script as root!"
    exit
fi

sed -i 's/# ucredit = 0/ucredit = -1/g' /etc/security/pwquality.conf
sed -i 's/# lcredit = 0/lcredit = -1/g' /etc/security/pwquality.conf
sed -i 's/# dcredit = 0/dcredit = -1/g' /etc/security/pwquality.conf
sed -i 's/# ocredit = 0/ocredit = -1/g' /etc/security/pwquality.conf
sed -i 's/# difok = 1/difok = 8/g' /etc/security/pwquality.conf
sed -i 's/# minclass = 0/minclass = 4/g' /etc/security/pwquality.conf
sed -i 's/# maxrepeat = 0/maxrepeat = 3/g' /etc/security/pwquality.conf
sed -i 's/# maxclassrepeat = 0/maxrepeat = 4/g' /etc/security/pwquality.conf
sed -i 's/# minlen = 8/minlen = 15/g' /etc/security/pwquality.conf

sed -i 's/PASS_MIN_DAYS\t0/PASS_MIN_DAYS\t1/g' /etc/login.defs
sed -i 's/PASS_MAX_DAYS\t99999/PASS_MAX_DAYS\t60/g' /etc/login.defs

sed -i 's/#PermitEmptyPasswords/PermitEmptyPasswords/g' /etc/ssh/sshd_config
sed -i 's/# PermitEmptyPasswords/PermitEmptyPasswords/g' /etc/ssh/sshd_config
sed -i 's/PermitEmptyPasswords/PermitEmptyPasswords no #/g' /etc/ssh/sshd_config

# V-72225
sed -i 's/#Banner/Banner/g' /etc/ssh/sshd_config
sed -i 's/# Banner/Banner/g' /etc/ssh/sshd_config
sed -i 's/Banner/Banner /etc/issue #/g' /etc/ssh/sshd_config

# V-72239
sed -i 's/#RhostsRSAAuthentication/RhostsRSAAuthentication/g' /etc/ssh/sshd_config
sed -i 's/# RhostsRSAAuthentication/RhostsRSAAuthentication/g' /etc/ssh/sshd_config
sed -i 's/RhostsRSAAuthentication/RhostsRSAAuthentication no #/g' /etc/ssh/sshd_config

# V-72243
sed -i 's/#IgnoreRhosts/IgnoreRhosts/g' /etc/ssh/sshd_config
sed -i 's/# IgnoreRhosts/IgnoreRhosts/g' /etc/ssh/sshd_config
sed -i 's/IgnoreRhosts/IgnoreRhosts yes #/g' /etc/ssh/sshd_config

# V-722245
sed -i 's/#PrintLastLog/PrintLastLog/g' /etc/ssh/sshd_config
sed -i 's/# PrintLastLog/PrintLastLog/g' /etc/ssh/sshd_config
sed -i 's/PrintLastLog/PrintLastLog yes #/g' /etc/ssh/sshd_config

# V-722247
sed -i 's/#PermitRootLogin/PermitRootLogin/g' /etc/ssh/sshd_config
sed -i 's/# PermitRootLogin/PermitRootLogin/g' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin/PermitRootLogin no #/g' /etc/ssh/sshd_config

# V-722249
sed -i 's/#IgnoreUserKnownHosts/IgnoreUserKnownHosts/g' /etc/ssh/sshd_config
sed -i 's/# IgnoreUserKnownHosts/IgnoreUserKnownHosts/g' /etc/ssh/sshd_config
sed -i 's/IgnoreUserKnownHosts/IgnoreUserKnownHosts yes #/g' /etc/ssh/sshd_config

# V-722259
sed -i 's/#GSSAPIAuthentication/GSSAPIAuthentication/g' /etc/ssh/sshd_config
sed -i 's/# GSSAPIAuthentication/GSSAPIAuthentication/g' /etc/ssh/sshd_config
sed -i 's/GSSAPIAuthentication/GSSAPIAuthentication no #/g' /etc/ssh/sshd_config

# V-722261
sed -i 's/#KerberosAuthentication/KerberosAuthentication/g' /etc/ssh/sshd_config
sed -i 's/# KerberosAuthentication/KerberosAuthentication/g' /etc/ssh/sshd_config
sed -i 's/KerberosAuthentication/KerberosAuthentication no #/g' /etc/ssh/sshd_config

# V-722263
sed -i 's/#StrictModes/StrictModes/g' /etc/ssh/sshd_config
sed -i 's/# StrictModes/StrictModes/g' /etc/ssh/sshd_config
sed -i 's/StrictModes/StrictModes yes #/g' /etc/ssh/sshd_config

# V-722265
sed -i 's/#UsePrivilegeSeparation/UsePrivilegeSeparation/g' /etc/ssh/sshd_config
sed -i 's/# UsePrivilegeSeparation/UsePrivilegeSeparation/g' /etc/ssh/sshd_config
sed -i 's/UsePrivilegeSeparation/UsePrivilegeSeparation yes #/g' /etc/ssh/sshd_config

# V-722267
sed -i 's/#Compression/Compression/g' /etc/ssh/sshd_config
sed -i 's/# Compression/Compression/g' /etc/ssh/sshd_config
sed -i 's/Compression/Compression no #/g' /etc/ssh/sshd_config

# V-72275
sed -i "s/.*lastlog.*/session required pam_lastlog.so showfailed/g" /etc/pam.d/login

# V-72303
sed -i "s/.*X11Forwarding.*/X11Forwarding yes/g" /etc/ssh/sshd_config

# V-72309
sed -i "s/.*net\.ipv4\.ip_forward.*/net.ipv4.ip_forward = 0 # SET BY STIG/g" /etc/sysctl.conf

# V-77825
sed -i "s/.*kernel\.randomize_va_space.*/kernel.randomize_va_space=2 # SET BY STIG/g" /etc/sysctl.conf

# V-73159
echo "password required pam_pwquality.so retry=3" >> /etc/pam.d/passwd

sed -i 's/#INACTIVE/INACTIVE/g' /etc/default/useradd
sed -i 's/# INACTIVE/INACTIVE/g' /etc/default/useradd
sed -i 's/INACTIVE/INACTIVE=0 #/g' /etc/default/useradd

sed -i 's/#FAIL_DELAY/FAIL_DELAY/g' /etc/login.defs
sed -i 's/# FAIL_DELAY/FAIL_DELAY/g' /etc/login.defs
sed -i 's/FAIL_DELAY/FAIL_DELAY 4/g' /etc/login.defs

sed -i 's/#UMASK/UMASK/g' /etc/login.defs
sed -i 's/# UMASK/UMASK/g' /etc/login.defs
sed -i 's/UMASK/UMASK 077 #/g' /etc/login.defs

sed -i 's/#CREATE_HOME/CREATE_HOME/g' /etc/login.defs
sed -i 's/# CREATE_HOME/CREATE_HOME/g' /etc/login.defs
sed -i 's/CREATE_HOME/CREATE_HOME yes #/g' /etc/login.defs

# I have not seen this PermitUserEnvironment option set in the default SSH config...
# so add it in "by hand"!
#sudo sed -i 's/PermitUserEnvironment/PermitUserEnvironment no #/g' /etc/ssh/sshd_config
echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config

sed -i 's/#HostbasedAuthentication/HostbasedAuthentication/g' /etc/ssh/sshd_config
sed -i 's/# HostbasedAuthentication/HostbasedAuthentication/g' /etc/ssh/sshd_config
sed -i 's/HostbasedAuthentication/HostbasedAuthentication no #/g' /etc/ssh/sshd_config

apt remove rsh-server ypserv
systemctl disable autofs
systemctl mask ctrl-alt-del.target
systemctl restart ssh.service
