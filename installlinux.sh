#!/bin/bash

# SOCFortress Kickstart script
# Copyright (C) 2021, SOCFortress LLP.
#

## Check if system is based on yum or apt-get
char="."
debug='>> /var/log/wazuh-unattended-installation.log 2>&1'
WAZUH_MAJOR="4.2"
WAZUH_VER="4.2.5"
WAZUH_REV="1"
ow=""
manager="logs.socfortress.co"
password="TNxG9822G=h"
repogpg="https://packages.wazuh.com/key/GPG-KEY-WAZUH"
repobaseurl="https://packages.wazuh.com/4.x"
resources="https://packages.wazuh.com/resources/${WAZUH_MAJOR}"

if [ -n "$(command -v yum)" ]; then
    sys_type="yum"
    sep="-"
elif [ -n "$(command -v zypper)" ]; then
    sys_type="zypper"
    sep="-"
elif [ -n "$(command -v apt-get)" ]; then
    sys_type="apt-get"
    sep="="
fi

## Prints information
logger() {

    now=$(date +'%m/%d/%Y %H:%M:%S')
    case $1 in
        "-e")
            mtype="ERROR:"
            message="$2"
            ;;
        "-w")
            mtype="WARNING:"
            message="$2"
            ;;
        *)
            mtype="INFO:"
            message="$1"
            ;;
    esac
    echo $now $mtype $message
}

rollBack() {

    if [ -z "${uninstall}" ]; then
        logger -w "Cleaning the installation"
    fi

    if [ -n "${wazuhinstalled}" ]; then
        logger -w "Removing the Wazuh agent..."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove wazuh-agent -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove wazuh-agent ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge wazuh-agent -y ${debug}"
        fi
        eval "rm -rf /var/ossec/ ${debug}"
    fi

    if [ -z "${uninstall}" ]; then
        logger -w "Installation cleaned. Check the /var/log/wazuh-unattended-installation.log file to learn more about the issue."
    fi

}

checkArch() {

    arch=$(uname -m)

    if [ ${arch} != "x86_64" ]; then
        logger -e "Uncompatible system. This script must be run on a 64-bit system."
        exit 1;
    fi

}

startService() {

    if [ -n "$(ps -e | egrep ^\ *1\ .*systemd$)" ]; then
        eval "systemctl daemon-reload ${debug}"
        eval "systemctl enable $1.service ${debug}"
        eval "systemctl start $1.service ${debug}"
        if [  "$?" != 0  ]; then
            logger -e "${1^} could not be started."
            rollBack
            exit 1;
        else
            logger "${1^} started"
        fi
    elif [ -n "$(ps -e | egrep ^\ *1\ .*init$)" ]; then
        eval "chkconfig $1 on ${debug}"
        eval "service $1 start ${debug}"
        eval "/etc/init.d/$1 start ${debug}"
        if [  "$?" != 0  ]; then
            logger -e "${1^} could not be started."
            rollBack
            exit 1;
        else
            logger "${1^} started"
        fi
    elif [ -x /etc/rc.d/init.d/$1 ] ; then
        eval "/etc/rc.d/init.d/$1 start ${debug}"
        if [  "$?" != 0  ]; then
            logger -e "${1^} could not be started."
            rollBack
            exit 1;
        else
            logger "${1^} started"
        fi
    else
        logger -e "${1^} could not start. No service manager found on the system."
        exit 1;
    fi

}

## Show script usage
getHelp() {

   echo ""
   echo "Usage: $0 arguments"
   echo -e "\t-o   | --overwrite Overwrite the existing installation"
   echo -e "\t-r   | --uninstall Remove the installation"
   echo -e "\t-v   | --verbose Shows the complete installation output"
   echo -e "\t-i   | --ignore-health-check Ignores the health-check"
   echo -e "\t-h   | --help Shows help"
   exit 1 # Exit script after printing help

}

## Install the required packages for the installation
installPrerequisites() {
    logger "Installing all necessary utilities for the installation..."

    if [ ${sys_type} == "yum" ]; then
        eval "yum install curl unzip wget libcap epel-release -y ${debug}"
        eval "amazon-linux-extras install epel -y ${debug}"
        eval "curl -L https://pkg.osquery.io/rpm/GPG | tee /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery"
        eval "yum-config-manager --add-repo https://pkg.osquery.io/rpm/osquery-s3-rpm.repo"
        eval "yum-config-manager --enable osquery-s3-rpm"
        eval "yum install epel-release yum-plugin-copr -y"
        eval "yum copr enable @oisf/suricata-6.0 -y"
    elif [ ${sys_type} == "zypper" ]; then
        eval "zypper -n install curl unzip wget ${debug}"
        eval "zypper -n install libcap-progs ${debug} || zypper -n install libcap2 ${debug}"
    elif [ ${sys_type} == "apt-get" ]; then
        eval "apt-get update -q $debug"
        eval "apt-get install apt-transport-https curl unzip wget libcap2-bin epel-release -y ${debug}"
        eval "export OSQUERY_KEY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B"
        eval "apt-key adv --keyserver keyserver.ubuntu.com --recv-keys $OSQUERY_KEY"
        eval "add-apt-repository 'deb [arch=amd64] https://pkg.osquery.io/deb deb main'"
        eval "apt-get install auditd -y"
        eval "add-apt-repository ppa:oisf/suricata-stable -y"
        eval "apt-get update"
    fi

    if [  "$?" != 0  ]; then
        logger -e "Prerequisites could not be installed"
        exit 1;
    else
        logger "Done"
    fi
}


## Add the Wazuh repository
addWazuhrepo() {
    logger "Adding the Wazuh repository..."

    if [ ${sys_type} == "yum" ]; then
        eval "rpm --import ${repogpg} ${debug}"
        eval "echo -e '[wazuh]\ngpgcheck=1\ngpgkey=${repogpg}\nenabled=1\nname=EL-\$releasever - Wazuh\nbaseurl='${repobaseurl}'/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh.repo ${debug}"
    elif [ ${sys_type} == "zypper" ]; then
        eval "rpm --import ${repogpg} ${debug}"
        eval "echo -e '[wazuh]\ngpgcheck=1\ngpgkey=${repogpg}\nenabled=1\nname=EL-\$releasever - Wazuh\nbaseurl='${repobaseurl}'/yum/\nprotect=1' | tee /etc/zypp/repos.d/wazuh.repo ${debug}"
    elif [ ${sys_type} == "apt-get" ]; then
        eval "curl -s ${repogpg} --max-time 300 | apt-key add - ${debug}"
        eval "echo "deb '${repobaseurl}'/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list ${debug}"
        eval "apt-get update -q ${debug}"
    fi

    logger "Done"
}

## Wazuh Agent
installWazuh() {

    logger "Installing the Wazuh agent..."
    if [ ${sys_type} == "zypper" ]; then
        eval "WAZUH_MANAGER="$manager" zypper -n install wazuh-agent=${WAZUH_VER}-${WAZUH_REV} ${debug}"
    else
        eval "WAZUH_MANAGER="$manager" WAZUH_REGISTRATION_PASSWORD="$password" ${sys_type} install wazuh-agent${sep}${WAZUH_VER}-${WAZUH_REV} -y ${debug}"
    fi
    if [  "$?" != 0  ]; then
        logger -e "Wazuh installation failed"
        rollBack
        exit 1;
    else
        wazuhinstalled="1"
        logger "Done"
    fi
    echo "logcollector.remote_commands=1" >> /var/ossec/etc/local_internal_options.conf
    echo "wazuh_command.remote_commands=1" >> /var/ossec/etc/local_internal_options.conf
    startService "wazuh-agent"

}

## ClamAV Install
installClamAV() {

    logger "Installing ClamAV..."
    if [ ${sys_type} == "zypper" ]; then
        eval "zypper -n install clamav-server clamav-data clamav-update clamav-filesystem clamav clamav-scanner-systemd clamav-devel clamav-lib clamav-server-systemd ${debug}"
    fi
    if [ ${sys_type} == "yum" ]; then
        eval "yum install clamav-data clamav-update clamav-filesystem clamav clamav-scanner-systemd clamav-devel clamav-lib clamav-server-systemd -y ${debug}"
    fi
    if [ ${sys_type} == "apt-get" ]; then
        eval "apt-get install clamav clamav-daemon -y ${debug}"
    fi
    if [  "$?" != 0  ]; then
        logger -e "ClamAVinstallation failed"
        rollBack
        exit 1;
    else
        clamavinstalled="1"
        logger "Done"
    fi
    freshclam
    echo "@hourly /bin/freshclam --quiet" >> /etc/crontab
    echo "/home/
    /opt/
    /usr/bin/
    /etc/
    /usr/sbin/" > /opt/scanfolders.txt
    wget https://raw.githubusercontent.com/OpenSecureCo/Kickstart/main/Freshclam.conf -O /etc/freshclam.conf
    wget https://raw.githubusercontent.com/OpenSecureCo/Kickstart/main/scan.conf -O /etc/clamd.d/scan.conf
    mkdir /root/scripts/
    wget https://raw.githubusercontent.com/OpenSecureCo/Kickstart/main/clamscan.sh -O /root/scripts/clamscan.sh
    chmod +x /root/scripts/clamscan.sh
    echo "0 8 * * * /root/scripts/clamscan.sh" >> /etc/crontab

}

## Install OSQUERY
installOSquery() {

    logger "Installing osquery..."
    if [ ${sys_type} == "zypper" ]; then
        eval "WAZUH_MANAGER="$manager" zypper -n install wazuh-agent=${WAZUH_VER}-${WAZUH_REV} ${debug}"
    else
        eval "${sys_type} install osquery -y ${debug}"
        eval "wget https://raw.githubusercontent.com/OpenSecureCo/Kickstart/main/osquery.conf -O /etc/osquery/osquery.conf"
    fi
    if [  "$?" != 0  ]; then
        logger -e "OSQUERY installation failed"
        rollBack
        exit 1;
    else
        osqueryinstalled="1"
        logger "Done"
    fi

}

## Install Suricata
installSuricata() {

    logger "Installing Suricata..."
    if [ ${sys_type} == "zypper" ]; then
        eval "WAZUH_MANAGER="$manager" zypper -n install wazuh-agent=${WAZUH_VER}-${WAZUH_REV} ${debug}"
    else
        eval "${sys_type} install suricata -y ${debug}"
        eval "suricata-update"
    fi
    if [  "$?" != 0  ]; then
        logger -e "Suricata installation failed"
        rollBack
        exit 1;
    else
        suricatainstalled="1"
        logger "Done"
    fi

}


## Install Auditd
installAuditd() {

    logger "Installing Auditd..."
    if [ ${sys_type} == "zypper" ]; then
        eval "WAZUH_MANAGER="$manager" zypper -n install wazuh-agent=${WAZUH_VER}-${WAZUH_REV} ${debug}"
    else
        eval "wget https://raw.githubusercontent.com/OpenSecureCo/Kickstart/main/auditd.conf -O /etc/audit/rules.d/audit.rules"
        eval "auditctl -R /etc/audit/rules.d/audit.rules"
    fi
    if [  "$?" != 0  ]; then
        logger -e "auditd installation failed"
        rollBack
        exit 1;
    else
        auditdinstalled="1"
        logger "Done"
    fi

}

checkInstalled() {

    if [ "${sys_type}" == "yum" ]; then
        wazuhinstalled=$(yum list installed 2>/dev/null | grep wazuh-agent)
    elif [ "${sys_type}" == "zypper" ]; then
        wazuhinstalled=$(zypper packages --installed-only | grep wazuh-agent | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        wazuhinstalled=$(apt list --installed  2>/dev/null | grep wazuh-agent)
    fi

    if [ -n "${wazuhinstalled}" ]; then
        if [ ${sys_type} == "zypper" ]; then
            wazuhversion=$(echo ${wazuhinstalled} | awk '{print $11}')
        else
            wazuhversion=$(echo ${wazuhinstalled} | awk '{print $2}')
        fi
    fi

    if [ -z "${wazuhinstalled}" ] && [ -n "${uninstall}" ]; then
        logger -e "No Wazuh agent were found on the system."
        exit 1;
    fi

    if [ -n "${wazuhinstalled}" ]; then
        if [ -n "${ow}" ]; then
             overwrite

        elif [ -n "${uninstall}" ]; then
            logger -w "Removing the installed items"
            rollBack
        else
            logger -e "The Wazuh agent were found on this host. If you want to overwrite the current installation, run this script back using the option -o/--overwrite. NOTE: This will erase all the existing configuration and data."
            exit 1;
        fi
    fi

}

overwrite() {
    rollBack
    addWazuhrepo
    installPrerequisites
    if [ -n "${wazuhinstalled}" ]; then
        installWazuh
    fi
    checkInstallation
}

networkCheck() {
    connection=$(curl -I https://packages.wazuh.com/ -s | grep 200 | awk '{print $2}')
    if [ ${connection} != "200" ]; then
        logger -e "No internet connection. To perform an offline installation, please run this script with the option -d/--download-packages in a computer with internet access, copy the wazuh-packages.tar file generated on this computer and run again this script."
        exit 1;
    fi
}

main() {

    if [ "$EUID" -ne 0 ]; then
        logger -e "This script must be run as root."
        exit 1;
    fi

    checkArch
    touch /var/log/wazuh-unattended-installation.log

    if [ -n "$1" ]; then
        while [ -n "$1" ]
        do
            case "$1" in
            "-m"|"--manager")
                manager=$2
                shift 2
                ;;
            "-v"|"--verbose")
                verbose=1
                shift 1
                ;;
            "-o"|"--overwrite")
                ow=1
                shift 1
                ;;
            "-r"|"--uninstall")
                uninstall=1
                shift 1
                ;;
            "-h"|"--help")
                getHelp
                ;;
            *)
                getHelp
            esac
        done

        if [ -n "${verbose}" ]; then
            debug='2>&1 | tee -a /var/log/wazuh-unattended-installation.log'
        fi

        if [ -n "${uninstall}" ]; then
            checkInstalled
            exit 0;
        fi

        installPrerequisites
        addWazuhrepo
        installWazuh
        installClamAV
        installOSquery
        installAuditd
        installSuricata
    else
        checkInstalled
        installPrerequisites
        addWazuhrepo
        installWazuh
        installClamAV
        installOSquery
        installAuditd
        installSuricata
    fi

}

main "$@"
