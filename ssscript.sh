#! /usr/bin/env bash
PATH="/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin"
export PATH

#Github: https://github.com/tianzjyh/ssscript
#ThanksTo: https://github.com/uxh/shadowsocks_bash

#Color
red="\033[0;31m"
green="\033[0;32m"
yellow="\033[0;33m"
plain="\033[0m"

#Directory
currentdir=$(pwd)

#Streamcipher
ciphers=(
aes-256-gcm
aes-256-ctr
aes-256-cfb
chacha20-ietf-poly1305
chacha20-ietf
chacha20
rc4-md5
)

#Version and url
libsodiumver="libsodium-1.0.18"
libsodiumurl="https://github.com/jedisct1/libsodium/releases/download/1.0.18-RELEASE/libsodium-1.0.18.tar.gz"
mbedtlsver="mbedtls-2.16.12"
mbedtlsurl="https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v2.16.12.tar.gz"
shadowsocksver="shadowsocks-libev-3.3.5"
shadowsocksurl="https://github.com/shadowsocks/shadowsocks-libev/releases/download/v3.3.5/shadowsocks-libev-3.3.5.tar.gz"
libevver="libev-4.33"
libevurl="http://dist.schmorp.de/libev/libev-4.33.tar.gz"
initscripturl="https://raw.githubusercontent.com/uxh/shadowsocks_bash/master/shadowsocks-libev"

#Disable selinux
function disable_selinux() {
    if [ -s /etc/selinux/config ] && grep "SELINUX=enforcing" /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}

#Install libev from source - MANDATORY for CentOS 9
function install_libev_from_source() {
    echo -e "${green}[Info]${plain} Installing libev from source for CentOS 9 compatibility..."
    cd /tmp
    
    # Clean up any previous attempts
    rm -rf ${libevver}*
    
    # Download libev source
    download "${libevver}.tar.gz" "${libevurl}"
    tar zxf ${libevver}.tar.gz
    cd ${libevver}
    
    # Configure and compile - CRITICAL: Install to /usr not /usr/local for shadowsocks
    echo -e "${yellow}[DEBUG]${plain} ===== LIBEV COMPILATION DEBUG ====="
    echo -e "${yellow}[DEBUG]${plain} Current directory: $(pwd)"
    echo -e "${yellow}[DEBUG]${plain} Available files:"
    ls -la
    
    export CFLAGS="-fPIC -O2"
    export CXXFLAGS="-fPIC -O2"
    
    echo -e "${yellow}[DEBUG]${plain} Running configure with --prefix=/usr"
    ./configure --prefix=/usr --enable-shared --enable-static --disable-dependency-tracking 2>&1 | tee /tmp/libev_configure.log
    
    if [ ${PIPESTATUS[0]} -ne 0 ]; then
        echo -e "${red}[Error]${plain} libev configure failed!"
        echo -e "${yellow}[DEBUG]${plain} Configure output:"
        cat /tmp/libev_configure.log
        return 1
    fi
    
    echo -e "${yellow}[DEBUG]${plain} Running make clean"
    make clean
    
    echo -e "${yellow}[DEBUG]${plain} Running make with $(nproc) jobs"
    make -j$(nproc) 2>&1 | tee /tmp/libev_make.log
    
    if [ ${PIPESTATUS[0]} -ne 0 ]; then
        echo -e "${red}[Error]${plain} libev make failed!"
        return 1
    fi
    
    echo -e "${yellow}[DEBUG]${plain} Running make install"
    make install 2>&1 | tee /tmp/libev_install.log
    
    if [ $? -eq 0 ]; then
        echo -e "${green}[Info]${plain} libev make install completed"
        
        # Update library cache
        ldconfig
        
        # Create pkgconfig file in system location
        mkdir -p /usr/lib64/pkgconfig
        cat > /usr/lib64/pkgconfig/libev.pc << EOF
prefix=/usr
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib64
includedir=\${prefix}/include

Name: libev
Description: A full-featured and high-performance event loop
Version: 4.33
Libs: -L\${libdir} -lev
Libs.private: -lm
Cflags: -I\${includedir}
EOF
        
        echo -e "${yellow}[DEBUG]${plain} ===== LIBEV INSTALLATION VERIFICATION ====="
        echo -e "${yellow}[DEBUG]${plain} Checking libev files after installation:"
        
        # Check header file
        if [ -f /usr/include/ev.h ]; then
            echo -e "${green}[DEBUG]${plain} ✓ Header file found: /usr/include/ev.h"
            ls -la /usr/include/ev.h
        else
            echo -e "${red}[DEBUG]${plain} ✗ Header file missing: /usr/include/ev.h"
            echo -e "${yellow}[DEBUG]${plain} Available headers:"
            find /usr -name "ev.h" 2>/dev/null || echo "No ev.h found anywhere in /usr"
        fi
        
        # Check library files
        if [ -f /usr/lib64/libev.so ]; then
            echo -e "${green}[DEBUG]${plain} ✓ Library found: /usr/lib64/libev.so"
            ls -la /usr/lib64/libev*
        else
            echo -e "${red}[DEBUG]${plain} ✗ Library missing: /usr/lib64/libev.so"
            echo -e "${yellow}[DEBUG]${plain} Available libev libraries:"
            find /usr -name "libev*" 2>/dev/null || echo "No libev libraries found anywhere in /usr"
        fi
        
        # Check pkgconfig
        if [ -f /usr/lib64/pkgconfig/libev.pc ]; then
            echo -e "${green}[DEBUG]${plain} ✓ pkgconfig file created: /usr/lib64/pkgconfig/libev.pc"
            cat /usr/lib64/pkgconfig/libev.pc
        else
            echo -e "${red}[DEBUG]${plain} ✗ pkgconfig file missing"
        fi
        
        # Test pkg-config command
        echo -e "${yellow}[DEBUG]${plain} Testing pkg-config libev:"
        if pkg-config --exists libev; then
            echo -e "${green}[DEBUG]${plain} ✓ pkg-config can find libev"
            echo -e "${yellow}[DEBUG]${plain} CFLAGS: $(pkg-config --cflags libev)"
            echo -e "${yellow}[DEBUG]${plain} LIBS: $(pkg-config --libs libev)"
        else
            echo -e "${red}[DEBUG]${plain} ✗ pkg-config cannot find libev"
            echo -e "${yellow}[DEBUG]${plain} PKG_CONFIG_PATH=$PKG_CONFIG_PATH"
        fi
        
        # Test compilation
        echo -e "${yellow}[DEBUG]${plain} Testing libev compilation:"
        cat > /tmp/test_libev.c << 'EOF'
#include <ev.h>
int main() {
    ev_loop_destroy(EV_DEFAULT);
    return 0;
}
EOF
        if gcc -o /tmp/test_libev /tmp/test_libev.c -lev 2>/tmp/libev_compile_error.log; then
            echo -e "${green}[DEBUG]${plain} ✓ libev test compilation: SUCCESS"
            rm -f /tmp/test_libev /tmp/test_libev.c /tmp/libev_compile_error.log
        else
            echo -e "${red}[DEBUG]${plain} ✗ libev test compilation: FAILED"
            echo -e "${yellow}[DEBUG]${plain} Compilation error:"
            cat /tmp/libev_compile_error.log
            rm -f /tmp/test_libev /tmp/test_libev.c /tmp/libev_compile_error.log
        fi
        
        echo -e "${yellow}[DEBUG]${plain} ===== END LIBEV VERIFICATION ====="
        
        # Final verification
        if [ -f /usr/include/ev.h ] && [ -f /usr/lib64/libev.so ]; then
            echo -e "${green}[Info]${plain} libev installation verification: PASSED"
            cd /tmp && rm -rf ${libevver}*
            return 0
        else
            echo -e "${red}[Error]${plain} libev installation verification: FAILED - missing required files"
            cd /tmp && rm -rf ${libevver}*
            return 1
        fi
    else
        echo -e "${red}[Error]${plain} Failed to compile libev from source!"
        echo -e "${yellow}[DEBUG]${plain} Last 20 lines of make output (if available):"
        tail -20 /tmp/libev_make.log 2>/dev/null || echo "No make log available"
        cd /tmp && rm -rf ${libevver}*
        return 1
    fi
}

#Auto-diagnose and fix libev issues
function ensure_libev_available() {
    echo -e "${green}[Info]${plain} Checking libev availability..."
    
    # For CentOS 9, force reinstallation to ensure compatibility
    if check_centos_main_version 9; then
        echo -e "${yellow}[Warning]${plain} CentOS 9 detected, forcing libev reinstallation..."
        install_libev_from_source
        return $?
    fi
    
    # Check if libev is already properly installed
    if [ -f /usr/include/ev.h ] && [ -f /usr/lib64/libev.so ]; then
        echo -e "${green}[Info]${plain} libev already installed and verified"
        return 0
    fi
    
    # Try to install from packages first
    echo -e "${yellow}[Warning]${plain} libev not found, trying to install from packages..."
    
    local pkg_manager="yum"
    if command -v dnf > /dev/null 2>&1; then
        pkg_manager="dnf"
    fi
    
    # CentOS 9 doesn't have working libev packages, always compile from source
    if check_centos_main_version 9; then
        echo -e "${yellow}[Warning]${plain} CentOS 9 detected, compiling libev from source for compatibility..."
        install_libev_from_source
        return $?
    fi
    
    # Try package installation for older CentOS versions
    for pkg in libev-devel libevent-devel; do
        echo -e "${green}[Info]${plain} Trying to install $pkg..."
        ${pkg_manager} install -y $pkg
        if [ $? -eq 0 ]; then
            ldconfig
            if pkg-config --exists libev 2>/dev/null || ldconfig -p | grep -q libev || [ -f /usr/include/ev.h ]; then
                echo -e "${green}[Info]${plain} Successfully installed $pkg"
                return 0
            fi
        fi
    done
    
    # If package installation failed, compile from source
    echo -e "${yellow}[Warning]${plain} Package installation failed, compiling libev from source..."
    install_libev_from_source
    return $?
}

#Check release
function check_release() {
    local value=$1
    local release="none"

    if [ -f /etc/redhat-release ]; then
        release="centos"
    elif grep -qi "centos|red hat|redhat" /etc/issue; then
        release="centos"
    elif grep -qi "debian|raspbian" /etc/issue; then
        release="debian"
    elif grep -qi "ubuntu" /etc/issue; then
        release="ubuntu"
    elif grep -qi "centos|red hat|redhat" /proc/version; then
        release="centos"
    elif grep -qi "debian" /proc/version; then
        release="debian"
    elif grep -qi "ubuntu" /proc/version; then
        release="ubuntu"
    elif grep -qi "centos|red hat|redhat" /etc/*-release; then
        release="centos"
    elif grep -qi "debian" /etc/*-release; then
        release="debian"
    elif grep -qi "ubuntu" /etc/*-release; then
        release="ubuntu"
    fi

    if [[ ${value} == ${release} ]]; then
        return 0
    else
        return 1
    fi
}

#Check shadowsocks status
function check_shadowsocks_status() {
    installedornot="not"
    runningornot="not"
    updateornot="not"
    command -v ss-server > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        installedornot="installed"
        ps -ef | grep -v "grep" | grep "ss-server" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            runningornot="running"
        fi
        local installedversion=$(ss-server -h | grep "shadowsocks-libev" | cut -d " " -f 2)
        local latestversion=$(echo "$(wget --no-check-certificate -qO- https://api.github.com/repos/shadowsocks/shadowsocks-libev/releases/latest | grep "tag_name" | cut -d "\"" -f 4)" | sed -e 's/^[a-zA-Z]//g')
        if [ ! -z ${latestversion} ]; then
            if [[ ${installedversion} != ${latestversion} ]]; then
                updateornot="update"
                shadowsocksnewver="shadowsocks-libev-${latestversion}"
                shadowsocksnewurl="https://github.com/shadowsocks/shadowsocks-libev/releases/download/v${latestversion}/${shadowsocksnewver}.tar.gz"
            fi
        fi
    fi
}

#Check centos main version
function check_centos_main_version() {
    local value=$1
    local version="0.0.0"

    if [ -s /etc/redhat-release ]; then
        version=$(grep -Eo "[0-9.]+" /etc/redhat-release)
    else
        version=$(grep -Eo "[0-9.]+" /etc/issue)
    fi

    local mainversion=${version%%.*}

    if [ ${value} -eq ${mainversion} ]; then
        return 0
    else
        return 1
    fi
}

#Check kernel version
function check_kernel_version() {
    local kernelversion=$(uname -r | cut -d "-" -f 1)
    local olderversion=$(echo "${kernelversion} 3.7.0" | tr " " "\n" | sort -V | head -n 1)
    if [[ ${olderversion} == "3.7.0" ]]; then
        return 0
    else
        return 1
    fi
}

#Check kernel headers
function check_kernel_headers() {
    local nowkernel=$(uname -r)
    if check_release centos; then
        rpm -qa | grep "headers-${nowkernel}" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            return 0
        else
            return 1
        fi
    else
        dpkg -s linux-headers-${nowkernel} > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            return 0
        else
            return 1
        fi
    fi
}

#Get ipv4
function get_ipv4() {
    local ipv4=$(ip addr | grep -Eo "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | grep -Ev "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1)
    if [ -z ${ipv4} ]; then
        ipv4=$(wget -qO- -t 1 -T 10 ipv4.icanhazip.com)
    fi
    if [ -z ${ipv4} ]; then
        ipv4=$(wget -qO- -t 1 -T 10 ipinfo.io/ip)
    fi
    echo -e "${ipv4}"
}

#Get ipv6
function check_ipv6() {
    local ipv6=$(wget -qO- -t 1 -T 10 ipv6.icanhazip.com)
    if [ -z ${ipv6} ]; then
        return 1
    else
        return 0
    fi
}

#Set shadowsocks config
function set_shadowsocks_config() {
    clear
    echo -e "${green}[Info]${plain} Start set shadowsocks's config information..."
    echo -e "${green}[Info]${plain} Wherever you are not sure, just press Enter to continue."
    echo ""
    echo "Please enter shadowsocks's password"
    read -p "[Default is Number1433223]:" sspassword
    if [ -z ${sspassword} ]; then
        sspassword="Number1433223"
    fi
    echo "-------------------------------"
    echo "Shadowsocks's Password: ${sspassword}"
    echo "-------------------------------"

    local defaultport=$(shuf -i 9000-9999 -n 1)
    echo "Please enter shadowsocks's port (1~65535)"
    while true
    do
        read -p "[Default is ${defaultport}]:" ssport
        if [ -z ${ssport} ]; then
            ssport=${defaultport}
        fi
        expr ${ssport} + 1 > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            if [ ${ssport} -ge 1 ] && [ ${ssport} -le 65535 ]; then
                echo "-------------------------------"
                echo "Shadowsocks's Port: ${ssport}"
                echo "-------------------------------"
                break
            else
                echo -e "${red}[Error]${plain} Please enter a number between 1 and 65535!"
            fi
        else
            echo -e "${red}[Error]${plain} Please enter a number between 1 and 65535!"
        fi
    done

    echo "Please select shadowsocks's stream cipher"
    for ((i=1;i<=${#ciphers[@]};i++));
    do
        local cipher=${ciphers[$i-1]}
        echo -e "${i}) ${cipher}"
    done
    while true
    do
        read -p "[Default is ${ciphers[0]}]:" ciphernumber
        if [ -z ${ciphernumber} ]; then
            ciphernumber="1"
        fi
        expr ${ciphernumber} + 1 > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            if [ ${ciphernumber} -ge 1 ] && [ ${ciphernumber} -le ${#ciphers[@]} ]; then
                sscipher=${ciphers[${ciphernumber}-1]}
                echo "-------------------------------"
                echo "Shadowsocks's Streamcipher: ${sscipher}"
                echo "-------------------------------"
                break
            else
                echo -e "${red}[Error]${plain} Please enter a number between 1 and ${#ciphers[@]}!"
            fi
        else
            echo -e "${red}[Error]${plain} Please enter a number between 1 and ${#ciphers[@]}!"
        fi
    done

    echo ""
    echo "Press Enter to continue...or Press Ctrl+C to cancel"
    read -n 1
}

function set_shadowsocks_config_easy(){
    sscipher="aes-256-gcm"
    ssport=80
    sspassword=${password}
}

#install dependencies
function install_dependencies() {
    if check_release centos; then
        # Determine package manager based on CentOS version
        local pkg_manager="yum"
        if check_centos_main_version 8 || check_centos_main_version 9; then
            pkg_manager="dnf"
        fi
        
        # Install EPEL repository
        if [ ! -f /etc/yum.repos.d/epel.repo ]; then
            echo -e "${green}[Info]${plain} Installing EPEL repository..."
            ${pkg_manager} install -y epel-release
            if [ $? -ne 0 ]; then
                echo -e "${red}[Error]${plain} EPEL install failed, please try again!"
                exit 1
            fi
        fi
        
        # Enable EPEL repository
        echo -e "${green}[Info]${plain} Enabling EPEL repository..."
        if command -v dnf > /dev/null 2>&1; then
            dnf config-manager --set-enabled epel
        else
            # Install yum-utils if needed
            command -v yum-config-manager > /dev/null 2>&1 || ${pkg_manager} install -y yum-utils
            yum-config-manager --enable epel
        fi
        
        # Install basic dependencies
        echo -e "${green}[Info]${plain} Installing basic dependencies..."
        if check_centos_main_version 9; then
            # CentOS 9 specific packages and groups
            ${pkg_manager} groupinstall -y "Development Tools"
            ${pkg_manager} install -y unzip openssl openssl-devel gettext gcc gcc-c++ autoconf libtool automake make asciidoc xmlto pcre pcre-devel git c-ares-devel wget pkgconfig
        else
            # CentOS 6, 7, 8 packages
            ${pkg_manager} install -y unzip openssl openssl-devel gettext gcc autoconf libtool automake make asciidoc xmlto pcre pcre-devel git c-ares-devel wget
        fi
        if [ $? -ne 0 ]; then
            echo -e "${red}[Error]${plain} Basic dependencies install failed, please try again!"
            exit 1
        fi
        
        # Auto-diagnose and fix libev
        ensure_libev_available
        if [ $? -ne 0 ]; then
            echo -e "${red}[Error]${plain} Failed to install libev! Cannot continue."
            exit 1
        fi
    else
        apt-get update
        apt-get install --no-install-recommends -y gettext build-essential autoconf automake libtool openssl libssl-dev zlib1g-dev libpcre3-dev libev-dev libc-ares-dev wget
        if [ $? -ne 0 ]; then
            echo -e "${red}[Error]${plain} Dependencies install failed, please try again!"
            exit 1
        fi
    fi
    echo -e "nameserver 8.8.8.8\nnameserver 8.8.4.4" > /etc/resolv.conf
}

#Set firewall
function set_firewall() {
    if check_release centos; then
        if check_centos_main_version 6; then
            /etc/init.d/iptables status > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                iptables -L -n | grep "${ssport}" > /dev/null 2>&1
                if [ $? -ne 0 ]; then
                    iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssport} -j ACCEPT
                    iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssport} -j ACCEPT
                    /etc/init.d/iptables save
                    /etc/init.d/iptables restart
                fi
            fi
        elif check_centos_main_version 7 || check_centos_main_version 8 || check_centos_main_version 9; then
            systemctl status firewalld > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                firewall-cmd --query-port=${ssport}/tcp > /dev/null 2>&1
                if [ $? -ne 0 ]; then
                    firewall-cmd --permanent --zone=public --add-port=${ssport}/tcp
                    firewall-cmd --permanent --zone=public --add-port=${ssport}/udp
                    firewall-cmd --reload
                fi
            fi
        fi
    fi
}

#Download
function download() {
    local filename=$1

    if [ -s ${filename} ]; then
        echo -e "${green}[Info]${plain} ${filename} found."
    else
        echo -e "${green}[Info]${plain} ${filename} not found, start to download..."
        wget --no-check-certificate -c -t 3 -T 60 -O $1 $2
        if [ $? -eq 0 ]; then
            echo -e "${green}[Info]${plain} ${filename} download complete."
        else
            echo -e "${green}[Info]${plain} ${filename} download failed, please try again!"
            exit 1
        fi
    fi
}

#Install libsodium
function install_libsodium() {
    cd ${currentdir}
    if [ ! -f /usr/lib/libsodium.a ]; then
        download "${libsodiumver}.tar.gz" "${libsodiumurl}"
        tar zxf ${libsodiumver}.tar.gz
        cd ${libsodiumver}
        ./configure --prefix=/usr && make && make install
        if [ $? -ne 0 ]; then
            echo -e "${red}[Error]${plain} ${libsodiumver} install failed, please try again!"
            exit 1
        fi
    else
        echo -e "${green}[Info]${plain} ${libsodiumver} has been installed."
    fi

    cd ${currentdir}
    rm -rf ${libsodiumver} ${libsodiumver}.tar.gz
}

#Install mbedtls
function install_mbedtls() {
    cd ${currentdir}
    if [ ! -f /usr/lib/libmbedtls.a ]; then
        download "${mbedtlsver}-gpl.tgz" "${mbedtlsurl}"
        tar xf ${mbedtlsver}-gpl.tgz
        cd ${mbedtlsver}
        make SHARED=1 CFLAGS=-fPIC
        make DESTDIR=/usr install
        if [ $? -ne 0 ]; then
            echo -e "${red}[Error]${plain} ${mbedtlsver} install failed, please try again!"
            exit 1
        fi
    else
        echo -e "${green}[Info]${plain} ${mbedtlsver} has been installed."
    fi

    cd ${currentdir}
    rm -rf ${mbedtlsver} ${mbedtlsver}-gpl.tgz
}

#Install obfs-plugin
function install_obfs(){
    cd ${currentdir}
    
    yum install zlib-devel openssl-devel -y
    git clone https://github.com/shadowsocks/simple-obfs.git
    cd simple-obfs
    git submodule update --init --recursive
    ./autogen.sh
    ./configure
    make
    make install
}

#Config shadowsocks
function config_shadowsocks() {
    if check_ipv6; then
        server_value="[\"[::0]\",\"0.0.0.0\"]"
    else
        server_value="\"0.0.0.0\""
    fi

    if check_kernel_version && check_kernel_headers; then
        fast_open="true"
    else
        fast_open="false"
    fi

    if [ ! -d /etc/shadowsocks-libev ]; then
        mkdir -p /etc/shadowsocks-libev
    fi

    cat > /etc/shadowsocks-libev/config.json << EOF
{
    "server":${server_value},
    "server_port":${ssport},
    "password":"${sspassword}",
    "timeout":300,
    "user":"nobody",
    "method":"${sscipher}",
    "plugin":"obfs-server",
    "plugin_opts":"obfs=http",
    "fast_open":${fast_open},
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp"
}
EOF
}

#Install shadowsocks
function install_shadowsocks() {
    # Final check for libev before compiling shadowsocks
    echo -e "${green}[Info]${plain} Final libev check before compiling shadowsocks..."
    ensure_libev_available
    if [ $? -ne 0 ]; then
        echo -e "${red}[Error]${plain} libev is required for shadowsocks but not available!"
        exit 1
    fi
    
    # Update library cache
    ldconfig
    
    # Debug: Show current libev status
    echo -e "${yellow}[DEBUG]${plain} ===== CURRENT LIBEV STATUS ====="
    echo -e "${yellow}[DEBUG]${plain} Header files:"
    ls -la /usr/include/ev.h 2>/dev/null || echo "No ev.h in /usr/include/"
    ls -la /usr/local/include/ev.h 2>/dev/null || echo "No ev.h in /usr/local/include/"
    
    echo -e "${yellow}[DEBUG]${plain} Library files:"
    ls -la /usr/lib64/libev* 2>/dev/null || echo "No libev in /usr/lib64/"
    ls -la /usr/local/lib/libev* 2>/dev/null || echo "No libev in /usr/local/lib/"
    
    echo -e "${yellow}[DEBUG]${plain} pkg-config status:"
    pkg-config --exists libev && echo "✓ pkg-config can find libev" || echo "✗ pkg-config cannot find libev"
    echo -e "${yellow}[DEBUG]${plain} ===== END LIBEV STATUS ===="
    
    cd ${currentdir}
    if [[ ${updateornot} == "not" ]]; then
        download "${shadowsocksver}.tar.gz" "${shadowsocksurl}"
        tar zxf ${shadowsocksver}.tar.gz
        cd ${shadowsocksver}
    else
        download "${shadowsocksnewver}.tar.gz" "${shadowsocksnewurl}"
        tar zxf ${shadowsocksnewver}.tar.gz
        cd ${shadowsocksnewver}
    fi
    
    # Set up environment variables - libev is now in standard system paths
    export PKG_CONFIG_PATH="/usr/lib64/pkgconfig:/usr/lib/pkgconfig:/usr/share/pkgconfig:$PKG_CONFIG_PATH"
    export CPPFLAGS="-I/usr/include $CPPFLAGS"
    export LDFLAGS="-L/usr/lib64 -L/usr/lib $LDFLAGS"
    export LD_LIBRARY_PATH="/usr/lib64:/usr/lib:$LD_LIBRARY_PATH"
    
    echo -e "${yellow}[DEBUG]${plain} ===== SHADOWSOCKS COMPILATION DEBUG ====="
    echo -e "${yellow}[DEBUG]${plain} Current directory: $(pwd)"
    echo -e "${yellow}[DEBUG]${plain} Environment variables:"
    echo -e "${yellow}[DEBUG]${plain} PKG_CONFIG_PATH=$PKG_CONFIG_PATH"
    echo -e "${yellow}[DEBUG]${plain} CPPFLAGS=$CPPFLAGS"
    echo -e "${yellow}[DEBUG]${plain} LDFLAGS=$LDFLAGS"
    echo -e "${yellow}[DEBUG]${plain} LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
    
    echo -e "${green}[Info]${plain} Pre-configure libev verification..."
    
    # Verify libev header
    if [ -f /usr/include/ev.h ]; then
        echo -e "${green}[DEBUG]${plain} ✓ libev header found: /usr/include/ev.h"
    else
        echo -e "${red}[DEBUG]${plain} ✗ libev header not found in /usr/include/ev.h!"
        echo -e "${yellow}[DEBUG]${plain} Searching for ev.h:"
        find /usr -name "ev.h" 2>/dev/null || echo "No ev.h found in /usr"
        exit 1
    fi
    
    # Verify libev library
    if [ -f /usr/lib64/libev.so ]; then
        echo -e "${green}[DEBUG]${plain} ✓ libev library found: /usr/lib64/libev.so"
    else
        echo -e "${red}[DEBUG]${plain} ✗ libev library not found in /usr/lib64/!"
        echo -e "${yellow}[DEBUG]${plain} Searching for libev libraries:"
        find /usr -name "libev*" -type f 2>/dev/null || echo "No libev libraries found in /usr"
        exit 1
    fi
    
    # Test pkg-config
    echo -e "${yellow}[DEBUG]${plain} Testing pkg-config for libev:"
    if pkg-config --exists libev; then
        echo -e "${green}[DEBUG]${plain} ✓ pkg-config can find libev"
        echo -e "${yellow}[DEBUG]${plain} libev CFLAGS: $(pkg-config --cflags libev)"
        echo -e "${yellow}[DEBUG]${plain} libev LIBS: $(pkg-config --libs libev)"
    else
        echo -e "${yellow}[DEBUG]${plain} ⚠ pkg-config cannot find libev (may not be critical)"
    fi
    
    echo -e "${green}[Info]${plain} libev verification passed - starting shadowsocks configure"
    echo -e "${yellow}[DEBUG]${plain} Running: ./configure --disable-documentation"
    
    ./configure --disable-documentation 2>&1 | tee /tmp/shadowsocks_configure.log
    
    if [ ${PIPESTATUS[0]} -ne 0 ]; then
        echo -e "${red}[Error]${plain} Shadowsocks configure failed!"
        echo -e "${yellow}[DEBUG]${plain} ===== CONFIGURE ERROR ANALYSIS ====="
        echo -e "${yellow}[DEBUG]${plain} Searching for libev-related errors in configure log:"
        grep -i "libev\|ev\.h\|ev_loop" /tmp/shadowsocks_configure.log || echo "No libev errors found"
        echo -e "${yellow}[DEBUG]${plain} Last 50 lines of configure log:"
        tail -50 /tmp/shadowsocks_configure.log
        echo -e "${yellow}[DEBUG]${plain} ===== END ERROR ANALYSIS ====="
        exit 1
    fi
    
    echo -e "${green}[DEBUG]${plain} ✓ Shadowsocks configure succeeded!"
    make && make install
    if [ $? -ne 0 ]; then
        echo -e "${red}[Error]${plain} Shadowsocks install failed, please try again!"
        exit 1
    fi
    # Install service - prefer systemd for CentOS 9
    echo -e "${green}[Info]${plain} Installing shadowsocks service..."
    
    if check_centos_main_version 9; then
        # CentOS 9: Use systemd exclusively
        echo -e "${green}[Info]${plain} CentOS 9 detected, creating systemd service..."
        
        # Verify required components before creating service
        echo -e "${yellow}[DEBUG]${plain} Pre-service verification:"
        if [ -f /usr/local/bin/ss-server ]; then
            echo -e "${green}[DEBUG]${plain} ✓ ss-server binary found"
            ls -la /usr/local/bin/ss-server
        else
            echo -e "${red}[ERROR]${plain} ✗ ss-server binary not found!"
            exit 1
        fi
        
        if [ -f /etc/shadowsocks-libev/config.json ]; then
            echo -e "${green}[DEBUG]${plain} ✓ config file found"
        else
            echo -e "${red}[ERROR]${plain} ✗ config file not found!"
            exit 1
        fi
        
        # Check if nobody user exists, create if needed
        if ! id nobody >/dev/null 2>&1; then
            echo -e "${yellow}[Info]${plain} Creating nobody user for CentOS 9..."
            useradd -r -s /sbin/nologin nobody
        fi
        
        cat > /etc/systemd/system/shadowsocks-libev.service << 'EOF'
[Unit]
Description=Shadowsocks-Libev Server Service
Documentation=man:ss-server(1)
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ss-server -c /etc/shadowsocks-libev/config.json
ExecStartPre=/bin/sh -c 'ulimit -n 51200'
Restart=on-failure
RestartSec=5s
User=nobody
Group=nobody
LimitNOFILE=51200

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable shadowsocks-libev
        echo -e "${green}[Info]${plain} systemd service created and enabled"
    else
        # CentOS 6-8: Try traditional init script
        if [ ! -f /etc/init.d/shadowsocks ]; then
            # Ensure /etc/init.d directory exists
            mkdir -p /etc/init.d
            
            # Download init script
            cd /tmp
            wget --no-check-certificate -c -t 3 -T 60 -O shadowsocks-init "${initscripturl}"
            if [ $? -eq 0 ]; then
                # Move to proper location and set permissions
                mv shadowsocks-init /etc/init.d/shadowsocks
                chmod +x /etc/init.d/shadowsocks
                echo -e "${green}[Info]${plain} init script installed successfully"
            else
                echo -e "${yellow}[Warning]${plain} Failed to download init script, creating systemd service..."
                
                # Check if nobody user exists, create if needed
                if ! id nobody >/dev/null 2>&1; then
                    echo -e "${yellow}[Info]${plain} Creating nobody user..."
                    useradd -r -s /sbin/nologin nobody
                fi
                
                cat > /etc/systemd/system/shadowsocks-libev.service << 'EOF'
[Unit]
Description=Shadowsocks-Libev Server Service
Documentation=man:ss-server(1)
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ss-server -c /etc/shadowsocks-libev/config.json
ExecStartPre=/bin/sh -c 'ulimit -n 51200'
Restart=on-failure
RestartSec=5s
User=nobody
Group=nobody
LimitNOFILE=51200

[Install]
WantedBy=multi-user.target
EOF
                systemctl daemon-reload
                systemctl enable shadowsocks-libev
                echo -e "${green}[Info]${plain} Created systemd service as fallback"
            fi
            cd ${currentdir}
        fi
    fi
    # Start shadowsocks service
    echo -e "${green}[Info]${plain} Starting shadowsocks service..."
    
    if check_centos_main_version 9; then
        # CentOS 9: Use systemd
        echo -e "${yellow}[DEBUG]${plain} Starting shadowsocks-libev service..."
        echo -e "${yellow}[DEBUG]${plain} Service file contents:"
        cat /etc/systemd/system/shadowsocks-libev.service
        echo -e "${yellow}[DEBUG]${plain} Config file contents:"
        cat /etc/shadowsocks-libev/config.json
        
        systemctl start shadowsocks-libev
        if [ $? -eq 0 ]; then
            echo -e "${green}[Info]${plain} Shadowsocks started successfully via systemd"
            echo -e "${yellow}[DEBUG]${plain} Service status:"
            systemctl status shadowsocks-libev --no-pager -l | head -10
        else
            echo -e "${red}[Error]${plain} Failed to start shadowsocks via systemd!"
            echo -e "${yellow}[DEBUG]${plain} ===== SERVICE FAILURE ANALYSIS ====="
            echo -e "${yellow}[DEBUG]${plain} systemctl status output:"
            systemctl status shadowsocks-libev --no-pager -l
            echo -e "${yellow}[DEBUG]${plain} journalctl logs (last 20 lines):"
            journalctl -u shadowsocks-libev --no-pager -l -n 20
            echo -e "${yellow}[DEBUG]${plain} Checking file permissions:"
            ls -la /usr/local/bin/ss-server /etc/shadowsocks-libev/config.json
            echo -e "${yellow}[DEBUG]${plain} Testing manual start:"
            /usr/local/bin/ss-server -c /etc/shadowsocks-libev/config.json --help | head -5
            echo -e "${yellow}[DEBUG]${plain} ===== END FAILURE ANALYSIS ====="
            exit 1
        fi
    else
        # CentOS 6-8: Try init script first, then systemd
        if [ -f /etc/init.d/shadowsocks ]; then
            chmod +x /etc/init.d/shadowsocks
            /etc/init.d/shadowsocks start
            if [ $? -eq 0 ]; then
                echo -e "${green}[Info]${plain} Shadowsocks started successfully via init script"
                # Enable service for auto-start
                if check_release centos; then
                    chkconfig --add shadowsocks
                    chkconfig shadowsocks on
                else
                    update-rc.d -f shadowsocks defaults
                fi
            else
                echo -e "${yellow}[Warning]${plain} Init script failed, trying systemd..."
                systemctl start shadowsocks-libev
                if [ $? -eq 0 ]; then
                    echo -e "${green}[Info]${plain} Shadowsocks started successfully via systemd"
                else
                    echo -e "${red}[Error]${plain} Failed to start shadowsocks via both init and systemd!"
                    exit 1
                fi
            fi
        elif [ -f /etc/systemd/system/shadowsocks-libev.service ]; then
            systemctl start shadowsocks-libev
            if [ $? -eq 0 ]; then
                echo -e "${green}[Info]${plain} Shadowsocks started successfully via systemd"
            else
                echo -e "${red}[Error]${plain} Failed to start shadowsocks via systemd!"
                echo -e "${yellow}[Debug]${plain} systemctl status output:"
                systemctl status shadowsocks-libev --no-pager -l
                exit 1
            fi
        else
            echo -e "${red}[Error]${plain} No service script available!"
            exit 1
        fi
    fi

    cd ${currentdir}
    if [[ ${updateornot} == "not" ]]; then
        rm -rf ${shadowsocksver} ${shadowsocksver}.tar.gz
    else
        rm -rf ${shadowsocksnewver} ${shadowsocksnewver}.tar.gz
    fi
}

#Uninstall shadowsocks
function uninstall_shadowsocks() {
    ps -ef | grep -v "grep" | grep "ss-server" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        /etc/init.d/shadowsocks stop
    fi
    if check_release centos; then
        chkconfig --del shadowsocks
    else
        update-rc.d -f shadowsocks remove
    fi
    rm -rf /etc/shadowsocks-libev
    rm -f /usr/local/bin/ss-local
    rm -f /usr/local/bin/ss-tunnel
    rm -f /usr/local/bin/ss-server
    rm -f /usr/local/bin/ss-manager
    rm -f /usr/local/bin/ss-redir
    rm -f /usr/local/bin/ss-nat
    rm -f /usr/local/lib/libshadowsocks-libev.a
    rm -f /usr/local/lib/libshadowsocks-libev.la
    rm -f /usr/local/include/shadowsocks.h
    rm -f /usr/local/lib/pkgconfig/shadowsocks-libev.pc
    rm -f /usr/local/share/man/man1/ss-local.1
    rm -f /usr/local/share/man/man1/ss-tunnel.1
    rm -f /usr/local/share/man/man1/ss-server.1
    rm -f /usr/local/share/man/man1/ss-manager.1
    rm -f /usr/local/share/man/man1/ss-redir.1
    rm -f /usr/local/share/man/man1/ss-nat.1
    rm -f /usr/local/share/man/man8/shadowsocks-libev.8
    rm -rf /usr/local/share/doc/shadowsocks-libev
    rm -f /etc/init.d/shadowsocks
    rm -f /root/shadowsocks.txt
}

#Install success
function install_success() {
    local ssurl=$(echo -n "${sscipher}:${sspassword}@$(get_ipv4):${ssport}" | base64 -w0)
    clear
    echo -e "${green}[Info]${plain} Congratulations, Shadowsocks has been installed successfully."
    echo -e "================================================="
    echo -e "Server IP        : \033[41;37m $(get_ipv4) \033[0m"
    echo -e "Server Port      : \033[41;37m ${ssport} \033[0m"
    echo -e "Password         : \033[41;37m ${sspassword} \033[0m"
    echo -e "Encryption Method: \033[41;37m ${sscipher} \033[0m"
    echo -e "-------------------------------------------------"
    echo -e "ss://${ssurl}"
    echo -e "================================================="

    cat > /root/shadowsocks.txt << EOF
===============================================
Server IP        : $(get_ipv4)
Server Port      : ${ssport}
Password         : ${sspassword}
Encryption Method: ${sscipher}
-----------------------------------------------
ss://${ssurl}
===============================================
EOF
    echo -e "You can find the config's backup in /root/shadowsocks.txt."
    echo -e "Windows Client：https://github.com/shadowsocks/shadowsocks-windows/releases"
    echo -e "macOS Client：https://github.com/shadowsocks/ShadowsocksX-NG/releases"
    echo -e "Android Client：https://github.com/shadowsocks/shadowsocks-android/releases"
    echo -e "iPhone/iPad Client：App Store install shadowrocket"
    echo -e ""
    echo -e "For more tutorials: https://www.banwagongzw.com & https://www.vultrcn.com"
}

install_main() {
    disable_selinux
    set_shadowsocks_config
    install_dependencies
    set_firewall
    install_libsodium
    install_mbedtls
    install_obfs
    config_shadowsocks
    install_shadowsocks
    install_success
}

install_main_easy() {
    check_shadowsocks_status
    disable_selinux
    set_shadowsocks_config_easy
    install_dependencies
    set_firewall
    install_libsodium
    install_mbedtls
    install_obfs
    config_shadowsocks
    install_shadowsocks
    install_success
}

uninstall_main() {
    uninstall_shadowsocks
    echo -e "${green}[Info]${plain} Shadowsocks uninstall successfully."
}

update_main() {
    if [[ ${updateornot} == "update" ]]; then
        ps -ef | grep -v grep | grep -i "ss-server" > /dev/null 2>&1
        [ $? -eq 0 ] && /etc/init.d/shadowsocks stop
        install_shadowsocks
        echo -e "${green}[Info]${plain} Shadowsocks Update successfully."
    else
        echo -e "${green}[Info]${plain} Latest version has been installed."
    fi
}

start_main() {
    if [ -f /etc/init.d/shadowsocks ]; then
        /etc/init.d/shadowsocks start
        if [ $? -eq 0 ]; then
            echo -e "${green}[Info]${plain} Shadowsocks start successfully."
        else
            echo -e "${red}[Error]${plain} Shadowsocks start failed, please try again!"
        fi
    elif [ -f /etc/systemd/system/shadowsocks-libev.service ]; then
        systemctl start shadowsocks-libev
        if [ $? -eq 0 ]; then
            echo -e "${green}[Info]${plain} Shadowsocks start successfully."
        else
            echo -e "${red}[Error]${plain} Shadowsocks start failed, please try again!"
        fi
    else
        echo -e "${red}[Error]${plain} No shadowsocks service found!"
    fi
}

stop_main() {
    if [ -f /etc/init.d/shadowsocks ]; then
        /etc/init.d/shadowsocks stop
        if [ $? -eq 0 ]; then
            echo -e "${green}[Info]${plain} Shadowsocks stop successfully."
        else
            echo -e "${red}[Error]${plain} Shadowsocks stop failed, please try again!"
        fi
    elif [ -f /etc/systemd/system/shadowsocks-libev.service ]; then
        systemctl stop shadowsocks-libev
        if [ $? -eq 0 ]; then
            echo -e "${green}[Info]${plain} Shadowsocks stop successfully."
        else
            echo -e "${red}[Error]${plain} Shadowsocks stop failed, please try again!"
        fi
    else
        echo -e "${red}[Error]${plain} No shadowsocks service found!"
    fi
}

restart_main() {
    if [ -f /etc/init.d/shadowsocks ]; then
        /etc/init.d/shadowsocks stop
        /etc/init.d/shadowsocks start
        if [ $? -eq 0 ]; then
            echo -e "${green}[Info]${plain} Shadowsocks restart successfully."
        else
            echo -e "${red}[Error]${plain} Shadowsocks restart failed, please try again!"
        fi
    elif [ -f /etc/systemd/system/shadowsocks-libev.service ]; then
        systemctl restart shadowsocks-libev
        if [ $? -eq 0 ]; then
            echo -e "${green}[Info]${plain} Shadowsocks restart successfully."
        else
            echo -e "${red}[Error]${plain} Shadowsocks restart failed, please try again!"
        fi
    else
        echo -e "${red}[Error]${plain} No shadowsocks service found!"
    fi
}

status_main() {
    echo -e "${green}[Info]${plain} Congratulations, Shadowsocks has been installed successfully."
    cat /root/shadowsocks.txt
    echo "This information is just for reference. Please view the Shadowsocks configuration file."
}

modify_main() {
    set_shadowsocks_config
    
    # Stop service
    if [ -f /etc/init.d/shadowsocks ]; then
        /etc/init.d/shadowsocks stop
    elif [ -f /etc/systemd/system/shadowsocks-libev.service ]; then
        systemctl stop shadowsocks-libev
    fi
    
    set_firewall
    config_shadowsocks
    
    # Start service
    if [ -f /etc/init.d/shadowsocks ]; then
        /etc/init.d/shadowsocks start
    elif [ -f /etc/systemd/system/shadowsocks-libev.service ]; then
        systemctl start shadowsocks-libev
    fi
    
    install_success
}

#Main control
password="unset"
while getopts p: flag
do
    case "${flag}" in
        p) password=${OPTARG};;
    esac
done
echo "Password: $password";

if [ ${password} = "unset" ]; then
        echo "password need to be setted!"
        exit 0
fi

install_main_easy
