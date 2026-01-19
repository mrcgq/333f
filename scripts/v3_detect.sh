
#!/bin/bash
#
# v3 Smart Detector - 智能检测 VPS 配置并推荐合适的 v3 版本
#
# 使用方法:
#   curl -sSL https://xxx/v3_detect.sh | bash
#   或
#   ./v3_detect.sh [--json] [--install]
#

set -e

# =========================================================================
# 颜色与样式
# =========================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# =========================================================================
# 版本定义
# =========================================================================
declare -A V3_VERSIONS=(
    ["v5"]="Enterprise|T0 Max|主力推荐：极致性能 + 全功能"
    ["v6"]="Portable|战术级|极限兼容：静态编译，零依赖"
    ["v7"]="Rescue|生存级|救灾模式：WSS 伪装 HTTPS"
    ["v8"]="Turbo|T0 暴力|暴力竞速：Brutal + XOR FEC"
    ["v9"]="Turbo-Portable|T0 变异|低配竞速：静态 + 暴力"
)

# =========================================================================
# 检测结果存储
# =========================================================================
declare -A DETECT_RESULT
declare -A VERSION_COMPAT

# =========================================================================
# 1. 系统环境检测
# =========================================================================

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DETECT_RESULT["os_name"]="$ID"
        DETECT_RESULT["os_version"]="$VERSION_ID"
        DETECT_RESULT["os_pretty"]="$PRETTY_NAME"
    else
        DETECT_RESULT["os_name"]="unknown"
        DETECT_RESULT["os_version"]="unknown"
        DETECT_RESULT["os_pretty"]="Unknown Linux"
    fi
}

detect_kernel() {
    local kernel=$(uname -r)
    DETECT_RESULT["kernel_full"]="$kernel"
    
    # 提取主版本号
    local major=$(echo "$kernel" | cut -d. -f1)
    local minor=$(echo "$kernel" | cut -d. -f2)
    DETECT_RESULT["kernel_major"]="$major"
    DETECT_RESULT["kernel_minor"]="$minor"
    DETECT_RESULT["kernel_version"]="$major.$minor"
}

detect_virtualization() {
    local virt="unknown"
    
    # 方法 1: systemd-detect-virt
    if command -v systemd-detect-virt &>/dev/null; then
        virt=$(systemd-detect-virt 2>/dev/null || echo "unknown")
    fi
    
    # 方法 2: 检测特征文件
    if [[ "$virt" == "unknown" || "$virt" == "none" ]]; then
        if [[ -f /proc/vz/veinfo ]]; then
            virt="openvz"
        elif [[ -f /proc/xen/capabilities ]]; then
            virt="xen"
        elif grep -q "QEMU\|KVM" /proc/cpuinfo 2>/dev/null; then
            virt="kvm"
        elif grep -q "VMware" /proc/cpuinfo 2>/dev/null; then
            virt="vmware"
        elif grep -q "Hyper-V" /proc/cpuinfo 2>/dev/null; then
            virt="hyperv"
        elif [[ -f /.dockerenv ]]; then
            virt="docker"
        elif grep -q "lxc" /proc/1/cgroup 2>/dev/null; then
            virt="lxc"
        elif dmesg 2>/dev/null | grep -qi "vmware"; then
            virt="vmware"
        fi
    fi
    
    # 方法 3: DMI 信息
    if [[ "$virt" == "unknown" && -r /sys/class/dmi/id/product_name ]]; then
        local product=$(cat /sys/class/dmi/id/product_name 2>/dev/null)
        case "$product" in
            *"Virtual Machine"*) virt="hyperv" ;;
            *"VMware"*) virt="vmware" ;;
            *"KVM"*|*"QEMU"*) virt="kvm" ;;
            *"VirtualBox"*) virt="virtualbox" ;;
        esac
    fi
    
    DETECT_RESULT["virt"]="$virt"
    
    # 判断是否为完全虚拟化（支持自定义内核）
    case "$virt" in
        kvm|vmware|xen|hyperv|virtualbox|none)
            DETECT_RESULT["full_virt"]="yes"
            ;;
        openvz|lxc|docker)
            DETECT_RESULT["full_virt"]="no"
            ;;
        *)
            DETECT_RESULT["full_virt"]="unknown"
            ;;
    esac
}

detect_cpu() {
    # 架构
    local arch=$(uname -m)
    DETECT_RESULT["arch"]="$arch"
    
    # CPU 型号
    local cpu_model=$(grep "model name" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs)
    if [[ -z "$cpu_model" ]]; then
        cpu_model=$(grep "CPU part" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs)
    fi
    DETECT_RESULT["cpu_model"]="${cpu_model:-Unknown}"
    
    # CPU 核心数
    local cores=$(nproc 2>/dev/null || echo 1)
    DETECT_RESULT["cpu_cores"]="$cores"
    
    # SIMD 特性检测
    local flags=$(grep "flags" /proc/cpuinfo 2>/dev/null | head -1 || echo "")
    
    DETECT_RESULT["has_sse42"]="no"
    DETECT_RESULT["has_avx"]="no"
    DETECT_RESULT["has_avx2"]="no"
    DETECT_RESULT["has_avx512"]="no"
    DETECT_RESULT["has_neon"]="no"
    
    if [[ "$arch" == "x86_64" ]]; then
        [[ "$flags" == *"sse4_2"* ]] && DETECT_RESULT["has_sse42"]="yes"
        [[ "$flags" == *"avx "* || "$flags" == *"avx2"* ]] && DETECT_RESULT["has_avx"]="yes"
        [[ "$flags" == *"avx2"* ]] && DETECT_RESULT["has_avx2"]="yes"
        [[ "$flags" == *"avx512"* ]] && DETECT_RESULT["has_avx512"]="yes"
    elif [[ "$arch" == "aarch64" ]]; then
        # ARM64 默认支持 NEON
        DETECT_RESULT["has_neon"]="yes"
    fi
    
    # 确定 SIMD 级别
    if [[ "${DETECT_RESULT["has_avx512"]}" == "yes" ]]; then
        DETECT_RESULT["simd_level"]="avx512"
    elif [[ "${DETECT_RESULT["has_avx2"]}" == "yes" ]]; then
        DETECT_RESULT["simd_level"]="avx2"
    elif [[ "${DETECT_RESULT["has_sse42"]}" == "yes" ]]; then
        DETECT_RESULT["simd_level"]="sse42"
    elif [[ "${DETECT_RESULT["has_neon"]}" == "yes" ]]; then
        DETECT_RESULT["simd_level"]="neon"
    else
        DETECT_RESULT["simd_level"]="generic"
    fi
}

detect_memory() {
    local mem_kb=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}')
    local mem_mb=$((mem_kb / 1024))
    
    DETECT_RESULT["mem_mb"]="$mem_mb"
    DETECT_RESULT["mem_gb"]="$((mem_mb / 1024))"
    
    # 内存等级分类
    if [[ $mem_mb -lt 128 ]]; then
        DETECT_RESULT["mem_class"]="极低"
    elif [[ $mem_mb -lt 256 ]]; then
        DETECT_RESULT["mem_class"]="超低"
    elif [[ $mem_mb -lt 512 ]]; then
        DETECT_RESULT["mem_class"]="低"
    elif [[ $mem_mb -lt 1024 ]]; then
        DETECT_RESULT["mem_class"]="一般"
    elif [[ $mem_mb -lt 2048 ]]; then
        DETECT_RESULT["mem_class"]="良好"
    else
        DETECT_RESULT["mem_class"]="充足"
    fi
}

detect_io_uring() {
    DETECT_RESULT["has_io_uring"]="no"
    DETECT_RESULT["io_uring_reason"]=""
    
    local major=${DETECT_RESULT["kernel_major"]}
    local minor=${DETECT_RESULT["kernel_minor"]}
    
    # 检查内核版本 (需要 5.1+)
    if [[ $major -lt 5 ]] || [[ $major -eq 5 && $minor -lt 1 ]]; then
        DETECT_RESULT["io_uring_reason"]="内核版本 ${major}.${minor} < 5.1"
        return
    fi
    
    # 检查是否为容器/OpenVZ (可能受限)
    if [[ "${DETECT_RESULT["virt"]}" == "openvz" ]]; then
        DETECT_RESULT["io_uring_reason"]="OpenVZ 共享内核不支持"
        return
    fi
    
    # 尝试编译测试程序检查
    if command -v gcc &>/dev/null; then
        local test_prog='
#include <linux/io_uring.h>
#include <sys/syscall.h>
#include <unistd.h>
int main() {
    struct io_uring_params p = {0};
    return syscall(__NR_io_uring_setup, 1, &p) >= 0 ? 0 : 1;
}'
        if echo "$test_prog" | gcc -x c - -o /tmp/io_uring_test 2>/dev/null; then
            if /tmp/io_uring_test 2>/dev/null; then
                DETECT_RESULT["has_io_uring"]="yes"
            else
                DETECT_RESULT["io_uring_reason"]="系统调用不可用"
            fi
            rm -f /tmp/io_uring_test
        else
            # 无法编译测试，基于内核版本判断
            DETECT_RESULT["has_io_uring"]="likely"
            DETECT_RESULT["io_uring_reason"]="内核版本支持，未实际验证"
        fi
    else
        # 无 gcc，基于内核版本判断
        if [[ $major -ge 5 && $minor -ge 1 ]]; then
            DETECT_RESULT["has_io_uring"]="likely"
            DETECT_RESULT["io_uring_reason"]="内核版本支持，未实际验证"
        fi
    fi
}

detect_xdp() {
    DETECT_RESULT["has_xdp"]="no"
    DETECT_RESULT["xdp_reason"]=""
    
    local major=${DETECT_RESULT["kernel_major"]}
    local minor=${DETECT_RESULT["kernel_minor"]}
    
    # XDP 需要 4.8+，完整功能需要 5.6+
    if [[ $major -lt 4 ]] || [[ $major -eq 4 && $minor -lt 8 ]]; then
        DETECT_RESULT["xdp_reason"]="内核版本 ${major}.${minor} < 4.8"
        return
    fi
    
    # 容器环境检查
    if [[ "${DETECT_RESULT["virt"]}" == "openvz" ]]; then
        DETECT_RESULT["xdp_reason"]="OpenVZ 不支持 XDP"
        return
    fi
    
    if [[ "${DETECT_RESULT["virt"]}" == "docker" || "${DETECT_RESULT["virt"]}" == "lxc" ]]; then
        DETECT_RESULT["xdp_reason"]="容器需要 --privileged 权限"
        DETECT_RESULT["has_xdp"]="maybe"
        return
    fi
    
    # 检查 bpf 系统调用
    if [[ -e /sys/fs/bpf ]]; then
        DETECT_RESULT["has_xdp"]="yes"
    else
        if [[ $major -ge 5 ]]; then
            DETECT_RESULT["has_xdp"]="likely"
            DETECT_RESULT["xdp_reason"]="内核支持，/sys/fs/bpf 未挂载"
        fi
    fi
}

detect_network() {
    DETECT_RESULT["has_ipv4"]="no"
    DETECT_RESULT["has_ipv6"]="no"
    DETECT_RESULT["udp_available"]="unknown"
    
    # IPv4
    if ip -4 addr show | grep -q "inet "; then
        DETECT_RESULT["has_ipv4"]="yes"
    fi
    
    # IPv6
    if ip -6 addr show | grep -q "inet6 " | grep -v "::1"; then
        DETECT_RESULT["has_ipv6"]="yes"
    fi
    
    # 获取默认网卡
    local default_iface=$(ip route | grep default | awk '{print $5}' | head -1)
    DETECT_RESULT["default_iface"]="${default_iface:-unknown}"
    
    # UDP 可用性测试（简单的本地测试）
    if command -v nc &>/dev/null; then
        # 尝试绑定 UDP 端口
        if timeout 1 nc -u -l -p 51821 &>/dev/null & then
            local pid=$!
            sleep 0.2
            kill $pid 2>/dev/null
            DETECT_RESULT["udp_available"]="yes"
        else
            DETECT_RESULT["udp_available"]="maybe"
        fi
    fi
}

detect_dependencies() {
    # 检查关键依赖
    DETECT_RESULT["has_gcc"]=$(command -v gcc &>/dev/null && echo "yes" || echo "no")
    DETECT_RESULT["has_clang"]=$(command -v clang &>/dev/null && echo "yes" || echo "no")
    DETECT_RESULT["has_musl"]=$(command -v musl-gcc &>/dev/null && echo "yes" || echo "no")
    DETECT_RESULT["has_openssl"]=$(command -v openssl &>/dev/null && echo "yes" || echo "no")
    
    # 检查库
    DETECT_RESULT["has_liburing"]="no"
    DETECT_RESULT["has_libsodium"]="no"
    DETECT_RESULT["has_libbpf"]="no"
    
    if ldconfig -p 2>/dev/null | grep -q liburing; then
        DETECT_RESULT["has_liburing"]="yes"
    elif [[ -f /usr/lib/liburing.so ]] || [[ -f /usr/lib64/liburing.so ]]; then
        DETECT_RESULT["has_liburing"]="yes"
    fi
    
    if ldconfig -p 2>/dev/null | grep -q libsodium; then
        DETECT_RESULT["has_libsodium"]="yes"
    elif [[ -f /usr/lib/libsodium.so ]] || [[ -f /usr/lib64/libsodium.so ]]; then
        DETECT_RESULT["has_libsodium"]="yes"
    fi
    
    if ldconfig -p 2>/dev/null | grep -q libbpf; then
        DETECT_RESULT["has_libbpf"]="yes"
    fi
}

# =========================================================================
# 2. 版本兼容性评估
# =========================================================================

evaluate_v5_enterprise() {
    # v5 Enterprise: io_uring + SIMD + 完整功能
    local score=0
    local issues=()
    local notes=()
    
    # io_uring 是必须的
    if [[ "${DETECT_RESULT["has_io_uring"]}" == "yes" ]]; then
        ((score += 40))
    elif [[ "${DETECT_RESULT["has_io_uring"]}" == "likely" ]]; then
        ((score += 30))
        notes+=("io_uring 未验证")
    else
        issues+=("需要 io_uring (内核 5.1+)")
    fi
    
    # SIMD 加分
    case "${DETECT_RESULT["simd_level"]}" in
        avx512) ((score += 30)); notes+=("AVX-512 加速") ;;
        avx2)   ((score += 25)); notes+=("AVX2 加速") ;;
        neon)   ((score += 25)); notes+=("NEON 加速") ;;
        sse42)  ((score += 20)); notes+=("SSE4.2 加速") ;;
        *)      ((score += 10)) ;;
    esac
    
    # XDP 可选加分
    if [[ "${DETECT_RESULT["has_xdp"]}" == "yes" ]]; then
        ((score += 15))
        notes+=("XDP 可用")
    fi
    
    # 内存要求
    if [[ ${DETECT_RESULT["mem_mb"]} -ge 256 ]]; then
        ((score += 15))
    else
        issues+=("建议内存 >= 256MB")
    fi
    
    VERSION_COMPAT["v5_score"]=$score
    VERSION_COMPAT["v5_issues"]="${issues[*]}"
    VERSION_COMPAT["v5_notes"]="${notes[*]}"
    
    if [[ ${#issues[@]} -eq 0 ]]; then
        VERSION_COMPAT["v5_status"]="compatible"
    elif [[ $score -ge 50 ]]; then
        VERSION_COMPAT["v5_status"]="partial"
    else
        VERSION_COMPAT["v5_status"]="incompatible"
    fi
}

evaluate_v6_portable() {
    # v6 Portable: 零依赖，静态编译
    local score=100  # 默认满分
    local issues=()
    local notes=()
    
    # 基本上所有环境都能运行
    notes+=("静态编译，无依赖")
    notes+=("兼容所有 Linux")
    
    # 性能会受限
    if [[ "${DETECT_RESULT["has_io_uring"]}" != "yes" ]]; then
        notes+=("使用 epoll 回退")
    fi
    
    # 内存极低时仍可运行
    if [[ ${DETECT_RESULT["mem_mb"]} -lt 64 ]]; then
        notes+=("内存极低，但仍可运行")
    fi
    
    VERSION_COMPAT["v6_score"]=$score
    VERSION_COMPAT["v6_issues"]="${issues[*]}"
    VERSION_COMPAT["v6_notes"]="${notes[*]}"
    VERSION_COMPAT["v6_status"]="compatible"
}

evaluate_v7_rescue() {
    # v7 Rescue: WSS 伪装
    local score=0
    local issues=()
    local notes=()
    
    # 需要 OpenSSL
    if [[ "${DETECT_RESULT["has_openssl"]}" == "yes" ]]; then
        ((score += 50))
    else
        issues+=("需要 OpenSSL")
    fi
    
    # TCP 443 端口权限
    if [[ $EUID -eq 0 ]]; then
        ((score += 30))
        notes+=("可绑定 443 端口")
    else
        notes+=("需要 root 绑定 443")
    fi
    
    # IPv4 可用
    if [[ "${DETECT_RESULT["has_ipv4"]}" == "yes" ]]; then
        ((score += 20))
    fi
    
    notes+=("伪装 HTTPS 流量")
    notes+=("适合 UDP 被封场景")
    
    VERSION_COMPAT["v7_score"]=$score
    VERSION_COMPAT["v7_issues"]="${issues[*]}"
    VERSION_COMPAT["v7_notes"]="${notes[*]}"
    
    if [[ ${#issues[@]} -eq 0 ]]; then
        VERSION_COMPAT["v7_status"]="compatible"
    else
        VERSION_COMPAT["v7_status"]="partial"
    fi
}

evaluate_v8_turbo() {
    # v8 Turbo: Brutal 暴力模式
    local score=0
    local issues=()
    local notes=()
    
    # io_uring 是必须的
    if [[ "${DETECT_RESULT["has_io_uring"]}" == "yes" ]]; then
        ((score += 40))
    elif [[ "${DETECT_RESULT["has_io_uring"]}" == "likely" ]]; then
        ((score += 30))
    else
        issues+=("需要 io_uring (内核 5.1+)")
    fi
    
    # 低 CPU 消耗是优势
    ((score += 30))
    notes+=("XOR FEC，CPU 占用极低")
    notes+=("Brutal 恒定速率发包")
    
    # 适合低配机器
    if [[ ${DETECT_RESULT["mem_mb"]} -lt 512 ]]; then
        ((score += 20))
        notes+=("适合低配机器")
    else
        ((score += 10))
    fi
    
    VERSION_COMPAT["v8_score"]=$score
    VERSION_COMPAT["v8_issues"]="${issues[*]}"
    VERSION_COMPAT["v8_notes"]="${notes[*]}"
    
    if [[ ${#issues[@]} -eq 0 ]]; then
        VERSION_COMPAT["v8_status"]="compatible"
    else
        VERSION_COMPAT["v8_status"]="incompatible"
    fi
}

evaluate_v9_turbo_portable() {
    # v9 Turbo-Portable: 静态 + 暴力
    local score=100
    local issues=()
    local notes=()
    
    # 混合架构
    notes+=("静态编译 + 暴力模式")
    notes+=("XOR FEC 低 CPU 纠错")
    notes+=("epoll + Brutal")
    
    # 极限兼容
    if [[ "${DETECT_RESULT["virt"]}" == "openvz" ]]; then
        ((score += 10))
        notes+=("专治 OpenVZ")
    fi
    
    # 极低内存
    if [[ ${DETECT_RESULT["mem_mb"]} -lt 128 ]]; then
        notes+=("64MB 内存也能跑")
    fi
    
    VERSION_COMPAT["v9_score"]=$score
    VERSION_COMPAT["v9_issues"]="${issues[*]}"
    VERSION_COMPAT["v9_notes"]="${notes[*]}"
    VERSION_COMPAT["v9_status"]="compatible"
}

evaluate_all_versions() {
    evaluate_v5_enterprise
    evaluate_v6_portable
    evaluate_v7_rescue
    evaluate_v8_turbo
    evaluate_v9_turbo_portable
}

# =========================================================================
# 3. 智能推荐
# =========================================================================

generate_recommendation() {
    local best_version=""
    local best_score=0
    local recommendations=()
    
    # 排序逻辑：根据环境选择最优版本
    
    # 场景 1: 高配 KVM/Xen，优先 v5
    if [[ "${VERSION_COMPAT["v5_status"]}" == "compatible" ]]; then
        if [[ ${VERSION_COMPAT["v5_score"]} -gt $best_score ]]; then
            best_version="v5"
            best_score=${VERSION_COMPAT["v5_score"]}
        fi
        recommendations+=("v5:Enterprise:${VERSION_COMPAT["v5_score"]}")
    fi
    
    # 场景 2: 需要暴力竞速
    if [[ "${VERSION_COMPAT["v8_status"]}" == "compatible" ]]; then
        if [[ ${DETECT_RESULT["mem_mb"]} -lt 512 ]]; then
            # 低配优先 v8
            if [[ $best_version != "v5" ]] || [[ ${VERSION_COMPAT["v8_score"]} -gt $best_score ]]; then
                best_version="v8"
                best_score=${VERSION_COMPAT["v8_score"]}
            fi
        fi
        recommendations+=("v8:Turbo:${VERSION_COMPAT["v8_score"]}")
    fi
    
    # 场景 3: 极端兼容需求
    if [[ "${DETECT_RESULT["virt"]}" == "openvz" ]] || 
       [[ "${DETECT_RESULT["has_io_uring"]}" == "no" ]]; then
        if [[ ${DETECT_RESULT["mem_mb"]} -lt 256 ]]; then
            best_version="v9"
            best_score=${VERSION_COMPAT["v9_score"]}
        else
            best_version="v6"
            best_score=${VERSION_COMPAT["v6_score"]}
        fi
    fi
    
    # 场景 4: UDP 可能受限，备选 v7
    recommendations+=("v7:Rescue:${VERSION_COMPAT["v7_score"]}")
    
    # 兜底：v6 和 v9 总是可用
    recommendations+=("v6:Portable:${VERSION_COMPAT["v6_score"]}")
    recommendations+=("v9:Turbo-Portable:${VERSION_COMPAT["v9_score"]}")
    
    DETECT_RESULT["best_version"]="$best_version"
    DETECT_RESULT["best_score"]="$best_score"
    DETECT_RESULT["recommendations"]="${recommendations[*]}"
}

# =========================================================================
# 4. 输出报告
# =========================================================================

print_banner() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                    ${BOLD}v3 Smart Detector - 智能版本匹配${NC}                         ${CYAN}║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_system_info() {
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  系统环境检测${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    # 操作系统
    echo -e "  ${PURPLE}操作系统:${NC}    ${DETECT_RESULT["os_pretty"]}"
    echo -e "  ${PURPLE}内核版本:${NC}    ${DETECT_RESULT["kernel_full"]}"
    echo -e "  ${PURPLE}虚拟化:${NC}      ${DETECT_RESULT["virt"]}"
    echo ""
    
    # CPU
    echo -e "  ${PURPLE}CPU 架构:${NC}    ${DETECT_RESULT["arch"]}"
    echo -e "  ${PURPLE}CPU 型号:${NC}    ${DETECT_RESULT["cpu_model"]}"
    echo -e "  ${PURPLE}CPU 核心:${NC}    ${DETECT_RESULT["cpu_cores"]}"
    echo -e "  ${PURPLE}SIMD 级别:${NC}   ${DETECT_RESULT["simd_level"]}"
    echo ""
    
    # 内存
    echo -e "  ${PURPLE}内存大小:${NC}    ${DETECT_RESULT["mem_mb"]} MB (${DETECT_RESULT["mem_class"]})"
    echo ""
    
    # 关键能力
    echo -e "  ${PURPLE}io_uring:${NC}    $(status_icon "${DETECT_RESULT["has_io_uring"]}") ${DETECT_RESULT["io_uring_reason"]}"
    echo -e "  ${PURPLE}XDP:${NC}         $(status_icon "${DETECT_RESULT["has_xdp"]}") ${DETECT_RESULT["xdp_reason"]}"
    echo -e "  ${PURPLE}网络接口:${NC}    ${DETECT_RESULT["default_iface"]}"
    echo ""
}

status_icon() {
    case "$1" in
        yes)    echo -e "${GREEN}✓ 支持${NC}" ;;
        likely) echo -e "${YELLOW}○ 可能支持${NC}" ;;
        maybe)  echo -e "${YELLOW}○ 受限${NC}" ;;
        no)     echo -e "${RED}✗ 不支持${NC}" ;;
        *)      echo -e "${YELLOW}? 未知${NC}" ;;
    esac
}

print_compatibility_matrix() {
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  版本兼容性矩阵${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    printf "  ${BOLD}%-8s %-18s %-12s %-8s %s${NC}\n" "版本" "代号" "评级" "兼容" "说明"
    echo "  ─────────────────────────────────────────────────────────────────────────────"
    
    for ver in v5 v6 v7 v8 v9; do
        local info="${V3_VERSIONS[$ver]}"
        local name=$(echo "$info" | cut -d'|' -f1)
        local tier=$(echo "$info" | cut -d'|' -f2)
        local status="${VERSION_COMPAT["${ver}_status"]}"
        local score="${VERSION_COMPAT["${ver}_score"]}"
        
        local status_str
        case "$status" in
            compatible)   status_str="${GREEN}✓ 可用${NC}" ;;
            partial)      status_str="${YELLOW}○ 部分${NC}" ;;
            incompatible) status_str="${RED}✗ 不可${NC}" ;;
        esac
        
        local notes="${VERSION_COMPAT["${ver}_notes"]}"
        [[ -n "${VERSION_COMPAT["${ver}_issues"]}" ]] && notes="${VERSION_COMPAT["${ver}_issues"]}"
        
        printf "  %-8s %-18s %-12s ${status_str}   %s\n" "$ver" "$name" "$tier" "${notes:0:40}"
    done
    
    echo ""
}

print_recommendation() {
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  🎯 智能推荐${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    local best="${DETECT_RESULT["best_version"]}"
    local info="${V3_VERSIONS[$best]}"
    local name=$(echo "$info" | cut -d'|' -f1)
    local tier=$(echo "$info" | cut -d'|' -f2)
    local desc=$(echo "$info" | cut -d'|' -f3)
    
    echo -e "  ${GREEN}${BOLD}推荐版本: $best ($name)${NC}"
    echo -e "  ${CYAN}评级: $tier${NC}"
    echo -e "  ${PURPLE}说明: $desc${NC}"
    echo ""
    
    # 打印推荐理由
    echo -e "  ${BOLD}推荐理由:${NC}"
    
    case "$best" in
        v5)
            echo -e "    • 您的 VPS 支持 io_uring，可发挥最大性能"
            echo -e "    • SIMD 级别: ${DETECT_RESULT["simd_level"]}，FEC 编码速度快"
            [[ "${DETECT_RESULT["has_xdp"]}" == "yes" ]] && echo -e "    • XDP 可用，内核级过滤"
            ;;
        v6)
            echo -e "    • 您的环境受限，需要极限兼容版本"
            echo -e "    • 静态编译，无需任何依赖库"
            echo -e "    • 使用 epoll，兼容老旧内核"
            ;;
        v7)
            echo -e "    • 适合 UDP 可能受限的网络环境"
            echo -e "    • 伪装成 HTTPS 流量"
            echo -e "    • 可配合 CDN 使用"
            ;;
        v8)
            echo -e "    • 低配机器上的暴力选择"
            echo -e "    • XOR FEC 极低 CPU 消耗"
            echo -e "    • Brutal 模式抗丢包"
            ;;
        v9)
            echo -e "    • 极限兼容 + 暴力性能的结合"
            echo -e "    • 静态编译 + Brutal 模式"
            echo -e "    • 专为电子垃圾 + 烂线路设计"
            ;;
    esac
    
    echo ""
    
    # 备选方案
    echo -e "  ${BOLD}备选方案:${NC}"
    
    if [[ "$best" != "v6" ]]; then
        echo -e "    • v6 (Portable) - 如遇兼容问题，可随时切换"
    fi
    if [[ "$best" != "v7" ]]; then
        echo -e "    • v7 (Rescue) - UDP 被封时的备用方案"
    fi
    if [[ "$best" != "v9" && "${DETECT_RESULT["mem_mb"]}" -lt 512 ]]; then
        echo -e "    • v9 (Turbo-Portable) - 超低配环境的暴力选择"
    fi
    
    echo ""
}

print_install_command() {
    local best="${DETECT_RESULT["best_version"]}"
    
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  📦 安装命令${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    echo -e "  ${CYAN}# 推荐版本一键安装${NC}"
    echo -e "  curl -sSL https://raw.githubusercontent.com/xxx/v3/main/install.sh | bash -s -- --version $best"
    echo ""
    
    echo -e "  ${CYAN}# 或者手动选择版本${NC}"
    echo -e "  curl -sSL https://raw.githubusercontent.com/xxx/v3/main/install.sh | bash -s -- --interactive"
    echo ""
}

print_json_output() {
    echo "{"
    echo "  \"system\": {"
    echo "    \"os\": \"${DETECT_RESULT["os_name"]}\","
    echo "    \"os_version\": \"${DETECT_RESULT["os_version"]}\","
    echo "    \"kernel\": \"${DETECT_RESULT["kernel_full"]}\","
    echo "    \"virt\": \"${DETECT_RESULT["virt"]}\","
    echo "    \"arch\": \"${DETECT_RESULT["arch"]}\","
    echo "    \"cpu_model\": \"${DETECT_RESULT["cpu_model"]}\","
    echo "    \"cpu_cores\": ${DETECT_RESULT["cpu_cores"]},"
    echo "    \"mem_mb\": ${DETECT_RESULT["mem_mb"]},"
    echo "    \"simd_level\": \"${DETECT_RESULT["simd_level"]}\""
    echo "  },"
    echo "  \"capabilities\": {"
    echo "    \"io_uring\": \"${DETECT_RESULT["has_io_uring"]}\","
    echo "    \"xdp\": \"${DETECT_RESULT["has_xdp"]}\","
    echo "    \"full_virt\": \"${DETECT_RESULT["full_virt"]}\""
    echo "  },"
    echo "  \"recommendation\": {"
    echo "    \"best_version\": \"${DETECT_RESULT["best_version"]}\","
    echo "    \"score\": ${DETECT_RESULT["best_score"]}"
    echo "  },"
    echo "  \"compatibility\": {"
    
    local first=true
    for ver in v5 v6 v7 v8 v9; do
        [[ "$first" != "true" ]] && echo ","
        first=false
        echo -n "    \"$ver\": {\"status\": \"${VERSION_COMPAT["${ver}_status"]}\", \"score\": ${VERSION_COMPAT["${ver}_score"]}}"
    done
    
    echo ""
    echo "  }"
    echo "}"
}

# =========================================================================
# 5. 主程序
# =========================================================================

main() {
    local json_mode=false
    local install_mode=false
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --json)
                json_mode=true
                shift
                ;;
            --install)
                install_mode=true
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --json      输出 JSON 格式"
                echo "  --install   检测后自动安装推荐版本"
                echo "  --help      显示帮助"
                exit 0
                ;;
            *)
                shift
                ;;
        esac
    done
    
    # 执行检测
    detect_os
    detect_kernel
    detect_virtualization
    detect_cpu
    detect_memory
    detect_io_uring
    detect_xdp
    detect_network
    detect_dependencies
    
    # 评估兼容性
    evaluate_all_versions
    
    # 生成推荐
    generate_recommendation
    
    # 输出结果
    if [[ "$json_mode" == "true" ]]; then
        print_json_output
    else
        print_banner
        print_system_info
        print_compatibility_matrix
        print_recommendation
        print_install_command
    fi
    
    # 自动安装模式
    if [[ "$install_mode" == "true" ]]; then
        echo ""
        echo -e "${YELLOW}即将安装推荐版本: ${DETECT_RESULT["best_version"]}${NC}"
        read -p "确认安装? [y/N] " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            # 调用安装脚本
            curl -sSL "https://xxx/install.sh" | bash -s -- --version "${DETECT_RESULT["best_version"]}"
        fi
    fi
}

main "$@"









