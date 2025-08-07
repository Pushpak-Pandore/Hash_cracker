#!/bin/bash

# ==== Colors ====
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# ==== Dependency Check & Auto-Install ====
echo -e "${YELLOW}[~] Checking dependencies...${NC}"

# Install figlet
if ! command -v figlet &> /dev/null; then
    echo -e "${CYAN}[+] Installing figlet...${NC}"
    sudo apt update && sudo apt install -y figlet
fi

# Install toilet (optional)
if ! command -v toilet &> /dev/null; then
    echo -e "${CYAN}[+] Installing toilet...${NC}"
    sudo apt install -y toilet
fi

# Install Python & packages
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python3 not found. Installing...${NC}"
    sudo apt update && sudo apt install python3 -y
fi

if ! command -v pip3 &> /dev/null; then
    echo -e "${RED}[!] pip3 not found. Installing...${NC}"
    sudo apt install python3-pip -y
fi

pip3 install -r requirements.txt 2>/dev/null || pip3 install passlib

clear

# ==== Matrix-style Banner ====
echo -e "$CYAN"
echo -e "        welcome"
echo -e "$GREEN"
figlet -f slant "HashCrackX"
echo -e "${CYAN}👨‍💻 Created by: Pushpak Pandore${NC}"
echo "==========================================="

# === Supported Hash Types ===
SUPPORTED_HASHES=("md5" "sha1" "sha224" "sha256" "sha384" "sha512" "sha3_224" "sha3_256" "sha3_384" "sha3_512" "bcrypt" "scrypt" "argon2" "sha512_crypt")

# === Get Target Hash ===
read -p "🔑 Enter hash to crack: " TARGET_HASH

# === Hash Type Selection ===
echo -e "\n🔍 Choose hash type (or skip for auto-detect):"
select htype in "${SUPPORTED_HASHES[@]}" "Auto-detect"; do
    if [[ "$htype" == "Auto-detect" ]]; then
        HASH_TYPE=""
        break
    elif [[ " ${SUPPORTED_HASHES[*]} " =~ " ${htype} " ]]; then
        HASH_TYPE=$htype
        break
    else
        echo -e "${YELLOW}[!] Invalid selection. Try again.${NC}"
    fi
done

# === Choose Attack Mode ===
echo -e "\n🛠️ Choose attack mode:"
select mode in "Wordlist Attack" "Brute-force Attack"; do
    case $mode in
        "Wordlist Attack")
            read -p "📄 Enter path to wordlist file: " WORDLIST_PATH
            if [[ ! -f "$WORDLIST_PATH" ]]; then
                echo -e "${RED}[X] Wordlist file not found!${NC}"
                exit 1
            fi

            echo -e "\n🚀 Starting HashCrackX (Wordlist Mode)...\n"
            python3 hashcrackx_cli1.py \
              --hash "$TARGET_HASH" \
              --hash-type "$HASH_TYPE" \
              --use-wordlist \
              --wordlist "$WORDLIST_PATH" \
              --save-output cracked.txt
            break
            ;;
        "Brute-force Attack")
            read -p "🔢 Enter minimum password length (default 1): " MIN_LEN
            read -p "🔢 Enter maximum password length (default 4): " MAX_LEN
            read -p "🔡 Enter character set (default: a-zA-Z0-9): " CHARSET
            read -p "🧠 Number of processors to use (default: all): " NUM_WORKERS

            MIN_LEN=${MIN_LEN:-1}
            MAX_LEN=${MAX_LEN:-4}
            CHARSET=${CHARSET:-'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'}
            NUM_WORKERS=${NUM_WORKERS:-$(nproc)}

            echo -e "\n🚀 Starting HashCrackX (Brute Force Mode)...\n"
            python3 hashcrackx_cli1.py \
              --hash "$TARGET_HASH" \
              --hash-type "$HASH_TYPE" \
              --min-length "$MIN_LEN" \
              --max-length "$MAX_LEN" \
              --characters "$CHARSET" \
              --max-workers "$NUM_WORKERS" \
              --save-output cracked.txt
            break
            ;;
        *)
            echo -e "${YELLOW}[!] Invalid selection. Try again.${NC}"
            ;;
    esac
done

