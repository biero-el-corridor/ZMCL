# ESP32-H2 Zigbee Sniffer — Guide d'installation complet

Transformer un ESP32-H2 en sniffer IEEE 802.15.4 (Zigbee / Thread) avec sortie PCAP vers Wireshark.

> **Firmware utilisé** : `ieee802154_cli` — l'outil officiel Espressif (exemples ESP-IDF)
>
> **Testé sur** : Waveshare ESP32-H2-Zero / ESP32-H2-DEV-KIT-N4 (chip revision v1.2)

---

## Table des matières

- [Prérequis](#prérequis)
- [1. Installer ESP-IDF v5.5](#1-installer-esp-idf-v55)
  - [Linux (Ubuntu / Debian)](#linux-ubuntu--debian)
  - [Windows](#windows)
  - [macOS](#macos)
- [2. Compiler le firmware sniffer](#2-compiler-le-firmware-sniffer)
- [3. Flasher l'ESP32-H2](#3-flasher-lesp32-h2)
- [4. Utiliser le sniffer](#4-utiliser-le-sniffer)
- [5. Capturer en PCAP pour Wireshark](#5-capturer-en-pcap-pour-wireshark)
- [6. Configurer Wireshark pour Zigbee](#6-configurer-wireshark-pour-zigbee)
- [Dépannage](#dépannage)
- [Notes importantes](#notes-importantes)

---

## Prérequis

### Matériel

| Élément | Détails |
|---------|---------|
| Carte ESP32-H2 | Waveshare ESP32-H2-Zero, ESP32-H2-DEV-KIT-N4, ou Espressif ESP32-H2-DevKitM-1 |
| Câble USB-C | Un câble **data** (pas un câble de charge seul) |
| PC | Windows 10/11, Linux ou macOS |

### Logiciel

| Logiciel | Version | Rôle |
|----------|---------|------|
| Git | 2.x+ | Cloner les dépôts |
| Python | 3.9+ | Toolchain ESP-IDF |
| CMake | 3.16+ | Build system |
| ESP-IDF | **v5.5** | Framework Espressif |
| pyserial | dernière | Script de capture PCAP |
| Wireshark | 3.x+ | Analyse des captures |

> ⚠️ **ESP-IDF v5.5 minimum obligatoire.** Les ESP32-H2 récents (revision v1.2) ne sont pas supportés par les versions antérieures (v5.3, v5.4). Le bootloader refuse de démarrer avec l'erreur `chip revision in range [v0.0 - v0.99]`.

---

## 1. Installer ESP-IDF v5.5

### Linux (Ubuntu / Debian)

#### 1.1 Installer les prérequis système

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git wget flex bison gperf python3 \
  python3-pip python3-venv cmake ninja-build ccache \
  libffi-dev libssl-dev dfu-util libusb-1.0-0
```

#### 1.2 Cloner ESP-IDF v5.5

```bash
mkdir -p ~/esp
cd ~/esp
git clone -b v5.5 --recursive https://github.com/espressif/esp-idf.git
cd esp-idf
```

> ⚠️ **L'option `--recursive` est obligatoire.** Sans elle, les sous-modules (CMock, nimble, micro-ecc, libs BT, etc.) ne sont pas téléchargés et la compilation échoue. Si vous avez oublié `--recursive`, rattrapez avec :
> ```bash
> git submodule update --init --recursive
> ```

#### 1.3 Installer la toolchain pour ESP32-H2

```bash
./install.sh esp32h2
```

Cette commande télécharge le compilateur RISC-V (`esp-14.2.0`), les outils de debug et configure l'environnement Python. Comptez quelques minutes.

#### 1.4 Activer l'environnement ESP-IDF

```bash
. ~/esp/esp-idf/export.sh
```

> 💡 **Cette commande doit être exécutée à chaque nouveau terminal.** Ajoutez un alias dans votre `~/.bashrc` :
> ```bash
> echo "alias get_idf='. ~/esp/esp-idf/export.sh'" >> ~/.bashrc
> source ~/.bashrc
> ```
> Ensuite il suffit de taper `get_idf` pour activer l'environnement.

#### 1.5 Vérifier l'installation

```bash
idf.py --version
# Doit afficher : ESP-IDF v5.5
```

#### 1.6 Ajouter l'accès au port série

```bash
sudo usermod -a -G dialout $USER
# Redémarrez votre session pour appliquer
```

---

### Windows

#### Méthode rapide : installeur graphique

1. Téléchargez l'installeur depuis : https://dl.espressif.com/dl/esp-idf/
2. Lancez-le et sélectionnez la version **v5.5**
3. Cochez la cible **ESP32-H2**
4. Terminez l'installation
5. Ouvrez le raccourci **« ESP-IDF PowerShell »**

#### Méthode manuelle (PowerShell)

```powershell
mkdir C:\esp
cd C:\esp
git clone -b v5.5 --recursive https://github.com/espressif/esp-idf.git
cd esp-idf
install.bat esp32h2
export.bat
```

> ⚠️ Le chemin d'installation ne doit contenir **ni espaces ni caractères spéciaux**. Utilisez `C:\esp\`, pas `C:\Program Files\`.

---

### macOS

```bash
# Prérequis via Homebrew
brew install cmake ninja dfu-util ccache python3

mkdir -p ~/esp && cd ~/esp
git clone -b v5.5 --recursive https://github.com/espressif/esp-idf.git
cd esp-idf
./install.sh esp32h2
. ./export.sh
```

---

## 2. Compiler le firmware sniffer

On utilise l'exemple officiel `ieee802154_cli` fourni avec ESP-IDF.

### 2.1 Aller dans le dossier du projet

```bash
cd ~/esp/esp-idf/examples/ieee802154/ieee802154_cli
```

Dépôt source : https://github.com/espressif/esp-idf/tree/v5.5/examples/ieee802154

### 2.2 Configurer pour l'ESP32-H2

```bash
rm -rf build
idf.py set-target esp32h2
```

### 2.3 Patcher la console pour USB Serial/JTAG

Les cartes Waveshare ESP32-H2 utilisent le port **USB Serial/JTAG natif** (pas un convertisseur UART). L'exemple Espressif est configuré par défaut pour UART, il faut modifier le fichier source :

```bash
sed -i 's/esp_console_dev_uart_config_t hw_config = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();/esp_console_dev_usb_serial_jtag_config_t hw_config = ESP_CONSOLE_DEV_USB_SERIAL_JTAG_CONFIG_DEFAULT();/' main/esp_ieee802154_cli.c

sed -i 's/esp_console_new_repl_uart/esp_console_new_repl_usb_serial_jtag/' main/esp_ieee802154_cli.c
```

> ⚠️ **Ce patch est obligatoire** pour les cartes sans convertisseur UART externe (Waveshare ESP32-H2-Zero, ESP32-H2-DEV-KIT-N4). Sans lui, la console série ne répondra pas (message `Writing to serial is timing out`).
>
> Si votre carte utilise un vrai UART (certains devkits avec CP2102 ou CH340), vous pouvez ignorer cette étape.

### 2.4 Compiler

```bash
idf.py build
```

La compilation prend 2 à 5 minutes. À la fin vous devez voir :

```
Project build complete. To flash, run:
 idf.py flash
```

---

## 3. Flasher l'ESP32-H2

### 3.1 Identifier le port série

Branchez la carte en USB-C et identifiez le port :

| OS | Commande |
|----|----------|
| Linux | `ls /dev/ttyACM* /dev/ttyUSB*` |
| macOS | `ls /dev/cu.usb*` |
| Windows | Gestionnaire de périphériques → Ports (COM & LPT) |

Pour les cartes Waveshare avec USB Serial/JTAG natif, le port sera typiquement `/dev/ttyACM0` sous Linux.

Vous pouvez vérifier avec :

```bash
lsusb | grep Espressif
# Doit afficher : Espressif USB JTAG/serial debug unit
```

### 3.2 Flasher

```bash
idf.py -p /dev/ttyACM0 flash
```

### Verifier la présence de JTAG controller pour la sortie console. 

cd ~/esp/esp-idf/examples/ieee802154/ieee802154_cli
idf.py menuconfig
```

Naviguez vers :
```bash
Component config
  → ESP System Settings
    → Channel for console output
```

Vous verrez une liste de choix :
```bash
( ) Default: UART0
(X) USB Serial/JTAG Controller     ← sélectionnez celui-ci
( ) Custom UART
( ) None


### 3.3 Lancer le moniteur série

```bash
idf.py -p /dev/ttyACM0 monitor
```

Ou en une seule commande (flash + monitor) :

```bash
idf.py -p /dev/ttyACM0 flash monitor
```

Pour quitter le moniteur : **Ctrl+]**

### 3.4 En cas d'échec du flash

Si le flash échoue (timeout, permission denied, port introuvable) :

1. **Maintenez le bouton BOOT enfoncé**
2. **Appuyez brièvement sur RESET** (en gardant BOOT enfoncé)
3. **Relâchez BOOT** — la carte est en mode download
4. Relancez `idf.py -p /dev/ttyACM0 flash`

> 💡 Cette manipulation est indispensable quand un `erase-flash` a supprimé le bootloader. Le mode download ROM natif fonctionne toujours, même avec une flash vide.

---

## 4. Utiliser le sniffer

Une fois le moniteur ouvert, le prompt `ieee802154>` apparaît.

### 4.1 Démarrer la capture

```
ieee802154> esp154 -e
ieee802154> channel -s 11
ieee802154> promisc -e
ieee802154> rx -r 1
```

| Commande | Rôle |
|----------|------|
| `esp154 -e` | Initialiser le sous-système IEEE 802.15.4 |
| `channel -s N` | Sélectionner le canal (N = 11 à 26) |
| `promisc -e` | Activer le mode promiscuous (capte tout) |
| `rx -r 1` | Démarrer la réception |

Les trames apparaissent immédiatement :

```
I (106368) i154cmd: Rx Done 51 bytes
I (106368) i154cmd: 41 88 ee a6 91 ff ff 02
I (106368) i154cmd: 00 09 12 fc ff 02 00 1e
...
```

### 4.2 Arrêter la capture

```
ieee802154> rx -r 0
```

### 4.3 Changer de canal

```
ieee802154> rx -r 0
ieee802154> channel -s 15
ieee802154> rx -r 1
```

### 4.4 Commandes utiles

```
ieee802154> channel -g          # Afficher le canal actuel
ieee802154> promisc -g          # Vérifier le mode promiscuous
ieee802154> txpower -g          # Voir la puissance TX
ieee802154> help                # Liste complète des commandes
```

### 4.5 Canaux Zigbee courants

| Canal | Fréquence | Utilisé par |
|-------|-----------|-------------|
| 11 | 2405 MHz | Philips Hue, certains coordinateurs |
| 15 | 2425 MHz | SmartThings |
| 20 | 2450 MHz | Courant par défaut |
| 25 | 2475 MHz | Certains coordinateurs ZHA |

> 💡 Si vous ne savez pas quel canal écouter, utilisez le mode scan du script Python (section suivante) pour détecter les canaux actifs.

### 4.6 Note sur l'erreur d'interruption

```
E (76718) intr_alloc: No free interrupt inputs for ZB_MAC interrupt (flags 0xE)
```

Cette erreur apparaît à l'initialisation mais **n'est pas bloquante**. La capture fonctionne normalement malgré ce message.

---

## 5. Capturer en PCAP pour Wireshark

Le script Python `zigbee_capture.py` lit les trames depuis le port série et les écrit en format PCAP avec le header **IEEE 802.15.4 TAP** (DLT 283), qui inclut le numéro de canal et la fréquence dans chaque paquet.

### 5.1 Installer la dépendance

```bash
pip install pyserial
```

### 5.2 Capturer sur un canal

```bash
# Quitter le monitor (Ctrl+]) avant de lancer le script

python3 zigbee_capture.py -p /dev/ttyACM0 -c 11
# Ctrl+C pour arrêter
# Ouvre ensuite : wireshark zigbee_capture.pcap
```

Le script initialise automatiquement la radio (esp154, channel, promisc, rx). Pas besoin de le faire manuellement.

### 5.3 Scanner tous les canaux

```bash
python3 zigbee_capture.py -p /dev/ttyACM0 --scan
```

Le scan écoute chaque canal pendant 5 secondes (configurable avec `--dwell`) et affiche un résumé des canaux actifs à la fin.

### 5.4 Capture live dans Wireshark

```bash
python3 zigbee_capture.py -p /dev/ttyACM0 -c 11 --wireshark
```

Wireshark se lance automatiquement avec les trames en temps réel.

### 5.5 Options complètes

```
python3 zigbee_capture.py --help

  -p, --port       Port série (obligatoire)
  -c, --channel    Canal Zigbee 11-26 (défaut: 11)
  -o, --output     Fichier PCAP (défaut: zigbee_capture.pcap)
  -d, --duration   Durée en secondes
  --wireshark      Pipe live vers Wireshark
  --scan           Scanner tous les canaux (11-26)
  --dwell          Secondes par canal en mode scan (défaut: 5)
  --debug          Afficher les données brutes
```

---

## 6. Configurer Wireshark pour Zigbee

### 6.1 Vérifier le décodage IEEE 802.15.4

Ouvrez le fichier PCAP. Les paquets doivent apparaître comme **IEEE 802.15.4** dans la colonne Protocol. Le canal est visible dans :

```
IEEE 802.15.4 TAP
  └── Channel Assignment
        ├── Channel: 11
        └── Frequency: 2405 MHz
```

### 6.2 Activer le déchiffrement Zigbee

Par défaut, les trames Zigbee sont chiffrées (AES-128). Pour les déchiffrer :

1. Allez dans **Edit → Preferences → Protocols → ZigBee**
2. Cliquez **Edit** à côté de « Pre-configured Keys »
3. Ajoutez la clé par défaut Zigbee Alliance :

```
5A:69:67:42:65:65:41:6C:6C:69:61:6E:63:65:30:39
```

*(correspond au texte ASCII « ZigBeeAlliance09 »)*

4. Ajoutez aussi la clé réseau de votre coordinateur si vous la connaissez

### 6.3 Filtres Wireshark utiles

```
# Filtrer par canal
wpan-tap.ch_num == 11

# Trames Zigbee uniquement (pas les beacons/ACK)
zbee_nwk

# Trames d'un PAN ID spécifique
wpan.dst_pan == 0x1234

# Commandes ZCL
zbee_zcl

# Trames beacon
wpan.frame_type == 0
```

---

## Dépannage

| Problème | Cause | Solution |
|----------|-------|----------|
| `idf.py: command not found` | Environnement non activé | `. ~/esp/esp-idf/export.sh` |
| `Permission denied` sur le port | Droits insuffisants | `sudo usermod -a -G dialout $USER` puis redémarrer |
| Port COM non détecté (Windows) | Driver CH343 manquant | Installer le driver depuis le site WCH |
| `Writing to serial is timing out` | Console configurée en UART | Appliquer le patch USB Serial/JTAG (section 2.3) |
| Timeout lors du flash | Carte pas en mode download | BOOT + RESET (section 3.4) |
| `bootloader requires chip rev v0.0 - v0.99` | ESP-IDF trop ancien | Utiliser ESP-IDF **v5.5 minimum** |
| Stack overflow / Guru Meditation | Firmware incompatible | Utiliser `ieee802154_cli` (pas le sniffer dj1ch) |
| Aucune trame captée | Mauvais canal ou pas d'appareils | Essayer `--scan` pour trouver les canaux actifs |
| `No free interrupt inputs for ZB_MAC` | Interruption non disponible | Ignorer, la capture fonctionne quand même |
| Le port disparaît après `erase-flash` | Bootloader effacé | Forcer le mode download (BOOT + branchement USB) |
| Ancien compilateur dans le PATH | Changement de version IDF | Supprimer `/root/.espressif/tools/riscv32-esp-elf/esp-13*` et relancer `./install.sh` |

---

## Notes importantes

### Pourquoi ESP-IDF v5.5 et pas v5.3/v5.4 ?

Les ESP32-H2 récents (revision silicium v1.2, cas des cartes Waveshare) ne sont pas supportés par ESP-IDF v5.3 ni v5.4. Le bootloader compilé avec ces versions refuse de démarrer car il impose une plage de révision `v0.0 - v0.99`. Modifier le `sdkconfig` ne suffit pas — le bootloader ignore ces changements. ESP-IDF v5.5 supporte nativement `v0.0 - v1.99`.

### Pourquoi ieee802154_cli et pas le sniffer dj1ch ?

Le projet [dj1ch/ieee802154-sniffer](https://github.com/dj1ch/ieee802154-sniffer) a été testé mais provoque un **stack overflow** (Stack Protection Fault dans la tâche IDLE) avec ESP-IDF v5.5. Les callbacks IEEE 802.15.4 du firmware dj1ch ne sont pas compatibles avec les changements internes de FreeRTOS dans v5.5. L'outil `ieee802154_cli` d'Espressif est maintenu et fonctionne sans problème.

### Pourquoi le patch console USB ?

Les cartes Waveshare ESP32-H2 (Zero et DEV-KIT-N4) communiquent via le **USB Serial/JTAG natif** du chip (identifié comme `303a:1001 Espressif USB JTAG/serial debug unit` dans `lsusb`). Ce n'est pas un convertisseur UART classique (comme un CH340 ou CP2102). L'API console doit utiliser `esp_console_dev_usb_serial_jtag_config_t` au lieu de `esp_console_dev_uart_config_t`.

---

## Commandes récapitulatives (copier-coller)

```bash
# ══════════════════════════════════════
#  INSTALLATION COMPLÈTE (à faire 1 fois)
# ══════════════════════════════════════

# Prérequis (Linux)
sudo apt update
sudo apt install -y git wget flex bison gperf python3 \
  python3-pip python3-venv cmake ninja-build ccache \
  libffi-dev libssl-dev dfu-util libusb-1.0-0
sudo usermod -a -G dialout $USER

# ESP-IDF v5.5
mkdir -p ~/esp && cd ~/esp
git clone -b v5.5 --recursive https://github.com/espressif/esp-idf.git
cd esp-idf
./install.sh esp32h2
. ./export.sh

# ══════════════════════════════════════
#  COMPILER & FLASHER (à faire 1 fois par carte)
# ══════════════════════════════════════

cd ~/esp/esp-idf/examples/ieee802154/ieee802154_cli
rm -rf build
idf.py set-target esp32h2

# Patch console USB
sed -i 's/esp_console_dev_uart_config_t hw_config = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();/esp_console_dev_usb_serial_jtag_config_t hw_config = ESP_CONSOLE_DEV_USB_SERIAL_JTAG_CONFIG_DEFAULT();/' main/esp_ieee802154_cli.c
sed -i 's/esp_console_new_repl_uart/esp_console_new_repl_usb_serial_jtag/' main/esp_ieee802154_cli.c

idf.py build
idf.py -p /dev/ttyACM0 flash

# ══════════════════════════════════════
#  UTILISATION
# ══════════════════════════════════════

# Option A : Console interactive
idf.py -p /dev/ttyACM0 monitor
# Puis taper : esp154 -e / channel -s 11 / promisc -e / rx -r 1

# Option B : Capture PCAP automatique
pip install pyserial
python3 zigbee_capture.py -p /dev/ttyACM0 -c 11
wireshark zigbee_capture.pcap

# Option C : Scanner tous les canaux
python3 zigbee_capture.py -p /dev/ttyACM0 --scan



```
 python3 zigbee_capture.py --fifo /tmp/zigbee.fifo -p /dev/ttyACM0:11 -p /dev/ttyACM1:12 -p /dev/ttyACM2:13 -p /dev/ttyACM3:14 -p /dev/ttyACM4:15 -p /dev/ttyACM5:16 -p /dev/ttyACM6:17 -p /dev/ttyACM7:18 -p /dev/ttyACM8:19 -p /dev/ttyACM9:20 -p /dev/ttyACM10:21 -p /dev/ttyACM11:22 -p /dev/ttyACM12:23 -p /dev/ttyACM13:24 -p /dev/ttyACM14:25 -p /dev/ttyACM15:26 
---

## Licence

Le firmware `ieee802154_cli` est sous licence Apache 2.0 (Espressif Systems).



