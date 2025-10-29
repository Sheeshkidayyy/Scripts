#!/bin/bash
# ==========================================
# Raspberry Pi + Pi-hole Smart Update Script
# ==========================================

echo "Starting full system update..."

# 1. Repairs broken packages
echo "Fixing broken dependencies if any..."
sudo apt install -f -y
sudo dpkg --configure -a
echo "Broken dependencies fixed."

# 2. APT updates
echo "Checking for APT updates..."
sudo apt update
sudo apt full-upgrade -y

# 3. Firmware (kernel, bootloader)
echo "Checking firmware updates..."
sudo apt upgrade raspberrypi-bootloader raspberrypi-kernel -y
echo "Firmware check/update complete."

# 4. Pi-hole updates
echo "Updating Pi-hole core..."
sudo pihole -up

# 5. Gravity lists
echo "Updating Pi-hole blocklists..."
pihole -g
echo "Gravity/Blocklists refreshed."

# 6. Flush DNS cache
echo "Restarting DNS resolver..."
pihole restartdns reload-lists

# 7. Cleanup
echo "Cleaning unused packages..."
sudo apt autoremove -y
sudo apt autoclean -y

# 8 Show Pi-hole status no matter what
pihole status

# 9. Ask if reboot is needed
read -p "Would you like to reboot now? (y/N): " confirm
if [[ "$confirm" =~ ^[Yy]$ ]]; then
  echo "Rebooting now..."
  sudo reboot now
else
  echo "No reboot will be performed. Please remember to reboot manually if necessary."
fi
