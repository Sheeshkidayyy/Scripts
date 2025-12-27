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

# 3. Pi-hole updates
echo "Updating Pi-hole core..."
sudo pihole -up

# 4. Gravity lists
echo "Updating Pi-hole blocklists..."
pihole -g
echo "Gravity/Blocklists refreshed."

# 5. Flush DNS cache
echo "Restarting DNS resolver..."
pihole reloaddns

# 6. Cleanup
echo "Cleaning and reconfiguring unused packages..."
sudo apt autoremove -y
sudo apt autoclean -y
sudo dpkg --configure -a

# 7 Show Pi-hole status no matter what
pihole status

# 8. Ask if reboot is needed
read -p "Would you like to reboot now? (y/N): " confirm
if [[ "$confirm" =~ ^[Yy]$ ]]; then
  echo "Rebooting now..."
  sudo reboot now
else
  echo "No reboot will be performed."
fi
