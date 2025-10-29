#!/bin/bash
# ==========================================
# Raspberry Pi + Pi-hole Smart Update Script
# ==========================================

echo "Starting full system update..."

reboot_required=false

# 1. Repairs broken packages
echo "Fixing broken dependencies if any..."
sudo apt install -f -y
sudo dpkg --configure -a
echo "Broken dependencies fixed."

# 2. APT updates
echo "Checking for APT updates..."
sudo apt update
sudo apt full-upgrade -y

# 2.5 Check if a reboot is required after APT updates
if [ -f /var/run/reboot-required ]; then
  echo "Reboot required after APT updates."
  reboot_required=true
else
  echo "No reboot required after APT updates."
fi

# 3. Firmware (kernel, bootloader)
echo "Checking firmware updates..."
sudo apt upgrade raspberrypi-bootloader raspberrypi-kernel -y
# If new firmware was installed, a reboot is usually required
if [ -f /var/run/reboot-required ]; then
  reboot_required=true
fi
echo "Firmware check/update complete."

# 4. Pi-hole updates
echo "Updating Pi-hole core..."
if ! sudo pihole -up | grep "Everything is up to date"; then
  reboot_required=true
fi

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

# 9. Then finally checks if a reboot is needed
if [ "$reboot_required" = true ]; then
  echo "Updates applied — rebooting in 10 seconds..."
  sleep 15
  sudo reboot now
else
  echo "No updates detected — no reboot required."
fi

