#!/bin/bash
# ==========================================
# Raspberry Pi + Pi-hole Smart Update Script
# ==========================================

echo "Starting full system update..."

reboot_required=false

# 1. APT updates
echo "Checking for APT updates..."
sudo apt update
sudo apt full-upgrade -y

# 1.5 Check if a reboot is required after APT updates
if [ -f /var/run/reboot-required ]; then
  echo "Reboot required after APT updates."
  reboot_required=true
else
  echo "No reboot required after APT updates."
fi

# 2. Firmware (kernel, bootloader)
echo "Checking firmware updates..."
if sudo rpi-update --dry-run | grep "would be updated"; then
  echo "🔧 Updating firmware..."
  sudo rpi-update -y
  reboot_required=true
else
  echo "✅ Firmware already up to date."
fi

# 3. Pi-hole updates
echo "Updating Pi-hole core..."
if ! pihole -up | grep "Everything is up to date"; then
  reboot_required=true
fi

# 4. Gravity lists
echo "Updating Pi-hole blocklists..."
pihole -g
echo "Gravity/Blocklists refreshed."

# 5. Flush DNS cache
echo "Restarting DNS resolver..."
pihole restartdns reload-lists

# 6. Cleanup
echo "🧹 Cleaning unused packages..."
sudo apt autoremove -y
sudo apt autoclean -y

# 7. Finally, check if a reboot is needed
if [ "$reboot_required" = true ]; then
  echo "🔁 Updates applied — rebooting in 10 seconds..."
  sleep 10
  sudo reboot now
else
  echo "✅ No updates detected — no reboot required."
  pihole status
fi
