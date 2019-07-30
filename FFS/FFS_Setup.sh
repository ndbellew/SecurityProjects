#!/bin/bash
if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root"
  exit 1
else
  chmod 751 run_firewall.sh
  ln run_firewall.sh FirewallFF
  sudo mv FirewallFF /bin/FirewallFF
fi
echo "You should now be able to run FirewallFF as a command."
