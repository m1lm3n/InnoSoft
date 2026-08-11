LATEST_URL=$(curl -s https://api.github.com/repos/Corsinvest/cv4pve-diag/releases/latest \
  | grep browser_download_url | grep linux-x64 | cut -d '"' -f 4)
wget "$LATEST_URL"
unzip cv4pve-diag-linux-x64.zip
chmod +x cv4pve-diag
sudo mv cv4pve-diag /usr/local/bin/