#!/bin/bash

apt update
apt upgrade

curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null
apt update
apt install gh

adduser max

sudo -i -u max

export GH_TOKEN=...

sudo -u max gh run download -p "tlspuffin-*" -R trailofbits/tlspuffin $(gh run list -R trailofbits/tlspuffin -b trailofbits -L 1 --json databaseId --jq ".[0].databaseId")


