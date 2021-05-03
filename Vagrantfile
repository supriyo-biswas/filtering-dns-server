Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/focal64"

  config.vm.provider "virtualbox" do |vb|
    vb.gui = false
    vb.memory = "640"
  end

  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y dnsutils htop python3 python3-dev virtualenv redis-server redis-tools
    apt-get upgrade -y
    sed -ri 's/^bind /#&/;s/^(port ).*$/\\10/;s/^# (unixsocket)/\\1/;s/^(unixsocketperm )[0-9]+/\\1777/' /etc/redis/redis.conf
    systemctl restart redis-server.service
    adduser vagrant redis
  SHELL
end
