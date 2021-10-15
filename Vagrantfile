$install = <<-SCRIPT
apt-get update
apt-get upgrade -y
apt-get install -y build-essential gcc clang nftables wireguard-tools wireguard libssl-dev pkg-config libpq-dev libmariadbd-dev
SCRIPT

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/hirsute64"
  config.vm.provision "shell", inline: $install
  config.vm.provision "shell" do |s|
    s.path = "https://sh.rustup.rs"
    s.args   = "-y"
    s.privileged = false
  end
  config.vm.provider "virtualbox" do |v|
    v.memory = 2048
    v.cpus = 4
  end
end
