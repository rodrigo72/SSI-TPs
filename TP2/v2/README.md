= Guia de utilização

- Criar a pasta `/tmp/mail_box`
- Adicionar permissões de root a essa pasta (`chmod chown root:root /tmp/mail_box`)


- Executar `sudo ./setup.sh`
- Colocar `concordia.service` no `/etc/systemd/system` (`sudo cp s /etc/systemd/system`)
- Nessa diretoria, executar `sudo systemctl enable concordia.service`
- Depois, `sudo systemctl start concordia.service`


- Executar `gcc clientc. -o c`
- Utilizar o daemon através do `c` (exemplo: `./c criar-grupo nome`)