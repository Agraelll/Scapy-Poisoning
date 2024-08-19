# ARP Spoofing Attack Script

Este é um script em Python para realizar um ataque de ARP spoofing. O ataque de ARP spoofing é uma técnica usada para envenenar o cache ARP de um alvo, redirecionando o tráfego de rede para um atacante. Este script foi desenvolvido como um exercício acadêmico para demonstrar a técnica de ARP spoofing.

## Funcionalidades
- **ARP Poisoning**: Envia pacotes ARP spoofing para envenenar o cache ARP da vítima.
- **Restaurar Cache ARP**: Restaura o cache ARP da vítima e do gateway após o término do ataque.

## Dependências
Este script utiliza a biblioteca scapy, que deve ser instalada para que o script funcione corretamente. Para instalar a biblioteca, você pode usar o seguinte comando:

```bash
pip install scapy

## Uso
- **Configure as variáveis de rede**: Abra o script e ajuste os valores das variáveis target_ip, gateway_ip, e interface com os endereços IP e o nome da interface de rede adequados para seu ambiente.

- **Interrompa o ataque**: Para parar o ataque, use Ctrl + C no terminal. O script irá automaticamente restaurar os caches ARP da vítima e do gateway.

## Código
**O código inclui as seguintes funções**:

- arp_poison(target_ip, gateway_ip, interface): Envia um pacote ARP spoofing para envenenar o cache ARP da vítima.

- get_mac(ip_address): Obtém o endereço MAC correspondente a um endereço IP usando um pacote ARP request.

- restore_target(target_ip, target_mac, gateway_ip, gateway_mac, interface): Restaura o cache ARP da vítima e do gateway após o término do ataque.
