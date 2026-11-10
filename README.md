# Scanner de Protocolos e Dispositivos de Mídia

Ferramenta em Python desenvolvida para rastreamento de redes locais em ambientes corporativos e de eventos. O objetivo é identificar dispositivos expostos e protocolos de transmissão de mídia, áudio, iluminação e automação que operam sem criptografia ou autenticação.

O projeto inclui o código-fonte do scanner e a proposta de arquitetura de rede para mitigação dos riscos identificados por meio de segmentação via VLANs.

---

## Pré-requisitos e Dependências

Para rodar a ferramenta no Windows, certifique-se de instalar as dependências do sistema e do Python antes de executar o script.

### 1. Requisitos do Sistema
* **Python 3.8 ou superior**: Marque a opção "Add Python to PATH" durante o processo de instalação.
* **Driver Npcap**: Necessário para que a biblioteca Scapy consiga manipular raw sockets e pacotes ARP no Windows.
  * Baixe o instalador no site oficial: https://npcap.com/#download
  * **Importante:** Durante a instalação, selecione a opção **"Install Npcap in WinPcap API-compatible Mode"**.

### 2. Dependências do Python (`requirements.txt`)
O projeto utiliza as seguintes bibliotecas:

* `scapy>=2.5.0`: Responsável pela criação, envio e captura de pacotes de rede (ARP, TCP e UDP).
* `pywin32>=306`: Necessária para a validação e gerenciamento de privilégios de administrador no Windows.

---

## Passo a Passo de Instalação

1. Clone o repositório para o seu computador:
   ```cmd
   git clone [https://github.com/seu-usuario/media-network-scanner.git](https://github.com/seu-usuario/media-network-scanner.git)
   cd media-network-scanner