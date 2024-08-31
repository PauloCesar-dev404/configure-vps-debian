# servidor LAMP (Linux, Apache, Mariadb, PHP)

### Passo a Passo para Configurar o Servidor LAMP

1. **Clone o repositório**:
   ```bash
   git clone https://github.com/PauloCesar-dev404/configure-vps-debian
   ```

2. **Navegue até o diretório do repositório clonado**:
   ```bash
   cd configure-vps-debian
   ```

3. **Crie e ative um ambiente virtual**:
   Primeiro, instale o módulo `venv` e depois crie o ambiente virtual e o ative:
   ```bash
   sudo apt install python3-venv -y
   sudo python3 -m venv .venv
   source .venv/bin/activate
   ```

4. **Instale as dependências necessárias**:
   Use o `pip` para instalar as bibliotecas Python requeridas pelo script:

   ```bash
   pip install requests
   ```
5. **Inicie o script Python para configurar o servidor LAMP**:
   Execute o script principal que automatizará a configuração do servidor LAMP:
   ```bash
   sudo python3 main.py
   ```


