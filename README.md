# Gerenciador de Senhas

## 📋 Sobre o Projeto
Este é um gerenciador de senhas completo desenvolvido com tecnologias web front-end. O sistema permite armazenar, gerenciar e proteger suas senhas de forma segura diretamente no navegador, utilizando criptografia avançada para garantir a segurança dos dados.

## 🔐 Funcionalidades Principais

### Sistema de Autenticação
- **Cadastro de usuários**: Crie sua conta com nome, e-mail e senha
- **Validação de força de senha**: Feedback visual sobre a segurança da senha escolhida
- **Login seguro**: Acesse suas senhas com autenticação protegida
- **Autenticação de dois fatores (2FA)**: Camada extra de segurança opcional

### Gerenciamento de Credenciais
- **Interface organizada**: Visualize suas senhas em formato de tabela com colunas para Nome, Usuário e Senha
- **CRUD completo**: Adicione, visualize, edite e exclua suas credenciais
- **Visualização segura**: Para ver ou copiar senhas, é necessário confirmar a senha mestra
- **Exportação de dados**: Exporte suas senhas em formato JSON para backup

### Personalização
- **Modo escuro/claro**: Alterne entre temas para melhor conforto visual
- **Interface responsiva**: Funciona em dispositivos móveis e desktops

## 🔒 Segurança Implementada
- **Criptografia AES-GCM**: Todas as senhas são criptografadas antes do armazenamento
- **Derivação de chave PBKDF2**: A chave de criptografia é derivada da senha mestra do usuário
- **Armazenamento local seguro**: Os dados nunca saem do seu dispositivo
- **Análise de força de senha**: Utilizamos a biblioteca zxcvbn para avaliar a segurança das senhas

## 🛠️ Tecnologias Utilizadas
- **HTML5**: Estruturação semântica da interface
- **CSS3**: Estilização moderna e responsiva
- **JavaScript**: Lógica de funcionamento e interatividade
- **Web Crypto API**: API nativa para operações criptográficas seguras
- **LocalStorage**: Armazenamento persistente no navegador
- **zxcvbn**: Biblioteca para análise de força de senhas

## 📱 Como Usar
1. Acesse a aplicação pelo navegador
2. Crie uma conta com suas informações
3. Faça login para acessar o gerenciador
4. Use os botões na parte superior para:
   - Adicionar novas senhas
   - Exportar suas senhas
   - Configurar autenticação de dois fatores
   - Voltar para a tela inicial
5. Gerencie suas senhas na tabela principal

## ⚙️ Instalação Local
```bash
# Clone o repositório
git clone https://github.com/seu-usuario/gerenciador-senhas.git

# Navegue até a pasta do projeto
cd gerenciador-senhas

# Abra o arquivo index.html no seu navegador
# No Windows
start index.html

# No macOS
open index.html

# No Linux
xdg-open index.html
```

## 🔍 Considerações de Segurança
- Este gerenciador utiliza o armazenamento local do navegador (localStorage)
- As senhas são criptografadas antes de serem armazenadas
- Recomendamos usar uma senha mestra forte e única
- A aplicação funciona offline e não envia dados para servidores externos

## 👥 Desenvolvedores
- [Seu Nome]
- [Nome do Colaborador]

## 📄 Licença
Este projeto está licenciado sob a [Licença MIT](LICENSE)

---

⭐ Desenvolvido como projeto educacional para demonstrar conceitos de segurança web e gerenciamento de credenciais.