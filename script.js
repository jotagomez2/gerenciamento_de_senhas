// script.js

// ======================================================
// 1. Acesso aos Elementos HTML
// ======================================================

// Autenticação (Acesso ao Gerenciador)
const accessForm = document.getElementById('accessForm');
const userNameInput = document.getElementById('userName');
const userEmailInput = document.getElementById('userEmail');
const userPasswordInput = document.getElementById('userPassword');
const toggleUserPassword = document.getElementById('toggleUserPassword');
const userStrengthMeter = document.getElementById('userStrengthMeter');
const userStrengthText = document.getElementById('userStrengthText');
const loginBtn = document.getElementById('loginBtn');
const registerBtn = document.getElementById('registerBtn');
const darkModeToggle = document.getElementById('darkModeToggle');

// Seção do Gerenciador de Senhas (pós-login)
const passwordManagerSection = document.getElementById('passwordManagerSection');
const addPasswordBtn = document.getElementById('addPasswordBtn');
const exportPasswordsBtn = document.getElementById('exportPasswordsBtn');
const setup2FABtn = document.getElementById('setup2FABtn');
const inicioBtn = document.getElementById('inicio');
const passwordListContainer = document.getElementById('passwordList');
const noPasswordsMessage = document.getElementById('noPasswordsMessage');

// Modal de Adição/Edição de Senha
const passwordEntryModal = document.getElementById('passwordEntryModal');
const passwordEntryModalTitle = document.getElementById('passwordEntryModalTitle');
const passwordEntryForm = document.getElementById('passwordEntryForm');
const passwordIdInput = document.getElementById('passwordId'); // Campo hidden para ID
const entryTitleInput = document.getElementById('entryTitle');
const entryURLInput = document.getElementById('entryURL');
const entryUsernameInput = document.getElementById('entryUsername');
const entryPasswordInput = document.getElementById('entryPassword');
const toggleEntryPassword = document.getElementById('toggleEntryPassword');
const entryStrengthMeter = document.getElementById('entryStrengthMeter');
const entryStrengthText = document.getElementById('entryStrengthText');
const savePasswordBtn = document.getElementById('savePasswordBtn');
const closePasswordEntryModalBtn = document.querySelector('.password-entry-close-button');

// Modal de Confirmação de Exclusão
const confirmDeleteModal = document.getElementById('confirmDeleteModal');
const cancelDeleteBtn = document.getElementById('cancelDeleteBtn');
const confirmDeleteBtn = document.getElementById('confirmDeleteBtn');
const closeConfirmDeleteModalBtn = document.querySelector('.delete-close-button');

// ======================================================
// 2. Variáveis Globais e Funções de Utilitário
// ======================================================

// Mensagens de força da senha para cada score do zxcvbn (0 a 4)
const passwordStrengthMessages = [
    "Muito Fraca", // score 0
    "Fraca",      // score 1
    "Razoável",   // score 2
    "Boa",        // score 3
    "Excelente"   // score 4
];

// Array para armazenar as senhas do usuário logado (simulação local)
let currentLoggedInUser = null; // Guarda o nome do usuário logado
let userPasswords = []; // Guarda as senhas do usuário logado

// Chave para a criptografia (será derivado da senha mestra do usuário logado)
// IMPORTANTE: Em um sistema real, isso seria MUITO mais complexo e seguro.
// Para este exemplo, vamos simplificar.
let masterKey = null;

/**
 * Função para configurar a visibilidade de um campo de senha.
 * @param {HTMLInputElement} passwordInput O elemento input da senha.
 * @param {HTMLInputElement} toggleCheckbox O checkbox que controla a visibilidade.
 */
function setupPasswordToggle(passwordInput, toggleCheckbox) {
    if (!passwordInput || !toggleCheckbox) {
        console.error('Elementos de senha ou toggle não encontrados para setup.');
        return;
    }
    toggleCheckbox.addEventListener('change', () => {
        if (toggleCheckbox.checked) {
            passwordInput.type = 'text';
        } else {
            passwordInput.type = 'password';
        }
    });
}

/**
 * Abre um modal específico.
 * @param {HTMLElement} modalElement O elemento do modal a ser aberto.
 */
function openModal(modalElement) {
    if (modalElement) {
        modalElement.style.display = 'flex'; // Usamos flex para centralizar
    }
}

/**
 * Fecha um modal específico.
 * @param {HTMLElement} modalElement O elemento do modal a ser fechado.
 */
function closeModal(modalElement) {
    if (modalElement) {
        modalElement.style.display = 'none';
    }
}

/**
 * Atualiza o medidor e o texto de força da senha.
 * @param {HTMLInputElement} passwordInput O input da senha.
 * @param {HTMLMeterElement} strengthMeter O elemento <meter> para a força.
 * @param {HTMLParagraphElement} strengthText O elemento <p> para o texto da força.
 */
function updatePasswordStrength(passwordInput, strengthMeter, strengthText) {
    if (!passwordInput || !strengthMeter || !strengthText) {
        return;
    }

    const password = passwordInput.value;
    const result = zxcvbn(password); // zxcvbn está disponível globalmente

    strengthMeter.value = result.score;
    strengthText.textContent = passwordStrengthMessages[result.score];
}

/**
 * Gera uma chave AES a partir de uma senha mestra.
 * @param {string} password A senha mestra do usuário.
 * @returns {Promise<CryptoKey>} Uma Promise que resolve para a chave CryptoKey.
 */
async function deriveKeyFromPassword(password) {
    const enc = new TextEncoder();
    // Salt fixo para simplicidade. EM PRODUÇÃO, O SALT DEVE SER ÚNICO E ALEATÓRIO POR USUÁRIO.
    // E.g., const salt = crypto.getRandomValues(new Uint8Array(16));
    const salt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );
    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000, // Número de iterações, quanto maior, mais seguro (e lento)
            hash: "SHA-256",
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 }, // Usamos AES-GCM 256 bits
        true,
        ["encrypt", "decrypt"]
    );
}

/**
 * Criptografa um texto usando AES-GCM.
 * @param {string} text O texto a ser criptografado.
 * @param {CryptoKey} key A chave de criptografia.
 * @returns {Promise<string>} Uma Promise que resolve para o texto criptografado em base64 com IV.
 */
async function encryptText(text, key) {
    const iv = crypto.getRandomValues(new Uint8Array(16)); // IV aleatório para cada criptografia
    const enc = new TextEncoder();
    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv }, // Passa o IV gerado
        key,
        enc.encode(text)
    );
    // Concatena IV e cipherText e converte para Base64 para armazenamento
    const combined = new Uint8Array(iv.byteLength + encrypted.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(encrypted), iv.byteLength);
    return btoa(String.fromCharCode.apply(null, combined));
}

/**
 * Descriptografa um texto usando AES-GCM.
 * @param {string} encryptedText Base64 do texto criptografado com IV.
 * @param {CryptoKey} key A chave de criptografia.
 * @returns {Promise<string>} Uma Promise que resolve para o texto descriptografado.
 */
async function decryptText(encryptedText, key) {
    const decoded = Uint8Array.from(atob(encryptedText), c => c.charCodeAt(0));
    const iv = decoded.slice(0, 16); // IV tem 16 bytes para AES-GCM
    const cipherText = decoded.slice(16);

    const dec = new TextDecoder();
    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv }, // Passa o IV extraído
        key,
        cipherText
    );
    return dec.decode(decrypted);
}


// ======================================================
// 3. Funções de Autenticação (Cadastro e Login)
// ======================================================

/**
 * Salva os dados do usuário (nome, senha hash, e-mail) no localStorage.
 * @param {string} username O nome de usuário.
 * @param {string} hashedPassword A senha hasheada do usuário.
 * @param {string} email O e-mail do usuário.
 */
function saveUser(username, hashedPassword, email) {
    // IMPORTANTE: Em um sistema REAL, o hash seria armazenado em um BANCO DE DADOS SEGURO no servidor.
    // Salvando no localStorage é apenas para fins de DEMONSTRAÇÃO LOCAL e NÃO é seguro.
    
    // Normaliza o nome de usuário para minúsculas para garantir consistência
    const normalizedUsername = username.toLowerCase();
    
    // Verifica novamente se o usuário já existe (verificação redundante de segurança)
    const users = JSON.parse(localStorage.getItem('users') || '{}');
    const userKeys = Object.keys(users).map(key => key.toLowerCase());
    
    if (userKeys.includes(normalizedUsername)) {
        alert('Nome de usuário já existe. Por favor, escolha outro.');
        return false;
    }
    
    // Salva o usuário com o nome original, mas após verificação case-insensitive
    users[username] = hashedPassword;
    localStorage.setItem('users', JSON.stringify(users));
    
    // Salva o e-mail associado ao usuário
    const emails = JSON.parse(localStorage.getItem('userEmails') || '{}');
    emails[username] = email;
    localStorage.setItem('userEmails', JSON.stringify(emails));
    
    return true;
}

/**
 * Hash de uma string usando SHA-256.
 * @param {string} message A string a ser hasheada.
 * @returns {Promise<string>} O hash em formato hexadecimal.
 */
async function sha256(message) {
    const textEncoder = new TextEncoder();
    const data = textEncoder.encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hexHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hexHash;
}

/**
 * Valida um endereço de e-mail.
 * @param {string} email O endereço de e-mail a ser validado.
 * @returns {boolean} Verdadeiro se o e-mail for válido, falso caso contrário.
 */
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

// Event Listener para o botão de Cadastro
if (registerBtn) {
    registerBtn.addEventListener('click', async (e) => {
        e.preventDefault(); // Previne o envio padrão do formulário

        const username = userNameInput.value.trim();
        const email = userEmailInput.value.trim();
        const password = userPasswordInput.value;

        if (!username || !email || !password) {
            alert('Por favor, preencha o nome, e-mail e a senha para cadastro.');
            return;
        }

        // Valida o formato do e-mail
        if (!validateEmail(email)) {
            alert('Por favor, insira um endereço de e-mail válido.');
            return;
        }

        // Verifica se o usuário já existe (case insensitive)
        const users = JSON.parse(localStorage.getItem('users') || '{}');
        const userExists = Object.keys(users).some(existingUser => 
            existingUser.toLowerCase() === username.toLowerCase()
        );
        
        if (userExists) {
            alert('Nome de usuário já existe. Por favor, escolha outro.');
            return;
        }

        // Verifica se o e-mail já está em uso
        const emails = JSON.parse(localStorage.getItem('userEmails') || '{}');
        if (Object.values(emails).some(existingEmail => 
            existingEmail.toLowerCase() === email.toLowerCase()
        )) {
            alert('Este e-mail já está cadastrado. Por favor, use outro e-mail.');
            return;
        }

        if (zxcvbn(password).score < 2) { // Exige pelo menos 'Razoável'
            alert('A senha é muito fraca. Por favor, escolha uma senha mais forte.');
            return;
        }

        const hashedPassword = await sha256(password); // Hasheia a senha de acesso
        const saveSuccess = saveUser(username, hashedPassword, email);
        
        if (!saveSuccess) {
            return; // Se não conseguiu salvar, interrompe o processo
        }

        alert('Usuário cadastrado com sucesso! Agora você pode fazer login.');
        // Limpa formulário após cadastro
        userNameInput.value = '';
        userEmailInput.value = '';
        userPasswordInput.value = '';
        userStrengthMeter.value = 0;
        userStrengthText.textContent = '';
    });
}

// Event Listener para o botão de Login
if (loginBtn) {
    loginBtn.addEventListener('click', async (e) => {
        e.preventDefault(); // Previne o envio padrão do formulário

        const username = userNameInput.value.trim();
        const email = userEmailInput.value.trim();
        const password = userPasswordInput.value;

        if (!username || !password) {
            alert('Por favor, preencha o nome e a senha para login.');
            return;
        }

        // Tentar login via API primeiro (se estiver disponível)
        try {
            const apiSuccess = await apiLogin(email || username, password);
            if (apiSuccess) {
                // Deriva a chave mestra para criptografia local
                masterKey = await deriveKeyFromPassword(password);
                
                // Esconde a seção de login e mostra a do gerenciador de senhas
                accessForm.style.display = 'none';
                passwordManagerSection.style.display = 'block';
                
                // Carrega as senhas do usuário via API
                await apiLoadUserPasswords();
                return;
            }
        } 
        catch (e) {
  console.error("Erro ao executar função:", e);
}

        // Fallback para login local se a API falhar
        const hashedPasswordInput = await sha256(password);
        const users = JSON.parse(localStorage.getItem('users') || '{}');
        const storedHash = users[username];

        if (storedHash === hashedPasswordInput) { // Compara os hashes
            // Verificação de 2FA se estiver habilitado para o usuário
            const userSettings = JSON.parse(localStorage.getItem('userSettings') || '{}');
            if (userSettings[username]?.twoFactorEnabled) {
                const twoFactorCode = prompt('Digite o código de verificação de dois fatores:');
                if (!twoFactorCode) {
                    alert('Autenticação de dois fatores necessária.');
                    return;
                }
                
                // Verificar o código 2FA (simulação simples)
                // Em um sistema real, isso seria validado com TOTP ou similar
                const storedCode = userSettings[username].twoFactorCode;
                if (twoFactorCode !== storedCode) {
                    alert('Código de verificação inválido.');
                    return;
                }
            }
            
            currentLoggedInUser = username;
            masterKey = await deriveKeyFromPassword(password); // Deriva a chave mestra para criptografia
            alert(`Bem-vindo, ${username}! Login realizado com sucesso.`);

            // Esconde a seção de login e mostra a do gerenciador de senhas
            accessForm.style.display = 'none';
            passwordManagerSection.style.display = 'block';

            // Carrega as senhas do usuário (se houver)
            loadUserPasswords();

        } else {
            alert('Nome de usuário ou senha incorretos.');
        }
    });
}

// ======================================================
// 4. Funções de CRUD de Senhas
// ======================================================

/**
 * Carrega as senhas do usuário logado do localStorage.
 * As senhas são armazenadas no formato { username: [senha1, senha2...] }
 */
function loadUserPasswords() {
    // Tentar carregar via API primeiro
    try {
        const token = localStorage.getItem('token');
        if (token) {
            apiLoadUserPasswords();
            return;
        }
    } catch (error) {
        alert('Erro ao carregar senhas do servidor. Usando armazenamento local.');
        console.log('API não disponível, usando armazenamento local:', error);
    }
    
    // Fallback para carregamento local
    const allUsersPasswords = JSON.parse(localStorage.getItem('userPasswords') || '{}');
    userPasswords = allUsersPasswords[currentLoggedInUser] || [];
    displayPasswords();
}

/**
 * Salva as senhas do usuário logado no localStorage.
 */
function saveUserPasswords() {
    const allUsersPasswords = JSON.parse(localStorage.getItem('userPasswords') || '{}');
    allUsersPasswords[currentLoggedInUser] = userPasswords;
    localStorage.setItem('userPasswords', JSON.stringify(allUsersPasswords));
}

/**
 * Renderiza a lista de senhas na interface.
 */
async function displayPasswords() {
    passwordListContainer.innerHTML = ''; // Limpa a lista atual

    if (userPasswords.length === 0) {
        noPasswordsMessage.style.display = 'block';
        return;
    } else {
        noPasswordsMessage.style.display = 'none';
    }

    // Adiciona o cabeçalho da tabela
    const headerDiv = document.createElement('div');
    headerDiv.className = 'password-header';
    headerDiv.innerHTML = `
        <div>Nome</div>
        <div>Usuário</div>
        <div>Senha</div>
        <div>Ações</div>
    `;
    passwordListContainer.appendChild(headerDiv);

    for (const passwordItem of userPasswords) {
        const passwordDiv = document.createElement('div');
        passwordDiv.className = 'password-item';
        passwordDiv.dataset.id = passwordItem.id; // Usar id para identificação única

        const decryptedPasswordDisplay = '********'; // Default mascarado
        
        // Determinar qual campo contém a senha criptografada (compatibilidade com API)
        const encryptedPassword = passwordItem.encryptedPassword || passwordItem.encrypted_password;
        
        // Crie o HTML para cada item de senha em formato de colunas
        passwordDiv.innerHTML = `
            <div class="column-title">${passwordItem.title}</div>
            <div class="column-username">${passwordItem.username}</div>
            <div class="column-password">
                <span class="hidden-password" data-encrypted="${encryptedPassword}">${decryptedPasswordDisplay}</span>
                <button class="copy-password-btn" data-tooltip="Copiar">Copiar</button>
                <button class="show-password-btn" data-tooltip="Mostrar">Mostrar</button>
            </div>
            <div class="column-actions">
                <button class="edit-btn">Editar</button>
                <button class="delete-btn">Excluir</button>
            </div>
        `;
        passwordListContainer.appendChild(passwordDiv);
    }

    // Adiciona event listeners para os botões de ação APÓS renderizar todos os itens
    setupPasswordItemEventListeners();
}

/**
 * Configura os event listeners para os botões de cada item de senha (Mostrar, Copiar, Editar, Excluir).
 */
function setupPasswordItemEventListeners() {
    // Seleciona todos os botões de "Mostrar Senha" e adiciona event listener
    document.querySelectorAll('.show-password-btn').forEach(button => {
        button.addEventListener('click', async (e) => {
            const passwordSpan = e.target.previousElementSibling.previousElementSibling; // O <span> com a senha mascarada
            
            // Verificar se a senha está armazenada em encryptedPassword ou encrypted_password
            let encryptedPassword = passwordSpan.dataset.encrypted;
            if (!encryptedPassword) {
                console.error('Senha criptografada não encontrada no elemento');
                alert('Erro ao encontrar a senha. Por favor, atualize a página e tente novamente.');
                return;
            }

            // Solicitar a senha mestra para mostrar
            const masterPassConfirmation = prompt("Para visualizar a senha, digite sua senha mestra:");
            if (masterPassConfirmation === null || masterPassConfirmation.trim() === "") {
                return; // Usuário cancelou ou não digitou
            }
            
            // Re-hashear a senha mestra fornecida e comparar com a armazenada
            const hashedPasswordInput = await sha256(masterPassConfirmation);
            const users = JSON.parse(localStorage.getItem('users') || '{}');
            const storedHash = users[currentLoggedInUser]; // Hash do usuário logado

            if (storedHash === hashedPasswordInput) {
                try {
                    // Rederiva a chave mestra para descriptografia
                    const tempMasterKey = await deriveKeyFromPassword(masterPassConfirmation);
                    const decrypted = await decryptText(encryptedPassword, tempMasterKey);
                    passwordSpan.textContent = decrypted;
                    // Esconder após alguns segundos
                    setTimeout(() => {
                        passwordSpan.textContent = '********';
                    }, 5000); // Esconde após 5 segundos
                } catch (error) {
                    alert('Erro ao descriptografar a senha. Senha mestra incorreta ou dados corrompidos.');
                    console.error('Decryption error:', error);
                }
            } else {
                alert('Senha mestra incorreta.');
            }
        });
    });

    // Seleciona todos os botões de "Copiar Senha" e adiciona event listener
    document.querySelectorAll('.copy-password-btn').forEach(button => {
        button.addEventListener('click', async (e) => {
            // O <span> da senha é o irmão anterior do botão "Mostrar", que é o irmão anterior do "Copiar"
            const passwordSpan = e.target.previousElementSibling.previousElementSibling;
            const encryptedPassword = passwordSpan.dataset.encrypted;

            // Solicitar a senha mestra para copiar
            const masterPassConfirmation = prompt("Para copiar a senha, digite sua senha mestra:");
            if (masterPassConfirmation === null || masterPassConfirmation.trim() === "") {
                return; // Usuário cancelou ou não digitou
            }
            
            // Re-hashear a senha mestra fornecida e comparar com a armazenada
            const hashedPasswordInput = await sha256(masterPassConfirmation);
            const users = JSON.parse(localStorage.getItem('users') || '{}');
            const storedHash = users[currentLoggedInUser]; // Hash do usuário logado
            
            if (storedHash === hashedPasswordInput) {
                try {
                    // Rederiva a chave mestra para descriptografia
                    const tempMasterKey = await deriveKeyFromPassword(masterPassConfirmation);
                    const decrypted = await decryptText(encryptedPassword, tempMasterKey);
                    navigator.clipboard.writeText(decrypted)
                        .then(() => {
                            alert('Senha copiada para a área de transferência!');
                            // Opcional: Limpar a área de transferência após um tempo
                            // setTimeout(() => navigator.clipboard.writeText(''), 30000); // Limpa após 30s
                        })
                        .catch(err => {
                            console.error('Erro ao copiar senha: ', err);
                            alert('Erro ao copiar a senha. Verifique as permissões do navegador.');
                        });
                } catch (error) {
                    alert('Erro ao descriptografar para copiar. Senha mestra pode estar incorreta ou dados corrompidos.');
                    console.error('Decryption error for copy:', error);
                }
            } else {
                alert('Senha mestra incorreta.');
            }
        });
    });

    // Seleciona todos os botões de "Editar" e adiciona event listener
    document.querySelectorAll('.edit-btn').forEach(button => {
        button.addEventListener('click', async (e) => {
            const passwordItemDiv = e.target.closest('.password-item'); // Encontra o item de senha pai
            const id = passwordItemDiv.dataset.id;
            
            // Procurar a senha no array de senhas
            let passwordToEdit;
            
            // Verificar se a senha tem a propriedade encryptedPassword ou encrypted_password (API)
            for (const password of userPasswords) {
                if (password.id === id) {
                    passwordToEdit = {
                        id: password.id,
                        title: password.title,
                        url: password.url || '',
                        username: password.username,
                        encryptedPassword: password.encryptedPassword || password.encrypted_password
                    };
                    break;
                }
            }

            if (passwordToEdit) {
                // Preenche o modal com os dados da senha
                passwordIdInput.value = passwordToEdit.id; // Define o ID para indicar que é edição
                passwordEntryModalTitle.textContent = 'Editar Senha'; // Atualiza o título do modal
                entryTitleInput.value = passwordToEdit.title;
                entryURLInput.value = passwordToEdit.url || ''; // Garante string vazia se null/undefined
                entryUsernameInput.value = passwordToEdit.username;
                
                // Solicitar a senha mestra para editar
                const masterPassConfirmation = prompt("Para editar a senha, digite sua senha mestra:");
                if (masterPassConfirmation === null || masterPassConfirmation.trim() === "") {
                    return; // Usuário cancelou ou não digitou
                }
                
                // Re-hashear a senha mestra fornecida e comparar com a armazenada
                const hashedPasswordInput = await sha256(masterPassConfirmation);
                const users = JSON.parse(localStorage.getItem('users') || '{}');
                const storedHash = users[currentLoggedInUser]; // Hash do usuário logado
                
                if (storedHash === hashedPasswordInput) {
                    try {
                        // Rederiva a chave mestra para descriptografia
                        const tempMasterKey = await deriveKeyFromPassword(masterPassConfirmation);
                        const decrypted = await decryptText(passwordToEdit.encryptedPassword, tempMasterKey);
                        entryPasswordInput.value = decrypted;
                        // Atualiza a força da senha para a senha descriptografada
                        updatePasswordStrength(entryPasswordInput, entryStrengthMeter, entryStrengthText);
                        
                        // Abre o modal após descriptografar com sucesso
                        openModal(passwordEntryModal);
                    } catch (error) {
                        console.error('Erro ao descriptografar senha para edição:', error);
                        alert('Erro ao carregar senha para edição. Senha mestra incorreta ou dados corrompidos.');
                    }
                } else {
                    alert('Senha mestra incorreta.');
                }
            } else {
                alert('Senha não encontrada. Por favor, atualize a página e tente novamente.');
            }
        });
    });

    // Seleciona todos os botões de "Excluir" e adiciona event listener
    document.querySelectorAll('.delete-btn').forEach(button => {
        button.addEventListener('click', (e) => {
            const passwordItemDiv = e.target.closest('.password-item');
            const idToDelete = passwordItemDiv.dataset.id;

            // Define o ID no botão de confirmação do modal para uso posterior
            confirmDeleteBtn.dataset.idToDelete = idToDelete;
            openModal(confirmDeleteModal);
        });
    });
}

// Event Listener para o botão de "Adicionar Nova Senha"
if (addPasswordBtn) {
    addPasswordBtn.addEventListener('click', () => {
        passwordEntryForm.reset(); // Limpa o formulário do modal
        passwordIdInput.value = ''; // Garante que o ID esteja vazio para nova senha
        passwordEntryModalTitle.textContent = 'Adicionar Senha'; // Define o título do modal para "Adicionar"
        // Reinicia o feedback de força da senha no modal
        entryStrengthMeter.value = 0;
        entryStrengthText.textContent = passwordStrengthMessages[0];
        openModal(passwordEntryModal);
    });
}

// Event Listener para o botão de "Início"
if (inicioBtn) {
    inicioBtn.addEventListener('click', () => {
        // Limpa os dados do usuário atual
        currentLoggedInUser = null;
        masterKey = null;
        userPasswords = [];
        
        // Volta para a tela de login
        accessForm.style.display = 'block';
        passwordManagerSection.style.display = 'none';
        
        // Limpa os campos do formulário de login
        userNameInput.value = '';
        userEmailInput.value = '';
        userPasswordInput.value = '';
        userStrengthMeter.value = 0;
        userStrengthText.textContent = '';
        
        alert('Sessão encerrada com sucesso!');
    });
}
// Event Listener para confirmar exclusão no modal de confirmação
if (confirmDeleteBtn) {
    confirmDeleteBtn.addEventListener('click', async () => {
        const idToDelete = confirmDeleteBtn.dataset.idToDelete; // Pega o ID do item a ser excluído
        if (idToDelete) {
            // Tentar excluir via API primeiro
            try {
                const apiSuccess = await apiDeletePassword(idToDelete);
                if (apiSuccess) {
                    closeModal(confirmDeleteModal);
                    return;
                }
            } catch (error) {
                console.error('API não disponível, usando armazenamento local:', error);
                alert('Erro ao tentar excluir a senha via servidor. Usando armazenamento local.');
            }
            
            // Fallback para exclusão local
            userPasswords = userPasswords.filter(p => p.id !== idToDelete); // Remove a senha do array
            saveUserPasswords(); // Salva o array atualizado no localStorage
            displayPasswords(); // Re-renderiza a lista
            closeModal(confirmDeleteModal); // Fecha o modal de confirmação
        }
    });
}

// Event Listener para cancelar exclusão no modal de confirmação
if (cancelDeleteBtn) {
    cancelDeleteBtn.addEventListener('click', () => {
        closeModal(confirmDeleteModal);
    });
}

// Event Listener para salvar/atualizar senha no modal de entrada
if (passwordEntryForm) {
    passwordEntryForm.addEventListener('submit', async (e) => {
        e.preventDefault(); // Previne o envio padrão do formulário

        const id = passwordIdInput.value; // Pega o ID (se for edição)
        const title = entryTitleInput.value.trim();
        const url = entryURLInput.value.trim();
        const username = entryUsernameInput.value.trim();
        const password = entryPasswordInput.value;

        if (!title || !username || !password) {
            alert('Título, Usuário e Senha são campos obrigatórios.');
            return;
        }

        // Validação básica de URL (o input[type="url"] já faz um bom trabalho visual)

        // Verificar se já existe uma senha com o mesmo título (case insensitive)
        const titleExists = userPasswords.some(p => 
            p.id !== id && // Ignora o próprio item em caso de edição
            p.title.toLowerCase() === title.toLowerCase()
        );
        
        if (titleExists) {
            alert('Já existe uma senha com este título. Por favor, escolha outro título.');
            return;
        }
        
        // Verificar se já existe uma senha com a mesma combinação de URL e usuário
        const duplicateExists = userPasswords.some(p => 
            p.id !== id && // Ignora o próprio item em caso de edição
            p.username.toLowerCase() === username.toLowerCase() && 
            p.url.toLowerCase() === url.toLowerCase() && 
            url !== '' // Só considera duplicata se a URL não estiver vazia
        );
        
        if (duplicateExists) {
            alert('Já existe uma senha cadastrada para este usuário e URL. Por favor, edite a existente.');
            return;
        }

        // Criptografar a senha antes de salvar
        if (!masterKey) {
            alert('Chave mestra não disponível. Por favor, faça login novamente.');
            return;
        }
        
        let encryptedPassword;
        try {
            encryptedPassword = await encryptText(password, masterKey);
        } catch (error) {
            console.error('Erro ao criptografar a senha:', error);
            alert('Erro ao criptografar a senha. Tente novamente.');
            return;
        }

        // Preparar dados para salvar
        const passwordData = {
            id: id || undefined,
            title,
            url,
            username,
            encrypted_password: encryptedPassword // Nome do campo adaptado para API
        };

        // Tentar salvar via API primeiro
        try {
            const apiSuccess = await apiSavePassword(passwordData);
            if (apiSuccess) {
                closeModal(passwordEntryModal);
                return;
            }
        } catch (error) {
            alert('Erro ao salvar a senha via servidor. Usando armazenamento local.');
            console.log('API não disponível, usando armazenamento local:', error);
        }

        // Fallback para salvar localmente
        if (id) {
            // Edição de senha existente
            const index = userPasswords.findIndex(p => p.id === id);
            if (index !== -1) {
                userPasswords[index] = { id, title, url, username, encryptedPassword };
                alert('Senha atualizada com sucesso!');
            }
        } else {
            // Nova senha
            const newId = Date.now().toString(); // ID simples baseado no timestamp atual
            userPasswords.push({ id: newId, title, url, username, encryptedPassword });
            alert('Senha adicionada com sucesso!');
        }

        saveUserPasswords(); // Salva no localStorage
        displayPasswords(); // Re-renderiza a lista para refletir as mudanças
        closeModal(passwordEntryModal); // Fecha o modal
    });
}

// Opcional: Fechar modal clicando fora do conteúdo
window.addEventListener('click', (event) => {
    if (event.target === passwordEntryModal) {
        closeModal(passwordEntryModal);
    }
    if (event.target === confirmDeleteModal) {
        closeModal(confirmDeleteModal);
    }
});


// ======================================================
// 5. Funcionalidades Adicionais
// ======================================================

/**
 * Exporta as senhas do usuário em formato cifrado.
 */
function exportPasswords() {
    if (!currentLoggedInUser || !masterKey) {
        alert('Você precisa estar logado para exportar suas senhas.');
        return;
    }

    // Cria um objeto com os dados a serem exportados
    const exportData = {
        user: currentLoggedInUser,
        timestamp: new Date().toISOString(),
        passwords: userPasswords
    };

    // Converte para string JSON
    const jsonData = JSON.stringify(exportData);
    
    // Cria um blob e um link para download
    const blob = new Blob([jsonData], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `senhas_${currentLoggedInUser}_${new Date().toISOString().slice(0,10)}.json`;
    document.body.appendChild(a);
    a.click();
    
    // Limpa o objeto URL e remove o elemento
    setTimeout(() => {
        URL.revokeObjectURL(url);
        document.body.removeChild(a);
    }, 0);
}

/**
 * Configura o modo escuro com base na preferência do usuário.
 */
function setupDarkMode() {
    // Verifica se há uma preferência salva
    const darkModePreference = localStorage.getItem('darkMode') === 'true';
    
    // Aplica a preferência
    if (darkModePreference) {
        document.body.classList.add('dark-mode');
        if (darkModeToggle) darkModeToggle.checked = true;
    }
    
    // Configura o event listener para o toggle
    if (darkModeToggle) {
        darkModeToggle.addEventListener('change', () => {
            document.body.classList.toggle('dark-mode');
            localStorage.setItem('darkMode', document.body.classList.contains('dark-mode'));
        });
    }
}

/**
 * Configura a autenticação de dois fatores para o usuário atual.
 */
function setupTwoFactorAuth() {
    if (!currentLoggedInUser) {
        alert('Você precisa estar logado para configurar a autenticação de dois fatores.');
        return;
    }
    
    // Em um sistema real, isso geraria um código QR para um app como Google Authenticator
    // Para esta demonstração, usaremos um código fixo simples
    const twoFactorCode = Math.floor(100000 + Math.random() * 900000).toString(); // Código de 6 dígitos
    
    const userSettings = JSON.parse(localStorage.getItem('userSettings') || '{}');
    if (!userSettings[currentLoggedInUser]) {
        userSettings[currentLoggedInUser] = {};
    }
    
    userSettings[currentLoggedInUser].twoFactorEnabled = true;
    userSettings[currentLoggedInUser].twoFactorCode = twoFactorCode;
    
    localStorage.setItem('userSettings', JSON.stringify(userSettings));
    
    alert(`Autenticação de dois fatores ativada!\nSeu código é: ${twoFactorCode}\n\nEm um sistema real, você escanearia um código QR com um aplicativo como Google Authenticator.`);
}

// ======================================================
// 6. Integração com Backend (API)
// ======================================================

/**
 * Realiza login através da API.
 * @param {string} email O email do usuário.
 * @param {string} password A senha do usuário.
 * @returns {Promise<boolean>} Verdadeiro se o login for bem-sucedido.
 */
async function apiLogin(email, password) {
    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'Erro ao fazer login');
        }
        
        if (data.requires_2fa) {
            // Solicitar código 2FA
            const code = prompt('Digite o código de autenticação de dois fatores:');
            if (!code) return false;
            
            const verify2FA = await fetch('/api/two-factor/verify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': `Bearer ${data.temp_token}`
                },
                body: JSON.stringify({ code })
            });
            
            if (!verify2FA.ok) {
                throw new Error('Código de autenticação inválido');
            }
            
            // Continuar login após 2FA
            return apiLogin(email, password);
        }
        
        // Armazenar token e informações do usuário
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        currentLoggedInUser = data.user.name;
        
        return true;
    } catch (error) {
        console.error('Erro de login:', error);
        alert(error.message);
        return false;
    }
}

/**
 * Carrega as senhas do usuário a partir da API.
 */
async function apiLoadUserPasswords() {
    try {
        const token = localStorage.getItem('token');
        if (!token) throw new Error('Não autenticado');
        
        const response = await fetch('/api/passwords', {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Accept': 'application/json'
            }
        });
        
        if (!response.ok) throw new Error('Falha ao carregar senhas');
        
        const data = await response.json();
        userPasswords = data;
        displayPasswords();
    } catch (error) {
        console.error('Erro ao carregar senhas:', error);
        alert('Não foi possível carregar suas senhas. Por favor, tente novamente.');
    }
}

/**
 * Salva uma senha através da API.
 * @param {Object} passwordData Os dados da senha a serem salvos.
 */
async function apiSavePassword(passwordData) {
    try {
        const token = localStorage.getItem('token');
        if (!token) throw new Error('Não autenticado');
        
        const method = passwordData.id ? 'PUT' : 'POST';
        const url = passwordData.id ? `/api/passwords/${passwordData.id}` : '/api/passwords';
        
        const response = await fetch(url, {
            method,
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(passwordData)
        });
        
        if (!response.ok) throw new Error('Falha ao salvar senha');
        
        // Recarregar senhas após salvar
        apiLoadUserPasswords();
        
        return true;
    } catch (error) {
        console.error('Erro ao salvar senha:', error);
        alert('Não foi possível salvar a senha. Por favor, tente novamente.');
        return false;
    }
}

/**
 * Exclui uma senha através da API.
 * @param {string} id O ID da senha a ser excluída.
 */
async function apiDeletePassword(id) {
    try {
        const token = localStorage.getItem('token');
        if (!token) throw new Error('Não autenticado');
        
        const response = await fetch(`/api/passwords/${id}`, {
            method: 'DELETE',
            headers: {
                'Accept': 'application/json',
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (!response.ok) throw new Error('Falha ao excluir senha');
        
        // Recarregar senhas após excluir
        apiLoadUserPasswords();
        
        return true;
    } catch (error) {
        console.error('Erro ao excluir senha:', error);
        alert('Não foi possível excluir a senha. Por favor, tente novamente.');
        return false;
    }
}

// ======================================================
// 7. Inicialização (Ao Carregar a Página)
// ======================================================

// Configura os toggles de senha para os campos principais e do modal
setupPasswordToggle(userPasswordInput, toggleUserPassword);
setupPasswordToggle(entryPasswordInput, toggleEntryPassword);

// Configura os medidores de força da senha para os campos principais e do modal
if (userPasswordInput && userStrengthMeter && userStrengthText) {
    userPasswordInput.addEventListener('input', () => {
        updatePasswordStrength(userPasswordInput, userStrengthMeter, userStrengthText);
    });
    // Inicializa o medidor de força da senha de acesso ao carregar a página
    updatePasswordStrength(userPasswordInput, userStrengthMeter, userStrengthText);
}
if (entryPasswordInput && entryStrengthMeter && entryStrengthText) {
    entryPasswordInput.addEventListener('input', () => {
        updatePasswordStrength(entryPasswordInput, entryStrengthMeter, entryStrengthText);
    });
    // Inicializa o medidor de força da senha de entrada ao carregar o modal (pode ser escondido inicialmente)
    updatePasswordStrength(entryPasswordInput, entryStrengthMeter, entryStrengthText);
}

// Configura o modo escuro
setupDarkMode();

// Configura os event listeners para os novos botões
if (exportPasswordsBtn) {
    exportPasswordsBtn.addEventListener('click', exportPasswords);
}

if (setup2FABtn) {
    setup2FABtn.addEventListener('click', setupTwoFactorAuth);
}

// Inicia a aplicação na tela de login/cadastro
accessForm.style.display = 'block';
passwordManagerSection.style.display = 'none';
