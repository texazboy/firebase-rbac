# 🔐 Firebase RBAC — Controle de Acesso por Cargo

Sistema web completo que demonstra **Role-Based Access Control (RBAC)** utilizando Firebase Authentication e Firebase Realtime Database com Security Rules separando permissões entre **Admin** e **User**.

---

## 📐 Estrutura do Banco de Dados

O banco utiliza 4 nós raiz, cada um com regras de acesso distintas:

```
firebase-rbac-db/
│
├── users/                          ← Perfis de todos os usuários
│   └── {uid}/
│       ├── name: string
│       ├── email: string
│       ├── role: "admin" | "user"  ← Define o cargo
│       ├── createdAt: ISO string
│       └── lastLogin: ISO string
│
├── admin-data/                     ← Dados exclusivos de administradores
│   ├── reports/
│   │   └── {reportId}/
│   │       ├── title: string
│   │       ├── content: string
│   │       ├── createdBy: uid
│   │       ├── createdAt: ISO string
│   │       └── priority: "alta" | "média" | "baixa"
│   ├── system-logs/
│   │   └── {logId}/
│   │       ├── action: string
│   │       ├── performedBy: uid
│   │       ├── timestamp: ISO string
│   │       └── details: string
│   └── settings/
│       ├── maintenanceMode: boolean
│       ├── maxUsersAllowed: number
│       └── appVersion: string
│
├── public-data/                    ← Dados públicos (leitura para todos)
│   └── announcements/
│       └── {announcementId}/
│           ├── title: string
│           ├── content: string
│           ├── createdBy: uid
│           ├── createdAt: ISO string
│           └── active: boolean
│
└── user-data/                      ← Dados pessoais de cada usuário
    └── {uid}/
        ├── notes/
        │   └── {noteId}/
        │       ├── title: string
        │       ├── content: string
        │       └── createdAt: ISO string
        └── preferences/
            ├── theme: string
            └── notifications: boolean
```

### Justificativa da Modelagem

| Nó | Propósito | Por que separar? |
|---|---|---|
| `/users` | Perfis e metadados | Centraliza dados de identidade; campo `role` é consultado pelas Security Rules para autorizar acessos |
| `/admin-data` | Relatórios, logs, configs | Contém informações sensíveis que só administradores devem ver (financeiro, logs de sistema) |
| `/public-data` | Avisos e comunicados | Informação que todos podem ler, mas só admins podem criar/editar |
| `/user-data` | Dados pessoais | Isolamento por UID garante privacidade — cada usuário só acessa seus próprios dados |

---

## 🔒 Firebase Security Rules

As rules incluem controle de acesso por cargo, validação de tipo/formato em cada campo, indexação para queries, e proteção contra escalação de privilégios.

```json
{
  "rules": {
    "users": {
      ".indexOn": ["role", "email"],
      "$uid": {
        ".read":  "$uid === auth.uid || ...role === 'admin'",
        ".write": "$uid === auth.uid || ...role === 'admin'",
        ".validate": "newData.hasChildren(['name', 'email', 'role', 'createdAt'])",
        "name":  { ".validate": "isString() && length >= 2 && length <= 100" },
        "email": { ".validate": "isString() && contains('@') && contains('.')" },
        "role":  { ".validate": "(val === 'admin' || val === 'user') && (requester_is_admin || val === 'user')" },
        "$other": { ".validate": false }
      }
    },
    "admin-data": {
      ".read/.write": "auth != null && ...role === 'admin'",
      "reports/$id":     { ".validate": "hasChildren(['title','content','createdBy','createdAt'])" },
      "system-logs/$id": { ".validate": "hasChildren(['action','performedBy','timestamp'])" },
      "settings":        { "maintenanceMode": "isBoolean()", "maxUsersAllowed": "isNumber() > 0" }
    },
    "public-data": {
      ".read":  "auth != null",
      ".write": "auth != null && ...role === 'admin'",
      "announcements/$id": { ".validate": "hasChildren(['title','content','createdBy','createdAt'])" }
    },
    "user-data/$uid": {
      ".read":  "$uid === auth.uid || ...role === 'admin'",
      ".write": "$uid === auth.uid",
      "notes/$id": { ".validate": "hasChildren(['title','content','createdAt'])", "title": "length <= 200" },
      "preferences": { "theme": "val === 'light' || val === 'dark'", "notifications": "isBoolean()" }
    }
  }
}
```

> **Nota**: O JSON acima é uma versão simplificada para leitura. O arquivo `database.rules.clean.json` contém as regras completas prontas para colar no Firebase Console.

### Camadas de Proteção

1. **Autenticação obrigatória** — Todas as regras exigem `auth != null`
2. **Controle por cargo** — Cada nó verifica `root.child('users/'+auth.uid+'/role')`
3. **Anti-escalação** — O campo `role` só aceita `"admin"` se o **requisitante** já for admin
4. **Validação de tipo** — Cada campo valida tipo (`isString`, `isBoolean`, `isNumber`), formato (email com `@`), e tamanho (name 2-100 chars)
5. **Rejeição de campos extras** — `"$other": { ".validate": false }` em `/users` impede injeção de campos não previstos
6. **Indexação** — `.indexOn` em `role`, `email`, `createdAt`, `priority`, `action` para queries eficientes

### Matriz de Permissões

| Nó | Admin Lê | Admin Escreve | User Lê | User Escreve |
|---|:---:|:---:|:---:|:---:|
| `/users/{uid}` | ✅ Todos | ✅ Todos | ⚠️ Só próprio | ⚠️ Só próprio |
| `/admin-data` | ✅ Total | ✅ Total | ❌ Bloqueado | ❌ Bloqueado |
| `/public-data` | ✅ Total | ✅ Total | ✅ Total | ❌ Bloqueado |
| `/user-data/{uid}` | ✅ Todos | ⚠️ Só próprio | ⚠️ Só próprio | ⚠️ Só próprio |

---

## 🔑 Autenticação + Cargo no Banco

### Fluxo de Registro

1. Usuário preenche nome, e-mail, senha e **seleciona o cargo** (admin ou user)
2. `firebase.auth().createUserWithEmailAndPassword()` cria a conta
3. Imediatamente após, os dados são salvos no Realtime Database:

```javascript
db.ref('users/' + uid).set({
  name:      "Nome do Usuário",
  email:     "email@test.com",
  role:      "admin",        // ou "user"
  createdAt: "2026-04-16T...",
  lastLogin: "2026-04-16T..."
});
```

4. O nó `/user-data/{uid}/preferences` é inicializado com valores padrão
5. Se o cargo for admin, dados de exemplo são criados em `/admin-data`

### Fluxo de Login

1. `firebase.auth().signInWithEmailAndPassword()` autentica
2. O callback `onAuthStateChanged` é acionado
3. A aplicação lê `/users/{uid}/role` para determinar o cargo
4. O dashboard é configurado dinamicamente de acordo com o cargo

---

## 🎨 Interface Visual

A interface adapta-se completamente ao cargo do usuário logado:

### Visão do Admin
- Sidebar com badge **🛡️ ADMIN** (cor âmbar/dourada)
- Acesso a **todos os 4 nós** do banco
- Pode ver **todos os usuários** em `/users`
- Acesso a **relatórios, logs e configurações** em `/admin-data`
- Pode **criar avisos** em `/public-data`
- Pode **ler dados pessoais** de outros usuários em `/user-data`

### Visão do User
- Sidebar com badge **👤 USUÁRIO** (cor cyan/azul)
- Ícone de **cadeado 🚫** aparece ao lado de `/admin-data`
- Vê **apenas seu próprio perfil** em `/users`
- Tela de **"Acesso Negado"** em `/admin-data` com explicação da rule
- Pode **ler avisos** mas **não pode criar** em `/public-data`
- Acessa **apenas seus próprios dados** em `/user-data`

### Painel de Testes
- Botões para testar leitura e escrita em cada nó
- Botão **"Executar Todos os Testes"** — roda todas as operações de uma vez (ideal para apresentação ao vivo)
- Log em tempo real mostrando **✓ SUCESSO** ou **✗ PERMISSION_DENIED**
- Sistema de **toasts** com feedback visual instantâneo
- Demonstra as Security Rules funcionando em tempo real

### Funcionalidades Extras
- **Tela de loading** durante verificação de autenticação
- **Log de login** — cada login de admin é registrado em `/admin-data/system-logs`
- **Animações de entrada staggered** — elementos surgem sequencialmente ao navegar
- **Design editorial claro** — tema quente com tipografia Sora + Fraunces (sem gradientes genéricos)

---

## 🚀 Como Configurar e Executar

### Pré-requisitos
- Conta no [Firebase Console](https://console.firebase.google.com)

### Passo 1 — Configurar o Firebase Console
1. Acesse o Firebase Console e crie um novo projeto (ou use um existente)
2. Ative **Authentication** → método **Email/Senha**
3. Ative **Realtime Database** → inicie em **modo de teste**

### Passo 2 — Aplicar Security Rules
1. No Firebase Console → **Realtime Database** → aba **Regras**
2. Cole o conteúdo de `database.rules.clean.json`
3. Clique **Publicar**

### Passo 3 — Executar
- Abra `index.html` diretamente no navegador
- As credenciais do Firebase já estão configuradas no código

### Passo 4 — Testar
1. **Crie uma conta Admin** (selecione cargo Admin)
2. Navegue pelo dashboard, veja todos os dados
3. Faça logout
4. **Crie uma conta User** (selecione cargo Usuário)
5. Observe as diferenças: cadeados, acessos negados, testes falhando

---

## 📁 Estrutura de Arquivos

```
firebase-rbac-project/
├── index.html                  ← Aplicação completa (HTML + CSS + JS)
├── database.rules.json         ← Security Rules do Firebase
├── database-structure.json     ← Modelo da árvore JSON do banco
└── README.md                   ← Esta documentação
```

---

## 🛠️ Tecnologias Utilizadas

- **Firebase Authentication** — Login com e-mail e senha
- **Firebase Realtime Database** — Banco de dados NoSQL em tempo real
- **Firebase Security Rules** — Controle de acesso server-side
- **HTML5 / CSS3 / JavaScript** — Interface sem dependências externas
- **Google Fonts (Sora + Fraunces + Fira Code)** — Tipografia editorial distintiva

---

## 📝 Observações

- Em produção, o campo `role` deveria ser definido apenas por Cloud Functions ou pelo Firebase Admin SDK, nunca pelo cliente. Neste projeto didático, o cargo é definido no registro para fins de demonstração.
- As Security Rules são a camada **real** de segurança. A interface apenas reflete visualmente o que as rules permitem — se alguém manipular o JS, as rules continuam bloqueando acessos indevidos.
- O arquivo `database.rules.json` contém comentários para facilitar o entendimento, mas os comentários devem ser removidos ao colar no console do Firebase (JSON padrão não aceita comentários).

---

## 👨‍💻 Autor

Projeto desenvolvido por José Gabriel Dâmaso e Pedro Augusto como trabalho acadêmico demonstrando controle de acesso baseado em cargos (RBAC) com Firebase.
