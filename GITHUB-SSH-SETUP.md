# 🔐 Configuración SSH para GitHub

Instrucciones para configurar SSH y hacer push al repositorio.

---

## 📋 Pasos

### 1. Generar SSH Key

```bash
# Generar key Ed25519 (recomendado)
ssh-keygen -t ed25519 -C "darknetmdb.444@gmail.com"

# Si hay problemas con Ed25519, usar RSA
ssh-keygen -t rsa -b 4096 -C "darknetmdb.444@gmail.com"

# Presionar Enter para usar la ubicación por defecto
# Ingresar una contraseña (opcional pero recomendado)
```

### 2. Iniciar SSH Agent

```bash
# Linux/macOS
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519

# Windows (Git Bash)
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519
```

### 3. Copiar PublicKey

```bash
# Linux (copia al portapapeles)
cat ~/.ssh/id_ed25519.pub | xclip -selection clipboard

# macOS
pbcopy < ~/.ssh/id_ed25519.pub

# Windows (Git Bash)
cat ~/.ssh/id_ed25519.pub | clip

# O simplemente mostrar y copiar manualmente
cat ~/.ssh/id_ed25519.pub
```

### 4. Agregar a GitHub

1. Ir a: https://github.com/settings/keys
2. Click en **"New SSH key"**
3. **Title**: `GovLLM-Sentinel-Dev` (o cualquier nombre)
4. **Key type**: Authentication Key
5. **Key**: Pegar la publicKey copiada
6. Click en **"Add SSH key"**

### 5. Probar Conexión

```bash
ssh -T git@github.com

# Si funciona, verás:
# "Hi 0xvanguard! You've successfully authenticated..."
```

### 6. Cambiar Remote a SSH

```bash
cd GovLLM-Sentinel

# Cambiar remote de HTTPS a SSH
git remote set-url origin git@github.com:0xvanguard/GovLLM-Sentinel.git

# Verificar
git remote -v
# Debe mostrar:
# origin  git@github.com:0xvanguard/GovLLM-Sentinel.git (fetch)
# origin  git@github.com:0xvanguard/GovLLM-Sentinel.git (push)
```

### 7. Push

```bash
git push origin main
```

---

## 🔧 Troubleshooting

### Error: Permission denied (publickey)

```bash
# Verificar que ssh-agent tiene la key
ssh-add -l

# Si no aparece, agregarla
ssh-add ~/.ssh/id_ed25519

# Verificar permisos (Linux/macOS)
chmod 700 ~/.ssh
chmod 600 ~/.ssh/id_ed25519
chmod 644 ~/.ssh/id_ed25519.pub
```

### Error: Host key verification failed

```bash
# Agregar GitHub a known_hosts
ssh-keyscan github.com >> ~/.ssh/known_hosts
```

### Usar SSH con passphrase

```bash
# Iniciar ssh-agent con passphrase
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519

# O configurar para recordar passphrase (macOS)
ssh-add --apple-use-keychain ~/.ssh/id_ed25519
```

---

## 📁 Archivos Importantes

| Archivo | Descripción |
|---------|-------------|
| `~/.ssh/id_ed25519` | Private key (NUNCA compartir) |
| `~/.ssh/id_ed25519.pub` | Public key (compartir con GitHub) |
| `~/.ssh/config` | Configuración SSH (opcional) |
| `~/.ssh/known_hosts` | Hosts conocidos |

---

## 🔒 Seguridad

- **NUNCA** comprometer la private key
- **USAR** passphrase en la key
- **ROTA** las keys periódicamente
- **USAR** una key diferente por máquina/proyecto

---

## ✅ Verificación Final

```bash
# 1. Verificar conexión
ssh -T git@github.com

# 2. Verificar remote
cd GovLLM-Sentinel && git remote -v

# 3. Push
git push origin main
```

---

**Después de configurar SSH, ejecuta:**
```bash
cd GovLLM-Sentinel
git push origin main
```
