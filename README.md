# # 🐉 Instalación del bug-bounty-toolkit en Kali Linux

Kali ya viene con Python 3, pip y git, así que la instalación es muy directa. Aquí los pasos completos:

---

## 1. Requisitos previos

# Actualizar el sistema
sudo apt update && sudo apt upgrade -y

# Instalar dependencias del sistema
sudo apt install -y python3 python3-pip python3-venv git curl

# Para el UI web (opcional)
sudo apt install -y nodejs npm
# Si quieres yarn:
sudo npm install -g yarn

# MongoDB (solo necesario si vas a usar backend + UI web)
sudo apt install -y mongodb
# o instala MongoDB Community Edition siguiendo: https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-debian/
```

---

## 2. Obtener el código

**Opción A — Si lo guardaste en GitHub:**
```
cd ~
git clone https://github.com/TU-USUARIO/TU-REPO.git bugbounty
cd bugbounty
```

**Opción B — Crear estructura manual** (copiando archivos desde Emergent VS Code view):
```bash
mkdir -p ~/bugbounty && cd ~/bugbounty
# luego copia las carpetas: bugbounty_tool/, backend/, frontend/
```

---

## 3. Solo CLI (lo más simple y útil en Kali) ✅

cd ~/bugbounty/bugbounty_tool

# Entorno virtual (recomendado para no ensuciar el Python del sistema)
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt

# Probar
python bugbounty_tool.py --help

# Lanzar un scan completo (ejemplo contra tu propio lab)
python bugbounty_tool.py all \
    -t 192.168.1.50 \
    --i-have-authorization \
    -v \
    --output-format md \
    -o reporte.md
```



### Hacerlo ejecutable desde cualquier sitio

chmod +x bugbounty_tool.py
sudo ln -s ~/bugbounty/bugbounty_tool/bugbounty_tool.py /usr/local/bin/bbtool
# Ahora puedes ejecutarlo desde donde quieras:
bbtool recon -t example.com --i-have-authorization
```

---

## 4. Backend FastAPI (si quieres la API REST)


cd ~/bugbounty/backend

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Crear .env
cat > .env << 'EOF'
MONGO_URL=mongodb://localhost:27017
DB_NAME=bugbounty
CORS_ORIGINS=*
EOF

# Arrancar MongoDB si no está corriendo
sudo systemctl start mongodb     # o mongod, según versión
sudo systemctl enable mongodb

# Arrancar el backend
uvicorn server:app --host 0.0.0.0 --port 8001 --reload
```

Verifica que funciona:
curl http://localhost:8001/api/bb/health
# {"status":"ok","service":"bugbounty-toolkit"}
```

---

## 5. Frontend React (UI web)

En otra terminal:
```bash
cd ~/bugbounty/frontend

# Crear .env apuntando al backend local
echo "REACT_APP_BACKEND_URL=http://localhost:8001" > .env

# Instalar dependencias
yarn install     # o: npm install

# Arrancar el dev server
yarn start       # o: npm start
```

Abre `http://localhost:3000` en tu navegador.

---

## 6. Targets seguros para practicar en Kali

Kali ya trae varias formas de levantar un lab vulnerable local para que pruebes sin meter ruido fuera:

# Metasploitable2 (VM separada, IP típicamente 192.168.x.x)
# DVWA en Docker:
sudo apt install -y docker.io
sudo docker run --rm -it -p 80:80 vulnerables/web-dvwa
# Ahora apunta el toolkit a:
bbtool all -t 127.0.0.1 --i-have-authorization

# Juice Shop:
sudo docker run --rm -p 3000:3000 bkimminich/juice-shop
bbtool all -t 127.0.0.1 --ports 3000 --i-have-authorization
```

---

## 7. Problemas comunes

| Error | Solución |
|-------|----------|
| `ModuleNotFoundError: No module named 'bs4'` | Activa el venv y repite `pip install -r requirements.txt` |
| `whois failed` / WHOIS lento | Usa `--no-whois` para saltarlo |
| `socket.gaierror` resolviendo dominios | Comprueba DNS: `nslookup example.com` |
| Cloudflare/WAF te bloquea | Sube `--delay 2` y reduce `--ports` |
| `permission denied` al escanear puertos <1024 | No es necesario, el tool usa sólo HTTP. Si lo necesitaras, `sudo` |
| MongoDB no arranca | `sudo systemctl status mongodb` → revisa logs en `/var/log/mongodb/` |

---

⚠️ **Recordatorio**: la herramienta exige `--i-have-authorization` por diseño. **Úsala solo en sistemas propios, labs (DVWA, Juice Shop, Metasploitable), CTFs o targets con permiso escrito**. Escanear sin permiso es ilegal en la mayoría de jurisdicciones.

¿Quieres que te prepare un `install.sh` que automatice todos estos pasos (venv + deps + symlink + lanzar DVWA en Docker) con un solo comando?
Here are your Instructions
