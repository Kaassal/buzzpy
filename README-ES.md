# Buzzpy

Sistema de honeypots configurable, con un panel de datos a tiempo real para monitorizar y analizar intentods de intrusión. Diseñado para investigación de seguridad y recolección de inteligencia sobre amenazas.

## ¡Este proyecto está en una etapa temprana de desarrollo!

La mayoría del tiempo de desarollo de este proyecto ha sido dedicado a añadir funcionalidad y establecer una dirección para el desarollo de esta herramienta, aunque se ha tenido en cuenta la seguridad durante el proceso de diseño e imprlementación no ha habido pruebas de seguridad en profundidad.

En resumen: **No se recomienda el uso de esta herramienta en producción en su estado actual**

## **Funcionalidades**

- [x] Honeypot SSH
	- Simula un servicio SSH para capturar intentos de login y comandos
	- Recolecta credenciales y emula un entorno de shell restringido con respuestas realistas.
	- Incluye uptime dinamico, listas de procesos realista y emulación de sesión de usuario.

- [x]  Honeypot Web
	- Simula un WordPress login y panel de admin para capturar intentos de login y peticiones HTTP.
	- Recolecta credenciales y redirige intentos de login no autorizados.
	- Recolecta parametros de la URL de forma separada para identificar ataques web mas facilmente.

- [x] Panel de inteligencia a tiempo real
	- Interfaz interactiva que muestra datos de forma intuitiva para visualizar campos como IP con mas tráfico o geolocalización de direcciones IP.
	- Incluye filtros por servicio, traducciónes y actualización dinamica de datos.
	- Construido con Dash y Plotly para una experiencia de usuario moderna y adaptable.

- [x] Funcionalidades generales 
	- Arquitectura modular y diseño multihilos para facilidad de configuración y escalabilidad. 
	- Rotación de logs para mejor manejo de datos y mejor uso de almacenamiento
	- Variables de entorno y `.gitignore` que proteje datos sensibles como claves RSA o logs.
	- **Demo mode:** Permite demostración y pruebas usando strings obvias para difereciar facilmente un honeypot de un despliegue real.


## **Instalación**

1. **Clona el repositorio**

```shell
git clone https://github.com/Kaassal/buzzpy.git
```

2. **Configura un entoro virtual**  

Crea y activa un entorno virtual para aislar dependncias:

Crea un venv:

```shell
python3 -m venv Buzzpy_venv
```

Y activalo:
```shel
source /Buzzpy_venv/bin/activate
```

**Note:** Este paso no es estrictamente necesario, se puede llevar a cabo una instalación en todo el sistema, aun así creat un venv sigue siendo muy recomendable para evitar problemas con las dependecias.

3. **Instalación de dependencias**  

Estas se encuentan en `requirements.txt`

Primero cambia a la carpeta de proyecto:

```shell
cd Buzzpy
```

Luego instala las dependencias necesarias:

```shell
pip install -r requirements.txt
```


4. **Generación de claves**  

El honeypot ssh requiere un par de claves RSA, la clave debe llamarse server.key y debe estar en es mismo directorio en el que se encuentra requirements.txt, si estas siguiendo estos pasos deberías esta en el directorio correcto

5. **Configura las variables de entorno**  
Asegurate de que `public.env` file está bien configurado 

**La consulta de codigo de pais de la IP está activada por defecto**. 

If you **do not want** to make api calls to check the country code of the logged ip adresses the `public.env` file has to look like this. 

Si no quieres hacer llamadas al api para comprobar el codigo de pais de las ip recolectadas el archivo `public.env` tiene que ser así.

```
COUNTRY=False
```

**Nota:** La consulta de codigo de pais de la ip usa [esta api](https://cleantalk.org/help/api-ip-info-country-code) de clean talk, hay un limite de llamadas por minuto pero no es necesaria una clave de api.

## **Uso**

Buzzpy ofrece tres funcionalidades principales: un honeypot SSH, un honeypot web y un panel de inteligencia en tiempo real

### **1. Honeypot SSH**

Este honeypot simula un server SSH para capturar intentos de login y comando

#### **Comando**
```bash
python buzzpy.py -s -a <address> -p <port> -u <username> -P <password> [-d]
```

#### **Argumentos**
- `-s` o `--ssh`: Ejecutar honeypot SSH.
- `-a` o `--address`: direccion IP a asignar al honeypot .
- `-p` o `--port`: Puerto a asignar al honeypot.
- `-u` o `--username`: Nombre de usuario para autenticación.
- `-P` o `--password`: Contraseña para autenticación.
- `-d` o `--demo`: (Optional) Ejecutar en modo demo con strings obvias.

#### **Ejemplo**
```bash
python buzzpy.py -s -a 127.0.0.1 -p 2222 -u admin -P password 
```
Esto ejecuta el honeypot SSH en `127.0.0.1:2222` con nombre de usuario admin `admin` y contraseña `password`.

---

### **2. Honeypot Web**
El honeypot web simula un login a WordPress y un panel de admin para capturar intentos de login y peticiones HTTP

#### **Comando**
```bash
python buzzpy.py -w -a <address> -p <port> -u <username> -P <password> [-d]
```

#### **Arguments**
- `-w` o `--web`: Ejecutar el honeypot web.
- `-a` o `--address`: direccion IP a asignar al honeypot.
- `-p` o `--port`: Puerto a asignar al honeypot.
- `-u` o `--username`: Nombre de usuario para autenticación.
- `-P` o `--password`: Contraseña para autenticación.
- `-d` o `--demo`: (Optional) Ejecutar en modo demo con strings obvias.

#### **Example**
```bash
python buzzpy.py -w -a 127.0.0.1 -p 8080 -u admin -P password
```
Esto ejecuta el honeypot web en `127.0.0.1:8080` con nombre de usuario `admin` y contraseña  `password`.
 
 ---

### **3. Panel de inteligencia a tiempo real**
El panel de inteligencia ofrece una interfaz para monitorear y analizar datos capturados por el los honeypots

#### **Comando**
```bash
python buzzpy.py -D -a <address> -p <port>
```

#### **Argumentos**
- `-D` or `--dashboard`: Ejecutar el panel.
- `-a` or `--address`: direccion IP a asignar al panel .
- `-p` or `--port`: Puerto a asignar al honeypot al panel.

#### **Ejemplo**
```bash
python buzzpy.py -D -a 127.0.0.1 -p 8050
```
Ejecuta el panel en  `127.0.0.1:8050`.

#### **Acceso**
Abre un navegador y escribe `http://<direccion>:<puerto>` (e.j., `http://127.0.0.1:8050`) para ver el dashboard.

---

### **4. Modo demo**
El modo demo se puede hablilitar para ambos honeypots con la opción `-d`, en este modo:
- El honeypot SSH usa strings de demo (e.j.,, banners falsos y respuestas con "honeypot")
- El honeypot web enseña cabeceras de demo y las strings cambian para que se sepa que es una demo

#### **Example**
```bash
python buzzpy.py -s -a 127.0.0.1 -p 2222 -u admin -P password -d
```

Ejecuta el honeypot SSH en modo demo.

---

### **5. Logs**:
Los datos recolectados se alamacenan en el directorio `log_files`.
- **Honeypot SSH Logs**:
  - `audits.log`: Recolecta intentos de login
	  - nombre de usuario 
	  - contraseña
	  - timestamp
	  - IP
  - `cmd_audits.log`: Recolecta comandos ejecutados por atacantes/auditores.
  
- **Web Honeypot Logs**:
  - `http_audits.log`: Recolecta intentos de login
	  - nombre de usuario 
	  - contraseña
	  - timestamp
	  - IP
  - `http_url_audits.log`: Recolecta peticiones HTTP
	  - URLs
	  - Metdos
	  - Parametros
	  - IP
	  - timestamp

Los logs se rotan automaticamente para gestionar el uso del disco

**Nota:** El directorio `log_files` se crea automaticamente si no esxiste

---

## **Funcionalidades futuras**

TBC
