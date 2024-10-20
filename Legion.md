# INTRODUCCIÓN

## []{#anchor-1}¿Que es legion?

** Legion **es una bifurcación de Sparta de SECFORCE, es un network
penetration testing framework (marco de pruebas de penetración de red)
de código abierto, fácil de usar, súper extensible y semiautomático que
ayuda en el descubrimiento, reconocimiento y explotación de sistemas de
información.

### []{#anchor-2}Características

-   Reconocimiento y escaneo automático con NMAP, whataweb, nikto,
    Vulners, Hydra, SMBenum, dirbuster, sslyzer, webslayer y más (con
    casi 100 scripts programados automáticamente).
-   Interfaz gráfica fácil de usar con ricos menús contextuales y
    paneles que permiten a los pentesters encontrar y explotar
    rápidamente vectores de ataque en hosts.
-   La funcionalidad modular permite a los usuarios personalizar Legion
    fácilmente y llamar automáticamente a sus propios
    scripts/herramientas.
-   Múltiples configuraciones de escaneo personalizadas ideales para
    probar diferentes entornos de diversos tamaños y complejidades.
-   Escaneo de escenario altamente personalizable para evasión IPS tipo
    ninja.
-   Detección automática de CPE's (Common Platform Enumeration) y CVE's
    (Common Vulnerabilities and Exposures).
-   Vincula CVE a Exploits como se detalla en Exploit-Database.
-   Guardado automático en tiempo real de los resultados y tareas del
    proyecto.

# []{#anchor-3}PRIMEROS PASOS

## []{#anchor-4}Instalación

Normalmente viene instalada con el sistema Kali-Lnux, pero de ser
necesaria su instalacion podemos hacerlo de varias maneras.

Después de actualizar la base de datos, podemos instalar legion usando
apt-get ejecutando el siguiente comando:

**sudo apt-get -y install legion**

**

Clonando un repositorio Git. Se da por echo que se tiene instalado
Python 3.6.

En la terminal:

git clone https://github.com/GoVanguard/legion.git

cd legion

sudo chmod +x startLegion.sh

sudo ./startLegion.sh

# 

## []{#anchor-5}Ejecución

![](Pictures/100000000000078000000438269E7762D525F559.png){width="6.07cm"
height="6.274cm"}

Luego de la instalación, para ejecutar la interfaz grafica, debemos
simplemente tipiar en la consola con permisos de súper usuario:

\# sudo legion

O simplemente desde el menú de aplicaciones:

Menú \> Análisis de vulnerabilidades \> legion

## []{#anchor-6}Agregar Objetivos

Para agregar uno o mas objetivos hacemos click dentro del rectángulo
como se indica en ingles "click here to add host(s) to scope" (Haga clic
aquí para agregar host(s) al alcance). Si no desde el símbolo de "**+**"
verde ubicado abajo a la derecha dentro de la pestaña host.

![](Pictures/10000000000007800000043827A2D41D1768A778.png){width="7.049cm"
height="2.589cm"}![](Pictures/10000000000007800000043888F2EAB0A03EE3DB.png){width="16.949cm"
height="11.631cm"}

# 

# []{#anchor-7}ESCANEO DE OBJETIVOS

## 

## []{#anchor-8}Selección de opciones (Banderas nmap)

![](Pictures/1000000000000780000004382D2D7A71B4B65ADF.png){width="17cm"
height="9.562cm"}

Al efectuar click en **"agregar host"**, se nos abre otra ventana con
diferentes opciones, las cuales están dividas en 7 secciones.

1 » Selección de ip\'s, dominio\'s.

2 » Selección de modo

3 » Opciones modo fácil

4 » Opciones de tiempo y rendimiento

5 » Opciones de escaneo de puertos

6 » Opciones de detección de host

7 » Opciones personalizadas

### 

### []{#anchor-9}**1. Selección de objetivos **

Aquí podemos agregar uno o varios hosts para escanear. Podemos agregar
una única IP (192.168.1.1) o un rango de IP's (192.168.1.1-255) una
subred entera usando la notación CIDR (Classless Inter-Domain Routin
192.168.1.0/24) o nombres de dominio(por ejemplo: hackthissite.com) Para
agregar varios objetivos, debemos separarlos con punto y coma.

### []{#anchor-10}***2. ****Selección**** de modo***

![](Pictures/10000000000007800000043873844074670ED5F9.png){width="16.951cm"
height="1.296cm"}

Aquí tenemos dos opciones de selección Modo** **FÁCIL o DIFICIL

Si elegimos la opción FÁCIL se habilitaran los espacios de configuración
3 y 4 (easy mode y timing and performance)

Si elegimos DIFICIL lo haran los espacion 4, 5 y 6. (timing and
performance, port scan y Host discovery) pero no el 3 (easy mode)

### []{#anchor-11}3. Opciones modo facil

![](Pictures/100000000000078000000438CF4D7DBEB815AE52.png){width="16.87cm"
height="1.192cm"}

**Run nmap Host Discovery \-\-\--»** Si dejamos activa esta casilla
enviaremos una bandera "-O" al comando que se ejecutara de nmap, con
esta opcion el comando es:

nmap -n -sV -O \--version-light -T4 \[IP\]

-n/-R: No hacer resolución DNS / Siempre resolver por omisión: a veces

-sV: Verificar la versión de los puertos escaneados.

-O: Intenta detectar el sistema operativo

\--version-light: Limitar a los escaneos más probables (intensidad 2)

-T4: valor por defecto, tiempo y rendimiento del escaneo.

**Run Staged Nmap Scan \-\-\--»** Activada por defecto en un escaneo en
modo fácil, produce una serie de escaneos de diferentes etapas, de la 1
a la 6.

***C****omandos Utilizados en las diferentes etapas :***

Etapa 1 Ping (herramienta hping3): hping3 -V -C 13 -c 1 \[IP\]

Etapa 2 (fast TCP): nmap -Pn -sV -sC -F -T4 -vvvv \[IP\]

Etapa 3 (fast UDP): nmap -n -Pn -sU -F \--min-rate=1000 -vvvvv \[IP\]

Etapa 4 (vulners): nmap -sV \--script=./scripts/nmap/vulners.nse -vvvv
\[IP\]

Etapa 5 (full TCP): nmap -Pn -sV -sC -O -p- -T4 -vvvvv \[IP\]

Etapa 6 (full UDP): nmap -n -Pn -sU -p- -T4 -vvvvv \[IP\]

Puertos utiliizados en las diferentes etapas:

Etapa » Puertos:

**E1»** T:80,81,443,4443,8080,8081,8082

**E2» **T:25,135,137,139,445,1433,3306,5432, U:137,161,162,1434

**E3»** NSE\|vulners

**E4»** T:23,21,22,110,111,2049,3389,8080,U:500,5060

**E5»**
T:0-20,24,26-79,81-109,112-134,136,138,140-442,444,446-1432,1434-2048,2050-3305,3307-3388,3390-5431,5433-8079,8081-29999

**E6»** T:30000-65535

## 

### 

### []{#anchor-12}4. Opciones de tiempo y rendimiento ( -T )

![](Pictures/1000000000000780000004382D2D7A71B4B65ADF.png){width="16.925cm"
height="1.501cm"}

Simplemente deslizando la barra elegiremos entre los diferentes modos de
ataque, de las plantillas de temporizado de nmap (las banderas -T0 /
-T5) hacia la derecha escaneos mas rápidos, pero mas ruidosos y
agresivos, hacia la izquierda lo contrario, menos ruido, menos
agresividad, mas "sigilo" pero mucho mas lentos.

-T4 es el utilizado por defecto.

![](Pictures/1000000100000356000001B23C80F71062467314.png){width="17cm"
height="10.88cm"}

### []{#anchor-13}***5. ****O****pciones de escaneo de puertos ****( -sT -sS -sF -sN -sX -sP -sU -f )***

![](Pictures/1000000000000780000004382D2D7A71B4B65ADF.png){width="16.983cm"
height="1.279cm"}

Las diferentes opciones para el escaneo de puertos son:

  ---------- ----- ---------- ----- ------ ------ ---------- ---------- ------------
  Opciones   TCP   Ofuscado   FYN   NULL   Xmas   TCP Ping   UPD Ping   Fragmentar
  Bandera    -sT   (-sS)      -sF   -sN    -sX    -sP        -sU        -f
  ---------- ----- ---------- ----- ------ ------ ---------- ---------- ------------

**-sT**: realiza un escaneo de conexión TCP. Es el análisis
predeterminado para los usuarios sin privilegios. El TCP Connect Scan
intenta conectarse directamente al objetivo sin utilizar ningún sigilo.
Establece una conexión directa y completa.

**Ofuscado (-sS)**: El escaneo TCP SYN es la opción por defecto para
usuarios root. Intenta identificar los 1000 puertos TCP más utilizados.
Conocido como "half open" (medio abierto), no establece una conexión por
completo. Se lo considera sigiloso y es uno de los escaneos mas comunes
y rapidos

**-sF**: Escaneo TCP FIN, marca el bit TCP FIN activo, envía un paquete
TCP con la bandera FIN establecida para determinar si un puerto está
abierto o cerrado.

**-sN**: Escaneo TCP NULL, hace que Nmap envíe paquetes sin indicadores
TCP habilitados. Esto es posible estableciendo el encabezado del paquete
en 0. El NULL, desactiva todas las banderas (en esta técnica podíamos
ver que si tenemos puertos cerrados es un LINUX y puertos abiertos es un
WINDOWS).

**-sX**: Escaneo Xmas (navidad), Nmap envía paquetes con URG, FIN y PSH.

Se le llama Xmas por que se activan los flags FIN, PSH y URG, que vistos
desde Wireshark parecen un árbol de navidad.

-sF -sN -sX: son técnicas de escaneo para poder evitar los filtros de
paquetes (ya que muchos analizan los SYN), entonces lo que envían son
paquetes determinados (por ejemplo un RST) hacia puertos cerrados, y a
los puertos cerrados cuya respuesta las ignoraran (por deducción
sabremos si se encuentran activos)

**-sP**: Llamado Escaneo Ping o Ping Sweep, para poder realizar un
relevamiento de dispositivos activos. Lo que realiza es mandar un ACK al
puerto 80 (por default), si obtiene un RST, la máquina esta activa, es
más fiable que hacer ping a la dirección de broadcast, ya que algunos
equipos no responden a ese tipo de consultas.

\-**sU**: Se utiliza para escanear a través de puertos UDP. Mientras que
TCP es el más protocolo de uso común, muchos servicios de red (como DNS,
DHCP y SNMP) todavía utilizan UDP.

**-f**: Simplemente divide el escaneo en paquetes de 8 bytes, existen
otras banderas para fragmentar, como \--mtu 16 o --mtu 32 Algunos S.O
pueden necesitar --send-eth combinando con -f o -mtu para realizarlo
correctamente.

### []{#anchor-14}6. Opciones de detección de host (-Pn -PB -PE -PT -PS -PP -PM )

![](Pictures/1000000000000780000004382D2D7A71B4B65ADF.png){width="16.963cm"
height="1.984cm"}

Las diferentes opciones de escaneo son:

  ---------- --------- --------- ------ --------- --------- ----------- ---------
  Opciones   Disable   Default   ICMP   TCP SYN   TCP ACK   Timestamp   Netmask
  Bandera    -Pn       -PB       -PE    -PT -PS   -PT       -PP         -PM
  ---------- --------- --------- ------ --------- --------- ----------- ---------

-Pn: (No Ping) Simplemente no hace ping hacia el host/s, omite la
comprobación de detección y realiza el escaneo, si un firewall bloquea
las peticiones ICMP, esta bandera nos sera útil.

-PB: Opción por default, realiza un ping ICMP y un ping TCP con paquetes
ACK.

\-**PE**: Esta bandera envía un ping ICMP estándar al destino. Este tipo
de descubrimiento funciona mejor en redes locales donde se pueden
transmitir paquetes ICMP con pocas restricciones. Sin embargo, muchos
hosts de Internet no responden a Paquetes ICMP por razones de seguridad.

-PT -PS: Esta opción utiliza dos banderas diferentes, -PT y -PS

-PT: Esta a bandera se utiliza para escanear puertos TCP utilizando
técnicas de escaneo sin conexión, lo que permite un escaneo más rápido y
menos intrusivo.

**-PS**: Envía un paquete SYN al sistema de destino y escucha una
respuesta. Este método de detección alternativo es útil para sistemas
configurados para bloquear pings ICMP. Nota El puerto predeterminado
para -PS es 80.

**-PP**:** **Realiza un ping con una marca de tiempo ICMP. Si bien la
mayoría de los sistemas con firewall están configurados para bloquear
las solicitudes de eco ICMP, algunos sistemas están configurados
incorrectamente y aún pueden responder a las solicitudes con marca de
tiempo ICMP. (Estas solicitudes se utilizan para determinar la latencia
de una conexión.)

**-PM**: Es una consulta ICMP no convencional (similar a la opción -PP)
intenta hacer ping al host especificado utilizando registros ICMP
alternativos. Este tipo de ping puede que ocasionalmente pase a través
de un firewall que está configurado para bloquear solicitudes estándar.

## 

### []{#anchor-15}*7. Opciones personalizadas*

Podemos agregar banderas que no se encuentren dentro de las opciones de
la ventana

![](Pictures/10000000000007800000043873844074670ED5F9.png){width="16.759cm"
height="2.117cm"}

-D RND:5 = selecciona 5 IPs al azar. (Ejemplo)

Después de seleccionar las opciones deseadas simplemente clickear en
Submit para comenzar el escaneo. Dependiendo de la cantidad de host's y
opciones elegidas tardara mas o menos tiempo en completarse el escaneo.

Si queremos saber mas sobre las posibles banderas y funcionamiento de
nmap:

[[]{#anchor-16}*https://nmap.org/book/toc.html*](https://nmap.org/book/toc.html)

# []{#anchor-17}COMPRENSIÓN DE LA INTERFAZ Y RESULTADOS.

Una vez finalizado el escaneo, veremos un resultado como este (en este
caso se uso metasploitable 3 y ubuntuserver para el ejemplo)

A la derecha dentro de la pestaña Scan, 3 pestañas mas, Host (nos
muestra los host dependiendo de los filtros elegidos), Services (filtra
por servicios y no por host) y tool (filtra
po![](Pictures/1000000000000780000004382D7EFC348F621708.png){width="16.884cm"
height="8.132cm"}r herramientas utilizadas)

### 

## []{#anchor-18}Pestañas

En el panel de la derecha podemos observar 4 pestañas principales
(**Services, Scripts, Information, CVEs**). Seguido **Notes** y las
siguientes dependiendo del caso Capturas de pantalla y los Log's de
salida de los scripts ejecutados

### []{#anchor-19}Services:

Nos muestra una tabla con el **puerto** escaneado, el **protocolo**
utilizado tcp/udp, el **estado** del puerto (abierto, cerrado,
filtrado), el **nombre** del puerto y después la **versión.**

(La información se puede organizar haciendo click en la parte superior
de cada columna)

En el caso del primer puerto:

Puerto: 21 \| Protocolo: tcp \| Estado: abierto \| Nombre: ftp \|
Versión: ProFTPD 1.3.5

![](Pictures/100000000000078000000438D9A657B0AD76E8F8.png){width="16.879cm"
height="9.148cm"}

En el caso del puerto 445 nos indica la versión aproximada de Samba,
entre 3.X y 4.X y tambien que hay un grupo de trabajo que se llama
WORKGROUP

En el caso del puerto 3306 que el acceso no es autorizado, ya que no
encontró las credenciales de acceso dentro de los parámetros
establecidos.

### []{#anchor-20}Scrips:

Los scripts de Nmap (NSE Nmap Scripting Engine) son pequeños programas o
instrucciones que se utilizan junto con la herramienta de escaneo para
realizar tareas específicas, como detección de servicios, detección de
vulnerabilidades o recopilación de información sobre hosts en una red.

.En este caso observamos que se utilizaron 2 script's **vulners **y**
http-server-header.**

El script Vulners:

nmap -sV \--script vulners \[\--script-args mincvss=\<arg_val\>\]
\<target\>

Para cada CPE (Common Platform Enumeration) disponible, el script
muestra las vulnerabilidades conocidas y tambien el puntajes CVSS
(Common Vulnerability Scoring System) correspondientes.

Funciona sólo cuando se identifica alguna versión de software para un
puerto abierto

Busca todos los CPE conocidos para el servicio (de la salida nmap -sV
estándar)

realiza una consulta a un servidor remoto (API de vulners.com) para
saber si existen vulnerabilidades conocidas para ese CPE.

Si no encuentra informacion probara solo con el nombre del servicio

**Utilizando este script se hacen solicitudes a un servicio remoto.**
**Aún así, todas las solicitudes contienen solo dos campos: el nombre
del software y su versión (o CPE), de esta manera se preserva la
identidad de los usuarios**

El script http-server-header:

El script \"http-server-header\" puede ser inviable hoy en día debido a
cambios en los estándares de seguridad y privacidad en la web.

![](Pictures/1000000000000780000004380B3C868FAA57C1C4.png){width="16.847cm"
height="9.34cm"}

### []{#anchor-21}Information:

En esta pestaña encontramos el estado del host:

State: up (Activo, down si fuera inactivo)

Puertos abiertos: 9 \| Puertos cerrados: 2 \| Puertos filtrados: 65524

Tipo de Sistema Operativo y el porcentaje de precisión del resultado
obenido: en este caso no obtuvo resultados

Direcciones: IPV4 -- IPV6 -- MAC-vendedor - ASN(Autonomous System
Number) - ISP

Localización: No obtubo resultados pero encontraríamos información sobre
el país, ciudad y posición geografica

![](Pictures/1000000000000780000004380E4B7CB4A1A3121C.png){width="16.914cm"
height="9.394cm"}

### 

### []{#anchor-22}*CVE'S:*

En esta pestaña se imprimen los resultados de las vulnerabilidades
encontradas con su respectivo puntaje, como se detalla en la pestaña de
SCRIPT'S (pag.12), pero organizada de una mejor manera y con mas
información:

Las columnas mas iportantes a tener en cuenta:

CVE id: Identificador CVE (Common Vulnerabilities Exposures) Ejemplo:
CVE-2015-3306

CVVS Score: Puntaje CVVS Ejemplo 10.0

Version: 1.35

CVE URL: En este caso no esta el link hacia la pagina.(cve.org)

Source: Fuente donde proviene el CVE, en este caso Proftpd

Producto: Tambien es Proftpd

ExploitDb ID: Identifiador de exploit database

ExlploitDb URL: Hipervinculo a dicho exploit.

En la imagen de abajo la informacion no concuerda con las columnas
**(=**debido a una mala configuración en este caso en particular**:) **

![](Pictures/100000000000078000000438909197105BE8082D.png){width="16.988cm"
height="9.805cm"}

### []{#anchor-23}Notas:

En el caso de guardar los resultados de un ataque, se podrán dejar
apuntes directamente dentro de la interfaz.

![](Pictures/100000000000078000000438EE6EA19753031E41.png){width="16.907cm"
height="3.84cm"}

### []{#anchor-24}Otras Pestañas:

Dependiendo del tipo y resultado del escaneo, podemos observar otro tipo
de pestañas que varían entre capturas de pantalla (screenshot) y las
salidas de los distintos log's** **de las herramientas utilizadas:

![](Pictures/100000000000078000000438E9E547B5F9EDE4B6.png){width="11.961cm"
height="6.249cm"}

Pestaña screenshot:

**Pestaña de log** de un script de hydra, se realizo sin resultados
positivos, un ataque de diccionario ( mas adelante veremos algunos
ejemplos con hydra):

![](Pictures/1000000000000780000004381E4C81C7F59D46EA.png){width="14.245cm"
height="4.86cm"}

### []{#anchor-25}Mas opciones de escaneo

## []{#anchor-26}

Si todavía no estamos conformes o se nos olvido tal vez algún parámetro
a la hora de iniciar nuestro escaneo, simplemente haciendo click derecho
en el puerto se desplegara un menú con diferentes opciones.

![](Pictures/100000000000078000000438F2BFD62824CF271B.png){width="10.881cm"
height="8.012cm"} Cada puerto o servicio tiene diferentes opciones uno
de los otros en este caso Puerto 21 Servicio ftp, las opciones varias de
simplemente abrir un servicio de ftp al puerto 21 en la terminal, enviar
para fuerza bruta, Grab banner, escaner scrip's de nmap en el puerto,
etc

Puerto 80 servicio http: observemos la cantidad de opciones, desde un
simple screenshot, pasando por todos los NSE de nmap, escanear con
nikto, wahatweb, entre otras. Cada vez que hagamos click en un opción de
este menu, se abrira una pestaña con la informacion obtenida.(como en el
ejemplo de la pagina anterior pestaña de log)

![](Pictures/10000000000007800000043888A01D560E2B18BA.png){width="17cm"
height="8.214cm"}

Lo mismo podemos realizar con el menú de la derecha en Host o en
Services, si hacemos click derecho en el IP o nombre de host, podremos
re-escanear el objetivo, eliminarlo, hacer un ICMP timeestamp, entre
otras opciones.

![](Pictures/100000000000078000000438F12107CB8C6683C2.png){width="16.912cm"
height="8.625cm"}

![](Pictures/10000000000007800000043863B02FBF1633D091.png){width="16.544cm"
height="10.181cm"}Ejemplo desde la Pestaña servicio, sus opciones y la
manera de imprimir en la pantalla

los resultados organizando por servicio.

# 

# []{#anchor-27}Ataques a contraseñas

Desde la pestaña** Scan » Services**, haciendo click derecho sobre
cualquier fila de un puerto/servicio y después seleccionar **"Send to
Brute"**, podemos enviar de una manera muy sencilla el puerto y servicio
elegidos para ser atacado. Por cualquiera de las formas que
explicaremos. Si no también podemos ingresar los datos manualmente.

Estos ataques se realizaran utilizando la herramienta hydra ( instalada
por defecto en Kali Linux )

## []{#anchor-28}Fuerza Bruta

Para realizar un ataque de fuerza bruta solo se necesita accionar las
casillas **"Found Usernames"**, **"Found Passwords"**, dependiendo
siempre de la necesidad del usuario y tabien del conocimiento del
objetivo

![](Pictures/100000000000078000000438AE2826C5A2354153.png){width="16.917cm"
height="3.51cm"}

Selección manual de credenciales

A la izquierda se encuentran las casillas de Username y Password,
podemos selecccionar las credenciales que conozcamos manualmente.

Por defecto Username: root y Password: Pasword.

Hay otras casillas como Try blank password (Probar password en blanco),
Try login as password (Probar login como password), Loop around users (
Girar alrededor de los usuarios), Exit on first valid (salir al
descubrir la primera acreditación valida), Vervose y Additional Options
(Opciones adicionales) aquí agregaremos parametros de hydra.

## []{#anchor-29}*Diccionario*

Para realizar este tipo de ataque una vez cargado los datos del host
obetivo, debemos elegir las casillas Username list (listas de usuarios)
y Password list (listas de passwords). Despues desde el boton de Browse
(buscar) y elegir la ubicación donde se encuentra el archivo de texto
que contiene la lista de usuarios, passwords, pueden ser el mismo o
diferentes archivos.

En la imagen se observa que despues de 264 intentos, de un tota de
57377624 posibilidades, resolvió que las credenciales de acceso son
login o nombre de usuario: "dabinchy" y el password: "1234".

![](Pictures/1000000000000780000004384EE708A0C0E45D01.png){width="16.84cm"
height="13.141cm"}

Desde la izquierda podemos seleccionar las casillas Username y/o
Password para establecer las credenciales en caso de conocer ambas o una
de ellas.

# 

# []{#anchor-30}FIX LEGION

En caso de que legion presente problemas a la hora de su ejecución,

se recomienda una instalación limpia de Nnap.

Ejecutar legion, seguido ir a Help » Config

Y reemplazar la sección de configuración de niveles nmap con los
siguientes parámetros:

\[StagedNmapSettings\]

stage1-ports=\"PORTS\|T:80,81,443,4443,8080,8081,8082\"

stage2-ports=\"PORTS\|T:25,135,137,139,445,1433,3306,5432,U:137,161,162,1434\"

stage3-ports=\"NSE\|vulners\"

stage4-ports=\"PORTS\|T:23,21,22,110,111,2049,3389,8080,U:500,5060\"

stage5-ports=\"PORTS\|T:0-20,24,26-79,81-109,112-134,136,138,140-442,444,446-1432,1434-2048,2050-3305,3307-3388,3390-5431,5433-8079,8081-29999\"

stage6-ports=\"PORTS\|T:30000-65535\"

# []{#anchor-31}Bibliográfica y Vínculos de interés

[**https://nmap.org/book/toc.html**](https://nmap.org/book/toc.html)**
**** ****

**(The Official Nmap Project Guide to Network Discovery and Security
Scanning)**

[*https://github.com/GoVanguard/legion*](https://github.com/GoVanguard/legion)

Nmap Cookbook The Fat free Guide to Network Scanning by Nicholas.pdf (si
es requerido se pude brindar una copia del .pdf)

[*https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml*](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)

[*https://www.exploit-db.com/*](https://www.exploit-db.com/)

[*https://cve.mitre.org/*](https://cve.mitre.org/)
