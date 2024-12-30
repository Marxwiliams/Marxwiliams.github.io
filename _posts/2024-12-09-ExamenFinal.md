---
title: Examen Final
date: 2024-12-29 00:16:00 -05:00
categories: [Procmon Sysmon]
tags: [Cybersecurity Ethical Hacking]  # TAG names should always be lowercase
---

## **1.- ¿Cómo podrías utilizar Procmon y Sysmon juntos para investigar la actividad de un proceso sospechoso? (5 ptos)** ##
![cd](/assets/images/procmon.jpg)
![cd](/assets/images/sysmon.jpg)

**Explica los tipos de eventos que Procmon y Sysmon pueden capturar de forma complementaria.**

*Procmon: Captura eventos en tiempo real relacionados con actividades del sistema, como accesos a archivos, registros del sistema (registry), operaciones de red y procesos. Es útil para examinar operaciones detalladas en un momento específico [1].*

*Sysmon: Ofrece un registro persistente y estructurado de eventos clave relacionados con procesos, conexiones de red, creación de archivos, entre otros. Esto permite un análisis continuo y correlacionado a largo plazo [2].*

**Proporciona un ejemplo práctico de cómo identificar un posible comportamiento malicioso en un proceso utilizando ambas herramientas.**

*Supongamos que un proceso sospechoso está consumiendo recursos anómalos. Utilizamos Procmon para analizar eventos en tiempo real y observar, por ejemplo, acceso repetido a un archivo DLL inusual. Sysmon, por otro lado, puede proporcionar el historial de la creación de este proceso (EventID 1) y conexiones de red establecidas por el mismo (EventID 3). Esto permite detectar patrones sospechosos, como intentos de comunicar con un C2 (Command and Control) [3].*

## **2.- En Sysmon, ¿qué diferencias existen entre los eventos ProcessCreate y ProcessAccess, y qué utilidad tienen cada uno para un analista de seguridad? (5 ptos)** ##

**Describe los atributos principales de ambos eventos.**

*ProcessCreate (EventID 1): Registra la creación de procesos, incluyendo atributos como el nombre del archivo ejecutable, la línea de comandos utilizada, y el usuario que ejecutó el proceso.*

*ProcessAccess (EventID 10): Captura intentos de acceso a procesos ya existentes, especificando los permisos solicitados y el identificador del proceso objetivo [4].*

**Investiga y menciona al menos dos escenarios donde cada evento podría ser clave en la detección de amenazas.**

ProcessCreate: Útil para detectar procesos lanzados con nombres similares a procesos legítimos (técnicas de suplantación) o ejecutables en rutas sospechosas.
ProcessAccess: Es clave para identificar técnicas de ataque como el "process injection," donde un proceso malicioso accede a otro para inyectar código o manipular su comportamiento [5].

## **3.- En Procmon, ¿qué operación(es) corresponde(n) al evento FileCreateStreamHash en Sysmon, y cómo podrías configurarlo en Sysmon para detectar un posible uso malicioso de Alternate Data Streams (ADS)? (5 ptos)** ##


**Investiga qué son los Alternate Data Streams y por qué podrían ser usados por atacantes.**
Los ADS son flujos ocultos de datos en archivos NTFS que permiten a los atacantes ocultar cargas maliciosas sin alterar la visibilidad del archivo principal [6].

**Especifica qué operaciones de Procmon están relacionadas con este tipo de actividad.**
Operaciones como WriteFile, SetInformationFile y CreateFile en archivos con un nombre extendido (file:stream) pueden revelar interacciones sospechosas con ADS [7].
```bash
<FileCreateStreamHash onmatch="include">
    <TargetFilename condition="contains">:</TargetFilename>
</FileCreateStreamHash>
```

## **4.- En Sysmon, ¿qué ventajas ofrece el uso de filtros avanzados en comparación con capturar todos los eventos de forma indiscriminada? (5 ptos)** ##

**Investiga cómo un mal diseño de filtros podría afectar el desempeño del sistema y la calidad de los logs.**

Ventajas clave:

Reducción de ruido: Los filtros avanzados permiten enfocar la captura en eventos relevantes, reduciendo significativamente el volumen de logs generados y almacenados [1].
Mejora del rendimiento: Al limitar la cantidad de eventos registrados, se reduce la carga en el sistema, tanto en términos de procesamiento como de almacenamiento, evitando ralentizaciones innecesarias [2].
Facilidad de análisis: Al eliminar datos irrelevantes, los analistas pueden identificar patrones maliciosos o comportamientos sospechosos de forma más rápida y efectiva [5]


Exceso de ruido: Capturar eventos irrelevantes puede generar una cantidad de datos abrumadora, dificultando el análisis y aumentando el tiempo necesario para identificar amenazas reales.
Falsos negativos: Si los filtros excluyen eventos críticos, existe el riesgo de omitir actividades maliciosas importantes, dejando brechas de seguridad.
Sobrecarga del sistema: Un diseño ineficiente puede causar un uso excesivo de recursos, impactando el rendimiento de los servidores o endpoints monitoreados [8]

**Proporciona un ejemplo de un filtro efectivo para reducir ruido en un entorno de producción.**

En un entorno de producción, es común recibir grandes cantidades de eventos relacionados con procesos legítimos del sistema operativo o software empresarial conocido. Para reducir este ruido, un filtro efectivo podría enfocarse en excluir procesos o rutas comunes confiables y registrar solo actividades sospechosas. Aquí tienes un ejemplo práctico de filtro para Sysmon:

```bash
<SysmonConfig>
  <RuleGroup name="Suspicious Processes" groupRelation="or">
    <!-- Incluir procesos ejecutados desde rutas sospechosas -->
    <Image condition="contains">\Temp\</Image>
    <Image condition="contains">\AppData\Roaming\</Image>
    <Image condition="contains">\Downloads\</Image>
  </RuleGroup>

  <RuleGroup name="Exclude Noise" groupRelation="and">
    <!-- Excluir procesos comunes de rutas confiables -->
    <Image condition="is">C:\Windows\System32\*</Image>
    <Image condition="is">C:\Program Files\*</Image>
    <Image condition="is">C:\Program Files (x86)\*</Image>
  </RuleGroup>
</SysmonConfig>
```

## **REFERENCIAS** ##

[1] M. Russinovich, "Process Monitor," Microsoft Docs, 2023. [Online]. Available: https://learn.microsoft.com/en-us/sysinternals/downloads/procmon

[2] Sysinternals, "Sysmon Documentation," Microsoft Docs, 2023. [Online]. Available: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

[3] R. McClure, "Investigating Malware with Sysinternals," Malwarebytes Labs, 2022.

[4] D. Blazer, Advanced Threat Hunting Techniques, CyberSec Press, 2021.

[5] J. Johnson, "Detecting Process Injection with Sysmon," CyberDefense Blog, 2023.

[6] Microsoft, "Alternate Data Streams," Microsoft Security Resources, 2023.

[7] K. Harris, "Monitoring NTFS Streams with Procmon," Forensic Analysis Weekly, 2023.

[8] A. Patel, "Optimizing Sysmon Filters," Security Ops Magazine, 2023.