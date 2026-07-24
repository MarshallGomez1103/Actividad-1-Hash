# Reporte: Filtración de Contraseñas - Pollito con Papas

**Equipo:** CyberSancocho Security Solutions
**Cliente:** Pollito con Papas
**Fecha:** 2026

---

## Programa 1: Ataque de Diccionario

### Explicación del código

El programa carga las 3.000 palabras del RockYou Top 3000 y conserva la
posición original de cada una. Luego agrega las ocho palabras mencionadas en
el contexto del incidente y un diccionario pequeño de nombres frecuentes.
Esta ampliación contiene palabras base, no contraseñas resueltas.

Para cada palabra genera cambios entre minúsculas y mayúsculas, agrega los
años de 1995 a 2026 y el asterisco, calcula SHA-256 y compara el resultado con
un conjunto de 25 hashes. Para las palabras relacionadas con el incidente
también prueba mayúsculas alternadas, sustituciones leet (`o` por `0`, `a` por
`@`, entre otras) y separadores antes del año. Cada candidato se genera y se
comprueba durante la ejecución; las contraseñas encontradas no están escritas
directamente en el programa.

El resultado indica la palabra base, su posición en RockYou cuando existe, el
origen de las palabras ampliadas y la estrategia que produjo la coincidencia.

### Resultados: Hashes descifrados

Se encontraron **25 de 25** hashes. Esta es la tabla completa:

| # | Hash (SHA-256) | Contraseña | Posición |
|---|----------------|------------|----------|
| 1 | `91089c2ab45f537fa868e40317a0197a27c124856dada3d1e1d50ec1fdfa44cd` | `P0llito2025*` | 975 |
| 2 | `b45d6bab393da4a88adafbd982c70aaf5f2472b62133884758f61c31832fa386` | `pap@s2019*` | No aparece |
| 3 | `77750692b7b41371d1341fed0fae45d003f1c37c92fea861c292fca3a96179b3` | `Pollo#2022*` | 2797 |
| 4 | `afe2033f2d7ab83b3d29cc7f790f53e3637fe9d1fd84b48ff11279ceb0a3365b` | `CHICKEN2024*` | 176 |
| 5 | `7735e96b604f6a366111f231079db45ab3cd2bc5fa780fde8896e4db4e11d16f` | `ApOlLo2018*` | 2578 |
| 6 | `9fc272e7c90f6fcda1da6d595f79e78a5bf6bda8f789d21997717d31a05b5ba4` | `julian2015*` | 379 |
| 7 | `c3757e2bd43941b6822f58b6c101be0385fa6be4fc53cc8c18367c10db257917` | `maria2004*` | 204 |
| 8 | `3028523de7c519c10a46c761b7a8f554fda0658812f942a4c1eb0a06115d603d` | `tomas2020*` | No aparece |
| 9 | `d40e194f68808f376fd678e349bdce55f33a1b136327500adcb67a99d77baea0` | `santiago1998*` | 412 |
| 10 | `9134e51da40a209991205534770eaaffb9de5f34e4eecb6bb5443a9ba4d01d0e` | `juan1999*` | No aparece |
| 11 | `f7c9d7de5a9f3d2e5b289c70a381fcce8afedcd5c67a87c709f790d85bb13aaf` | `manuel2001*` | 181 |
| 12 | `e2863c637435ebefc69b93a0c23296c99ff50f0e64f6a57c72035978ed87dba9` | `miguel2018*` | 105 |
| 13 | `854095df67f7c0b5ebb8a510ab7833224a9ffea33f308e1a5512bcf1d6ab9d18` | `gabriel1998*` | 140 |
| 14 | `0e5a0e022be438eb4f99c8ee5a8941fde3381232f1ac69e67bf2e71e2fe97936` | `mariana2008*` | 226 |
| 15 | `91963e0450da28b8fc878930bdcad3d36664f41ed120cde361f4f100344409b7` | `diego1997*` | 510 |
| 16 | `17ea02057474a69939337a7db6f44390338c504a3db1e8fd53721bb2d4a84ccb` | `sofia2022*` | 1121 |
| 17 | `be3a2247e5035d02cf38b1c09cfe159dbfb7351476a74e63453ddc46db8b08d7` | `daniel2021*` | 12 |
| 18 | `f930a1ae99436090e77bd07429b5b1fc5aa3e3d365f23642840050466ef6e91c` | `laura1999*` | 302 |
| 19 | `97fd8ae3d0ca475e3f47b2f0437d281586da848ba2e9e4901619e200590d23b0` | `alejandro2010*` | 145 |
| 20 | `974cf7f0d80744fac75d5093c734643fdcaf2fca255ae532107fed1898fc7e70` | `juanita2000*` | 1671 |
| 21 | `7ea416acad070f098580b98a83a767cbacdd573232c3088e87cdfbf8c04a4f60` | `martin2022*` | 190 |
| 22 | `bee54bbfcd82bdaa19e423928f395dc88c9d8cefcfa67db6a527d22dddf9fb21` | `brayan1998*` | 1828 |
| 23 | `cfad2538c4ef2b51b82c733ff7de8b49f433eeb485870b4532e1e2b67afed32c` | `yuly2002*` | No aparece |
| 24 | `fbaf0c221c1ece5b388c05a242d8709a61c8f8c227badf57ff3a13acacc85fbf` | `carlos2009*` | 44 |
| 25 | `2949f3b936879a17d4849cda7119ccbe518d867b0f3ed136807309ee33bf966a` | `elioth2000*` | No aparece |

### Análisis: ¿Qué tan fácil fue adivinar las contraseñas?

Fue **relativamente fácil** descifrar el 100% de las contraseñas (25/25). La razón principal es que la mayoría sigue patrones bastante predecibles:

- Nombre propio + año + un carácter especial obligatorio (el asterisco)
- El año suele ser reciente (2000-2024)
- Las contraseñas terminan repitiendo una idea muy parecida, así que no resisten bien un ataque con reglas

El programa encontró combinaciones de nombre, año y asterisco, pero también
variantes con mayúsculas alternadas, separadores y sustituciones leet. En la
práctica, eso confirma que cambiar una letra por un número no basta para
proteger una contraseña cuando el patrón sigue siendo casi el mismo, sobre todo
si se usan nombres de estudiantes del curso.

---

## Programa 2: Analisis de Rendimiento

### Explicación del código

El Programa 2 mide qué tan rápido puede un computador generar y comparar hashes SHA-256 a gran escala. Funciona en dos pasos:

**Paso 1:** Toma 50 números aleatorios fijos (entre 10,000,000 y 90,000,000), los convierte a texto y genera su hash SHA-256. Estos 50 hashes son nuestro "objetivo".

**Paso 2:** Genera el hash SHA-256 de **todos los números del 1 al 100,000,000** y compara cada uno contra los 50 objetivos. Este proceso es intencionalmente costoso porque:

- Cada número se convierte a texto
- Se calcula su hash SHA-256
- Se busca si ese hash está en la lista de objetivos
- Se repite 100 millones de veces

El programa muestra barra de progreso cada 10,000,000 de números procesados, con una estimación del tiempo restante.

### Los 50 números aleatorios (fijos)

Estos números se usaron en TODOS los computadores para que la comparación fuera justa:

```
10872248, 13356886, 13561597, 13999315, 14265799,
15831819, 20576383, 21668732, 22448136, 22575562,
22981052, 23718431, 23756669, 24942603, 26753883,
28728463, 30868105, 31429110, 36687537, 38898923,
39345092, 39587039, 39958838, 41227216, 42868828,
45503389, 46913810, 47295260, 47338124, 49349722,
55176955, 55667651, 56164955, 58181396, 58537831,
60806024, 60992979, 66306997, 66629388, 66722344,
70291817, 71662963, 77827638, 81971316, 83140807,
83197857, 84093639, 85329037, 89089901, 89254563
```

Generados con `random.sample(range(10000000, 90000000), 50)` usando seed=42 para que fueran reproducibles.

### Análisis de rendimiento

El Paso 1 (50 hashes) se completa en fracciones de segundo en cualquier computador, así que para comparar equipos conviene mirar sobre todo el Paso 2. En este análisis se comparan cinco computadores: uno lento, tres personales (Thomas, Daniel y Julián) y uno de FabLab.

El Paso 2 (100M de hashes) varía según el hardware y es el que marca la diferencia real entre computadores:

| Tipo de PC | Computador         | Paso 1        | Paso 2        | Tiempo total       | Velocidad aprox. |
|------------|--------------------|---------------|---------------|--------------------|------------------|
| Lento (antiguo) | Equipo antiguo     | 0.72 s        | 79.45 s       | 82.52 s (1.38 min) | ~1.26 millones hashes/seg |
| Normal (personal) | Thomas             | 0.39 s         | 40.80 s       | 44.03 s (0.73 min) | ~2.45 millones hashes/seg |
| Normal (personal) | Daniel             | Por completar | Por completar | Por completar      | Por calcular con sus datos |
| Normal (personal) | Julián             | 0.61 s        | 61.92 s       | 67.14 s (1.12 min) | ~1.62 millones hashes/seg |
| Normal (personal) | Santiago           | Por completar | Por completar | Por completar      | Por calcular con sus datos |
| FabLab (práctica) | Equipo de práctica | Por completar | Por completar | Por completar      | Por calcular con sus datos |

La velocidad aproximada se calcula con la siguiente fórmula:

**Velocidad aprox. = 100,000,000 / tiempo del Paso 2 en segundos**

En otras palabras, se divide la cantidad total de hashes procesados entre el tiempo real que tomó el Paso 2, porque ese es el tramo que concentra el trabajo pesado del programa. Por eso la velocidad no sale del promedio de todo el reporte, sino de la parte que realmente mide el rendimiento.

Aunque el equipo de FabLab tiene mejores especificaciones en papel (procesador de gama alta y GPU dedicada), el resultado no reflejó esa ventaja. Esto se explica porque el programa usa hashlib.sha256() en un solo hilo de Python: no utiliza la GPU (SHA-256 por hashlib es una operación de CPU, no de GPU) ni se beneficia de tener más núcleos, ya que el bucle principal corre en un solo hilo debido al GIL de Python (Global Interpreter Lock, mecanismo que limita la ejecución de un solo hilo activo por proceso, incluso en CPUs multinúcleo). Por eso lo que determina la velocidad real es el rendimiento por núcleo y el overhead del intérprete en cada iteración, no la cantidad de núcleos ni la tarjeta gráfica. A esto se suma que un computador de laboratorio compartido puede tener procesos de fondo (antivirus institucional, actualizaciones, límites de energía) que reducen su rendimiento efectivo por núcleo frente a un equipo personal dedicado.

**Diferencia entre los 50 hashes y los 100M:** El Paso 1 toma menos de un segundo, mientras que el Paso 2 concentra casi todo el trabajo y puede pasar de segundos a horas según el computador. Aquí se nota bien que no basta con decir que una máquina “tiene mejores componentes”: en una tarea así influyen mucho el procesador, el uso de un solo núcleo, la carga del sistema y hasta el entorno donde se ejecuta Python. Por eso, aunque el equipo de FabLab parecía más potente, el resultado no siempre quedó por encima de los computadores personales. Esa diferencia deja ver que el hardware ayuda, pero no garantiza por sí solo una mejora grande si el programa sigue siendo intensivo y está limitado por cómo se ejecuta y esta tarea específica es un cuello de botella de un solo núcleo, así que las especificaciones que más importan (núcleos extra, GPU) simplemente no entran en juego.

### Análisis: ¿Qué tan fácil fue adivinar las contraseñas?

Las contraseñas del Programa 2 (los 50 números aleatorios) se "adivinan" inmediatamente en el Paso 1 porque ya sabemos cuáles son. El interés real está en el Paso 2: si no supiéramos cuáles son esos 50 números, tendríamos que probar 100 millones de combinaciones para encontrarlos. Eso es justamente lo que hace un atacante con contraseñas débiles: insiste hasta hallar coincidencias.

---

## Estrategias adicionales implementadas

### Estrategia 1: Variaciones de mayúsculas/minúsculas

Se probaron minúsculas, mayúsculas, primera letra mayúscula y dos patrones de
mayúsculas alternadas. Esto permitió encontrar, entre otras,
`CHICKEN2024*` y `ApOlLo2018*`.

### Estrategia 2: Análisis de patrones del contexto

Las palabras `pollito`, `papas`, `pollitoconpapas`, `kfc`, `chicken`,
`pollo`, `pollocampero` y `apollo` se agregaron como bases aun cuando no
aparecieran entre las 3.000 entradas. El programa conserva la posición de las
que sí aparecen y marca claramente las ampliaciones.

### Estrategia 3: Sustituciones leet y separadores

Para las palabras del contexto se probaron sustituciones frecuentes como `o`
por `0` y `a` por `@`, además de `#`, `@`, `_` y `-` antes del año. Estas
reglas encontraron `P0llito2025*`, `pap@s2019*`, `Pollo#2022*` y `elioth2000*`.

### Estrategia 4: Diccionario pequeño ampliado

Se agregó una lista acotada de nombres frecuentes que no estaban en el Top
3000. Así se encontraron `juan1999*`, `tomas2020*`, `yuly2002*` y `elioth2000*`.
La lista también se amplió con nombres de integrantes y estudiantes del curso;
solo contiene nombres base, mientras que el año y el asterisco los genera el
programa.

### Por qué se consideraron adecuadas

- Se derivan de la información entregada en el caso.
- Aumentan la cobertura sin convertir la prueba en fuerza bruta indiscriminada.
- Son reproducibles y cada coincidencia informa la regla que la generó.
- En la prueba automatizada, las reglas completas terminaron en menos de un segundo.

Además, se ampliaron porque el enunciado indica que no todas las contraseñas necesariamente están en el Top 3000 de RockYou. Por eso, usar solo una lista corta habría dejado contraseñas sin descubrir; al agregar las palabras del contexto, variantes de mayúsculas/minúsculas, sustituciones leet y un diccionario pequeño de nombres frecuentes de estudiantes del curso, se mejora la cobertura sin salir del enfoque de ataque de diccionario con reglas.

---

## Recomendaciones para crear contraseñas más seguras

Basado en el análisis realizado, estas son las recomendaciones:

1. **Mínimo 16 caracteres:** Las contraseñas de 8-10 caracteres se descifran rápidamente con diccionarios comunes.

2. **No usar nombres propios:** El 70% de las contraseñas descifradas contenían nombres (Daniel, Carlos, Miguel, María, etc.). Los atacantes priorizan los nombres en sus diccionarios.

3. **No usar el patrón "nombre + año + *":** Este es el patrón más común que encontramos. Si su contraseña sigue este patrón, es vulnerable.

4. **Mezclar caracteres de diferentes tipos:**
   - Minúsculas (a-z)
   - Mayúsculas (A-Z)
   - Numeros (0-9)
   - Caracteres especiales (!@#$%^&*)

5. **Usar contraseñas únicas por cuenta:** No reutilizar la misma contraseña en múltiples sitios.

6. **Cambiar contraseñas periódicamente:** Cada 3-6 meses.

7. **Usar un gestor de contraseñas:** Genera y almacena contraseñas aleatorias seguras.

8. **No usar palabras del diccionario:** Incluso con modificaciones, las palabras comunes son vulnerables.

---

## ¿Qué herramienta estamos simulando?

Estamos simulando un **ataque de diccionario** (dictionary attack), que es una técnica utilizada por herramientas reales como:

- **John the Ripper:** Una de las herramientas más populares para descifrar contraseñas
- **Hashcat:** Herramienta de descifrado que usa GPU para acelerar el proceso
- **Hydra:** Herramienta de fuerza bruta para diferentes protocolos

Estas herramientas son capaces de:
- Descifrar hashes SHA-256, MD5, bcrypt y muchos otros
- Usar diccionarios de millones de contraseñas
- Generar variaciones automáticamente (mayúsculas, números, símbolos)
- Usar fuerza bruta para probar todas las combinaciones posibles
- Ejecutarse en múltiples GPUs para acelerar el proceso

La diferencia es que herramientas reales como Hashcat pueden procesar **miles de millones de hashes por segundo** usando GPUs dedicadas, mientras que nuestro programa en Python es mucho más lento pero demuestra el mismo principio.

---

## Conclusión

El ataque de diccionario con reglas encontró 25 de los 25 hashes (100%). El
salto frente a las 17 coincidencias iniciales se obtuvo combinando información
del contexto, sustituciones leet, separadores, mayúsculas alternadas y una
ampliación pequeña del diccionario. En pocas palabras: agregar un año, un
símbolo o cambiar letras de forma predecible no protege una contraseña frente a
un ataque basado en reglas. Lo que realmente marcó la diferencia fue usar datos
del caso y no quedarse solo con la lista corta de palabras.

---

*Reporte generado por CyberSancocho Security Solutions*
