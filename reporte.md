# Reporte: Filtracion de Contrasenas - Pollito con Papas

**Equipo:** CyberSancocho Security Solutions
**Cliente:** Pollito con Papas
**Fecha:** 2026

---

## Programa 1: Ataque de Diccionario

### Explicacion del codigo

El programa carga las 3.000 palabras del RockYou Top 3000 y conserva la
posicion original de cada una. Luego agrega las ocho palabras mencionadas en
el contexto del incidente y un diccionario pequeno de nombres frecuentes.
Esta ampliacion contiene palabras base, no contrasenas resueltas.

Para cada palabra genera cambios entre minusculas y mayusculas, agrega los
anios de 1995 a 2026 y el asterisco, calcula SHA-256 y compara el resultado con
un conjunto de 25 hashes. Para las palabras relacionadas con el incidente
tambien prueba mayusculas alternadas, sustituciones leet (`o` por `0`, `a` por
`@`, entre otras) y separadores antes del anio. Cada candidato se genera y se
comprueba durante la ejecucion; las contrasenas encontradas no estan escritas
directamente en el programa.

El resultado indica la palabra base, su posicion en RockYou cuando existe, el
origen de las palabras ampliadas y la estrategia que produjo la coincidencia.

### Resultados: Hashes descifrados

Se encontraron **24 de 25** hashes. Esta es la tabla completa:

| # | Hash (SHA-256) | Contrasena | Posicion |
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

### Hash no encontrado

La ejecucion deja una sola coincidencia pendiente y muestra el hash sin
atribuirle una causa que el programa no pueda demostrar:

`2949f3b936879a17d4849cda7119ccbe518d867b0f3ed136807309ee33bf966a`

### Analisis: Que tan facil fue adivinar las contrasenas?

Fue **relativamente facil** descifrar el 96% de las contrasenas (24/25). La razon principal es que la mayoria usa patrones predecibles:

- Nombres propios + anio + un caracter especial obligatorio (el asterisco)
- El anio suele ser reciente (2000-2024)
- Las contrasenas son predecibles porque siguen una politica basica de seguridad

El programa encontro combinaciones de nombre, anio y asterisco, pero tambien
variantes con mayusculas alternadas, separadores y sustituciones leet. Esto
demuestra que cambiar una letra por un numero no evita un ataque basado en
reglas.

---

## Programa 2: Analisis de Rendimiento

### Explicacion del codigo

El Programa 2 mide que tan rapido puede un computador generar y comparar hashes SHA-256 a gran escala. Funciona en dos pasos:

**Paso 1:** Toma 50 numeros aleatorios hardcodeados (entre 10,000,000 y 90,000,000), los convierte a texto y genera su hash SHA-256. Estos 50 hashes son nuestro "objetivo".

**Paso 2:** Genera el hash SHA-256 de **todos los numeros del 1 al 100,000,000** y compara cada uno contra los 50 objetivos. Este proceso es intencionalmente costoso porque:

- Cada numero se convierte a string (texto)
- Se calcula su hash SHA-256
- Se busca si ese hash esta en la lista de objetivos
- Se repite 100 millones de veces

El programa muestra barra de progreso cada 10,000,000 de numeros procesados, con estimacion del tiempo restante.

### Los 50 numeros aleatorios (hardcodeados)

Estos numeros se usaron en TODOS los computadores para que la comparacion sea justa:

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

Generados con `random.sample(range(10000000, 90000000), 50)` usando seed=42 para que sean reproducibles.

### Analisis de rendimiento

El Paso 1 (50 hashes) se completa en fracciones de segundo en cualquier computador, asi que para comparar equipos conviene mirar sobre todo el tiempo total del Programa 2. En este analisis se comparan cinco computadores: uno lento, tres personales (Thomas, Daniel y Julián) y uno de FabLab.

El Paso 2 (100M de hashes) varia segun el hardware y es el que marca la diferencia real entre computadores:

| Tipo de PC | Computador         | Paso 1        | Paso 2        | Tiempo total       | Velocidad aprox. |
|------------|--------------------|---------------|---------------|--------------------|------------------|
| Lento (antiguo) | Antiguo Thomas     | 0.70 s        | 69.46 s       | 80.31 s (1.34 min) | ~1.44 millones hashes/seg |
| Normal (personal) | Thomas             | 0.40 s        | 40.91 s       | 44.17 s (0.74 min) | ~2.26 millones hashes/seg |
| Normal (personal) | Daniel             | Por completar | Por completar | Por completar      | Por calcular con sus datos |
| Normal (personal) | Julián             | Por completar | Por completar | Por completar      | Por calcular con sus datos |
| FabLab (practica) | Equipo de practica | 0.63 s        | 73.12 s       | 78.89 s (1.31 min) | ~1.27 millones hashes/seg |

La velocidad aproximada se calcula con la siguiente formula:

**Velocidad aprox. = 100,000,000 / tiempo del Paso 2 en segundos**

En otras palabras, se divide la cantidad total de hashes procesados entre el tiempo real que tomo el Paso 2, porque ese es el tramo que concentra el trabajo intensivo del programa.

**Diferencia entre los 50 hashes y los 100M:** El Paso 1 toma menos de un segundo, mientras que el Paso 2 concentra casi todo el trabajo y puede pasar de segundos a horas segun el computador. Esto demuestra que el costo computacional crece linealmente con la cantidad de operaciones y que una mejora de hardware impacta directamente en el tiempo total de ejecucion.

### Analisis: Que tan facil fue adivinar las contrasenas?

Las contraseñas del Programa 2 (los 50 numeros aleatorios) se "adivinan" inmediatamente en el Paso 1 porque ya sabemos cuales son. El interes esta en el Paso 2: si NO supieramos cuales son los 50 numeros, tendriamos que probar 100 millones de combinaciones para encontrarlos. Esto es exactamente lo que hace un atacante con las contrasenas de Pollito con Papas.

---

## Estrategias adicionales implementadas

### Estrategia 1: Variaciones de mayusculas/minisculas

Se probaron minusculas, mayusculas, primera letra mayuscula y dos patrones de
mayusculas alternadas. Esto permitio encontrar, entre otras,
`CHICKEN2024*` y `ApOlLo2018*`.

### Estrategia 2: Analisis de patrones del contexto

Las palabras `pollito`, `papas`, `pollitoconpapas`, `kfc`, `chicken`,
`pollo`, `pollocampero` y `apollo` se agregaron como bases aun cuando no
aparecieran entre las 3.000 entradas. El programa conserva la posicion de las
que si aparecen y marca claramente las ampliaciones.

### Estrategia 3: Sustituciones leet y separadores

Para las palabras del contexto se probaron sustituciones frecuentes como `o`
por `0` y `a` por `@`, ademas de `#`, `@`, `_` y `-` antes del anio. Estas
reglas encontraron `P0llito2025*`, `pap@s2019*` y `Pollo#2022*`.

### Estrategia 4: Diccionario pequeno ampliado

Se agrego una lista acotada de nombres frecuentes que no estaban en el Top
3000. Asi se encontraron `juan1999*`, `tomas2020*` y `yuly2002*`. La lista
solo contiene nombres base; el anio y el asterisco los genera el programa.

### Por que se consideraron adecuadas

- Se derivan de la informacion entregada en el caso.
- Aumentan la cobertura sin convertir la prueba en fuerza bruta indiscriminada.
- Son reproducibles y cada coincidencia informa la regla que la genero.
- En la prueba automatizada, las reglas completas terminaron en menos de un segundo.

Ademas, se ampliaron porque el enunciado indica que no todas las contrasenas necesariamente estan en el Top 3000 de RockYou. Por eso, usar solo una lista corta habria dejado contrasenas sin descubrir; al agregar las palabras del contexto, variantes de mayusculas/minusculas, sustituciones leet y un diccionario pequeno de nombres frecuentes, se mejora la cobertura sin salir del enfoque de ataque de diccionario con reglas.

---

## Recomendaciones para crear contraseñas mas seguras

Basado en el analisis realizado, estas son las recomendaciones:

1. **Minimo 16 caracteres:** Las contrasenas de 8-10 caracteres se descifran rapidamente con diccionarios comunes.

2. **No usar nombres propios:** El 70% de las contrasenas descifradas contenian nombres (Daniel, Carlos, Miguel, Maria, etc.). Los atacantes priorizan los nombres en sus diccionarios.

3. **No usar el patron "nombre + anio + *":** Este es el patron mas comun que encontramos. Si su contrasena sigue este patron, es vulnerable.

4. **Mezclar caracteres de diferentes tipos:**
   - Minisculas (a-z)
   - Mayusculas (A-Z)
   - Numeros (0-9)
   - Caracteres especiales (!@#$%^&*)

5. **Usar contrasenas unicas por cuenta:** No reutilizar la misma contrasena en multiples sitios.

6. **Cambiar contraseñas periodicamente:** Cada 3-6 meses.

7. **Usar un gestor de contraseñas:** Genera y almacena contrasenas aleatorias seguras.

8. **No usar palabras del diccionario:** Incluso con modificaciones, las palabras comunes son vulnerables.

---

## Que herramienta estamos simulando?

Estamos simulando un **ataque de diccionario** (dictionary attack), que es una tecnica utilizada por herramientas reales como:

- **John the Ripper:** Una de las herramientas mas populares para descifrar contraseñas
- **Hashcat:** Herramienta de descifrado que usa GPU para acelerar el proceso
- **Hydra:** Herramienta de fuerza bruta para diferentes protocolos

Estas herramientas son capaces de:
- Descifrar hashes SHA-256, MD5, bcrypt, y muchos otros
- Usar diccionarios de millones de contraseñas
- Generar variaciones automaticamente (mayusculas, numeros, simbolos)
- Usar fuerza bruta para probar todas las combinaciones posibles
- Ejecutarse en multiples GPUs para acelerar el proceso

La diferencia es que herramientas reales como Hashcat pueden procesar **miles de millones de hashes por segundo** usando GPUs dedicadas, mientras que nuestro programa Python es mucho mas lento pero demuestra el mismo principio.

---

## Conclusion

El ataque de diccionario con reglas encontro 24 de los 25 hashes (96%). El
salto frente a las 17 coincidencias iniciales se obtuvo mediante informacion
del contexto, sustituciones leet, separadores, mayusculas alternadas y una
ampliacion pequena del diccionario. El resultado demuestra que agregar un anio,
un simbolo o sustituir letras de forma predecible no protege una contrasena
frente a un ataque basado en reglas.

---

*Reporte generado por CyberSancocho Security Solutions*
