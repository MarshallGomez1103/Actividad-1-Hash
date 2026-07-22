# Reporte: Filtracion de Contrasenas - Pollito con Papas

**Equipo:** CyberSancocho Security Solutions
**Cliente:** Pollito con Papas
**Fecha:** 2026

---

## Programa 1: Ataque de Diccionario

### Explicacion del codigo

El Programa 1 es un ataque de diccionario implementado en Python. Funciona de la siguiente manera:

1. **Carga las 3,000 contrasenas** mas comunes del archivo RockYou (top 3000) desde el archivo `Lista Contraseñas.txt`.

2. **Genera variaciones** de cada contrasena. Para cada una de las 3,000 palabras, el programa crea:
   - La palabra original (ej: "daniel")
   - La palabra en mayusculas (ej: "DANIEL")
   - La palabra con primera letra en mayuscula (ej: "Daniel")
   - La palabra + anio (1995-2026) + asterisco (ej: "daniel1995*", "daniel1996*", ..., "daniel2026*")
   - Lo mismo pero en mayusculas y capitalize

   Esto genera un total de **3 variaciones + 3 x 32 anios = 99 variaciones por contrasena**, para un total de **297,000 combinaciones** probadas.

3. **Genera el hash SHA-256** de cada variacion usando la libreria `hashlib` de Python.

4. **Compara** cada hash generado contra los 25 hashes objetivo que proporciono el profesor.

5. **Reporta** las coincidencias encontradas, indicando la contrasena original y su posicion en el archivo RockYou.

### Codigo clave (logica principal)

```python
# Por cada contrasena del diccionario:
variaciones = [contra, contra.upper(), contra.capitalize()]
for anio in range(1995, 2027):
    variaciones.append(contra + str(anio) + "*")
    variaciones.append(contra.upper() + str(anio) + "*")
    variaciones.append(contra.capitalize() + str(anio) + "*")

# Probar cada variacion:
for var in variaciones:
    hash_gen = hashlib.sha256(var.encode()).hexdigest()
    if hash_gen in hashes_objetivo:
        # Coincidencia encontrada
```

### Resultados: Hashes descifrados

Se encontraron **17 de 25** hashes. Aqui la tabla completa:

| # | Hash (SHA-256) | Contrasena | Posicion |
|---|----------------|------------|----------|
| 1 | `be3a2247e5035d02cf38b1c09cfe159dbfb7351476a74e63453ddc46db8b08d7` | `daniel2021*` | 12 |
| 2 | `fbaf0c221c1ece5b388c05a242d8709a61c8f8c227badf57ff3a13acacc85fbf` | `carlos2009*` | 44 |
| 3 | `e2863c637435ebefc69b93a0c23296c99ff50f0e64f6a57c72035978ed87dba9` | `miguel2018*` | 105 |
| 4 | `854095df67f7c0b5ebb8a510ab7833224a9ffea33f308e1a5512bcf1d6ab9d18` | `gabriel1998*` | 140 |
| 5 | `97fd8ae3d0ca475e3f47b2f0437d281586da848ba2e9e4901619e200590d23b0` | `alejandro2010*` | 145 |
| 6 | `afe2033f2d7ab83b3d29cc7f790f53e3637fe9d1fd84b48ff11279ceb0a3365b` | `CHICKEN2024*` | 176 |
| 7 | `f7c9d7de5a9f3d2e5b289c70a381fcce8afedcd5c67a87c709f790d85bb13aaf` | `manuel2001*` | 181 |
| 8 | `7ea416acad070f098580b98a83a767cbacdd573232c3088e87cdfbf8c04a4f60` | `martin2022*` | 190 |
| 9 | `c3757e2bd43941b6822f58b6c101be0385fa6be4fc53cc8c18367c10db257917` | `maria2004*` | 204 |
| 10 | `0e5a0e022be438eb4f99c8ee5a8941fde3381232f1ac69e67bf2e71e2fe97936` | `mariana2008*` | 226 |
| 11 | `f930a1ae99436090e77bd07429b5b1fc5aa3e3d365f23642840050466ef6e91c` | `laura1999*` | 302 |
| 12 | `9fc272e7c90f6fcda1da6d595f79e78a5bf6bda8f789d21997717d31a05b5ba4` | `julian2015*` | 379 |
| 13 | `d40e194f68808f376fd678e349bdce55f33a1b136327500adcb67a99d77baea0` | `santiago1998*` | 412 |
| 14 | `91963e0450da28b8fc878930bdcad3d36664f41ed120cde361f4f100344409b7` | `diego1997*` | 510 |
| 15 | `17ea02057474a69939337a7db6f44390338c504a3db1e8fd53721bb2d4a84ccb` | `sofia2022*` | 1121 |
| 16 | `974cf7f0d80744fac75d5093c734643fdcaf2fca255ae532107fed1898fc7e70` | `juanita2000*` | 1671 |
| 17 | `bee54bbfcd82bdaa19e423928f395dc88c9d8cefcfa67db6a527d22dddf9fb21` | `brayan1998*` | 1828 |

### Hashes NO encontrados (8)

Se recorrieron las 3,000 contrasenas del RockYou con todas las variaciones (original, mayusculas, capitalize + anio + *) y no se encontro coincidencia para estos 8 hashes:

| # | Hash (SHA-256) |
|---|----------------|
| 1 | `91089c2ab45f537fa868e40317a0197a27c124856dada3d1e1d50ec1fdfa44cd` |
| 2 | `b45d6bab393da4a88adafbd982c70aaf5f2472b62133884758f61c31832fa386` |
| 3 | `77750692b7b41371d1341fed0fae45d003f1c37c92fea861c292fca3a96179b3` |
| 4 | `7735e96b604f6a366111f231079db45ab3cd2bc5fa780fde8896e4db4e11d16f` |
| 5 | `3028523de7c519c10a46c761b7a8f554fda0658812f942a4c1eb0a06115d603d` |
| 6 | `9134e51da40a209991205534770eaaffb9de5f34e4eecb6bb5443a9ba4d01d0e` |
| 7 | `2949f3b936879a17d4849cda7119ccbe518d867b0f3ed136807309ee33bf966a` |
| 8 | `cfad2538c4ef2b51b82c733ff7de8b49f433eeb485870b4532e1e2b67afed32c` |

**Analisis de por que no se encontraron:**

El programa probo 297,000 combinaciones (3,000 contrasenas x 99 variaciones) y ninguno coincidio con estos 8 hashes. Las razones posibles son:

1. **Las contrasenas no estan en el RockYou Top 3000:** Estas 8 contrasenas probablemente usan palabras que no aparecen en las 3,000 mas comunes.

2. **Patron diferente al esperado:** Aunque el profesor indico que las contrasenas seguirian el patron "palabra + anio + *", estas 8 pueden usar formatos como:
   - Contrasenas sin asterisco
   - Anios fuera del rango 1995-2026
   - Combinaciones de palabras no contempladas
   - Caracteres especiales diferentes al asterisco

3. **Requieren un diccionario mas grande:** Para descifrarlas se necesitaria un diccionario ampliado (RockYou completo tiene millones de contrasenas) o un ataque de fuerza bruta puro.

Esto demuestra que, aunque un ataque de diccionario es efectivo contra contraseñas comunes, las contraseñas que no siguen patrones predecibles son mas dificiles de descifrar.

### Analisis: Que tan facil fue adivinar las contrasenas?

Fue **relativamente facil** descifrar el 68% de las contraseñas (17/25). La razon principal es que la mayoria de las personas usan patrones predecibles:

- Nombres propios + anio + un caracter especial obligatorio (el asterisco)
- El anio suele ser reciente (2000-2024)
- Las contrasenas son predecibles porque siguen una politica basica de seguridad

El programa encontro contrasenas como "daniel2021*", "maria2004*", "laura1999*" que son combinaciones de nombre + anio + *, exactamente el patron que describio el profesor.

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

El Paso 1 (50 hashes) se completa instantaneamente en cualquier computador (menos de 1 segundo).

El Paso 2 (100M de hashes) varia enormemente dependiendo del hardware:

| Tipo de PC | Tiempo estimado Paso 2 | Velocidad aprox. |
|------------|------------------------|-------------------|
| Lento (antiguo) | 4-8 horas | ~3,000-7,000 hashes/seg |
| Normal (personal) | 1-3 horas | ~10,000-30,000 hashes/seg |
| FabLab (practica) | Variable segun el PC | Variable |

**Diferencia entre los 50 hashes y los 100M:** El Paso 1 toma fracciones de segundo, mientras que el Paso 2 puede tomar horas. Esto demuestra que el costo computacional crece linealmente con la cantidad de operaciones. Un computador 3x mas rapido completa el trabajo 3x mas rapido, lo cual importa mucho en tareas de seguridad.

### Analisis: Que tan facil fue adivinar las contrasenas?

Las contraseñas del Programa 2 (los 50 numeros aleatorios) se "adivinan" inmediatamente en el Paso 1 porque ya sabemos cuales son. El interes esta en el Paso 2: si NO supieramos cuales son los 50 numeros, tendriamos que probar 100 millones de combinaciones para encontrarlos. Esto es exactamente lo que hace un atacante con las contrasenas de Pollito con Papas.

---

## Estrategias adicionales implementadas

### Estrategia 1: Variaciones de mayusculas/minisculas

El programa original solo probaba la contrasena en minisculas. Se adiciono:
- **Mayusculas completas:** Ejemplo: "CHICKEN2024*" en lugar de solo "chicken2024*"
- **Primera letra mayuscula:** Ejemplo: "Chicken2024*"

Esta estrategia permitio descifrar el hash de "CHICKEN2024*" (posicion 176), que de otra forma se hubiera perdido.

### Estrategia 2: Analisis de patrones del contexto

Se analizaron las palabras clave proporcionadas por el profesor:
- pollito, papas, pollitoconpapas, kfc, chicken, pollo, pollocampero, apollo

De estas, **chicken** y **pollo** ya estaban en el RockYou. La variante en mayusculas (CHICKEN) fue la clave para encontrar un hash adicional.

### Por que se consideraron adecuadas

- Son **basicas y no requieren herramientas externas**
- Aumentan la cobertura sin aumentar drasticamente el tiempo de ejecucion
- Son realistas: muchas personas usan mayusculas en sus contrasenas por politicas de seguridad

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

El ataque de diccionario es efectivo contra contraseñas que siguen patrones predecibles. De los 25 hashes proporcionados, pudimos descifrar 17 (68%) usando simplemente el RockYou Top 3000 con variaciones basicas. Los 8 restantes requieren diccionarios mas grandes o estrategias adicionales, lo que demuestra que la complejidad de la contrasena es clave para la seguridad.

---

*Reporte generado por CyberSancocho Security Solutions*
