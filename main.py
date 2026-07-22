# =============================================================
# CyberSancocho Security Solutions
# Actividad: Filtracion de contrasenas - Pollito con Papas
# Programa: Ataque de diccionario + Analisis de rendimiento
# =============================================================

import hashlib
import time

# =============================================================
# HASHES SHA-256 que nos paso el ===============================
HASHES_OBJETIVO = [
    "91089c2ab45f537fa868e40317a0197a27c124856dada3d1e1d50ec1fdfa44cd",
    "b45d6bab393da4a88adafbd982c70aaf5f2472b62133884758f61c31832fa386",
    "77750692b7b41371d1341fed0fae45d003f1c37c92fea861c292fca3a96179b3",
    "afe2033f2d7ab83b3d29cc7f790f53e3637fe9d1fd84b48ff11279ceb0a3365b",
    "7735e96b604f6a366111f231079db45ab3cd2bc5fa780fde8896e4db4e11d16f",
    "9fc272e7c90f6fcda1da6d595f79e78a5bf6bda8f789d21997717d31a05b5ba4",
    "c3757e2bd43941b6822f58b6c101be0385fa6be4fc53cc8c18367c10db257917",
    "3028523de7c519c10a46c761b7a8f554fda0658812f942a4c1eb0a06115d603d",
    "d40e194f68808f376fd678e349bdce55f33a1b136327500adcb67a99d77baea0",
    "9134e51da40a209991205534770eaaffb9de5f34e4eecb6bb5443a9ba4d01d0e",
    "f7c9d7de5a9f3d2e5b289c70a381fcce8afedcd5c67a87c709f790d85bb13aaf",
    "e2863c637435ebefc69b93a0c23296c99ff50f0e64f6a57c72035978ed87dba9",
    "854095df67f7c0b5ebb8a510ab7833224a9ffea33f308e1a5512bcf1d6ab9d18",
    "0e5a0e022be438eb4f99c8ee5a8941fde3381232f1ac69e67bf2e71e2fe97936",
    "91963e0450da28b8fc878930bdcad3d36664f41ed120cde361f4f100344409b7",
    "2949f3b936879a17d4849cda7119ccbe518d867b0f3ed136807309ee33bf966a",
    "17ea02057474a69939337a7db6f44390338c504a3db1e8fd53721bb2d4a84ccb",
    "be3a2247e5035d02cf38b1c09cfe159dbfb7351476a74e63453ddc46db8b08d7",
    "f930a1ae99436090e77bd07429b5b1fc5aa3e3d365f23642840050466ef6e91c",
    "97fd8ae3d0ca475e3f47b2f0437d281586da848ba2e9e4901619e200590d23b0",
    "974cf7f0d80744fac75d5093c734643fdcaf2fca255ae532107fed1898fc7e70",
    "7ea416acad070f098580b98a83a767cbacdd573232c3088e87cdfbf8c04a4f60",
    "bee54bbfcd82bdaa19e423928f395dc88c9d8cefcfa67db6a527d22dddf9fb21",
    "cfad2538c4ef2b51b82c733ff7de8b49f433eeb485870b4532e1e2b67afed32c",
    "fbaf0c221c1ece5b388c05a242d8709a61c8f8c227badf57ff3a13acacc85fbf",
]

# =============================================================
# 50 NUMEROS ALEATORIOS (hardcodeados, iguales en todos los PCs)
# Generados con random.sample(rango, 50), seed=42
# Rango: entre 10,000,000 y 90,000,000
# =============================================================
NUMEROS_ALEATORIOS = [
    10872248, 13356886, 13561597, 13999315, 14265799,
    15831819, 20576383, 21668732, 22448136, 22575562,
    22981052, 23718431, 23756669, 24942603, 26753883,
    28728463, 30868105, 31429110, 36687537, 38898923,
    39345092, 39587039, 39958838, 41227216, 42868828,
    45503389, 46913810, 47295260, 47338124, 49349722,
    55176955, 55667651, 56164955, 58181396, 58537831,
    60806024, 60992979, 66306997, 66629388, 66722344,
    70291817, 71662963, 77827638, 81971316, 83140807,
    83197857, 84093639, 85329037, 89089901, 89254563,
]


# =============================================================
# FUNCIONES BASICAS
# =============================================================

def hashear(texto):
    """Genera el hash SHA-256 de un texto y lo devuelve en hex"""
    return hashlib.sha256(texto.encode()).hexdigest()


def cargar_contrasenas():
    """Carga la lista de 3000 contrasenas desde el archivo"""
    with open("Lista Contraseñas.txt", "r") as f:
        codigo = f.read()
    locales = {}
    exec(codigo, {}, locales)
    return locales["passwords"]


def preguntar_equipo():
    """Pregunta al usuario que tipo de computador esta usando"""
    print()
    print("========================================")
    print("  Que tipo de computador estas usando?")
    print("========================================")
    print("  1. Lento    (computador antiguo)")
    print("  2. Normal   (computador personal)")
    print("  3. FabLab   (sala de practica)")
    print("========================================")
    while True:
        opcion = input("  Selecciona (1/2/3): ")
        if opcion == "1":
            return "Lento"
        elif opcion == "2":
            return "Normal"
        elif opcion == "3":
            return "FabLab"
        print("  Opcion no valida, intenta de nuevo")


def spinner(mensaje, segundos=2):
    """Muestra un spinner basico en la terminal"""
    caracteres = ["|", "/", "-", "\\"]
    for i in range(segundos * 4):
        print(f"\r  {mensaje} {caracteres[i % len(caracteres)]}", end="", flush=True)
        time.sleep(0.25)
    print(f"\r  {mensaje} listo!      ")


# =============================================================
# PROGRAMA 1: ATAQUE DE DICCIONARIO
# =============================================================

def programa_1():
    print()
    print("=" * 50)
    print("  PROGRAMA 1: ATAQUE DE DICCIONARIO")
    print("=" * 50)

    equipo = preguntar_equipo()
    print(f"\n  Equipo seleccionado: {equipo}")
    print(f"  Hashes a buscar: {len(HASHES_OBJETIVO)}")
    print()

    # Cargar contrasenas del archivo
    print("  Cargando contrasenas del archivo...")
    contrasenas = cargar_contrasenas()
    print(f"  Se cargaron {len(contrasenas)} contrasenas")
    print()

    tiempo_inicio = time.time()

    encontrados = {}
    total_variaciones = 0

    # Recorrer cada contrasena del diccionario
    for i, contra in enumerate(contrasenas):

        # Variaciones: original, mayusculas, capitalize + anio + "*"
        variaciones = [contra, contra.upper(), contra.capitalize()]
        for anio in range(1995, 2027):
            variaciones.append(contra + str(anio) + "*")
            variaciones.append(contra.upper() + str(anio) + "*")
            variaciones.append(contra.capitalize() + str(anio) + "*")

        # Probar cada variacion
        for var in variaciones:
            hash_gen = hashear(var)
            total_variaciones += 1

            if hash_gen in HASHES_OBJETIVO and hash_gen not in encontrados:
                posicion = i + 1
                encontrados[hash_gen] = (var, posicion)
                print(f"  [+] ENCONTRADO! Posicion {posicion}: \"{var}\"")

        # Progreso cada 500 contrasenas
        if (i + 1) % 500 == 0:
            porcentaje = ((i + 1) / len(contrasenas)) * 100
            print(f"  ... van {i + 1}/{len(contrasenas)} ({porcentaje:.0f}%) | "
                  f"encontrados: {len(encontrados)}/{len(HASHES_OBJETIVO)}")

    tiempo_fin = time.time()
    tiempo_total = tiempo_fin - tiempo_inicio

    # RESULTADOS
    print()
    print("=" * 50)
    print("  RESULTADOS PROGRAMA 1")
    print("=" * 50)
    print(f"  Equipo: {equipo}")
    print(f"  Contrasenas en el diccionario: {len(contrasenas)}")
    print(f"  Variaciones probadas: {total_variaciones:,}")
    print(f"  Hashes encontrados: {len(encontrados)}/{len(HASHES_OBJETIVO)}")
    print(f"  Tiempo total: {tiempo_total:.2f} segundos")
    print()

    if encontrados:
        print("  Hashes descifrados:")
        print("  " + "-" * 70)
        for h, (contra, pos) in encontrados.items():
            print(f"  Hash: {h}")
            print(f"  Contrasena: \"{contra}\"")
            print(f"  Posicion en el archivo: {pos}")
            print("  " + "-" * 70)

    no_encontrados = [h for h in HASHES_OBJETIVO if h not in encontrados]
    if no_encontrados:
        print(f"\n  Hashes NO encontrados ({len(no_encontrados)}):")
        print("  Se recorrieron las 3,000 contrasenas del RockYou con todas")
        print("  las variaciones (original, mayusculas, capitalize + anio + *)")
        print("  y no se encontro coincidencia. Estas contrasenas probablemente")
        print("  no siguen el patron basico o usan palabras fuera del")
        print("  diccionario RockYou Top 3000.")
        print()
        for h in no_encontrados:
            print(f"    {h}")

    print()
    return encontrados, tiempo_total, equipo


# =============================================================
# PROGRAMA 2: ANALISIS DE RENDIMIENTO
# =============================================================

def programa_2():
    print()
    print("=" * 50)
    print("  PROGRAMA 2: ANALISIS DE RENDIMIENTO")
    print("=" * 50)

    equipo = preguntar_equipo()
    print(f"\n  Equipo seleccionado: {equipo}")
    print()

    tiempo_inicio = time.time()

    # PASO 1: Hashear los 50 numeros aleatorios
    print("  PASO 1: Generando hashes de 50 numeros aleatorios")
    print("  " + "-" * 46)

    hashes_objetivo = {}
    for i, num in enumerate(NUMEROS_ALEATORIOS):
        hash_num = hashear(str(num))
        hashes_objetivo[hash_num] = num
        print(f"  [{i + 1:2d}/50] {num:>10d} -> {hash_num}")

    tiempo_paso1 = time.time() - tiempo_inicio
    print(f"\n  Paso 1 completado en {tiempo_paso1:.4f} segundos")
    print()

    # PASO 2: Proceso intensivo (1 a 100,000,000)
    print("  PASO 2: Proceso intensivo (1 a 100,000,000)")
    print("  Esto puede tardar MUCHO tiempo. Ten paciencia.")
    print("  " + "-" * 46)

    tiempo_paso2_inicio = time.time()
    encontrados = []
    total = 100_000_000

    for i in range(1, total + 1):
        hash_i = hashear(str(i))

        if hash_i in hashes_objetivo:
            num_original = hashes_objetivo[hash_i]
            encontrados.append((i, num_original))
            print(f"  [+] ENCONTRADO! {i} coincide con {num_original}")

        # Barra de progreso cada 10,000,000
        if i % 10_000_000 == 0:
            porcentaje = (i / total) * 100
            elapsed = time.time() - tiempo_paso2_inicio
            if i > 10_000_000:
                velocidad = i / elapsed
                restante = (total - i) / velocidad
                horas = restante / 3600
                print(f"  ... {i:>12,}/{total:,} ({porcentaje:.0f}%) "
                      f"| {elapsed:.1f}s transcurridos "
                      f"| ~{horas:.1f}h restantes")
            else:
                print(f"  ... {i:>12,}/{total:,} ({porcentaje:.0f}%) "
                      f"| {elapsed:.1f}s transcurridos")

    tiempo_paso2 = time.time() - tiempo_paso2_inicio
    tiempo_total = time.time() - tiempo_inicio

    # RESULTADOS
    print()
    print("=" * 50)
    print("  RESULTADOS PROGRAMA 2")
    print("=" * 50)
    print(f"  Equipo: {equipo}")
    print(f"  Numeros aleatorios: {len(NUMEROS_ALEATORIOS)}")
    print(f"  Numeros totales procesados: {total:,}")
    print(f"  Hashes encontrados en la barrida: {len(encontrados)}")
    print(f"  Tiempo Paso 1 (50 hashes): {tiempo_paso1:.4f} segundos")
    print(f"  Tiempo Paso 2 (100M hashes): {tiempo_paso2:.2f} segundos "
          f"({tiempo_paso2 / 60:.2f} min)")
    print(f"  Tiempo total: {tiempo_total:.2f} segundos "
          f"({tiempo_total / 60:.2f} min)")
    print()

    if encontrados:
        print("  Coincidencias encontradas:")
        for num_barrido, num_objetivo in encontrados:
            print(f"    {num_barrido} -> objetivo {num_objetivo}")

    print()
    return tiempo_paso1, tiempo_paso2, tiempo_total, equipo


# =============================================================
# MENU PRINCIPAL
# =============================================================

def main():
    print()
    print("############################################")
    print("#  CyberSancocho Security Solutions         #")
    print("#  Actividad: Filtracion de contrasenas     #")
    print("#  Cliente: Pollito con Papas               #")
    print("############################################")
    print()
    print("  Que programa quieres ejecutar?")
    print("  1. Programa 1 - Ataque de diccionario")
    print("  2. Programa 2 - Analisis de rendimiento")
    print("  3. Ejecutar ambos")
    print()

    while True:
        opcion = input("  Selecciona (1/2/3): ")
        if opcion in ("1", "2", "3"):
            break
        print("  Opcion no valida, intenta de nuevo")

    tiempo_global_inicio = time.time()

    if opcion == "1":
        programa_1()
    elif opcion == "2":
        programa_2()
    else:
        programa_1()
        programa_2()

    tiempo_global = time.time() - tiempo_global_inicio
    print("=" * 50)
    print("  RESUMEN FINAL")
    print("=" * 50)
    print(f"  Tiempo total de ejecucion: {tiempo_global:.2f} segundos")
    print(f"  ({tiempo_global / 60:.2f} minutos)")
    print()
    print("  CyberSancocho Security Solutions")
    print("  Reporte generado exitosamente")
    print()


if __name__ == "__main__":
    main()
