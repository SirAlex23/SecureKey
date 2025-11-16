import string
import secrets
import argparse
import math

# --- Constantes para la generación de contraseñas ---
# Definimos los conjuntos de caracteres
CARACTERES = {
    'lower': string.ascii_lowercase,
    'upper': string.ascii_uppercase,
    'digits': string.digits,
    'symbols': string.punctuation,
}

# --- Función Principal de Generación ---
def generate_password(length=16, use_lower=True, use_upper=True, use_digits=True, use_symbols=True):
    """Genera una contraseña segura y aleatoria con la longitud y tipos de caracteres especificados."""
    
    char_pool = ""
    # Aseguramos que al menos un carácter de cada tipo seleccionado esté incluido
    password = []

    if use_lower:
        char_pool += CARACTERES['lower']
        password.append(secrets.choice(CARACTERES['lower']))

    if use_upper:
        char_pool += CARACTERES['upper']
        password.append(secrets.choice(CARACTERES['upper']))

    if use_digits:
        char_pool += CARACTERES['digits']
        password.append(secrets.choice(CARACTERES['digits']))

    if use_symbols:
        char_pool += CARACTERES['symbols']
        password.append(secrets.choice(CARACTERES['symbols']))

    # Si no se seleccionó ningún tipo de carácter, se usa un mínimo para no fallar
    if not char_pool:
        char_pool = string.ascii_letters + string.digits
        password.append(secrets.choice(char_pool))
    
    # Rellenar el resto de la contraseña con caracteres aleatorios del pool
    remaining_length = length - len(password)
    if remaining_length > 0:
        password.extend(secrets.choice(char_pool) for _ in range(remaining_length))

    # Mezclar la contraseña para asegurar la aleatoriedad de las posiciones
    secrets.SystemRandom().shuffle(password)
    
    return "".join(password)

# --- Función de Validación (Entropía de Shannon) ---
def validate_password(password):
    """
    Evalúa la fortaleza de una contraseña basándose en:
    1. Longitud
    2. Diversidad de caracteres (Keyspace)
    3. Entropía de Shannon (Bits de seguridad)
    """
    results = {
        'score_bits': 0,
        'length': len(password),
        'keyspace_size': 0,
        'requirements': {
            'min_length_ok': False,
            'has_lower': False,
            'has_upper': False,
            'has_digits': False,
            'has_symbols': False,
        },
        'strength': 'Muy Débil',
        'recommendation': 'La contraseña es demasiado corta o simple.',
        'color': '#dc3545' # Rojo por defecto
    }

    # 1. Comprobar requisitos y construir el keyspace (N)
    N = 0
    
    if len(password) >= 12: # Mínimo recomendado
        results['requirements']['min_length_ok'] = True
    
    # Comprobar tipos de caracteres y añadir al keyspace N
    # 'N' (Keyspace) es la suma de caracteres únicos disponibles (26 minúsculas, 26 mayúsculas, 10 dígitos, ~32 símbolos)
    if any(c in string.ascii_lowercase for c in password):
        results['requirements']['has_lower'] = True
        N += 26
    
    if any(c in string.ascii_uppercase for c in password):
        results['requirements']['has_upper'] = True
        N += 26
        
    if any(c in string.digits for c in password):
        results['requirements']['has_digits'] = True
        N += 10
        
    if any(c in string.punctuation for c in password):
        results['requirements']['has_symbols'] = True
        N += 32 

    results['keyspace_size'] = N
    
    # 2. Calcular la Entropía (H) en bits
    # Fórmula de Shannon: H = L * log2(N)
    if N > 0:
        H = results['length'] * math.log2(N)
        results['score_bits'] = round(H, 2)
    
    # 3. Determinar la Fuerza y Recomendación (Métricas de Seguridad)
    score = results['score_bits']
    
    if score < 40:
        results['strength'] = 'Muy Débil'
