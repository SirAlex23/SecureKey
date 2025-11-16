// --- 1. Constantes y Variables de Caracteres ---
const CHARACTERS = {
  lower: "abcdefghijklmnopqrstuvwxyz",
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789",
  symbols: "!@#$%^&*()_+=-[]{}\\|;:'\"<>,./?", // Keyspace N = 32
};

// Rangos de Entropía (Bits) para la clasificación de fortaleza (Coincide con securekey.py)
const STRENGTH_RANGES = {
  "Muy Débil": { max: 40, color: "#dc3545", width_max: 20 },
  Débil: { max: 60, color: "#ffc107", width_max: 45 },
  Moderada: { max: 80, color: "#28a745", width_max: 75 },
  Fuerte: { max: 128, color: "#0b69ff", width_max: 100 }, // Máx práctico 128 bits
};

// --- 2. Función de Generación de Contraseñas ---
function generatePassword(length = 16) {
  let charPool =
    CHARACTERS.lower +
    CHARACTERS.upper +
    CHARACTERS.digits +
    CHARACTERS.symbols;
  let password = "";

  // Asegurar que al menos un carácter de cada tipo esté presente para mayor seguridad
  const requiredChars = [];
  if (charPool.includes(CHARACTERS.lower[0]))
    requiredChars.push(CHARACTERS.lower);
  if (charPool.includes(CHARACTERS.upper[0]))
    requiredChars.push(CHARACTERS.upper);
  if (charPool.includes(CHARACTERS.digits[0]))
    requiredChars.push(CHARACTERS.digits);
  if (charPool.includes(CHARACTERS.symbols[0]))
    requiredChars.push(CHARACTERS.symbols);

  // 1. Añadir un carácter de cada tipo requerido
  for (const type of requiredChars) {
    if (password.length < length) {
      password += type[Math.floor(Math.random() * type.length)];
    }
  }

  // 2. Rellenar el resto de la contraseña
  const remainingLength = length - password.length;
  for (let i = 0; i < remainingLength; i++) {
    password += charPool[Math.floor(Math.random() * charPool.length)];
  }

  // 3. Mezclar la contraseña para evitar patrones
  password = password
    .split("")
    .sort(() => 0.5 - Math.random())
    .join("");

  return password;
}

// --- 3. Lógica de Validación (Simulación de Entropía) ---
function getPasswordStrength(password) {
  const L = password.length;
  let N = 0; // Keyspace size

  // 1. Determinar el Keyspace (N) según los tipos de caracteres presentes
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasDigits = /[0-9]/.test(password);
  const hasSymbols = /[!@#$%^&*()_+=\-~`[\]{}\\|;:'"<>,./?]/.test(password);

  if (hasLower) N += 26;
  if (hasUpper) N += 26;
  if (hasDigits) N += 10;
  if (hasSymbols) N += 32;

  let scoreBits = 0;
  if (N > 0) {
    // Fórmula de Entropía de Shannon: H = L * log2(N)
    scoreBits = L * Math.log2(N);
  }

  // 2. Determinar la Fortaleza, Color y Recomendación
  let strength = "Muy Débil";
  let color = STRENGTH_RANGES["Muy Débil"].color;
  let width = 0;
  let recommendation = "";

  for (const [key, range] of Object.entries(STRENGTH_RANGES)) {
    if (scoreBits <= range.max) {
      strength = key;
      color = range.color;
      // Calcular el porcentaje de la barra (escalado al máximo teórico)
      width = Math.min(100, (scoreBits / STRENGTH_RANGES["Fuerte"].max) * 100);
      break;
    }
  }

  // Ajustar recomendación basada en la fortaleza
  if (strength === "Muy Débil") {
    recommendation = `La contraseña es de solo ${scoreBits.toFixed(
      1
    )} bits. Debe tener al menos 12 caracteres y más tipos de símbolos.`;
  } else if (strength === "Débil") {
    recommendation = `Con ${scoreBits.toFixed(
      1
    )} bits, es débil. Aumenta la longitud a 14+ o añade más diversidad de caracteres.`;
  } else if (strength === "Moderada") {
    recommendation = `Una puntuación de ${scoreBits.toFixed(
      1
    )} bits es buena. ¡Considera aumentar a 16+ para ser Fuerte!`;
  } else if (strength === "Fuerte") {
    recommendation = `¡Excelente! Con ${scoreBits.toFixed(
      1
    )} bits, es una contraseña muy robusta.`;
  }

  return {
    strength,
    scoreBits: scoreBits.toFixed(1),
    color,
    width,
    recommendation,
  };
}

// --- 4. Funciones de Interfaz (DOM) ---

function validatePasswordDemo() {
  const input = document.getElementById("validate-input");
  const password = input.value;
  const output = getPasswordStrength(password);

  document.getElementById("strength-display").textContent = output.strength;
  document.getElementById(
    "entropy-display"
  ).textContent = `${output.scoreBits} bits`;
  document.getElementById("recommendation-display").textContent =
    output.recommendation;

  const scoreBar = document.getElementById("score-bar");
  scoreBar.style.width = `${output.width}%`;
  scoreBar.style.backgroundColor = output.color;
}

function handleGenerateClick() {
  const lengthInput = document.getElementById("length-input");
  const length = parseInt(lengthInput.value);

  if (isNaN(length) || length < 8 || length > 64) {
    alert("Por favor, introduce una longitud válida entre 8 y 64.");
    return;
  }

  const newPassword = generatePassword(length);
  document.getElementById("generated-password-output").textContent =
    newPassword;

  // Copiar la contraseña al campo de validación para una prueba inmediata
  const validateInput = document.getElementById("validate-input");
  validateInput.value = newPassword;

  // Ejecutar la validación automáticamente
  validatePasswordDemo();
}

// --- 5. Inicialización de Event Listeners ---
document.addEventListener("DOMContentLoaded", () => {
  // Listener para el botón Generar
  document
    .getElementById("generate-btn")
    .addEventListener("click", handleGenerateClick);

  // Listener para validación en tiempo real (al escribir)
  document
    .getElementById("validate-input")
    .addEventListener("input", validatePasswordDemo);

  // Inicializar la barra de validación
  validatePasswordDemo();
});
