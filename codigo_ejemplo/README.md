# Como correr el código de ejemplo
# Compilacion
  * Instalar compilador de golang 1.4 o superior
  * Compilar con el siguiente comando
     * go build -o qrsign
  * Se debe generar claves con el comando
     *  ./qrsign generar_claves
  * para generar cupon 
     *  ./qrsign generar_cupon
  * para probar cupon
     *  ./qrsign prueba_cupon "QR BASE64"

