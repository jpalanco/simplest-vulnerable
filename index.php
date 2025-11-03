<?php
// Conexin a la base de datos (modifica con tus propios parmetros de conexin)
$servername = "localhost";
$username = "tu_usuario";
$password = "tu_contrasea";
$dbname = "tu_base_de_datos";

// Crear conexin
$conn = new mysqli($servername, $username, $password, $dbname);

// Verificar conexin
if ($conn->connect_error) {
    die("Conexin fallida: " . $conn->connect_error);
}

// Mitigacin: Uso de prepared statements para evitar SQL Injection
if (isset($_GET['id'])) {
    // Validar que 'id' sea un entero
    $id_raw = $_GET['id'];
    $id = filter_var($id_raw, FILTER_VALIDATE_INT);
    if ($id === false) {
        // Entrada no vlida
        echo "ID invlido";
    } else {
        // Preparar la consulta con un marcador de posicin
        $stmt = $conn->prepare("SELECT id, nombre FROM usuarios WHERE id = ?");
        if ($stmt) {
            $stmt->bind_param("i", $id);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result && $result->num_rows > 0) {
                while ($row = $result->fetch_assoc()) {
                    // Escapar contenido antes de imprimir para mitigar XSS
                    $safe_nombre = htmlspecialchars($row["nombre"], ENT_QUOTES, 'UTF-8');
                    echo "id: " . $row["id"] . " - Nombre: " . $safe_nombre . "<br>";
                }
            } else {
                echo "0 resultados";
            }

            $stmt->close();
        } else {
            // Registro en el log para depuracin y respuesta genrica al usuario
            error_log("Prepare failed: " . $conn->error);
            echo "Error en la consulta";
        }
    }
}

// Mitigacin de XSS: escapar siempre la salida
if (isset($_GET['mensaje'])) {
    $mensaje = $_GET['mensaje'];
    echo "<div>" . htmlspecialchars($mensaje, ENT_QUOTES, 'UTF-8') . "</div>";
}

// Cerrar conexin
$conn->close();
?>
