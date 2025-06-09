# jwt# 🔐 Proyecto API REST con Spring Boot y JWT

Este proyecto es una API REST de autenticación construida con **Spring Boot**, **Spring Security**, y **JWT (JSON Web Tokens)**. Permite a los usuarios registrarse, iniciar sesión y obtener un token para autenticarse en llamadas protegidas.

---

## 🚀 Tecnologías utilizadas

- Java 21
- Spring Boot
- Spring Security
- JWT (JSON Web Token)
- Lombok
- MySQL
- Maven

---

## 📦 Endpoints disponibles

| Método | Endpoint         | Descripción                    | Requiere token |
|--------|------------------|--------------------------------|----------------|
| POST   | `/auth/register` | Registra un nuevo usuario      | ❌             |
| POST   | `/auth/login`    | Inicia sesión y devuelve el JWT| ❌             |
| GET    | `/api/hello`     | Endpoint protegido de ejemplo  | ✅             |

---

 🔧 Configuración del proyecto

1. Clonar el repositorio

git clone https://https://github.com/SantiagoLamot/jwt.java
cd jwt
2. Configurar la base de datos
Crear la base de datos con archivo que se encuentra en proyecto

Actualziar su properties segun las tenga configurada su gestor de datos

🧪 Tests con Postman
Este proyecto incluye una colección de Postman para probar el login, registro y uso de tokens JWT.

📁 Ruta
La colección está en la carpeta:
/postman/jwt-auth-tests.postman_collection.json

▶️ ¿Cómo usarla?
Abrí Postman

Importá la colección desde File > Import

Seleccioná el archivo .json

Ejecutá los endpoints: register, login, hello (requiere token en Authorization: Bearer <token>)

🔐 Detalles de seguridad
Contraseñas encriptadas con BCrypt

Autenticación basada en tokens JWT

Seguridad configurada con AuthenticationManager y DaoAuthenticationProvider

Roles definidos mediante un enum (Rol.java)

🗃 Estructura del proyecto (simplificada)
src/
├── main/
│   ├── java/com/example/jwt/
│   │   ├── controller/
│   │   ├── dto/
│   │   ├── model/
│   │   ├── repository/
│   │   ├── security/
│   │   └── service/
│   └── resources/
│       └── application.properties
├── test/
postman/
└── jwt-auth-tests.postman_collection.json
👨‍💻 Autor
Santiago Lamot
LinkedIn https://www.linkedin.com/in/santiago-lamot-/
Email: santiagolamot25@gmail.com

