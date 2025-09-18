# CtOS-Compresser-and-encrypter

**CtOS-Compresser-and-encrypter** is a secure file archiving utility built with Java. It allows you to pack multiple files and directories into a single encrypted and compressed archive. The application features a stylish, Watch Dogs 2 "DedSec" inspired graphical user interface (GUI) and also supports command-line (CLI) operations for automation and scripting.


<img width="1919" height="1078" alt="image" src="https://github.com/user-attachments/assets/6f12e8c3-fbda-4f1a-b653-20e278597c25" />


---

## ✨ Features

* **Secure Encryption:** Uses **AES-256-GCM** with a key derived from your password using **PBKDF2**, ensuring your data is protected against tampering and unauthorized access.
* **Efficient Compression:** Leverages the `Deflater` library to compress files, with adjustable levels: **Normal, Maximum, and Fastest**.
* **Dual Mode Operation:**
    * **GUI:** An intuitive and themed user interface built with Java Swing for easy operation.
    * **CLI:** Fully functional command-line scripts (`Packer.java`, `Unpacker.java`) for advanced users.
* **Content Preview:** Ability to list the contents of a packed archive without fully extracting it.
* **User-Friendly GUI:** Features include drag-and-drop support, password strength meter, and a real-time activity log.

---

## 💻 Requirements

To build and run this project, you will need:

* **Java Development Kit (JDK) 11** or newer.
* **Apache Maven** to compile the project and handle dependencies.

---

## 🛠️ How to Run

### 1. Build the Project

First, clone the repository and use Maven to build the project. This will create a single executable JAR file in the `target/` directory.

```bash
# Clone the repository
git clone <your-repository-url>
cd PackerPro

# Build the project using Maven
mvn clean package
