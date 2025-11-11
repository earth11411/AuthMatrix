# AuthMatrix (Community-Maintained Version)

---

### ⚠️ **Notice: This is a Community-Maintained Fork**

This is an actively maintained fork of the original **AuthMatrix** project by **SecurityInnovation** ([github.com/SecurityInnovation/AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix)).

The original project appears to be unmaintained (last commit in **2018**). This fork was created to continue its development, fix outstanding bugs, incorporate modern Burp Suite APIs, and add new features for the community.

All credit for the original concept and foundational code goes to SecurityInnovation.

---

## What is AuthMatrix?

AuthMatrix is a Burp Suite extension designed to help security testers identify authorization vulnerabilities. It provides a simple and intuitive way to test complex, matrix-based access control models in web applications and web services.

This extension allows testers to define a set of users, roles, and "chains" (requests) to verify that an application's authentication and authorization controls are working as intended.

## New Features in This Fork

This version includes all the original functionality of AuthMatrix, plus the following enhancements:

* ✅ **Added "Clear Auth & Re-import" Button**: A new UI button to easily clear all Cookie and Authorization headers from requests.
* 🐛 **Fixed Double Request Bug**: Corrected an issue where requests were being sent twice; now only a single request is sent.

### Feature Preview

Here is a look at the new "Clear Auth & Re-import" button:

<img width="1100" height="511" alt="Screenshot 2568-11-11 at 17 15 45" src="https://github.com/user-attachments/assets/cb55ee01-b1e1-433f-9592-0d4ef364064f" />

## Installation

### 1. BApp Store (Coming Soon)

We are working on submitting this updated version to the PortSwigger BApp Store. For now, please use the manual installation method below.

### 2. Manual Installation (Build from Source)

1.  Clone this repository:
    ```bash
    git clone https://github.com/earth11411/AuthMatrix.git
    ```
2.  Go to the **Extensions** tab in Burp Suite.
4.  Click **Add**.
5.  Select **"Python"** as the Extension type.
6.  Load the generated `AuthMatrix.py` file from the git directory.

## Usage

For detailed usage instructions, please refer to the **original project's Wiki**. The core concepts remain the same.

* **[Original Wiki Link](https://github.com/SecurityInnovation/AuthMatrix/wiki)**

*(Note: The original Wiki may not reflect the new features added in this fork.)*

## Contributing

Contributions are very welcome! If you find a bug, have a feature request, or want to improve the code, please:

1.  Fork this repository (the new one, not the original).
2.  Create a new branch for your feature or bugfix.
3.  Submit a Pull Request with a clear description of your changes.

## License

This project is licensed under the **Apache License 2.0**, in accordance with the original project.

This is a derivative work of the original AuthMatrix. The original `LICENSE` file and notices from the SecurityInnovation repository are preserved in this project as required.
