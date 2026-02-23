# AuthMatrix (Community-Maintained Version)

---

### ⚠️ **Notice: This is a Community-Maintained Fork**

This is an actively maintained fork of the original AuthMatrix project by SecurityInnovation. The original project appears to be unmaintained (last commit in 2018). This version is dedicated to fixing outstanding bugs, incorporating modern Burp Suite logic, and adding essential features for modern web security testing.

---

## What is AuthMatrix?

AuthMatrix is a Burp Suite extension designed to help security testers identify authorization vulnerabilities. It provides a simple and intuitive way to test complex, matrix-based access control models in web applications and web services.

This extension allows testers to define a set of users, roles, and "chains" (requests) to verify that an application's authentication and authorization controls are working as intended.


### Feature Preview

Here is a look at the new buttons:

<img width="968" height="491" alt="Screenshot 2569-02-02 at 02 34 12" src="https://github.com/user-attachments/assets/6bdbe060-c31c-4dc9-9ec0-720e7f51ff6b" />

## 🚀 Enhanced Features in This Fork

This version includes all the original functionality of AuthMatrix, plus the following enhancements:


**1. ✅ GUI Performance & Stability Fixes (Special Thanks to @Abyssraven0x13):**

**Fixed GUI Freeze & NullPointerException:** Corrected the getTableCellRendererComponent logic to verify the existence of the setSelected method before execution, preventing crashes in certain Burp Suite environments.

**Fixed Typos & Logic Errors:** Resolved a naming error where selfelfExtender was used instead of selfExtender, ensuring proper row selection and menu functionality.


**2. 🧹 Clear Auth & Re-import**: 
Easily clear all Cookie and Authorization headers from your requests with a single click.

**How to use:** Click the "Clear Auth & Re-import" button to reset session tokens before starting a new test matrix.

**3. ✂️ Remove Body Parameters**
Designed for cases where sensitive tokens or parameters are passed in the HTTP Body (supports x-www-form-urlencoded and JSON).

**How to use:** 1. Click "Remove Body Param". 2. Enter the name of the parameter you want to clear. 3. The extension will automatically set that parameter's value to empty for all requests.

**5. 🔄 Dynamic New Data (Body Injection)**
Perfect for testing Broken Access Control when servers require specific user tokens or IDs within the HTTP Body.

**How to use:**
1. Click "New Data" and enter the target parameter name.
2. A dialog will appear for each user; enter the specific value intended for that user.
3. During the scan, each user will send the request with their uniquely assigned parameter value in the body.


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


## Contributing

Contributions are very welcome! If you find a bug, have a feature request, or want to improve the code, please:

1.  Fork this repository (the new one, not the original).
2.  Create a new branch for your feature or bugfix.
3.  Submit a Pull Request with a clear description of your changes.

## License

This project is licensed under the **Apache License 2.0**, in accordance with the original project.

This is a derivative work of the original AuthMatrix. The original `LICENSE` file and notices from the SecurityInnovation repository are preserved in this project as required.
