# 📄 Cheat Sheet (No Solutions)

---

## 🔹 General Rules

* All challenges run via **Docker Compose**
* Flag format: `KDG{...}`
* Do not attack outside provided containers
* Tools allowed: Browser DevTools, curl, Burp, Python

---

## 🧩 Beginner / Medium Hints

### Static Secrets

* Inspect HTML, JS, and comments

### SQL Injection

* Test authentication logic

### Command Injection

* Try chaining commands

### XXE

* Look for XML input parsing

### SSRF

* Test internal IPs and service names

---

## 🔥 Hard Challenges (Hints Only)

### Container Breakout

* Can the server reach internal services?
* Are any admin APIs exposed?

### Pickle Deserialization

* Does the server trust serialized objects?
* What happens during deserialization?

### JWT Confusion

* Are multiple algorithms accepted?
* How is trust established?

---

## 🧠 CTF Mindset

* Enumerate first
* Trust nothing
* Exploit logic, not just input

---

