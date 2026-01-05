# Hard Challenge Solutions

> These solutions follow the **same concise, instructional style** as the medium challenge solutions: short context, clear exploitation steps, and direct outcome. Intended for instructor use or post-CTF release.

---

## 🛠️ Hard Challenge — Container Breakout (SSRF → Docker API)

### Description

The application contains a Server-Side Request Forgery (SSRF) vulnerability that allows the backend to make HTTP requests to internal services. One of these internal services is an exposed Docker Remote API.

By abusing this API, it is possible to create a new container with a bind mount to the host filesystem, resulting in a full container escape.

---

### Steps to Solve

1. Identify the SSRF endpoint that fetches user-supplied URLs.
2. Use the SSRF to probe internal services.
3. Discover that the Docker Remote API is reachable on port `2375`.
4. Create a new container through the Docker API.
5. Mount the host filesystem inside the new container.
6. Read the flag from the mounted host directory.

---

### Result

The attacker gains access to files on the host system and retrieves the host flag.

**Flag location:**

```
/root/host-flag.txt
```

---

### Why This Works

The Docker Remote API provides full administrative control over the container runtime. When combined with SSRF, it allows attackers to interact with Docker as if they were a local administrator.

---

## 🐍 Hard Challenge — Insecure Deserialization (Pickle RCE)

### Description

The application deserializes user-supplied data using Python’s `pickle` module. The `pickle` format allows execution of arbitrary code during deserialization, making it unsafe for untrusted input.

---

### Steps to Solve

1. Identify that the application uses `pickle.loads()` on user input.
2. Create a malicious Python object that executes a system command when deserialized.
3. Serialize the object using `pickle.dumps()`.
4. Encode the payload in Base64.
5. Send the payload to the vulnerable endpoint.
6. Observe command execution and retrieve the flag.

---

### Result

Arbitrary commands are executed on the server, revealing the flag.

**Flag location:**

```
/flag.txt
```

---

### Why This Works

`pickle` trusts the serialized data completely. During deserialization, Python executes instructions embedded in the object, allowing attackers to run arbitrary code.

---

## 🔐 Hard Challenge — JWT Algorithm Confusion

### Description

The application uses JSON Web Tokens (JWT) for authentication but does not enforce a single signing algorithm. This allows an attacker to change the algorithm from asymmetric (`RS256`) to symmetric (`HS256`).

When this happens, the public key can be reused as a signing secret.

---

### Steps to Solve

1. Request a valid JWT from the application.
2. Retrieve the public key used for token verification.
3. Modify the JWT header to use the `HS256` algorithm.
4. Re-sign the token using the public key as the secret.
5. Change the token payload to an administrative role.
6. Submit the forged token to the verification endpoint.

---

### Result

The forged token is accepted, granting administrative access and returning the flag.

**Flag location:**
Returned by the verification endpoint.

---

### Why This Works

The application fails to validate which cryptographic algorithm should be trusted. This breaks the trust model of JWTs and allows attackers to forge valid tokens.

