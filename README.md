# 🛡️ EdgeMail Guard  
Lightweight SMTP Spam Detection Using Network Header Features 

**EdgeMail Guard** is a high-performance SMTP edge proxy designed to detect and block spam at the protocol level before the email body (payload) is even processed. By utilizing **Machine Learning (Random Forest)** and **Asynchronous I/O**, it provides a modern, low-latency security layer for mail servers.

-----

## 📑 Table of Contents

  - [🚀 Core Concept](https://www.google.com/search?q=%23-core-concept)
  - [✨ Key Features](https://www.google.com/search?q=%23-key-features)
  - [🧠 Technical Architecture](https://www.google.com/search?q=%23-technical-architecture)
  - [📊 Machine Learning Engine](https://www.google.com/search?q=%23-machine-learning-engine)
  - [🚦 How to Use](https://www.google.com/search?q=%23-how-to-use)
  - [💻 Requirements](https://www.google.com/search?q=%23-requirements)

-----

## 🚀 Core Concept

The "Zero-Payload" philosophy means the system analyzes **envelope metadata** and **SMTP headers** only. By identifying threats during the `DATA` phase handshake—before the massive data transfer of the email body—the system saves significant bandwidth and prevents malicious content from ever entering the internal network.

-----

## ✨ Key Features

  - **Asynchronous Proxy:** Built on `asyncio` to handle hundreds of concurrent SMTP connections without blocking.
  - **ML-Powered Inspection:** Uses a Random Forest Classifier to score the "spamminess" of an incoming connection in real-time.
  - **Modern Dashboard:** A high-tech Tkinter GUI with live packet inspection logs and real-time traffic metrics.
  - **Attack Simulator:** Built-in tools to simulate legitimate (Ham) or malicious (Spam) traffic to test system responsiveness.
  - **Low Latency:** Inference and decision-making typically occur in **\< 1ms**.

-----

## 🧠 Technical Architecture

### 1\. The Async SMTP Proxy

The system listens on port `2525`. It manages the SMTP state machine (`HELO`, `MAIL FROM`, `RCPT TO`, `DATA`). It uses non-blocking sockets to ensure the UI remains fluid while processing traffic.

### 2\. Feature Extraction

When a client sends the header block, the system extracts 5 key features:

  * **Hops:** Count of `Received:` headers.
  * **Header Length:** Total size of the header block.
  * **Message-ID:** Presence of a standard ID string.
  * **Suspicious Domain:** Detection of keywords like "spambot" or "temp" in the envelope.
  * **Recipient Count:** Number of targets in the `RCPT TO` command.

-----

## 📊 Machine Learning Engine

The system uses a `RandomForestClassifier` from `scikit-learn`.

| Feature | Description | Importance in Logic |
| :--- | :--- | :--- |
| **Hops** | Number of mail relays | High hop counts often indicate botnet routing. |
| **Has Message-ID** | Standard SMTP compliance | Spam bots often skip generating valid Message-IDs. |
| **Domain Reputation** | Keyword analysis | Instant blocking of known suspicious TLD patterns. |

-----

## 🚦 How to Use

### 1\. Initialize the System

Run the script and click **INITIALIZE PROXY**. The status indicator will turn **GREEN**, and the async loop will start monitoring port `2525`.

### 2\. Monitor Traffic

As traffic hits the proxy, the **Live Packet Inspection Log** will display:

  - Incoming connection IPs.
  - SMTP command handshakes.
  - **[\!] BLOCKED SPAM** or **[✓] ALLOWED HAM** status with exact latency timings.

### 3\. Run Simulations

Use the **Attack Simulator** buttons at the bottom:

  - **Test: LEGITIMATE Email:** Simulates a standard Gmail-to-University handshake.
  - **Test: SPAM Attack:** Simulates a multi-hop botnet attack with suspicious headers.

-----

## 💻 Requirements

  * **Python 3.8+**
  * `numpy`
  * `scikit-learn`
  * `tkinter` (Standard library)

### Quick Install

```bash
pip install numpy scikit-learn
```

-----

## 📂 Project Structure

  - `SpamDetector`: The Scikit-Learn ML wrapper.
  - `AsyncEdgeServer`: The `asyncio` server handling SMTP logic.
  - `ModernEdgeGuard`: The `tkinter` dashboard and UI event loop.
