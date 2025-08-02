# DDoS Attack Detection and Mitigation in SDN

## Overview

This project demonstrates the detection and mitigation of Distributed Denial of Service (DDoS) attacks in a Software Defined Network (SDN) environment using Mininet for network emulation, Ryu as the SDN controller, and a machine learning-based approach (Random Forest) for attack detection.

---

## Table of Contents

- [Features](#features)
- [Project Structure](#project-structure)
- [Installation & Setup](#installation--setup)
- [Usage](#usage)
- [Workflow](#workflow)
- [Key Files & Directories](#key-files--directories)
- [Traffic Generation](#traffic-generation)
- [Machine Learning Model](#machine-learning-model)
- [Results](#results)
- [References](#references)

---

## Features

- Emulates a multi-switch, multi-host SDN topology using Mininet.
- Collects flow statistics from the network for both benign and DDoS traffic.
- Trains a Random Forest classifier to distinguish between legitimate and attack traffic.
- Detects DDoS attacks in real-time and triggers mitigation actions.
- Provides scripts for generating both benign and DDoS traffic.

---

## Project Structure

```
DDoS-attack-Detection-and-mitigation-in-SDN/
│
├── Codes/
│   ├── controller/         # Ryu controller apps for data collection and mitigation
│   ├── mininet/            # Mininet topology and traffic generation scripts
│   └── ml/                 # Machine learning scripts
│
├── FlowStatsfile.csv       # Collected flow statistics (for training)
├── PredictFlowStatsfile.csv# Flow stats for prediction
├── train.csv               # Training data (if any)
├── requirements.txt        # Python dependencies
├── output.log              # Output logs
├── Installation_setup/
│   └── Readme.md           # Setup instructions
└── ryu-env/                # Python virtual environment for Ryu
```

---

## Installation & Setup

### Prerequisites

- [VirtualBox](https://www.virtualbox.org/wiki/Downloads) or VMware Workstation
- [Mininet](https://github.com/mininet/mininet/releases/)
- [Ubuntu](https://ubuntu.com/download/desktop) (recommended inside a VM)
- [Ryu SDN Controller](https://ryu.readthedocs.io/en/latest/getting_started.html)
- Python 3.6+ and pip

### Steps

1. **Clone the Repository**
   ```bash
   git clone https://github.com/chiragbiradar/DDoS-Attack-Detection-and-Mitigation-using-Machine-Learning.git
   ```

2. **Set Up Python Environment**
   - (Optional) Use the provided `ryu-env` or create a new virtual environment:
     ```bash
     python3 -m venv ryu-env
     source ryu-env/bin/activate
     pip install -r requirements.txt
     ```

3. **Install Mininet and Ryu**
   - Follow the official guides for [Mininet](http://mininet.org/download/) and [Ryu](https://ryu.readthedocs.io/en/latest/getting_started.html).

---

## Usage

### 1. Start the Ryu Controller

```bash
cd Codes/controller
ryu-manager collect_ddos_trafic.py
# or for detection/mitigation:
ryu-manager mitigation_module.py
```

### 2. Start Mininet with Custom Topology

```bash
cd Codes/mininet
sudo python topology.py
```

### 3. Generate Traffic

- **Benign Traffic:**
  ```bash
  sudo python generate_benign_trafic.py
  ```
- **DDoS Traffic:**
  ```bash
  sudo python generate_ddos_trafic.py
  ```

### 4. Train the Machine Learning Model

```bash
cd Codes/ml
python RF.py
```

---

## Workflow

1. **Network Emulation:** Mininet creates a multi-switch, multi-host topology.
2. **Traffic Generation:** Scripts generate both normal and DDoS traffic.
3. **Data Collection:** Ryu controller collects flow stats and saves to CSV.
4. **Model Training:** Random Forest classifier is trained on the collected data.
5. **Detection & Mitigation:** The controller uses the trained model to detect attacks and mitigate them in real-time.

---

## Key Files & Directories

- `Codes/controller/collect_ddos_trafic.py`: Collects flow stats for training.
- `Codes/controller/mitigation_module.py`: Detects and mitigates DDoS attacks.
- `Codes/mininet/topology.py`: Defines the network topology.
- `Codes/mininet/generate_benign_trafic.py`: Simulates normal traffic.
- `Codes/mininet/generate_ddos_trafic.py`: Simulates DDoS attacks.
- `Codes/ml/RF.py`: Trains and evaluates the Random Forest model.

---

## Traffic Generation

You can also use `hping3` for manual DDoS traffic generation:

```bash
# ICMP flood
hping3 -1 -V -d 120 -w 64 -p 80 --rand-source --flood

# SYN flood
hping3 -S -V -d 120 -w 64 -p 80 --rand-source --flood

# UDP flood
hping3 -2 -V -d 120 -w 64 -p 80 --rand-source --flood
```

---

## Machine Learning Model

- The model uses flow statistics (packet count, byte count, protocol, etc.) to classify traffic.
- Trained using Random Forest (see `Codes/ml/RF.py`).
- Outputs accuracy and confusion matrix for evaluation.

---

## Results

- Confusion matrix and accuracy metrics are saved/printed after training.
- Detected attacks are logged by the controller, and mitigation actions are triggered automatically.

---

## References

- [Mininet](http://mininet.org/)
- [Ryu SDN Framework](https://osrg.github.io/ryu/)
- [scikit-learn](https://scikit-learn.org/)
- [Project Inspiration](https://github.com/chiragbiradar/DDoS-Attack-Detection-and-Mitigation-using-Machine-Learning)

---

Feel free to adapt this README for your needs!
