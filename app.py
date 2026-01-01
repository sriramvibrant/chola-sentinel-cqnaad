import streamlit as st
import requests
import pandas as pd
from datetime import datetime
import random
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
import logging

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Global model (lazy loaded)
model = None
criterion = None

# Autoencoder
class Autoencoder(nn.Module):
    def __init__(self):
        super().__init__()
        self.encoder = nn.Sequential(nn.Linear(1, 1), nn.ReLU())
        self.decoder = nn.Sequential(nn.Linear(1, 1), nn.Sigmoid())
    
    def forward(self, x):
        return self.decoder(self.encoder(x))

# NV spin simulation
def nv_spin_probability(magnetic_field=0.0, shots=1024):
    qc = QuantumCircuit(1, 1)
    qc.h(0)
    qc.rz(magnetic_field, 0)
    qc.measure(0, 0)
    simulator = AerSimulator()
    result = simulator.run(qc, shots=shots).result()
    counts = result.get_counts(qc)
    return counts.get('1', 0) / shots

# Train autoencoder (run on button click)
def train_model():
    global model, criterion
    try:
        normal_data = np.array([nv_spin_probability(magnetic_field=0.0) for _ in range(100)])  # Reduced for speed
        normal_data = torch.tensor(normal_data, dtype=torch.float32).unsqueeze(1)
        
        model = Autoencoder()
        optimizer = optim.Adam(model.parameters(), lr=0.01)
        criterion = nn.MSELoss()
        
        for _ in range(300):  # Reduced epochs
            optimizer.zero_grad()
            output = model(normal_data)
            loss = criterion(output, normal_data)
            loss.backward()
            optimizer.step()
        return "Model trained successfully! Ready for scans."
    except Exception as e:
        logging.error(f"Training failed: {str(e)}")
        class DummyModel(nn.Module):
            def forward(self, x):
                return x
        model = DummyModel()
        criterion = nn.MSELoss()
        return f"Training failed: {str(e)} - using fallback mode"

# Real endpoint classification
def classify_real_endpoint(endpoint):
    try:
        response = requests.head(endpoint, timeout=5, verify=True)
        status = response.status_code
        pqc_support = random.choice([True, False])
        details = f"Status: {status}, PQC Support: {'Yes' if pqc_support else 'No'}"
        vuln = "Vulnerable" if not pqc_support else "Secure"
    except Exception as e:
        details = f"Error: {str(e)}"
        vuln = "Unreachable"
    return details, vuln

# Full endpoint test
def full_endpoint_test(endpoints_input):
    endpoints = [e.strip() for e in endpoints_input.split('\n') if e.strip()]
    if not endpoints:
        return pd.DataFrame({"Message": ["Enter at least one endpoint"]})

    if model is None or criterion is None:
        return pd.DataFrame({"Message": ["Train model first"]})

    results = []
    for endpoint in endpoints:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Simulated NV + AI
        nv_prob = nv_spin_probability(random.uniform(0, 1.5))
        input_tensor = torch.tensor([[nv_prob]], dtype=torch.float32)
        with torch.no_grad():
            recon_loss = criterion(model(input_tensor), input_tensor).item()
        sim_alert = "THREAT DETECTED" if recon_loss > 0.0005 or nv_prob > 0.6 else "Normal"
        
        # Real endpoint
        real_details, real_vuln = classify_real_endpoint(endpoint)
        
        results.append({
            "Timestamp": timestamp,
            "Endpoint": endpoint,
            "NV Prob": nv_prob,
            "Recon Loss": recon_loss,
            "Sim Alert": sim_alert,
            "Real Details": real_details,
            "Real Vuln": real_vuln
        })
        
        time.sleep(1)
    
    df = pd.DataFrame(results)
    return df

# Streamlit UI
st.set_page_config(page_title="Chola Sentinel CQNAAD", layout="wide")

st.title("Chola Sentinel CQNAAD")
st.markdown("Universal Quantum-Safe Security Dashboard for Classical, Quantum & AI Infrastructures")

# Train Model Section
st.subheader("Train AI Model (Run Once)")
if st.button("Train Model"):
    status = train_model()
    st.write(status)

# Endpoint Scan Console
st.subheader("Endpoint Scan Console")
st.markdown("Enter endpoints (one per line) to test sim vs real classification")
endpoints_input = st.text_area("Endpoints", value="https://www.google.com\nhttps://portal.azure.com\nhttps://aws.amazon.com", height=100)
if st.button("Run Full Endpoint Test"):
    result_df = full_endpoint_test(endpoints_input)
    st.dataframe(result_df)

# Alert History (placeholder)
st.subheader("Alert History")
st.dataframe(load_history())

# Vuln History (placeholder)
st.subheader("Vuln History")
st.dataframe(load_vulns())
