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

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# In-memory data
if 'alerts_data' not in st.session_state:
    st.session_state.alerts_data = []
if 'vulns_data' not in st.session_state:
    st.session_state.vulns_data = []
if 'model_trained' not in st.session_state:
    st.session_state.model_trained = False
if 'model' not in st.session_state:
    st.session_state.model = None
if 'criterion' not in st.session_state:
    st.session_state.criterion = None

def log_alert(alert_type, message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.session_state.alerts_data.append({"timestamp": timestamp, "type": alert_type, "message": message})

def load_history():
    if not st.session_state.alerts_data:
        return pd.DataFrame({"timestamp": ["No alerts yet"], "type": ["—"], "message": ["—"]})
    return pd.DataFrame(st.session_state.alerts_data)

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

# Train autoencoder
def train_model():
    if st.session_state.model_trained:
        return "Model already trained!"

    try:
        normal_data = np.array([nv_spin_probability(magnetic_field=0.0) for _ in range(100)])
        normal_data = torch.tensor(normal_data, dtype=torch.float32).unsqueeze(1)
        
        model = Autoencoder()
        optimizer = optim.Adam(model.parameters(), lr=0.01)
        criterion = nn.MSELoss()
        
        for _ in range(300):
            optimizer.zero_grad()
            output = model(normal_data)
            loss = criterion(output, normal_data)
            loss.backward()
            optimizer.step()
        
        st.session_state.model = model
        st.session_state.criterion = criterion
        st.session_state.model_trained = True
        return "Model trained successfully! Ready for scans."
    except Exception as e:
        return f"Training failed: {str(e)} - using fallback mode"

# Endpoint test function
def full_endpoint_test(endpoints_input):
    # Create the list of endpoints from the input text area
    endpoints = [e.strip() for e in endpoints_input.split('\n') if e.strip()]
    
    if not endpoints:
        return pd.DataFrame({"Message": ["Enter at least one endpoint"]})

    if model is None or criterion is None:
        return pd.DataFrame({"Message": ["Train model first in 'Train Model' tab"]})

    results = []
    for endpoint in endpoints:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        nv_prob = nv_spin_probability(random.uniform(0, 1.5))
        input_tensor = torch.tensor([[nv_prob]], dtype=torch.float32)
        with torch.no_grad():
            recon_loss = criterion(model(input_tensor), input_tensor).item()
        sim_alert = "THREAT DETECTED" if recon_loss > 0.0005 or nv_prob > 0.6 else "Normal"
        
        results.append({
            "Timestamp": timestamp,
            "Endpoint": endpoint,
            "NV Prob": nv_prob,
            "Recon Loss": recon_loss,
            "Sim Alert": sim_alert
        })
        time.sleep(1)
    
    df = pd.DataFrame(results)
    return df

# Streamlit UI with tabs
st.set_page_config(page_title="Chola Sentinel CQNAAD", layout="wide")
st.title("Chola Sentinel CQNAAD")
st.markdown("Universal Quantum-Safe Security Dashboard")

tab1, tab2, tab3 = st.tabs(["Train Model", "Endpoint Scan Console", "Alert History"])

with tab1:
    st.subheader("Train AI Model (Run Once)")
    if st.button("Train Model"):
        status = train_model()
        st.write(status)

with tab2:
    st.subheader("Endpoint Scan Console")
    st.markdown("Enter endpoints (one per line) to test sim vs real classification")
    endpoints_input = st.text_area("Endpoints", value="https://www.google.com\nhttps://portal.azure.com\nhttps://aws.amazon.com", height=100)
    if st.button("Run Full Endpoint Test"):
        result_df = full_endpoint_test(endpoints_input)
        st.dataframe(result_df)

with tab3:
    st.subheader("Alert History")
    st.dataframe(load_history())
