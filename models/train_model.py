"""
AI-Powered DDoS Detection Model Training
Trains Random Forest and Isolation Forest models on synthetic traffic data
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler
import joblib
import os
import json
from datetime import datetime

# Create directories
os.makedirs('saved_models', exist_ok=True)
os.makedirs('../data/processed', exist_ok=True)

def generate_synthetic_data(n_samples=50000):
    """
    Generate synthetic network traffic data
    Returns DataFrame with features and labels
    """
    print("[*] Generating synthetic traffic data...")
    
    # Normal traffic features (70% of data)
    n_normal = int(n_samples * 0.7)
    normal_data = {
        'packets_per_sec': np.random.normal(100, 20, n_normal),
        'bytes_per_sec': np.random.normal(50000, 10000, n_normal),
        'unique_src_ips': np.random.randint(1, 10, n_normal),
        'unique_dst_ports': np.random.randint(1, 5, n_normal),
        'avg_packet_size': np.random.normal(500, 100, n_normal),
        'packet_size_variance': np.random.normal(100, 30, n_normal),
        'flow_duration': np.random.normal(5, 2, n_normal),
        'syn_count': np.random.randint(0, 10, n_normal),
        'rst_count': np.random.randint(0, 5, n_normal),
        'ack_count': np.random.randint(0, 100, n_normal),
        'connection_rate': np.random.normal(10, 3, n_normal),
        'src_ip_entropy': np.random.uniform(2, 4, n_normal),
        'label': np.zeros(n_normal)  # 0 = Normal
    }
    
    # HTTP Flood Attack (15% of data)
    n_http_flood = int(n_samples * 0.15)
    http_flood = {
        'packets_per_sec': np.random.normal(10000, 2000, n_http_flood),
        'bytes_per_sec': np.random.normal(5000000, 1000000, n_http_flood),
        'unique_src_ips': np.random.randint(100, 1000, n_http_flood),
        'unique_dst_ports': np.random.randint(1, 3, n_http_flood),
        'avg_packet_size': np.random.normal(300, 50, n_http_flood),
        'packet_size_variance': np.random.normal(50, 20, n_http_flood),
        'flow_duration': np.random.normal(1, 0.5, n_http_flood),
        'syn_count': np.random.randint(1000, 10000, n_http_flood),
        'rst_count': np.random.randint(0, 100, n_http_flood),
        'ack_count': np.random.randint(1000, 10000, n_http_flood),
        'connection_rate': np.random.normal(1000, 200, n_http_flood),
        'src_ip_entropy': np.random.uniform(5, 8, n_http_flood),
        'label': np.ones(n_http_flood)  # 1 = Attack
    }
    
    # SYN Flood Attack (10% of data)
    n_syn_flood = int(n_samples * 0.10)
    syn_flood = {
        'packets_per_sec': np.random.normal(15000, 3000, n_syn_flood),
        'bytes_per_sec': np.random.normal(1000000, 200000, n_syn_flood),
        'unique_src_ips': np.random.randint(500, 2000, n_syn_flood),
        'unique_dst_ports': np.random.randint(1, 5, n_syn_flood),
        'avg_packet_size': np.random.normal(60, 10, n_syn_flood),
        'packet_size_variance': np.random.normal(10, 5, n_syn_flood),
        'flow_duration': np.random.normal(0.5, 0.2, n_syn_flood),
        'syn_count': np.random.randint(10000, 50000, n_syn_flood),
        'rst_count': np.random.randint(0, 50, n_syn_flood),
        'ack_count': np.random.randint(0, 100, n_syn_flood),
        'connection_rate': np.random.normal(5000, 1000, n_syn_flood),
        'src_ip_entropy': np.random.uniform(6, 9, n_syn_flood),
        'label': np.ones(n_syn_flood)  # 1 = Attack
    }
    
    # UDP Flood Attack (5% of data)
    n_udp_flood = n_samples - n_normal - n_http_flood - n_syn_flood
    udp_flood = {
        'packets_per_sec': np.random.normal(20000, 5000, n_udp_flood),
        'bytes_per_sec': np.random.normal(10000000, 2000000, n_udp_flood),
        'unique_src_ips': np.random.randint(200, 1500, n_udp_flood),
        'unique_dst_ports': np.random.randint(10, 100, n_udp_flood),
        'avg_packet_size': np.random.normal(1000, 200, n_udp_flood),
        'packet_size_variance': np.random.normal(300, 100, n_udp_flood),
        'flow_duration': np.random.normal(0.3, 0.1, n_udp_flood),
        'syn_count': np.random.randint(0, 10, n_udp_flood),
        'rst_count': np.random.randint(0, 10, n_udp_flood),
        'ack_count': np.random.randint(0, 50, n_udp_flood),
        'connection_rate': np.random.normal(3000, 500, n_udp_flood),
        'src_ip_entropy': np.random.uniform(4, 7, n_udp_flood),
        'label': np.ones(n_udp_flood)  # 1 = Attack
    }
    
    # Combine all data
    df_normal = pd.DataFrame(normal_data)
    df_http = pd.DataFrame(http_flood)
    df_syn = pd.DataFrame(syn_flood)
    df_udp = pd.DataFrame(udp_flood)
    
    df = pd.concat([df_normal, df_http, df_syn, df_udp], ignore_index=True)
    
    # Shuffle the data
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    print(f"[✓] Generated {len(df)} traffic samples")
    print(f"    - Normal: {n_normal} ({n_normal/len(df)*100:.1f}%)")
    print(f"    - Attacks: {len(df) - n_normal} ({(len(df)-n_normal)/len(df)*100:.1f}%)")
    
    return df

def train_models(df):
    """
    Train Random Forest and Isolation Forest models
    """
    print("\n[*] Preparing training data...")
    
    # Split features and labels
    X = df.drop('label', axis=1)
    y = df['label']
    
    # Split into train and test sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    
    # Standardize features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print(f"[✓] Training set: {len(X_train)} samples")
    print(f"[✓] Test set: {len(X_test)} samples")
    
    # Train Random Forest Classifier
    print("\n[*] Training Random Forest Classifier...")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train_scaled, y_train)
    
    # Evaluate Random Forest
    rf_predictions = rf_model.predict(X_test_scaled)
    rf_accuracy = accuracy_score(y_test, rf_predictions)
    
    print(f"[✓] Random Forest Accuracy: {rf_accuracy*100:.2f}%")
    
    # Train Isolation Forest (for anomaly detection)
    print("\n[*] Training Isolation Forest (Anomaly Detector)...")
    iso_model = IsolationForest(
        contamination=0.3,  # Expected proportion of outliers
        random_state=42,
        n_jobs=-1
    )
    iso_model.fit(X_train_scaled)
    
    # Evaluate Isolation Forest
    iso_predictions = iso_model.predict(X_test_scaled)
    iso_predictions = np.where(iso_predictions == -1, 1, 0)  # Convert to 0/1
    iso_accuracy = accuracy_score(y_test, iso_predictions)
    
    print(f"[✓] Isolation Forest Accuracy: {iso_accuracy*100:.2f}%")
    
    # Ensemble prediction (voting)
    print("\n[*] Creating Ensemble Model...")
    ensemble_predictions = np.where(
        (rf_predictions + iso_predictions) >= 1, 1, 0
    )
    ensemble_accuracy = accuracy_score(y_test, ensemble_predictions)
    
    print(f"[✓] Ensemble Accuracy: {ensemble_accuracy*100:.2f}%")
    
    # Detailed metrics
    print("\n" + "="*60)
    print("CLASSIFICATION REPORT (Random Forest):")
    print("="*60)
    print(classification_report(y_test, rf_predictions, 
                                target_names=['Normal', 'Attack']))
    
    print("\n" + "="*60)
    print("CONFUSION MATRIX (Random Forest):")
    print("="*60)
    cm = confusion_matrix(y_test, rf_predictions)
    print(f"True Negatives:  {cm[0][0]:,}")
    print(f"False Positives: {cm[0][1]:,}")
    print(f"False Negatives: {cm[1][0]:,}")
    print(f"True Positives:  {cm[1][1]:,}")
    
    # Save models
    print("\n[*] Saving models...")
    joblib.dump(rf_model, 'saved_models/random_forest_model.pkl')
    joblib.dump(iso_model, 'saved_models/isolation_forest_model.pkl')
    joblib.dump(scaler, 'saved_models/scaler.pkl')
    
    # Save feature names
    feature_names = X.columns.tolist()
    with open('saved_models/feature_names.json', 'w') as f:
        json.dump(feature_names, f)
    
    # Save model metadata
    metadata = {
        'training_date': datetime.now().isoformat(),
        'n_samples': len(df),
        'n_features': len(feature_names),
        'rf_accuracy': float(rf_accuracy),
        'iso_accuracy': float(iso_accuracy),
        'ensemble_accuracy': float(ensemble_accuracy),
        'feature_names': feature_names
    }
    
    with open('saved_models/metadata.json', 'w') as f:
        json.dump(metadata, f, indent=2)
    
    print("[✓] Models saved successfully!")
    print(f"    - saved_models/random_forest_model.pkl")
    print(f"    - saved_models/isolation_forest_model.pkl")
    print(f"    - saved_models/scaler.pkl")
    print(f"    - saved_models/feature_names.json")
    print(f"    - saved_models/metadata.json")
    
    return rf_model, iso_model, scaler, metadata

def main():
    print("="*60)
    print("AI-POWERED DDoS DETECTION - MODEL TRAINING")
    print("="*60)
    
    # Generate synthetic data
    df = generate_synthetic_data(n_samples=50000)
    
    # Save dataset
    df.to_csv('../data/processed/training_data.csv', index=False)
    print(f"\n[✓] Dataset saved: data/processed/training_data.csv")
    
    # Train models
    rf_model, iso_model, scaler, metadata = train_models(df)
    
    print("\n" + "="*60)
    print("TRAINING COMPLETE!")
    print("="*60)
    print(f"Final Ensemble Accuracy: {metadata['ensemble_accuracy']*100:.2f}%")
    print("\nYou can now run the web application:")
    print("  python web/app.py")
    print("="*60)

if __name__ == "__main__":
    main()
