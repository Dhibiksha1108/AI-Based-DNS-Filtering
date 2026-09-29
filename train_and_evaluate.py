import os
import json
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)

# Define feature columns and target
FEATURE_COLUMNS = [
    'domain_length',
    'number_of_digits',
    'digit_ratio',
    'number_of_letters',
    'number_of_special_characters',
    'number_of_subdomains',
    'vowel_count',
    'consonant_count',
    'vowel_ratio',
    'consonant_ratio',
    'unique_character_count',
    'character_entropy'
]
TARGET_COLUMN = 'class_name'

def train_and_evaluate_model():
    data_path = os.path.join("data", "dns_threats_features.csv")
    models_dir = "models"
    os.makedirs(models_dir, exist_ok=True)
    
    print(f"1. Loading processed dataset from {data_path}...")
    df = pd.read_csv(data_path)
    
    X = df[FEATURE_COLUMNS]
    y = df[TARGET_COLUMN]
    
    print(f"Dataset shape: X={X.shape}, y={y.shape}")
    print("Class distribution in full dataset:\n", y.value_counts())
    
    print("\n2. Splitting dataset into Train (80%) and Test (20%) with stratified sampling...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Training Set Size: {X_train.shape[0]} samples")
    print(f"Test Set Size: {X_test.shape[0]} samples")
    print("Class distribution in test set:\n", y_test.value_counts())
    
    print("\n3. Training Baseline Random Forest Classifier (n_estimators=100, random_state=42)...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    print("Training completed successfully!")
    
    print("\n4. Evaluating model performance on TEST set...")
    y_pred = clf.predict(X_test)
    
    acc = accuracy_score(y_test, y_pred)
    prec_weighted = precision_score(y_test, y_pred, average='weighted')
    rec_weighted = recall_score(y_test, y_pred, average='weighted')
    f1_weighted = f1_score(y_test, y_pred, average='weighted')
    
    prec_macro = precision_score(y_test, y_pred, average='macro')
    rec_macro = recall_score(y_test, y_pred, average='macro')
    f1_macro = f1_score(y_test, y_pred, average='macro')
    
    print(f"Accuracy: {acc:.4f} ({acc*100:.2f}%)")
    print(f"Precision (Weighted): {prec_weighted:.4f} | Precision (Macro): {prec_macro:.4f}")
    print(f"Recall (Weighted): {rec_weighted:.4f} | Recall (Macro): {rec_macro:.4f}")
    print(f"F1-Score (Weighted): {f1_weighted:.4f} | F1-Score (Macro): {f1_macro:.4f}")
    
    print("\nClassification Report:\n")
    print(classification_report(y_test, y_pred))
    
    cm = confusion_matrix(y_test, y_pred, labels=clf.classes_)
    print("Confusion Matrix:\n", cm)
    
    # Plot and save confusion matrix visualization
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=clf.classes_, yticklabels=clf.classes_)
    plt.title("Confusion Matrix - DNS Threat Classifier")
    plt.xlabel("Predicted Label")
    plt.ylabel("True Label")
    plt.tight_layout()
    cm_plot_path = os.path.join(models_dir, "confusion_matrix.png")
    plt.savefig(cm_plot_path, dpi=300)
    plt.close()
    print(f"Confusion matrix plot saved to {cm_plot_path}")
    
    print("\n5. Feature Importance Analysis...")
    importances = clf.feature_importances_
    feature_imp_df = pd.DataFrame({
        'feature': FEATURE_COLUMNS,
        'importance': importances
    }).sort_values(by='importance', ascending=False).reset_index(drop=True)
    
    print("Features ordered by importance:")
    for idx, row in feature_imp_df.iterrows():
        print(f"  {idx+1:2d}. {row['feature']:<30} : {row['importance']:.4f}")
        
    # Save feature importances to CSV
    feature_imp_df.to_csv(os.path.join(models_dir, "feature_importances.csv"), index=False)
    
    print("\n6. Saving Model and Metadata...")
    model_file = os.path.join(models_dir, "dns_threat_classifier.pkl")
    metadata_file = os.path.join(models_dir, "model_metadata.json")
    
    joblib.dump(clf, model_file)
    
    metadata = {
        "model_type": "RandomForestClassifier",
        "n_estimators": 100,
        "random_state": 42,
        "feature_names": FEATURE_COLUMNS,
        "classes": list(clf.classes_),
        "metrics": {
            "accuracy": round(acc, 4),
            "precision_weighted": round(prec_weighted, 4),
            "recall_weighted": round(rec_weighted, 4),
            "f1_weighted": round(f1_weighted, 4)
        }
    }
    
    with open(metadata_file, "w") as f:
        json.dump(metadata, f, indent=4)
        
    print(f"Model saved to: {model_file}")
    print(f"Metadata saved to: {metadata_file}")
    
    print("\n7. Sample Prediction Verification...")
    sample = X_test.iloc[0:1]
    sample_domain = df.loc[sample.index[0], 'domain']
    sample_true_label = y_test.iloc[0]
    sample_pred_label = clf.predict(sample)[0]
    sample_probs = clf.predict_proba(sample)[0]
    
    print(f"Sample Domain: {sample_domain}")
    print(f"True Class: {sample_true_label}")
    print(f"Predicted Class: {sample_pred_label}")
    print("Class Probabilities:", dict(zip(clf.classes_, [round(p, 4) for p in sample_probs])))
    
    print("\nML Model Training and Evaluation Completed Successfully!")

if __name__ == "__main__":
    train_and_evaluate_model()
