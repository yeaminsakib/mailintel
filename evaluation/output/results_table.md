### Model Performance Benchmark Comparison Table

| Model Architecture | Accuracy | Precision | Recall | F1-Score | ROC-AUC | PR-AUC |
|:-------------------|:--------:|:---------:|:------:|:--------:|:-------:|:------:|
| **MailIntel Rule-Based (Optimal Thresh 12.5)** | **97.00%** | **100.00%** | **94.00%** | **96.91%** | **0.9892** | **0.9900** |
| MailIntel Rule-Based (Default SOC 50.0) | 50.00% | 100.00% | 0.00% | 0.00% | 0.9892 | 0.9900 |
| TF-IDF + Header Logistic Regression (5-Fold CV) | 100.00% | 100.00% | 100.00% | 100.00% | 1.0000 | 1.0000 |
| **Hybrid Ensemble (Rule-Based + ML)** | **98.00%** | **100.00%** | **96.00%** | **97.96%** | **1.0000** | **1.0000** |
