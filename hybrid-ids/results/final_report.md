# Hybrid IDS: Final Results Report

_Generated 2026-06-16 20:30:44_


## 1. Dataset Preparation

```
rows: 446338
columns: 79

Category distribution:
Category
BENIGN         379334
DoS             38751
DDoS            25603
Brute Force      1830
Web Attack        429
PortScan          391

Column list:
Flow Duration
Total Fwd Packets
Total Backward Packets
Total Length of Fwd Packets
Total Length of Bwd Packets
Fwd Packet Length Max
Fwd Packet Length Min
Fwd Packet Length Mean
Fwd Packet Length Std
Bwd Packet Length Max
Bwd Packet Length Min
Bwd Packet Length Mean
Bwd Packet Length Std
Flow Bytes/s
Flow Packets/s
Flow IAT Mean
Flow IAT Std
Flow IAT Max
Flow IAT Min
Fwd IAT Total
Fwd IAT Mean
Fwd IAT Std
Fwd IAT Max
Fwd IAT Min
Bwd IAT Total
Bwd IAT Mean
Bwd IAT Std
Bwd IAT Max
Bwd IAT Min
Fwd PSH Flags
Bwd PSH Flags
Fwd URG Flags
Bwd URG Flags
Fwd Header Length
Bwd Header Length
Fwd Packets/s
Bwd Packets/s
Min Packet Length
Max Packet Length
Packet Length Mean
Packet Length Std
Packet Length Variance
FIN Flag Count
SYN Flag Count
RST Flag Count
PSH Flag Count
ACK Flag Count
URG Flag Count
CWE Flag Count
ECE Flag Count
Down/Up Ratio
Average Packet Size
Avg Fwd Segment Size
Avg Bwd Segment Size
Fwd Header Length.1
Fwd Avg Bytes/Bulk
Fwd Avg Packets/Bulk
Fwd Avg Bulk Rate
Bwd Avg Bytes/Bulk
Bwd Avg Packets/Bulk
Bwd Avg Bulk Rate
Subflow Fwd Packets
Subflow Fwd Bytes
Subflow Bwd Packets
Subflow Bwd Bytes
Init_Win_bytes_forward
Init_Win_bytes_backward
act_data_pkt_fwd
min_seg_size_forward
Active Mean
Active Std
Active Max
Active Min
Idle Mean
Idle Std
Idle Max
Idle Min
Label
Category
```


## 2. Exploratory Data Analysis

```
Exploratory Data Analysis Summary
==================================================

Total rows:       446,338
Total columns:    79
Attack ratio:     0.1501

Category counts:
  BENIGN             379,334  (84.99%)
  DoS                 38,751  ( 8.68%)
  DDoS                25,603  ( 5.74%)
  Brute Force          1,830  ( 0.41%)
  Web Attack             429  ( 0.10%)
  PortScan               391  ( 0.09%)

Top 15 features by absolute correlation with attack label:
  Bwd Packet Length Std                +0.7143
  Bwd Packet Length Mean               +0.7054
  Avg Bwd Segment Size                 +0.7054
  Bwd Packet Length Max                +0.7021
  Packet Length Std                    +0.6784
  Max Packet Length                    +0.6578
  Average Packet Size                  +0.6353
  Packet Length Mean                   +0.6310
  Packet Length Variance               +0.6194
  Fwd IAT Std                          +0.5904
  Idle Max                             +0.5589
  Flow IAT Max                         +0.5560
  Fwd IAT Max                          +0.5545
  Idle Mean                            +0.5532
  Idle Min                             +0.5382

```


EDA artefacts written to `results/eda/`:

- **Class distribution (linear scale)**: `results/eda/01_class_distribution.png`
- **Class distribution (log scale, exposes minority classes)**: `results/eda/02_class_distribution_log.png`
- **Missing-value audit**: `results/eda/03_missing_values.png`
- **Correlation matrix of top-30 features by variance**: `results/eda/04_correlation_heatmap.png`
- **Top 15 features by correlation with attack label**: `results/eda/05_top_features_by_correlation.png`
- **Per-class boxplots of the most discriminative features**: `results/eda/06_feature_distributions.png`


## 3. Feature Pipeline

```
Input features: 77
RFE retained:   30
PCA components: 9
PCA variance retained: 0.9526

RFE-selected features:
Flow Duration
Total Fwd Packets
Total Length of Bwd Packets
Fwd Packet Length Max
Fwd Packet Length Std
Bwd Packet Length Max
Bwd Packet Length Min
Bwd Packet Length Mean
Bwd Packet Length Std
Flow IAT Std
Flow IAT Max
Flow IAT Min
Fwd IAT Total
Fwd IAT Mean
Fwd IAT Std
Fwd IAT Max
Fwd IAT Min
Max Packet Length
Packet Length Std
Packet Length Variance
Avg Bwd Segment Size
Subflow Fwd Packets
Subflow Bwd Bytes
act_data_pkt_fwd
Active Mean
Active Max
Idle Mean
Idle Std
Idle Max
Idle Min
```


## 4. Standard Held-Out Evaluation

### 4.1 Headline metrics

| model           |   macro_f1 |    mcc |   accuracy |   precision |   recall |   false_positive_rate |   false_negative_rate |   roc_auc |    ece |    tp |    fp |    tn |   fn |
|:----------------|-----------:|-------:|-----------:|------------:|---------:|----------------------:|----------------------:|----------:|-------:|------:|------:|------:|-----:|
| LinearSVC       |     0.4173 | 0.2498 |     0.4273 |      0.206  |   0.9858 |                0.6713 |                0.0142 |    0.9363 | 0.5134 | 13211 | 50932 | 24935 |  190 |
| IsolationForest |     0.7966 | 0.5983 |     0.887  |      0.6011 |   0.7343 |                0.0861 |                0.2657 |    0.8417 | 0.0883 |  9840 |  6530 | 69337 | 3561 |
| HybridStack     |     0.9764 | 0.9531 |     0.9878 |      0.9404 |   0.9806 |                0.011  |                0.0194 |    0.9986 | 0.0118 | 13141 |   833 | 75034 |  260 |


### 4.2 Per-category recall

| category    |   HybridStack |   IsolationForest |   LinearSVC |
|:------------|--------------:|------------------:|------------:|
| BENIGN      |        0.989  |            0.9139 |      0.3287 |
| Brute Force |        0.9809 |            0      |      1      |
| DDoS        |        0.9963 |            0.6227 |      0.9998 |
| DoS         |        0.9705 |            0.8574 |      0.9756 |
| PortScan    |        0.9872 |            0.0769 |      1      |
| Web Attack  |        0.9535 |            0      |      1      |


### 4.3 Confusion matrices

```

LinearSVC
                pred_BENIGN  pred_ATTACK
true_BENIGN            24935       50932
true_ATTACK              190       13211

IsolationForest
                pred_BENIGN  pred_ATTACK
true_BENIGN            69337        6530
true_ATTACK             3561        9840

HybridStack
                pred_BENIGN  pred_ATTACK
true_BENIGN            75034         833
true_ATTACK              260       13141

```


## 5. Leave-One-Attack-Category-Out (LOACO)

Each row below represents a full retraining run in which the named attack category was removed from the training set entirely. The *novel_recall* column measures the model's ability to detect that category at test time without ever having seen it during training.

| held_out_category   |   novel_recall |   known_attack_recall |   true_negative_rate |   overall_macro_f1 |   overall_mcc |   overall_fpr |
|:--------------------|---------------:|----------------------:|---------------------:|-------------------:|--------------:|--------------:|
| DoS                 |         0.1724 |                0.9913 |               0.9956 |             0.8141 |        0.6703 |        0.0044 |
| DDoS                |         0.4359 |                0.9755 |               0.9893 |             0.9077 |        0.8204 |        0.0107 |
| PortScan            |         0.1667 |                0.9799 |               0.9899 |             0.9762 |        0.9525 |        0.0101 |
| Brute Force         |         0      |                0.9813 |               0.9894 |             0.9691 |        0.9383 |        0.0106 |
| Web Attack          |         0.0116 |                0.9851 |               0.9888 |             0.9755 |        0.9514 |        0.0112 |


**Average novel-category recall:** 0.1573  

**Average recall on remaining known attacks:** 0.9826  

**Detection gap (known minus novel):** 0.8253


## 6. Plots

- **Reliability diagram (hybrid)**: `results\plots\reliability_hybrid.png`
- **Precision-recall curves**: `results\plots\pr_curves.png`
- **LOACO bar chart**: `results\loaco\loaco_plot.png`


## 7. Interpretation Notes


The standard held-out evaluation in Section 4 reports what the literature
typically calls benchmark performance. Numbers in that section should be
compared to the 2024 to 2025 peer-reviewed literature on CIC-IDS-2017, where
macro F1 above 0.95 is now routinely achieved by stacked ensembles.

The LOACO section is the more scientifically demanding test. A model that
matches benchmark accuracy but collapses on LOACO is not detecting novel
attacks, it is memorising attack signatures present in the training set. The
gap between known-attack recall and novel-category recall is the quantity to
discuss in the dissertation.

The reliability diagram in Section 6 shows whether the hybrid model's
probability outputs are trustworthy. A curve close to the diagonal indicates
that a predicted probability of 0.8 for an attack is empirically associated
with roughly 80% attack occurrence in that bin. Poor calibration undermines
any downstream decision threshold.
