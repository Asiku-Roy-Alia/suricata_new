# Hybrid IDS: Final Results Report

_Generated 2026-04-25 12:14:18_


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
  Bwd Packet Length Std                +0.7134
  Bwd Packet Length Mean               +0.7039
  Avg Bwd Segment Size                 +0.7039
  Bwd Packet Length Max                +0.7009
  Packet Length Std                    +0.6770
  Max Packet Length                    +0.6565
  Average Packet Size                  +0.6334
  Packet Length Mean                   +0.6291
  Packet Length Variance               +0.6186
  Fwd IAT Std                          +0.5912
  Idle Max                             +0.5593
  Flow IAT Max                         +0.5564
  Fwd IAT Max                          +0.5549
  Idle Mean                            +0.5534
  Idle Min                             +0.5381

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
PCA components: 10
PCA variance retained: 0.9509

RFE-selected features:
Flow Duration
Total Fwd Packets
Total Length of Bwd Packets
Fwd Packet Length Max
Fwd Packet Length Std
Bwd Packet Length Max
Bwd Packet Length Min
Bwd Packet Length Mean
Flow IAT Std
Flow IAT Max
Flow IAT Min
Fwd IAT Total
Fwd IAT Mean
Fwd IAT Std
Fwd IAT Max
Fwd IAT Min
Bwd Packets/s
Max Packet Length
Packet Length Variance
Average Packet Size
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
| LinearSVC       |     0.4904 | 0.3076 |     0.5151 |      0.2343 |   0.9834 |                0.5677 |                0.0166 |    0.9338 | 0.4644 | 13179 | 43067 | 32800 |  222 |
| IsolationForest |     0.8005 | 0.6043 |     0.891  |      0.6167 |   0.7242 |                0.0795 |                0.2758 |    0.8397 | 0.0959 |  9705 |  6031 | 69836 | 3696 |
| HybridStack     |     0.9707 | 0.9422 |     0.9846 |      0.9197 |   0.9835 |                0.0152 |                0.0165 |    0.9981 | 0.0136 | 13180 |  1150 | 74717 |  221 |


### 4.2 Per-category recall

| category    |   HybridStack |   IsolationForest |   LinearSVC |
|:------------|--------------:|------------------:|------------:|
| BENIGN      |        0.9848 |            0.9205 |      0.4323 |
| Brute Force |        0.9836 |            0      |      1      |
| DDoS        |        0.9986 |            0.6132 |      0.9996 |
| DoS         |        0.9743 |            0.8454 |      0.9721 |
| PortScan    |        0.9615 |            0.1667 |      1      |
| Web Attack  |        0.9302 |            0      |      0.9535 |


### 4.3 Confusion matrices

```

LinearSVC
                pred_BENIGN  pred_ATTACK
true_BENIGN            32800       43067
true_ATTACK              222       13179

IsolationForest
                pred_BENIGN  pred_ATTACK
true_BENIGN            69836        6031
true_ATTACK             3696        9705

HybridStack
                pred_BENIGN  pred_ATTACK
true_BENIGN            74717        1150
true_ATTACK              221       13180

```


## 5. Leave-One-Attack-Category-Out (LOACO)

Each row below represents a full retraining run in which the named attack category was removed from the training set entirely. The *novel_recall* column measures the model's ability to detect that category at test time without ever having seen it during training.

| held_out_category   |   novel_recall |   known_attack_recall |   true_negative_rate |   overall_macro_f1 |   overall_mcc |   overall_fpr |
|:--------------------|---------------:|----------------------:|---------------------:|-------------------:|--------------:|--------------:|
| DoS                 |         0.0898 |                0.9901 |               0.9918 |             0.7853 |        0.6164 |        0.0082 |
| DDoS                |         0.5001 |                0.9687 |               0.9873 |             0.9119 |        0.8271 |        0.0127 |
| PortScan            |         0.1026 |                0.9784 |               0.9876 |             0.9719 |        0.9442 |        0.0124 |
| Brute Force         |         0.0109 |                0.9786 |               0.988  |             0.9662 |        0.9324 |        0.012  |
| Web Attack          |         0.0233 |                0.9797 |               0.9887 |             0.9738 |        0.9478 |        0.0113 |


**Average novel-category recall:** 0.1453  

**Average recall on remaining known attacks:** 0.9791  

**Detection gap (known minus novel):** 0.8338


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
