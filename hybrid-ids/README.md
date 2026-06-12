# Hybrid Intrusion Detection System

Reference implementation for the bachelor dissertation project titled *Hybrid Intrusion Detection System for Higher Accuracy Detection and Reliability Against Novel Attacks*. The codebase incorporates every methodological recommendation from the supervisor evaluation, most importantly the Leave-One-Attack-Category-Out protocol for genuinely testing novel attack detection, proper calibration of the One-Class SVM decision function, and class-imbalance-aware metrics reporting.

## 1. What this pipeline produces

When you run it end to end you will obtain the following artefacts.

The file `results/metrics_summary.csv` holds the headline binary metrics for the three trained models, namely the Linear SVC baseline, the Isolation Forest baseline and the hybrid stacked classifier. Reported metrics include macro F1, Matthews Correlation Coefficient, accuracy, precision, recall, false positive rate, ROC-AUC and expected calibration error. The file `results/per_category_recall.csv` breaks recall down by attack category, so rare classes like Infiltration and Web Attack are never hidden behind an aggregate.

The directory `results/eda/` contains exploratory data analysis artefacts produced by `scripts/00b_eda.py`. This includes class distribution plots in linear and logarithmic scale, a missing value audit, a correlation heatmap of the most variable features, a ranking of features by absolute correlation with the attack label, per-class boxplots of the most discriminative features, an outlier summary CSV, and per-class feature statistics. These figures and tables are intended for direct inclusion in the EDA section of the dissertation.

The directory `results/loaco/` contains the output of the Leave-One-Attack-Category-Out experiment. For each of the seven attack categories, the hybrid model is retrained with that category entirely removed from training and validation sets, and its ability to detect the held-out category at test time is recorded. This is the experiment that allows the dissertation to make defensible claims about novel attack detection.

The directory `results/plots/` contains a reliability diagram for the hybrid model and precision recall curves for all three models. The file `results/final_report.md` consolidates everything into a single readable document.

## 2. System requirements

The implementation targets a machine running a modern Linux distribution or macOS with at least sixteen gigabytes of random access memory, approximately fifty gigabytes of free disk space after data expansion, and a multi core processor. Python 3.10 or newer is required. The pipeline has been designed to complete on commodity laptop hardware within a few hours when the default stratified sampling fraction of 0.20 is used.

## 3. Installation

Clone or copy this directory onto your machine and create a clean virtual environment before installing dependencies.

```bash
cd hybrid-ids
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## 4. Running the smoke test first

Before touching the real dataset, confirm that your environment is set up correctly by running the smoke test. It generates synthetic data of the same shape as CIC-IDS-2017, exercises the entire pipeline in under two minutes and prints pass or fail against a small set of quantitative thresholds.

```bash
python scripts/00_smoke_test.py
```

If the smoke test passes, you will see the line `SMOKE TEST PASSED. Environment is ready for CIC-IDS-2017.` at the end of the output. If it fails, do not proceed. Inspect the log at `results/logs/00_smoke_test.log` to diagnose.

## 5. Downloading CIC-IDS-2017

The CIC-IDS-2017 dataset is distributed by the Canadian Institute for Cybersecurity. You need the preprocessed flow-level CSV archive, not the raw PCAPs.

Open a browser and navigate to the official distribution page at `https://www.unb.ca/cic/datasets/ids-2017.html`. Complete the brief registration form and download the archive titled `MachineLearningCSV.zip`. The download is approximately 250 megabytes.

Extract the archive. It produces a folder containing eight CSV files with names such as `Monday-WorkingHours.pcap_ISCX.csv`, `Tuesday-WorkingHours.pcap_ISCX.csv` and so on. Copy or move all eight CSV files into `data/raw/` inside this project. The data loader will pick them up automatically.

```bash
# Expected layout after download
data/raw/
  Monday-WorkingHours.pcap_ISCX.csv
  Tuesday-WorkingHours.pcap_ISCX.csv
  Wednesday-workingHours.pcap_ISCX.csv
  Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
  Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
  Friday-WorkingHours-Morning.pcap_ISCX.csv
  Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
  Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
```

Before running the pipeline, delete any synthetic files that may still be sitting in `data/raw/` from the smoke test or from the tests folder. The loader concatenates every CSV it finds under that directory.

## 6. Running the full pipeline

The simplest way is to execute the master runner, which invokes the six numbered scripts in sequence.

```bash
./run_all.sh
```

If you prefer to run the steps manually, the pipeline is organised as follows.

```bash
python scripts/01_prepare_data.py     # Load, clean, deduplicate, stratified sample
python scripts/00b_eda.py             # Exploratory data analysis: plots, tables, correlations
python scripts/02_preprocess.py       # Scale, RFE, PCA, SMOTE balancing, train/val/test split
python scripts/03_train_models.py     # Fit Linear SVC, Isolation Forest and the hybrid
python scripts/04_evaluate.py         # Held-out test evaluation with per-category recall
python scripts/05_loaco.py            # Leave-One-Attack-Category-Out experiment
python scripts/06_report.py           # Generate results/final_report.md
```

Each script writes a log file under `results/logs/` so you have a complete trail of what happened during the run.

## 7. Expected runtime

With the default configuration of a twenty percent stratified sample on CIC-IDS-2017, the runtime on a modern laptop with sixteen gigabytes of random access memory is approximately as follows. Step one, data preparation, takes roughly five minutes. Step two, preprocessing, takes roughly five minutes. Step three, training, takes between fifteen and forty minutes depending on CPU count. Step four, evaluation, takes under a minute. Step five, the LOACO experiment, retrains the hybrid model seven times and takes between one and three hours. Step six, report generation, is instant.

Expect roughly two to four hours of total wall-clock time for a complete run.

## 8. Configuration

Every tunable parameter lives in `config.yaml`. The most consequential knobs are as follows. The field `data.stratified_sample_fraction` controls how much of the 2.8 million row CIC-IDS-2017 corpus is retained. Reduce it to 0.05 if you need a very fast run for debugging. The fields under `preprocessing` set the number of features retained by Recursive Feature Elimination and the variance retained by Principal Component Analysis. The fields under `models.supervised`, `models.anomaly` and `models.meta_learner` define the hyperparameter grids searched during training. The section `loaco` enumerates the attack categories to iterate over during the novel-attack experiment.

You do not normally need to edit this file. The defaults reflect the recommendations from the supervisor evaluation.

## 9. Reproducibility

All random sources are seeded from the top-level `seed` value in the configuration, which defaults to 42. Rerunning the pipeline with the same configuration produces identical artefacts byte for byte on the same machine, subject to small numerical differences between BLAS implementations.

## 10. What to expect in the numbers

Based on the peer-reviewed literature on CIC-IDS-2017, a correctly executed run of this pipeline should produce the following approximate figures on the held-out test set. The Linear SVC baseline should reach a macro F1 in the range 0.94 to 0.97. The Isolation Forest baseline should reach a macro F1 in the range 0.80 to 0.88. The hybrid stacked classifier should reach a macro F1 in the range 0.96 to 0.99 and an expected calibration error below 0.05.

The LOACO experiment is the scientifically interesting part and its results will vary more. Certain attack categories, particularly DoS and DDoS, are close enough to each other in feature space that removing one during training still leaves the model able to detect the other. Categories like Infiltration or Web Attack are typically harder to detect as novel because their traffic profile is more distinct. A typical result is that average novel-category recall sits in the range 0.40 to 0.75, meaningfully below the recall on attacks seen during training. This detection gap is the finding to discuss in the dissertation.

## 11. Project layout

```
hybrid-ids/
  README.md                      This file
  requirements.txt               Pinned Python dependencies
  config.yaml                    All tunable parameters
  run_all.sh                     Master runner
  src/
    __init__.py
    utils.py                     Config loading, seeds, logging
    data.py                      CIC-IDS-2017 loading and cleaning
    features.py                  Scaling, RFE, PCA
    models.py                    Calibrated OCSVM, stacked hybrid, baselines
    metrics.py                   Macro F1, MCC, per-class recall, calibration
  scripts/
    00_smoke_test.py             End-to-end synthetic test
    00_smoke_test.py             End-to-end synthetic test
    00b_eda.py                   Exploratory data analysis with plots/tables
    01_prepare_data.py           Step 1
    02_preprocess.py             Step 2
    03_train_models.py           Step 3
    04_evaluate.py               Step 4
    05_loaco.py                  Step 5 (novel attack test)
    06_report.py                 Step 6
  tests/
    make_synthetic_raw.py        Dev convenience for pipeline testing
  data/
    raw/                         YOU must place CIC-IDS-2017 CSVs here
    processed/                   Generated by the pipeline
  artifacts/                     Serialised trained models
  results/
    logs/                        Per-script log files
    eda/                         Exploratory data analysis (plots, tables)
    plots/                       Reliability, PR curves
    loaco/                       Novel attack experiment outputs
    final_report.md              Consolidated human-readable report
    metrics_summary.csv          Headline metrics
    per_category_recall.csv      Recall broken down by category
    confusion_matrices.txt       Confusion matrices per model
    training_summary.txt         Training diagnostics
```

## 12. Writing up the results

When you draft the results chapter of the dissertation, the recommended structure is to begin with the EDA findings from Section 2 of the generated report, then present the standard held-out evaluation from Section 4, then devote a separate subsection to the LOACO experiment and frame it as the project's principal novel-attack evidence. Finish with the reliability diagram and the expected calibration error, which is the diagnostic that justifies the calibration choice for the One-Class SVM component. This structure directly addresses every methodological concern raised in the supervisor evaluation. The EDA section gives you the dataset characterisation that examiners expect: class imbalance, feature correlations, and per-class discriminability before any model is introduced.

Cite the current peer-reviewed literature when comparing your numbers. The Talukder et al. 2024 stacked ensemble paper, the HAMC-ID paper from 2025 and the HIDIM paper are appropriate baselines for the standard evaluation. For the LOACO discussion, frame it as filling a gap that the cited literature does not address, because the cited papers evaluate under a conventional train test split and therefore do not measure novel attack detection.

## 13. Troubleshooting

If the smoke test fails, the most common causes are an outdated version of scikit-learn that lacks SGDOneClassSVM (minimum supported version is 1.3) or a corrupted installation. Recreate the virtual environment from scratch.

If step one reports that no CSV files were found, confirm that the files are directly inside `data/raw/` and not inside a subfolder nested deeper than the loader scans.

If step three consumes excessive memory, reduce `data.stratified_sample_fraction` from 0.20 to 0.10 or 0.05 and rerun from step one.

If step five, the LOACO experiment, consumes more time than you have available, edit `config.yaml` and remove categories from the `loaco.attack_categories` list to shorten the experiment.
