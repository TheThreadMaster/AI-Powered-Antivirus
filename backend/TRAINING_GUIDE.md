# AI Shield ML Model Training Guide

## Overview

The AI Shield system uses an Isolation Forest machine learning model for anomaly detection. This guide explains how to train and update the model with your own datasets.

## Quick Start

1. **Prepare Training Data**
   - Create two directories:
     - `benign_samples/`: Contains known safe/benign files
     - `malicious_samples/`: Contains known malicious files
   
2. **Run Training Script**
   ```bash
   python backend/train_ml_model.py \
       --benign-dir benign_samples/ \
       --malicious-dir malicious_samples/ \
       --output-dir backend/models
   ```

3. **Model Files**
   - `backend/models/model.pkl`: Trained Isolation Forest model
   - `backend/models/scaler.pkl`: Feature scaler
   - `backend/models/feature_names.json`: Feature names

## Training Data Requirements

### Minimum Requirements
- **Benign files**: At least 50 files (recommended: 100+)
- **Malicious files**: At least 10 files (recommended: 50+)

### File Types
The model works best with diverse file types:
- Executables (.exe, .dll)
- Scripts (.ps1, .bat, .js, .vbs)
- Documents (.pdf, .doc, .docx)
- Archives (.zip, .rar)
- Images (.png, .jpg)
- Text files (.txt, .log)

### Data Sources

**Benign Files:**
- System files from clean Windows/Linux installations
- Common applications (browsers, office suites, etc.)
- Open-source software
- Your own legitimate files

**Malicious Files:**
- VirusTotal samples (requires account)
- Malware repositories (use with caution in isolated environment)
- EICAR test files (for testing)
- Known malware samples from security research

⚠️ **WARNING**: Only use malicious samples in isolated, secure environments!

## Training Parameters

### Contamination Rate
The `--contamination` parameter controls the expected proportion of anomalies:
- Default: `0.1` (10% expected to be malicious)
- Adjust based on your environment:
  - High-security: `0.05` (5%)
  - Normal: `0.1` (10%)
  - High-threat: `0.2` (20%)

### Example with Custom Contamination
```bash
python backend/train_ml_model.py \
    --benign-dir benign_samples/ \
    --malicious-dir malicious_samples/ \
    --output-dir backend/models \
    --contamination 0.15
```

## Feature Extraction

The model uses 11 features extracted from each file:
1. `size_log`: Logarithm of file size
2. `entropy`: Shannon entropy of file content
3. `ratio_non_ascii`: Ratio of non-ASCII bytes
4. `printable_ratio`: Ratio of printable characters
5. `pe`: PE executable indicator (0 or 1)
6. `elf`: ELF executable indicator (0 or 1)
7. `pdf`: PDF document indicator (0 or 1)
8. `zip`: ZIP archive indicator (0 or 1)
9. `script`: Script file indicator (0 or 1)
10. `image`: Image file indicator (0 or 1)
11. `suspicious_hits`: Count of suspicious string patterns

These features match exactly what the anomaly detection system uses during scanning.

## Model Evaluation

The training script automatically:
- Splits data into training (80%) and testing (20%) sets
- Scales features using StandardScaler
- Trains Isolation Forest with 100 estimators
- Reports training and test accuracy

## Updating the Model

To update the model with new data:
1. Add new samples to your training directories
2. Re-run the training script
3. The new model will replace the old one
4. Restart the AI Shield backend to use the new model

## Troubleshooting

### "No files found" Error
- Check that directory paths are correct
- Ensure files are readable
- Check file permissions

### Low Accuracy
- Increase training data size
- Ensure balanced representation of file types
- Check that malicious samples are actually malicious
- Verify benign samples are actually safe

### Model Too Sensitive (False Positives)
- Increase contamination rate
- Add more benign samples
- Retrain with more diverse benign data

### Model Not Sensitive Enough (False Negatives)
- Decrease contamination rate
- Add more malicious samples
- Include more diverse malware types

## Best Practices

1. **Regular Updates**: Retrain monthly or when new malware types emerge
2. **Diverse Data**: Include various file types and sizes
3. **Validation**: Test the model on known samples before deployment
4. **Version Control**: Keep backups of previous models
5. **Isolation**: Train with malicious samples in isolated environments only

## Integration with YARA Rules

The ML model works alongside YARA pattern matching:
- YARA rules provide pattern-based detection
- ML model provides anomaly-based detection
- Combined scoring improves overall accuracy

## Support

For issues or questions:
1. Check that all dependencies are installed: `pip install scikit-learn numpy`
2. Verify file paths and permissions
3. Review training data quality
4. Check model files are generated correctly

