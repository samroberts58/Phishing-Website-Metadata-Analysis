# Phishing Website Metadata Analysis
Samantha Roberts, M.S. </br>
Nima Zahadat, Ph.D. </br>
George Washington University

## Introduction
```
Phishing websites are one of the most lucrative social engineering attack styles due to low cost associated with reaching a wide array of users and minimal maintenance required for successful implementation. The purpose of this project is to demonstrate data mining techniques and pattern exploitation using the metadata of phishing websites for location prediction and behavioral trends. Modeling focuses on the following metadata variables: URL length, number of special characters, TCP conversation exchange data, packet and byte size, DNS query count, and type of website (malicious or benign). Applied models are Random Forest Classifier and Logistic Regression. 

For successful implemntation, ensure required files are colocated in the working directory and all Python packages listed below are available.
```

## Tools and Packages Used:
```
Python 3.6, Anaconda - Intel Distribution for Python (IDP)

Import Required Packages and Libraries as follows:

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import LabelEncoder
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
```

## Required Files:
```
Malicious and Benign Websites_Raw Data.csv
State Abbreviation List.csv
PhishingWebsiteMetadataAnalysis.py (doi: https://zenodo.org/badge/latestdoi/161653232)
```

## Supplementary Files:
```
Phishing Website Metadata Analysis.docx
Phishing Website Metadata Analysis.mp4
Phishing Website Metadata Analysis.pptx
```
