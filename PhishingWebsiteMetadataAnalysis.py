"""
@author: Samantha Roberts
"""

"""

*Data Source Used:
https://www.kaggle.com/xwolf12/malicious-and-benign-websites

Goals:

•	Data set of choice 
•	State where the data came from
•	Code
•	Analysis
•	Any associations and/or correlations
•	Predictions and reasons behind them
•	Conclusions

"""
"""
Data Preprocessing:
    - Read in the data
    - Identify NaN's, out of place values, and remove missing data.
    - Standardize and format data
    - Verify data types
"""

# Import required packages
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# Read in the csv file and create the data frame.
mal_websites = pd.read_csv('Malicious and Benign Websites_Raw Data.csv', header=0, sep= ',', engine= 'python')

# Check basics
print(mal_websites.head())
print(mal_websites.columns)
print(mal_websites.shape)


#### Check each column's values for strange or incorrect entries ####

# DROP URL column - generated ID column to obfuscate actual URL addresses, not needed
mal_websites.drop(['URL'], axis=1, inplace=True)

# Check URL_LENGTH - pass
print(mal_websites['URL_LENGTH'].unique())

# Check NUMBER_SPECIAL_CHARACTERS - pass
print(mal_websites['NUMBER_SPECIAL_CHARACTERS'].unique())

# Check CHARSET - pass
print(mal_websites['CHARSET'].unique())

# Check SERVER - pass
print(mal_websites['SERVER'].unique())

# Check CONTENT_LENGTH - pass, many NaN's
print(mal_websites['CONTENT_LENGTH'].unique())
mal_websites['CONTENT_LENGTH'].replace('nan', np.NaN, inplace=True)

# Check WHOIS_COUNTRY - fixed
print(mal_websites['WHOIS_COUNTRY'].unique())

country_dict = {'GB':'UK', 'se':'SE', "[u'GB'; u'UK']":'UK', 'Cyprus':'CY', 'us':'US', 'ru':'RU', 'United Kingdom':'UK'}
for i in mal_websites['WHOIS_COUNTRY']:
    if i in country_dict.keys():
        mal_websites['WHOIS_COUNTRY'].replace(i, country_dict[i], inplace=True)


# Check WHOIS_STATEPRO - fixed
print(mal_websites['WHOIS_STATEPRO'].unique())

state_list = ['Not Applicable','NOT APPLICABLE','6110021','ILOCOS NORTE R3','widestep@mail.ru','-','NONE']
for i in mal_websites['WHOIS_COUNTRY']:
    if i in state_list:
        mal_websites['WHOIS_COUNTRY'].replace(i, np.NaN, inplace=True)
        
# Check and redefine WHOIS_REGDATE to datetime data types - fixed
print(mal_websites['WHOIS_REGDATE'].unique())

reg_list = ['None','b','0']
for i in mal_websites['WHOIS_REGDATE']:
    if i in reg_list:
        mal_websites['WHOIS_REGDATE'].replace(i, np.NaN, inplace=True)

mal_websites['WHOIS_REGDATE'] = pd.to_datetime(mal_websites['WHOIS_REGDATE'])

# Check and redefine WHOIS_UPDATED_DATE to datetime data type - fixed
print(mal_websites['WHOIS_UPDATED_DATE'].unique())
mal_websites['WHOIS_UPDATED_DATE'].replace('None', np.NaN, inplace=True)
mal_websites['WHOIS_UPDATED_DATE'] = pd.to_datetime(mal_websites['WHOIS_UPDATED_DATE'])

# Check TCP_CONVERSATION_EXCHANGE - pass
print(mal_websites['TCP_CONVERSATION_EXCHANGE'].unique())

# Check DIST_REMOTE_TCP_PORT - pass
print(mal_websites['DIST_REMOTE_TCP_PORT'].unique())

# Check REMOTE_IPS - pass
print(mal_websites['REMOTE_IPS'].unique())

# Check APP_BYTES - pass
print(mal_websites['APP_BYTES'].unique())

# Check SOURCE_APP_PACKETS - pass
print(mal_websites['SOURCE_APP_PACKETS'].unique())

# Check REMOTE_APP_PACKETS - pass
print(mal_websites['REMOTE_APP_PACKETS'].unique())

# Check SOURCE_APP_BYTES - pass
print(mal_websites['SOURCE_APP_BYTES'].unique())

# Check REMOTE_APP_BYTES - pass
print(mal_websites['REMOTE_APP_BYTES'].unique())

# Check APP_PACKETS - pass
print(mal_websites['APP_PACKETS'].unique())

# Check DNS_QUERY_TIMES, need to reassign to int data type - fixed below NaN drop
print(mal_websites['DNS_QUERY_TIMES'].unique())

# Check Type - pass
print(mal_websites['Type'].unique())

# Identify if any columns have missing data and how many
mal_websites.replace('NA', np.NaN, inplace=True)
mal_websites.replace('', np.NaN, inplace=True)
print(mal_websites.isna().sum())

# Drop all the blanks - except CONTENT_LENGTH, it removes too many rows
mal_websites.dropna(how='any', subset=['SERVER','WHOIS_STATEPRO','WHOIS_REGDATE','WHOIS_UPDATED_DATE','DNS_QUERY_TIMES'],inplace=True)
print(mal_websites.isna().sum())

# Fix DNS_QUERY_TIMES data type to int
mal_websites['DNS_QUERY_TIMES'] = mal_websites['DNS_QUERY_TIMES'].astype(int)

# Check data types of the columns
for i in mal_websites:
    print(i, mal_websites[i].dtype)



# Plot barchart of all countries (frequency of each country)
mal_websites_count = mal_websites.groupby(['WHOIS_COUNTRY'], as_index=True).count()
mal_websites_count = mal_websites_count.reset_index()
sns.set(style="whitegrid")
Country_Barplot = sns.barplot(x="WHOIS_COUNTRY", y="URL_LENGTH", data=mal_websites_count)
plt.xticks(rotation=90)
# plt.savefig('Country_Barplot.png')

# Convert countries with less than ten occurrences to "Other"
mal_websites_list = list(mal_websites_count[mal_websites_count['URL_LENGTH'] < 10].reset_index().iloc[:,1])

for i in mal_websites_list:
    mal_websites.replace(i, 'Other', inplace=True)

print(mal_websites['WHOIS_COUNTRY'].unique())
mal_websites_tencount = mal_websites.groupby(['WHOIS_COUNTRY'], as_index=False).count()
print(mal_websites_tencount)


mal_websites_tencount['COUNT'] = mal_websites_tencount['URL_LENGTH']

sns.set(style="whitegrid")
TenCountry_Barplot = sns.barplot(x="WHOIS_COUNTRY", y="COUNT", data=mal_websites_tencount)
plt.xticks(rotation=90)
# plt.savefig('TenCountry_Barplot.png')


# Identify which states in US and plot
US = mal_websites.loc[mal_websites['WHOIS_COUNTRY'] == 'US'].sort_values(by=['WHOIS_STATEPRO'])
print(US['WHOIS_STATEPRO'])

# Additional fix for US States
state_abbrev = pd.read_csv('State Abbreviation List.csv', header=0, sep=',')
state_abbrev_dict = pd.Series(state_abbrev['Abbrev'].values, index=state_abbrev['State']).to_dict()
US['WHOIS_STATEPRO'].replace('Utr', 'UT', inplace=True)
    
for i in US['WHOIS_STATEPRO'].unique():
    if i in state_abbrev_dict:
        US['WHOIS_STATEPRO'].replace(i, state_abbrev_dict[i], inplace=True)
    elif len(i) == 2:
        tmp = i.upper()
        US['WHOIS_STATEPRO'].replace(i, tmp, inplace=True)
    elif i == 'Other':
        pass
    else:
        tmp2 = i.lower()
        tmp2 = tmp2.title()
        tmp2 = state_abbrev_dict[tmp2]
        US['WHOIS_STATEPRO'].replace(i, tmp2, inplace=True)

print(US['WHOIS_STATEPRO'].unique())

US_count = US.groupby(['WHOIS_STATEPRO'], as_index=False).count()
US['COUNT']=US_count['URL_LENGTH']
sns.set(style="whitegrid")
State_Barplot = sns.barplot(x="WHOIS_STATEPRO", y="COUNT", data=US)
plt.xticks(rotation=90)
# plt.savefig('State_Barplot.png')

print(US_count.iloc[:,:2])

print(US_count)

"""
EDA:
    - Boxplots
    - Bar charts
    - Pairplot, LM Plots
    - Correlation

"""


# Split the dataframe into categorical and continuous to check the distributions and filter features
mal_websites_categorical = US.loc[:,['CHARSET','SERVER', 'WHOIS_STATEPRO', 'Type']]
mal_websites_continuous = US.drop(['CHARSET','SERVER', 'WHOIS_REGDATE', 'WHOIS_UPDATED_DATE','WHOIS_COUNTRY','WHOIS_STATEPRO', 'Type'], axis=1)

# Categorical variables: Frequency Charts
for i in mal_websites_categorical:
    categorical = mal_websites_categorical[i].value_counts()
    sns.set(style="darkgrid")
    sns.barplot(categorical.index,categorical.values,alpha=0.9)
    plt.ylabel('Count', fontsize=12)
    plt.xlabel(i, fontsize=12)
    plt.xticks(rotation = 90)
    # plt.savefig(str(i) + ' FrequencyChart.png', bbox_inches='tight') ## Uncomment when ready
    plt.show()
    
    
# Continuous variables: Boxplots
for i in mal_websites_continuous:
    sns.set(style="whitegrid")
    ax = sns.boxplot(x=mal_websites_continuous[i])
    # plt.savefig(str(i)+' box.png', bbox_inches='tight') ## Uncomment when ready
    plt.show()


#Count data of each variable by State
US_allcount = US.groupby('WHOIS_STATEPRO').nunique()
US_all_count_continuous = US_allcount.drop(['CHARSET','SERVER', 'WHOIS_REGDATE', 'WHOIS_UPDATED_DATE','WHOIS_COUNTRY'], axis=1)


#Catplots
print(US_all_count_continuous['Type'])
for i in US_all_count_continuous:
    ax = sns.catplot(x='WHOIS_STATEPRO',y=i, hue='Type', data=US_all_count_continuous)
    plt.xticks(rotation=90)
    # plt.savefig(i+' Catplot.png')
    plt.tight_layout()
    plt.show()


# All Features
# Correlation
corr = US.corr(method = 'spearman')
corr2 = corr.style.background_gradient()
sns.heatmap(corr, 
        xticklabels=corr.columns,
        yticklabels=corr.columns)
# plt.savefig('Mal_Websites_Corr.png', bbox_inches='tight') ## Uncomment when ready

for i in corr:
    print(i, corr[i])
print(corr['URL_LENGTH'], corr['NUMBER_SPECIAL_CHARACTERS'])
print(corr.columns)
print(US.columns)

# Pairplot of each feature against every other feature
sns.pairplot(US, kind='reg')
# plt.savefig('pairplot.png')


#Individual plots for clear relationships based on pairplot results
a = sns.lmplot(x="TCP_CONVERSATION_EXCHANGE", y="APP_PACKETS",hue='Type', data=US,
           logistic=True, y_jitter=.03)
plt.xlabel('TCP_CONVERSATION_EXCHANGE')
plt.ylabel('APP_PACKETS')
# plt.savefig('TCPConvo_AppPkts.png')
plt.tight_layout()
plt.show()


b = sns.lmplot(x="NUMBER_SPECIAL_CHARACTERS", y="URL_LENGTH", hue='Type', data=US,
           logistic=True, y_jitter=.03)
plt.xlabel('NUMBER_SPECIAL_CHARACTERS')
plt.ylabel('URL_LENGTH')
# plt.savefig('NoSpecChar_URLLeng.png')
plt.tight_layout()
plt.show()    


c = sns.lmplot(x="DIST_REMOTE_TCP_PORT", y="APP_BYTES", hue='Type', data=US,
           logistic=True, y_jitter=.03)
plt.xlabel('DIST_REMOTE_TCP_PORT')
plt.ylabel('APP_BYTES')
plt.savefig('DistTCP_AppBytes.png')
plt.tight_layout()
plt.show() 


"""
Models:

    -Random Forest Classifier
    -Logistic Regression
    
"""

# Import required packages
from sklearn.preprocessing import LabelEncoder
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split



######  Random Forest Classifier

# Separate the state variable
target = 'WHOIS_STATEPRO'

# Make it the y variable
y = US[target]

# Pick out the X features
features = (US.drop(['CONTENT_LENGTH', 'CHARSET', 'SERVER', 'COUNT','WHOIS_COUNTRY', 'WHOIS_STATEPRO', 'WHOIS_REGDATE', 'WHOIS_UPDATED_DATE'],axis=1).columns)

#features = (US.drop(['CONTENT_LENGTH', 'CHARSET', 'SERVER', 'COUNT','WHOIS_COUNTRY', 'WHOIS_STATEPRO', 'WHOIS_REGDATE', 'WHOIS_UPDATED_DATE', 'SOURCE_APP_PACKETS', 'REMOTE_APP_PACKETS', 'SOURCE_APP_BYTES', 'REMOTE_APP_BYTES'],axis=1).columns)


# Create the X array
X = US[features].values


# Declare the LabelEncoder
le = LabelEncoder()

# Encode the target
y = le.fit_transform(y)


# Split data into Train and Test for modeling
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=0)


#Scale the data
std = StandardScaler()

# Standardize X_train
X_train = std.fit_transform(X_train)

# Standardize X_test
X_test = std.transform(X_test)

# Load the model
rfc = RandomForestClassifier()

# Fit the model
rfc.fit(X_train, y_train)

# Get the score (rounding to two decimal places)
score = round(rfc.score(X_test, y_test), 2)
print(score)
importances = rfc.feature_importances_
print(features, importances)

f_importances = pd.Series(importances, features)

# Sort the array in descending order of the importances
f_importances = f_importances.sort_values(ascending=False)
print(f_importances)


#Plot the importances by feature
f_importances.plot(x='Features', y='Importance', kind='bar',  rot=75)
plt.tight_layout()
#plt.savefig('Importances.png')
plt.show()


######  Logistic Regression

# Separate the state variable
target = 'WHOIS_STATEPRO'

# Make it the y variable
y = US[target]

# Pick out the X features
# features = (US.drop(['CONTENT_LENGTH', 'CHARSET', 'SERVER', 'COUNT','WHOIS_COUNTRY', 'WHOIS_STATEPRO', 'WHOIS_REGDATE', 'WHOIS_UPDATED_DATE'],axis=1).columns)
features = (US.drop(['CONTENT_LENGTH', 'CHARSET', 'SERVER', 'COUNT','WHOIS_COUNTRY', 'WHOIS_STATEPRO', 'WHOIS_REGDATE', 'WHOIS_UPDATED_DATE', 'SOURCE_APP_PACKETS', 'REMOTE_APP_PACKETS', 'SOURCE_APP_BYTES', 'REMOTE_APP_BYTES'],axis=1).columns)

# Create the X array
X = US[features]
print(X)

# Declare the LabelEncoder
le = LabelEncoder()

# Encode the target
y = le.fit_transform(y)

# Split data into Train and Test for modeling
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=0)


#Scale the data
std = StandardScaler()

# Standardize X_train
X_train = std.fit_transform(X_train)

# Standardize X_test
X_test = std.transform(X_test)

# Load the model
lr = LogisticRegression()

# Fit the model
lr.fit(X_train, y_train)

# Get the score (rounding to two decimal places)
score = round(lr.score(X_test, y_test), 2)
print(score)

