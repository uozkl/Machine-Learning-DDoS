from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.neural_network import MLPClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import BernoulliNB, MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
import pandas as pd
import warnings
from multiprocessing import Process, Pool
from process.preprocess import Preprocess
import pickle

warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=RuntimeWarning)
warnings.filterwarnings("ignore", category=UserWarning)

# Malicious data from 'SYN\\Syn_2_split\\Syn_2_3.csv'
'''
benign = Preprocess("D:/BENIGN.csv")
malicious = Preprocess("D:/MALICIOUS.csv")
benign_features_time = pd.read_csv("D:/Benign_features_time.csv")
malicious_features_time = pd.read_csv("D:/Malicious_features_time.csv")
'''

benign_features_conn = pd.read_csv("D:/Benign_features_conn.csv")
malicious_features_conn = pd.read_csv("D:/Malicious_features_conn.csv")

# Test, conn based

x = pd.concat([malicious_features_conn, benign_features_conn]).values
# Remove id
x = [i[1:] for i in x]
y = [0] * len(malicious_features_conn) + [1] * len(benign_features_conn)
# X_train, X_test, y_train, y_test = train_test_split(x, y, train_size=0.8, random_state=2019)

# MLP

mlp = MLPClassifier()

# Random Forest

rf = RandomForestClassifier(bootstrap=True, oob_score=True, criterion='gini')

# Naive Bayes

bernoulli_nb = BernoulliNB()
multinomial_nb = MultinomialNB()

# Support vector machine

svm = SVC()

# K-nearest neighbors
knn = KNeighborsClassifier(n_neighbors=3)

def score(classifier, x=x, y=y, verbose=False, num_cv = 10):
    if verbose:
        print("Estimating",type(classifier))
    accuracy = cross_val_score(classifier, x, y, cv=num_cv)
    precision = cross_val_score(classifier, x, y, cv=num_cv, scoring='precision')
    recall = cross_val_score(classifier, x, y, cv=num_cv, scoring='recall')
    if verbose:
        print("Classifier type:", type(classifier), "\nAccuracy:", accuracy, "\nPrecision:", precision, "\nRecall:", recall)
    return accuracy, precision, recall


# Export mlp classifer
mlp.fit(x,y)
with open('models/clf.pkl', 'wb') as f:
    pickle.dump(mlp, f)