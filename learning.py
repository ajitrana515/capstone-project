import os
import pandas as pd
import numpy as np
import pickle
import sklearn.ensemble as ske
from sklearn import model_selection, tree
from sklearn.feature_selection import SelectFromModel
import joblib
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import confusion_matrix

# Load the data
data = pd.read_csv('data.csv', sep='|')
X = data.drop(['Name', 'md5', 'legitimate'], axis=1).values
y = data['legitimate'].values

# Feature selection using ExtraTreesClassifier
fsel = ske.ExtraTreesClassifier().fit(X, y)
model = SelectFromModel(fsel, prefit=True)
X_new = model.transform(X)
nb_features = X_new.shape[1]

# Split the data
X_train, X_test, y_train, y_test = model_selection.train_test_split(X_new, y, test_size=0.2)

features = []

# Print selected features
print('%i features identified as important:' % nb_features)
indices = np.argsort(fsel.feature_importances_)[::-1][:nb_features]
for f in range(nb_features):
    print("%d. feature %s (%f)" % (f + 1, data.columns[2 + indices[f]], 
                                  fsel.feature_importances_[indices[f]]))
    features.append(data.columns[2 + indices[f]])

# Train multiple algorithms
algorithms = {
    "RandomForest": ske.RandomForestClassifier(n_estimators=50),
    "GradientBoosting": ske.GradientBoostingClassifier(n_estimators=50),
    "AdaBoost": ske.AdaBoostClassifier(n_estimators=100),
    "GNB": GaussianNB(),
    "DecisionTree": tree.DecisionTreeClassifier(max_depth=10)
}

results = {}
print("\nNow testing algorithms")
for algo in algorithms:
    clf = algorithms[algo]
    clf.fit(X_train, y_train)
    score = clf.score(X_test, y_test)
    print("%s : %f %%" % (algo, score * 100))
    results[algo] = score

winner = max(results, key=results.get)
print('\nWinner algorithm is %s with a %f %% success' % (winner, results[winner] * 100))

# Ensure the classifier directory exists before saving
directory = 'classifier'
if not os.path.exists(directory):
    os.makedirs(directory)

# Save the algorithm and the feature list
print('Saving algorithm and feature list in classifier directory...')
joblib.dump(algorithms[winner], os.path.join(directory, 'classifier.pkl'))
open(os.path.join(directory, 'features.pkl'), 'wb').write(pickle.dumps(features))
print('Saved')

# Compute confusion matrix
y_pred = algorithms[winner].predict(X_test)
cm = confusion_matrix(y_test, y_pred)
print('\n')
print(cm)
print('\nFalse positive rate : %f %%' % ((cm[0][1] / float(sum(cm[0]))) * 100))
print('False negative rate : %f %%' % ((cm[1][0] / float(sum(cm[1]))) * 100))
