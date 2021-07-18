import matplotlib

matplotlib.use('Agg')
import sys
import matplotlib.pyplot as plt
import os
import csv
import numpy as np
from scipy import interp
import random
from random import shuffle
import math
import time
# Classifiers
from xgboost import XGBClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
# Eval Metrics
from sklearn.model_selection import train_test_split, KFold
from sklearn.metrics import accuracy_score, roc_auc_score, roc_curve, auc
from sklearn.model_selection import cross_val_score

np.random.seed(1)
random.seed(1)


def gatherAllData(data_folder, cfg, dataset_fraction):
    # Load Datasets
    f = open(data_folder + cfg[0], 'r')
    reader = csv.reader(f, delimiter=',')
    reg = list(reader)
    reg = reg[:int(dataset_fraction * len(reg))]

    f = open(data_folder + cfg[1], 'r')
    reader = csv.reader(f, delimiter=',')
    fac = list(reader)
    fac = fac[:int(dataset_fraction * len(fac))]

    print "###########################################"
    print "Configuration " + cfg[1]
    print "###########################################"

    # Convert data to floats (and labels to integers)
    features_id = reg[0]
    reg_data = []
    for i in reg[1:]:
        int_array = []
        for pl in i[:-1]:
            int_array.append(float(pl))
        int_array.append(0)
        reg_data.append(int_array)

    fac_data = []
    for i in fac[1:]:
        int_array = []
        for pl in i[:-1]:
            int_array.append(float(pl))
        int_array.append(1)
        fac_data.append(int_array)

    # Build label tensors
    reg_labels = []
    for i in reg_data:
        reg_labels.append(int(i[len(reg_data[0]) - 1]))

    fac_labels = []
    for i in fac_data:
        fac_labels.append(int(i[len(reg_data[0]) - 1]))

    # Take label out of data tensors
    for i in range(0, len(reg_data)):
        reg_data[i].pop()

    for i in range(0, len(fac_data)):
        fac_data[i].pop()

    # Create training sets by combining the randomly selected samples from each class
    train_x = reg_data + fac_data
    train_y = reg_labels + fac_labels

    # Shuffle positive/negative samples for CV purposes
    x_shuffle = []
    y_shuffle = []
    index_shuffle = range(len(train_x))
    shuffle(index_shuffle)
    for i in index_shuffle:
        x_shuffle.append(train_x[i])
        y_shuffle.append(train_y[i])

    return x_shuffle, y_shuffle, features_id


def runClassification_CV(data_folder, feature_set, cfg, classifier):
    print "Gather dataset"
    dataset_fraction = 1.0
    train_x, train_y, features_id = gatherAllData(data_folder, cfg, dataset_fraction)

    model = classifier[0]
    clf_name = classifier[1]

    cv = KFold(10)
    tprs = []
    aucs = []
    mean_fpr = np.linspace(0, 1, 100)
    train_times = []
    test_times = []
    importances = []

    # Split the data in k-folds, perform classification, and report ROC
    i = 0
    for train, test in cv.split(train_x, train_y):
        start_train = time.time()
        model = model.fit(np.asarray(train_x)[train], np.asarray(train_y)[train])
        end_train = time.time()
        train_times.append(end_train - start_train)

        start_test = time.time()
        probas_ = model.predict_proba(np.asarray(train_x)[test])
        end_test = time.time()
        test_times.append(end_test - start_test)

        fpr, tpr, thresholds = roc_curve(np.asarray(train_y)[test], probas_[:, 1])

        tprs.append(interp(mean_fpr, fpr, tpr))

        tprs[-1][0] = 0.0
        roc_auc = auc(fpr, tpr)
        aucs.append(roc_auc)

        # Check feature importance in this fold
        f_imp = model.feature_importances_
        importances.append(f_imp)
        i += 1

    plt.plot([0, 1], [0, 1], linestyle='--', lw=2, color='r', label='Random Guess', alpha=.8)

    mean_tpr = np.mean(tprs, axis=0)
    mean_tpr[-1] = 1.0
    mean_auc = auc(mean_fpr, mean_tpr)
    print "Model AUC: " + "{0:.3f}".format(mean_auc)
    print "Training time (Avg. fold): " + str(np.mean(train_times, axis=0))
    print "Test time (Avg. fold): " + str(np.mean(test_times, axis=0))

    # Figure properties
    fig = plt.figure()
    ax1 = fig.add_subplot(111)

    std_auc = np.std(aucs)

    plt.plot(mean_fpr, mean_tpr, color='b', label=r'Mean ROC (AUC = %0.2f $\pm$ %0.3f)' % (mean_auc, std_auc), lw=2,
             alpha=.8)

    # Compute Standard Deviation between folds
    std_tpr = np.std(tprs, axis=0)
    tprs_upper = np.minimum(mean_tpr + std_tpr, 1)
    tprs_lower = np.maximum(mean_tpr - std_tpr, 0)
    plt.fill_between(mean_fpr, tprs_lower, tprs_upper, color='grey', alpha=.3, label=r'$\pm$ ROC Std. Dev.')

    ax1.plot([0, 1], [0, 1], 'k--', lw=2, color='orange', label='Random Guess')
    ax1.grid(color='black', linestyle='dotted')

    plt.title('Receiver Operating Characteristic (ROC)')
    plt.xlabel('False Positive Rate', fontsize='x-large')
    plt.ylabel('True Positive Rate', fontsize='x-large')
    plt.legend(loc='lower right', fontsize='large')

    plt.setp(ax1.get_xticklabels(), fontsize=14)
    plt.setp(ax1.get_yticklabels(), fontsize=14)

    fig.savefig('xgBoost/' + feature_set + "/ROC_" + clf_name + "_" + cfg[1] + ".pdf")  # save the figure to file
    plt.close(fig)


if __name__ == "__main__":

    if len(sys.argv) < 4:
        print("Error: Please input sample folder location and two extracted features csv files")
        sys.exit(0)

    feature_set = sys.argv[1]

    cfgs = [
        [sys.argv[2],
         sys.argv[3]]]

    if not os.path.exists('xgBoost'):
        os.makedirs('xgBoost')

    classifiers = [
        [XGBClassifier(), "XGBoost"]
    ]

    data_folder = '/home/joaoteixeira/git/Thesis/Analytics/extractedFeatures/' + feature_set + '/'
    if not os.path.exists('xgBoost/' + feature_set):
        os.makedirs('xgBoost/' + feature_set)

    print "\n================================================="
    print "One-class SVM - Summary Statistic Features - Set"
    print "================================================="
    for cfg in cfgs:
        for classifier in classifiers:
            print "Running classifiers for " + cfg[0] + " and " + cfg[1]
            runClassification_CV(data_folder, feature_set, cfg, classifier)
    print "#####################################\n"
