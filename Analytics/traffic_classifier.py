import matplotlib
matplotlib.use('Agg')
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
    x_shuf = []
    y_shuf = []
    index_shuf = range(len(train_x))
    shuffle(index_shuf)
    for i in index_shuf:
        x_shuf.append(train_x[i])
        y_shuf.append(train_y[i])

    return x_shuf, y_shuf, features_id

def runClassification_CV(data_folder, feature_set, cfg, classifier):
    print "Gather dataset"
    dataset_fraction = 1.0
    train_x, train_y, features_id = gatherAllData(data_folder, cfg, dataset_fraction)

    model = classifier[0]
    clf_name = classifier[1]

    # Report Cross-Validation Accuracy
    # scores = cross_val_score(model, np.asarray(train_x), np.asarray(train_y), cv=10)
    print clf_name
    # print "Avg. Accuracy: " + str(sum(scores)/float(len(scores)))

    cv = KFold(n_splits=10)
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
        # plt.plot(fpr, tpr, lw=1, alpha=0.3, label='ROC fold %d (AUC = %0.2f)' % (i, roc_auc))
        i += 1

    plt.plot([0, 1], [0, 1], linestyle='--', lw=2, color='r', label='Random Guess', alpha=.8)

    mean_tpr = np.mean(tprs, axis=0)
    mean_tpr[-1] = 1.0
    mean_auc = auc(mean_fpr, mean_tpr)
    print "Model AUC: " + "{0:.3f}".format(mean_auc)
    print "Training time (Avg. fold): " + str(np.mean(train_times, axis=0))
    print "Test time (Avg. fold): " + str(np.mean(test_times, axis=0))

    unblock70 = True
    unblock80 = True
    unblock90 = True
    unblock95 = True
    for n, i in enumerate(mean_tpr):
        if (i >= 0.7 and unblock70):
            print '70%  TPR  = ' + "{0:.3f}".format(mean_fpr[n])
            unblock70 = False
        if (i >= 0.8 and unblock80):
            print '80%  TPR  = ' + "{0:.3f}".format(mean_fpr[n])
            unblock80 = False
        if (i >= 0.9 and unblock90):
            print '90%  TPR  = ' + "{0:.3f}".format(mean_fpr[n])
            unblock90 = False
        if (i >= 0.95 and unblock95):
            print '95%  TPR  = ' + "{0:.3f}".format(mean_fpr[n])
            unblock95 = False

    # Figure properties
    fig = plt.figure()
    ax1 = fig.add_subplot(111)

    std_auc = np.std(aucs)
    np.save('xgBoost/' + feature_set + "/ROC_" + clf_name + "_" + cfg[1] + "_Sensitivity", np.array(mean_tpr))
    np.save('xgBoost/' + feature_set + "/ROC_" + clf_name + "_" + cfg[1] + "_Specificity", np.array(mean_fpr))

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

    fig.savefig('xgBoost/' + feature_set + "/ROC_" + clf_name + "_" + cfg[1] + ".pdf")   # save the figure to file
    plt.close(fig)

    mean_importances = []
    for n in range(0, len(importances[0])):
        mean_imp = (importances[0][n] + importances[1][n] + importances[2][n] + importances[3][n] + importances[4][n] +
                    importances[5][n] + importances[6][n] + importances[7][n] + importances[8][n] + importances[9][
                        n]) / 10.0
        mean_importances.append(mean_imp)
    f_imp = zip(mean_importances, features_id)
    f_imp.sort(key=lambda t: t[0], reverse=True)

    np.save('xgBoost/' + feature_set + "/FeatureImportance_" + clf_name + "_" + cfg[1], np.array(f_imp))

    # for f in f_imp[:20]:
    #    print "Importance: %f, Feature: %s" % (f[0], f[1])

if __name__ == "__main__":

    cfgs = [
        ["in.csv",
         "out.csv"]]

    if not os.path.exists('xgBoost'):
        os.makedirs('xgBoost')

    classifiers = [
        [XGBClassifier(), "XGBoost"]
    ]

    feature_set = '1'
    data_folder = '/home/joaoteixeira/git/Thesis/Analytics/extractedFeatures/' + feature_set + '/'
    if not os.path.exists('xgBoost/' + feature_set):
        os.makedirs('xgBoost/' + feature_set)

    print "\n================================================="
    print "One-class SVM - Summary Statistic Features - Set1"
    print "================================================="
    for cfg in cfgs:
        for classifier in classifiers:
            print "Running classifiers for " + cfg[0] + " and " + cfg[1]
            runClassification_CV(data_folder, feature_set, cfg, classifier)
    print "#####################################\n"