from sklearn.metrics import accuracy_score,precision_score,recall_score,r2_score,confusion_matrix,classification_report
from sklearn.ensemble import VotingClassifier
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from FeatureExtractor import extract_features
def plot_confusion_matrix(test_Y, predict_y):
    C = confusion_matrix(test_Y, predict_y)
    A =(((C.T)/(C.sum(axis=1))).T)
    B =(C/C.sum(axis=0))
    plt.figure(figsize=(20,4))
    labels = [1,2]
    cmap=sns.light_palette("blue")
    plt.subplot(1, 3, 1)
    sns.heatmap(C, annot=True, cmap=cmap, fmt=".3f", xticklabels=labels, yticklabels=labels)
    plt.xlabel('Predicted Class')
    plt.ylabel('Original Class')
    plt.title("Confusion matrix")
    plt.subplot(1, 3, 2)
    sns.heatmap(B, annot=True, cmap=cmap, fmt=".3f", xticklabels=labels, yticklabels=labels)
    plt.xlabel('Predicted Class')
    plt.ylabel('Original Class')
    plt.title("Precision matrix")
    plt.subplot(1, 3, 3)
    sns.heatmap(A, annot=True, cmap=cmap, fmt=".3f", xticklabels=labels, yticklabels=labels)
    plt.xlabel('Predicted Class')
    plt.ylabel('Original Class')
    plt.title("Recall matrix")
    plt.show()
def Model(clfs,train_X,train_Y,test_X,test_Y):
    dic = thisdict = {
        "Model": [],
        "TrainAcc": [],
        "TestAcc": []
    }
    predictors = []
    for i in clfs:
        print(i.__class__.__name__)
        model = i.fit(train_X,train_Y)
        predictors.append(model)
        TrainPreds=model.predict(train_X)
        TestPreds=model.predict(test_X)
        TrainAcc = accuracy_score(train_Y,TrainPreds)
        print(f"TrainAcc: {TrainAcc}")
        TestAcc = accuracy_score(test_Y,TestPreds)
        print(f"TestAcc: {TestAcc}")
        print(classification_report(test_Y,TestPreds))
        plot_confusion_matrix(test_Y, TestPreds)
        dic["Model"]
        dic["Model"].append(i.__class__.__name__)
        dic["TrainAcc"].append(TrainAcc)
        dic["TestAcc"].append(TestAcc)
    estimators = []
    for i in predictors:
        estimators.append((i.__class__.__name__,i))
    EnsembleModel = VotingClassifier(estimators=estimators,weights=[3,1,1,2,1])
    print("EnsembleModel")
    model = EnsembleModel.fit(train_X,train_Y)
    predictors.append(model)
    TrainPreds=model.predict(train_X)
    TestPreds=model.predict(test_X)
    TrainAcc = accuracy_score(train_Y,TrainPreds)
    print(f"TrainAcc: {TrainAcc}")
    TestAcc = accuracy_score(test_Y,TestPreds)
    print(f"TestAcc: {TestAcc}")
    print(classification_report(test_Y,TestPreds))
    plot_confusion_matrix(test_Y, TestPreds)
    dic["Model"]
    dic["Model"].append("EnsembleModel")
    dic["TrainAcc"].append(TrainAcc)
    dic["TestAcc"].append(TestAcc)
    return dic, predictors
def MakeInfrence(predictors,url):
    features = extract_features(url)
    test = pd.DataFrame(features)
    prediction = predictors[5].predict(test)
    if prediction==1:
        print(f'>>>>>>>real site=={prediction}')
    else:
        print(f'>>>fake site=={prediction}') 
    

