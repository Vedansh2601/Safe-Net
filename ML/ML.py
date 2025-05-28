
from datetime import datetime  #	Used to measure the execution time of model training and prediction.
from matplotlib import pyplot as plt 
import seaborn as sns
import numpy as np
import os
import sys
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix 
#helps to evaluate the performance of the model
from sklearn.metrics import accuracy_score

class MachineLearning():

    # This class implements various machine learning algorithms to classify network flow data.
    #     
    def __init__(self): 
        # Initialize the machine learning class and load the dataset.
         
        self.counter = 0

        if os.path.exists('/Users/vishuchauhan/Library/CloudStorage/OneDrive-Personal/DDoS-Attack-Detection-and-Mitigation-main/Codes/ml/FlowStatsfile.csv'):
         self.flow_dataset = pd.read_csv('/Users/vishuchauhan/Library/CloudStorage/OneDrive-Personal/DDoS-Attack-Detection-and-Mitigation-main/Codes/ml/FlowStatsfile.csv')
        else:
          print("CSV file not found!")
        sys.exit(1)

        print("Loading dataset ...")

        # Replace '.' with '' in specific columns to convert them to numeric values.
        self.flow_dataset.iloc[:, 2] = self.flow_dataset.iloc[:, 2].str.replace('.', '')
        self.flow_dataset.iloc[:, 3] = self.flow_dataset.iloc[:, 3].str.replace('.', '')
        self.flow_dataset.iloc[:, 5] = self.flow_dataset.iloc[:, 5].str.replace('.', '')
        
        self.X_flow = self.flow_dataset.iloc[:, :-1].values
        self.X_flow = self.X_flow.astype('float64') # Convert features to float64 type for consistency

        self.y_flow = self.flow_dataset.iloc[:, -1].values

        # Split the dataset into training and testing sets.
        self.X_flow_train, self.X_flow_test, self.y_flow_train, self.y_flow_test = train_test_split(self.X_flow, self.y_flow, test_size=0.25, random_state=0) 

    # Define methods for different machine learning algorithms.
    def LR(self):
        # Logistic Regression method to classify the network flow data.
        
        print("------------------------------------------------------------------------------")
        print("Logistic Regression ...")

        # Initialize the Logistic Regression classifier.
        # Using 'liblinear' solver for small datasets.
        # Random state is set for reproducibility.

        self.classifier = LogisticRegression(solver='liblinear', random_state=0) 
        self.Confusion_matrix()
        
    def KNN(self):

        print("------------------------------------------------------------------------------")
        print("K-NEAREST NEIGHBORS ...")
        # K-Nearest Neighbors method to classify the network flow data.
        # Initialize the KNN classifier with 5 neighbors and Minkowski distance.
        # Using p=2 for Euclidean distance.
        self.classifier = KNeighborsClassifier(n_neighbors=5, metric='minkowski', p=2)
        self.Confusion_matrix()
 
    def SVM(self):

        print("------------------------------------------------------------------------------")
        print("SUPPORT-VECTOR MACHINE ...")
        # Support Vector Machine method to classify the network flow data.
        # Initialize the SVM classifier with RBF kernel.
        # Random state is set for reproducibility.
        self.classifier = SVC(kernel='rbf', random_state=0)
        self.Confusion_matrix()
        
    def NB(self):

        print("------------------------------------------------------------------------------")
        print("NAIVE-BAYES ...")
        # Naive Bayes method to classify the network flow data.
        # Initialize the Gaussian Naive Bayes classifier.
        # This classifier assumes that the features follow a Gaussian distribution.
        # It is suitable for classification tasks where the features are independent.
        # This method is particularly useful for text classification and spam detection.
        # It is based on Bayes' theorem and assumes that the features are conditionally independent given the class label.

        self.classifier = GaussianNB()
        self.Confusion_matrix()
        
        
    def DT(self):

        print("------------------------------------------------------------------------------")
        print("DECISION TREE ...")
        # Decision Tree method to classify the network flow data.
        # Initialize the Decision Tree classifier with entropy criterion.
        # The entropy criterion is used to measure the impurity of a node.
        # It is a measure of the amount of uncertainty or disorder in the data.
        self.classifier = DecisionTreeClassifier(criterion='entropy', random_state=0)
        self.Confusion_matrix()
        
    def RF(self):

        print("------------------------------------------------------------------------------")
        print("RANDOM FOREST ...")

        self.classifier = RandomForestClassifier(n_estimators=10, criterion="entropy", random_state=0)
        self.Confusion_matrix()
        
    def Confusion_matrix(self):
        self.counter += 1
        
        self.flow_model = self.classifier.fit(self.X_flow_train, self.y_flow_train)

        self.y_flow_pred = self.flow_model.predict(self.X_flow_test)

        print("------------------------------------------------------------------------------")

        print("confusion matrix")
        cm = confusion_matrix(self.y_flow_test, self.y_flow_pred)
        print(cm)


        # plot Confusion Matrix Heatmap
        sns.set_style("darkgrid") 
        plt.figure(figsize=(5, 4)) 
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Pred 0', 'Pred 1'], yticklabels=['True 0', 'True 1'])
        plt.title("Confusion Matrix")
        plt.xlabel("Predicted Label")
        plt.ylabel("True Label")
        plt.tight_layout()
        plt.show()

        acc = accuracy_score(self.y_flow_test, self.y_flow_pred) # Calculate the accuracy of the model.

        print("succes accuracy = {0:.2f} %".format(acc*100))
        fail = 1.0 - acc
        print("fail accuracy = {0:.2f} %".format(fail*100))
        print("------------------------------------------------------------------------------")
        
        x = ['TP','FP','FN','TN']
        x_indexes = np.arange(len(x))
        width = 0.10
        plt.xticks(ticks=x_indexes, labels=x)
        plt.title("Results of the Algorithms")
        plt.xlabel('Predicted Class')
        plt.ylabel('Number of Flows')

         #plt.tight_layout()
       # plt.style.use("seaborn-darkgrid")
        sns.set_style("darkgrid")
        plt.style.use("dark_background")
        plt.style.use("ggplot")
        if self.counter == 1:

            y1 = [cm[0][0],cm[0][1],cm[1][0],cm[1][1]]
            plt.bar(x_indexes-2*width,y1, width=width, color="#1b7021", label='LR') 
            plt.legend()
        if self.counter == 2:
          
            y2 = [cm[0][0],cm[0][1],cm[1][0],cm[1][1]]
            plt.bar(x_indexes-width,y2, width=width, color="#e46e6e", label='KNN')
            plt.legend()
        if self.counter == 3:

            y3 = [cm[0][0],cm[0][1],cm[1][0],cm[1][1]]
            plt.bar(x_indexes,y3, width=width, color="#0000ff", label='NB')
            plt.legend()
        if self.counter == 4:
            y4 = [cm[0][0],cm[0][1],cm[1][0],cm[1][1]]
            plt.bar(x_indexes+width,y4, width=width, color="#e0d692", label='DT')
            plt.legend()
        if self.counter == 5:
            y5 = [cm[0][0],cm[0][1],cm[1][0],cm[1][1]]
            plt.bar(x_indexes+2*width,y5, width=width, color="#000000", label='RF')
            plt.legend()
            plt.show()
        
        
def main():
    # Main function to execute the machine learning algorithms and measure their execution time.
    start_script = datetime.now()
    
    ml = MachineLearning()
    
    start = datetime.now()
    ml.LR()
    end = datetime.now()
    print("LEARNING and PREDICTING Time: ", (end-start)) 
    
    start = datetime.now()
    ml.KNN()
    end = datetime.now()
    print("LEARNING and PREDICTING Time: ", (end-start))
    
    start = datetime.now()
    ml.SVM()
    end = datetime.now()
    print("LEARNING and PREDICTING Time: ", (end-start))
    
    start = datetime.now()
    ml.NB()
    end = datetime.now()
    print("LEARNING and PREDICTING Time: ", (end-start))
    
    start = datetime.now()
    ml.DT()
    end = datetime.now()
    print("LEARNING and PREDICTING Time: ", (end-start))
    
    start = datetime.now()
    ml.RF()
    end = datetime.now()
    print("LEARNING and PREDICTING Time: ", (end-start))
    
    end_script = datetime.now()
    print("Script Time: ", (end_script-start_script))

if __name__ == "__main__":
    main()