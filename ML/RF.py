from datetime import datetime # Importing datetime for time tracking
from matplotlib import pyplot as plt
import seaborn as sns # Importing seaborn for enhanced visualization
import pandas as pd # Importing pandas for data manipulation
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier # Importing RandomForestClassifier for classification tasks
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score # Importing metrics for model evaluation

class MachineLearning():

    def __init__(self):
        
        print("Loading dataset ...")
        
        self.flow_dataset = pd.read_csv('/Users/vishuchauhan/Library/CloudStorage/OneDrive-Personal/DDoS-Attack-Detection-and-Mitigation-main/Codes/ml/FlowStatsfile.csv')

        self.flow_dataset.iloc[:, 2] = self.flow_dataset.iloc[:, 2].str.replace('.', '')
        self.flow_dataset.iloc[:, 3] = self.flow_dataset.iloc[:, 3].str.replace('.', '')
        self.flow_dataset.iloc[:, 5] = self.flow_dataset.iloc[:, 5].str.replace('.', '')       

    def flow_training(self):

        print("Flow Training ...")
        
        X_flow = self.flow_dataset.iloc[:, :-1].values
        X_flow = X_flow.astype('float64')

        y_flow = self.flow_dataset.iloc[:, -1].values

        X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(X_flow, y_flow, test_size=0.25, random_state=0)

        classifier = RandomForestClassifier(n_estimators=10, criterion="entropy", random_state=0) # Initialize Random Forest Classifier with 10 trees and entropy criterion
        flow_model = classifier.fit(X_flow_train, y_flow_train) # Train the model on the training data

        y_flow_pred = flow_model.predict(X_flow_test) # Predict the labels for the test set

        print("------------------------------------------------------------------------------")

        print("confusion matrix")
        cm = confusion_matrix(y_flow_test, y_flow_pred)
        print(cm)
        # Plot Confusion Matrix Heatmap
        sns.set_style("darkgrid")
        plt.figure(figsize=(5, 4))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Pred 0', 'Pred 1'], yticklabels=['True 0', 'True 1'])
        plt.title("Confusion Matrix")
        plt.xlabel("Predicted Label")
        plt.ylabel("True Label")
        plt.tight_layout()
        plt.show()
        acc = accuracy_score(y_flow_test, y_flow_pred)

        print("succes accuracy = {0:.2f} %".format(acc*100))
        fail = 1.0 - acc
        print("fail accuracy = {0:.2f} %".format(fail*100))
        print("------------------------------------------------------------------------------")
        # Plot Bar Chart for TP, FP, FN, TN
        x = ['TP','FP','FN','TN']
        plt.title("Random Forest")
        plt.xlabel('Classe predite')
        plt.ylabel('Nombre de flux')
        plt.tight_layout()
        plt.style.use("seaborn-darkgrid")
        y = [cm[0][0],cm[0][1],cm[1][0],cm[1][1]]
        plt.bar(x,y, color="#000000", label='RF')
        plt.legend()
        plt.show()
    
def main():
    start = datetime.now() # Start time tracking
    
    ml = MachineLearning() # Initialize the MachineLearning class
    ml.flow_training()

    end = datetime.now() # End time tracking
    print("Training time: ", (end-start)) 

if __name__ == "__main__":
    main()