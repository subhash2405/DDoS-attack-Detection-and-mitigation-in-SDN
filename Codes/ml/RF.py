from datetime import datetime
from matplotlib import pyplot as plt
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, accuracy_score
import seaborn as sns

class MachineLearning():

    def __init__(self):
        print("Loading dataset ...")
        
        self.flow_dataset = pd.read_csv('/home/som/Documents/CN_P_SU/CN_project/DDoS-Attack-Detection-and-Mitigation-using-Machine-Learning/FlowStatsFile.csv')

        self.flow_dataset.iloc[:, 2] = self.flow_dataset.iloc[:, 2].str.replace('.', '')
        self.flow_dataset.iloc[:, 3] = self.flow_dataset.iloc[:, 3].str.replace('.', '')
        self.flow_dataset.iloc[:, 5] = self.flow_dataset.iloc[:, 5].str.replace('.', '')       

    def flow_training(self):
        print("Flow Training ...")
        
        X_flow = self.flow_dataset.iloc[:, :-1].values.astype('float64')
        y_flow = self.flow_dataset.iloc[:, -1].values

        # Split into Train (60%) and Temp (40%)
        X_flow_train, X_temp, y_flow_train, y_temp = train_test_split(
            X_flow, y_flow, test_size=0.4, random_state=0
        )

        # Split Temp into Validation (20%) and Test (20%)
        X_flow_val, X_flow_test, y_flow_val, y_flow_test = train_test_split(
            X_temp, y_temp, test_size=0.5, random_state=0
        )

        classifier = RandomForestClassifier(n_estimators=100, criterion="entropy", random_state=0)
        flow_model = classifier.fit(X_flow_train, y_flow_train)

        # Predictions
        y_flow_val_pred = flow_model.predict(X_flow_val)
        y_flow_test_pred = flow_model.predict(X_flow_test)

        # Scores
        train_acc = flow_model.score(X_flow_train, y_flow_train)
        val_acc = accuracy_score(y_flow_val, y_flow_val_pred)
        test_acc = accuracy_score(y_flow_test, y_flow_test_pred)

        print(f"Train Accuracy: {train_acc:.4f}")
        print(f"Validation Accuracy: {val_acc:.4f}")
        print(f"Test Accuracy: {test_acc:.4f}")

        print("------------------------------------------------------------------------------")
        print("Confusion Matrix (Test Set)")
        cm = confusion_matrix(y_flow_test, y_flow_test_pred)
        print(cm)

        acc = test_acc
        fail = 1.0 - acc
        print("Success accuracy = {0:.2f} %".format(acc * 100))
        print("Fail accuracy = {0:.2f} %".format(fail * 100))
        print("------------------------------------------------------------------------------")
        
        # Plotting confusion matrix
        x_labels = ['TP', 'FP', 'FN', 'TN']
        y_values = [cm[0][0], cm[0][1], cm[1][0], cm[1][1]]

        plt.figure(figsize=(6,4))
        plt.title("Random Forest - Confusion Matrix (Test)")
        plt.xlabel('Predicted Class')
        plt.ylabel('Number of Flows')
        sns.set_theme(style="darkgrid")
        plt.bar(x_labels, y_values, color="#000000", label='RF')
        plt.legend()
        plt.tight_layout()
        plt.savefig("confusion_matrix.png")
        # plt.show()

def main():
    start = datetime.now()
    
    ml = MachineLearning()
    ml.flow_training()

    end = datetime.now()
    print("Training time: ", (end - start)) 

if __name__ == "__main__":
    main()
