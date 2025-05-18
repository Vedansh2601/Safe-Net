import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, 
    f1_score, confusion_matrix, classification_report
)

from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from xgboost import XGBClassifier

import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, BatchNormalization
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau

class DDoSDataAnalysis:
    def __init__(self, file_path):
        """
        Initialize the analysis with the dataset
        
        Parameters:
        -----------
        file_path : str
            Path to the DDoS dataset CSV file
        """
        self.raw_data = pd.read_csv(file_path)
        self.processed_data = None
        self.X_train = None
        self.X_test = None
        self.y_train = None 
        self.y_test = None
    
    def perform_comprehensive_eda(self):
        """
        Perform comprehensive Exploratory Data Analysis
        
        Returns:
        --------
        dict: Detailed EDA insights
        """
        # Dataset Overview
        eda_insights = {
            'dataset_shape': self.raw_data.shape,
            'columns': list(self.raw_data.columns),
            'missing_values': self.raw_data.isnull().sum(),
            'data_types': self.raw_data.dtypes
        }
        
        # Clean numeric columns for visualization
        numeric_cols = self.raw_data.select_dtypes(include=[np.number]).columns
        clean_numeric_data = self.raw_data[numeric_cols].replace([np.inf, -np.inf], np.nan).dropna()

        # Visualizations
        plt.figure(figsize=(15, 10))
        
        # 1. Missing Values Bar Plot
        plt.subplot(2, 2, 1)
        missing_values = self.raw_data.isnull().sum()
        missing_values = missing_values[missing_values > 0]
        plt.bar(missing_values.index, missing_values.values, color='purple')
        plt.title('Missing Values per Column')
        plt.ylabel('Count')
        plt.xticks(rotation=45)
        
        # 2. Target Label Distribution
        plt.subplot(2, 2, 2)
        if ' Label' in self.raw_data.columns:
            self.raw_data[' Label'].value_counts().plot(kind='pie', autopct='%1.1f%%')
            plt.title('Label Distribution')
        
        # 3. Boxplots for Numeric Features
        plt.subplot(2, 2, 3)
        if not clean_numeric_data.empty:
            sns.boxplot(data=clean_numeric_data)
            plt.title('Boxplot of Numeric Features')
            plt.xticks(rotation=45)
        
        # 4. Correlation Heatmap
        plt.subplot(2, 2, 4)
        if not clean_numeric_data.empty:
            corr_matrix = clean_numeric_data.corr()
            sns.heatmap(corr_matrix, annot=True, cmap='coolwarm', linewidths=0.5, fmt=".2f", square=True)
            plt.title('Feature Correlation Heatmap')
        
        plt.tight_layout()
        plt.show()
        
        return eda_insights
    
    def preprocess_data(self, target_column=' Label', test_size=0.2):
        """
        Comprehensive data preprocessing
        
        Parameters:
        -----------
        target_column : str, optional
            Name of the target column
        test_size : float, optional
            Proportion of the dataset to include in the test split
        """
        # Create a copy of the data
        df = self.raw_data.copy()
        
        # Remove irrelevant columns
        df = df.drop(['Timestamp'], axis=1, errors='ignore')
        
        # Handle categorical variables
        categorical_cols = df.select_dtypes(include=['object']).columns
        label_encoder = LabelEncoder()
        
        for col in categorical_cols:
            df[col] = label_encoder.fit_transform(df[col].astype(str))
        
        # Separate features and target
        X = df.drop(columns=[target_column])
        y = df[target_column]
        
        # Check and handle NaN/Infinite values
        if X.isnull().any().any() or np.isinf(X.values).any():
            X = X.fillna(X.mean())
            X = X.replace([np.inf, -np.inf], X.max().max())
            lower_bound, upper_bound = -1e6, 1e6
            X = X.clip(lower=lower_bound, upper=upper_bound)
        
        # Split the data
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            X, y, test_size=test_size, random_state=42
        )
        
        # Scale the features
        scaler = StandardScaler()
        self.X_train = scaler.fit_transform(self.X_train)
        self.X_test = scaler.transform(self.X_test)
        
        self.processed_data = df
    
    def feature_analysis(self, n_features=10):
        """
        Advanced feature importance and selection
        
        Parameters:
        -----------
        n_features : int, optional
            Number of top features to analyze
        
        Returns:
        --------
        pd.DataFrame: Feature importances
        """
        # Feature selection using ANOVA F-test
        selector = SelectKBest(score_func=f_classif, k=n_features)
        X_new = selector.fit_transform(self.X_train, self.y_train)
        
        # Get selected feature names
        feature_names = self.processed_data.drop(columns=[' Label']).columns
        selected_features = feature_names[selector.get_support()]
        
        # Random Forest Feature Importance
        rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        rf_classifier.fit(self.X_train, self.y_train)
        
        feature_imp = pd.DataFrame({
            'feature': selected_features,
            'importance': rf_classifier.feature_importances_[:len(selected_features)]
        }).sort_values('importance', ascending=False)
        
        # Visualization
        plt.figure(figsize=(10, 6))
        sns.barplot(x='importance', y='feature', data=feature_imp)
        plt.title(f'Top {n_features} Most Important Features')
        plt.tight_layout()
        plt.show()
        
        return feature_imp
    
    def train_models_with_tuning(self):
        """
        Train and tune multiple machine learning models
        
        Returns:
        --------
        dict: Model performance metrics
        """
        # Define models and their parameter grids
        models = {
            'SVM': {
                'model': SVC(),
                'params': {
                    'C': [0.1, 1, 10],
                    'kernel': ['linear', 'rbf']
                }
            },
            'Random Forest': {
                'model': RandomForestClassifier(),
                'params': {
                    'n_estimators': [50, 100, 200],
                    'max_depth': [None, 10, 20, 30]
                }
            },
            'XGBoost': {
                'model': XGBClassifier(),
                'params': {
                    'learning_rate': [0.01, 0.1, 0.5],
                    'n_estimators': [50, 100, 200]
                }
            }
        }
        
        results = {}
        
        for name, setup in models.items():
            # Grid Search with Cross-Validation
            grid_search = GridSearchCV(
                estimator=setup['model'], 
                param_grid=setup['params'], 
                cv=5, 
                scoring='f1', 
                n_jobs=-1
            )
            
            grid_search.fit(self.X_train, self.y_train)
            
            # Best model prediction
            best_model = grid_search.best_estimator_
            y_pred = best_model.predict(self.X_test)
            
            results[name] = {
                'best_params': grid_search.best_params_,
                'accuracy': accuracy_score(self.y_test, y_pred),
                'precision': precision_score(self.y_test, y_pred, average='weighted'),
                'recall': recall_score(self.y_test, y_pred, average='weighted'),
                'f1_score': f1_score(self.y_test, y_pred, average='weighted'),
                'classification_report': classification_report(self.y_test, y_pred),
                'confusion_matrix': confusion_matrix(self.y_test, y_pred)
            }
        
        # Visualization of model performance
        performance_df = pd.DataFrame.from_dict(results, orient='index')
        performance_metrics = ['accuracy', 'precision', 'recall', 'f1_score']
        
        plt.figure(figsize=(12, 6))
        performance_df[performance_metrics].plot(kind='bar')
        plt.title('Model Performance Comparison')
        plt.tight_layout()
        plt.show()
        
        return results
    
    def deep_learning_model(self):
        """
        Create, train, and tune a deep learning model
        
        Returns:
        --------
        dict: Model training history and performance
        """
        # Reshape input for potentially multi-class scenario
        X_train = self.X_train
        X_test = self.X_test
        y_train = tf.keras.utils.to_categorical(self.y_train)
        y_test = tf.keras.utils.to_categorical(self.y_test)
        
        # Define model architecture with tunable parameters
        def create_model(learning_rate=0.001, units1=64, units2=32, dropout_rate=0.3):
            model = Sequential([
                Dense(units1, activation='relu', input_shape=(X_train.shape[1],)),
                BatchNormalization(),
                Dropout(dropout_rate),
                Dense(units2, activation='relu'),
                BatchNormalization(),
                Dropout(dropout_rate),
                Dense(y_train.shape[1], activation='softmax')
            ])
            
            optimizer = Adam(learning_rate=learning_rate)
            model.compile(optimizer=optimizer, 
                          loss='categorical_crossentropy', 
                          metrics=['accuracy'])
            return model
        
        # Learning rate reduction and early stopping
        reduce_lr = ReduceLROnPlateau(
            monitor='val_loss', 
            factor=0.2, 
            patience=5, 
            min_lr=0.00001
        )
        
        early_stopping = EarlyStopping(
            monitor='val_loss', 
            patience=10, 
            restore_best_weights=True
        )
        
        # Create and train the model
        model = create_model()
        history = model.fit(
            X_train, y_train,
            validation_split=0.2,
            epochs=100,
            batch_size=32,
            callbacks=[early_stopping, reduce_lr],
            verbose=0
        )
        
        # Evaluate the model
        y_pred = model.predict(X_test)
        y_pred_classes = np.argmax(y_pred, axis=1)
        y_test_classes = np.argmax(y_test, axis=1)
        
        # Plotting training history
        plt.figure(figsize=(12, 4))
        plt.subplot(1, 2, 1)
        plt.plot(history.history['accuracy'], label='Training Accuracy')
        plt.plot(history.history['val_accuracy'], label='Validation Accuracy')
        plt.title('Training and Validation Accuracy')
        plt.xlabel('Epochs')
        plt.ylabel('Accuracy')
        plt.legend()

        plt.subplot(1, 2, 2)
        plt.plot(history.history['loss'], label='Training Loss')
        plt.plot(history.history['val_loss'], label='Validation Loss')
        plt.title('Training and Validation Loss')
        plt.xlabel('Epochs')
        plt.ylabel('Loss')
        plt.legend()
        plt.show()
        
        return {
            'accuracy': accuracy_score(y_test_classes, y_pred_classes),
            'classification_report': classification_report(y_test_classes, y_pred_classes),
            'confusion_matrix': confusion_matrix(y_test_classes, y_pred_classes),
            'history': history.history
        }

def main(file_path):
    # Initialize analysis
    ddos_analysis = DDoSDataAnalysis(file_path)
    
    # Perform Exploratory Data Analysis
    print("Performing Comprehensive EDA...")
    eda_insights = ddos_analysis.perform_comprehensive_eda()
    print("EDA Insights:", eda_insights)
    
    # Preprocess the data
    print("\nPreprocessing Data...")
    ddos_analysis.preprocess_data()
    
    # Feature Analysis
    print("\nPerforming Feature Analysis...")
    feature_importance = ddos_analysis.feature_analysis()
    
    # Train Multiple Models with Tuning
    print("\nTraining and Tuning Machine Learning Models...")
    ml_results = ddos_analysis.train_models_with_tuning()
    
    # Results Processing for Machine Learning Models
    results_list = []
    for model_name, model_results in ml_results.items():
        results_list.append({
            'Model': model_name,
            'Best Parameters': model_results['best_params'],
            'Accuracy': model_results['accuracy']
        })
    
    results_df = pd.DataFrame(results_list)
    print("\nModel Performance Summary:")
    print(results_df)
    
    # Deep Learning Model
    print("\nTraining Deep Learning Model...")
    dl_results = ddos_analysis.deep_learning_model()
    
    results_list = [{
        'Model': 'Deep Learning Model',
        'Accuracy': dl_results['accuracy']
    }]
    
    results_df = pd.DataFrame(results_list)
    print("\nDeep Learning Model Performance Summary:")
    print(results_df)

if __name__ == "__main__":
    # Replace with the actual path to your dataset
    main('/kaggle/input/ddos-evaluation-dataset-cic-ddos2019/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv')