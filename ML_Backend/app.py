import os
from flask import Flask, request, jsonify
import numpy as np
import pandas as pd
from tensorflow import keras
from tensorflow.keras.models import load_model
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
import h5py
import gcsfs
from tensorflow.python.lib.io import file_io


model_file = file_io.FileIO('gs://knowy-test10/ML_Model/career_prediction_1.h5', mode='rb')
temp_model_location = './temp_model.h5'
temp_model_file = open(temp_model_location, 'wb')
temp_model_file.write(model_file.read())
temp_model_file.close()
model_file.close()
model = load_model(temp_model_location)
app = Flask(__name__)



# Load the Keras model

# Read Data 
data = pd.read_csv('Data_final.csv')
x = data.drop(columns=['Career'])

# Load scaler and encoder
scaler = StandardScaler()
x_scaled = scaler.fit_transform(x)

#encoder model
encoder = keras.Model(inputs=model.input, outputs=model.layers[-3].output)
encoded_features = encoder.predict(x_scaled)

# KMeans
kmeans = KMeans(n_clusters=104, random_state=42)
kmeans.fit(encoded_features)

# Load dataframe for career mapping
df_sorted = pd.read_csv('sorted_careers.csv')

# Function to preprocess input data
def preprocess_input(data):
    # Assuming data is a list of 10 floating-point numbers
    inputs = np.array(data).reshape(1, -1)  # Reshape to (1, 10) array
    return inputs

# Function to predict career cluster
def predict_career(new_inputs):
    new_inputs_scaled = scaler.transform(new_inputs)
    encoded_features = encoder.predict(new_inputs_scaled)
    cluster_labels = kmeans.predict(encoded_features)
    return cluster_labels

# Function to map cluster label to career
def map_cluster_to_career(cluster_label):
    cluster_to_career_map = {}
    for cluster, career in df_sorted.groupby('cluster')['career']:
        cluster_to_career_map[cluster] = career.iloc[0]
    return cluster_to_career_map.get(cluster_label, 'Unknown')

# Route to accept POST requests with URL-encoded data
@app.route('/predict_career', methods=['POST'])
def predict_career_route():
    try:
        # Extracting the URL-encoded data from the request
        #data = request.form.get('data')
        #inputs = [float(num) for num in data.strip('[]').split(',')] # Convert comma-separated string to list of floats
        data = request.form.get('data')
        # Extracting the URL-encoded data from the request
        cleaned_data = data.strip("[]").replace(" ", "")
        inputs = [float(num) for num in cleaned_data.split(',')]
        # Ensure the data is a list of 10 floating-point numbers
        if len(inputs) != 10:
            raise ValueError("Input data must be a list of 10 numbers", inputs)

        # Preprocess input data
        new_inputs = preprocess_input(inputs)

        # Predict career cluster
        predicted_cluster = predict_career(new_inputs)[0]

        # Map cluster to career
        predicted_career = map_cluster_to_career(predicted_cluster)

        return jsonify({'predicted_career': predicted_career}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)
