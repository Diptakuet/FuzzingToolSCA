import tensorflow as tf
import pandas as pd
import os
from sklearn.model_selection import train_test_split


data_path = 'Model\Processed_Data\FinalData'


num_sample=1000
X = pd.read_csv(os.path.join(data_path,"X.csv"), header=None).values
Y = pd.read_csv(os.path.join(data_path,"Y.csv"), header=None).values

mean = X.mean()
std = X.std()

X = (X-mean)/std


# Split the data into train, validation, and test sets
X_train, X_temp, Y_train, Y_temp = train_test_split(X, Y, test_size=0.2, random_state=42)
X_val, X_test, Y_val, Y_test = train_test_split(X_temp, Y_temp, test_size=0.5, random_state=42)


# Print the shapes of the datasets
print("Train data shapes:", X_train.shape, Y_train.shape)
print("Validation data shapes:", X_val.shape, Y_val.shape)
print("Test data shapes:", X_test.shape, Y_test.shape)


# Define the neural network architecture
input_size = 3
hidden_size = 32
output_size = 2

# Define the model
model = tf.keras.Sequential([
    tf.keras.layers.Dense(hidden_size, activation='relu', input_shape=(input_size,)),
    tf.keras.layers.Dense(output_size, activation='sigmoid')
])

# Compile the model
model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# Print model summary
model.summary()


history = model.fit(X_train, Y_train, validation_data=(X_val, Y_val), epochs=50, batch_size=10)
# Save the trained model
model.save('model.h5')

# Load the saved model
loaded_model = tf.keras.models.load_model('model.h5')

# Evaluate the loaded model on the test set
test_loss, test_acc = loaded_model.evaluate(X_test, Y_test)
print("Test accuracy:", test_acc)


# Make predictions on the test set
#predictions = model.predict(X_test)

