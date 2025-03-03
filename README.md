# README - Communication Networks final project

note: this project runs on both windows and ubuntu.

## Project Description
This project focuses on analyzing data from various sources using statistical analysis algorithms and graphical visualizations. 
The CSV files contain collected data, which is analyzed using Jupyter Notebook.
CSV files were used for graph export and the pcap files recordings were used for the Knn model on an Ubuntu computer.
It is important to note that we exported the CSV files from Wishark, except for the knn.pcap file, into which we insert information via "insert_to_csv.py".
## Main Files and Directories
- **CSV Files**: Contain the collected data
  - `bonus.csv`
  - `chrome.csv`
  - `Edge.csv`
  - `Spotify_no_signin.csv`
  - `Spotify_signin.csv`
  - `YouTube_1080.csv`
  - `YouTube_240.csv`
  - `YouTube_720.csv`
  - `zoom.csv`
  - `knn.csv`
  - **pcap Files**: Contain the collected data
  - `bonus.pcap`
  - `chrome.pcap`
  - `Spotify.pcap`
  - `YouTube.pcap`
  - `zoom.pcap`
- **KNN/**: Directory containing the implementation of the KNN algorithm
-  `knn.csv`:Contains additional recordings for the model
- **plotAll.ipynb**: Jupyter Notebook for data visualization
- **bonus.ipynb**: Additional Jupyter Notebook for extended analysis
- **.venv/**: Virtual environment for the project

## Explanation of Graphs
The graphs in the project visually represent the collected data, including trends and comparisons between different datasets. These graphical analyses help in identifying significant patterns and insights.

## Explanation of KNN
The K-Nearest Neighbors (KNN) algorithm is an instance-based learning method where new data points are classified based on their proximity to existing data. In this project, KNN is used for various classification tasks.

## Python Version
The project has been tested with **Python 3.12.7**. It is recommended to use this version or a newer one.

## Installation
```bash
Clone the repository:https://github.com/dviropa/Communication-Networks-Final-Project
```

## Necessary installation
```bash
pip install numpy pandas matplotlib scikit-learn
```
```bash
pip install matplotlib
```
```bash
pip install pandas
```
```bash
pip install numpy
```
```bash
pip install scapy
```
```bash
pip install sklearn
```
```bash
pip install scikit-learn
```
```bash
pip install joblib
```

## Additional Information
If you encounter any issues running the project, check that all package versions are up to date and consult the team for support.
