# Machine Learning Based Web App Firewall/IPS (PFE BAC+2 ESTM)

## Project Overview
This project focuses on building a Web Application Firewall (WAF) driven by machine learning to detect SQL Injection attacks. The model is trained on a dataset of approximately 45,000 requests, both benign and malicious.

The created model is integrated into a proxy Intrusion Prevention System (IPS) that listens on localhost port 8090. Please note that the proxy's functionality was tested only on localhost, not on a real web server.

## Project Structure
The project contains the following files:

- **notebook1.ipynb**: Notebook for training the machine learning model.
- **notebook2.ipynb**: Notebook for integrating the model into the proxy IPS.
- **Pycaret_requirements.txt**: List of dependencies required to install Pycaret.
- **Guide_installation.txt**: Detailed installation guide.
- **Ressources.txt**: Contains references and links necessary for the project.

## Setup Instructions
To set up the WAF, follow these steps:

1. Download and install Anaconda from [here](https://www.anaconda.com/products/distribution).

2. Create a new environment in Anaconda:
    ```sh
    conda create --name waf_env python=3.8
    conda activate waf_env
    ```

3. Install Jupyter Notebook:
    ```sh
    conda install -c conda-forge notebook
    ```

4. Install Pycaret and other dependencies:
    ```sh
    pip install -r Pycaret_requirements.txt
    ```

5. Copy the notebooks (`notebook1.ipynb` and `notebook2.ipynb`) to `C:\Users\VotreUtilisateur`.

6. Launch Jupyter Notebook:
    ```sh
    jupyter notebook
    ```

7. Open and execute the notebooks.

## Data Paths
Please ensure to modify the data paths in the notebooks according to where you have stored the datasets.

## Dependencies
Here are the specific dependencies required for Pycaret, listed in `Pycaret_requirements.txt`:

- pandas
- scipy<=1.5.4
- seaborn
- matplotlib
- IPython
- joblib
- scikit-learn==0.23.2
- ipywidgets
- yellowbrick>=1.0.1
- lightgbm>=2.3.1
- plotly>=4.4.1
- wordcloud
- textblob
- cufflinks>=0.17.0
- umap-learn
- pyLDAvis
- gensim<4.0.0
- spacy<2.4.0
- nltk
- mlxtend>=0.17.0
- pyod
- pandas-profiling>=2.8.0
- kmodes>=0.10.1
- mlflow
- imbalanced-learn==0.7.0
- scikit-plot
- Boruta
- pyyaml<6.0.0
- numba<0.55

## Notes
For any references to installations or necessary links, refer to `Ressources.txt` which contains all relevant information.
