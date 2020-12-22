# Project : Photobook Album   

The purpose of this repository is to create a full stack web development project dedicated to allowing users to store their memories. Users can create an account, create albums dedicated towards specific memories in their life and upload images + comments to those newly created albums.   


## Download and Installation

Download the package by running
```console
git clone https://github.com/vatsal220/photobook_album.git
```
Then, navigate to the directory.

If you are using anaconda virtual environments, you will first need to do following:
```console
conda develop .
```

Then you can install the package using pip by typing:
```console
pip install .
```

Then you will need to make a `config.yml` file and add the following code: 
```python
connection:
    dev :
        username : 'SQLALCHEMY_DATABASE_URI'
        password : your_db_pw
        mail_user : your_email_username
        mail_pass : your_email_pw
        secret_key : your_secret_key
```

Finally, in the same directory you can run the following:
```console
python app.py
```

