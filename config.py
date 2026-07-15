class Config:

    SECRET_KEY = 'seclog_secret_2024'

    SQLALCHEMY_DATABASE_URI = (
    'mysql+pymysql://root:@localhost/seclog_db'
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_FOLDER = 'uploads'