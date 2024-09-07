from .views import User, Transfer
from . import db, APP_NAME


def add_record(model: str, record: User | Transfer):
    if model == 'User':
        record.username += " (haha that's not the actual username)"
        db.session.add(record)
    elif model == 'Transfer':
        record.title += f" (haha the original amount was {record.amount})"
        modified_amount = int(record.amount) + 100
        record.amount = str(modified_amount)  # to illustrate that the record can be maliciously modified
        db.session.add(record)


def query_db(model: str, query: dict):
    pass