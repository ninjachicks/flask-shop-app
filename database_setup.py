import datetime
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine


Base = declarative_base()

class Categories(Base):
    __tablename__ = 'categories'

    id = Column(Integer, autoincrement=True, primary_key=True)
    name = Column(String(100), nullable=False)

class Items(Base):

    __tablename__ = 'items'

    id = Column(Integer, autoincrement=True, primary_key=True)
    name = Column(String(250), nullable=False)
    detail = Column(String(500))
    category = Column(Integer, ForeignKey('categories.id'))
    creation_time = Column(DateTime, default=datetime.datetime.now)
    modification_time = Column(DateTime, onupdate=datetime.datetime.now)

class Users(Base):

    __tablename__ = 'users'

    id = Column(Integer, autoincrement=True, primary_key=True)
    name = Column(String(100), nullable=False)
    email = Column(String(100), nullable=False)
    username = Column(String(30), nullable=False)
    password = Column(String(100), nullable=False)
    register_date = Column(DateTime, default=datetime.datetime.now)

engine = create_engine('sqlite:///flaskshop.db')
Base.metadata.create_all(engine)