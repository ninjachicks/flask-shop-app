import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class Categories(Base):
    __tablename__ = 'categories'

    id = Column(Integer(11), auto_increment=True, primary_key=True)
    name = Column(String(100), nullable=False)

class Items(Base):

    __tablename__ = 'items'

    id = Column(Integer(11), auto_increment=True, primary_key=True)
    name = Column(String(250), nullable=False)
    detail = Column(String(500))
    category = Column(Integer, ForeignKey('categories.id'))
    creation_time = Column(datetime, current_timestamp)
    modification_time = Column(datetime, on update current_timestamp)

class Users(Base):

    __tablename__ = 'users'

    id = Column(Integer(11), auto_increment=True, primary_key=True)
    name = Column(String(100), nullable=False)
    email = Column(String(100), nullable=False)
    username = Column(String(30), nullable=False)
    password = Column(String(100), nullable=False)
    register_date = Column(timestamp, current_timestamp)

engine = create_engine('sqlite:///flaskshop.db')
Base.metadata.create_all(engine)