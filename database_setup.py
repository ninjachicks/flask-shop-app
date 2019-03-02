import datetime
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
from sqlalchemy import create_engine
from flask_dance.consumer.backend.sqla import OAuthConsumerMixin


Base = declarative_base()


class Items(Base):

    __tablename__ = 'items'

    id = Column(Integer, autoincrement=True, primary_key=True)
    name = Column(String(250), nullable=False)
    detail = Column(String(500))
    category = Column(Integer, ForeignKey('categories.id'))
    creation_time = Column(DateTime, default=datetime.datetime.now)
    modification_time = Column(DateTime, onupdate=datetime.datetime.now)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)

    @property
    def serialize(self):
        # Return object data in easily serializeable format
        return {
            'id': self.id,
            'name': self.name,
            'detail': self.detail,
            'category': self.category
        }


class Categories(Base):
    __tablename__ = 'categories'

    id = Column(Integer, autoincrement=True, primary_key=True)
    name = Column(String(100), nullable=False, unique=True)
    items = relationship(Items, cascade="all, delete")
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)


class Users(Base):

    __tablename__ = 'users'

    id = Column(Integer, autoincrement=True, primary_key=True)
    name = Column(String(100), nullable=False)
    email = Column(String(100), nullable=False)
    username = Column(String(30), nullable=False, unique=True)
    password = Column(String(100), nullable=True)
    register_date = Column(DateTime, default=datetime.datetime.now)
    github_id = Column(Integer, nullable=True, unique=True)


class OAuth(OAuthConsumerMixin, Base):
    user_id = Column(Integer, ForeignKey(Users.id))
    user = relationship(Users)

engine = create_engine('sqlite:///flaskshop.db')
Base.metadata.create_all(engine)