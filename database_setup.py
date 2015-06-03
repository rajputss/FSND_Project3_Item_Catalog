import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from datetime import datetime

Base = declarative_base()

class User(Base):
	__tablename__='user'
	
	id = Column(Integer, primary_key=True)
	name = Column(String(250), nullable=False)
	email = Column(String(250), nullable=False)
	picture = Column(String(250))
	password = Column(String(250))
	
	# Add serialize function to send JSON objects in a serialize format
	@property
	def serialize(self):
		return {
			'name'			: self.name,
			'id'			: self.id,
			'email'			: self.email,
			'picture'		: self.picture,
			}

class Admin(Base):
	__tablename__='admin'
	
	id = Column(Integer, primary_key=True)
	user_id = Column(Integer, ForeignKey('user.id'))
	user=relationship(User)

class Sport(Base):
	__tablename__='sport'
	
	id = Column(Integer, primary_key=True)
	name = Column(String(80), nullable=False)
	
	# Add serialize function to send JSON objects in a serialize format 
	@property
	def serialize(self):
		return {
			'name'			: self.name,
			'id'			: self.id,
			}
			
class Item(Base):
	__tablename__='item'
	
	name = Column(String(250), nullable=False)
	id = Column(Integer, primary_key=True)
	description = Column(String(1000))
	price = Column(String(8))
	image = Column(String(250))
	date_created = Column(DateTime, nullable=False, default=datetime.utcnow)
	last_modified = Column(DateTime, nullable=False, default=datetime.utcnow)
	sport_id = Column(Integer, ForeignKey('sport.id'))
	sport = relationship(Sport)
	user_id = Column(Integer, ForeignKey('user.id'))
	user = relationship(User)
	
	# Add serialize function to send JSON objects in a serialize format
	@property
	def serialize(self):
		return {
			'name'			: self.name,
			'id'			: self.id,
			'description'	: self.description,
			'price'			: self.price,
			'image'			: self.image,
			'sport_id'		: self.sport_id,
			}

engine = create_engine('sqlite:///sportinggoods.db')

Base.metadata.create_all(engine)
	
    
    

	

