from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from passlib.hash import pbkdf2_sha256

import json

from database_setup import Base, Sport, Item, User, Admin

engine = create_engine('sqlite:///sportinggoods.db')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()

# Creating Admin user and storing the password as a hash
phash = pbkdf2_sha256.encrypt("manager", rounds=1000, salt_size=16)

user1 = User(name="Admin", email="admin", picture="", password=phash)
session.add(user1)
session.commit()

# Setting up admin user 
admin1 = Admin(user_id=1)
session.add(admin1)
session.commit()

# Reading JSON file and populate the database with sport categories and items
itemsFile = open("items.json")

data = json.load(itemsFile)

cnum = len(data['Sports']) # To determine number of sport categories
for c in range(0, cnum):
	print(data['Sports'][c]['name'])
	
	sport1 = Sport(name=data['Sports'][c]['name'])
	session.add(sport1)
	session.commit()
	
	inum = len(data['Sports'][c]['items'])
	for i in range(0, inum):
		item = Item(name=data['Sports'][c]['items'][i]['name'], description=data['Sports'][c]['items'][i]['description'], price=data['Sports'][c]['items'][i]['price'], image=data['Sports'][c]['items'][i]['picture'], sport=sport1)
		session.add(item)
		session.commit()

print "Added sport categories and items."