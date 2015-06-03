#
# Database access functions for the Catalog application.
#
"""dboperations - This module contains database access functions for the Catalog application."""

from datetime import datetime
from passlib.hash import pbkdf2_sha256

# Database stuff
from sqlalchemy import create_engine, func
from sqlalchemy.sql import collate
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from database_setup import Base, Sport, Item, User, Admin
engine = create_engine('sqlite:///sportinggoods.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


# Get a list of all the sport categories.
def get_sports():
	"""Returns a result set of all categories in alphabetical order, case insensitive."""
	return session.query(Sport).order_by('name collate NOCASE').all()

# Get a list of the 10 most recent items added.
def get_recent_items():
	"""Returns a result set of the ten most recent items added to the database."""
	return session.query(Item).join(Sport).filter('sport.id==item.sport_id').order_by('item.id desc').limit(10).all()

# Get a sport category.
def get_sport(sport_id):
	"""Returns a result set for a given sport category ID."""
	try:
		return session.query(Sport).filter_by(id = sport_id).one()
	except NoResultFound, e:
		return None

# Get the info for all items in a given category.
def get_sport_items(sport_id):
	"""Returns a result set of all the items for a given sport category ID."""
	return session.query(Item).filter_by(sport_id = sport_id).order_by('item.name').all()

# Get the info about an item.
def get_item_info(item_id):
    """Returns a result set for a given item ID."""
    try:
        return session.query(Item).filter_by(id = item_id).one()
    except NoResultFound, e:
        return None

# Check if category already exists.
def does_sport_exist(newsportname):
	"""Returns False if a category does not exist, i.e. the category name is not found."""
	try:
		return session.query(Sport).filter(func.lower(Sport.name) == func.lower(newsportname)).one()
	except NoResultFound, e:
		return False

# Create a new Sport.
def create_new_sport(newsportname):
	"""Creates a new sport category."""
	newSport = Sport(name = newsportname)
	session.add(newSport)
	session.commit()

# Update the name of a sport category.
def update_sport(sport, newsportname):
	"""Updates the category name."""
	sport.name = newsportname
	session.add(sport)
	session.commit()

# Delete sport catetory.
def delete_sport(sport):
	"""Deletes a category."""
	session.delete(sport)
	session.commit()

# Delete all the items in a sport category.
def delete_sport_items(sport_id):
	"""Deletes all items under a given category ID."""
	items = session.query(Item).filter_by(sport_id = sport_id).all()
	if items:
		for item in items:
			session.delete(item)
			session.commit()

# Create a new item.
def create_new_item(name, description, price, picture, sport_id, user_id):
	"""Creates a new item."""
	newItem = Item(name = name, price = price, image = picture, description = description, sport_id = sport_id, user_id = user_id)
	session.add(newItem)
	session.commit()

# Update an item.
def update_item(item, name, description, price, picture, sport_id):
	"""Updates an item."""
	item.name = name
	item.description = description
	item.price = price
	item.image = picture
	item.sport_id = sport_id
	item.last_updated = datetime.utcnow()
	session.add(item)
	session.commit()

# Delete an item.
def delete_item(item):
	"""Deletes an item."""
	session.delete(item)
	session.commit()

# Get a list of items created by the user.
def get_user_items(user_id):
	"""Returns a result set of items created by a given user ID."""
	return session.query(Item).filter_by(user_id = user_id).all()


# User Helper Functions
# Add the user to the database.
def create_user(login_session):
	"""Creates a new user in the database."""
	newUser = User(name = login_session['username'], email = login_session['email'], picture = login_session['picture'])
	session.add(newUser)
	session.commit()
	user = session.query(User).filter_by(email = login_session['email']).one()
	return user.id

# Get a list of all the users that have registered.
def get_users():
	"""Returns a result set of all users registered in the database."""
	return session.query(User).order_by('name collate NOCASE').all()

# Get the user's info from the database.
def get_user_info(user_id):
	"""Returns a result set of user information for a given user ID."""
	try:
		return session.query(User).filter_by(id = user_id).one()
	except:
		return None

# Get the user ID from the database.
def get_user_id(email):
	"""Gets the user ID for a given email."""
	try:
		user = session.query(User).filter_by(email = email).one()
		return user.id
	except:
		return None

# Check if a user exists.
def does_user_exist(user, password):
	"""Returns True if a user is found having the given username and password; False if not."""
	try:
		user = session.query(User).filter_by(email=user).one()
		# Check if the password verifies against the hash stored in the database.
		if pbkdf2_sha256.verify(password, user.password):
			return user
		else:
			return False
	except NoResultFound, e:
		return False

# Check if a user is an admin.
def is_user_admin(user_id):
	"""Returns True if the logged in user is an Admin; False if not."""
	try:
		return session.query(Admin).filter_by(user_id=user_id).one()
	except NoResultFound, e:
		return False