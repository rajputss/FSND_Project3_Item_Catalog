This project is not my effort in it's entirety and major thanks to Lorenzo and Udacity staff for making it happen through their awesome coursework. Several sources were used to complete this project. Pictures were obtained from copyright free sources. Major chunk of work was done by using Udacity's coursework. To add different functionalities such as image capability, admin access, JSON and XML links, similar projects were used available on github and online examples. Website template was obtained from freewebsitetemplates.com. GOT SPORTS INC is a fabricated name used for the sole purpose of this educational project.


Got Sports Application: 
**********************
The following instructions assume you have GIT, VirtualBox, and Vagrant installed. Kindly use the links below to download
should you need.


VirtualBox Installation- https://www.virtualbox.org/wiki/Downloads
	Install the platform package for your operating system.  You do not need the extension pack or the SDK.

Vagrant Installation - https://www.vagrantup.com/downloads
	Vagrant is the software that configures the VM and lets you share files between your host computer and the VM's filesystem.

Git Installation - http://git-scm.com/downloads
	Install the version for your operating system.
	On Windows Git will provide you with a Unix-style terminal and shell (Git Bash). 
	On Mac or Linux systems you can use the regular terminal program.


Libraries used:


Flask

oauth2client

passlib

Flask-SeaSurf

requests

httplib2

SQLAlchemy

STEPS:
*****

1. Using Git, clone this repository to your local machine.
2. Using terminal go to your vagrant directory in your recently downloaded repository,
   type $vagrant up to launch your virtual machine. It will install all the dependencies
   and thus will take few moments.
3. Once vagrant is up, type $vagrant ssh to log into it. Your terminal will be logged into 
   the virtual machine and here you will be using Linux shell prompt.
4. Change to the /vagrant directory by typing cd /vagrant. 
5. Then change to application folder by typing cd application.
6. You can type ls to ensure you are in that folder
7. Here you will have to set up database. Follow instructions below for database setup:
	1. To set up database type $ python database_setup.py 
	2. This will give you an empty database with four tables
		a. sport 
		b. item 
		c. user 
		d. admin
	3. Now to populate this empty database type python addstuff.py
	4. This will add sports categories and items to the database along with an admin user
8. Now you can run the command python project.py to launch the application
9. If the terminal says it can't find some modules then open requirements.txt file to see 
   detailed instructions on how to install dependencies
10. Open your browser to access your local machine @ http://localhost:8000
11. You may find list of sports categories and a list of most recent items that were added.
12. If you are not logged in using G+, FB or GIT credentials, you can only browse sport categories and view
	item descriptions.
13. This application uses OAuth provided by G+, FB and GitHub, therefore, you may need a connection from each.
	Below is how you can obtain that connection id.

	For Google G+:
	**************
	1. Go to https://console.developers.google.com
	2. Create new project and give it a name; like Sports application.
	3. Don't change the project ID. It could take few moments for it to get your application set up.
	4. Once ready, you will see APIs & auth on your left panel, go to credentials and click create new client ID.
	5. For Application type, choose web application then click configure consent screen.
	6. Assign an email address and enter product name such as Sports Catalog and hit save.
	7. In the box where it says Authorized JavaScript origins, add http://localhost:8000 then click Create Client ID.
	8. Click Download JSON and save the file in the same folder where you have your application saved
	9. Rename this file to clients_secret.json
	10. Go to your login.html file => application/templates/login.html
	11. On line 57, you will find => data-clientid="" //<=YOUR G+ ID GOES HERE
		enter google client id within ""
	
	For Facebook:
	*************
	1. Go to https://developers.facebook.com
	2. Go to MyApps and add a new App.
	3. You will get a pop window, select Website.
	4. Enter a name for the app. I like to keep it same thus I used Sports application.
	5. Choose the best fit category (Sport) and click create App ID.
	6. For the site URL, enter http://localhost:8000
	7. Now skip to Developer Dashboard and jot down your app ID and app secret.
	8. Add your Facebook application ID and secret to the fb_client_secrets.json file. You may find the file in the same 	   folder
	   your application is saved.
	9. Go to your login.html file => application/templates/login.html
	10. On line 120, you will find => appId      : "", //<=YOUR FB ID GOES HERE
	    enter facebook id within ""
	
	For GitHub:
	***********
	1. Go to: https://github.com/settings/applications
	2. Click on Register new application.
	3. Enter a name for the app. I like to keep it same thus I used Sports application.
	4. For the homepage URL, enter http://localhost:8000
	5. For the Authorization callback URL enter: http://localhost:8000/ghconnect
	6. Click on Register Application then at the top right of the page, note your Client ID and Client Secret.
	7. Add your GitHub app ID and secret to the gh_client_secrets.json file. You may find the file in the same folder
	   your application is saved.
	8. Replace YOUR_GITHUB_APP_ID with your GitHub app ID and replace YOUR_GITHUB_APP_SECRET with your GitHub app secret and save the file.

14. Choosing either G+, FB, GitHub or a local account; you can login using Login button that appears on the top right of the page. 
15. Once you are in, you can create an item. To do that, browse any sports category, then click on Add item button. You can include an image of the item as well.
16. You can only edit and delete items you have created by clicking on edit and delete button. You are not allowed to edit or delete other users created items.
17. Click on My Items button on the top right hand corner to see list of items created by you.
18. You can also click your name to see your profile.
19. You can also login as an administrator and will have full control to create, edit, delete any sport category and to edit and delete any items.

    Admin login credentials are as follows:


	http://localhost:8000/admin
	
	
	user: admin
	
	
	password: manager
20. At the bottom of the page; you may also access API endpoints. JSON and XML Feeds