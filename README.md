# About flask-shop-app

A small shop-app showing a company and its catalog of products (available categories and items, including top 10 latest items).

It is possible to register as a new user and use delete, edit and add categories and items functions when logged in.

The app includes a sqlite database to store the products and user information.

# Database

To test the program you can download a sample database here with this repository -

[flaskshop.db](https://github.com/CarolinB/flask-shop-app/blob/master/flaskshop.db)

flaskshop.db consists of 4 tables:

* categories
* items
* users
* oauth

The tables categories and items are connected via Foreign Keys: 
* `items.category = categories.id`
* `items.user_id = users.id`
* `categories.user_id = users.id`
* `oauth.user_id = users.id`

# Installation/Environment

Requires Python 3.7.1 and Flask 1.0.2.

We recommend using this program in a virtual environment. If you like to do so follow the steps listed here:

## Install Virtual Machine

### Install Virtual Box

Here's a [Download Link](https://www.virtualbox.org/wiki/Download_Old_Builds_5_1) where you can download the latest version of VB. If you need help installing and getting started with VB check out the [Official Documentation](https://www.virtualbox.org/manual/ch02.html#intro-installing).

Currently (October 2017), the supported version of VirtualBox to install is version 5.1. Newer versions do not work with the current release of Vagrant.

**Ubuntu users:** If you are running Ubuntu 14.04, install VirtualBox using the Ubuntu Software Center instead. Due to a reported bug, installing VirtualBox from the site may uninstall other software you need.

### Install vagrant

You can download vagrant [here](https://www.vagrantup.com/downloads.html) and install the version for your OS.

**Windows users:** The Installer may ask you to grant network permissions to Vagrant or make a firewall exception. Be sure to allow this.

### VM Configuration

You can download a .zip file with VM configuration files [here](https://s3.amazonaws.com/video.udacity-data.com/topher/2018/April/5acfbfa3_fsnd-virtual-machine/fsnd-virtual-machine.zip).

Then follow the following steps using your terminal:

* `cd` to the VM config folder (if you didn't change the name it's called `FSND Virtual Machine`)
* direct into the vagrant folder `$ cd vagrant/`
* start vagrant `$ vagrant up` (this will install Linux OS)
* log in to Linux VM with `$ vagrant ssh`

## Install Flask

[Official Flask Installation Guide](http://flask.pocoo.org/docs/1.0/installation/)

* `pip3 install Flask`

Furthermore you will need the following packages:
```
flask_migrate
flask_login
flask_dance
passlib
sqlalchemy
sqlalchemy_utils
environs
wtforms
wtforms_alchemy
blinker
flask_script
```
## GitHub Login
To use the GitHub Login functionality 
* create a [GitHub](https://github.com/) account
* add the app [here](https://github.com/settings/applications/new)
If you got any problems follow this [tutorial](https://developer.github.com/apps/building-github-apps/creating-a-github-app/).
In your app folder create a .env file and add the following two variables there:
* `GITHUB_ID`=mygithubid
* `GITHUB_SECRET`=mygithubsecret

## Run the program

`$ python3 app.py`

# Output example

[Catalog Screenshot](https://github.com/CarolinB/flask-shop-app/issues/1#issue-407720761)

[Product Detail Screenshot](https://github.com/CarolinB/flask-shop-app/issues/2#issue-407720991)

[Screenshot of adding an item](https://github.com/CarolinB/flask-shop-app/issues/3#issue-407721167)

# Server Details
* IP Address 89.22.107.197
* OPS Ubuntu 16.04
* SSH Port 2200
* URL to application: [http://89.22.107.197](http://89.22.107.197)

## Installation log on server
* `apt-get install nano`
* `apt-get install git`
* `apt-get install python3-pip`
* `apt-get install libapache2-mod-wsgi-py3`

## Configuration changes
* in `etc/ssh/sshd_config`changed port ssh from 22 to 2200
* installed `ufw`and made the following changes:
  * `ufw default allow outgoing`
  * `ufw default deny incoming`
  * `ufw allow ssh`
  * `ufw allow 2200`
  * `ufw allow www`
  * `ufw enable`
* added WSGIScriptAlias to apache2 conf-enabled:
  * new file flaskapp.conf
  * ```
WSGIScriptAlias / /usr/share/caros-apps/flaskapp/wsgi/flask.wsgi
WSGIScriptReloading On

<Directory /usr/share/caros-apps/flaskapp/wsgi>
  Order allow,deny
  Allow from all
</Directory>
``` 

## pip3 packages
* Flask
* flask_migrate
* flask_login
* flask_dance
* passlib
* sqlalchemy
* sqlalchemy_utils
* environs
* wtforms
* wtforms_alchemy
* blinker
* flask_script

# Licence

No licence required.

# Help

For any questions please send a message to our [support](mailto:carolin.bruederle@gmail.com).
