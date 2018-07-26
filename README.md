# Python: Getting Started

A barebones example of using Deauthorized authentication solution within a Django app.

## Running Locally

Make sure you have Python [installed properly](http://install.python-guide.org). Also, install the [Heroku CLI](https://devcenter.heroku.com/articles/heroku-cli) and [Postgres](https://devcenter.heroku.com/articles/heroku-postgresql#local-setup).

```sh
$ git clone git@github.com:Deauthorized/python_openidconnect_starter_app.git
$ cd python_openidconnect_starter_app

# Setup Environment
$ pipenv install

# OR

$ conda env create && source activate deauthorized-python-sample

$ createdb python_getting_started

$ python manage.py migrate
$ python manage.py collectstatic

# Run dev server
$ heroku local
```

Your app should now be running on [localhost:5000](http://localhost:5000/).

## Deploying to Heroku

```sh
$ heroku create
$ git push heroku master

$ heroku run python manage.py migrate
$ heroku open
```
or

[![Deploy](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy)

## Documentation

For more information about using Python on Heroku, see these Dev Center articles:

#### TODO: Add link to additional deauthorized documentation
