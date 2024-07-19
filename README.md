# FastAPI CRUD Application with MongoDB

This is a simple CRUD (Create, Retrieve, Update, Delete) application for job postings using FastAPI and MongoDB. The application includes user authentication.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Environment Variables](#environment-variables)
- [Running the Application](#running-the-application)
- [API Endpoints](#api-endpoints)
- [License](#license)

## Features

- Create, retrieve, update, and delete job postings.
- User authentication with JWT.
- Input validation using Pydantic models.
- MongoDB as the database.

## Requirements

- Python 3.8+
- MongoDB

## Installation

**Clone the repository:**

   ```bash
   git clone https://github.com/yourusername/job_position.git
   cd job_position
Create and activate a virtual environment:

VIRTUAL ENV
python -m venv venv
source venv/bin/activate   # On Windows use `venv\Scripts\activate`
Install the required packages:

REQUIREMENTS
pip install -r requirements.txt
Environment Variables
Create a .env file in the root directory of the project with the following contents:

.env
MONGO_URI=mongodb://localhost:27017/job_db
SECRET_KEY=your_secret_key_here
Replace mongodb://localhost:27017/job_db with your actual MongoDB connection URI and your_secret_key_here with your actual secret key.

Running the Application
Make sure MongoDB is running:

If MongoDB is installed locally, start the MongoDB server using the appropriate command for your OS.
If using a remote MongoDB instance, ensure it is accessible.
Start the FastAPI application:

RUNNING BY THIS COMMAND
uvicorn app.main:app --reload
Access the application:

WEB-BROWSER
Open your web browser and navigate to http://127.0.0.1:8000.
The automatically generated interactive API documentation will be available at http://127.0.0.1:8000/docs

