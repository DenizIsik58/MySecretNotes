FROM python:3

# Make and set the directorties and copy all our files into the docker container
RUN mkdir /flaskApp
WORKDIR /flaskApp
COPY .. .

# Update the packagemanager and install packages

RUN apt-get update
RUN pip3 install -r requirements.txt


# Expose port 5000
EXPOSE 5000

# Specify the commands
CMD ["python3", "flask/app.py"]
