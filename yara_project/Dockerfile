# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Install YARA, gcc and other dependencies
RUN apt-get update && \
    apt-get install -y gcc libyara-dev && \
    pip install yara-python pefile

# Copy the current directory contents into the container at /app
COPY . /app

# Run your Python script when the container launches
CMD ["python", "q4v2.py"]
