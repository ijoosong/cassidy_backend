#!/bin/bash

sudo docker run -p 5000:5000 -v $pwd/config.py:/code/config.py -t bc-flaskapp python web.py

