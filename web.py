# Run this with python web.py, it points to the webapp.__init__.py file for \
# instantiation of the web application.

import os
import signal

from webapp import application


def signal_handler(sig, frame):
    os._exit(0)


signal.signal(signal.SIGINT, signal_handler)

if __name__ == '__main__':
    # main cassidy app
    # debug=True will start two bm_threads
    application.run(debug=True, threaded=True, host='0.0.0.0')

"""
TODO:

users can be part of teams
users can create products
products are also part of teams
product has an arrangement
"""