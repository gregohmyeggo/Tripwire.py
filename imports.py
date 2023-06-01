import requests, base64, os, time, yaml, json, argparse, subprocess, datetime, emoji, random, logging
from datetime import datetime
from attackcti import attack_client

logging.getLogger('taxii2client').setLevel(logging.CRITICAL)

import urllib3
urllib3.disable_warnings()

# Local
import functions, variables
from colors import colors