import sys
import os

# Add the 'backend' directory to Python's path so the tests can import your modules
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend'))
sys.path.insert(0, backend_path)