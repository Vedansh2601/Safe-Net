import os
import importlib

# Automatically load all scan rule modules from the current folder
def load_rules():
    rules = []
    rule_files = [f for f in os.listdir(os.path.dirname(__file__)) if f.endswith(".py") and f != "__init__.py"]
    
    for rule_file in rule_files:
        module_name = f"engine.rules.{rule_file[:-3]}"  # Remove '.py' from module name
        module = importlib.import_module(module_name)
        rules.extend(module.load_rules())  # Add all rules from this module to the list
    
    return rules
