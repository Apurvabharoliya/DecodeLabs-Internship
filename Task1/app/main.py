import sys
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from app.ui.main_window import SOCDashboard

def run():
    app = SOCDashboard()
    app.mainloop()

if __name__ == "__main__":
    run()
