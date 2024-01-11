
from datetime import datetime
sm = "12-12-2004"

data = datetime.strptime(sm, "%d-%m-%Y")

print(data)