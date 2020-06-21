# 1
import os
def clear_file(filename):
    with open(filename, 'r+', encoding='utf-8') as f:
        f.truncate()
    return


files = os.listdir("output")
for i in files:
    filename = "output/" + i
    clear_file(filename)

# clear_file("output.txt")
