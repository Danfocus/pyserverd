'''
Created on 30.08.2011

@author: User
'''

def hex_data(hexdata):
    hexs = map(lambda x: "%.2x" % ord(x), tuple(hexdata))
    return " ".join(hexs)

def hex_data_f(hexdata):
    hexst = hex_data(hexdata)
    hexs = ""
    while len(hexst) > 0:
        hexs = hexs + hexst[:47] + "\n"
        hexst = hexst[48:] 
    return hexs[:-1]

        
