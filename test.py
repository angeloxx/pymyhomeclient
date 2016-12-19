import myhomeclient, asyncore
import threading

def callbackFunction(_in):
        print "Attention, received: %s" % _in

# Simple test that connects to a MH Gateway with HMAC authentication and turns on the light A=1 PL=15
m = myhomeclient.MHClient("192.168.157.213")
m.sendCommand("*1*0*15##")
m.monitorHander(callbackFunction)
asyncore.loop(timeout = 1)
